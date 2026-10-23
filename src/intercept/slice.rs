//! Bounded views of stored bodies for `http_get` (019 T059).
//!
//! Bodies are stored as they crossed the wire, so a view first decodes the `Content-Encoding`
//! (identity, gzip, deflate, br, zstd — stacked encodings in reverse) **up to a hard cap**: a
//! decompression bomb stops at [`DECODE_CAP`] and says so, it never expands without bound. Then one
//! view: the head, a byte range, a regex grep with context, a JSON pointer, or the raw head bytes.

use std::io::Read;

/// Largest decoded body any view works on.
pub const DECODE_CAP: usize = 64 * 1024 * 1024;

/// A decoded body.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub bytes: Vec<u8>,
    /// Decoding stopped at the cap: `bytes` is a prefix.
    pub decoded_truncated: bool,
}

/// Decode `body` per `encoding` (a `Content-Encoding` value), capped at `cap` bytes.
pub fn decode(body: &[u8], encoding: &str, cap: usize) -> Result<Decoded, String> {
    let mut cur = body.to_vec();
    let mut truncated = false;
    let codings: Vec<String> = encoding
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect();
    for coding in codings.iter().rev() {
        let (next, t) = match coding.as_str() {
            "gzip" | "x-gzip" => read_capped(flate2::read::MultiGzDecoder::new(&cur[..]), cap)?,
            "deflate" => {
                // Servers send both zlib-wrapped (correct) and raw deflate (common); try in order.
                match read_capped(flate2::read::ZlibDecoder::new(&cur[..]), cap) {
                    Ok(v) => v,
                    Err(_) => read_capped(flate2::read::DeflateDecoder::new(&cur[..]), cap)?,
                }
            }
            "br" => read_capped(brotli_decompressor::Decompressor::new(&cur[..], 4096), cap)?,
            "zstd" => {
                let d = ruzstd::decoding::StreamingDecoder::new(&cur[..])
                    .map_err(|e| format!("zstd: {e}"))?;
                read_capped(d, cap)?
            }
            other => return Err(format!("unsupported content-encoding `{other}`")),
        };
        cur = next;
        truncated |= t;
    }
    if cur.len() > cap {
        cur.truncate(cap);
        truncated = true;
    }
    Ok(Decoded {
        bytes: cur,
        decoded_truncated: truncated,
    })
}

fn read_capped<R: Read>(r: R, cap: usize) -> Result<(Vec<u8>, bool), String> {
    let mut out = Vec::new();
    let n = r
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("decode: {e}"))?;
    if n > cap {
        out.truncate(cap);
        return Ok((out, true));
    }
    Ok((out, false))
}

/// One `http_get` view.
#[derive(Debug, Clone, PartialEq)]
pub enum View {
    Headers,
    Range {
        start: usize,
        len: usize,
    },
    Grep {
        pattern: String,
        context_lines: usize,
        max_matches: usize,
    },
    JsonPointer(String),
    RawHead,
}

impl View {
    /// Parse the `view` argument: exactly one key.
    pub fn parse(v: &serde_json::Value) -> Result<View, String> {
        let obj = v
            .as_object()
            .ok_or("view must be an object with exactly one key")?;
        if obj.len() != 1 {
            return Err(
                "view must have exactly one of headers, range, grep, json_pointer, raw_head".into(),
            );
        }
        let (k, val) = obj.iter().next().expect("one key");
        match k.as_str() {
            "headers" => Ok(View::Headers),
            "raw_head" => Ok(View::RawHead),
            "range" => {
                let start = val.get("start").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                let len = val
                    .get("len")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(4096)
                    .min(32 * 1024) as usize;
                Ok(View::Range { start, len })
            }
            "grep" => {
                let pattern = val
                    .get("pattern")
                    .and_then(|x| x.as_str())
                    .ok_or("grep needs a pattern")?
                    .to_string();
                Ok(View::Grep {
                    pattern,
                    context_lines: val
                        .get("context_lines")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0)
                        .min(5) as usize,
                    max_matches: val
                        .get("max_matches")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(20)
                        .clamp(1, 100) as usize,
                })
            }
            "json_pointer" => Ok(View::JsonPointer(
                val.as_str()
                    .ok_or("json_pointer must be a string")?
                    .to_string(),
            )),
            other => Err(format!("unknown view `{other}`")),
        }
    }
}

/// Apply `view`, keeping the result within `bound` bytes.
pub fn apply(view: &View, head: &[u8], body: &[u8], bound: usize) -> Result<String, String> {
    match view {
        View::RawHead => Ok(lossy_bounded(head, bound)),
        View::Headers => {
            let text = String::from_utf8_lossy(head);
            let mut out = String::new();
            for line in text.split('\n').skip(1) {
                let line = line.trim_end_matches('\r');
                if line.is_empty() {
                    break;
                }
                out.push_str(line);
                out.push('\n');
                if out.len() > bound {
                    break;
                }
            }
            Ok(cut(out, bound))
        }
        View::Range { start, len } => {
            let s = (*start).min(body.len());
            let e = s.saturating_add(*len).min(body.len());
            Ok(lossy_bounded(&body[s..e], bound))
        }
        View::Grep {
            pattern,
            context_lines,
            max_matches,
        } => {
            let re = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
                .map_err(|e| format!("invalid pattern: {e}"))?;
            let text = String::from_utf8_lossy(body);
            let lines: Vec<&str> = text.lines().collect();
            let mut out = String::new();
            let mut found = 0;
            for (i, l) in lines.iter().enumerate() {
                if !re.is_match(l) {
                    continue;
                }
                found += 1;
                if found > *max_matches {
                    out.push_str(&format!(
                        "… more matches beyond max_matches={max_matches}\n"
                    ));
                    break;
                }
                let from = i.saturating_sub(*context_lines);
                let to = (i + context_lines + 1).min(lines.len());
                for (j, cl) in lines.iter().enumerate().take(to).skip(from) {
                    let mark = if j == i { ':' } else { '-' };
                    out.push_str(&format!("{}{mark} {}\n", j + 1, clip_line(cl, 400)));
                }
                if context_lines > &0 {
                    out.push_str("--\n");
                }
                if out.len() > bound {
                    break;
                }
            }
            if found == 0 {
                out.push_str("(no matches)\n");
            }
            Ok(cut(out, bound))
        }
        View::JsonPointer(p) => {
            let v: serde_json::Value =
                serde_json::from_slice(body).map_err(|e| format!("body is not JSON: {e}"))?;
            match v.pointer(p) {
                Some(x) => Ok(cut(
                    serde_json::to_string_pretty(x).unwrap_or_default(),
                    bound,
                )),
                None => Err(format!("no value at JSON pointer {p}")),
            }
        }
    }
}

fn clip_line(l: &str, max: usize) -> String {
    if l.len() <= max {
        return l.to_string();
    }
    let mut c = max;
    while !l.is_char_boundary(c) {
        c -= 1;
    }
    format!("{}…", &l[..c])
}

fn lossy_bounded(b: &[u8], bound: usize) -> String {
    cut(
        String::from_utf8_lossy(&b[..b.len().min(bound)]).into_owned(),
        bound,
    )
}

fn cut(mut s: String, bound: usize) -> String {
    if s.len() > bound {
        let mut c = bound;
        while !s.is_char_boundary(c) {
            c -= 1;
        }
        s.truncate(c);
        s.push_str("\n… [cut]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_decodes() {
        let d = decode(&gz(b"hello"), "gzip", 1024).unwrap();
        assert_eq!(d.bytes, b"hello");
        assert!(!d.decoded_truncated);
    }

    #[test]
    fn a_bomb_stops_at_the_cap() {
        let bomb = gz(&vec![0u8; 8 * 1024 * 1024]);
        let d = decode(&bomb, "gzip", 1024 * 1024).unwrap();
        assert_eq!(d.bytes.len(), 1024 * 1024);
        assert!(d.decoded_truncated);
    }

    #[test]
    fn views() {
        let head = b"HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\n\r\n";
        assert_eq!(
            apply(&View::Headers, head, b"", 100).unwrap(),
            "A: 1\nB: 2\n"
        );
        assert_eq!(
            apply(&View::Range { start: 2, len: 3 }, head, b"abcdefg", 100).unwrap(),
            "cde"
        );
        let g = apply(
            &View::Grep {
                pattern: "csrf".into(),
                context_lines: 1,
                max_matches: 5,
            },
            head,
            b"a\nb csrf=1\nc\n",
            1000,
        )
        .unwrap();
        assert!(
            g.contains("2: b csrf=1") && g.contains("1- a") && g.contains("3- c"),
            "{g}"
        );
        assert_eq!(
            apply(
                &View::JsonPointer("/user/role".into()),
                head,
                br#"{"user":{"role":"guest"}}"#,
                100
            )
            .unwrap(),
            "\"guest\""
        );
    }

    #[test]
    fn view_parsing_is_strict() {
        assert!(View::parse(&serde_json::json!({"headers": true, "raw_head": true})).is_err());
        assert!(View::parse(&serde_json::json!({"bogus": 1})).is_err());
        assert_eq!(
            View::parse(&serde_json::json!({"range": {"start": 5, "len": 999999}})).unwrap(),
            View::Range {
                start: 5,
                len: 32 * 1024
            }
        );
    }
}
