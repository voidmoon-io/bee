//! Bounding and decoding helpers shared by every HTTP operation and tool (FR-037).

use serde_json::Value;

/// Render `v` as compact JSON within `bound` bytes — always **valid** JSON. Each tool shapes its
/// result to fit first; this is the backstop. It halves the longest string field (marking the cut)
/// until the serialised form fits, so a model never receives a JSON value cut off mid-token.
pub fn bounded_json(v: &Value, bound: usize) -> String {
    let mut v = v.clone();
    for _ in 0..32 {
        let s = serde_json::to_string(&v).unwrap_or_default();
        if s.len() <= bound {
            return s;
        }
        if !halve_longest_string(&mut v) {
            break;
        }
    }
    serde_json::json!({ "error": format!("result exceeded its {bound}-byte bound") }).to_string()
}

/// Halve the longest string in `v` (by serialised length, which is what the bound counts). `false`
/// when there is no string left worth shortening.
fn halve_longest_string(v: &mut Value) -> bool {
    fn longest(v: &mut Value) -> Option<(&mut String, usize)> {
        match v {
            Value::String(s) => {
                let n = serde_json::to_string(s).map(|j| j.len()).unwrap_or(0);
                Some((s, n))
            }
            Value::Array(a) => a.iter_mut().filter_map(longest).max_by_key(|(_, n)| *n),
            Value::Object(o) => o.values_mut().filter_map(longest).max_by_key(|(_, n)| *n),
            _ => None,
        }
    }
    let Some((s, n)) = longest(v) else {
        return false;
    };
    if n < 32 {
        return false;
    }
    let mut cut = s.len() / 2;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str("… [cut]");
    true
}

/// Text for the model from body bytes: printable as-is, or — when the bytes are mostly not text — a
/// one-line description instead of a page of escapes.
pub fn text_or_binary(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    let odd = text
        .chars()
        .filter(|c| (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) || *c == '\u{FFFD}')
        .count();
    if !b.is_empty() && odd * 10 > text.chars().count() {
        return format!(
            "(binary: {} bytes shown here would be mostly unprintable)",
            b.len()
        );
    }
    text.into_owned()
}

/// `s` cut to at most `max` bytes on a char boundary, marked with `…` when cut.
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut c = max;
    while !s.is_char_boundary(c) {
        c -= 1;
    }
    format!("{}…", &s[..c])
}

/// Standard base64 (padding optional).
pub fn b64(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    }
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
        .collect();
    if bytes.len() % 4 == 1 {
        return Err("invalid base64 length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c).ok_or("invalid base64 character")? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}
