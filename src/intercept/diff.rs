//! Edits over a stored request, and the measured diff between two responses (019 T071/T072,
//! research R10).
//!
//! [`Edit`] is shared by `http_replay` and intercept rules (US7). Edits are applied to the raw request
//! as stored, preserving header order, casing and line endings, and `Content-Length` is fixed after a
//! body change.
//!
//! The diff is **measured**, not guessed: with a noise probe — the unmodified original sent once more
//! — anything that differs between original and probe is volatile, suppressed from the edit-vs-
//! original diff, and reported as a count plus paths. A fixed header list (`date`, `expires`, …) is
//! volatile regardless.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One change to a request (data-model.md §Edit). Externally tagged: `{"set_header": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    SetHeader {
        name: String,
        value: String,
    },
    RemoveHeader {
        name: String,
    },
    SetQuery {
        name: String,
        value: String,
    },
    RemoveQuery {
        name: String,
    },
    SetPath {
        value: String,
    },
    SetMethod {
        value: String,
    },
    JsonSet {
        pointer: String,
        value: Value,
    },
    JsonRemove {
        pointer: String,
    },
    FormSet {
        name: String,
        value: String,
    },
    Replace {
        #[serde(rename = "in")]
        part: Part,
        find: String,
        replace: String,
        #[serde(default)]
        regex: bool,
    },
    SetBody {
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        base64: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    Head,
    Body,
}

/// A request split into its parts, preserving what an editor must not disturb.
struct Request {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    eol: &'static str,
    body: Vec<u8>,
}

impl Request {
    fn parse(head: &[u8], body: &[u8]) -> Result<Request, String> {
        let text = std::str::from_utf8(head).map_err(|_| "request head is not UTF-8")?;
        let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let mut lines = text.split(eol);
        let line = lines.next().ok_or("empty request")?;
        let mut parts = line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let target = parts
            .next()
            .ok_or("request line has no target")?
            .to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        let mut headers = Vec::new();
        for l in lines {
            if l.is_empty() {
                break;
            }
            let (k, v) = l
                .split_once(':')
                .ok_or_else(|| format!("bad header line {l:?}"))?;
            headers.push((k.to_string(), v.trim_start().to_string()));
        }
        Ok(Request {
            method,
            target,
            version,
            headers,
            eol,
            body: body.to_vec(),
        })
    }

    fn head(&self) -> Vec<u8> {
        let mut s = format!(
            "{} {} {}{}",
            self.method, self.target, self.version, self.eol
        );
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}{}", self.eol));
        }
        s.push_str(self.eol);
        s.into_bytes()
    }

    fn set_header(&mut self, name: &str, value: &str) {
        match self
            .headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            Some(h) => h.1 = value.to_string(),
            None => self.headers.push((name.to_string(), value.to_string())),
        }
        // A replaced header's duplicates go too, so the edit means what it says.
        let mut seen = false;
        self.headers.retain(|(k, _)| {
            if !k.eq_ignore_ascii_case(name) {
                return true;
            }
            let keep = !seen;
            seen = true;
            keep
        });
    }

    fn query(&mut self, f: impl FnOnce(&mut Vec<(String, String)>)) {
        let (path, q) = match self.target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (self.target.clone(), String::new()),
        };
        let mut pairs: Vec<(String, String)> = q
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (k.to_string(), v.to_string())
            })
            .collect();
        f(&mut pairs);
        self.target = if pairs.is_empty() {
            path
        } else {
            let q: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{path}?{}", q.join("&"))
        };
    }
}

/// Apply `edits`, in order, to a stored request. Returns the new head and body.
pub fn apply_edits(head: &[u8], body: &[u8], edits: &[Edit]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut r = Request::parse(head, body)?;
    let mut body_changed = false;
    for e in edits {
        match e {
            Edit::SetHeader { name, value } => {
                if value.contains(['\r', '\n']) || name.contains(['\r', '\n', ':']) {
                    return Err("set_header: a name or value may not contain a line break".into());
                }
                r.set_header(name, value);
            }
            Edit::RemoveHeader { name } => r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name)),
            Edit::SetQuery { name, value } => {
                r.query(|q| match q.iter_mut().find(|(k, _)| k == name) {
                    Some(p) => p.1 = value.clone(),
                    None => q.push((name.clone(), value.clone())),
                })
            }
            Edit::RemoveQuery { name } => r.query(|q| q.retain(|(k, _)| k != name)),
            Edit::SetPath { value } => {
                if !value.starts_with('/') || value.contains([' ', '\r', '\n']) {
                    return Err("set_path: a path starts with `/` and has no spaces".into());
                }
                let q = r.target.split_once('?').map(|(_, q)| q.to_string());
                r.target = match q {
                    Some(q) => format!("{value}?{q}"),
                    None => value.clone(),
                };
            }
            Edit::SetMethod { value } => {
                if value.is_empty() || value.contains([' ', '\r', '\n']) {
                    return Err("set_method: not a token".into());
                }
                r.method = value.clone();
            }
            Edit::JsonSet { pointer, value } => {
                let mut v: Value = serde_json::from_slice(&r.body)
                    .map_err(|e| format!("json_set: body is not JSON: {e}"))?;
                json_set(&mut v, pointer, value.clone())?;
                r.body = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
                body_changed = true;
            }
            Edit::JsonRemove { pointer } => {
                let mut v: Value = serde_json::from_slice(&r.body)
                    .map_err(|e| format!("json_remove: body is not JSON: {e}"))?;
                json_remove(&mut v, pointer)?;
                r.body = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
                body_changed = true;
            }
            Edit::FormSet { name, value } => {
                let text = String::from_utf8_lossy(&r.body).into_owned();
                let mut pairs: Vec<(String, String)> = text
                    .split('&')
                    .filter(|s| !s.is_empty())
                    .map(|kv| {
                        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                        (k.to_string(), v.to_string())
                    })
                    .collect();
                match pairs.iter_mut().find(|(k, _)| k == name) {
                    Some(p) => p.1 = value.clone(),
                    None => pairs.push((name.clone(), value.clone())),
                }
                let s: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
                r.body = s.join("&").into_bytes();
                body_changed = true;
            }
            Edit::Replace {
                part,
                find,
                replace,
                regex,
            } => {
                let apply = |s: &str| -> Result<String, String> {
                    if *regex {
                        let re = regex::RegexBuilder::new(find)
                            .size_limit(1 << 20)
                            .build()
                            .map_err(|e| format!("replace: {e}"))?;
                        Ok(re.replace_all(s, replace.as_str()).into_owned())
                    } else {
                        Ok(s.replace(find.as_str(), replace))
                    }
                };
                match part {
                    Part::Body => {
                        r.body = apply(&String::from_utf8_lossy(&r.body))?.into_bytes();
                        body_changed = true;
                    }
                    Part::Head => {
                        let new = apply(&String::from_utf8_lossy(&r.head()))?;
                        r = Request::parse(new.as_bytes(), &r.body)?;
                    }
                }
            }
            Edit::SetBody { text, base64 } => {
                r.body = match (text, base64) {
                    (Some(t), None) => t.clone().into_bytes(),
                    (None, Some(b)) => crate::tools::http_send::b64(b)?,
                    _ => return Err("set_body: give exactly one of text or base64".into()),
                };
                body_changed = true;
            }
        }
    }
    if body_changed {
        let has_len = r
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        let chunked = r.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        if !chunked && (has_len || !r.body.is_empty()) {
            let n = r.body.len().to_string();
            r.set_header("Content-Length", &n);
        }
    }
    Ok((r.head(), r.body))
}

fn json_set(v: &mut Value, pointer: &str, new: Value) -> Result<(), String> {
    if pointer.is_empty() {
        *v = new;
        return Ok(());
    }
    let (parent, last) = pointer
        .rsplit_once('/')
        .ok_or_else(|| format!("json pointer {pointer:?} must start with `/`"))?;
    let key = last.replace("~1", "/").replace("~0", "~");
    let target = if parent.is_empty() {
        Some(v)
    } else {
        v.pointer_mut(parent)
    }
    .ok_or_else(|| format!("no parent at {parent}"))?;
    match target {
        Value::Object(m) => {
            m.insert(key, new);
            Ok(())
        }
        Value::Array(a) => {
            let i: usize = key.parse().map_err(|_| format!("{key} is not an index"))?;
            if i < a.len() {
                a[i] = new;
            } else if i == a.len() {
                a.push(new);
            } else {
                return Err(format!("index {i} out of range"));
            }
            Ok(())
        }
        _ => Err(format!("{parent} is not an object or array")),
    }
}

fn json_remove(v: &mut Value, pointer: &str) -> Result<(), String> {
    let (parent, last) = pointer
        .rsplit_once('/')
        .ok_or_else(|| format!("json pointer {pointer:?} must start with `/`"))?;
    let key = last.replace("~1", "/").replace("~0", "~");
    let target = if parent.is_empty() {
        Some(v)
    } else {
        v.pointer_mut(parent)
    }
    .ok_or_else(|| format!("no parent at {parent}"))?;
    match target {
        Value::Object(m) => m
            .remove(&key)
            .map(|_| ())
            .ok_or_else(|| format!("no key {key}")),
        Value::Array(a) => {
            let i: usize = key.parse().map_err(|_| format!("{key} is not an index"))?;
            if i < a.len() {
                a.remove(i);
                Ok(())
            } else {
                Err(format!("index {i} out of range"))
            }
        }
        _ => Err(format!("{parent} is not an object or array")),
    }
}

// ── the diff ─────────────────────────────────────────────────────────────────────────────────────

/// Headers volatile regardless of any probe (research R10).
pub const VOLATILE_HEADERS: &[&str] = &[
    "date",
    "expires",
    "age",
    "last-modified",
    "etag",
    "x-request-id",
    "x-amzn-requestid",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "cf-ray",
    "server-timing",
    "set-cookie",
    "content-length",
];

/// One response, as the diff sees it.
pub struct Side {
    pub status: Option<u16>,
    pub head: Vec<u8>,
    /// Decoded body.
    pub body: Vec<u8>,
    pub elapsed_ms: Option<u64>,
}

fn headers(head: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(head)
        .split('\n')
        .skip(1)
        .map(|l| l.trim_end_matches('\r'))
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

fn header_map(head: &[u8]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut m: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (k, v) in headers(head) {
        m.entry(k).or_default().push(v);
    }
    m
}

/// JSON pointer paths that differ between two documents.
fn json_paths(a: &Value, b: &Value) -> Vec<String> {
    let patch = json_patch::diff(a, b);
    let mut paths: Vec<String> = patch
        .0
        .iter()
        .map(|op| match op {
            json_patch::PatchOperation::Add(o) => o.path.to_string(),
            json_patch::PatchOperation::Remove(o) => o.path.to_string(),
            json_patch::PatchOperation::Replace(o) => o.path.to_string(),
            json_patch::PatchOperation::Move(o) => o.path.to_string(),
            json_patch::PatchOperation::Copy(o) => o.path.to_string(),
            json_patch::PatchOperation::Test(o) => o.path.to_string(),
        })
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// The `http_replay` diff (contracts/http-tools.md#http_replay) of `new` against `original`, with
/// whatever `probe` shows to be volatile suppressed. Bounded: at most 40 hunks of ≤ 3 context lines.
pub fn diff(original: &Side, new: &Side, probe: Option<&Side>) -> Value {
    let mut volatile: Vec<String> = Vec::new();

    // Headers.
    let (ho, hn) = (header_map(&original.head), header_map(&new.head));
    let hp = probe.map(|p| header_map(&p.head));
    let is_volatile_header = |k: &str| {
        VOLATILE_HEADERS.contains(&k) || hp.as_ref().is_some_and(|p| p.get(k) != ho.get(k))
    };
    let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    let mut keys: Vec<&String> = ho.keys().chain(hn.keys()).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        // Volatility is reported as identified, whether or not it moved in this particular pair:
        // the model learns which values are noise, not only which happened to change this time.
        if is_volatile_header(k) {
            volatile.push(format!("header:{k}"));
            continue;
        }
        let (a, b) = (ho.get(k), hn.get(k));
        if a == b {
            continue;
        }
        match (a, b) {
            (None, Some(_)) => added.push(k.clone()),
            (Some(_), None) => removed.push(k.clone()),
            _ => changed.push(k.clone()),
        }
    }

    // Body.
    let as_json = |b: &[u8]| serde_json::from_slice::<Value>(b).ok();
    let body = match (as_json(&original.body), as_json(&new.body)) {
        (Some(a), Some(b)) => {
            let probe_paths: Vec<String> = probe
                .and_then(|p| as_json(&p.body))
                .map(|p| json_paths(&a, &p))
                .unwrap_or_default();
            volatile.extend(probe_paths.iter().cloned());
            let mut paths = json_paths(&a, &b);
            paths.retain(|p| {
                !probe_paths
                    .iter()
                    .any(|q| p == q || p.starts_with(&format!("{q}/")))
            });
            json!({ "kind": "json", "json_paths_changed": paths })
        }
        _ => {
            let text = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
            match (text(&original.body), text(&new.body)) {
                (Some(a), Some(b)) => {
                    let d = similar::TextDiff::from_lines(&a, &b);
                    let hunks: Vec<String> = d
                        .unified_diff()
                        .context_radius(3)
                        .iter_hunks()
                        .take(40)
                        .map(|h| {
                            let s = h.to_string();
                            if s.len() > 2048 {
                                format!("{}… [hunk cut]", &s[..s.floor_char_boundary_compat(2048)])
                            } else {
                                s
                            }
                        })
                        .collect();
                    json!({ "kind": "text", "hunks": hunks })
                }
                _ => json!({
                    "kind": "binary",
                    "same": original.body == new.body,
                }),
            }
        }
    };

    volatile.sort();
    volatile.dedup();
    let length = [original.body.len(), new.body.len()];
    json!({
        "status": [original.status, new.status],
        "length": length,
        "elapsed_ms": [original.elapsed_ms, new.elapsed_ms],
        "headers": { "added": added, "removed": removed, "changed": changed },
        "body": body,
        "volatile_suppressed": { "count": volatile.len(), "paths": volatile },
    })
}

/// `str::floor_char_boundary` is unstable; this is the stable spelling.
trait FloorBoundary {
    fn floor_char_boundary_compat(&self, i: usize) -> usize;
}

impl FloorBoundary for str {
    fn floor_char_boundary_compat(&self, mut i: usize) -> usize {
        if i >= self.len() {
            return self.len();
        }
        while !self.is_char_boundary(i) {
            i -= 1;
        }
        i
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &[u8] = b"POST /api/x?a=1&b=2 HTTP/1.1\r\nHost: t\r\nX-Dup: 1\r\nx-dup: 2\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n";
    const BODY: &[u8] = br#"{"user":{"role":"guest"}}"#;

    #[test]
    fn json_set_rewrites_the_body_and_its_length() {
        let (h, b) = apply_edits(
            HEAD,
            BODY,
            &[Edit::JsonSet {
                pointer: "/user/role".into(),
                value: json!("admin"),
            }],
        )
        .unwrap();
        assert_eq!(b, br#"{"user":{"role":"admin"}}"#);
        let h = String::from_utf8(h).unwrap();
        assert!(
            h.contains(&format!("Content-Length: {}\r\n", b.len())),
            "{h}"
        );
        assert!(
            h.starts_with("POST /api/x?a=1&b=2 HTTP/1.1\r\nHost: t\r\nX-Dup: 1\r\nx-dup: 2\r\n"),
            "{h}"
        );
    }

    #[test]
    fn head_edits_preserve_order_and_casing() {
        let (h, _) = apply_edits(
            HEAD,
            BODY,
            &[
                Edit::SetHeader {
                    name: "x-forwarded-for".into(),
                    value: "127.0.0.1".into(),
                },
                Edit::SetQuery {
                    name: "a".into(),
                    value: "9".into(),
                },
                Edit::RemoveQuery { name: "b".into() },
                Edit::SetMethod {
                    value: "PUT".into(),
                },
            ],
        )
        .unwrap();
        let h = String::from_utf8(h).unwrap();
        assert!(h.starts_with("PUT /api/x?a=9 HTTP/1.1\r\n"), "{h}");
        assert!(h.contains("X-Dup: 1\r\nx-dup: 2\r\n"), "{h}");
        assert!(h.contains("x-forwarded-for: 127.0.0.1\r\n"), "{h}");
    }

    #[test]
    fn a_header_value_cannot_smuggle_a_line() {
        assert!(apply_edits(
            HEAD,
            BODY,
            &[Edit::SetHeader {
                name: "X".into(),
                value: "a\r\nB: c".into()
            }]
        )
        .is_err());
    }

    #[test]
    fn edits_parse_from_the_model_shape() {
        let e: Vec<Edit> = serde_json::from_value(json!([
            {"set_header": {"name": "X-Forwarded-For", "value": "127.0.0.1"}},
            {"json_set": {"pointer": "/user/role", "value": "admin"}},
            {"replace": {"in": "body", "find": "a", "replace": "b"}}
        ]))
        .unwrap();
        assert_eq!(e.len(), 3);
        assert!(serde_json::from_value::<Edit>(json!({"set_hedaer": {}})).is_err());
    }

    #[test]
    fn the_probe_suppresses_what_moves_by_itself() {
        let side = |status: u16, date: &str, body: &str| Side {
            status: Some(status),
            head: format!("HTTP/1.1 {status} X\r\nDate: {date}\r\nX-A: 1\r\n\r\n").into_bytes(),
            body: body.as_bytes().to_vec(),
            elapsed_ms: Some(5),
        };
        let orig = side(
            200,
            "d1",
            r#"{"user":{"role":"guest"},"meta":{"request_id":"r1"}}"#,
        );
        let probe = side(
            200,
            "d2",
            r#"{"user":{"role":"guest"},"meta":{"request_id":"r2"}}"#,
        );
        let new = side(
            200,
            "d3",
            r#"{"user":{"role":"admin"},"meta":{"request_id":"r3"}}"#,
        );
        let d = diff(&orig, &new, Some(&probe));
        assert_eq!(d["body"]["json_paths_changed"], json!(["/user/role"]));
        let v = d["volatile_suppressed"]["paths"].as_array().unwrap();
        assert!(
            v.contains(&json!("header:date")) && v.contains(&json!("/meta/request_id")),
            "{v:?}"
        );
    }
}
