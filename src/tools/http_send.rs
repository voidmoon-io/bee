//! `http_send` (019 T055/T056, contracts/http-tools.md#http_send).
//!
//! Two shapes, exactly one per call:
//! - `raw` — bytes sent **byte for byte** (FR-018); bee adds nothing;
//! - `request` — method, URL, an ordered list of header pairs (duplicates and casing preserved) and
//!   a body, serialised to raw bytes **here, in the harness**, so the worker has one send path.
//!   `Host` and `Content-Length` are added only when absent.
//!
//! The worker checks scope before any connect (proxy-control invariant 2) and records a refusal as a
//! proxy event attributed to the call. `follow_redirects` (≤ 5) scope-checks every hop and stops at
//! the first that leaves scope, reporting it (FR-023).

use std::time::Duration;

use serde_json::{json, Value};

use crate::intercept::control::{OriginKind, RawTarget, WireCtx};
use crate::intercept::sidecar::{InterceptError, Interceptor, Sent};
use crate::intercept::worker::scope::ScopeChecker;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{bounded_json, invalid, live, with_notices};
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult, UnavailableReason};

pub const BOUND: usize = 4 * 1024;
const MAX_REDIRECTS: u32 = 5;
const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const PREVIEW: usize = 1024;

pub struct HttpSend {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpSend {
    fn name(&self) -> &'static str {
        "http_send"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_send".into(),
            description: "Send one HTTP/1.1 request to an in-scope target through the session's \
                          interception proxy, and record it. Give either `request` (method, url, \
                          ordered header pairs, body) or `raw` (exact bytes, sent unmodified). \
                          Returns an exchange id, status, timing and a short preview; use \
                          `http_get` to read more of it. Out-of-scope and egress-only hosts are \
                          refused."
                .into(),
            parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "request": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "method": { "type": "string" },
                            "url": { "type": "string", "description": "http:// or https:// URL" },
                            "headers": { "type": "array", "items": { "type": "array", "items": { "type": "string" }, "minItems": 2, "maxItems": 2 } },
                            "body": { "type": "string" },
                            "body_base64": { "type": "string" }
                        },
                        "required": ["url"]
                    },
                    "raw": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "scheme": { "type": "string", "enum": ["http", "https"] },
                            "host": { "type": "string" },
                            "port": { "type": "integer" },
                            "bytes": { "type": "string" },
                            "bytes_base64": { "type": "string" }
                        },
                        "required": ["scheme", "host", "port"]
                    },
                    "baseline": { "type": "string", "description": "exchange id to diff against (needs http_replay, M2)" },
                    "follow_redirects": { "type": "integer", "minimum": 0, "maximum": 5 },
                    "timeout_ms": { "type": "integer", "minimum": 1 },
                    "tags": { "type": "array", "items": { "type": "string" } }
                }
            }),
        }
    }

    async fn call(&self, args: Value, sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let parsed = match parse_args(&args) {
            Ok(p) => p,
            Err(e) => return invalid("http_send", e),
        };
        if parsed.baseline.is_some() {
            return invalid("http_send", "baseline requires http_replay (M2)");
        }
        let ctx = call_ctx(sandbox);
        let scope = ScopeChecker::new(icpt.http_scope());

        let mut target = parsed.target;
        let mut bytes = parsed.bytes;
        let mut redirects: Vec<Value> = Vec::new();
        let mut hops_left = parsed.follow_redirects;
        loop {
            // No harness-side gate here: the worker decides, and records the refusal as a proxy
            // event attributed to this call — which is what lets the operator be asked to widen
            // the scope (US3). One decision, in one place, on the proxy layer.
            let sent = match icpt
                .send(
                    target.clone(),
                    bytes.clone(),
                    ctx.clone(),
                    OriginKind::Tool,
                    None,
                    parsed.tags.clone(),
                    parsed.timeout,
                )
                .await
            {
                Ok(s) => s,
                Err(InterceptError::Unavailable(d)) => return crate::tools::http::unavailable(&d),
                Err(e) => {
                    return ToolOutcome::<()>::failed(e.to_string())
                        .into_tool_result(|_| String::new())
                }
            };
            if let crate::intercept::control::Outcome::Refused { kind } = &sent.record.outcome {
                return refusal(kind, &target, &redirects);
            }
            let next = match (hops_left, sent.record.status) {
                (n, Some(st)) if n > 0 && matches!(st, 301 | 302 | 303 | 307 | 308) => {
                    redirect_target(icpt, &sent, &target, st)
                }
                _ => None,
            };
            match next {
                None => return render(icpt, &sent, redirects),
                Some(Err(stop)) => {
                    redirects.push(json!({ "id": sent.exchange_id, "status": sent.record.status, "stopped": stop }));
                    return render(icpt, &sent, redirects);
                }
                Some(Ok((t, b))) => {
                    redirects.push(json!({
                        "id": sent.exchange_id,
                        "status": sent.record.status,
                        "location": format!("{}://{}:{}", t.scheme, t.host, t.port),
                    }));
                    if scope.check_testable(&t.host, t.port).is_err() {
                        if let Some(last) = redirects.last_mut() {
                            last["stopped"] = json!(format!(
                                "next hop {}:{} is out of scope; not followed",
                                t.host, t.port
                            ));
                        }
                        return render(icpt, &sent, redirects);
                    }
                    target = t;
                    bytes = b;
                    hops_left -= 1;
                }
            }
        }
    }
}

struct Parsed {
    target: RawTarget,
    bytes: Vec<u8>,
    baseline: Option<String>,
    follow_redirects: u32,
    timeout: Duration,
    tags: Vec<String>,
}

fn parse_args(a: &Value) -> Result<Parsed, String> {
    let obj = a.as_object().ok_or("arguments must be an object")?;
    for k in obj.keys() {
        if ![
            "request",
            "raw",
            "baseline",
            "follow_redirects",
            "timeout_ms",
            "tags",
        ]
        .contains(&k.as_str())
        {
            return Err(format!("unknown argument `{k}`"));
        }
    }
    let (target, bytes) = match (obj.get("request"), obj.get("raw")) {
        (Some(r), None) => structured(r)?,
        (None, Some(r)) => raw(r)?,
        _ => return Err("give exactly one of `request` or `raw`".into()),
    };
    let follow_redirects = obj
        .get("follow_redirects")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if follow_redirects > u64::from(MAX_REDIRECTS) {
        return Err(format!("follow_redirects is at most {MAX_REDIRECTS}"));
    }
    let timeout_ms = obj
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(1, MAX_TIMEOUT_MS);
    let tags = obj
        .get("tags")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .take(16)
                .collect()
        })
        .unwrap_or_default();
    Ok(Parsed {
        target,
        bytes,
        baseline: obj
            .get("baseline")
            .and_then(Value::as_str)
            .map(str::to_string),
        follow_redirects: follow_redirects as u32,
        timeout: Duration::from_millis(timeout_ms),
        tags,
    })
}

fn raw(r: &Value) -> Result<(RawTarget, Vec<u8>), String> {
    let scheme = r
        .get("scheme")
        .and_then(Value::as_str)
        .ok_or("raw.scheme is required")?;
    if scheme != "http" && scheme != "https" {
        return Err("raw.scheme must be http or https".into());
    }
    let host = r
        .get("host")
        .and_then(Value::as_str)
        .ok_or("raw.host is required")?;
    let port = r
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .ok_or("raw.port must be 1–65535")? as u16;
    let bytes = match (r.get("bytes"), r.get("bytes_base64")) {
        (Some(Value::String(s)), None) => s.as_bytes().to_vec(),
        (None, Some(Value::String(b))) => b64(b)?,
        _ => return Err("give exactly one of raw.bytes or raw.bytes_base64".into()),
    };
    if bytes.is_empty() {
        return Err("raw request is empty".into());
    }
    Ok((
        RawTarget {
            scheme: scheme.into(),
            host: bee_core::pattern::normalize_host(host),
            port,
        },
        bytes,
    ))
}

/// Serialise a structured request to HTTP/1.1 bytes (T055).
pub fn structured(r: &Value) -> Result<(RawTarget, Vec<u8>), String> {
    let url = r
        .get("url")
        .and_then(Value::as_str)
        .ok_or("request.url is required")?;
    let (target, origin_form, authority) = split_url(url)?;
    let method = r.get("method").and_then(Value::as_str).unwrap_or("GET");
    if method.is_empty()
        || method
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("request.method is not a token".into());
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(h) = r.get("headers") {
        let arr = h
            .as_array()
            .ok_or("request.headers must be a list of [name, value] pairs")?;
        for pair in arr {
            let p = pair
                .as_array()
                .filter(|p| p.len() == 2)
                .ok_or("each header is a [name, value] pair")?;
            let (Some(k), Some(v)) = (p[0].as_str(), p[1].as_str()) else {
                return Err("header names and values are strings".into());
            };
            if k.bytes()
                .any(|b| b == b':' || b.is_ascii_control() || b == b' ')
                || k.is_empty()
            {
                return Err(format!("invalid header name {k:?}"));
            }
            if v.bytes().any(|b| b == b'\r' || b == b'\n') {
                return Err(format!(
                    "header {k} contains a line break; use `raw` to send that"
                ));
            }
            headers.push((k.to_string(), v.to_string()));
        }
    }
    let body = match (r.get("body"), r.get("body_base64")) {
        (Some(Value::String(s)), None) => s.as_bytes().to_vec(),
        (None, Some(Value::String(b))) => b64(b)?,
        (None, None) => Vec::new(),
        _ => return Err("give at most one of request.body or request.body_base64".into()),
    };
    let has = |n: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    let mut out = format!("{method} {origin_form} HTTP/1.1\r\n");
    if !has("host") {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    for (k, v) in &headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() && !has("content-length") && !has("transfer-encoding") {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    Ok((target, bytes))
}

/// `http(s)://host[:port][/path?query]` → target, origin-form, and the authority for `Host`.
fn split_url(url: &str) -> Result<(RawTarget, String, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("url needs a scheme (http:// or https://)")?;
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err(format!("unsupported scheme `{scheme}`")),
    };
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..split];
    if authority.contains('@') {
        return Err("userinfo in the url is not supported; send an Authorization header".into());
    }
    let mut path = rest[split..].split('#').next().unwrap_or("").to_string();
    if path.is_empty() || path.starts_with('?') {
        path.insert(0, '/');
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => match p.parse::<u16>() {
            Ok(p) => (h, p),
            Err(_) if authority.starts_with('[') && authority.ends_with(']') => {
                (authority, default)
            }
            Err(_) => return Err(format!("invalid port in {authority}")),
        },
        _ => (authority, default),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("url has no host".into());
    }
    Ok((
        RawTarget {
            scheme,
            host: bee_core::pattern::normalize_host(host),
            port,
        },
        path,
        authority.to_string(),
    ))
}

/// The next hop of a redirect: `Ok((target, GET bytes))`, or `Err(reason)` when it cannot be
/// followed. `None` when there is no `Location`.
fn redirect_target(
    icpt: &Interceptor,
    sent: &Sent,
    from: &RawTarget,
    status: u16,
) -> Option<Result<(RawTarget, Vec<u8>), String>> {
    let head = icpt
        .with_store(|s| s.get_exchange(&sent.exchange_id).ok().flatten())?
        .resp_head;
    let text = String::from_utf8_lossy(&head).into_owned();
    let loc = text.split('\n').skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("location")
            .then(|| v.trim().to_string())
    })?;
    let url = if loc.contains("://") {
        loc
    } else if loc.starts_with('/') {
        format!("{}://{}:{}{}", from.scheme, from.host, from.port, loc)
    } else {
        return Some(Err(format!("relative Location `{loc}` is not followed")));
    };
    // 307/308 would repeat the body; bee follows them as GET only when the original had none, so
    // simplest and safest: every hop is a GET. The hop list says so.
    let _ = status;
    Some(structured(&json!({ "method": "GET", "url": url })))
}

fn refusal(
    kind: &crate::intercept::control::ProxyEventKind,
    t: &RawTarget,
    redirects: &[Value],
) -> ToolResult {
    use crate::intercept::control::ProxyEventKind as K;
    let reason = match kind {
        K::RefusedEgressOnly => UnavailableReason::EgressOnly {
            host: t.host.clone(),
        },
        K::RefusedLimit => UnavailableReason::LimitExceeded {
            limit: "rps/concurrency".into(),
            value: 0,
        },
        _ => UnavailableReason::OutOfScope {
            host: t.host.clone(),
            port: t.port,
            layer: format!("proxy ({})", kind.as_str()),
        },
    };
    let mut r = ToolOutcome::<()>::unavailable(reason).into_tool_result(|_| String::new());
    if !redirects.is_empty() {
        r.content.push_str(&format!(
            "\nredirects followed before the refusal: {}",
            serde_json::to_string(redirects).unwrap_or_default()
        ));
    }
    r
}

/// The bounded `http_send` result.
fn render(icpt: &Interceptor, sent: &Sent, redirects: Vec<Value>) -> ToolResult {
    let stored = icpt.with_store(|s| s.get_exchange(&sent.exchange_id).ok().flatten());
    let (content_type, headers_preview, body_preview) = match &stored {
        Some(e) => {
            let text = String::from_utf8_lossy(&e.resp_head).into_owned();
            let headers: Vec<(String, String)> = text
                .split('\n')
                .skip(1)
                .map_while(|l| {
                    let l = l.trim_end_matches('\r');
                    (!l.is_empty()).then(|| l.split_once(':'))
                })
                .flatten()
                .map(|(k, v)| (k.trim().to_string(), clip(v.trim(), 200)))
                .collect();
            let ct = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone());
            let preview = body_preview(icpt, e);
            (
                ct,
                headers.into_iter().take(12).collect::<Vec<_>>(),
                preview,
            )
        }
        None => (None, Vec::new(), String::new()),
    };
    let r = &sent.record;
    let mut v = json!({
        "id": sent.exchange_id,
        "status": r.status,
        "elapsed_ms": r.timing.total_ms,
        "resp_bytes": r.resp_bytes,
        "content_type": content_type,
        "headers_preview": headers_preview,
        "body_preview": body_preview,
        "redirects": redirects,
        "enforcement": icpt.enforcement().label(),
    });
    if let crate::intercept::control::Outcome::Failed { reason } = &r.outcome {
        v["failed"] = json!(reason);
    }
    if r.resp_truncated {
        v["stored_truncated"] = json!(true);
    }
    let body = with_notices(bounded_json(&v, BOUND), icpt);
    let mut res = if matches!(r.outcome, crate::intercept::control::Outcome::Failed { .. }) {
        ToolResult::error(body)
    } else {
        ToolResult::ok(body)
    };
    res = res.with_provenance(Provenance::Remote {
        source: format!("http:{}", sent.exchange_id),
    });
    res
}

fn body_preview(icpt: &Interceptor, e: &crate::intercept::store::StoredExchange) -> String {
    let Some(sha) = &e.resp_body else {
        return String::new();
    };
    let (Some(raw), Some(meta)) = icpt.with_store(|s| {
        (
            s.read_blob(sha).ok().flatten(),
            s.blob_meta(sha).ok().flatten(),
        )
    }) else {
        return "(body evicted)".into();
    };
    match crate::intercept::slice::decode(&raw, &meta.encoding, 64 * 1024) {
        Ok(d) => clip(
            &crate::tools::http::text_or_binary(&d.bytes[..d.bytes.len().min(PREVIEW)]),
            PREVIEW,
        ),
        Err(err) => format!("(cannot decode: {err})"),
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut c = max;
    while !s.is_char_boundary(c) {
        c -= 1;
    }
    format!("{}…", &s[..c])
}

/// The current call's attribution, from the sandbox's call context.
pub(crate) fn call_ctx(sandbox: &Sandbox) -> WireCtx {
    match sandbox.call_context() {
        Some(c) => crate::intercept::creds::wire_ctx(c),
        None => WireCtx {
            call_id: "unattributed".into(),
            turn: 0,
            origin: "tool".into(),
        },
    }
}

/// Standard base64 (padding optional).
pub(crate) fn b64(s: &str) -> Result<Vec<u8>, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_requests_serialise_in_order() {
        let (t, b) = structured(&json!({
            "method": "POST",
            "url": "https://App.test:8443/api/x?y=1#frag",
            "headers": [["X-A", "1"], ["x-a", "2"], ["Content-Type", "application/json"]],
            "body": "{\"a\":1}"
        }))
        .unwrap();
        assert_eq!(
            (t.scheme.as_str(), t.host.as_str(), t.port),
            ("https", "app.test", 8443)
        );
        let s = String::from_utf8(b).unwrap();
        assert_eq!(
            s,
            "POST /api/x?y=1 HTTP/1.1\r\nHost: App.test:8443\r\nX-A: 1\r\nx-a: 2\r\n\
             Content-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"
        );
    }

    #[test]
    fn an_explicit_host_is_not_duplicated() {
        let (_, b) =
            structured(&json!({ "url": "http://a.test/", "headers": [["host", "b.test"]] }))
                .unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            "GET / HTTP/1.1\r\nhost: b.test\r\n\r\n"
        );
    }

    #[test]
    fn header_injection_is_refused_in_structured_form() {
        assert!(
            structured(&json!({ "url": "http://a.test/", "headers": [["X", "a\r\nY: b"]] }))
                .is_err()
        );
        assert!(structured(&json!({ "url": "ftp://a.test/" })).is_err());
    }

    #[test]
    fn urls_split() {
        let (t, p, a) = split_url("http://[::1]:8080/x").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, p.as_str(), a.as_str()),
            ("::1", 8080, "/x", "[::1]:8080")
        );
        let (t, p, _) = split_url("https://h.test?q=1").unwrap();
        assert_eq!((t.port, p.as_str()), (443, "/?q=1"));
    }
}
