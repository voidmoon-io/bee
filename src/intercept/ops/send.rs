//! Send one request through the proxy, following redirects within the Target scope (FR-035).
//!
//! The worker checks scope before any connect (proxy-control invariant 2) and records a refusal as a
//! proxy event attributed to the call. Redirect following (≤ 5 hops, every hop a GET) scope-checks
//! each hop and stops at the first that leaves scope, reporting it (019 FR-023).

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::bound::{clip, text_or_binary};
use super::{CallCtx, OpError, Refusal};
use crate::intercept::control::{OriginKind, Outcome, RawTarget};
use crate::intercept::sidecar::{Interceptor, Sent};
use crate::intercept::worker::scope::ScopeChecker;

/// The most redirect hops a send follows.
pub const MAX_REDIRECTS: u32 = 5;
/// Bytes of the response body shown in [`Preview::body`].
const PREVIEW: usize = 1024;

/// A request in structured form: serialised to HTTP/1.1 bytes by [`build_request`], so the worker
/// has one send path. Header order, duplicates and casing are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredRequest {
    pub method: String,
    /// An `http://` or `https://` URL.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SendSpec {
    pub target: RawTarget,
    /// Sent byte for byte (019 FR-018).
    pub bytes: Vec<u8>,
    /// At most [`MAX_REDIRECTS`].
    pub follow_redirects: u32,
    pub timeout: Duration,
    pub tags: Vec<String>,
    /// An earlier exchange to diff the response against.
    pub baseline: Option<String>,
}

/// One redirect hop: the exchange that answered with it, and where it led — or why it stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub id: String,
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
}

/// A short look at the last response, read back from the store.
#[derive(Debug, Clone, Default)]
pub struct Preview {
    pub content_type: Option<String>,
    /// The first headers, values clipped.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct SendResult {
    /// The last exchange sent: the final response, or the refused hop.
    pub last: Sent,
    pub hops: Vec<Hop>,
    /// Set when the proxy refused the last hop; `preview` and `diff` are then empty.
    pub refused: Option<Refusal>,
    pub preview: Preview,
    /// The diff against `baseline`, in `http_replay`'s shape, when one was asked for.
    pub diff: Option<Value>,
}

/// Send `spec`, following redirects within scope.
pub async fn send(
    icpt: &Interceptor,
    ctx: &CallCtx,
    spec: SendSpec,
) -> Result<SendResult, OpError> {
    if let Some(b) = &spec.baseline {
        match icpt.with_store(|s| s.exchange_exists(b)) {
            Ok(true) => {}
            Ok(false) => return Err(OpError::Invalid(format!("no baseline exchange `{b}`"))),
            Err(e) => return Err(OpError::Invalid(e.to_string())),
        }
    }
    let scope = ScopeChecker::new(icpt.http_scope());
    let mut target = spec.target;
    let mut bytes = spec.bytes;
    let mut hops: Vec<Hop> = Vec::new();
    let mut hops_left = spec.follow_redirects.min(MAX_REDIRECTS);
    loop {
        // No harness-side gate here: the worker decides, and records the refusal as a proxy event
        // attributed to this call — which is what lets the operator be asked to widen the scope
        // (019 US3). One decision, in one place, on the proxy layer.
        let sent = icpt
            .send(
                target.clone(),
                bytes.clone(),
                ctx.clone(),
                OriginKind::Tool,
                None,
                spec.tags.clone(),
                spec.timeout,
            )
            .await?;
        if let Outcome::Refused { kind } = &sent.record.outcome {
            let refused = Some(Refusal::from_proxy(kind, &target));
            return Ok(SendResult {
                last: sent,
                hops,
                refused,
                preview: Preview::default(),
                diff: None,
            });
        }
        let next = match (hops_left, sent.record.status) {
            (n, Some(st)) if n > 0 && matches!(st, 301 | 302 | 303 | 307 | 308) => {
                redirect_target(icpt, &sent, &target)
            }
            _ => None,
        };
        match next {
            None => return Ok(finish(icpt, sent, hops, spec.baseline.as_deref())),
            Some(Err(stop)) => {
                hops.push(Hop {
                    id: sent.exchange_id.clone(),
                    status: sent.record.status,
                    location: None,
                    stopped: Some(stop),
                });
                return Ok(finish(icpt, sent, hops, spec.baseline.as_deref()));
            }
            Some(Ok((t, b))) => {
                let mut hop = Hop {
                    id: sent.exchange_id.clone(),
                    status: sent.record.status,
                    location: Some(format!("{}://{}:{}", t.scheme, t.host, t.port)),
                    stopped: None,
                };
                if scope.check_testable(&t.host, t.port).is_err() {
                    hop.stopped = Some(format!(
                        "next hop {}:{} is out of scope; not followed",
                        t.host, t.port
                    ));
                    hops.push(hop);
                    return Ok(finish(icpt, sent, hops, spec.baseline.as_deref()));
                }
                hops.push(hop);
                target = t;
                bytes = b;
                hops_left -= 1;
            }
        }
    }
}

/// Serialise a structured request to HTTP/1.1 bytes (019 T055). `Host` and `Content-Length` are
/// added only when absent.
pub fn build_request(r: StructuredRequest) -> Result<(RawTarget, Vec<u8>), OpError> {
    build(r).map_err(OpError::Invalid)
}

fn build(r: StructuredRequest) -> Result<(RawTarget, Vec<u8>), String> {
    let (target, origin_form, authority) = split_url(&r.url)?;
    let method = r.method.as_str();
    if method.is_empty()
        || method
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("request.method is not a token".into());
    }
    for (k, v) in &r.headers {
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
    }
    let has = |n: &str| r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    let mut out = format!("{method} {origin_form} HTTP/1.1\r\n");
    if !has("host") {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !r.body.is_empty() && !has("content-length") && !has("transfer-encoding") {
        out.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&r.body);
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
    Some(build(StructuredRequest {
        method: "GET".into(),
        url,
        headers: Vec::new(),
        body: Vec::new(),
    }))
}

/// The result for the last response: its preview, and the diff against `baseline` (no noise probe —
/// the caller chose what to compare).
fn finish(icpt: &Interceptor, sent: Sent, hops: Vec<Hop>, baseline: Option<&str>) -> SendResult {
    let preview = match icpt.with_store(|s| s.get_exchange(&sent.exchange_id).ok().flatten()) {
        Some(e) => preview(icpt, &e),
        None => Preview::default(),
    };
    let diff = baseline.and_then(|b| {
        let base = super::side_of(icpt, b).ok()?;
        let new = super::side_of(icpt, &sent.exchange_id).ok()?;
        Some(crate::intercept::diff::diff(&base, &new, None))
    });
    SendResult {
        last: sent,
        hops,
        refused: None,
        preview,
        diff,
    }
}

fn preview(icpt: &Interceptor, e: &crate::intercept::store::StoredExchange) -> Preview {
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
    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    Preview {
        content_type,
        headers: headers.into_iter().take(12).collect(),
        body: body_preview(icpt, e),
    }
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
            &text_or_binary(&d.bytes[..d.bytes.len().min(PREVIEW)]),
            PREVIEW,
        ),
        Err(err) => format!("(cannot decode: {err})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, url: &str, headers: &[(&str, &str)], body: &str) -> StructuredRequest {
        StructuredRequest {
            method: method.into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn structured_requests_serialise_in_order() {
        let (t, b) = build_request(req(
            "POST",
            "https://App.test:8443/api/x?y=1#frag",
            &[
                ("X-A", "1"),
                ("x-a", "2"),
                ("Content-Type", "application/json"),
            ],
            "{\"a\":1}",
        ))
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
            build_request(req("GET", "http://a.test/", &[("host", "b.test")], "")).unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            "GET / HTTP/1.1\r\nhost: b.test\r\n\r\n"
        );
    }

    #[test]
    fn header_injection_is_refused_in_structured_form() {
        assert!(build_request(req("GET", "http://a.test/", &[("X", "a\r\nY: b")], "")).is_err());
        assert!(build_request(req("GET", "ftp://a.test/", &[], "")).is_err());
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
