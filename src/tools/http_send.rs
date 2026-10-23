//! `http_send` (019 T055/T056, contracts/http-tools.md#http_send).
//!
//! Two shapes, exactly one per call:
//! - `raw` — bytes sent **byte for byte** (FR-018); bee adds nothing;
//! - `request` — method, URL, an ordered list of header pairs (duplicates and casing preserved) and
//!   a body, serialised to raw bytes **here, in the harness**, so the worker has one send path.
//!   `Host` and `Content-Length` are added only when absent.
//!
//! The send itself — the scope check, redirect following within scope, the preview and the baseline
//! diff — is [`ops::send`]; this adapter parses arguments and shapes the result.

use std::time::Duration;

use serde_json::{json, Value};

use crate::intercept::control::{Outcome, RawTarget};
use crate::intercept::ops::bound::b64;
use crate::intercept::ops::send::MAX_REDIRECTS;
use crate::intercept::ops::{self, OpError, SendResult, SendSpec, StructuredRequest};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{call_ctx, invalid, live, op_error, respond};
use crate::tools::{Provenance, Tool, ToolResult};

pub const BOUND: usize = 4 * 1024;
/// With a `baseline` diff (contracts/http-tools.md#http_send).
pub const BOUND_WITH_DIFF: usize = 16 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const MAX_TIMEOUT_MS: u64 = 120_000;

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
                    "baseline": { "type": "string", "description": "exchange id to diff the response against (same shape as http_replay's diff)" },
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
        let spec = match parse_args(&args) {
            Ok(p) => p,
            Err(e) => return invalid("http_send", e),
        };
        let baseline = spec.baseline.clone();
        let r = match ops::send(icpt, &call_ctx(sandbox), spec).await {
            Ok(r) => r,
            Err(e) => return op_error("http_send", e),
        };
        if let Some(reason) = r.refused {
            let note = (!r.hops.is_empty()).then(|| {
                format!(
                    "redirects followed before the refusal: {}",
                    serde_json::to_string(&r.hops).unwrap_or_default()
                )
            });
            return op_error("http_send", OpError::Refused { reason, note });
        }
        render(icpt, r, baseline.as_deref())
    }
}

fn parse_args(a: &Value) -> Result<SendSpec, String> {
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
    Ok(SendSpec {
        target,
        bytes,
        follow_redirects: follow_redirects as u32,
        timeout: Duration::from_millis(timeout_ms),
        tags,
        baseline: obj
            .get("baseline")
            .and_then(Value::as_str)
            .map(str::to_string),
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

/// A `request` argument as a [`StructuredRequest`], built into bytes by the op (019 T055).
fn structured(r: &Value) -> Result<(RawTarget, Vec<u8>), String> {
    let url = r
        .get("url")
        .and_then(Value::as_str)
        .ok_or("request.url is required")?;
    let method = r.get("method").and_then(Value::as_str).unwrap_or("GET");
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
            headers.push((k.to_string(), v.to_string()));
        }
    }
    let body = match (r.get("body"), r.get("body_base64")) {
        (Some(Value::String(s)), None) => s.as_bytes().to_vec(),
        (None, Some(Value::String(b))) => b64(b)?,
        (None, None) => Vec::new(),
        _ => return Err("give at most one of request.body or request.body_base64".into()),
    };
    ops::build_request(StructuredRequest {
        method: method.into(),
        url: url.into(),
        headers,
        body,
    })
    .map_err(|e| e.to_string())
}

/// The bounded `http_send` result.
fn render(icpt: &Interceptor, r: SendResult, baseline: Option<&str>) -> ToolResult {
    let rec = &r.last.record;
    let mut v = json!({
        "id": r.last.exchange_id,
        "status": rec.status,
        "elapsed_ms": rec.timing.total_ms,
        "resp_bytes": rec.resp_bytes,
        "content_type": r.preview.content_type,
        "headers_preview": r.preview.headers,
        "body_preview": r.preview.body,
        "redirects": r.hops,
        "enforcement": icpt.enforcement().label(),
    });
    let failed = matches!(rec.outcome, Outcome::Failed { .. });
    if let Outcome::Failed { reason } = &rec.outcome {
        v["failed"] = json!(reason);
    }
    if rec.resp_truncated {
        v["stored_truncated"] = json!(true);
    }
    let mut bound = BOUND;
    if let (Some(d), Some(b)) = (r.diff, baseline) {
        v["diff"] = d;
        v["baseline"] = json!(b);
        bound = BOUND_WITH_DIFF;
    }
    let provenance = Provenance::Remote {
        source: format!("http:{}", r.last.exchange_id),
    };
    let mut res = respond("http_send", icpt, Ok(v), bound, Some(provenance));
    res.is_error = failed;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_argument_serialises_in_order() {
        let (t, b) = structured(&json!({
            "method": "POST",
            "url": "https://App.test:8443/api/x?y=1#frag",
            "headers": [["X-A", "1"], ["x-a", "2"]],
            "body_base64": "e30="
        }))
        .unwrap();
        assert_eq!((t.host.as_str(), t.port), ("app.test", 8443));
        assert_eq!(
            String::from_utf8(b).unwrap(),
            "POST /api/x?y=1 HTTP/1.1\r\nHost: App.test:8443\r\nX-A: 1\r\nx-a: 2\r\n\
             Content-Length: 2\r\n\r\n{}"
        );
    }

    #[test]
    fn a_malformed_request_argument_is_refused() {
        assert!(structured(&json!({ "url": "http://a.test/", "headers": [["X"]] })).is_err());
        assert!(
            structured(&json!({ "url": "http://a.test/", "headers": [["X", "a\r\nY: b"]] }))
                .is_err()
        );
        assert!(structured(&json!({ "method": "GET" })).is_err());
    }
}
