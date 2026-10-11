//! `http_replay` (019 T073, contracts/http-tools.md#http_replay): send a stored request again with
//! edits, and answer with a **measured** diff against the original.
//!
//! With `noise_probe` (the default) the unmodified original is sent once more first; whatever differs
//! between original and probe is volatile and suppressed from the diff, reported as a count plus
//! paths (research R10). Both new exchanges are linked to the original by `parent`.

use std::time::Duration;

use serde_json::{json, Value};

use crate::intercept::control::{OriginKind, RawTarget};
use crate::intercept::diff::{self, Edit, Side};
use crate::intercept::sidecar::{InterceptError, Interceptor};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{bounded_json, invalid, live, with_notices};
use crate::tools::http_send::call_ctx;
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult};

pub const BOUND: usize = 16 * 1024;

pub struct HttpReplay {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpReplay {
    fn name(&self) -> &'static str {
        "http_replay"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_replay".into(),
            description: "Re-send a recorded request with edits and get a measured diff against the \
                          original: status, length, timing, headers, and the body (unified hunks for \
                          text, changed JSON pointer paths for JSON). With noise_probe (default) the \
                          original is re-sent once first so volatile values — dates, request ids — \
                          are suppressed instead of reported as changes. Edits: set_header, \
                          remove_header, set_query, remove_query, set_path, set_method, json_set, \
                          json_remove, form_set, replace, set_body."
                .into(),
            parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" },
                    "edits": { "type": "array", "items": { "type": "object" } },
                    "noise_probe": { "type": "boolean" },
                    "timeout_ms": { "type": "integer", "minimum": 1 }
                }
            }),
        }
    }

    async fn call(&self, args: Value, sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let Some(obj) = args.as_object() else {
            return invalid("http_replay", "arguments must be an object");
        };
        if let Some(k) = obj
            .keys()
            .find(|k| !["id", "edits", "noise_probe", "timeout_ms"].contains(&k.as_str()))
        {
            return invalid("http_replay", format!("unknown argument `{k}`"));
        }
        let Some(id) = obj.get("id").and_then(Value::as_str) else {
            return invalid("http_replay", "`id` is required");
        };
        let edits: Vec<Edit> = match obj.get("edits") {
            None => Vec::new(),
            Some(e) => match serde_json::from_value(e.clone()) {
                Ok(v) => v,
                Err(e) => return invalid("http_replay", format!("edits: {e}")),
            },
        };
        let probe = obj
            .get("noise_probe")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let timeout = Duration::from_millis(
            obj.get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(15_000)
                .clamp(1, 120_000),
        );
        match replay(icpt, sandbox, id, &edits, probe, timeout).await {
            Ok((new_id, v)) => ToolResult::ok(with_notices(bounded_json(&v, BOUND), icpt))
                .with_provenance(Provenance::Remote {
                    source: format!("http:{new_id}"),
                }),
            Err(Fail::Invalid(e)) => invalid("http_replay", e),
            Err(Fail::Unavailable(d)) => crate::tools::http::unavailable(&d),
            Err(Fail::Failed(e)) => {
                ToolOutcome::<()>::failed(e).into_tool_result(|_| String::new())
            }
        }
    }
}

pub(crate) enum Fail {
    Invalid(String),
    Unavailable(String),
    Failed(String),
}

impl From<InterceptError> for Fail {
    fn from(e: InterceptError) -> Fail {
        match e {
            InterceptError::Unavailable(d) => Fail::Unavailable(d),
            other => Fail::Failed(other.to_string()),
        }
    }
}

/// The stored request `id` as raw bytes, and where it went.
pub(crate) fn stored_request(
    icpt: &Interceptor,
    id: &str,
) -> Result<(RawTarget, Vec<u8>, Vec<u8>), Fail> {
    let e = icpt
        .with_store(|s| s.get_exchange(id))
        .map_err(|e| Fail::Failed(e.to_string()))?
        .ok_or_else(|| Fail::Invalid(format!("no exchange `{id}`")))?;
    let body = match &e.req_body {
        None => Vec::new(),
        Some(sha) => {
            let meta = icpt
                .with_store(|s| s.blob_meta(sha))
                .map_err(|e| Fail::Failed(e.to_string()))?;
            if meta.as_ref().is_some_and(|m| m.truncated) {
                return Err(Fail::Invalid(format!(
                    "the request body of {id} was stored truncated; it cannot be replayed exactly"
                )));
            }
            icpt.with_store(|s| s.read_blob(sha))
                .map_err(|e| Fail::Failed(e.to_string()))?
                .ok_or_else(|| Fail::Invalid(format!("the request body of {id} was evicted")))?
        }
    };
    let scheme = match e.tls.as_deref() {
        Some("inspected") | Some("client") => "https",
        _ => e.scheme.as_deref().unwrap_or("http"),
    };
    Ok((
        RawTarget {
            scheme: scheme.to_string(),
            host: e.host.clone(),
            port: e.port,
        },
        e.req_head.clone(),
        body,
    ))
}

/// The response side of exchange `id`, decoded, for the diff.
pub(crate) fn side_of(icpt: &Interceptor, id: &str) -> Result<Side, Fail> {
    let e = icpt
        .with_store(|s| s.get_exchange(id))
        .map_err(|e| Fail::Failed(e.to_string()))?
        .ok_or_else(|| Fail::Invalid(format!("no exchange `{id}`")))?;
    let body = match &e.resp_body {
        None => Vec::new(),
        Some(sha) => {
            let raw = icpt
                .with_store(|s| s.read_blob(sha))
                .ok()
                .flatten()
                .unwrap_or_default();
            let enc = icpt
                .with_store(|s| s.blob_meta(sha))
                .ok()
                .flatten()
                .map(|m| m.encoding)
                .unwrap_or_else(|| "identity".into());
            crate::intercept::slice::decode(&raw, &enc, 4 * 1024 * 1024)
                .map(|d| d.bytes)
                .unwrap_or(raw)
        }
    };
    Ok(Side {
        status: e.status,
        head: e.resp_head,
        body,
        elapsed_ms: e.total_ms,
    })
}

async fn replay(
    icpt: &Interceptor,
    sandbox: &Sandbox,
    id: &str,
    edits: &[Edit],
    probe: bool,
    timeout: Duration,
) -> Result<(String, Value), Fail> {
    let (target, head, body) = stored_request(icpt, id)?;
    let ctx = call_ctx(sandbox);
    let mut original_bytes = head.clone();
    original_bytes.extend_from_slice(&body);

    let probe_id = if probe {
        let sent = icpt
            .send(
                target.clone(),
                original_bytes,
                ctx.clone(),
                OriginKind::Replay,
                Some(id.to_string()),
                vec!["noise-probe".into()],
                timeout,
            )
            .await?;
        Some(sent.exchange_id)
    } else {
        None
    };

    let (new_head, new_body) = diff::apply_edits(&head, &body, edits).map_err(Fail::Invalid)?;
    let mut bytes = new_head;
    bytes.extend_from_slice(&new_body);
    let sent = icpt
        .send(
            target.clone(),
            bytes,
            ctx,
            OriginKind::Replay,
            Some(id.to_string()),
            Vec::new(),
            timeout,
        )
        .await?;
    if let crate::intercept::control::Outcome::Refused { kind } = &sent.record.outcome {
        return Err(Fail::Invalid(format!(
            "the replay was refused by the proxy ({}); edits cannot move a request out of scope",
            kind.as_str()
        )));
    }

    let original = side_of(icpt, id)?;
    let new = side_of(icpt, &sent.exchange_id)?;
    let probe_side = match &probe_id {
        Some(p) => Some(side_of(icpt, p)?),
        None => None,
    };
    let d = diff::diff(&original, &new, probe_side.as_ref());
    Ok((
        sent.exchange_id.clone(),
        json!({
            "id": sent.exchange_id,
            "parent": id,
            "probe": probe_id,
            "diff": d,
            "enforcement": icpt.enforcement().label(),
        }),
    ))
}
