//! `http_replay` (019 T073, contracts/http-tools.md#http_replay): send a stored request again with
//! edits, and answer with a **measured** diff against the original.
//!
//! With `noise_probe` (the default) the unmodified original is sent once more first, and what differs
//! between original and probe is suppressed as volatile. The replay is [`ops::replay`].

use std::time::Duration;

use serde_json::{json, Value};

use crate::intercept::diff::Edit;
use crate::intercept::ops::{self, ReplaySpec};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{call_ctx, invalid, live, respond};
use crate::tools::{Provenance, Tool, ToolResult};

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
        let spec = ReplaySpec {
            id: id.to_string(),
            edits,
            noise_probe: probe,
            timeout,
        };
        let result = ops::replay(icpt, &call_ctx(sandbox), spec).await;
        let provenance = result.as_ref().ok().map(|r| Provenance::Remote {
            source: format!("http:{}", r.id),
        });
        let v = result.map(|r| {
            json!({
                "id": r.id,
                "parent": r.parent,
                "probe": r.probe,
                "diff": r.diff,
                "enforcement": icpt.enforcement().label(),
            })
        });
        respond("http_replay", icpt, v, BOUND, provenance)
    }
}
