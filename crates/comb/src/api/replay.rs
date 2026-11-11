//! `http_replay` (019 T073, contracts/http-tools.md#http_replay): send a stored request again with
//! edits, and answer with a **measured** diff against the original.
//!
//! With `noise_probe` (the default) the unmodified original is sent once more first, and what differs
//! between original and probe is suppressed as volatile. The replay is [`ops::replay`].

use std::time::Duration;

use serde_json::{json, Value};

use super::{invalid, only_keys, CallError, Reply, ToolDef};
use crate::diff::Edit;
use crate::ops::{self, CallCtx, ReplaySpec};
use crate::sidecar::Interceptor;

pub const BOUND: usize = 16 * 1024;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_replay",
        description: "Re-send a recorded request with edits and get a measured diff against the \
                          original: status, length, timing, headers, and the body (unified hunks for \
                          text, changed JSON pointer paths for JSON). With noise_probe (default) the \
                          original is re-sent once first so volatile values — dates, request ids — \
                          are suppressed instead of reported as changes. Edits: set_header, \
                          remove_header, set_query, remove_query, set_path, set_method, json_set, \
                          json_remove, form_set, replace, set_body.",
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

pub(super) async fn call(
    icpt: &Interceptor,
    ctx: &CallCtx,
    args: &Value,
) -> Result<Reply, CallError> {
    only_keys(args, &["id", "edits", "noise_probe", "timeout_ms"])?;
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`id` is required"))?;
    let edits: Vec<Edit> = match args.get("edits") {
        None => Vec::new(),
        Some(e) => serde_json::from_value(e.clone()).map_err(|e| invalid(format!("edits: {e}")))?,
    };
    let noise_probe = args
        .get("noise_probe")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let timeout = Duration::from_millis(
        args.get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(15_000)
            .clamp(1, 120_000),
    );
    let spec = ReplaySpec {
        id: id.to_string(),
        edits,
        noise_probe,
        timeout,
    };
    let r = ops::replay(icpt, ctx, spec).await?;
    let mut v = json!({
        "id": r.id,
        "parent": r.parent,
        "probe": r.probe,
        "diff": r.diff,
        "enforcement": icpt.enforcement().label(),
    });
    if let Some(why) = r.probe_skipped {
        v["probe_skipped"] = json!(why);
    }
    Ok(Reply::json(&v, BOUND, Some(format!("http:{}", r.id))))
}
