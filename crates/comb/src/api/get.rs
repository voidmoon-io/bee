//! `http_get` (019 T060, contracts/http-tools.md#http_get): one bounded view of one stored exchange.
//!
//! Never a whole body unless it fits the 32 KiB bound: the model asks for headers, a byte range of
//! the decoded body, a grep with context, a JSON pointer, or the raw head. The result is
//! target-derived, so it reaches the model as `Remote { source: "http:<id>" }` — inside an
//! untrusted-data envelope.

use serde_json::{json, Value};

use super::{invalid, only_keys, CallError, Reply, ToolDef};
use crate::ops::{self, Part};
use crate::sidecar::Interceptor;
use crate::slice::View;

pub const BOUND: usize = 32 * 1024;
/// Room left for the result's own fields around the content.
const CONTENT_BOUND: usize = BOUND - 1024;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_get",
        description: "Read one bounded view of a recorded exchange: its headers, a byte range of \
                          the decoded body, a regex grep with context lines, a JSON pointer, or the \
                          exact raw head. `part` is `response` (default) or `request`. Bodies are \
                          never returned whole beyond 32 KiB.",
        parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "view"],
                "properties": {
                    "id": { "type": "string" },
                    "part": { "type": "string", "enum": ["request", "response"] },
                    "view": {
                        "type": "object",
                        "description": "exactly one of: {\"headers\": true} | {\"range\": {\"start\": 0, \"len\": 4096}} | {\"grep\": {\"pattern\": \"csrf\", \"context_lines\": 1, \"max_matches\": 20}} | {\"json_pointer\": \"/a/0\"} | {\"raw_head\": true}"
                    }
                }
            }),
    }
}

pub(super) fn call(icpt: &Interceptor, args: &Value) -> Result<Reply, CallError> {
    only_keys(args, &["id", "part", "view"])?;
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`id` is required"))?;
    let part = match args
        .get("part")
        .and_then(Value::as_str)
        .unwrap_or("response")
    {
        "request" => Part::Request,
        "response" => Part::Response,
        _ => return Err(invalid("part is `request` or `response`")),
    };
    let view = match args.get("view").map(View::parse) {
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(invalid(e)),
        None => return Err(invalid("`view` is required")),
    };
    let v = ops::read_exchange(icpt, id, part, &view, CONTENT_BOUND)?;
    Ok(Reply::json(&v, BOUND, Some(format!("http:{id}"))))
}
