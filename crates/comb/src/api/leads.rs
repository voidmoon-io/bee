//! `http_leads` (019 T087, contracts/http-tools.md#http_leads): the passive leads recorded from
//! traffic this session. A lead is an observation to check — never a finding (FR-028). Its summary
//! is bee's own template; the evidence is the exchange ids, read with `http_get` as data.

use serde_json::{json, Value};

use super::{only_keys, CallError, Reply, ToolDef};
use crate::ops::OpError;
use crate::sidecar::Interceptor;

pub const BOUND: usize = 8 * 1024;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_leads",
        description: "List passive leads bee noticed in recorded HTTP traffic: reflected \
                          parameters, weak session cookies, verbose errors, missing security \
                          headers, credentials in URLs. Leads are observations to check, not \
                          findings — confirm one, then record a finding citing its exchanges.",
        parameters: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "only_new": { "type": "boolean", "description": "only leads not listed before (default true)" },
                "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
            }
        }),
    }
}

pub(super) fn call(icpt: &Interceptor, args: &Value) -> Result<Reply, CallError> {
    only_keys(args, &["only_new", "limit"])?;
    let only_new = args
        .get("only_new")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 100) as u32;
    let rows = icpt
        .with_store(|s| s.leads(only_new, limit))
        .map_err(|e| OpError::Failed(e.to_string()))?;
    // Summaries are comb's templates and ids are comb's: harness content, not target data.
    Ok(Reply::json(&json!({ "leads": rows }), BOUND, None))
}
