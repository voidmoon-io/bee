//! `http_intercept` (019 T083, contracts/http-tools.md#http_intercept): session-scoped rules over
//! other tools' traffic — add, remove, list, and release a held request.
//!
//! Rules are runtime state, never policy: they live in the proxy worker for this session only, and
//! cannot widen scope — every rewritten request is checked again (US7).

use serde_json::{json, Value};

use super::{CallError, Reply, ToolDef};
use crate::ops::OpError;
use crate::sidecar::{InterceptError, Interceptor};
use crate::worker::rules::{Action, Matcher, RuleSpec};

pub const BOUND: usize = 8 * 1024;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_intercept",
        description: "Shape traffic that other tools send through the proxy with session-only \
                          rules. add_rule {matcher: {host, method, path_prefix, path_regex, \
                          header_present, body_contains}, action: {modify: [edits]} | \"drop\" | \
                          {hold: {timeout_s ≤ 300}}}; remove_rule {rule_id}; list; release {hold_id, \
                          decision: \"forward\" | \"drop\" | {forward_edited: [edits]}}. Held requests \
                          go through unchanged at their deadline. Rules cannot move traffic out of scope.",
        parameters: json!({
                "type": "object",
                "required": ["action"],
                "additionalProperties": false,
                "properties": {
                    "action": { "type": "string", "enum": ["add_rule", "remove_rule", "list", "release"] },
                    "rule": { "type": "object" },
                    "rule_id": { "type": "string" },
                    "hold_id": { "type": "string" },
                    "decision": {}
                }
            }),
    }
}

pub(super) async fn call(icpt: &Interceptor, args: &Value) -> Result<Reply, CallError> {
    let action = args.get("action").and_then(Value::as_str).unwrap_or("");
    let out: Value = match action {
        "add_rule" => {
            let rule = args.get("rule").cloned().unwrap_or(Value::Null);
            let matcher = rule.get("matcher").cloned().unwrap_or(json!({}));
            let act = rule.get("action").cloned().unwrap_or(Value::Null);
            // Validate here for a precise invalid_args; the worker validates again.
            serde_json::from_value::<Matcher>(matcher.clone())
                .map_err(|e| format!("matcher: {e}"))
                .and_then(|m| {
                    serde_json::from_value::<Action>(act.clone())
                        .map_err(|e| format!("action: {e}"))
                        .map(|a| RuleSpec {
                            id: "check".into(),
                            matcher: m,
                            action: a,
                        })
                })
                .and_then(|s| s.validate())
                .map_err(OpError::Invalid)?;
            let id = icpt.add_rule(matcher, act).await.map_err(fail)?;
            json!({ "rule_id": id })
        }
        "remove_rule" => {
            let id = args
                .get("rule_id")
                .and_then(Value::as_str)
                .ok_or_else(|| OpError::Invalid("remove_rule needs rule_id".into()))?;
            icpt.remove_rule(id).await.map_err(fail)?;
            json!({ "removed": id })
        }
        "list" => {
            let (rules, held) = icpt.rules_and_holds();
            json!({ "rules": rules, "held": held })
        }
        "release" => match (
            args.get("hold_id").and_then(Value::as_str),
            args.get("decision"),
        ) {
            (Some(h), Some(d)) => {
                icpt.release_hold(h, d.clone()).await.map_err(fail)?;
                json!({ "released": h })
            }
            _ => return Err(OpError::Invalid("release needs hold_id and decision".into()).into()),
        },
        other => return Err(OpError::Invalid(format!("unknown action `{other}`")).into()),
    };
    // Held-request summaries name hosts and paths from other tools' traffic: data.
    Ok(Reply::json(&out, BOUND, Some("http:intercept".into())))
}

/// The worker validates rules again; its `invalid` is the caller's to fix.
fn fail(e: InterceptError) -> OpError {
    match e {
        InterceptError::Worker { code, message } if code == "invalid" => OpError::Invalid(message),
        other => other.into(),
    }
}
