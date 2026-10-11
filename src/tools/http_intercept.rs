//! `http_intercept` (019 T083, contracts/http-tools.md#http_intercept): session-scoped rules over
//! other tools' traffic — add, remove, list, and release a held request.
//!
//! Rules are runtime state, never policy: they live in the proxy worker for this session only, and
//! cannot widen scope — every rewritten request is checked again (US7).

use serde_json::{json, Value};

use crate::intercept::sidecar::{InterceptError, Interceptor};
use crate::intercept::worker::rules::{Action, Matcher, RuleSpec};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{bounded_json, invalid, live, unavailable, with_notices};
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult};

pub const BOUND: usize = 8 * 1024;

pub struct HttpIntercept {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpIntercept {
    fn name(&self) -> &'static str {
        "http_intercept"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_intercept".into(),
            description: "Shape traffic that other tools send through the proxy with session-only \
                          rules. add_rule {matcher: {host, method, path_prefix, path_regex, \
                          header_present, body_contains}, action: {modify: [edits]} | \"drop\" | \
                          {hold: {timeout_s ≤ 300}}}; remove_rule {rule_id}; list; release {hold_id, \
                          decision: \"forward\" | \"drop\" | {forward_edited: [edits]}}. Held requests \
                          go through unchanged at their deadline. Rules cannot move traffic out of scope."
                .into(),
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

    async fn call(&self, args: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let action = args.get("action").and_then(Value::as_str).unwrap_or("");
        let out: Result<Value, ToolResult> = match action {
            "add_rule" => {
                let rule = args.get("rule").cloned().unwrap_or(Value::Null);
                let matcher = rule.get("matcher").cloned().unwrap_or(json!({}));
                let act = rule.get("action").cloned().unwrap_or(Value::Null);
                // Validate here for a precise invalid_args; the worker validates again.
                let spec = serde_json::from_value::<Matcher>(matcher.clone())
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
                    .and_then(|s| s.validate().map(|_| s));
                match spec {
                    Err(e) => Err(invalid("http_intercept", e)),
                    Ok(_) => icpt
                        .add_rule(matcher, act)
                        .await
                        .map(|id| json!({ "rule_id": id }))
                        .map_err(fail),
                }
            }
            "remove_rule" => match args.get("rule_id").and_then(Value::as_str) {
                None => Err(invalid("http_intercept", "remove_rule needs rule_id")),
                Some(id) => icpt
                    .remove_rule(id)
                    .await
                    .map(|_| json!({ "removed": id }))
                    .map_err(fail),
            },
            "list" => {
                let (rules, held) = icpt.rules_and_holds();
                Ok(json!({ "rules": rules, "held": held }))
            }
            "release" => match (
                args.get("hold_id").and_then(Value::as_str),
                args.get("decision"),
            ) {
                (Some(h), Some(d)) => icpt
                    .release_hold(h, d.clone())
                    .await
                    .map(|_| json!({ "released": h }))
                    .map_err(fail),
                _ => Err(invalid(
                    "http_intercept",
                    "release needs hold_id and decision",
                )),
            },
            other => Err(invalid(
                "http_intercept",
                format!("unknown action `{other}`"),
            )),
        };
        match out {
            // Held-request summaries name hosts and paths from other tools' traffic: data.
            Ok(v) => ToolResult::ok(with_notices(bounded_json(&v, BOUND), icpt)).with_provenance(
                Provenance::Remote {
                    source: "http:intercept".into(),
                },
            ),
            Err(r) => r,
        }
    }
}

fn fail(e: InterceptError) -> ToolResult {
    match e {
        InterceptError::Unavailable(d) => unavailable(&d),
        InterceptError::Worker { code, message } if code == "invalid" => {
            invalid("http_intercept", message)
        }
        other => ToolOutcome::<()>::failed(other.to_string()).into_tool_result(|_| String::new()),
    }
}
