//! `http_intercept` (019 T083, contracts/http-tools.md#http_intercept): session-scoped rules over
//! other tools' traffic — add, remove, list, and release a held request.
//!
//! Rules are runtime state, never policy: they live in the proxy worker for this session only, and
//! cannot widen scope — every rewritten request is checked again (US7).

use serde_json::{json, Value};

use crate::intercept::ops::OpError;
use crate::intercept::sidecar::{InterceptError, Interceptor};
use crate::intercept::worker::rules::{Action, Matcher, RuleSpec};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{live, respond};
use crate::tools::{Provenance, Tool, ToolResult};

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
        let out: Result<Value, OpError> = match action {
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
                    Err(e) => Err(OpError::Invalid(e)),
                    Ok(_) => icpt
                        .add_rule(matcher, act)
                        .await
                        .map(|id| json!({ "rule_id": id }))
                        .map_err(fail),
                }
            }
            "remove_rule" => match args.get("rule_id").and_then(Value::as_str) {
                None => Err(OpError::Invalid("remove_rule needs rule_id".into())),
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
                _ => Err(OpError::Invalid(
                    "release needs hold_id and decision".into(),
                )),
            },
            other => Err(OpError::Invalid(format!("unknown action `{other}`"))),
        };
        // Held-request summaries name hosts and paths from other tools' traffic: data.
        let provenance = Provenance::Remote {
            source: "http:intercept".into(),
        };
        respond("http_intercept", icpt, out, BOUND, Some(provenance))
    }
}

/// The worker validates rules again; its `invalid` is the model's to fix.
fn fail(e: InterceptError) -> OpError {
    match e {
        InterceptError::Worker { code, message } if code == "invalid" => OpError::Invalid(message),
        other => other.into(),
    }
}
