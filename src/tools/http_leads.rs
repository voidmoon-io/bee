//! `http_leads` (019 T087, contracts/http-tools.md#http_leads): the passive leads recorded from
//! traffic this session. A lead is an observation to check — never a finding (FR-028). Its summary
//! is bee's own template; the evidence is the exchange ids, read with `http_get` as data.

use serde_json::{json, Value};

use crate::intercept::ops::OpError;
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{invalid, live, respond};
use crate::tools::{Tool, ToolResult};

pub const BOUND: usize = 8 * 1024;

pub struct HttpLeads {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpLeads {
    fn name(&self) -> &'static str {
        "http_leads"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_leads".into(),
            description: "List passive leads bee noticed in recorded HTTP traffic: reflected \
                          parameters, weak session cookies, verbose errors, missing security \
                          headers, credentials in URLs. Leads are observations to check, not \
                          findings — confirm one, then record a finding citing its exchanges."
                .into(),
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

    async fn call(&self, args: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        if let Some(k) = args.as_object().and_then(|o| {
            o.keys()
                .find(|k| !["only_new", "limit"].contains(&k.as_str()))
        }) {
            return invalid("http_leads", format!("unknown argument `{k}`"));
        }
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
            .map(|rows| json!({ "leads": rows }))
            .map_err(|e| OpError::Failed(e.to_string()));
        // Summaries are bee templates and ids are bee's: harness content, not target data.
        respond("http_leads", icpt, rows, BOUND, None)
    }
}
