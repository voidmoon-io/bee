//! `http_get` (019 T060, contracts/http-tools.md#http_get): one bounded view of one stored exchange.
//!
//! Never a whole body unless it fits the 32 KiB bound: the model asks for headers, a byte range of
//! the decoded body, a grep with context, a JSON pointer, or the raw head. The result is
//! target-derived, so it reaches the model as `Remote { source: "http:<id>" }` — inside an
//! untrusted-data envelope.

use serde_json::{json, Value};

use crate::intercept::ops::{self, Part};
use crate::intercept::sidecar::Interceptor;
use crate::intercept::slice::View;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{invalid, live, respond};
use crate::tools::{Provenance, Tool, ToolResult};

pub const BOUND: usize = 32 * 1024;
/// Room left for the result's own fields around the content.
const CONTENT_BOUND: usize = BOUND - 1024;

pub struct HttpGet {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpGet {
    fn name(&self) -> &'static str {
        "http_get"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_get".into(),
            description: "Read one bounded view of a recorded exchange: its headers, a byte range of \
                          the decoded body, a regex grep with context lines, a JSON pointer, or the \
                          exact raw head. `part` is `response` (default) or `request`. Bodies are \
                          never returned whole beyond 32 KiB."
                .into(),
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

    async fn call(&self, args: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let Some(obj) = args.as_object() else {
            return invalid("http_get", "arguments must be an object");
        };
        if let Some(k) = obj
            .keys()
            .find(|k| !["id", "part", "view"].contains(&k.as_str()))
        {
            return invalid("http_get", format!("unknown argument `{k}`"));
        }
        let Some(id) = obj.get("id").and_then(Value::as_str) else {
            return invalid("http_get", "`id` is required");
        };
        let part = match obj
            .get("part")
            .and_then(Value::as_str)
            .unwrap_or("response")
        {
            "request" => Part::Request,
            "response" => Part::Response,
            _ => return invalid("http_get", "part is `request` or `response`"),
        };
        let view = match obj.get("view").map(View::parse) {
            Some(Ok(v)) => v,
            Some(Err(e)) => return invalid("http_get", e),
            None => return invalid("http_get", "`view` is required"),
        };
        let provenance = Provenance::Remote {
            source: format!("http:{id}"),
        };
        let v = ops::read_exchange(icpt, id, part, &view, CONTENT_BOUND);
        respond("http_get", icpt, v, BOUND, Some(provenance))
    }
}
