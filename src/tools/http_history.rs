//! `http_history` (019 T058, contracts/http-tools.md#http_history): structured filters over the
//! exchange store, one compact row per exchange, never bodies. A typo'd filter key is refused, not
//! read as "no filter".

use serde_json::{json, Value};

use crate::intercept::ops::OpError;
use crate::intercept::query::{self, HistoryFilter, QueryError};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{invalid, live, respond_text};
use crate::tools::{Provenance, Tool, ToolResult};

pub const BOUND: usize = 24 * 1024;

pub struct HttpHistory {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpHistory {
    fn name(&self) -> &'static str {
        "http_history"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_history".into(),
            description: "List recorded exchanges as compact rows (id, time, method, host, path, \
                          status, size, ms, origin, call id). Filters AND together; list values OR. \
                          Unknown filter keys are refused. Use `http_get` to read one."
                .into(),
            parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "host": { "type": ["string", "array"] },
                    "method": { "type": ["string", "array"] },
                    "path_prefix": { "type": "string" },
                    "status": { "type": ["integer", "array"] },
                    "status_range": { "type": "array", "items": { "type": "integer" }, "minItems": 2, "maxItems": 2 },
                    "min_bytes": { "type": "integer" },
                    "max_bytes": { "type": "integer" },
                    "since": { "type": "string", "description": "RFC 3339, or relative like -10m, -2h" },
                    "until": { "type": "string" },
                    "call_id": { "type": "string" },
                    "turn": { "type": "integer" },
                    "origin": { "type": ["string", "array"], "description": "tool | replay | fuzz | forwarded" },
                    "tags": { "type": ["string", "array"] },
                    "outcome": { "type": ["string", "array"], "description": "completed | refused | failed | truncated" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                    "order": { "type": "string", "enum": ["newest", "oldest"] },
                    "all_sessions": { "type": "boolean" }
                }
            }),
        }
    }

    async fn call(&self, args: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let args = if args.is_null() { json!({}) } else { args };
        let filter: HistoryFilter = match serde_json::from_value(args) {
            Ok(f) => f,
            Err(e) => return invalid("http_history", e),
        };
        let res = icpt
            .with_store(|s| query::history(s, &filter))
            .map_err(|e| match e {
                QueryError::Invalid(e) => OpError::Invalid(e),
                e => OpError::Failed(e.to_string()),
            })
            .map(|mut r| {
                // Keep within the bound by dropping rows from the end, and say how many.
                let mut body = serde_json::to_string(&r).unwrap_or_default();
                let mut dropped = 0;
                while body.len() > BOUND - 128 && !r.rows.is_empty() {
                    r.rows.pop();
                    dropped += 1;
                    r.returned = r.rows.len();
                    body = serde_json::to_string(&r).unwrap_or_default();
                }
                if dropped > 0 {
                    body.push_str(&format!(
                        "\n({dropped} more rows fit no bound; narrow the filter or lower `limit`)"
                    ));
                }
                body
            });
        // Paths and hosts come from requests other tools made — possibly from links in a hostile
        // page — so the rows travel as data too.
        let provenance = Provenance::Remote {
            source: "http:history".into(),
        };
        respond_text("http_history", icpt, res, Some(provenance))
    }
}
