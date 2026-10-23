//! `http_sitemap` (019 T074, contracts/http-tools.md#http_sitemap): a bounded tree of what has been
//! seen — hosts, path segments, methods, statuses, counts, and parameter names from query strings
//! and form/JSON request bodies. Built from the store by [`ops::sitemap`]; never sends anything.

use serde_json::{json, Value};

use crate::intercept::ops::{self, SitemapQuery};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{invalid, live, respond};
use crate::tools::{Provenance, Tool, ToolResult};

pub use crate::intercept::ops::sitemap::BOUND;

pub struct HttpSitemap {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpSitemap {
    fn name(&self) -> &'static str {
        "http_sitemap"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_sitemap".into(),
            description: "A tree of what has been seen on a host: path segments with methods, \
                          statuses, request counts and parameter names (query and body). Built from \
                          recorded traffic; sends nothing."
                .into(),
            parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "host": { "type": "string" },
                    "path_prefix": { "type": "string" },
                    "depth": { "type": "integer", "minimum": 1, "maximum": 8 }
                }
            }),
        }
    }

    async fn call(&self, args: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let obj = args.as_object().cloned().unwrap_or_default();
        if let Some(k) = obj
            .keys()
            .find(|k| !["host", "path_prefix", "depth"].contains(&k.as_str()))
        {
            return invalid("http_sitemap", format!("unknown argument `{k}`"));
        }
        let q = SitemapQuery {
            host: obj
                .get("host")
                .and_then(Value::as_str)
                .map(bee_core::pattern::normalize_host),
            path_prefix: obj
                .get("path_prefix")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_string(),
            depth: obj
                .get("depth")
                .and_then(Value::as_u64)
                .unwrap_or(4)
                .clamp(1, 8) as usize,
        };
        let provenance = Provenance::Remote {
            source: "http:sitemap".into(),
        };
        respond(
            "http_sitemap",
            icpt,
            ops::sitemap(icpt, q, BOUND),
            BOUND,
            Some(provenance),
        )
    }
}
