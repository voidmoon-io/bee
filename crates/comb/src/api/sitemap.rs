//! `http_sitemap` (019 T074, contracts/http-tools.md#http_sitemap): a bounded tree of what has been
//! seen — hosts, path segments, methods, statuses, counts, and parameter names from query strings
//! and form/JSON request bodies. Built from the store by [`ops::sitemap`]; never sends anything.

use serde_json::{json, Value};

use super::{only_keys, CallError, Reply, ToolDef};
use crate::ops::{self, SitemapQuery};
use crate::sidecar::Interceptor;

pub use crate::ops::sitemap::BOUND;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_sitemap",
        description: "A tree of what has been seen on a host: path segments with methods, \
                          statuses, request counts and parameter names (query and body). Built from \
                          recorded traffic; sends nothing.",
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

pub(super) fn call(icpt: &Interceptor, args: &Value) -> Result<Reply, CallError> {
    only_keys(args, &["host", "path_prefix", "depth"])?;
    let q = SitemapQuery {
        host: args
            .get("host")
            .and_then(Value::as_str)
            .map(bee_core::pattern::normalize_host),
        path_prefix: args
            .get("path_prefix")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string(),
        depth: args
            .get("depth")
            .and_then(Value::as_u64)
            .unwrap_or(4)
            .clamp(1, 8) as usize,
    };
    let v = ops::sitemap(icpt, q, BOUND)?;
    Ok(Reply::json(&v, BOUND, Some("http:sitemap".into())))
}
