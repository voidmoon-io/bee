//! `http_get` (019 T060, contracts/http-tools.md#http_get): one bounded view of one stored exchange.
//!
//! Never a whole body unless it fits the 32 KiB bound: the model asks for headers, a byte range of
//! the decoded body, a grep with context, a JSON pointer, or the raw head. The result is
//! target-derived, so it reaches the model as `Remote { source: "http:<id>" }` — inside an
//! untrusted-data envelope.

use serde_json::{json, Value};

use crate::intercept::sidecar::Interceptor;
use crate::intercept::slice::{self, View, DECODE_CAP};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{bounded_json, invalid, live, with_notices};
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult};

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
        let part = obj
            .get("part")
            .and_then(Value::as_str)
            .unwrap_or("response");
        if part != "request" && part != "response" {
            return invalid("http_get", "part is `request` or `response`");
        }
        let view = match obj.get("view").map(View::parse) {
            Some(Ok(v)) => v,
            Some(Err(e)) => return invalid("http_get", e),
            None => return invalid("http_get", "`view` is required"),
        };
        match read(icpt, id, part, &view) {
            Ok(v) => ToolResult::ok(with_notices(bounded_json(&v, BOUND), icpt)).with_provenance(
                Provenance::Remote {
                    source: format!("http:{id}"),
                },
            ),
            Err(Error::Invalid(e)) => invalid("http_get", e),
            Err(Error::Failed(e)) => {
                ToolOutcome::<()>::failed(e).into_tool_result(|_| String::new())
            }
        }
    }
}

enum Error {
    Invalid(String),
    Failed(String),
}

fn read(icpt: &Interceptor, id: &str, part: &str, view: &View) -> Result<Value, Error> {
    let e = icpt
        .with_store(|s| s.get_exchange(id))
        .map_err(|e| Error::Failed(e.to_string()))?
        .ok_or_else(|| Error::Invalid(format!("no exchange `{id}`")))?;
    let (head, sha) = if part == "request" {
        (e.req_head.clone(), e.req_body.clone())
    } else {
        (e.resp_head.clone(), e.resp_body.clone())
    };
    let meta = match &sha {
        Some(s) => icpt
            .with_store(|st| st.blob_meta(s))
            .map_err(|e| Error::Failed(e.to_string()))?,
        None => None,
    };
    let evicted = meta.as_ref().is_some_and(|m| m.evicted);
    let stored_truncated = meta.as_ref().is_some_and(|m| m.truncated);
    let encoding = if part == "request" {
        crate::intercept::store::content_encoding(&req_as_resp_head(&head))
    } else {
        meta.as_ref()
            .map(|m| m.encoding.clone())
            .unwrap_or_else(|| "identity".into())
    };

    let needs_body = !matches!(view, View::Headers | View::RawHead);
    let (decoded, decoded_truncated) = if needs_body && !evicted {
        let raw = match &sha {
            Some(s) => icpt
                .with_store(|st| st.read_blob(s))
                .map_err(|e| Error::Failed(e.to_string()))?
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let d = slice::decode(&raw, &encoding, DECODE_CAP).map_err(Error::Failed)?;
        (d.bytes, d.decoded_truncated)
    } else {
        (Vec::new(), false)
    };
    if needs_body && evicted {
        return Err(Error::Failed(format!(
            "the {part} body of {id} was evicted from the store (over store_cap_bytes); its \
             headers remain"
        )));
    }
    let content = slice::apply(view, &head, &decoded, CONTENT_BOUND).map_err(Error::Invalid)?;
    Ok(json!({
        "id": id,
        "part": part,
        "total_decoded_bytes": needs_body.then_some(decoded.len()),
        "encoding": encoding,
        "truncated": stored_truncated,
        "decoded_truncated": decoded_truncated,
        "evicted": evicted,
        "origin": e.origin_kind,
        "content": content,
    }))
}

/// A request head's headers, behind a dummy status line, so the response-head helpers can read it.
fn req_as_resp_head(head: &[u8]) -> Vec<u8> {
    head.to_vec()
}
