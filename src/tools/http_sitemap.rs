//! `http_sitemap` (019 T074, contracts/http-tools.md#http_sitemap): a bounded tree of what has been
//! seen — hosts, path segments, methods, statuses, counts, and parameter names from query strings
//! and form/JSON request bodies. Built from the store; never sends anything.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{invalid, live, with_notices};
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult};

pub const BOUND: usize = 24 * 1024;
/// Largest request body inspected for parameter names.
const BODY_CAP: usize = 256 * 1024;
/// Children listed per node before the rest are summarised.
const MAX_CHILDREN: usize = 25;

pub struct HttpSitemap {
    pub(crate) icpt: Option<Interceptor>,
}

#[derive(Default)]
struct Node {
    count: u64,
    methods: BTreeSet<String>,
    statuses: BTreeSet<u16>,
    query: BTreeSet<String>,
    body: BTreeSet<String>,
    children: BTreeMap<String, Node>,
}

impl Node {
    fn to_json(&self, segment: &str, depth: usize) -> Value {
        let mut kids: Vec<(&String, &Node)> = self.children.iter().collect();
        kids.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));
        let omitted = kids.len().saturating_sub(MAX_CHILDREN);
        let children: Vec<Value> = if depth == 0 {
            Vec::new()
        } else {
            kids.iter()
                .take(MAX_CHILDREN)
                .map(|(s, n)| n.to_json(s, depth - 1))
                .collect()
        };
        let mut v = json!({
            "segment": segment,
            "count": self.count,
            "methods": self.methods,
            "statuses": self.statuses,
        });
        if !self.query.is_empty() || !self.body.is_empty() {
            v["params"] = json!({ "query": self.query, "body": self.body });
        }
        if !children.is_empty() {
            v["children"] = json!(children);
        }
        let hidden = if depth == 0 { kids.len() } else { omitted };
        if hidden > 0 {
            v["omitted_children"] = json!(hidden);
        }
        v
    }
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
        let host = obj
            .get("host")
            .and_then(Value::as_str)
            .map(bee_core::pattern::normalize_host);
        let prefix = obj
            .get("path_prefix")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string();
        let depth = obj
            .get("depth")
            .and_then(Value::as_u64)
            .unwrap_or(4)
            .clamp(1, 8) as usize;

        let rows = icpt.with_store(
            |s| -> rusqlite::Result<
                Vec<(
                    String,
                    u16,
                    String,
                    Option<String>,
                    Option<u16>,
                    Option<String>,
                    Vec<u8>,
                )>,
            > {
                let mut stmt = s.conn().prepare(
                    "SELECT host, port, COALESCE(method, ''), target, status, req_body, req_head
                 FROM exchanges WHERE session_id = ?1 AND outcome NOT LIKE 'refused%'",
                )?;
                let it = stmt.query_map([s.session_id()], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
                    ))
                })?;
                it.collect()
            },
        );
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                return ToolOutcome::<()>::failed(e.to_string()).into_tool_result(|_| String::new())
            }
        };

        let mut hosts: BTreeMap<String, Node> = BTreeMap::new();
        for (h, port, method, target, status, body_sha, head) in rows {
            if host.as_ref().is_some_and(|want| *want != h) {
                continue;
            }
            let target = target.unwrap_or_default();
            let path = crate::intercept::store::path_of(&target);
            if !path.starts_with(&prefix) {
                continue;
            }
            let root = hosts.entry(format!("{h}:{port}")).or_default();
            root.count += 1;
            let mut node = root;
            for seg in path.split('/').filter(|s| !s.is_empty()) {
                node = node.children.entry(seg.to_string()).or_default();
                node.count += 1;
            }
            node.methods.insert(method);
            if let Some(st) = status {
                node.statuses.insert(st);
            }
            if let Some((_, q)) = target.split_once('?') {
                for kv in q.split('&').filter(|s| !s.is_empty()) {
                    node.query
                        .insert(kv.split('=').next().unwrap_or("").to_string());
                }
            }
            if let Some(sha) = body_sha {
                if let Some(b) = icpt.with_store(|s| s.read_blob(&sha)).ok().flatten() {
                    for name in body_params(&head, &b[..b.len().min(BODY_CAP)]) {
                        node.body.insert(name);
                    }
                }
            }
        }

        let mut v = json!({
            "hosts": hosts.iter().map(|(h, n)| n.to_json(h, depth)).collect::<Vec<_>>(),
            "enforcement": icpt.enforcement().label(),
        });
        // Fit the bound by shallowing the tree rather than cutting it.
        let mut d = depth;
        while serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0) > BOUND && d > 0 {
            d -= 1;
            v["hosts"] = json!(hosts
                .iter()
                .map(|(h, n)| n.to_json(h, d))
                .collect::<Vec<_>>());
            v["depth_reduced_to"] = json!(d);
        }
        ToolResult::ok(with_notices(
            crate::tools::http::bounded_json(&v, BOUND),
            icpt,
        ))
        .with_provenance(Provenance::Remote {
            source: "http:sitemap".into(),
        })
    }
}

/// Parameter names from a form-urlencoded or JSON request body.
fn body_params(head: &[u8], body: &[u8]) -> Vec<String> {
    let ct = String::from_utf8_lossy(head)
        .split('\n')
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-type")
                .then(|| v.trim().to_ascii_lowercase())
        })
        .unwrap_or_default();
    if ct.contains("json") {
        if let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(body) {
            return m.keys().take(50).cloned().collect();
        }
    }
    if ct.contains("x-www-form-urlencoded") {
        return String::from_utf8_lossy(body)
            .split('&')
            .filter(|s| !s.is_empty())
            .take(50)
            .map(|kv| kv.split('=').next().unwrap_or("").to_string())
            .collect();
    }
    Vec::new()
}
