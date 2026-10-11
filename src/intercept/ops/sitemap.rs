//! The sitemap (019 T074, FR-035): a bounded tree of what has been seen — hosts, path segments,
//! methods, statuses, counts, and parameter names from query strings and form/JSON request bodies.
//! Built from the store; never sends anything.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::OpError;
use crate::intercept::sidecar::Interceptor;

/// The `http_sitemap` bound (contracts/http-tools.md#http_sitemap).
pub const BOUND: usize = 24 * 1024;
/// Largest request body inspected for parameter names.
const BODY_CAP: usize = 256 * 1024;
/// Children listed per node before the rest are summarised.
const MAX_CHILDREN: usize = 25;

/// An exchange as the sitemap reads it: host, port, method, target, status, request body blob,
/// request head.
type SitemapRow = (
    String,
    u16,
    String,
    Option<String>,
    Option<u16>,
    Option<String>,
    Vec<u8>,
);

#[derive(Debug, Clone)]
pub struct SitemapQuery {
    /// Only this host (normalised); `None` for every host.
    pub host: Option<String>,
    pub path_prefix: String,
    /// Tree depth, 1–8.
    pub depth: usize,
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

/// The sitemap of this session's traffic, fitted to `bound` bytes by shallowing the tree rather than
/// cutting it.
pub fn sitemap(icpt: &Interceptor, q: SitemapQuery, bound: usize) -> Result<Value, OpError> {
    let rows = icpt
        .with_store(|s| -> rusqlite::Result<Vec<SitemapRow>> {
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
        })
        .map_err(|e| OpError::Failed(e.to_string()))?;

    let mut hosts: BTreeMap<String, Node> = BTreeMap::new();
    for (h, port, method, target, status, body_sha, head) in rows {
        if q.host.as_ref().is_some_and(|want| *want != h) {
            continue;
        }
        let target = target.unwrap_or_default();
        let path = crate::intercept::store::path_of(&target);
        if !path.starts_with(&q.path_prefix) {
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
        if let Some((_, query)) = target.split_once('?') {
            for kv in query.split('&').filter(|s| !s.is_empty()) {
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
        "hosts": hosts.iter().map(|(h, n)| n.to_json(h, q.depth)).collect::<Vec<_>>(),
        "enforcement": icpt.enforcement().label(),
    });
    let mut d = q.depth;
    while serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0) > bound && d > 0 {
        d -= 1;
        v["hosts"] = json!(hosts
            .iter()
            .map(|(h, n)| n.to_json(h, d))
            .collect::<Vec<_>>());
        v["depth_reduced_to"] = json!(d);
    }
    Ok(v)
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
