//! Read-only views: one bounded view of a stored exchange (019 T060), and the Target scope.

use serde_json::{json, Value};

use super::OpError;
use crate::intercept::sidecar::{Enforcement, Interceptor};
use crate::intercept::slice::{self, View, DECODE_CAP};

/// Which half of an exchange to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Request,
    Response,
}

impl Part {
    pub fn as_str(self) -> &'static str {
        match self {
            Part::Request => "request",
            Part::Response => "response",
        }
    }
}

/// `view` of `part` of exchange `id`, its content within `content_bound` bytes. Never a whole body
/// beyond that: the caller asks for headers, a byte range of the decoded body, a grep with context,
/// a JSON pointer, or the raw head.
pub fn read_exchange(
    icpt: &Interceptor,
    id: &str,
    part: Part,
    view: &View,
    content_bound: usize,
) -> Result<Value, OpError> {
    let e = icpt
        .with_store(|s| s.get_exchange(id))
        .map_err(|e| OpError::Failed(e.to_string()))?
        .ok_or_else(|| OpError::Invalid(format!("no exchange `{id}`")))?;
    let (head, sha) = match part {
        Part::Request => (e.req_head.clone(), e.req_body.clone()),
        Part::Response => (e.resp_head.clone(), e.resp_body.clone()),
    };
    let meta = match &sha {
        Some(s) => icpt
            .with_store(|st| st.blob_meta(s))
            .map_err(|e| OpError::Failed(e.to_string()))?,
        None => None,
    };
    let evicted = meta.as_ref().is_some_and(|m| m.evicted);
    let stored_truncated = meta.as_ref().is_some_and(|m| m.truncated);
    let encoding = match part {
        // A request head's headers read the same way a response head's do.
        Part::Request => crate::intercept::store::content_encoding(&head),
        Part::Response => meta
            .as_ref()
            .map(|m| m.encoding.clone())
            .unwrap_or_else(|| "identity".into()),
    };

    let needs_body = !matches!(view, View::Headers | View::RawHead);
    let (decoded, decoded_truncated) = if needs_body && !evicted {
        let raw = match &sha {
            Some(s) => icpt
                .with_store(|st| st.read_blob(s))
                .map_err(|e| OpError::Failed(e.to_string()))?
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let d = slice::decode(&raw, &encoding, DECODE_CAP).map_err(OpError::Failed)?;
        (d.bytes, d.decoded_truncated)
    } else {
        (Vec::new(), false)
    };
    if needs_body && evicted {
        return Err(OpError::Failed(format!(
            "the {} body of {id} was evicted from the store (over store_cap_bytes); its \
             headers remain",
            part.as_str()
        )));
    }
    let content = slice::apply(view, &head, &decoded, content_bound).map_err(OpError::Invalid)?;
    Ok(json!({
        "id": id,
        "part": part.as_str(),
        "total_decoded_bytes": needs_body.then_some(decoded.len()),
        "encoding": encoding,
        "truncated": stored_truncated,
        "decoded_truncated": decoded_truncated,
        "evicted": evicted,
        "origin": e.origin_kind,
        "content": content,
    }))
}

/// What may be tested, what is only reachable, and which layer enforces each rule (019 FR-010,
/// FR-011; contracts/http-tools.md#http_scope).
pub fn scope_view(icpt: &Interceptor) -> Value {
    let scope = icpt.http_scope();
    let checker = crate::intercept::worker::scope::ScopeChecker::new(scope.clone());
    let scope = &scope;
    let enforcement = icpt.enforcement();
    let entries: Vec<Value> = scope
        .targets
        .iter()
        .chain(&scope.egress)
        .map(|e| {
            let layers: Vec<Value> = e
                .enforced_by
                .iter()
                .map(|l| match l {
                    // In advisory mode no kernel rule is installed; say so rather than list one.
                    bee_core::compiler::EnforcedBy::Kernel { addr, port } => match enforcement {
                        Enforcement::Kernel => {
                            json!({ "layer": "kernel", "addr": addr, "port": port })
                        }
                        Enforcement::Advisory { .. } => {
                            json!({ "layer": "kernel", "addr": addr, "port": port, "installed": false })
                        }
                    },
                    bee_core::compiler::EnforcedBy::Proxy { host } => {
                        json!({ "layer": "proxy", "host": host })
                    }
                })
                .collect();
            json!({
                "host": e.host,
                "port": e.port,
                "role": e.role,
                "inspect": checker.is_inspected(&e.host, e.port),
                "insecure_upstream": checker.is_insecure_upstream(&e.host),
                "enforced_by": layers,
            })
        })
        .collect();
    let mut v = json!({
        "enforcement": enforcement.label(),
        "entries": entries,
        "limits": scope.limits,
        "widening": "requires operator approval",
    });
    if let Enforcement::Advisory { reason } = enforcement {
        v["advisory_reason"] = json!(reason);
    }
    v
}
