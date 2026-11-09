//! `http_scope` — read-only: what may be tested, what is only reachable, and which layer enforces
//! each rule (FR-010, FR-011). It cannot change anything; widening needs the operator.

use serde_json::json;

use super::{Reply, ToolDef};
use crate::ops;
use crate::sidecar::Interceptor;

pub const BOUND: usize = 8 * 1024;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_scope",
        description: "Show the HTTP target scope for this session: which hosts may be tested \
                      (targets), which are only reachable as tunnels (egress), which are \
                      TLS-inspected, the pacing limits, and which layer enforces each rule — \
                      the kernel (by address) or the proxy (by name). Read-only: the scope can \
                      only be widened by the operator.",
        parameters: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
    }
}

pub(super) fn call(icpt: &Interceptor) -> Reply {
    Reply::json(&ops::scope_view(icpt), BOUND, None)
}
