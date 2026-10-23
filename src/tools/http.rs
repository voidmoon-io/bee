//! The model-facing HTTP tools (019-http-intercept, contracts/http-tools.md).
//!
//! Every tool answers from the session's [`Interceptor`] and its store, never from a direct
//! connection: with no proxy (a session without `[policy.http]`, or a dead worker) each refuses with
//! `interceptor_unavailable`, so a tool can never fall back to unscoped egress. Results are bounded,
//! and every slice of target-derived bytes is framed `Remote { source: "http:<id>" }` so it reaches
//! the model inside an untrusted-data envelope (contracts/model-framing.md).
//!
//! The tools are adapters over [`crate::intercept::ops`] (024 US6): each parses its arguments into an
//! op spec, makes one op call, and reports through [`respond`].

use serde_json::{json, Value};

use crate::intercept::ops::bound::bounded_json;
use crate::intercept::ops::{self, CallCtx, OpError, Refusal};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult, UnavailableReason};

/// Per-tool output bounds (contracts/http-tools.md).
pub const SCOPE_BOUND: usize = 8 * 1024;

/// Build the HTTP tool `name` around `icpt` — the session's proxy, or `None`, in which case it refuses
/// `interceptor_unavailable`. Called only by [`crate::tools::ToolRegistry::register`], the one tool
/// constructor (024 FR-013).
pub(crate) fn tool(name: &str, icpt: Option<Interceptor>) -> Option<Box<dyn Tool>> {
    Some(match name {
        "http_scope" => Box::new(HttpScope { icpt }),
        "http_send" => Box::new(super::http_send::HttpSend { icpt }),
        "http_get" => Box::new(super::http_get::HttpGet { icpt }),
        "http_history" => Box::new(super::http_history::HttpHistory { icpt }),
        "http_replay" => Box::new(super::http_replay::HttpReplay { icpt }),
        "http_sitemap" => Box::new(super::http_sitemap::HttpSitemap { icpt }),
        "http_fuzz" => Box::new(super::http_fuzz::HttpFuzz { icpt }),
        "http_intercept" => Box::new(super::http_intercept::HttpIntercept { icpt }),
        "http_leads" => Box::new(super::http_leads::HttpLeads { icpt }),
        #[cfg(feature = "vm-test")]
        "http_debug" => Box::new(HttpDebug { icpt }),
        _ => return None,
    })
}

/// The refusal every HTTP tool gives when there is no live proxy.
pub(crate) async fn live(icpt: &Option<Interceptor>) -> Result<&Interceptor, ToolResult> {
    match icpt {
        None => Err(unavailable(
            "this session has no [policy.http], so there is no interception proxy",
        )),
        Some(i) if !i.available().await => Err(unavailable(
            "the proxy worker is not running; HTTP tools stay unavailable rather than send directly",
        )),
        Some(i) => Ok(i),
    }
}

pub(crate) fn unavailable(detail: &str) -> ToolResult {
    ToolOutcome::<()>::unavailable(UnavailableReason::InterceptorUnavailable {
        detail: detail.into(),
    })
    .into_tool_result(|_| String::new())
}

pub(crate) fn invalid(tool: &str, detail: impl std::fmt::Display) -> ToolResult {
    ToolResult::invalid_args(tool, detail)
}

/// The result of one op call, as tool `tool` reports it: a value rendered within `bound` bytes with
/// the proxy's notices appended and tagged with `provenance`, or the op's error. The one place an
/// [`OpError`] becomes a tool result (024 FR-036).
pub(crate) fn respond(
    tool: &str,
    icpt: &Interceptor,
    result: Result<Value, OpError>,
    bound: usize,
    provenance: Option<Provenance>,
) -> ToolResult {
    respond_text(
        tool,
        icpt,
        result.map(|v| bounded_json(&v, bound)),
        provenance,
    )
}

/// [`respond`] for a body the tool has already bounded.
pub(crate) fn respond_text(
    tool: &str,
    icpt: &Interceptor,
    result: Result<String, OpError>,
    provenance: Option<Provenance>,
) -> ToolResult {
    match result {
        Ok(body) => {
            let r = ToolResult::ok(with_notices(body, icpt));
            match provenance {
                Some(p) => r.with_provenance(p),
                None => r,
            }
        }
        Err(e) => op_error(tool, e),
    }
}

/// An op's error as tool `tool`'s result.
pub(crate) fn op_error(tool: &str, e: OpError) -> ToolResult {
    match e {
        OpError::Unavailable(d) => unavailable(&d),
        OpError::Invalid(d) => invalid(tool, d),
        OpError::Refused { reason, note } => {
            let reason = match reason {
                Refusal::OutOfScope { host, port, layer } => {
                    UnavailableReason::OutOfScope { host, port, layer }
                }
                Refusal::EgressOnly { host } => UnavailableReason::EgressOnly { host },
                Refusal::LimitExceeded { limit, value } => {
                    UnavailableReason::LimitExceeded { limit, value }
                }
            };
            let mut r = ToolOutcome::<()>::unavailable(reason).into_tool_result(|_| String::new());
            if let Some(n) = note {
                r.content.push('\n');
                r.content.push_str(&n);
            }
            r
        }
        OpError::Failed(d) => ToolOutcome::<()>::failed(d).into_tool_result(|_| String::new()),
    }
}

/// Operator notices (restart, eviction) appended to the next result — never silent.
fn with_notices(mut body: String, icpt: &Interceptor) -> String {
    for n in icpt.take_notices() {
        body.push_str("\n[bee] ");
        body.push_str(&crate::safe_text::safe_line(&n));
    }
    body
}

/// The current call's attribution, from the sandbox's call context. Computed once per call by the
/// adapter: ops never see the sandbox.
pub(crate) fn call_ctx(sandbox: &Sandbox) -> CallCtx {
    match sandbox.call_context() {
        Some(c) => crate::intercept::creds::wire_ctx(c),
        None => CallCtx {
            call_id: "unattributed".into(),
            turn: 0,
            origin: "tool".into(),
        },
    }
}

// ── http_scope ───────────────────────────────────────────────────────────────────────────────────

/// `http_scope` — read-only: what may be tested, what is only reachable, and which layer enforces
/// each rule (FR-010, FR-011). It cannot change anything; widening needs the operator.
pub struct HttpScope {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpScope {
    fn name(&self) -> &'static str {
        "http_scope"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_scope".into(),
            description: "Show the HTTP target scope for this session: which hosts may be tested \
                          (targets), which are only reachable as tunnels (egress), which are \
                          TLS-inspected, the pacing limits, and which layer enforces each rule — \
                          the kernel (by address) or the proxy (by name). Read-only: the scope can \
                          only be widened by the operator."
                .into(),
            parameters: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        }
    }

    async fn call(&self, _arguments: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        respond(
            "http_scope",
            icpt,
            Ok(ops::scope_view(icpt)),
            SCOPE_BOUND,
            None,
        )
    }
}

// ── http_debug (vm-test builds only) ─────────────────────────────────────────────────────────────

/// `http_debug` — **VM-test builds only** (019 T048). Asks the proxy worker to `connect` or `open`
/// from inside the proxy scope and reports the errno, so the VM matrix can show the kernel confines
/// the proxy itself. It exists in no shipping build: the control frames it sends do not decode
/// outside `vm-test` (asserted in `src/intercept/control.rs`).
#[cfg(feature = "vm-test")]
pub struct HttpDebug {
    pub(crate) icpt: Option<Interceptor>,
}

#[cfg(feature = "vm-test")]
#[async_trait::async_trait]
impl Tool for HttpDebug {
    fn name(&self) -> &'static str {
        "http_debug"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_debug".into(),
            description: "VM-test only: probe the proxy scope with a raw connect or open.".into(),
            parameters: json!({
                "type": "object",
                "properties": { "connect": { "type": "string" }, "read": { "type": "string" } }
            }),
        }
    }

    async fn call(&self, args: Value, _sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let connect = args
            .get("connect")
            .and_then(Value::as_str)
            .map(str::to_string);
        let read = args.get("read").and_then(Value::as_str).map(str::to_string);
        match icpt.debug_probe(connect, read).await {
            Ok(errno) => ToolResult::ok(format!("errno={errno}")),
            Err(e) => ToolResult::error(e.to_string()),
        }
    }
}
