//! The model-facing HTTP tools (019-http-intercept, contracts/http-tools.md).
//!
//! Every tool answers from the session's [`Interceptor`] and its store, never from a direct
//! connection: with no proxy (a session without `[policy.http]`, or a dead worker) each refuses with
//! `interceptor_unavailable`, so a tool can never fall back to unscoped egress. Results are bounded,
//! and every slice of target-derived bytes is framed `Remote { source: "http:<id>" }` so it reaches
//! the model inside an untrusted-data envelope (contracts/model-framing.md).

use serde_json::{json, Value};

use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::{Tool, ToolOutcome, ToolRegistry, ToolResult, UnavailableReason, HTTP_TOOLS};

/// Per-tool output bounds (contracts/http-tools.md).
pub const SCOPE_BOUND: usize = 8 * 1024;

/// An unconfigured tool for `name` — it refuses until [`configure_http_tools`] replaces it.
pub fn unconfigured(name: &str) -> Option<Box<dyn Tool>> {
    tool(name, None)
}

/// Re-register every HTTP tool present in `registry` with the session's proxy (last wins).
pub fn configure_http_tools(registry: &mut ToolRegistry, icpt: &Interceptor) {
    #[cfg(feature = "vm-test")]
    if registry.contains("http_debug") {
        registry.insert(Box::new(HttpDebug {
            icpt: Some(icpt.clone()),
        }));
    }
    for name in HTTP_TOOLS {
        if registry.contains(name) {
            if let Some(t) = tool(name, Some(icpt.clone())) {
                registry.insert(t);
            }
        }
    }
}

fn tool(name: &str, icpt: Option<Interceptor>) -> Option<Box<dyn Tool>> {
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

/// Render `v` as compact JSON within `bound` bytes — always **valid** JSON. Each tool shapes its
/// result to fit first; this is the backstop. It halves the longest string field (marking the cut)
/// until the serialised form fits, so a model never receives a JSON value cut off mid-token.
pub(crate) fn bounded_json(v: &Value, bound: usize) -> String {
    let mut v = v.clone();
    for _ in 0..32 {
        let s = serde_json::to_string(&v).unwrap_or_default();
        if s.len() <= bound {
            return s;
        }
        if !halve_longest_string(&mut v) {
            break;
        }
    }
    serde_json::json!({ "error": format!("result exceeded its {bound}-byte bound") }).to_string()
}

/// Halve the longest string in `v` (by serialised length, which is what the bound counts). `false`
/// when there is no string left worth shortening.
fn halve_longest_string(v: &mut Value) -> bool {
    fn longest(v: &mut Value) -> Option<(&mut String, usize)> {
        match v {
            Value::String(s) => {
                let n = serde_json::to_string(s).map(|j| j.len()).unwrap_or(0);
                Some((s, n))
            }
            Value::Array(a) => a.iter_mut().filter_map(longest).max_by_key(|(_, n)| *n),
            Value::Object(o) => o.values_mut().filter_map(longest).max_by_key(|(_, n)| *n),
            _ => None,
        }
    }
    let Some((s, n)) = longest(v) else {
        return false;
    };
    if n < 32 {
        return false;
    }
    let mut cut = s.len() / 2;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str("… [cut]");
    true
}

/// Text for the model from body bytes: printable as-is, or — when the bytes are mostly not text — a
/// one-line description instead of a page of escapes.
pub(crate) fn text_or_binary(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    let odd = text
        .chars()
        .filter(|c| (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) || *c == '\u{FFFD}')
        .count();
    if !b.is_empty() && odd * 10 > text.chars().count() {
        return format!(
            "(binary: {} bytes shown here would be mostly unprintable)",
            b.len()
        );
    }
    text.into_owned()
}

/// Operator notices (restart, eviction) appended to the next result — never silent.
pub(crate) fn with_notices(mut body: String, icpt: &Interceptor) -> String {
    for n in icpt.take_notices() {
        body.push_str("\n[bee] ");
        body.push_str(&crate::safe_text::safe_line(&n));
    }
    body
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
        let v = scope_view(icpt);
        ToolResult::ok(with_notices(bounded_json(&v, SCOPE_BOUND), icpt))
    }
}

/// The `http_scope` result (contracts/http-tools.md#http_scope).
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
                        crate::intercept::sidecar::Enforcement::Kernel => {
                            json!({ "layer": "kernel", "addr": addr, "port": port })
                        }
                        crate::intercept::sidecar::Enforcement::Advisory { .. } => {
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
    if let crate::intercept::sidecar::Enforcement::Advisory { reason } = enforcement {
        v["advisory_reason"] = json!(reason);
    }
    v
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
