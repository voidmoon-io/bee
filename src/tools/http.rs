//! The model-facing HTTP tools (019-http-intercept, contracts/http-tools.md).
//!
//! Every tool answers from the session's [`Interceptor`] and its store, never from a direct
//! connection: with no proxy (a session without `[policy.http]`, or a dead worker) each refuses with
//! `interceptor_unavailable`, so a tool can never fall back to unscoped egress. Results are bounded,
//! and every slice of target-derived bytes is framed `Remote { source: "http:<id>" }` so it reaches
//! the model inside an untrusted-data envelope (contracts/model-framing.md).
//!
//! The tools themselves — definitions, argument parsing, result shaping — are [`comb::api`], shared
//! with `comb serve`. This module is the one bee adapter: the sandbox's call attribution in, a
//! [`ToolResult`] with the proxy's notices and the result's provenance out.

use serde_json::Value;

use crate::intercept::fuzz;
use crate::intercept::ops::{CallCtx, OpError, Refusal};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult, UnavailableReason};
use comb::api::{self, CallError, LinesFuture, PayloadFiles, ToolDef};

/// Build the HTTP tool `name` around `icpt` — the session's proxy, or `None`, in which case it refuses
/// `interceptor_unavailable`. Called only by [`crate::tools::ToolRegistry::register`], the one tool
/// constructor (024 FR-013).
pub(crate) fn tool(name: &str, icpt: Option<Interceptor>) -> Option<Box<dyn Tool>> {
    Some(Box::new(HttpTool {
        def: api::def(name)?,
        icpt,
    }))
}

/// One `http_*` tool: its comb definition and the session's proxy.
struct HttpTool {
    def: ToolDef,
    icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpTool {
    fn name(&self) -> &'static str {
        self.def.name
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.def.name.into(),
            description: self.def.description.into(),
            parameters: self.def.parameters.clone(),
        }
    }

    async fn call(&self, args: Value, sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let files = ScopedFiles { sandbox };
        match api::call(icpt, self.def.name, args, &call_ctx(sandbox), &files).await {
            Ok(reply) => {
                let mut r = ToolResult::ok(with_notices(reply.text, icpt));
                if let Some(source) = reply.source {
                    // Target-derived: reaches the model inside an untrusted-data envelope.
                    r = r.with_provenance(Provenance::Remote { source });
                }
                r.is_error = reply.is_error;
                r
            }
            Err(CallError::Op(e)) => op_error(self.def.name, e),
            Err(CallError::NotGranted { name }) => {
                ToolOutcome::<()>::unavailable(UnavailableReason::NotGranted { name })
                    .into_tool_result(|_| String::new())
            }
            Err(CallError::UnknownTool(n)) => ToolResult::error(format!("unknown tool `{n}`")),
        }
    }
}

/// The refusal every HTTP tool gives when there is no live proxy.
async fn live(icpt: &Option<Interceptor>) -> Result<&Interceptor, ToolResult> {
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

fn unavailable(detail: &str) -> ToolResult {
    ToolOutcome::<()>::unavailable(UnavailableReason::InterceptorUnavailable {
        detail: detail.into(),
    })
    .into_tool_result(|_| String::new())
}

/// `http_fuzz` project payload files, read by a `cat` child in the tool scope so the kernel decides
/// whether the file is readable — the harness never opens a project file (016 rule).
struct ScopedFiles<'s> {
    sandbox: &'s Sandbox,
}

impl PayloadFiles for ScopedFiles<'_> {
    fn read_lines<'a>(&'a self, path: &'a str) -> LinesFuture<'a> {
        Box::pin(async move {
            let r = crate::tools::exec::run_child(
                self.sandbox,
                "cat",
                &["--".to_string(), path.to_string()],
                None,
                fuzz::MAX_FILE_BYTES + 1,
            )
            .await;
            let invalid = |e: String| CallError::Op(OpError::Invalid(e));
            match r.exit_code {
                Some(0) if !r.truncated => fuzz::file_lines(&r.content).map_err(invalid),
                Some(0) => Err(invalid(format!(
                    "payload file exceeds {} bytes",
                    fuzz::MAX_FILE_BYTES
                ))),
                // No exit code: the child never ran — `cat` is not in this scope's exec allowlist.
                None | Some(126) | Some(127) => Err(CallError::NotGranted { name: "cat".into() }),
                Some(_) => Err(CallError::Op(OpError::Failed(format!(
                    "reading {path} was refused in the tool scope: {}",
                    r.content.lines().last().unwrap_or("")
                )))),
            }
        })
    }
}

/// An op's error as tool `tool`'s result.
fn op_error(tool: &str, e: OpError) -> ToolResult {
    match e {
        OpError::Unavailable(d) => unavailable(&d),
        OpError::Invalid(d) => ToolResult::invalid_args(tool, d),
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
