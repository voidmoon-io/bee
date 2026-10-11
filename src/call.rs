//! One tool call, start to finish (024 FR-017–FR-027, contracts/call-lifecycle.md).
//!
//! Both loops — the headless episode and the interactive exchange — run every tool call through
//! [`run_call`], and nowhere else. It owns the whole sequence: proactive escalation, the timed
//! attempt, collecting the call's kernel audit, escalating on a kernel denial and retrying inside the
//! same call, closing the call, escalating on a proxy refusal and retrying in a new call, and the
//! proxy-scope and late drains. It returns one [`CallOutcome`]; rendering it is the loop's business.
//!
//! The rules this module is the only spelling of:
//!
//! - **At most one retry per call** (FR-019), and only after an escalation that actually widened the
//!   scope — never on `AlreadyHeld` or a refusal (FR-020).
//! - **The denial that justified a retry is kept** (FR-021): the denied attempt's audit in
//!   [`CallOutcome::denied_attempt_audit`], a refused attempt's proxy events in
//!   [`CallOutcome::denied_attempt_proxy_events`].
//! - **Proxy-scope events are the proxy's** (FR-022): they are drained after escalation, which they
//!   never drive, and never counted as the tool's denials ([`CallOutcome::tool_denials`]).
//! - **Late events belong to this call** (FR-023): the final drain attributes them here.
//! - **One time budget per call** (FR-024): a retry gets only what the first attempt left, under both
//!   timeout policies, and does not start when nothing is left.
//! - **Result and audit come from one attempt** (FR-025): a retry that times out is abandoned, and
//!   the attempt before it stands — its result, its audit, its proxy events — marked timed out. Any
//!   events the abandoned retry produced are appended: they are still this call's.
//!
//! The REPL turns its `tool_timeout_secs` into [`TimeoutPolicy::PerCall`]; the episode passes its
//! wall-clock deadline as [`TimeoutPolicy::Deadline`].

use std::time::{Duration, Instant};

use bee_core::AuditEvent;
use serde::{Deserialize, Serialize};

use crate::grants::escalate::{escalate, EscalateOutcome, LoopEscalation};
use crate::grants::{ActivePolicy, GrantOrigin};
use crate::hooks::StepEvent;
use crate::provider::ToolCall;
use crate::proxy_event::ProxyEvent;
use crate::sandbox::{CallContext, CallOrigin, Sandbox};
use crate::tools::{ToolRegistry, ToolResult};
use crate::transcript::RecordedCall;

/// How long one call may take, first attempt and retry together (FR-024).
#[derive(Debug, Clone, Copy)]
pub enum TimeoutPolicy {
    /// An absolute deadline — the episode's wall clock.
    Deadline(Instant),
    /// A limit per call — the REPL's `tool_timeout_secs`. Becomes a deadline when the call starts,
    /// so a retry shares it.
    PerCall(Duration),
}

/// The call to run.
pub struct CallInput<'a> {
    pub call: &'a ToolCall,
    /// The turn the call context is stamped with (it reaches the interception proxy's per-call
    /// credential).
    pub turn: u32,
    pub origin: CallOrigin,
    pub timeout: TimeoutPolicy,
}

/// The session's escalation state, for a call that may widen the scope.
pub struct Escalation<'a> {
    pub config: &'a LoopEscalation,
    pub active: &'a mut ActivePolicy,
    /// The turn a lease granted during this call is stamped with. Until 024 PR4 the REPL counts these
    /// per call (FR-029, D3); the episode passes the model turn.
    pub lease_turn: u32,
}

/// What started an escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Trigger {
    /// A hook asked for a grant before the call ran (a skill's `requires`).
    Proactive,
    /// The kernel denied the call `op` on `target`.
    KernelDenial { op: String, target: String },
    /// The interception proxy refused `host:port` as outside the target scope.
    ProxyRefusal { host: String, port: u16 },
}

/// One widen cycle run during a call, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationRecord {
    pub trigger: Trigger,
    pub outcome: EscalateOutcome,
}

/// Everything one tool call produced (data-model.md).
#[derive(Debug, Clone)]
pub struct CallOutcome {
    /// The result of the attempt that stands. Always from the same attempt as `audit` (FR-025).
    pub result: ToolResult,
    /// The tool scope's kernel events for the attempt that stands, plus late events (FR-023).
    pub audit: Vec<AuditEvent>,
    /// The audit of an attempt that was denied and retried (FR-021). Empty without a retry.
    pub denied_attempt_audit: Vec<AuditEvent>,
    /// The proxy scope's kernel events, `scope_id = "proxy"` (FR-022).
    pub proxy_audit: Vec<AuditEvent>,
    /// The proxy events of the attempt that stands.
    pub proxy_events: Vec<ProxyEvent>,
    /// The proxy events of an attempt a proxy refusal retried (FR-021). Empty without that retry.
    pub denied_attempt_proxy_events: Vec<ProxyEvent>,
    /// A retry ran to completion and its attempt is the one that stands.
    pub retried: bool,
    /// An attempt hit the time limit.
    pub timed_out: bool,
    /// Every widen cycle run during the call, in order.
    pub escalations: Vec<EscalationRecord>,
    /// A hook refused the call before it ran (FR-031): the tool never executed, and `result` says so.
    pub refused_by_hook: Option<String>,
}

impl CallOutcome {
    /// Denials the tool met in the attempt that stands — never the proxy scope's (FR-022), and never
    /// a denied attempt that a granted retry replaced: the call that stands was not denied.
    pub fn tool_denials(&self) -> usize {
        self.audit
            .iter()
            .filter(|e| e.decision == "denied" && e.scope_id.as_deref() != Some("proxy"))
            .count()
    }

    /// Every kernel event of the call, in the order the session record keeps them: the denied
    /// attempt, the attempt that stands, then the proxy scope.
    pub fn audit_trail(&self) -> impl Iterator<Item = &AuditEvent> {
        self.denied_attempt_audit
            .iter()
            .chain(&self.audit)
            .chain(&self.proxy_audit)
    }

    /// The transcript form. `audit` there keeps its pre-024 meaning — the call's tool and proxy
    /// events together, the proxy's tagged `scope_id = "proxy"` — so existing readers are unaffected.
    pub fn to_recorded(&self, call: &ToolCall) -> RecordedCall {
        RecordedCall {
            call: call.clone(),
            result: self.result.clone(),
            audit: self
                .audit
                .iter()
                .chain(&self.proxy_audit)
                .cloned()
                .collect(),
            proxy_events: self.proxy_events.clone(),
            denied_attempt_audit: self.denied_attempt_audit.clone(),
            denied_attempt_proxy_events: self.denied_attempt_proxy_events.clone(),
            escalations: self.escalations.clone(),
            retried: self.retried,
            timed_out: self.timed_out,
            refused_by_hook: self.refused_by_hook.clone(),
        }
    }
}

/// Run one tool call to completion, following contracts/call-lifecycle.md. The returned future is
/// `Send`: the concurrent runner spawns the episode loop.
pub async fn run_call(
    input: CallInput<'_>,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
    mut esc: Option<Escalation<'_>>,
) -> CallOutcome {
    let tc = input.call;
    let (deadline, timeout_message) = match input.timeout {
        TimeoutPolicy::Deadline(d) => (
            d,
            "tool aborted: episode wall-clock deadline reached".to_string(),
        ),
        TimeoutPolicy::PerCall(t) => (
            Instant::now() + t,
            format!("tool timed out after {}s", t.as_secs()),
        ),
    };
    let ctx = CallContext {
        call_id: tc.id.clone(),
        turn: input.turn,
        origin: input.origin,
    };
    let mut escalations = Vec::new();

    // 1. Before the call: a hook may refuse it, and then it never runs (FR-031); or ask for a grant
    //    (a loaded skill's `requires`), and the call then runs under the possibly-widened scope.
    if let Some(e) = esc.as_mut() {
        match before_call(e, tc, sandbox, registry).await {
            Before::Refused(reason) => {
                return CallOutcome {
                    result: ToolResult::refused_by_hook(&reason),
                    audit: Vec::new(),
                    denied_attempt_audit: Vec::new(),
                    proxy_audit: Vec::new(),
                    proxy_events: Vec::new(),
                    denied_attempt_proxy_events: Vec::new(),
                    retried: false,
                    timed_out: false,
                    escalations,
                    refused_by_hook: Some(reason),
                }
            }
            Before::Run(Some(rec)) => escalations.push(rec),
            Before::Run(None) => {}
        }
    }

    // 2–3. Open the call — attributing what it spawns, and any retry, to it — run it, collect.
    //    A call to an MCP tool owns the events of that server's own process (FR-027).
    let server = registry.mcp_server(&tc.name).map(str::to_string);
    let server = server.as_deref();
    sandbox.begin_call(ctx.clone()).await;
    let (mut result, mut timed_out) =
        attempt(tc, &*sandbox, &*registry, deadline, &timeout_message).await;
    sandbox.settle().await;
    let mut audit = sandbox.drain_audit(server);
    let mut denied_attempt_audit = Vec::new();
    let mut retried = false;

    // 4. A kernel denial may be escalated — a grant scoped to the denied resource — and the call
    //    retried once, inside the same open call.
    if let (Some(e), Some((op, target))) = (esc.as_mut(), first_denial(&audit)) {
        if let Some(rec) = reactive(e, &op, &target, tc, sandbox, registry).await {
            let granted = rec.outcome.is_granted();
            escalations.push(rec);
            if granted && !left(deadline).is_zero() {
                let (r, t) = attempt(tc, &*sandbox, &*registry, deadline, &timeout_message).await;
                sandbox.settle().await;
                let retry_audit = sandbox.drain_audit(server);
                if t {
                    // FR-025: the abandoned retry does not replace the attempt that stands. Its
                    // kernel events are still this call's.
                    timed_out = true;
                    audit.extend(retry_audit);
                } else {
                    denied_attempt_audit = std::mem::replace(&mut audit, retry_audit);
                    result = r;
                    retried = true;
                }
            }
        }
    }

    // 5. Close the call.
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut proxy_events = sandbox.end_call().await;
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut denied_attempt_proxy_events = Vec::new();

    // 6. A proxy refusal may become a consented target-scope widening, and the call is retried once
    //    in a new call — unless a kernel retry already spent the one retry.
    #[cfg(feature = "intercept")]
    if !retried {
        if let Some(e) = esc.as_mut() {
            if let Some(rec) = proxy_refusal(e, &proxy_events, tc, sandbox, registry).await {
                let granted = rec.outcome.is_granted();
                escalations.push(rec);
                if granted && !left(deadline).is_zero() {
                    sandbox.begin_call(ctx.clone()).await;
                    let (r, t) =
                        attempt(tc, &*sandbox, &*registry, deadline, &timeout_message).await;
                    sandbox.settle().await;
                    let retry_audit = sandbox.drain_audit(server);
                    let retry_proxy = sandbox.end_call().await;
                    if t {
                        // FR-025: as for a kernel retry, the attempt before stands; the abandoned
                        // retry's events are still this call's.
                        timed_out = true;
                        audit.extend(retry_audit);
                        proxy_events.extend(retry_proxy);
                    } else {
                        denied_attempt_audit = std::mem::replace(&mut audit, retry_audit);
                        denied_attempt_proxy_events =
                            std::mem::replace(&mut proxy_events, retry_proxy);
                        result = r;
                        retried = true;
                    }
                }
            }
        }
    }

    // 7. The proxy scope's kernel events, only now — after escalation, which they must never drive —
    //    then tool-scope events that reached the ring since the last drain, which belong here, not to
    //    the next call (FR-022, FR-023).
    let proxy_audit = sandbox.drain_sidecar_audit();
    audit.extend(sandbox.drain_audit(server));

    CallOutcome {
        result,
        audit,
        denied_attempt_audit,
        proxy_audit,
        proxy_events,
        denied_attempt_proxy_events,
        retried,
        timed_out,
        escalations,
        refused_by_hook: None,
    }
}

/// Time left before `deadline`.
fn left(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// One attempt under what is left of the call's time. `true` when it hit the limit.
async fn attempt(
    tc: &ToolCall,
    sandbox: &Sandbox,
    registry: &ToolRegistry,
    deadline: Instant,
    timeout_message: &str,
) -> (ToolResult, bool) {
    match tokio::time::timeout(left(deadline), registry.execute(tc, sandbox)).await {
        Ok(r) => (r, false),
        Err(_) => (ToolResult::error(timeout_message), true),
    }
}

/// The first denial in a drained tool-scope audit, as `(op, target)`.
fn first_denial(audit: &[AuditEvent]) -> Option<(String, String)> {
    audit
        .iter()
        .find(|e| e.decision == "denied")
        .map(|e| (e.op.clone(), e.target.clone()))
}

/// Run the widen cycle for `delta` from `origin`, recording it under `trigger`.
#[allow(clippy::too_many_arguments)]
async fn widen(
    e: &mut Escalation<'_>,
    trigger: Trigger,
    origin: GrantOrigin,
    delta: crate::grants::GrantDelta,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> EscalationRecord {
    let outcome = escalate(
        e.active,
        origin,
        delta,
        e.config.default_ttl,
        e.lease_turn,
        &e.config.operator,
        sandbox,
        registry,
    )
    .await;
    EscalationRecord { trigger, outcome }
}

/// What the hooks decided before a call.
enum Before {
    /// Run it — after the proactive widen cycle, if a hook proposed one.
    Run(Option<EscalationRecord>),
    /// Do not run it.
    Refused(String),
}

/// Dispatch `BeforeToolCall`: a refusal stops the call (FR-031, and outranks any proposed grant —
/// FR-034); a proposed grant runs the proactive widen cycle (007 US2).
async fn before_call(
    e: &mut Escalation<'_>,
    tc: &ToolCall,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Before {
    let d = crate::hooks::dispatch(&e.config.hooks, &StepEvent::BeforeToolCall(tc)).await;
    if let Some(reason) = d.deny {
        return Before::Refused(reason);
    }
    let Some(delta) = d.escalate else {
        return Before::Run(None);
    };
    let skill = tc
        .arguments
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("skill")
        .to_string();
    Before::Run(Some(
        widen(
            e,
            Trigger::Proactive,
            GrantOrigin::SkillRequires { skill },
            delta,
            sandbox,
            registry,
        )
        .await,
    ))
}

/// The reactive step (007 US1): dispatch `KernelDenial` for the first denial; on a proposed grant
/// scoped to the denied resource, widen.
async fn reactive(
    e: &mut Escalation<'_>,
    op: &str,
    target: &str,
    tc: &ToolCall,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Option<EscalationRecord> {
    let ev = StepEvent::KernelDenial {
        op,
        target,
        call: tc,
    };
    let delta = crate::hooks::dispatch(&e.config.hooks, &ev)
        .await
        .escalate?;
    Some(
        widen(
            e,
            Trigger::KernelDenial {
                op: op.to_string(),
                target: target.to_string(),
            },
            GrantOrigin::ReactiveDenial {
                op: op.to_string(),
                target: target.to_string(),
            },
            delta,
            sandbox,
            registry,
        )
        .await,
    )
}

/// The proxy-refusal step (019 US3): dispatch `ProxyRefusal` for the first out-of-scope refusal; on a
/// proposed grant, widen the target scope by exactly that `host:port`.
#[cfg(feature = "intercept")]
async fn proxy_refusal(
    e: &mut Escalation<'_>,
    events: &[ProxyEvent],
    tc: &ToolCall,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Option<EscalationRecord> {
    let ev = events
        .iter()
        .find(|e| e.kind == crate::proxy_event::ProxyEventKind::RefusedOutOfScope)?;
    let step = StepEvent::ProxyRefusal {
        host: &ev.host,
        port: ev.port,
        call: tc,
    };
    let delta = crate::hooks::dispatch(&e.config.hooks, &step)
        .await
        .escalate?;
    Some(
        widen(
            e,
            Trigger::ProxyRefusal {
                host: ev.host.clone(),
                port: ev.port,
            },
            GrantOrigin::ProxyRefusal {
                host: ev.host.clone(),
                port: ev.port,
                call: tc.id.clone(),
            },
            delta,
            sandbox,
            registry,
        )
        .await,
    )
}

/// `run_call`'s future must be `Send`: the concurrent runner spawns the episode loop (R2).
#[allow(dead_code)]
fn _assert_send<'a>(
    input: CallInput<'a>,
    sandbox: &'a mut Sandbox,
    registry: &'a mut ToolRegistry,
    esc: Option<Escalation<'a>>,
) {
    fn send<T: Send>(_: T) {}
    send(run_call(input, sandbox, registry, esc));
}
