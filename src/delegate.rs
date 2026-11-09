//! Delegation (018-subagent-scopes): run an operator-authored agent as a subagent, in its own kernel
//! scope, under a policy proven to be a subset of the delegating session's.
//!
//! The `task` tool only names an agent and a task ([`crate::tools::task`]); the call lifecycle
//! (`crate::call`) hands the request here, with what the delegating loop holds at that moment — its
//! active policy, its tool registry, its sandbox. In order, before anything runs:
//!
//! 1. the agent's tools must all be tools the session holds (FR-012);
//! 2. the child policy is `parent.derive(agent's request)` — **before any cgroup exists**, so an
//!    over-broad agent is refused with nothing to clean up (FR-009, FR-010);
//! 3. the child scope is created on the session's supervisor, flat beside the parent's
//!    ([`crate::supervisor`] on why never nested), and its events are routed to it alone;
//! 4. the child runs its own loop — its own conversation, the agent's body as instructions, `finish`
//!    to end — and its scope is torn down; a teardown failure makes the delegation `Failed` (FR-022).
//!
//! The parent receives a bounded report and never the child's individual calls (FR-027); the child's
//! whole record is attached to the parent's `task` call in the transcript.
//!
//! A session with no kernel scope still validates the derivation (FR-033) and then runs the child as
//! a host process, saying in the report and the record that nothing enforced its limits (FR-032).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use crate::episode::{run_loop, LoopOptions, ProgressSink};
use crate::provider::{Model, Provenance};
use crate::sandbox::Sandbox;
use crate::scenario::{Scenario, ScoringMode};
use crate::skills::SkillRegistry;
use crate::tools::finish::FinishOutcome;
use crate::tools::{DelegationRequest, ToolRegistry, ToolResult};
use crate::transcript::{
    CutShortReason, DelegationOutcome, DelegationRecord, EpisodeStatus, EpisodeTranscript,
    RefusalReason,
};

/// Delegation depth a session allows by default: its subagents do not delegate further.
pub const DEFAULT_MAX_DEPTH: u32 = 1;

/// A progress sink that can be shared with a child loop.
pub type SharedProgress = Arc<dyn Fn(&str) + Send + Sync>;

/// A loop's delegation settings, carried in [`LoopOptions`]. Present only when the session holds
/// the `task` tool.
#[derive(Clone)]
pub struct Delegation {
    /// The session's discovered agent definitions.
    pub agents: Arc<SkillRegistry>,
    /// The depth of the loop holding this: 0 for the session itself.
    pub depth: u32,
    pub max_depth: u32,
    /// Where delegation lines and the child's own progress go, indented by depth.
    pub progress: Option<SharedProgress>,
}

impl Delegation {
    /// Settings for a session over `agents`.
    pub fn new(agents: Arc<SkillRegistry>, progress: Option<SharedProgress>) -> Self {
        Delegation {
            agents,
            depth: 0,
            max_depth: DEFAULT_MAX_DEPTH,
            progress,
        }
    }

    fn emit(&self, line: &str) {
        if let Some(p) = &self.progress {
            p(&format!("{}{line}", "  ".repeat(self.depth as usize + 1)));
        }
    }
}

/// What a loop lends the call lifecycle so it can fulfil a `task` call: the settings, and the model
/// the child will use (the session's — per-agent models are out of scope).
pub struct Delegator<'a> {
    pub config: &'a Delegation,
    pub model: &'a dyn Model,
}

/// What the delegating loop holds when the `task` call returns.
pub struct ParentView<'a> {
    /// The session's active policy now — the child is bounded by what the parent holds *now*
    /// (US2 AS-4). `None`: the loop has no policy to derive from, and delegation is refused.
    pub policy: Option<&'a bee_core::Policy>,
    pub registry: &'a ToolRegistry,
    pub sandbox: &'a Sandbox,
    /// The parent call's wall-clock deadline; the child shares it.
    pub deadline: Instant,
}

/// A delegation's result: what replaces the `task` call's result, and the record attached to it.
pub struct Delegated {
    pub result: ToolResult,
    pub record: DelegationRecord,
}

/// The future of a delegation, boxed: a child runs a loop, which runs calls, which may delegate.
pub type DelegationFuture<'a> = Pin<Box<dyn Future<Output = Delegated> + Send + 'a>>;

/// Run `req` (see the module docs). Never panics on a bad request; every refusal names its cause.
pub fn run<'a>(
    d: &'a Delegator<'a>,
    req: &'a DelegationRequest,
    parent: ParentView<'a>,
) -> DelegationFuture<'a> {
    Box::pin(run_inner(d, req, parent))
}

async fn run_inner(
    d: &Delegator<'_>,
    req: &DelegationRequest,
    parent: ParentView<'_>,
) -> Delegated {
    let cfg = d.config;
    let depth = cfg.depth + 1;
    let refuse = |reason: RefusalReason| refused(&req.agent, depth, reason);

    let Some(agent) = cfg.agents.agent(&req.agent) else {
        return refuse(RefusalReason::UnknownAgent {
            name: req.agent.clone(),
        });
    };
    // FR-025, the loop's half: the tool is also left out of a child at the limit (R10).
    if cfg.depth >= cfg.max_depth {
        return refuse(RefusalReason::DepthExceeded {
            max_depth: cfg.max_depth,
        });
    }
    let Some(parent_policy) = parent.policy else {
        return refuse(RefusalReason::Unavailable {
            detail: "this loop has no session policy to derive a subagent's from".into(),
        });
    };
    // Plan Refresh §5: a child of an intercepted session would share the parent's proxy, and its
    // exchanges would be recorded as the parent's.
    if parent_policy.http.as_ref().is_some_and(|h| h.is_active()) {
        return refuse(RefusalReason::Unavailable {
            detail: "subagents of an intercepted session ([policy.http]) need their own proxy \
                     scope, which bee does not provide yet (019 T092)"
                .into(),
        });
    }
    // FR-012: every tool the agent names must be one the session holds — checked before anything
    // is built, by name.
    let child_may_delegate = depth < cfg.max_depth;
    for tool in &agent.tools {
        if tool == "task" && !child_may_delegate {
            continue;
        }
        if !parent.registry.contains(tool) || parent.registry.mcp_server(tool).is_some() {
            return refuse(RefusalReason::ToolNotHeld { tool: tool.clone() });
        }
    }
    // FR-009/FR-010: the child's policy is proven ⊆ the parent's before any scope exists.
    let derived = match parent_policy.derive(agent.requested_policy()) {
        Ok(p) => p,
        Err(e) => {
            return refuse(RefusalReason::OverGrant {
                detail: e.to_string(),
            })
        }
    };
    let instructions = match agent.body() {
        Ok(b) => b,
        Err(e) => {
            return failed(
                &req.agent,
                depth,
                String::new(),
                false,
                format!("could not read the agent's instructions: {e}"),
            )
        }
    };

    // The child's tools, built from the session's dependencies, recomputed for its policy.
    let deps = (**parent.registry.deps()).clone().with_policy(&derived);
    let mut registry = ToolRegistry::with_deps(Arc::new(deps));
    let mut tools: Vec<String> = Vec::new();
    for tool in &agent.tools {
        if tool == "task" && !child_may_delegate {
            continue;
        }
        if registry.register(tool).is_err() || !registry.contains(tool) {
            return refuse(RefusalReason::ToolNotHeld { tool: tool.clone() });
        }
        tools.push(tool.clone());
    }
    let _ = registry.register("finish");
    tools.push("finish".into());

    // The child's sandbox: its own scope on the session's supervisor, or — with no kernel scope to
    // give it — a host sandbox that says so.
    let (mut sandbox, scope_id, enforced) =
        match child_sandbox(parent.sandbox, &req.agent, &derived) {
            Ok(v) => v,
            Err(detail) => return failed(&req.agent, depth, String::new(), false, detail),
        };
    cfg.emit(&format!(
        "delegate '{}' → scope {} ({}, depth {depth})",
        req.agent,
        if scope_id.is_empty() { "-" } else { &scope_id },
        if enforced { "enforced" } else { "UNENFORCED" },
    ));

    let remaining = parent.deadline.saturating_duration_since(Instant::now());
    let scenario = Scenario {
        id: format!("subagent-{}", req.agent),
        policy_path: Default::default(),
        system_prompt: instructions,
        task: req.prompt.clone(),
        turn_limit: agent.turn_limit,
        // The child shares the parent's wall clock (FR-023); never a later deadline.
        timeout_secs: remaining.as_secs().max(1),
        tools,
        mode: ScoringMode::Standard,
        finish: true,
        workdir: Default::default(),
        mcp: Default::default(),
        skills: Vec::new(),
        ceiling_policy_path: None,
        security: Default::default(),
        context: Default::default(),
        stuck: Default::default(),
        lease_turns: None,
    };
    let child_cfg = Delegation {
        depth,
        ..cfg.clone()
    };
    let opts = LoopOptions {
        progress: cfg.progress.clone().map(|p| {
            let indent = "  ".repeat(depth as usize + 1);
            Box::new(move |line: &str| p(&format!("{indent}{line}"))) as ProgressSink
        }),
        delegation: child_may_delegate.then_some(child_cfg),
        ..LoopOptions::default()
    };
    let transcript = run_loop(d.model, &scenario, &mut registry, &mut sandbox, &opts).await;

    let teardown = sandbox.teardown();
    let turns_used = transcript.turns.len() as u32;
    let (outcome, header) = match teardown {
        Err(e) => (
            DelegationOutcome::Failed {
                detail: format!("subagent scope did not tear down: {e}"),
            },
            format!("FAILED: its scope did not tear down cleanly ({e})"),
        ),
        Ok(()) => judge(&transcript, agent.turn_limit),
    };
    cfg.emit(&format!(
        "delegate '{}' ← {} ({turns_used} turns, {} denials)",
        req.agent,
        outcome_label(&outcome),
        transcript.denials().count()
    ));
    let body = report_body(&transcript);
    let mut content = format!("subagent '{}' — {header}\n", req.agent);
    if !enforced {
        content.push_str(
            "WARNING: this subagent ran with NO kernel scope. Its declared capability limits \
             were validated but NOT enforced.\n",
        );
    }
    content.push('\n');
    content.push_str(&body);
    let is_error = !matches!(outcome, DelegationOutcome::Completed);
    let result = ToolResult {
        is_error,
        // The report is the child model's words about what it read: data, not instructions.
        provenance: Provenance::Remote {
            source: format!("subagent:{}", req.agent),
        },
        ..ToolResult::ok(content)
    };
    Delegated {
        result,
        record: DelegationRecord {
            agent: req.agent.clone(),
            scope_id,
            enforced,
            depth,
            outcome,
            transcript: Some(Box::new(transcript)),
            turns_used,
        },
    }
}

/// The child's sandbox, its scope id, and whether a kernel scope confines it.
#[cfg_attr(not(feature = "enforce"), allow(unused_variables))]
fn child_sandbox(
    parent: &Sandbox,
    agent: &str,
    #[cfg_attr(not(feature = "enforce"), allow(unused_variables))] policy: &bee_core::Policy,
) -> Result<(Sandbox, String, bool), String> {
    #[cfg(feature = "enforce")]
    if let Some(parent_scope) = parent.scope_handle() {
        use bee_userspace::{EnforcementPlan, ScopeMode, SystemResolver};
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let compiled = policy
            .compile(&SystemResolver::current())
            .map_err(|e| format!("subagent policy compile: {e}"))?;
        let mode = match compiled.mode {
            bee_core::Mode::Enforce => ScopeMode::Enforce,
            bee_core::Mode::Observe => ScopeMode::Observe,
        };
        let plan = EnforcementPlan::prepare(&compiled, mode)
            .map_err(|e| format!("subagent enforcement plan: {e}"))?;
        let id = format!(
            "{}-sub-{}-{}",
            parent_scope.id,
            crate::session::parts::sanitize(agent),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        // Flat beside the parent; the parent link only orders teardown (supervisor module docs).
        let scope = parent_scope
            .supervisor()
            .create_scope(&id, &id, Some(parent_scope), &plan)?;
        return Ok((Sandbox::enforced(scope, parent.strip_env()), id, true));
    }
    Ok((Sandbox::host(parent.strip_env()), String::new(), false))
}

/// How a child's loop ended, and the report's first line.
fn judge(t: &EpisodeTranscript, turn_limit: u32) -> (DelegationOutcome, String) {
    let n = t.turns.len();
    let turns = format!("{n} turn{}", if n == 1 { "" } else { "s" });
    match &t.status {
        EpisodeStatus::Finished { outcome, .. } => {
            let word = match outcome {
                FinishOutcome::Completed => "completed",
                FinishOutcome::Blocked => "blocked",
                FinishOutcome::Abandoned => "abandoned",
            };
            (DelegationOutcome::Completed, format!("{word} ({turns})"))
        }
        EpisodeStatus::Completed => (DelegationOutcome::Completed, format!("completed ({turns})")),
        EpisodeStatus::EndedWithoutFinish => (
            DelegationOutcome::Completed,
            format!("ended without finish ({turns})"),
        ),
        EpisodeStatus::Timeout => {
            let reason = if n as u32 >= turn_limit {
                CutShortReason::Turns
            } else {
                CutShortReason::Deadline
            };
            let why = match reason {
                CutShortReason::Turns => "its turn limit was reached",
                CutShortReason::Deadline => "the shared deadline was reached",
            };
            (
                DelegationOutcome::CutShort { reason },
                format!("CUT SHORT: {why} after {turns}. The task was NOT completed."),
            )
        }
        other => {
            let detail = format!("{other:?}");
            (
                DelegationOutcome::Failed {
                    detail: detail.clone(),
                },
                format!("FAILED after {turns}: {detail}"),
            )
        }
    }
}

/// The report body: the finish summary, else the child's last words, else a plain statement that
/// it produced nothing — never mistakable for "found nothing".
fn report_body(t: &EpisodeTranscript) -> String {
    if let EpisodeStatus::Finished { summary, .. } = &t.status {
        if !summary.trim().is_empty() {
            return summary.clone();
        }
    }
    t.turns
        .iter()
        .rev()
        .filter_map(|turn| turn.assistant_text.as_deref().map(str::trim))
        .find(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "(the subagent produced no output)".into())
}

fn outcome_label(o: &DelegationOutcome) -> &'static str {
    match o {
        DelegationOutcome::Completed => "completed",
        DelegationOutcome::CutShort { .. } => "cut short",
        DelegationOutcome::Refused { .. } => "refused",
        DelegationOutcome::Failed { .. } => "failed",
    }
}

fn refused(agent: &str, depth: u32, reason: RefusalReason) -> Delegated {
    let why = match &reason {
        RefusalReason::UnknownAgent { name } => format!("unknown agent '{name}'"),
        RefusalReason::ToolNotHeld { tool } => format!(
            "the agent needs tool '{tool}', which this session does not hold (or cannot give a \
             subagent)"
        ),
        RefusalReason::OverGrant { detail } => {
            format!("the agent asks for more than this session holds: {detail}")
        }
        RefusalReason::DepthExceeded { max_depth } => {
            format!("delegation depth limit ({max_depth}) reached")
        }
        RefusalReason::Unavailable { detail } => detail.clone(),
    };
    Delegated {
        result: ToolResult::error(format!("subagent '{agent}' — REFUSED: {why}. Nothing ran.")),
        record: DelegationRecord {
            agent: agent.to_string(),
            scope_id: String::new(),
            enforced: false,
            depth,
            outcome: DelegationOutcome::Refused { reason },
            transcript: None,
            turns_used: 0,
        },
    }
}

fn failed(agent: &str, depth: u32, scope_id: String, enforced: bool, detail: String) -> Delegated {
    Delegated {
        result: ToolResult::error(format!("subagent '{agent}' — FAILED: {detail}")),
        record: DelegationRecord {
            agent: agent.to_string(),
            scope_id,
            enforced,
            depth,
            outcome: DelegationOutcome::Failed { detail },
            transcript: None,
            turns_used: 0,
        },
    }
}
