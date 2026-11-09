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
use std::sync::atomic::{AtomicU32, Ordering};
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
/// Subagents a session runs at once by default (US5).
pub const DEFAULT_MAX_CONCURRENT: u32 = 4;
/// What no configuration may exceed: recursion and fan-out multiply scopes and spend.
pub const HARD_MAX_DEPTH: u32 = 4;
pub const HARD_MAX_CONCURRENT: u32 = 16;

/// The `[delegation]` configuration table (018 US4): how deep and how wide a session may delegate.
/// Every key is optional; [`DelegationLimits::resolve`] supplies defaults and the hard caps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLimits {
    /// How many levels of subagent below the session (1: subagents do not delegate).
    pub max_depth: Option<u32>,
    /// How many subagents one turn may run at once.
    pub max_concurrent: Option<u32>,
}

impl DelegationLimits {
    /// `self` with `lower` applied as a ceiling-respecting layer: a key `lower` sets may only make
    /// the limit smaller. This is how a project configuration — untrusted input — is folded over the
    /// operator's: it can ask for less delegation, never more.
    pub fn narrowed_by(self, lower: DelegationLimits) -> DelegationLimits {
        let min = |a: Option<u32>, b: Option<u32>, default: u32| match (a, b) {
            (_, None) => a,
            (a, Some(b)) => Some(b.min(a.unwrap_or(default))),
        };
        DelegationLimits {
            max_depth: min(self.max_depth, lower.max_depth, DEFAULT_MAX_DEPTH),
            max_concurrent: min(
                self.max_concurrent,
                lower.max_concurrent,
                DEFAULT_MAX_CONCURRENT,
            ),
        }
    }

    /// `(max_depth, max_concurrent)`, defaulted and clamped to the hard caps (and to at least 1).
    pub fn resolve(self) -> (u32, usize) {
        (
            self.max_depth
                .unwrap_or(DEFAULT_MAX_DEPTH)
                .clamp(1, HARD_MAX_DEPTH),
            self.max_concurrent
                .unwrap_or(DEFAULT_MAX_CONCURRENT)
                .clamp(1, HARD_MAX_CONCURRENT) as usize,
        )
    }
}

/// The session's shared budget (018 FR-023, research R8): one pool of model turns and one
/// deadline, drawn from by the session's loop and every subagent's. A child never gets a fresh
/// allocation, so delegating cannot make a session outspend the budget it started with (SC-005).
#[derive(Debug, Clone)]
pub struct Budget {
    turns: Arc<AtomicU32>,
    /// The shared wall clock. Every loop in the tree stops at it.
    pub deadline: Instant,
}

impl Budget {
    pub fn new(turns: u32, deadline: Instant) -> Self {
        Budget {
            turns: Arc::new(AtomicU32::new(turns)),
            deadline,
        }
    }

    /// Spend one model turn. `false` when none are left — and then nothing is spent.
    pub fn take_turn(&self) -> bool {
        let mut n = self.turns.load(Ordering::SeqCst);
        loop {
            let Some(left) = n.checked_sub(1) else {
                return false;
            };
            match self
                .turns
                .compare_exchange_weak(n, left, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(now) => n = now,
            }
        }
    }

    pub fn turns_left(&self) -> u32 {
        self.turns.load(Ordering::SeqCst)
    }
}

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
    /// How many `task` calls of one turn run their subagents together (US5).
    pub max_concurrent: usize,
    /// The session's shared budget, when it has one; every child draws from the same.
    pub budget: Option<Budget>,
    /// Where delegation lines and the child's own progress go, indented by depth.
    pub progress: Option<SharedProgress>,
}

impl Delegation {
    /// Settings for a session over `agents`.
    pub fn new(agents: Arc<SkillRegistry>, progress: Option<SharedProgress>) -> Self {
        let (max_depth, max_concurrent) = DelegationLimits::default().resolve();
        Delegation {
            agents,
            depth: 0,
            max_depth,
            max_concurrent,
            budget: None,
            progress,
        }
    }

    /// These settings under `limits` (the `[delegation]` table).
    pub fn with_limits(mut self, limits: DelegationLimits) -> Self {
        (self.max_depth, self.max_concurrent) = limits.resolve();
        self
    }

    /// These settings drawing from `budget`.
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
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
    /// Leave a delegation on the call's outcome instead of running it, so the loop can run several
    /// together (US5). Set only by a loop that will resolve them.
    pub defer: bool,
}

impl<'a> Delegator<'a> {
    pub fn new(config: &'a Delegation, model: &'a dyn Model) -> Self {
        Delegator {
            config,
            model,
            defer: false,
        }
    }

    /// This delegator, deferring (or not).
    pub fn deferring(&self, defer: bool) -> Delegator<'a> {
        Delegator {
            config: self.config,
            model: self.model,
            defer,
        }
    }
}

/// A delegation a call asked for and left for the loop to run (US5): the request, and the
/// delegating session's active policy when the call ran — what the child is derived from.
#[derive(Debug, Clone)]
pub struct PendingDelegation {
    pub request: Box<DelegationRequest>,
    pub policy: Option<bee_core::Policy>,
}

/// Run every pending delegation of one turn, at most `max_concurrent` at a time, and return each
/// result in the order given. Every child gets its own scope, so they cannot see one another, and
/// the supervisor routes each one's kernel events to it alone (US5 AS-1, AS-2).
pub async fn run_all<'a>(
    d: &'a Delegator<'a>,
    pending: &'a [PendingDelegation],
    registry: &'a ToolRegistry,
    sandbox: &'a Sandbox,
    deadline: Instant,
) -> Vec<Delegated> {
    use futures_util::StreamExt;
    // Built before the first await: a closure-mapped stream held across one makes the future's
    // `Send` bound unprovable (rustc's higher-ranked lifetime limitation).
    let futures: Vec<DelegationFuture<'a>> = pending
        .iter()
        .map(|p| {
            run(
                d,
                &p.request,
                ParentView {
                    policy: p.policy.as_ref(),
                    registry,
                    sandbox,
                    deadline,
                },
            )
        })
        .collect();
    futures_util::stream::iter(futures)
        .buffered(d.config.max_concurrent.max(1))
        .collect()
        .await
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

    let deadline = match &cfg.budget {
        Some(b) => parent.deadline.min(b.deadline),
        None => parent.deadline,
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
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
        // Prefixed with the agent: siblings run together, and their lines interleave.
        progress: cfg.progress.clone().map(|p| {
            let prefix = format!("{}[{}] ", "  ".repeat(depth as usize + 1), req.agent);
            Box::new(move |line: &str| p(&format!("{prefix}{line}"))) as ProgressSink
        }),
        budget: cfg.budget.clone(),
        delegation: child_may_delegate.then_some(child_cfg),
        ..LoopOptions::default()
    };
    let transcript = run_loop(d.model, &scenario, &mut registry, &mut sandbox, &opts).await;

    let teardown = sandbox.teardown();
    let turns_used = transcript.turns.len() as u32;
    let tokens_used = transcript.usage.as_ref().map_or(0, |u| {
        u64::from(u.input_tokens) + u64::from(u.output_tokens)
    });
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
    // FR-026: the same per-result cap as every other tool result, with the cut visible.
    let (content, truncated, original_len) =
        crate::transcript::truncate(content, crate::transcript::DEFAULT_OUTPUT_CAP);
    let result = ToolResult {
        is_error,
        truncated,
        original_len,
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
            tokens_used,
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
        use std::sync::atomic::AtomicU64;
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
        EpisodeStatus::BudgetExhausted => (
            DelegationOutcome::CutShort {
                reason: CutShortReason::SharedTurns,
            },
            format!(
                "CUT SHORT: the session's shared turn budget ran out after {turns}. The task was \
                 NOT completed."
            ),
        ),
        EpisodeStatus::Timeout => {
            let reason = if n as u32 >= turn_limit {
                CutShortReason::Turns
            } else {
                CutShortReason::Deadline
            };
            let why = match reason {
                CutShortReason::Turns => "its turn limit was reached",
                CutShortReason::SharedTurns => "the session's shared turn budget ran out",
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
            tokens_used: 0,
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
            tokens_used: 0,
            transcript: None,
            turns_used: 0,
        },
    }
}
