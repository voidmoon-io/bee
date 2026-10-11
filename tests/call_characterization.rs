//! Characterization of one tool call through both loops (024-session-core PR 1, FR-040).
//!
//! The episode loop (`bee::episode::run_loop`) and the REPL loop (`bee::repl::run_exchange`) each
//! carry their own copy of the per-call protocol: execute, drain audit, escalate, retry once, close
//! the call, drain the proxy scope and late events. Every scenario here runs the **same** script
//! through both and records what each does today, before `src/call.rs::run_call` replaces the copies.
//!
//! Where the loops differ, each loop's *current* value is asserted under a `// DRIFT FR-0xx` tag.
//! Later phases flip those assertions to one expected value; they are never deleted. A flipped one
//! keeps its requirement id and says which PR made the loops agree (PR 3: FR-021, FR-022, FR-024,
//! FR-025, when both loops moved onto `src/call.rs::run_call`; PR 4: FR-029, when both counted model
//! turns). A difference
//! without a tag would be behaviour the spec did not list as drift, and has to be raised rather than
//! folded into a fix.
//!
//! Inputs are scripted (research R1): kernel audit through `Sandbox::host_scripted`, proxy events
//! through `FakeCallHooks`, Target-scope widening through `FakeHttpScope`, consent through
//! `RecordingConsent`.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::episode::{run_loop, LoopOptions};
use bee::grants::escalate::{DenialEscalationHook, LoopEscalation, ProxyRefusalHook};
use bee::grants::Ttl;
use bee::hooks::LoopHook;
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Turn};
use bee::proxy_event::ProxyEvent;
use bee::repl::{run_exchange, ReplConfig, ReplEscalation, ReplOutput};
use bee::sandbox::{Sandbox, ScriptedAudit};
use bee::tools::{ToolRegistry, ToolResult};
use bee_core::{Access, AuditEvent, Policy};
use fixtures::*;
use scripted::*;

// ── The script ──────────────────────────────────────────────────────────────────────────────────

/// One call's inputs, shared verbatim by both loops.
#[derive(Clone)]
struct Case {
    /// The `scripted` tool's attempts, in order (first attempt, then the retry if any).
    attempts: Vec<Attempt>,
    /// Proxy-scope audit batches, one per sidecar drain.
    sidecar: Vec<Vec<AuditEvent>>,
    /// Proxy events for call `c1`, one batch per `end_call`.
    proxy: Vec<Vec<ProxyEvent>>,
    base: Policy,
    ceiling: Policy,
    /// The operator's answer.
    grant: bool,
    /// The episode's `timeout_secs` and the REPL's `tool_timeout_secs` — the same number, so the two
    /// timeout policies are compared at an equal budget.
    budget_secs: u64,
    /// The model's tool-calling turns, before the text turn that ends the run. Default: one turn
    /// calling `scripted` as `c1`.
    turns: Vec<Turn>,
}

impl Case {
    fn new(attempts: Vec<Attempt>) -> Self {
        Case {
            attempts,
            sidecar: Vec::new(),
            proxy: Vec::new(),
            base: policy(&[]),
            ceiling: policy(&[("/tmp", Access::Write)]),
            grant: true,
            budget_secs: 30,
            turns: vec![call_turn("c1", SCRIPTED)],
        }
    }
}

fn denial(target: &str) -> AuditEvent {
    ev("file_open", target, "denied", None)
}

fn hooks() -> Vec<Box<dyn LoopHook>> {
    vec![
        Box::new(DenialEscalationHook { enabled: true }),
        Box::new(ProxyRefusalHook { enabled: true }),
    ]
}

fn escalation(case: &Case, consent: Arc<RecordingConsent>) -> LoopEscalation {
    LoopEscalation {
        base: case.base.clone(),
        ceiling: case.ceiling.clone(),
        hooks: hooks(),
        consent,
        timeout: Duration::from_secs(5),
        default_ttl: Ttl::Forever,
    }
}

/// A host sandbox fed by the case's scripted inputs, plus the tool that feeds its tool-scope audit.
fn sandbox_for(case: &Case) -> (Sandbox, ScriptedTool, Arc<FakeHttpScope>) {
    let audit = Arc::new(ScriptedAudit::default());
    for batch in &case.sidecar {
        audit.push_proxy(batch.clone());
    }
    let mut sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let call_hooks = Arc::new(FakeCallHooks::default());
    for batch in &case.proxy {
        call_hooks.push("c1", batch.clone());
    }
    sb.set_call_hooks(call_hooks);
    let http = Arc::new(FakeHttpScope::default());
    sb.set_http_scope_hook(http.clone());
    (sb, ScriptedTool::new(audit, case.attempts.clone()), http)
}

fn model(case: &Case) -> MockModel {
    let mut turns = case.turns.clone();
    turns.push(text_turn("done"));
    MockModel::scripted(turns)
}

// ── What a run is reduced to ────────────────────────────────────────────────────────────────────

type A = (String, String, String, Option<String>);

fn norm_audit(audit: &[AuditEvent]) -> Vec<A> {
    audit
        .iter()
        .map(|e| {
            (
                e.op.clone(),
                e.target.clone(),
                e.decision.clone(),
                e.scope_id.clone(),
            )
        })
        .collect()
}

/// One recorded call: `(call_id, content, is_error, audit, proxy kinds)`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    id: String,
    content: String,
    is_error: bool,
    audit: Vec<A>,
    proxy: Vec<&'static str>,
    /// The proxy events of an attempt a proxy refusal retried (024 FR-021).
    denied_proxy: Vec<&'static str>,
}

#[derive(Debug)]
struct Run {
    calls: Vec<Call>,
    /// The loop-level audit record: the episode's `audit_trail`, the exchange's `audit`.
    trail: Vec<A>,
    /// Whether the loop counted the call as the tool's denial: the episode's `result DENIED` tag,
    /// the exchange's `denials > 0`.
    counted_denial: bool,
    /// Operator prompts.
    asked: usize,
    /// Tool attempts started.
    attempts: u32,
    /// Target lists pushed to the proxy.
    http_updates: Vec<Vec<String>>,
}

fn calls_of(turns: &[bee::transcript::TranscriptTurn]) -> Vec<Call> {
    turns
        .iter()
        .flat_map(|t| &t.calls)
        .map(|c| Call {
            id: c.call.id.clone(),
            content: c.result.content.clone(),
            is_error: c.result.is_error,
            audit: norm_audit(&c.audit),
            proxy: c.proxy_events.iter().map(|e| e.kind.as_str()).collect(),
            denied_proxy: c
                .denied_attempt_proxy_events
                .iter()
                .map(|e| e.kind.as_str())
                .collect(),
        })
        .collect()
}

async fn episode(case: &Case) -> Run {
    let (mut sb, tool, http) = sandbox_for(case);
    let attempts = tool.counter();
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(tool));
    let consent = RecordingConsent::new(case.grant);
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let opts = LoopOptions {
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        escalation: Some(escalation(case, consent.clone())),
        ..LoopOptions::default()
    };
    let t = run_loop(
        &model(case),
        &scenario("characterize", &[SCRIPTED], 5, case.budget_secs),
        &mut registry,
        &mut sb,
        &opts,
    )
    .await;
    let http_updates = http.updates.lock().unwrap().clone();
    let counted_denial = lines
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.starts_with("  result DENIED"));
    Run {
        calls: calls_of(&t.turns),
        trail: norm_audit(&t.audit_trail),
        counted_denial,
        asked: consent.asked().len(),
        attempts: attempts.load(Ordering::SeqCst),
        http_updates,
    }
}

/// Discards everything; the assertions read the exchange result.
struct Quiet;

impl ReplOutput for Quiet {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}

async fn repl_with(case: &Case) -> (Run, ReplConfig) {
    let (mut sb, tool, http) = sandbox_for(case);
    let attempts = tool.counter();
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(tool));
    let consent = RecordingConsent::new(case.grant);
    let config = ReplConfig {
        tool_timeout_secs: case.budget_secs,
        escalation: Some(ReplEscalation::new(escalation(case, consent.clone()))),
        ..ReplConfig::default()
    };
    let mut convo = Conversation::new("test", "");
    let steering = Arc::new(Mutex::new(VecDeque::new()));
    let r = run_exchange(
        "go",
        &model(case),
        &mut convo,
        &mut registry,
        &mut sb,
        &config,
        &Quiet,
        &steering,
        None,
    )
    .await;
    let http_updates = http.updates.lock().unwrap().clone();
    let run = Run {
        calls: calls_of(&r.turns),
        trail: norm_audit(&r.audit),
        counted_denial: r.denials > 0,
        asked: consent.asked().len(),
        attempts: attempts.load(Ordering::SeqCst),
        http_updates,
    };
    (run, config)
}

async fn repl(case: &Case) -> Run {
    repl_with(case).await.0
}

fn call(content: &str, is_error: bool, audit: &[AuditEvent]) -> Call {
    Call {
        id: "c1".into(),
        content: content.into(),
        is_error,
        audit: norm_audit(audit),
        proxy: Vec::new(),
        denied_proxy: Vec::new(),
    }
}

/// The assertions every scenario makes of a run whose two loops agree on the recorded calls.
fn assert_same_calls(e: &Run, r: &Run) {
    assert_eq!(e.calls, r.calls, "recorded calls differ between the loops");
    assert_eq!(e.attempts, r.attempts, "attempt count differs");
    assert_eq!(e.asked, r.asked, "operator prompt count differs");
    assert_eq!(e.http_updates, r.http_updates, "proxy scope updates differ");
}

// ── 1. No denial ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn s1_no_denial() {
    let case = Case::new(vec![Attempt::ok("fine")]);
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    assert_eq!(e.calls, vec![call("fine", false, &[])]);
    assert!(e.trail.is_empty() && r.trail.is_empty());
    assert!(!e.counted_denial && !r.counted_denial);
    assert_eq!((e.asked, e.attempts), (0, 1));
}

// ── 2. Kernel denial → granted within the ceiling → retry succeeds ──────────────────────────────

#[tokio::test]
async fn s2_kernel_denial_granted_and_retried() {
    let case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")]),
        Attempt::ok("written"),
    ]);
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    // The recorded call holds only the retry's result and audit, in both loops.
    assert_eq!(e.calls, vec![call("written", false, &[])]);
    assert_eq!((e.asked, e.attempts), (1, 2));
    assert!(!e.counted_denial && !r.counted_denial);

    // FR-021 (one value since PR 3; was DRIFT): the denial that justified the widening is in both
    // loops' audit records. Before, the exchange replaced the call's audit with the retry's.
    assert_eq!(e.trail, norm_audit(&[denial("/tmp/x")]));
    assert_eq!(r.trail, e.trail);
}

// ── 3. Kernel denial → beyond the ceiling → refused ─────────────────────────────────────────────

#[tokio::test]
async fn s3_kernel_denial_beyond_ceiling() {
    // The default ceiling grants `/tmp` only.
    let case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/etc/shadow")])
    ]);
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    assert_eq!(
        e.calls,
        vec![call("EACCES", true, &[denial("/etc/shadow")])]
    );
    // Beyond the ceiling is unpromptable, and nothing is retried.
    assert_eq!((e.asked, e.attempts), (0, 1));
    assert_eq!(e.trail, r.trail);
    assert!(e.counted_denial && r.counted_denial);
}

// ── 4. Kernel denial, delta already held ────────────────────────────────────────────────────────

#[tokio::test]
async fn s4_kernel_denial_already_held() {
    let mut case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")])
    ]);
    case.base = policy(&[("/tmp/x", Access::Write)]);
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    // `AlreadyHeld` widens nothing: no prompt, no retry (FR-020 holds in both loops today).
    assert_eq!((e.asked, e.attempts), (0, 1));
    assert_eq!(e.calls, vec![call("EACCES", true, &[denial("/tmp/x")])]);
    assert_eq!(e.trail, r.trail);
}

// ── 5. Proxy refusal → granted → retry ──────────────────────────────────────────────────────────

#[cfg(feature = "intercept")]
#[tokio::test]
async fn s5_proxy_refusal_granted_and_retried() {
    let mut case = Case::new(vec![Attempt::error("refused"), Attempt::ok("200 OK")]);
    case.base = http_policy(&[]);
    case.ceiling = http_policy(&["10.0.0.9:80"]);
    case.proxy = vec![vec![refusal("c1", "10.0.0.9", 80)], Vec::new()];
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    // The widening reaches the proxy, the call is retried once, and the result is the retry's.
    assert_eq!((e.asked, e.attempts), (1, 2));
    assert_eq!(e.http_updates, vec![vec!["10.0.0.9:80".to_string()]]);
    assert_eq!(
        e.calls,
        vec![Call {
            denied_proxy: vec!["refused_out_of_scope"],
            ..call("200 OK", false, &[])
        }]
    );

    // FR-021 (one value since PR 3; was DRIFT): the refusal that justified the widening is kept, in
    // `denied_attempt_proxy_events`, apart from the retry's own proxy events. Before, both loops
    // replaced the call's proxy events with the retry's and the refusal was in neither record.
    assert!(e.calls[0].proxy.is_empty() && r.calls[0].proxy.is_empty());
    assert_eq!(r.calls[0].denied_proxy, vec!["refused_out_of_scope"]);
}

// ── 6. A retry runs into the time limit ─────────────────────────────────────────────────────────

/// 6a. The retry alone outlasts the whole budget. Both loops abandon it and keep the first attempt's
/// result *and* audit, so the record is consistent. Paused clock.
#[tokio::test(start_paused = true)]
async fn s6a_kernel_retry_outlasts_the_budget() {
    let mut case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")]),
        Attempt::ok("late").taking(Duration::from_secs(120)),
    ]);
    case.budget_secs = 30;
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    assert_eq!((e.asked, e.attempts), (1, 2));
    assert_eq!(e.calls, vec![call("EACCES", true, &[denial("/tmp/x")])]);
}

/// 6b. Each attempt fits the budget on its own, the two together do not. Real clock: the episode
/// measures its deadline with `std::time::Instant`, which a paused tokio clock does not advance, so a
/// paused run would hand the episode's retry a full budget and hide the difference.
///
/// Budget 2 s, attempts 1.4 s each: the episode's retry gets ~0.6 s and misses by ~0.8 s; the REPL's
/// gets a fresh 2 s and finishes with ~0.6 s to spare. Both margins are far above scheduler noise, and
/// the two loops run concurrently, so the test takes ~2.8 s rather than twice that.
#[tokio::test]
async fn s6b_kernel_retry_after_the_first_attempt_used_the_budget() {
    let attempt = Duration::from_millis(1400);
    let mut case = Case::new(vec![
        Attempt::error("EACCES")
            .with_audit(vec![denial("/tmp/x")])
            .taking(attempt),
        Attempt::ok("written").taking(attempt),
    ]);
    case.budget_secs = 2;
    let (e, r) = tokio::join!(episode(&case), repl(&case));
    assert_eq!((e.attempts, r.attempts), (2, 2));

    // FR-024 (one value since PR 3; was DRIFT): the retry gets only what the first attempt left, in
    // both loops, so it times out and the first attempt's result stands. Before, the REPL gave the
    // retry a fresh per-call limit and it completed.
    assert_eq!(e.calls, vec![call("EACCES", true, &[denial("/tmp/x")])]);
    assert_eq!(r.calls, e.calls);
}

/// 6c. A proxy-refusal retry that times out. Both loops keep the first attempt's result but record
/// the retry's (empty) audit and proxy events — a result and an audit from different attempts.
/// Paused clock.
#[cfg(feature = "intercept")]
#[tokio::test(start_paused = true)]
async fn s6c_proxy_retry_times_out() {
    let mut case = Case::new(vec![
        Attempt::error("refused").with_audit(vec![ev("file_open", "/tmp/cache", "allowed", None)]),
        Attempt::ok("late").taking(Duration::from_secs(120)),
    ]);
    case.base = http_policy(&[]);
    case.ceiling = http_policy(&["10.0.0.9:80"]);
    case.proxy = vec![vec![refusal("c1", "10.0.0.9", 80)], Vec::new()];
    case.budget_secs = 30;
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    assert_eq!((e.asked, e.attempts), (1, 2));

    // FR-025 (one value since PR 3; was DRIFT): the abandoned retry does not replace the attempt that
    // stands, so the result, the audit and the proxy events are all the first attempt's. Before, the
    // record paired the first attempt's result with the timed-out retry's (empty) audit.
    let cache = ev("file_open", "/tmp/cache", "allowed", None);
    assert_eq!(
        e.calls,
        vec![Call {
            proxy: vec!["refused_out_of_scope"],
            ..call("refused", true, std::slice::from_ref(&cache))
        }]
    );
    // FR-021 (one value since PR 3; was DRIFT): the first attempt's audit is in both loops' records.
    assert_eq!(e.trail, norm_audit(&[cache]));
    assert_eq!(r.trail, e.trail);
}

// ── 7. A proxy-scope denial ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn s7_proxy_scope_denial() {
    let proxy_denial = ev("connect", "10.0.0.9:443", "denied", Some("proxy"));
    let mut case = Case::new(vec![Attempt::ok("fine")]);
    case.sidecar = vec![vec![proxy_denial.clone()]];
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    // Joins the call's audit after escalation, and never drives it.
    assert_eq!(
        e.calls,
        vec![call("fine", false, std::slice::from_ref(&proxy_denial))]
    );
    assert_eq!(e.asked, 0);
    assert_eq!(e.trail, r.trail);

    // FR-022 (one value since PR 3; was DRIFT): a proxy-scope denial is the proxy's, never counted as
    // the tool's. Before, the episode tagged the result `DENIED`.
    assert!(!e.counted_denial);
    assert!(!r.counted_denial);
}

// ── 8. A late tool-scope batch ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn s8_late_tool_batch_on_the_sidecar_drain() {
    let late = denial("/tmp/late");
    let case = Case::new(vec![
        Attempt::ok("fine").with_batches(vec![Vec::new(), vec![late.clone()]])
    ]);
    let (e, r) = (episode(&case).await, repl(&case).await);
    assert_same_calls(&e, &r);
    // Attributed to this call in both loops (FR-023 holds today), and too late to escalate.
    assert_eq!(
        e.calls,
        vec![call("fine", false, std::slice::from_ref(&late))]
    );
    assert_eq!(e.asked, 0);
    assert_eq!(e.trail, r.trail);
    assert!(e.counted_denial && r.counted_denial);
}

// ── Lease turns ─────────────────────────────────────────────────────────────────────────────────

/// A lease's turn. A grant on the second call of the first model turn is stamped turn 0 in both
/// loops: a turn is a model turn (D3). The episode passes the model turn's index; its `ActivePolicy`
/// is local to `run_loop`, so only the REPL's value can be observed from here.
#[tokio::test]
async fn lease_turn_counts() {
    let two_calls = tool_turn(None, &[("c0", SCRIPTED), ("c1", SCRIPTED)]);
    let mut case = Case::new(vec![
        Attempt::ok("first"),
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")]),
        Attempt::ok("written"),
    ]);
    case.turns = vec![two_calls];
    let (r, config) = repl_with(&case).await;
    assert_eq!(r.attempts, 3);
    let active = config.escalation.as_ref().unwrap().active.lock().await;
    let lease = &active.leases()[0];

    // FR-029 (one value since PR 4; was DRIFT): the REPL stamps the lease with the model turn (0).
    // Before, it counted one "turn" per tool call and stamped it 1.
    assert_eq!(lease.granted_at_turn, 0);
}
