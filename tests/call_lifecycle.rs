//! 024 PR3 (US3) — the call lifecycle, driven directly (contracts/call-lifecycle.md, SC-004).
//!
//! `bee::call::run_call` with no model, no provider and no BPF-LSM kernel: a scripted tool, a scripted
//! source of kernel audit (`Sandbox::host_scripted`), scripted proxy events (`FakeCallHooks`) and a
//! recording consent sink. Every retry path the spec names is here, each checked against the one
//! `CallOutcome` both loops now record.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bee::call::{run_call, CallInput, CallOutcome, Escalation, TimeoutPolicy, Trigger};
use bee::grants::escalate::{
    DenialEscalationHook, EscalateOutcome, LoopEscalation, ProxyRefusalHook,
};
use bee::grants::{ActivePolicy, Ttl};
use bee::provider::ToolCall;
use bee::proxy_event::ProxyEvent;
use bee::sandbox::{CallOrigin, Sandbox, ScriptedAudit};
use bee::tools::ToolRegistry;
use bee_core::{Access, AuditEvent, Policy};
use fixtures::policy;
use scripted::*;

/// One call's scripted inputs.
struct Case {
    attempts: Vec<Attempt>,
    sidecar: Vec<Vec<AuditEvent>>,
    proxy: Vec<Vec<ProxyEvent>>,
    base: Policy,
    ceiling: Policy,
    grant: bool,
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
        }
    }
}

/// What a run produced: the outcome, operator prompts, attempts started.
struct Ran {
    out: CallOutcome,
    asked: usize,
    attempts: u32,
}

fn denial(target: &str) -> AuditEvent {
    ev("file_open", target, "denied", None)
}

/// The decisions of `audit`, as `(target, decision)`.
fn targets(audit: &[AuditEvent]) -> Vec<(&str, &str)> {
    audit
        .iter()
        .map(|e| (e.target.as_str(), e.decision.as_str()))
        .collect()
}

async fn run(case: &Case, timeout: TimeoutPolicy) -> Ran {
    let audit = Arc::new(ScriptedAudit::default());
    for batch in &case.sidecar {
        audit.push_proxy(batch.clone());
    }
    let mut sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let hooks = Arc::new(FakeCallHooks::default());
    for batch in &case.proxy {
        hooks.push("c1", batch.clone());
    }
    sb.set_call_hooks(hooks);
    sb.set_http_scope_hook(Arc::new(FakeHttpScope::default()));

    let tool = ScriptedTool::new(audit, case.attempts.clone());
    let attempts = tool.counter();
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(tool));

    let consent = RecordingConsent::new(case.grant);
    let config = LoopEscalation {
        base: case.base.clone(),
        ceiling: case.ceiling.clone(),
        hooks: vec![
            Box::new(DenialEscalationHook { enabled: true }),
            Box::new(ProxyRefusalHook { enabled: true }),
        ],
        operator: bee::operator::Operator::with_consent(
            bee::operator::OperatorKind::Autonomous,
            consent.clone(),
        )
        .with_timeout(Duration::from_secs(5)),
        default_ttl: Ttl::Forever,
    };
    let mut active = ActivePolicy::new(case.base.clone(), case.ceiling.clone()).unwrap();
    let call = ToolCall {
        id: "c1".into(),
        name: SCRIPTED.into(),
        arguments: serde_json::json!({}),
    };
    let out = run_call(
        CallInput {
            call: &call,
            turn: 0,
            origin: CallOrigin::Tool,
            timeout,
        },
        &mut sb,
        &mut registry,
        Some(Escalation {
            config: &config,
            active: &mut active,
            lease_turn: 0,
        }),
    )
    .await;
    Ran {
        out,
        asked: consent.asked().len(),
        attempts: attempts.load(Ordering::SeqCst),
    }
}

fn per_call() -> TimeoutPolicy {
    TimeoutPolicy::PerCall(Duration::from_secs(30))
}

/// The escalations a call ran, as `(trigger, outcome kind)`.
fn escalations(out: &CallOutcome) -> Vec<(Trigger, &'static str)> {
    out.escalations
        .iter()
        .map(|r| {
            let kind = match r.outcome {
                EscalateOutcome::Granted(_) => "granted",
                EscalateOutcome::AlreadyHeld => "already_held",
                EscalateOutcome::Refused(_) => "refused",
            };
            (r.trigger.clone(), kind)
        })
        .collect()
}

fn kernel(target: &str) -> Trigger {
    Trigger::KernelDenial {
        op: "file_open".into(),
        target: target.into(),
    }
}

#[tokio::test]
async fn no_denial() {
    let r = run(&Case::new(vec![Attempt::ok("fine")]), per_call()).await;
    assert_eq!(r.out.result.content, "fine");
    assert!(!r.out.retried && !r.out.timed_out);
    assert!(r.out.escalations.is_empty() && r.out.denied_attempt_audit.is_empty());
    assert_eq!((r.asked, r.attempts), (0, 1));
}

// FR-019, FR-021: a granted widening retries once, and the denial that justified it is kept.
#[tokio::test]
async fn kernel_denial_granted_then_retried() {
    let case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")]),
        Attempt::ok("written"),
    ]);
    let r = run(&case, per_call()).await;
    assert_eq!(r.out.result.content, "written");
    assert!(r.out.retried);
    assert_eq!(
        targets(&r.out.denied_attempt_audit),
        vec![("/tmp/x", "denied")]
    );
    assert!(r.out.audit.is_empty(), "the retry's own audit");
    assert_eq!(
        r.out.tool_denials(),
        0,
        "the call that stands was not denied"
    );
    assert_eq!(escalations(&r.out), vec![(kernel("/tmp/x"), "granted")]);
    assert_eq!((r.asked, r.attempts), (1, 2));
}

// FR-020: a refused widening is not retried.
#[tokio::test]
async fn kernel_denial_refused_is_not_retried() {
    let case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/etc/shadow")])
    ]);
    let r = run(&case, per_call()).await;
    assert!(!r.out.retried && r.out.result.is_error);
    assert_eq!(
        escalations(&r.out),
        vec![(kernel("/etc/shadow"), "refused")]
    );
    assert_eq!(r.out.tool_denials(), 1);
    assert_eq!(
        (r.asked, r.attempts),
        (0, 1),
        "beyond the ceiling is never offered"
    );
}

// FR-020: a widening that changed nothing is not retried.
#[tokio::test]
async fn kernel_denial_already_held_is_not_retried() {
    let mut case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")])
    ]);
    case.base = policy(&[("/tmp/x", Access::Write)]);
    let r = run(&case, per_call()).await;
    assert!(!r.out.retried);
    assert_eq!(
        escalations(&r.out),
        vec![(kernel("/tmp/x"), "already_held")]
    );
    assert_eq!((r.asked, r.attempts), (0, 1));
}

// FR-022: a proxy-scope denial is the proxy's — reported in `proxy_audit`, never counted as the
// tool's, and never driving escalation.
#[tokio::test]
async fn a_proxy_scope_denial_is_the_proxys() {
    let mut case = Case::new(vec![Attempt::ok("fine")]);
    case.sidecar = vec![vec![ev("connect", "10.0.0.9:443", "denied", Some("proxy"))]];
    let r = run(&case, per_call()).await;
    assert_eq!(r.out.tool_denials(), 0);
    assert_eq!(
        targets(&r.out.proxy_audit),
        vec![("10.0.0.9:443", "denied")]
    );
    assert!(r.out.escalations.is_empty());
    assert_eq!(r.asked, 0);
}

// FR-023: tool-scope events that arrive after the attempt, on the final drain, are this call's.
#[tokio::test]
async fn a_late_tool_batch_belongs_to_this_call() {
    let case = Case::new(vec![
        Attempt::ok("fine").with_batches(vec![Vec::new(), vec![denial("/tmp/late")]])
    ]);
    let r = run(&case, per_call()).await;
    assert_eq!(targets(&r.out.audit), vec![("/tmp/late", "denied")]);
    // Late is after escalation: it is recorded, not escalated.
    assert!(r.out.escalations.is_empty());
}

// FR-024, FR-025, both policies: the retry gets only what the first attempt left, times out, and the
// first attempt — its result and its audit together — stands. Real clock, as in the characterization
// test s6b: the deadline is measured with `std::time::Instant`.
#[tokio::test]
async fn a_retry_gets_only_what_the_first_attempt_left() {
    let attempt = Duration::from_millis(1400);
    let case = Case::new(vec![
        Attempt::error("EACCES")
            .with_audit(vec![denial("/tmp/x")])
            .taking(attempt),
        Attempt::ok("written").taking(attempt),
    ]);
    let budget = Duration::from_secs(2);
    let (deadline, per_call) = tokio::join!(
        run(&case, TimeoutPolicy::Deadline(Instant::now() + budget)),
        run(&case, TimeoutPolicy::PerCall(budget)),
    );
    for (policy, r) in [("deadline", deadline), ("per-call", per_call)] {
        assert_eq!(r.attempts, 2, "{policy}: the retry was started");
        assert!(r.out.timed_out, "{policy}");
        assert!(
            !r.out.retried,
            "{policy}: the abandoned retry does not stand"
        );
        assert_eq!(r.out.result.content, "EACCES", "{policy}");
        assert_eq!(
            targets(&r.out.audit),
            vec![("/tmp/x", "denied")],
            "{policy}: the audit is the same attempt's"
        );
        assert!(r.out.denied_attempt_audit.is_empty(), "{policy}");
    }
}

// FR-024: once the call's time is used up, no retry starts — even after a granted widening.
#[tokio::test]
async fn no_retry_starts_when_no_time_is_left() {
    let case = Case::new(vec![
        Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")]),
        Attempt::ok("written"),
    ]);
    // An expired budget must not poll even an immediately-ready tool or consent handler.
    let r = run(&case, TimeoutPolicy::Deadline(Instant::now())).await;
    assert!(r.out.timed_out);
    assert!(r.out.escalations.is_empty());
    assert_eq!((r.asked, r.attempts), (0, 0));
    assert!(!r.out.retried);
}

#[cfg(feature = "intercept")]
mod proxy {
    use super::*;
    use fixtures::http_policy;

    fn proxy_case(attempts: Vec<Attempt>) -> Case {
        let mut case = Case::new(attempts);
        case.base = http_policy(&["10.0.0.1:80"]);
        case.ceiling = http_policy(&["10.0.0.1:80", "10.0.0.9:80"]);
        case.proxy = vec![vec![refusal("c1", "10.0.0.9", 80)], Vec::new()];
        case
    }

    fn proxy_trigger() -> Trigger {
        Trigger::ProxyRefusal {
            host: "10.0.0.9".into(),
            port: 80,
        }
    }

    // FR-021: a proxy refusal retried in a new call keeps the refusal apart from the retry's events.
    #[tokio::test]
    async fn a_proxy_refusal_granted_then_retried() {
        let r = run(
            &proxy_case(vec![Attempt::error("refused"), Attempt::ok("200 OK")]),
            per_call(),
        )
        .await;
        assert_eq!(r.out.result.content, "200 OK");
        assert!(r.out.retried);
        assert!(r.out.proxy_events.is_empty());
        assert_eq!(r.out.denied_attempt_proxy_events.len(), 1);
        assert!(r.out.denied_attempt_proxy_events[0].kind.is_refusal());
        assert_eq!(escalations(&r.out), vec![(proxy_trigger(), "granted")]);
        assert_eq!((r.asked, r.attempts), (1, 2));
    }

    // FR-019: a kernel denial and a proxy refusal in one call — one retry in total.
    #[tokio::test]
    async fn a_kernel_denial_and_a_proxy_refusal_retry_once() {
        let mut case = proxy_case(vec![
            Attempt::error("EACCES").with_audit(vec![denial("/tmp/x")]),
            Attempt::ok("written"),
            Attempt::ok("never"),
        ]);
        // A base with a target, so a filesystem widening keeps `[policy.http]` within the ceiling.
        case.base = http_policy(&["10.0.0.1:80"]);
        case.ceiling = http_policy(&["10.0.0.1:80", "10.0.0.9:80"]);
        case.ceiling.filesystem.insert("/tmp".into(), Access::Write);
        let r = run(&case, per_call()).await;
        assert_eq!(r.attempts, 2, "one retry");
        assert!(r.out.retried);
        assert_eq!(
            escalations(&r.out),
            vec![(kernel("/tmp/x"), "granted")],
            "the kernel retry spent the call's one retry; the proxy step did not run"
        );
    }

    // FR-025: a proxy retry that times out leaves the first attempt standing — result, audit and
    // proxy events.
    #[tokio::test]
    async fn a_proxy_retry_that_times_out_leaves_the_first_attempt() {
        let attempt = Duration::from_millis(1400);
        let case = proxy_case(vec![
            Attempt::error("refused")
                .with_audit(vec![ev("file_open", "/tmp/cache", "allowed", None)])
                .taking(attempt),
            Attempt::ok("late").taking(attempt),
        ]);
        let r = run(&case, TimeoutPolicy::PerCall(Duration::from_secs(2))).await;
        assert!(r.out.timed_out && !r.out.retried);
        assert_eq!(r.out.result.content, "refused");
        assert_eq!(targets(&r.out.audit), vec![("/tmp/cache", "allowed")]);
        assert!(r.out.proxy_events.iter().any(|e| e.kind.is_refusal()));
        assert!(r.out.denied_attempt_proxy_events.is_empty());
    }
}

/// Cancellation after the tool policy changes but before the proxy acknowledges must prevent
/// further execution: neither a lease nor tool membership may claim that update committed.
#[tokio::test]
async fn canceled_proxy_policy_update_stops_future_dispatch() {
    use bee::grants::escalate::escalate;
    use bee::grants::{GrantDelta, GrantOrigin};
    use bee::sandbox::HttpScopeHook;
    use std::sync::atomic::AtomicBool;

    struct PendingScope(AtomicBool);
    impl HttpScopeHook for PendingScope {
        fn compile(
            &self,
            policy: &Policy,
        ) -> Result<(bee_core::CompiledPolicy, bee_core::compiler::HttpScope), String> {
            FakeHttpScope::default().compile(policy)
        }
        fn update<'a>(
            &'a self,
            _: bee_core::compiler::HttpScope,
        ) -> futures_util::future::BoxFuture<'a, Result<(), String>> {
            self.0.store(true, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }
    }

    let base = fixtures::http_policy(&["10.0.0.1:80"]);
    let ceiling = fixtures::http_policy(&["10.0.0.1:80", "10.0.0.9:80"]);
    let mut active = ActivePolicy::new(base.clone(), ceiling).unwrap();
    let hook = Arc::new(PendingScope(AtomicBool::new(false)));
    let mut sandbox = Sandbox::host(vec![]);
    sandbox.set_http_scope_hook(hook.clone());
    let mut registry = bee::tools::registry_for(&["bash".into()], None);
    let operator = bee::operator::Operator::with_consent(
        bee::operator::OperatorKind::Autonomous,
        RecordingConsent::new(true),
    );
    let update = escalate(
        &mut active,
        GrantOrigin::Explicit,
        GrantDelta {
            http_targets: vec!["10.0.0.9:80".into()],
            tools: vec!["give_up".into()],
            ..Default::default()
        },
        Ttl::Forever,
        0,
        &operator,
        &mut sandbox,
        &mut registry,
    );
    assert!(tokio::time::timeout(Duration::from_millis(20), update)
        .await
        .is_err());
    assert!(hook.0.load(Ordering::SeqCst));
    assert!(active.leases().is_empty());
    assert_eq!(active.active(), &base);
    assert!(!registry.contains("give_up"));
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("must-not-run");
    let result = registry
        .execute(
            &ToolCall {
                id: "after-cancel".into(),
                name: "bash".into(),
                arguments: serde_json::json!({"command": format!("touch '{}'", marker.display())}),
            },
            &sandbox,
        )
        .await;
    assert!(result.is_error);
    assert!(
        result.content.contains("policy update canceled"),
        "{}",
        result.content
    );
    assert!(!marker.exists());
}
