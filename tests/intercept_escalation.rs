//! 019-http-intercept US3 (T062) — widening the target scope is a human decision.
//!
//! A proxy refusal becomes a consent request for exactly the refused `host:port`, bounded by the
//! ceiling's `[policy.http]`; approved, it reaches both layers atomically and the call can be retried;
//! declined, timed out, beyond the ceiling, or not acknowledged by the worker, nothing changes. And no
//! tool the model holds can widen the scope itself.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::call::{run_call, CallInput, CallOutcome, Escalation, TimeoutPolicy, Trigger};
use bee::grants::escalate::{escalate, LoopEscalation};
use bee::grants::{ActivePolicy, GrantDelta, GrantOrigin, Ttl};
use bee::operator::{Consent, ConsentRequest, Decision};
use bee::provider::ToolCall;
use bee_core::{HostPort, HttpPolicy, Policy};
use harness::{scope, Session};
use proptest::prelude::*;
use serde_json::json;

/// Records every request; answers with `answer` (`None` = never answers).
struct Recording {
    seen: Mutex<Vec<Vec<String>>>,
    answer: Option<bool>,
}

#[async_trait::async_trait]
impl Consent for Recording {
    async fn decide(&self, r: &ConsentRequest) -> Decision {
        self.seen.lock().unwrap().push(r.http_targets.clone());
        match self.answer {
            Some(true) => Decision::Granted,
            Some(false) => Decision::Denied,
            None => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Decision::Granted
            }
        }
    }
}

fn hp(s: &str) -> HostPort {
    HostPort::try_from(s.to_string()).unwrap()
}

fn policy_with(targets: &[String]) -> Policy {
    let mut p = Policy::from_toml("[policy]\nname = \"p\"\n").unwrap();
    p.http = Some(HttpPolicy {
        targets: targets.iter().map(|t| hp(t)).collect(),
        ..Default::default()
    });
    p
}

fn send_call(hostport: &str) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: "http_send".into(),
        arguments: json!({ "request": { "url": format!("http://{hostport}/search?q=x") } }),
    }
}

/// Send to `hostport` through the call lifecycle, with escalation on — the path both loops take: a
/// refusal is escalated and, if the target scope widened, the call retried (024 `run_call`).
async fn send_escalating(
    s: &mut Session,
    e: &LoopEscalation,
    active: &mut ActivePolicy,
    hostport: &str,
) -> CallOutcome {
    let tc = send_call(hostport);
    run_call(
        CallInput {
            call: &tc,
            turn: 1,
            origin: bee::sandbox::CallOrigin::Tool,
            timeout: TimeoutPolicy::PerCall(Duration::from_secs(30)),
        },
        &mut s.session.sandbox,
        &mut s.session.registry,
        Some(Escalation {
            config: e,
            active,
            lease_turn: 1,
        }),
    )
    .await
}

/// The one escalation a call ran, which must have been for a proxy refusal.
fn proxy_escalation(out: &CallOutcome) -> &bee::grants::escalate::EscalateOutcome {
    assert_eq!(out.escalations.len(), 1, "{:?}", out.escalations);
    assert!(matches!(
        out.escalations[0].trigger,
        Trigger::ProxyRefusal { .. }
    ));
    &out.escalations[0].outcome
}

struct Fixture {
    s: Session,
    /// The session's escalation: its floor is the policy (`a` in scope), its ceiling the fixture's.
    e: LoopEscalation,
    sink: Arc<Recording>,
    /// Outside the policy's target scope.
    b: String,
    _fx: (vuln_target::ShutdownHandle, vuln_target::ShutdownHandle),
}

impl Fixture {
    /// The session's active policy, from its escalation floor and ceiling.
    fn active(&self) -> ActivePolicy {
        ActivePolicy::new(self.e.base.clone(), self.e.ceiling.clone())
    }
}

/// Two fixture servers: `a` in scope, `b` not. The ceiling is `ceiling(a, b)`; the operator answers
/// with `answer` (`None` = never answers) within 300 ms.
async fn fixture(answer: Option<bool>, ceiling: impl FnOnce(&str, &str) -> Vec<String>) -> Fixture {
    let (a, _, fa) = vuln_target::start_with(false);
    let (b, _, fb) = vuln_target::start_with(false);
    let (a, b) = (
        format!("127.0.0.1:{}", a.port()),
        format!("127.0.0.1:{}", b.port()),
    );
    let sink = Arc::new(Recording {
        seen: Mutex::new(Vec::new()),
        answer,
    });
    let ceiling = policy_with(&ceiling(&a, &b));
    let operator = bee::operator::Operator::with_consent(
        bee::operator::OperatorKind::Autonomous,
        sink.clone(),
    )
    .with_timeout(Duration::from_millis(300));
    let mut s = Session::start_with(
        scope(&format!("targets = [\"{a}\"]"), &[]),
        &[],
        &["http_send"],
        |spec| {
            spec.ceiling = Some(ceiling);
            spec.operator = operator;
        },
    )
    .await;
    let e = s
        .session
        .escalation
        .take()
        .expect("a session has escalation");
    Fixture {
        s,
        e,
        sink,
        b,
        _fx: (fa, fb),
    }
}

async fn send_to(s: &mut Session, hostport: &str) -> (bool, Vec<bee::proxy_event::ProxyEvent>) {
    let (r, _, ev) = s
        .call_with_events(
            "http_send",
            json!({ "request": { "url": format!("http://{hostport}/search?q=x") } }),
        )
        .await;
    (!r.is_error, ev)
}

#[tokio::test]
async fn an_approved_widening_asks_for_exactly_the_refused_target_then_works() {
    let mut f = fixture(Some(true), |a, b| vec![a.into(), b.into()]).await;
    let mut active = f.active();

    let out = send_escalating(&mut f.s, &f.e, &mut active, &f.b).await;
    assert!(proxy_escalation(&out).is_granted(), "{out:?}");
    assert_eq!(*f.sink.seen.lock().unwrap(), vec![vec![f.b.clone()]]);
    // The lease records why it exists.
    assert!(matches!(
        &active.leases()[0].origin,
        GrantOrigin::ProxyRefusal { host, .. } if host == "127.0.0.1"
    ));
    // Both layers took it: the retry was sent and answered, and the refusal that justified it is
    // kept (024 FR-021).
    assert!(out.retried && !out.result.is_error, "{:?}", out.result);
    assert!(out
        .denied_attempt_proxy_events
        .iter()
        .any(|ev| ev.kind.is_refusal()));
    let (ok, _) = send_to(&mut f.s, &f.b).await;
    assert!(ok, "in scope after the grant");
}

#[tokio::test]
async fn a_declined_or_unanswered_widening_changes_nothing() {
    for answer in [Some(false), None] {
        let mut f = fixture(answer, |a, b| vec![a.into(), b.into()]).await;
        let mut active = f.active();
        let out = send_escalating(&mut f.s, &f.e, &mut active, &f.b).await;
        assert!(!proxy_escalation(&out).is_granted(), "{answer:?}: {out:?}");
        assert!(
            !out.retried && out.result.is_error,
            "{answer:?}: not retried"
        );
        assert_eq!(
            f.sink.seen.lock().unwrap().len(),
            1,
            "the operator was asked"
        );
        assert!(active.leases().is_empty());
        let (ok, _) = send_to(&mut f.s, &f.b).await;
        assert!(!ok, "{answer:?}: still refused");
    }
}

#[tokio::test]
async fn a_beyond_ceiling_target_is_refused_without_asking() {
    let mut f = fixture(Some(true), |a, _| vec![a.into()]).await; // b is not in the ceiling
    let mut active = f.active();
    let out = send_escalating(&mut f.s, &f.e, &mut active, &f.b).await;
    assert!(!proxy_escalation(&out).is_granted());
    assert!(
        f.sink.seen.lock().unwrap().is_empty(),
        "never prompted beyond the ceiling"
    );
}

#[tokio::test]
async fn a_worker_that_cannot_take_the_scope_rolls_the_grant_back() {
    let mut f = fixture(Some(true), |a, b| vec![a.into(), b.into()]).await;
    let mut active = f.active();
    // Kill the worker twice: the first death is restarted, the second leaves it gone.
    for _ in 0..2 {
        f.s.icpt.kill_worker_for_test().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    // The widen cycle for exactly the refused target, as a proxy refusal would drive it.
    let mut reg = bee::tools::ToolRegistry::new();
    let out = escalate(
        &mut active,
        GrantOrigin::ProxyRefusal {
            host: "127.0.0.1".into(),
            port: hp(&f.b).port,
            call: "c".into(),
        },
        GrantDelta {
            http_targets: vec![f.b.clone()],
            ..Default::default()
        },
        Ttl::Forever,
        1,
        &f.e.operator,
        &mut f.s.session.sandbox,
        &mut reg,
    )
    .await;
    assert!(!out.is_granted(), "{out:?}");
    assert!(active.leases().is_empty(), "the lease was released");
    assert!(!active
        .active()
        .http
        .as_ref()
        .unwrap()
        .targets
        .contains(&hp(&f.b)));
}

#[test]
fn no_model_tool_can_widen_the_scope() {
    // Every HTTP tool's argument schema, scanned for anything that could name scope.
    let reg = bee::tools::registry_for(
        &bee::tools::HTTP_TOOLS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        None,
    );
    for schema in reg.schemas() {
        let props = schema.parameters["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for k in [
            "targets",
            "egress",
            "inspect",
            "scope",
            "insecure_upstream",
            "limits",
        ] {
            assert!(!props.contains_key(k), "{} takes `{k}`", schema.name);
        }
    }
}

proptest! {
    /// SC-010: no sequence of target grants — approved or not — leaves the active scope outside the
    /// ceiling.
    #[test]
    fn no_grant_sequence_escapes_the_ceiling(
        ceiling_n in 0usize..6,
        asks in prop::collection::vec(0usize..10, 0..12),
    ) {
        let all: Vec<String> = (0..10).map(|i| format!("10.0.0.{i}:443")).collect();
        let ceiling = policy_with(&all[..ceiling_n]);
        let mut active = ActivePolicy::new(policy_with(&[]), ceiling.clone());
        for (turn, i) in asks.into_iter().enumerate() {
            let _ = active.try_apply(
                GrantOrigin::Explicit,
                GrantDelta { http_targets: vec![all[i].clone()], ..Default::default() },
                Ttl::Forever,
                turn as u32,
            );
            let held = active.active().http.as_ref().map(|h| h.targets.clone()).unwrap_or_default();
            let bound = &ceiling.http.as_ref().unwrap().targets;
            for t in &held {
                prop_assert!(bound.contains(t), "{t} outside the ceiling");
            }
        }
    }
}
