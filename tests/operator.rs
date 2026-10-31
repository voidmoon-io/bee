//! 024 PR 5b (US2) — the Operator: one seam for consent, and every decision recorded
//! (contracts/operator.md, FR-001–FR-005).
//!
//! Driven through `bee::call::run_call` and `bee::session::build` with no model and no BPF-LSM kernel:
//! a scripted tool, scripted kernel audit, and the real Operator adapters.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bee::call::{run_call, CallInput, CallOutcome, Escalation, TimeoutPolicy};
use bee::grants::escalate::{escalate, DenialEscalationHook, EscalateOutcome, LoopEscalation};
use bee::grants::{ActivePolicy, GrantDelta, GrantOrigin, Ttl};
use bee::operator::{
    ChannelConsent, ConsentReceiver, Decision, NullOutput, Operator, OperatorKind, Reason, Verdict,
};
use bee::provider::ToolCall;
use bee::sandbox::{CallOrigin, Sandbox, ScriptedAudit};
use bee::tools::ToolRegistry;
use bee::transcript::{EpisodeStatus, EpisodeTranscript, Timing};
use bee_core::{Access, Policy};
use fixtures::policy;
use scripted::*;

/// A session's call machinery around one scripted tool and one operator.
struct Rig {
    sandbox: Sandbox,
    registry: ToolRegistry,
    config: LoopEscalation,
    active: ActivePolicy,
    attempts: Arc<std::sync::atomic::AtomicU32>,
}

fn rig(attempts: Vec<Attempt>, ceiling: Policy, operator: Operator) -> Rig {
    let audit = Arc::new(ScriptedAudit::default());
    let mut sandbox = Sandbox::host_scripted(Vec::new(), audit.clone());
    sandbox.set_call_hooks(Arc::new(FakeCallHooks::default()));
    sandbox.set_http_scope_hook(Arc::new(FakeHttpScope::default()));
    let tool = ScriptedTool::new(audit, attempts);
    let counter = tool.counter();
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(tool));
    let base = policy(&[]);
    Rig {
        sandbox,
        registry,
        active: ActivePolicy::new(base.clone(), ceiling.clone()).unwrap(),
        config: LoopEscalation {
            base,
            ceiling,
            hooks: vec![Box::new(DenialEscalationHook { enabled: true })],
            operator,
            default_ttl: Ttl::Forever,
        },
        attempts: counter,
    }
}

impl Rig {
    async fn call(&mut self, id: &str, turn: u32) -> CallOutcome {
        let call = ToolCall {
            id: id.into(),
            name: SCRIPTED.into(),
            arguments: serde_json::json!({}),
        };
        run_call(
            CallInput {
                call: &call,
                turn,
                origin: CallOrigin::Tool,
                timeout: TimeoutPolicy::PerCall(Duration::from_secs(600)),
            },
            &mut self.sandbox,
            &mut self.registry,
            Some(Escalation {
                config: &self.config,
                active: &mut self.active,
                lease_turn: turn,
            }),
        )
        .await
    }
}

fn denied(target: &str) -> Attempt {
    Attempt::error("Permission denied").with_audit(vec![ev("file_open", target, "denied", None)])
}

fn ceiling() -> Policy {
    policy(&[("/tmp", Access::Write)])
}

// (a) Autonomous: a denial inside the ceiling is granted, one outside is refused unasked — two
// records, nobody prompted. A request for what is already held is no decision and adds nothing.
#[tokio::test(start_paused = true)]
async fn the_autonomous_operator_records_every_decision_and_asks_nobody() {
    let operator = Operator::autonomous(Arc::new(NullOutput));
    let mut r = rig(
        vec![denied("/tmp/w"), Attempt::ok("done"), denied("/etc/x")],
        ceiling(),
        operator.clone(),
    );

    let first = r.call("c1", 1).await;
    assert!(first.result.content.contains("done"), "granted and retried");
    let second = r.call("c2", 2).await;
    assert!(second.result.is_error, "beyond the ceiling stays denied");

    // The capability the first call won is held now: proposing it again is not a decision.
    let again = escalate(
        &mut r.active,
        GrantOrigin::SkillRequires {
            skill: "writer".into(),
        },
        GrantDelta {
            filesystem: [("/tmp/w".to_string(), Access::Write)].into(),
            ..Default::default()
        },
        Ttl::Forever,
        3,
        &operator,
        &mut r.sandbox,
        &mut r.registry,
    )
    .await;
    assert_eq!(again, EscalateOutcome::AlreadyHeld);

    let log = operator.take_log();
    assert_eq!(log.len(), 2, "{log:#?}");
    assert_eq!(
        (log[0].decision, log[0].reason),
        (Verdict::Granted, Reason::Granted)
    );
    assert_eq!(
        log[0].request.origin,
        GrantOrigin::ReactiveDenial {
            op: "file_open".into(),
            target: "/tmp/w".into()
        }
    );
    assert_eq!(log[0].request.turn, 1);
    assert!(log[0].lease.is_some(), "a grant names the lease it became");
    assert_eq!(
        (log[1].decision, log[1].reason),
        (Verdict::Refused, Reason::BeyondCeiling)
    );
    assert!(log[1].lease.is_none());
    assert!(log
        .iter()
        .all(|rec| rec.operator == OperatorKind::Autonomous));
}

// (b) Interactive, nobody answers: refused as `TimedOut` after the operator's timeout, the call is
// not retried, and an answer that arrives afterwards has nowhere to go.
#[tokio::test(start_paused = true)]
async fn an_unanswered_interactive_request_times_out_and_is_not_retried() {
    let (consent, mut rx): (ChannelConsent, ConsentReceiver) = ChannelConsent::new();
    let operator = Operator::interactive(consent, Arc::new(NullOutput));
    assert_eq!(operator.timeout(), Duration::from_secs(120));
    let mut r = rig(
        vec![denied("/tmp/w"), Attempt::ok("must not run")],
        ceiling(),
        operator.clone(),
    );

    let out = r.call("c1", 1).await;
    assert!(out.result.is_error);
    assert_eq!(
        r.attempts.load(Ordering::SeqCst),
        1,
        "no retry on a timeout"
    );
    assert!(r.active.leases().is_empty());

    let log = operator.take_log();
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].decision, log[0].reason),
        (Verdict::Refused, Reason::TimedOut)
    );
    assert_eq!(log[0].operator, OperatorKind::Interactive);

    // The front-end answers late: the question is gone, so the answer is neither applied nor kept.
    let late = rx.try_recv().expect("the question reached the front-end");
    assert!(late.reply.is_closed());
    assert!(late.reply.send(Decision::Granted).is_err());
    assert!(r.active.leases().is_empty());
}

// (c) The front-end is gone: refused by the operator, at once.
#[tokio::test(start_paused = true)]
async fn a_front_end_that_is_gone_refuses() {
    let (consent, rx) = ChannelConsent::new();
    drop(rx);
    let operator = Operator::interactive(consent, Arc::new(NullOutput));
    let mut r = rig(vec![denied("/tmp/w")], ceiling(), operator.clone());
    let started = tokio::time::Instant::now();
    r.call("c1", 1).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "no wait for a timeout"
    );
    let log = operator.take_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].reason, Reason::DeniedByOperator);
}

// (d) A start-up skill grant goes through the operator with the full request, recorded as start-up.
#[tokio::test]
async fn a_start_up_grant_carries_the_whole_request() {
    let root = std::env::temp_dir().join(format!("bee-operator-{}", std::process::id()));
    let dir = root.join("writer");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        "---\nname: writer\ndescription: writes\nrequires:\n  tools: [bash]\n  filesystem:\n    /tmp/out: write\n---\nWrite.\n",
    )
    .unwrap();

    let operator = Operator::autonomous(Arc::new(NullOutput));
    let spec = bee::session::SessionSpec {
        entry: bee::session::EntryPoint::Headless,
        label: "operator".into(),
        policy: Some(policy(&[])),
        ceiling: Some(ceiling()),
        enforcement: bee::session::Enforcement::Host,
        tools: vec!["read_file".into()],
        ctf_flag: None,
        skill_roots: vec![root.clone()],
        mcp: Default::default(),
        security: Default::default(),
        workdir: std::env::temp_dir(),
        system_prompt: "test".into(),
        strip_env: Vec::new(),
        http_scope_advisory: false,
        lease_turns: None,
        operator: operator.clone(),
        prebuilt_sandbox: None,
    };
    let mut session = bee::session::build(spec, &|_| {}).await.expect("builds");
    let log = session.operator.take_log();
    session.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(log.len(), 1, "{log:#?}");
    let req = &log[0].request;
    assert_eq!(
        req.origin,
        GrantOrigin::Startup {
            skill: "writer".into()
        }
    );
    assert_eq!(req.turn, 0);
    assert_eq!(req.tools, ["bash"]);
    assert_eq!(req.filesystem.get("/tmp/out"), Some(&Access::Write));
    assert_eq!(log[0].reason, Reason::Granted);
    // What an interactive prompt would show names every kind the request carries.
    let shown = req.render_lines().join("\n");
    assert!(shown.contains("tools: bash") && shown.contains("/tmp/out = write"));
}

fn transcript() -> EpisodeTranscript {
    EpisodeTranscript {
        audit_health: Default::default(),
        scenario_id: "golden".into(),
        model_id: "mock/golden".into(),
        status: EpisodeStatus::Completed,
        turns: Vec::new(),
        audit_trail: Vec::new(),
        timing: Timing {
            started_at: "2026-01-01T00:00:00Z".into(),
            ended_at: "2026-01-01T00:00:01Z".into(),
            total_ms: 1000,
        },
        usage: None,
        score: None,
        http_scope: None,
        consents: Vec::new(),
        mcp_audit: Default::default(),
        finish_offered: false,
        compactions: Vec::new(),
        summary_usage: None,
        #[cfg(feature = "durable-sessions")]
        durable_budget: None,
    }
}

// (e) `consents` appears only when there were decisions: a session without any serializes exactly as
// it did before the Operator existed (tests/fixtures/transcript_no_consents.json, written by main).
#[tokio::test]
async fn consents_are_recorded_only_when_there_are_any() {
    let golden = include_str!("fixtures/transcript_no_consents.json");
    assert_eq!(transcript().to_json(), golden.trim_end());

    let operator = Operator::autonomous(Arc::new(NullOutput));
    let mut r = rig(
        vec![denied("/tmp/w"), Attempt::ok("done")],
        ceiling(),
        operator.clone(),
    );
    r.call("c1", 1).await;
    let mut t = transcript();
    t.consents = operator.take_log();
    let json: serde_json::Value = serde_json::from_str(&t.to_json()).unwrap();
    let rec = &json["consents"][0];
    assert_eq!(rec["decision"], "granted");
    assert_eq!(rec["reason"], "granted");
    assert_eq!(rec["operator"], "autonomous");
    assert_eq!(rec["request"]["origin"]["kind"], "reactive_denial");
    assert_eq!(rec["request"]["filesystem"]["/tmp/w"], "write");
    // And it reads back.
    let back: EpisodeTranscript = serde_json::from_value(json).unwrap();
    assert_eq!(back.consents, t.consents);
}
