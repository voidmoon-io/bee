//! 026 US3 (T031–T034): bee as the ACP client of an external harness, against the scripted
//! `bee acp-fake-harness`.
//!
//! These drive [`bee::acp::harness::run`] on a host sandbox: the ACP client half — handshake,
//! permission answers, refused client methods, the deadline, a harness that dies. Delegation itself
//! refuses a harness without a kernel scope (T033, here); the contained run — its own scope and
//! proxy, the report the delegating model reads — is the VM case `harness-contained`.

#![cfg(all(feature = "acp", feature = "test-support"))]

#[path = "support/fixtures.rs"]
mod fixtures;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bee::acp::harness::{run, HarnessEnd, HarnessRun, HarnessSpec};
use bee::delegate::Delegation;
use bee::episode::{run_loop, LoopOptions};
use bee::grants::escalate::LoopEscalation;
use bee::grants::Ttl;
use bee::operator::{NullOutput, Operator};
use bee::provider::mock_model::MockModel;
use bee::provider::{StopReason, ToolCall, Turn};
use bee::sandbox::Sandbox;
use bee::skills::SkillRegistry;
use bee::tools::ToolRegistry;
use bee::transcript::{DelegationOutcome, RefusalReason};
use bee_core::{Access, Policy};
use serde_json::json;

async fn harness(script: serde_json::Value, deadline: Duration) -> HarnessRun {
    let mut sb = Sandbox::host(Vec::new());
    let args = vec!["acp-fake-harness".to_string()];
    run(
        &mut sb,
        HarnessSpec {
            agent: "fake",
            command: Path::new(env!("CARGO_BIN_EXE_bee")),
            args: &args,
            env: vec![("FAKE_HARNESS_SCRIPT".into(), script.to_string())],
            prompt: "do the task",
            deadline: Instant::now() + deadline,
            progress: None,
        },
    )
    .await
}

// T031: its final turn is the report; a permission is answered allow-once (not the always option
// offered first) and recorded; the harness's calls live in its record.
#[tokio::test]
async fn a_harness_reports_its_final_turn_and_its_calls_stay_in_its_record() {
    let r = harness(
        json!([{"say": "starting"}, {"ask_permission": "edit README"}, {"say": "all done"}]),
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(
        r.end,
        HarnessEnd::Stopped("end_turn".into()),
        "{:?}",
        r.record
    );
    let report = r.report();
    assert!(report.contains("ask_permission: chose once"), "{report}");
    assert!(report.contains("all done"), "{report}");
    assert_eq!(r.record.permissions.len(), 1);
    let p = &r.record.permissions[0];
    assert_eq!(p.chosen, "allow_once:once");
    assert_eq!(p.title, "edit README");
    assert_eq!(p.offered.len(), 3);
    assert_eq!(r.record.agent_info.as_deref(), Some("fake-harness 0.1"));
    assert_eq!(r.record.env_keys, vec!["FAKE_HARNESS_SCRIPT".to_string()]);
    assert_eq!(r.record.stop_reason, "end_turn");
}

// T032: bee advertised no client methods; one called anyway is refused, recorded, and the harness
// carries on.
#[tokio::test]
async fn fs_and_terminal_calls_are_refused_and_recorded() {
    let r = harness(
        json!([{"call_fs_read": "/etc/hostname"}, {"say": "carried on"}]),
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(r.end, HarnessEnd::Stopped("end_turn".into()));
    assert_eq!(
        r.record.refused_methods,
        vec!["fs/read_text_file".to_string()]
    );
    let report = r.report();
    assert!(report.contains("fs/read_text_file: refused"), "{report}");
    assert!(report.contains("carried on"), "{report}");
}

// T034: at the deadline bee cancels and cuts it short within the grace period.
#[tokio::test]
async fn deadline_cancels_then_cuts_short() {
    let start = Instant::now();
    let r = harness(json!([{"sleep": 30}]), Duration::from_secs(1)).await;
    assert_eq!(r.end, HarnessEnd::Deadline);
    assert_eq!(r.record.stop_reason, "deadline");
    assert!(r.report().contains("sleep: cancelled"), "{}", r.report());
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

// T034: a harness that dies mid-prompt fails, with its stderr kept for the record.
#[tokio::test]
async fn a_harness_that_exits_early_fails_with_its_stderr() {
    let r = harness(
        json!([{"stderr": "boom: no credentials"}, {"exit": 3}]),
        Duration::from_secs(30),
    )
    .await;
    let HarnessEnd::Failed(why) = &r.end else {
        panic!("{:?}", r.end)
    };
    assert!(!why.is_empty());
    assert!(
        r.record.stderr_tail.contains("boom: no credentials"),
        "{:?}",
        r.record.stderr_tail
    );
}

#[tokio::test]
async fn a_command_that_does_not_exist_fails_naming_it() {
    let mut sb = Sandbox::host(Vec::new());
    let r = run(
        &mut sb,
        HarnessSpec {
            agent: "ghost",
            command: Path::new("/nonexistent/harness"),
            args: &[],
            env: Vec::new(),
            prompt: "x",
            deadline: Instant::now() + Duration::from_secs(5),
            progress: None,
        },
    )
    .await;
    let HarnessEnd::Failed(why) = &r.end else {
        panic!("{:?}", r.end)
    };
    assert!(why.contains("/nonexistent/harness"), "{why}");
}

// T033 (FR-017): delegating to a harness from a session with no kernel scope is refused before
// anything is spawned.
#[tokio::test]
async fn a_harness_is_refused_without_a_kernel_scope() {
    let root = tempfile::tempdir().unwrap();
    let skills = root.path().join("skills");
    let dir = skills.join("fake");
    std::fs::create_dir_all(&dir).unwrap();
    let marker = root.path().join("ran");
    std::fs::write(
        dir.join("SKILL.md"),
        format!(
            "---\nname: fake\nkind: agent\ndescription: a harness\nruntime:\n  acp:\n    \
             command: {}\n    args: [acp-fake-harness]\n    env:\n      FAKE_HARNESS_SCRIPT: \
             '[{{\"write\": {{\"path\": \"{}\"}}}}]'\n---\nunused\n",
            env!("CARGO_BIN_EXE_bee"),
            marker.display()
        ),
    )
    .unwrap();
    let agents = Arc::new(SkillRegistry::discover(&[skills]));
    assert!(agents.warnings().is_empty(), "{:?}", agents.warnings());

    let policy = fixtures::policy(&[("/", Access::Write)]);
    let mut registry = ToolRegistry::with_deps(Arc::new(bee::tools::ToolDeps {
        agents: Some(agents.clone()),
        ..Default::default()
    }));
    registry.register("task").unwrap();
    let opts = LoopOptions {
        escalation: Some(escalation(policy)),
        delegation: Some(Delegation::new(agents, None)),
        ..LoopOptions::default()
    };
    let t = run_loop(
        &MockModel::scripted(vec![
            Turn {
                text: None,
                tool_calls: vec![ToolCall {
                    id: "t1".into(),
                    name: "task".into(),
                    arguments: json!({"agent": "fake", "prompt": "write"}),
                }],
                stop: StopReason::ToolUse,
                usage: None,
            },
            Turn {
                text: Some("ok".into()),
                tool_calls: Vec::new(),
                stop: StopReason::EndTurn,
                usage: None,
            },
        ]),
        &fixtures::scenario("parent", &["task"], 3, 30),
        &mut registry,
        &mut Sandbox::host(Vec::new()),
        &opts,
    )
    .await;
    let record = *t.delegations().first().expect("a delegation record");
    let DelegationOutcome::Refused {
        reason: RefusalReason::Unavailable { detail },
    } = &record.outcome
    else {
        panic!("{:?}", record.outcome)
    };
    assert!(detail.contains("harness 'fake'"), "{detail}");
    assert!(!marker.exists(), "nothing was spawned");
}

fn escalation(policy: Policy) -> LoopEscalation {
    LoopEscalation {
        base: policy.clone(),
        ceiling: policy,
        hooks: Vec::new(),
        operator: Operator::autonomous(Arc::new(NullOutput)),
        default_ttl: Ttl::Forever,
    }
}
