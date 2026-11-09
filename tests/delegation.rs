//! Delegation through the real loop (018-subagent-scopes, US1/US2/US3 host half; quickstart S2, S6).
//!
//! A scripted model drives the parent and, through the same script, the child: the parent's `task`
//! call runs the child's loop inside it, so the script reads parent turn, child turns, parent turn.
//! These run on a host sandbox — no kernel scope — so every delegation here is the *unenforced* kind
//! and must say so. Kernel denial inside a child is proven by the VM case `subagent-net-denied`.

#[path = "support/fixtures.rs"]
mod fixtures;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
use bee::transcript::{DelegationOutcome, EpisodeTranscript, RefusalReason};
use bee_core::{Access, Policy};
use fixtures::*;
use serde_json::{json, Value};

fn call(id: &str, name: &str, args: Value) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: args,
    }
}

fn turn(calls: Vec<ToolCall>) -> Turn {
    Turn {
        text: None,
        tool_calls: calls,
        stop: StopReason::ToolUse,
        usage: None,
    }
}

fn text(t: &str) -> Turn {
    Turn {
        text: Some(t.into()),
        tool_calls: Vec::new(),
        stop: StopReason::EndTurn,
        usage: None,
    }
}

fn task(id: &str, agent: &str) -> ToolCall {
    call(
        id,
        "task",
        json!({"agent": agent, "prompt": "count the bugs"}),
    )
}

fn finish(id: &str, summary: &str) -> ToolCall {
    call(
        id,
        "finish",
        json!({"outcome": "completed", "summary": summary}),
    )
}

/// Write an agent definition under `root/<name>/SKILL.md`.
fn agent(root: &Path, name: &str, front: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\nkind: agent\ndescription: test agent {name}\n{front}---\nYou count bugs.\n"),
    )
    .unwrap();
}

struct Setup {
    _root: tempfile::TempDir,
    agents: Arc<SkillRegistry>,
    work: PathBuf,
}

fn setup(front: &str) -> Setup {
    let root = tempfile::tempdir().unwrap();
    let skills = root.path().join("skills");
    agent(&skills, "reader", front);
    let work = root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("bugs.txt"), "3 bugs\n").unwrap();
    let agents = Arc::new(SkillRegistry::discover(&[skills]));
    assert!(agents.warnings().is_empty(), "{:?}", agents.warnings());
    Setup {
        _root: root,
        agents,
        work,
    }
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

struct Run {
    t: EpisodeTranscript,
    lines: Vec<String>,
}

/// Run the parent loop: `task` and `read_file` on its surface, `policy` as its active policy.
async fn run(s: &Setup, turns: Vec<Turn>, policy: Policy, delegation: Option<Delegation>) -> Run {
    let mut registry = ToolRegistry::with_deps(Arc::new(bee::tools::ToolDeps {
        agents: Some(s.agents.clone()),
        ..Default::default()
    }));
    registry.register("task").unwrap();
    registry.register("read_file").unwrap();
    let mut sb = Sandbox::host(Vec::new());
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let opts = LoopOptions {
        escalation: Some(escalation(policy)),
        delegation,
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        ..LoopOptions::default()
    };
    let t = run_loop(
        &MockModel::scripted(turns),
        &scenario("parent", &["task", "read_file"], 5, 60),
        &mut registry,
        &mut sb,
        &opts,
    )
    .await;
    let lines = lines.lock().unwrap().clone();
    Run { t, lines }
}

fn delegation(s: &Setup) -> Option<Delegation> {
    Some(Delegation::new(s.agents.clone(), None))
}

fn open_policy() -> Policy {
    policy(&[("/", Access::Write)])
}

// US1: the happy path. The parent sees one bounded report; the child's calls live only in its own
// record (FR-027), and a host delegation says it was unenforced (FR-032, FR-034).
#[tokio::test]
async fn a_delegation_returns_the_childs_report_and_keeps_its_calls_to_itself() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let bugs = s.work.join("bugs.txt");
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "reader")]),
            turn(vec![call("c1", "read_file", json!({"path": bugs}))]),
            turn(vec![finish("c2", "There are 3 bugs.")]),
            text("The subagent found 3 bugs."),
        ],
        open_policy(),
        delegation(&s),
    )
    .await;

    let parent_calls: Vec<&str> =
        r.t.turns
            .iter()
            .flat_map(|t| &t.calls)
            .map(|c| c.call.name.as_str())
            .collect();
    assert_eq!(
        parent_calls,
        vec!["task"],
        "the child's calls never enter the parent's record"
    );

    let rec = &r.t.turns[0].calls[0];
    assert!(rec.result.delegate.is_none());
    assert!(!rec.result.is_error, "{}", rec.result.content);
    let report = &rec.result.content;
    assert!(
        report.starts_with("subagent 'reader' — completed (2 turns)"),
        "{report}"
    );
    assert!(report.contains("There are 3 bugs."), "{report}");
    assert!(report.contains("NO kernel scope"), "{report}");

    let child = rec
        .child
        .as_ref()
        .expect("the delegation is recorded on its call");
    assert_eq!(child.agent, "reader");
    assert_eq!(child.outcome, DelegationOutcome::Completed);
    assert!(!child.enforced);
    assert_eq!(child.depth, 1);
    let ct = child.transcript.as_ref().expect("the child's own record");
    let child_calls: Vec<&str> = ct
        .turns
        .iter()
        .flat_map(|t| &t.calls)
        .map(|c| c.call.name.as_str())
        .collect();
    assert_eq!(child_calls, vec!["read_file", "finish"]);
    assert!(
        ct.turns[0].calls[0].result.content.contains("3 bugs"),
        "the child really read the file"
    );
    assert_eq!(r.t.delegations().len(), 1);

    assert!(
        r.lines.iter().any(|l| l.contains("call task")),
        "{:?}",
        r.lines
    );
}

// The record round-trips, and a session that never delegates serializes no delegation field.
#[tokio::test]
async fn the_record_round_trips_and_a_non_delegating_call_has_no_child() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "reader")]),
            turn(vec![finish("c1", "nothing to report")]),
            turn(vec![call(
                "p2",
                "read_file",
                json!({"path": s.work.join("bugs.txt")}),
            )]),
            text("done"),
        ],
        open_policy(),
        delegation(&s),
    )
    .await;
    let json = r.t.to_json();
    let back: EpisodeTranscript = serde_json::from_str(&json).unwrap();
    assert_eq!(back.delegations().len(), 1);
    let plain = serde_json::to_value(&r.t.turns[1].calls[0]).unwrap();
    assert!(plain.get("child").is_none(), "{plain}");
    assert!(
        plain["result"].get("delegate").is_none(),
        "a delegation request is never recorded"
    );
}

// US2 / FR-010: an agent asking for more than the session holds is refused before anything runs,
// and the refusal names the rule.
#[tokio::test]
async fn an_over_broad_agent_is_refused_naming_the_path() {
    let s = setup(
        "tools: [read_file]\nturn-limit: 4\nrequires:\n  filesystem:\n    /tmp/bee-018-x: write\n",
    );
    let r = run(
        &s,
        vec![turn(vec![task("p1", "reader")]), text("ok")],
        policy(&[("/tmp/bee-018-x", Access::Read)]),
        delegation(&s),
    )
    .await;
    let rec = &r.t.turns[0].calls[0];
    assert!(rec.result.is_error);
    assert!(
        rec.result.content.contains("REFUSED") && rec.result.content.contains("/tmp/bee-018-x"),
        "{}",
        rec.result.content
    );
    let child = rec.child.as_ref().unwrap();
    assert!(matches!(
        child.outcome,
        DelegationOutcome::Refused {
            reason: RefusalReason::OverGrant { .. }
        }
    ));
    assert!(child.transcript.is_none(), "nothing ran");
    assert_eq!(child.scope_id, "", "no scope was created");
}

// FR-012 / US1 AS-3: a tool the session does not hold is refused by name.
#[tokio::test]
async fn an_agent_needing_a_tool_the_session_lacks_is_refused_by_name() {
    let s = setup("tools: [bash]\nturn-limit: 4\n");
    let r = run(
        &s,
        vec![turn(vec![task("p1", "reader")]), text("ok")],
        open_policy(),
        delegation(&s),
    )
    .await;
    let rec = &r.t.turns[0].calls[0];
    assert!(
        rec.result.content.contains("'bash'"),
        "{}",
        rec.result.content
    );
    assert!(matches!(
        rec.child.as_ref().unwrap().outcome,
        DelegationOutcome::Refused {
            reason: RefusalReason::ToolNotHeld { .. }
        }
    ));
}

// FR-004: an unknown agent is the tool's own refusal, listing the agents there are.
#[tokio::test]
async fn an_unknown_agent_is_refused_listing_the_available_ones() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let r = run(
        &s,
        vec![turn(vec![task("p1", "ghost")]), text("ok")],
        open_policy(),
        delegation(&s),
    )
    .await;
    let rec = &r.t.turns[0].calls[0];
    assert!(rec.result.is_error);
    assert!(
        rec.result.content.contains("ghost") && rec.result.content.contains("reader"),
        "{}",
        rec.result.content
    );
    assert!(rec.child.is_none());
}

// FR-025 (the loop's half): a delegation past the depth limit is refused even if the tool is there.
#[tokio::test]
async fn a_delegation_past_the_depth_limit_is_refused() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let mut d = delegation(&s).unwrap();
    d.depth = 1;
    let r = run(
        &s,
        vec![turn(vec![task("p1", "reader")]), text("ok")],
        open_policy(),
        Some(d),
    )
    .await;
    assert!(matches!(
        r.t.turns[0].calls[0].child.as_ref().unwrap().outcome,
        DelegationOutcome::Refused {
            reason: RefusalReason::DepthExceeded { max_depth: 1 }
        }
    ));
}

// A loop that lends no delegator refuses the call rather than answer it with an empty result.
#[tokio::test]
async fn without_delegation_a_task_call_is_refused_not_answered_empty() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let r = run(
        &s,
        vec![turn(vec![task("p1", "reader")]), text("ok")],
        open_policy(),
        None,
    )
    .await;
    let rec = &r.t.turns[0].calls[0];
    assert!(rec.result.is_error);
    assert!(
        rec.result
            .content
            .contains("delegation is not available here"),
        "{}",
        rec.result.content
    );
}

// A child that runs out of turns is cut short, and the parent is told the task was not completed.
#[tokio::test]
async fn a_child_out_of_turns_is_reported_cut_short() {
    let s = setup("tools: [read_file]\nturn-limit: 1\n");
    let bugs = s.work.join("bugs.txt");
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "reader")]),
            turn(vec![call("c1", "read_file", json!({"path": bugs}))]),
            text("ok"),
        ],
        open_policy(),
        delegation(&s),
    )
    .await;
    let rec = &r.t.turns[0].calls[0];
    assert!(rec.result.is_error);
    assert!(
        rec.result.content.contains("CUT SHORT") && rec.result.content.contains("NOT completed"),
        "{}",
        rec.result.content
    );
}

// FR-011 at the policy level: what an agent leaves unsaid it inherits as a restriction.
#[test]
fn an_agent_inherits_what_its_parent_denies() {
    let root = tempfile::tempdir().unwrap();
    agent(
        root.path(),
        "narrow",
        "tools: []\nturn-limit: 2\nrequires:\n  filesystem:\n    /work: read\n",
    );
    let reg = SkillRegistry::discover(&[root.path().to_path_buf()]);
    let a = reg.agent("narrow").unwrap();
    // The agent says nothing about /srv/secret; the parent denies it.
    let parent = policy(&[("/work", Access::Write), ("/srv/secret", Access::Deny)]);
    let derived = parent.derive(a.requested_policy()).unwrap();
    assert_eq!(derived.filesystem.get("/work"), Some(&Access::Read));
    assert_eq!(
        derived.filesystem.get("/srv/secret"),
        Some(&Access::Deny),
        "the parent's deny survives the agent's silence"
    );
    // And an agent reaching *over* a parent deny is refused outright, not narrowed (FR-013).
    let over = policy(&[("/work", Access::Write), ("/work/secret", Access::Deny)]);
    assert!(over.derive(a.requested_policy()).is_err());
}
