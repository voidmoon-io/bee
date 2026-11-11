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

use bee::delegate::{Budget, Delegation, DelegationLimits};
use bee::episode::{run_loop, LoopOptions};
use bee::grants::escalate::LoopEscalation;
use bee::grants::Ttl;
use bee::operator::{NullOutput, Operator};
use bee::provider::mock_model::MockModel;
use bee::provider::{StopReason, ToolCall, Turn};
use bee::sandbox::Sandbox;
use bee::skills::SkillRegistry;
use bee::tools::ToolRegistry;
use bee::transcript::{
    CutShortReason, DelegationOutcome, EpisodeStatus, EpisodeTranscript, RefusalReason,
};
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
    run_with(s, turns, policy, delegation, None, 5).await
}

/// [`run`], drawing from `budget` with the parent's own `turn_limit`.
async fn run_with(
    s: &Setup,
    turns: Vec<Turn>,
    policy: Policy,
    delegation: Option<Delegation>,
    budget: Option<Budget>,
    turn_limit: u32,
) -> Run {
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
        delegation: delegation.map(|d| match &budget {
            Some(b) => d.with_budget(b.clone()),
            None => d,
        }),
        budget,
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        ..LoopOptions::default()
    };
    let t = run_loop(
        &MockModel::scripted(turns),
        &scenario("parent", &["task", "read_file"], turn_limit, 60),
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

// US7: a subagent carries its own escalation — its policy, under a ceiling of its parent's at spawn —
// so a subagent allowed to delegate derives its own subagent from what *it* holds. Before US7 the
// child loop had no policy and every nested delegation was refused as having none to derive from.
#[tokio::test]
async fn a_subagent_delegates_from_its_own_policy() {
    let s = setup("tools: [read_file, task]\nturn-limit: 4\n");
    let d = delegation(&s).unwrap().with_limits(DelegationLimits {
        max_depth: Some(2),
        max_concurrent: None,
    });
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "reader")]),
            turn(vec![task("c1", "reader")]),
            turn(vec![finish("g1", "deep")]),
            turn(vec![finish("c2", "mid")]),
            text("ok"),
        ],
        open_policy(),
        Some(d),
    )
    .await;
    let child = r.t.turns[0].calls[0].child.as_ref().unwrap();
    assert_eq!(child.outcome, DelegationOutcome::Completed, "{child:?}");
    let grandchild = child.transcript.as_ref().unwrap().turns[0].calls[0]
        .child
        .as_ref()
        .expect("the subagent's own task call delegated");
    assert_eq!(grandchild.depth, 2);
    assert_eq!(
        grandchild.outcome,
        DelegationOutcome::Completed,
        "{grandchild:?}"
    );
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

// US4 / SC-005: a subagent draws from the session's turns; delegating cannot buy more. The parent
// has 5; it spends one delegating, the child gets the 4 left and is cut short, and the parent then
// has none for itself.
#[tokio::test]
async fn a_subagent_draws_from_the_sessions_turns_and_cannot_exceed_them() {
    let s = setup("tools: [read_file]\nturn-limit: 20\n");
    let bugs = s.work.join("bugs.txt");
    let mut script = vec![turn(vec![task("p1", "reader")])];
    for i in 0..10 {
        script.push(turn(vec![call(
            &format!("c{i}"),
            "read_file",
            json!({"path": bugs}),
        )]));
    }
    let budget = Budget::new(
        5,
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    );
    let r = run_with(
        &s,
        script,
        open_policy(),
        delegation(&s),
        Some(budget.clone()),
        10,
    )
    .await;

    let rec = &r.t.turns[0].calls[0];
    let child = rec.child.as_ref().unwrap();
    assert_eq!(
        child.outcome,
        DelegationOutcome::CutShort {
            reason: CutShortReason::SharedTurns
        }
    );
    assert!(
        rec.result.content.contains("shared turn budget"),
        "{}",
        rec.result.content
    );
    assert_eq!(child.turns_used, Some(4));
    assert_eq!(
        r.t.turns.len() as u32 + child.turns_used.unwrap(),
        5,
        "parent and child together spent exactly the pool"
    );
    assert_eq!(r.t.status, EpisodeStatus::BudgetExhausted);
    assert_eq!(budget.turns_left(), 0);
}

// US5: several `task` calls in one turn each run their own subagent, and each result lands on its
// own call, in call order.
#[tokio::test]
async fn task_calls_in_one_turn_each_get_their_own_subagent() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let r = run(
        &s,
        vec![
            turn(vec![
                task("p1", "reader"),
                task("p2", "reader"),
                task("p3", "reader"),
            ]),
            // The children share the scripted model, so which takes which `finish` is not fixed;
            // each summary is unique, and each must land on exactly one call.
            turn(vec![finish("c1", "summary one")]),
            turn(vec![finish("c2", "summary two")]),
            turn(vec![finish("c3", "summary three")]),
            text("done"),
        ],
        open_policy(),
        delegation(&s),
    )
    .await;
    let calls = &r.t.turns[0].calls;
    assert_eq!(calls.len(), 3);
    let ids: Vec<&str> = calls.iter().map(|c| c.call.id.as_str()).collect();
    assert_eq!(ids, vec!["p1", "p2", "p3"], "results stay in call order");
    let mut summaries: Vec<String> = calls
        .iter()
        .map(|c| {
            assert_eq!(
                c.child.as_ref().unwrap().outcome,
                DelegationOutcome::Completed
            );
            c.result.content.lines().last().unwrap().to_string()
        })
        .collect();
    summaries.sort();
    assert_eq!(
        summaries,
        vec!["summary one", "summary three", "summary two"]
    );
    assert_eq!(r.t.delegations().len(), 3);
}

// US5: one sibling failing to start leaves the others running, and says which failed and why.
#[tokio::test]
async fn one_sibling_refused_does_not_stop_the_others() {
    let root = tempfile::tempdir().unwrap();
    let skills = root.path().join("skills");
    agent(&skills, "good", "tools: [read_file]\nturn-limit: 3\n");
    agent(&skills, "needs-bash", "tools: [bash]\nturn-limit: 3\n");
    let s = Setup {
        agents: Arc::new(SkillRegistry::discover(&[skills])),
        work: root.path().to_path_buf(),
        _root: root,
    };
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "needs-bash"), task("p2", "good")]),
            turn(vec![finish("c1", "fine")]),
            text("done"),
        ],
        open_policy(),
        delegation(&s),
    )
    .await;
    let calls = &r.t.turns[0].calls;
    assert!(
        calls[0].result.content.contains("REFUSED") && calls[0].result.content.contains("'bash'")
    );
    assert_eq!(
        calls[1].child.as_ref().unwrap().outcome,
        DelegationOutcome::Completed
    );
}

// US4: `max_concurrent` bounds a segment; calls beyond it still run, in the next segment.
#[tokio::test]
async fn max_concurrent_bounds_a_segment_and_every_call_still_runs() {
    let s = setup("tools: [read_file]\nturn-limit: 4\n");
    let d = Delegation::new(s.agents.clone(), None).with_limits(DelegationLimits {
        max_depth: None,
        max_concurrent: Some(1),
    });
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "reader"), task("p2", "reader")]),
            turn(vec![finish("c1", "first")]),
            turn(vec![finish("c2", "second")]),
            text("done"),
        ],
        open_policy(),
        Some(d),
    )
    .await;
    let calls = &r.t.turns[0].calls;
    // With one at a time the order is fixed: the first call's child takes the first `finish`.
    assert!(
        calls[0].result.content.ends_with("first"),
        "{}",
        calls[0].result.content
    );
    assert!(
        calls[1].result.content.ends_with("second"),
        "{}",
        calls[1].result.content
    );
}

// The `[delegation]` limits: defaults, hard caps, and a project layer that can only lower them.
#[test]
fn delegation_limits_resolve_and_only_narrow() {
    assert_eq!(DelegationLimits::default().resolve(), (1, 4));
    let huge = DelegationLimits {
        max_depth: Some(99),
        max_concurrent: Some(999),
    };
    assert_eq!(huge.resolve(), (4, 16), "hard caps");
    let operator = DelegationLimits {
        max_depth: Some(2),
        max_concurrent: Some(8),
    };
    let wider = DelegationLimits {
        max_depth: Some(3),
        max_concurrent: Some(12),
    };
    assert_eq!(
        operator.narrowed_by(wider),
        operator,
        "a project cannot raise them"
    );
    let narrower = DelegationLimits {
        max_depth: Some(1),
        max_concurrent: None,
    };
    assert_eq!(operator.narrowed_by(narrower).resolve(), (1, 8));
    // Over defaults the project still only lowers.
    assert_eq!(
        DelegationLimits::default().narrowed_by(wider).resolve(),
        (1, 4)
    );
}

// US4 / FR-026: a report is capped like any other tool result, and says so.
#[tokio::test]
async fn an_oversized_report_is_truncated_visibly() {
    let s = setup("tools: [read_file]\nturn-limit: 3\n");
    let huge = "x".repeat(150 * 1024);
    let r = run(
        &s,
        vec![
            turn(vec![task("p1", "reader")]),
            // `finish` caps a summary at 4000 characters; a child that ends in prose instead (a
            // reminder, then a second text turn) reports its last words, which are not capped.
            text(&huge),
            text(&huge),
            text("done"),
        ],
        open_policy(),
        delegation(&s),
    )
    .await;
    let res = &r.t.turns[0].calls[0].result;
    assert!(res.truncated);
    assert!(res.original_len.unwrap() > res.content.len());
    assert!(res.content.len() <= bee::transcript::DEFAULT_OUTPUT_CAP + 512);
}
