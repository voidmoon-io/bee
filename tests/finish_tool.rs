//! The finish tool through the episode loop (025 US3, quickstart Phase D, contracts/finish.md).
//!
//! The loop offers `finish` when the surface has it; `bee run` and the batch put it there for a
//! standard scenario (`episode::offers_finish`). Inputs are scripted (024 research R1).

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use bee::episode::{
    exit_code, offers_finish, run_loop, status_label, LoopOptions, EXIT_INCOMPLETE,
};
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, StopReason, ToolCall, Turn};
use bee::repl::{run_exchange, ExchangeOutcome, ReplConfig, ReplOutput};
use bee::sandbox::{Sandbox, ScriptedAudit};
use bee::scenario::ScoringMode;
use bee::tools::finish::{Finish, FinishOutcome};
use bee::tools::{ToolRegistry, ToolResult};
use bee::transcript::{EpisodeStatus, EpisodeTranscript, NoteKind};
use bee::viz::grid::Status;
use bee_core::AuditEvent;
use fixtures::*;
use scripted::*;
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

fn finish(id: &str, outcome: &str, summary: &str) -> ToolCall {
    call(
        id,
        "finish",
        json!({"outcome": outcome, "summary": summary}),
    )
}

fn work(id: &str) -> ToolCall {
    call(id, SCRIPTED, json!({}))
}

struct Run {
    t: EpisodeTranscript,
    lines: Vec<String>,
    /// How many times the `scripted` tool actually ran.
    worked: u32,
}

/// Run `turns` through the episode loop with `finish` on the surface when `offered`.
async fn run(turns: Vec<Turn>, offered: bool) -> Run {
    let audit = Arc::new(ScriptedAudit::default());
    let mut sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let tool = ScriptedTool::new(audit, Vec::new());
    let worked = tool.counter();
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(tool));
    if offered {
        registry.insert(Box::new(Finish));
    }
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let opts = LoopOptions {
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        ..LoopOptions::default()
    };
    let t = run_loop(
        &MockModel::scripted(turns),
        &scenario("finish", &[SCRIPTED], 10, 30),
        &mut registry,
        &mut sb,
        &opts,
    )
    .await;
    let lines = lines.lock().unwrap().clone();
    Run {
        t,
        lines,
        worked: worked.load(Ordering::SeqCst),
    }
}

fn finish_notes(t: &EpisodeTranscript) -> Vec<(u32, String)> {
    t.turns
        .iter()
        .flat_map(|turn| {
            turn.notes
                .iter()
                .filter(|n| n.kind == NoteKind::FinishRequired)
                .map(move |n| (turn.index, n.text.clone()))
        })
        .collect()
}

/// US3 AS-1: `finish` ends the run, and the record keeps the outcome and summary.
#[tokio::test]
async fn finish_completed_ends_run() {
    let r = run(
        vec![
            turn(vec![work("c0")]),
            turn(vec![finish("c1", "completed", "did the thing")]),
            text_turn("never reached"),
        ],
        true,
    )
    .await;
    assert_eq!(
        r.t.status,
        EpisodeStatus::Finished {
            outcome: FinishOutcome::Completed,
            summary: "did the thing".into(),
            turn: 1
        }
    );
    assert!(r.t.finish_offered);
    assert_eq!(r.t.turns.len(), 2);
    let done = r
        .lines
        .iter()
        .position(|l| l.starts_with("done: finished (completed) · 2 turns · "))
        .expect("a done line");
    assert_eq!(
        r.lines[done + 1],
        "  summary: did the thing",
        "the summary follows done:"
    );
    assert!(r
        .lines
        .contains(&"  result ok: run finished: completed".to_string()));
    assert_eq!(exit_code(&r.t.status, r.t.finish_offered), 0);
}

/// US3 AS-2: the first text-only turn gets one reminder, and the run goes on.
#[tokio::test]
async fn text_turn_gets_one_reminder() {
    let r = run(
        vec![
            text_turn("I think I'm done."),
            turn(vec![finish("c0", "completed", "done")]),
        ],
        true,
    )
    .await;
    assert_eq!(
        finish_notes(&r.t),
        vec![(1, bee::episode::FINISH_REMINDER.to_string())]
    );
    assert!(bee::episode::FINISH_REMINDER.starts_with(
        "[bee] This run ends only when you call finish. If the task is done, call finish with \
         outcome \"completed\" and a summary; otherwise continue working."
    ));
    assert!(matches!(
        r.t.status,
        EpisodeStatus::Finished { turn: 1, .. }
    ));
}

/// US3 AS-3: a second text-only turn, at any later point, ends the run without finishing.
#[tokio::test]
async fn second_text_turn_ends_without_finish() {
    let r = run(
        vec![
            text_turn("done?"),
            turn(vec![work("c0")]),
            text_turn("done."),
            turn(vec![finish("c1", "completed", "too late")]),
        ],
        true,
    )
    .await;
    assert_eq!(r.t.status, EpisodeStatus::EndedWithoutFinish);
    assert_eq!(finish_notes(&r.t).len(), 1, "one reminder only");
    assert_eq!(r.t.turns.len(), 3);
    assert_eq!(exit_code(&r.t.status, true), EXIT_INCOMPLETE);
}

/// US3 AS-4, FR-034: calls after `finish` in its turn are recorded as not run, and never run.
#[tokio::test]
async fn calls_after_finish_not_run() {
    let r = run(
        vec![turn(vec![
            work("c0"),
            finish("c1", "blocked", "no access"),
            work("c2"),
            work("c3"),
        ])],
        true,
    )
    .await;
    assert_eq!(r.worked, 1, "only the call before finish ran");
    let calls = &r.t.turns[0].calls;
    assert_eq!(calls.len(), 4);
    assert!(!calls[0].not_run && !calls[1].not_run);
    for c in &calls[2..] {
        assert!(c.not_run, "{} ran", c.call.id);
        assert_eq!(c.result.content, "not run: the run had already finished");
    }
    let json = serde_json::to_string(&r.t).unwrap();
    assert_eq!(json.matches(r#""not_run":true"#).count(), 2);
}

/// FR-032: a `finish` the tool refuses is an ordinary error, and the run continues.
#[tokio::test]
async fn invalid_finish_continues() {
    let r = run(
        vec![
            turn(vec![call(
                "c0",
                "finish",
                json!({"outcome": "done", "summary": "x"}),
            )]),
            turn(vec![finish("c1", "abandoned", "gave up")]),
        ],
        true,
    )
    .await;
    let first = &r.t.turns[0].calls[0].result;
    assert!(first.is_error && !first.terminal);
    assert!(
        first.content.starts_with("finish: invalid arguments:"),
        "{}",
        first.content
    );
    assert!(matches!(
        r.t.status,
        EpisodeStatus::Finished {
            outcome: FinishOutcome::Abandoned,
            turn: 1,
            ..
        }
    ));
    assert_eq!(exit_code(&r.t.status, true), EXIT_INCOMPLETE);
}

/// Discards everything.
struct Quiet;

impl ReplOutput for Quiet {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}

/// US3 AS-5, AS-6, FR-037: neither the REPL nor a CTF is offered `finish`.
#[tokio::test]
async fn repl_and_ctf_do_not_offer_finish() {
    // The REPL: not a default tool, and a text-only turn still hands control back.
    assert!(!bee::tools::DEFAULT_TOOLS.contains(&"finish"));
    let mut registry = ToolRegistry::new();
    let mut sb = Sandbox::host(Vec::new());
    let mut convo = Conversation::new("test", "");
    let steering = Arc::new(Mutex::new(VecDeque::new()));
    let r = run_exchange(
        "hi",
        &MockModel::scripted(vec![text_turn("hello")]),
        &mut convo,
        &mut registry,
        &mut sb,
        &ReplConfig::default(),
        &Quiet,
        &steering,
        None,
    )
    .await;
    assert_eq!(r.outcome, ExchangeOutcome::Responded);

    // A CTF: never offered, and listing it is refused.
    let mut ctf = scenario("ctf", &["submit_flag"], 5, 30);
    ctf.mode = ScoringMode::Ctf;
    ctf.finish = true;
    assert!(!offers_finish(&ctf));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctf.toml");
    std::fs::write(
        &path,
        r#"[scenario]
id = "ctf"
policy_path = "/dev/null"
system_prompt = "p"
task = "t"
turn_limit = 5
timeout_secs = 30
mode = "ctf"
tools = ["submit_flag", "finish"]
[scenario.workdir.flag]
path = "flag.txt"
value = "FLAG{x}"
"#,
    )
    .unwrap();
    let err = bee::scenario::Scenario::from_path(&path)
        .unwrap_err()
        .to_string();
    assert!(err.contains("finish is not available in ctf mode"), "{err}");
}

/// FR-031, FR-038: `finish = false` keeps the pre-025 endings and exit codes.
#[tokio::test]
async fn scenario_opt_out_keeps_old_endings() {
    let mut s = scenario("opt-out", &[SCRIPTED], 5, 30);
    s.finish = true;
    assert!(
        offers_finish(&s),
        "a standard run is offered finish by default"
    );
    s.finish = false;
    assert!(!offers_finish(&s));
    // TOML default: on.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.toml");
    std::fs::write(
        &path,
        "[scenario]\nid = \"s\"\npolicy_path = \"/dev/null\"\nsystem_prompt = \"p\"\ntask = \"t\"\n\
         turn_limit = 5\ntimeout_secs = 30\n",
    )
    .unwrap();
    assert!(bee::scenario::Scenario::from_path(&path).unwrap().finish);

    let r = run(vec![turn(vec![work("c0")]), text_turn("done")], false).await;
    assert_eq!(r.t.status, EpisodeStatus::Completed);
    assert!(!r.t.finish_offered);
    assert!(finish_notes(&r.t).is_empty());
    let r = run(vec![text_turn("hi")], false).await;
    assert_eq!(r.t.status, EpisodeStatus::NoToolCalls);
    assert_eq!(exit_code(&EpisodeStatus::Timeout, false), 0);
}

/// contracts/finish.md "Exit status".
#[test]
fn exit_codes() {
    let finished = |outcome| EpisodeStatus::Finished {
        outcome,
        summary: "s".into(),
        turn: 0,
    };
    let stuck = EpisodeStatus::Stuck {
        tool: "t".into(),
        arguments: json!({}),
        repeats: 8,
    };
    let ctx = EpisodeStatus::ContextExhausted { detail: "d".into() };
    for (status, offered, code) in [
        (finished(FinishOutcome::Completed), true, 0),
        (finished(FinishOutcome::Blocked), true, 3),
        (finished(FinishOutcome::Abandoned), true, 3),
        (EpisodeStatus::EndedWithoutFinish, true, 3),
        (stuck.clone(), true, 3),
        (stuck, false, 3),
        (ctx.clone(), true, 3),
        (ctx, false, 3),
        (EpisodeStatus::Timeout, true, 3),
        (EpisodeStatus::Timeout, false, 0),
        (EpisodeStatus::Completed, false, 0),
        (EpisodeStatus::NoToolCalls, false, 0),
        (EpisodeStatus::Captured { turn: 0 }, false, 0),
        (EpisodeStatus::NotCaptured, false, 0),
        (EpisodeStatus::ApiError { detail: "d".into() }, true, 69),
        (EpisodeStatus::ApiError { detail: "d".into() }, false, 69),
        (EpisodeStatus::InfraError { detail: "d".into() }, true, 70),
        (EpisodeStatus::InfraError { detail: "d".into() }, false, 70),
    ] {
        assert_eq!(
            exit_code(&status, offered),
            code,
            "{status:?} offered={offered}"
        );
    }
}

/// Every status, once. The `match` has no `_` arm, so a new variant does not compile until it is
/// listed here — and so reaches the label, batch and grid assertions below (SC-008).
fn every_status() -> Vec<EpisodeStatus> {
    let all = vec![
        EpisodeStatus::Completed,
        EpisodeStatus::Timeout,
        EpisodeStatus::NoToolCalls,
        EpisodeStatus::ApiError { detail: "d".into() },
        EpisodeStatus::InfraError { detail: "d".into() },
        EpisodeStatus::Captured { turn: 0 },
        EpisodeStatus::NotCaptured,
        EpisodeStatus::ContextExhausted { detail: "d".into() },
        EpisodeStatus::Stuck {
            tool: "t".into(),
            arguments: json!({}),
            repeats: 8,
        },
        EpisodeStatus::Finished {
            outcome: FinishOutcome::Completed,
            summary: "s".into(),
            turn: 0,
        },
        EpisodeStatus::Finished {
            outcome: FinishOutcome::Blocked,
            summary: "s".into(),
            turn: 0,
        },
        EpisodeStatus::EndedWithoutFinish,
    ];
    for s in &all {
        match s {
            EpisodeStatus::Completed
            | EpisodeStatus::Timeout
            | EpisodeStatus::NoToolCalls
            | EpisodeStatus::ApiError { .. }
            | EpisodeStatus::InfraError { .. }
            | EpisodeStatus::Captured { .. }
            | EpisodeStatus::NotCaptured
            | EpisodeStatus::ContextExhausted { .. }
            | EpisodeStatus::Stuck { .. }
            | EpisodeStatus::Finished { .. }
            | EpisodeStatus::EndedWithoutFinish => {}
        }
    }
    all
}

/// SC-008: every status has a label, a batch-summary dot and a grid status; data-model.md's mapping.
#[test]
fn every_status_maps_in_batch_and_grid() {
    for s in every_status() {
        assert!(!status_label(&s).is_empty(), "{s:?}");
        let mut t: EpisodeTranscript =
            serde_json::from_str(include_str!("fixtures/transcript-pre025.json")).unwrap();
        t.status = s.clone();
        assert!(!bee::batch::status_grid_summary(&[t]).is_empty(), "{s:?}");
        let expected = match &s {
            EpisodeStatus::Completed
            | EpisodeStatus::Captured { .. }
            | EpisodeStatus::Finished {
                outcome: FinishOutcome::Completed,
                ..
            } => Status::Pass,
            EpisodeStatus::NoToolCalls => Status::Skip,
            _ => Status::Fail,
        };
        assert_eq!(Status::from_episode(&s), expected, "{s:?}");
    }
    assert_eq!(
        status_label(&EpisodeStatus::Finished {
            outcome: FinishOutcome::Blocked,
            summary: "s".into(),
            turn: 0
        }),
        "finished (blocked)"
    );
    assert_eq!(
        status_label(&EpisodeStatus::EndedWithoutFinish),
        "ended without finish"
    );
}
