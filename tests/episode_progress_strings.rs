//! The episode loop's progress lines, byte for byte (024-session-core PR 1, contracts/operator.md).
//!
//! `bee run` prints these to stderr, and the Autonomous operator's `ProgressOutput` must keep
//! producing them unchanged once the loop's per-call code moves into `run_call`. FR-022 is the only
//! permitted change (`DENIED` stops being set by proxy-scope events alone); the consent line is
//! additive.
//!
//! Covers every line `run_loop` emits: header, harness note, turn, text, call, escalate (proactive,
//! reactive, proxy), proxy event, result ok/ERR/DENIED, audit, done. The setup lines (`skill
//! warning`, `skill grant`, the `[policy.http]` advisory, the teardown `WARNING`) come from
//! `run_episode_with`, not the loop, and are pinned when setup moves into the Session builder.
//!
//! Gated on `test-support`: a `DENIED` result needs a kernel denial, and on host only the scripted
//! audit source can produce one.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::episode::{run_loop, LoopOptions, ProgressSink};
use bee::grants::escalate::{DenialEscalationHook, LoopEscalation};
use bee::grants::{GrantDelta, Ttl};
use bee::hooks::{Flow, LoopHook, StepEvent, StepEventKind};
use bee::operator::{Operator, OperatorKind, ProgressOutput};
use bee::provider::mock_model::MockModel;
use bee::provider::Turn;
use bee::sandbox::{Sandbox, ScriptedAudit};
use bee::tools::{ToolRegistry, ToolResult};
use bee_core::{Access, Policy};
use fixtures::*;
use scripted::*;

/// Proposes write access to `/tmp/y` before the call with id `on`: a stand-in for a skill's
/// `requires`, so the proactive line is exercised without a skills root.
struct ProactiveOn {
    on: &'static str,
}

#[async_trait::async_trait]
impl LoopHook for ProactiveOn {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::BeforeToolCall
    }

    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        match ev {
            StepEvent::BeforeToolCall(call) if call.id == self.on => {
                let mut d = GrantDelta::default();
                d.filesystem.insert("/tmp/y".into(), Access::Write);
                Flow::Escalate(d)
            }
            _ => Flow::Continue,
        }
    }
}

/// Run `turns` (then a closing text turn) and return the progress lines, with the `done` line's
/// millisecond count replaced by `N` — the only part that is not deterministic.
async fn progress(
    turns: Vec<Turn>,
    attempts: Vec<Attempt>,
    hooks: Vec<Box<dyn LoopHook>>,
    ceiling: Policy,
    setup: impl FnOnce(&mut Sandbox, &FakeCallHooks),
) -> Vec<String> {
    progress_with(
        turns,
        attempts,
        hooks,
        ceiling,
        setup,
        false,
        Default::default(),
    )
    .await
}

/// Stuck detection that never fires within these short scripts, for the pins that predate it (025):
/// their fixture repeats `scripted {}`, which is a streak only by accident.
fn no_stuck() -> bee::stuck::StuckConfig {
    bee::stuck::StuckConfig {
        denied_remind_after: Some(100),
        remind_after: Some(100),
        stop_after: Some(101),
        stop: Some(false),
    }
}

/// [`progress`], optionally with the Autonomous operator reporting its decisions on the same sink,
/// as `bee run` wires it.
async fn progress_with(
    turns: Vec<Turn>,
    attempts: Vec<Attempt>,
    hooks: Vec<Box<dyn LoopHook>>,
    ceiling: Policy,
    setup: impl FnOnce(&mut Sandbox, &FakeCallHooks),
    consent_lines: bool,
    stuck: bee::stuck::StuckConfig,
) -> Vec<String> {
    let audit = Arc::new(ScriptedAudit::default());
    let mut sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let call_hooks = Arc::new(FakeCallHooks::default());
    setup(&mut sb, &call_hooks);
    sb.set_call_hooks(call_hooks);
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(ScriptedTool::new(audit, attempts)));

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let progress: Arc<ProgressSink> = Arc::new(Box::new(move |l: &str| {
        sink.lock().unwrap().push(l.to_string())
    }));
    let operator = if consent_lines {
        Operator::autonomous(Arc::new(ProgressOutput(progress.clone())))
    } else {
        Operator::with_consent(OperatorKind::Autonomous, RecordingConsent::new(true))
            .with_timeout(Duration::from_secs(5))
    };
    let opts = LoopOptions {
        progress: Some(Box::new(move |l: &str| progress(l))),
        escalation: Some(LoopEscalation {
            base: policy(&[]),
            ceiling,
            hooks,
            operator,
            default_ttl: Ttl::Forever,
        }),
        stuck,
        ..LoopOptions::default()
    };
    let mut turns = turns;
    turns.push(text_turn("all done"));
    run_loop(
        &MockModel::scripted(turns),
        &scenario("progress", &[SCRIPTED, "bash"], 10, 30),
        &mut registry,
        &mut sb,
        &opts,
    )
    .await;

    let mut out = lines.lock().unwrap().clone();
    let last = out.last_mut().expect("a done line");
    let (head, ms) = last.rsplit_once(" · ").expect("done line shape");
    assert!(
        ms.ends_with("ms") && ms[..ms.len() - 2].chars().all(|c| c.is_ascii_digit()),
        "done line ends in a millisecond count: {last}"
    );
    *last = format!("{head} · Nms");
    out
}

/// Every line the loop emits, one scenario: a note, text, ok, ERR with an exit code, a reactive
/// refusal beyond the ceiling, a reactive grant, a proactive grant and a proxy refusal.
async fn every_line(consent_lines: bool) -> Vec<String> {
    let mut err_with_exit = ToolResult::error("boom\nsecond line");
    err_with_exit.exit_code = Some(2);
    progress_with(
        vec![
            tool_turn(
                Some("\n  Looking around.\nnot this line"),
                &[("c1", SCRIPTED)],
            ),
            tool_turn(None, &[("c2", SCRIPTED)]),
            tool_turn(None, &[("c3", SCRIPTED)]),
            tool_turn(None, &[("c4", SCRIPTED)]),
            tool_turn(None, &[("c5", SCRIPTED)]),
        ],
        vec![
            Attempt::ok("fine\nmore"),
            Attempt {
                result: err_with_exit,
                ..Attempt::ok("")
            },
            Attempt::error("EACCES").with_audit(vec![ev(
                "file_open",
                "/etc/shadow",
                "denied",
                None,
            )]),
            Attempt::error("EACCES").with_audit(vec![ev("file_open", "/tmp/x", "denied", None)]),
            Attempt::ok("written"),
            Attempt::ok("fetched"),
        ],
        vec![
            Box::new(DenialEscalationHook { enabled: true }),
            Box::new(ProactiveOn { on: "c5" }),
        ],
        policy(&[("/tmp", Access::Write)]),
        |_, hooks| {
            hooks
                .notes
                .lock()
                .unwrap()
                .push("3 new passive leads".into());
            hooks.push("c5", vec![refusal("c5", "10.0.0.9", 80)]);
        },
        consent_lines,
        no_stuck(),
    )
    .await
}

fn every_line_expected() -> Vec<&'static str> {
    vec![
        "episode 'progress' · mock/scripted · tools: scripted,bash",
        "  3 new passive leads",
        "turn 0",
        // `preview` skips blank lines and trims only the end, so the indent stays.
        "  text:   Looking around.",
        "  call scripted {}",
        "  result ok: fine",
        "turn 1",
        "  call scripted {}",
        "  result ERR (exit 2): boom",
        "turn 2",
        "  call scripted {}",
        "  escalate(reactive): Refused(\"exceeds capability ceiling: attenuation violation on filesystem:/etc/shadow: no parent rule covers this path\")",
        "  result DENIED: EACCES",
        "  audit: file_open denied /etc/shadow",
        "turn 3",
        "  call scripted {}",
        "  escalate(reactive): Granted(\"g0\")",
        "  result ok: written",
        "turn 4",
        "  call scripted {}",
        "  escalate(proactive): Granted(\"g1\")",
        "  refused by proxy: 10.0.0.9:80 (refused_out_of_scope)",
        "  result ok: fetched",
        "turn 5",
        "  text: all done",
        "done: completed · 6 turns · Nms",
    ]
}

#[tokio::test]
async fn every_loop_line_is_byte_identical() {
    assert_eq!(every_line(false).await, every_line_expected());
}

// T052: under the Autonomous operator each decision adds one `  consent: …` line, just before the
// escalation it decided; every other line is unchanged.
#[tokio::test]
async fn the_autonomous_operator_adds_one_consent_line_per_decision() {
    let lines = every_line(true).await;
    let consent: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("  consent: "))
        .collect();
    assert_eq!(
        consent,
        [
            "  consent: refused (beyond ceiling) — kernel denial file_open /etc/shadow",
            "  consent: granted (granted) — kernel denial file_open /tmp/x",
            // A proactive grant is named for the skill the call loads; this stand-in hook fires on a
            // call with no `name`, which the origin reads as `skill`.
            "  consent: granted (granted) — skill 'skill'",
        ]
    );
    let rest: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| !l.starts_with("  consent: "))
        .collect();
    assert_eq!(rest, every_line_expected());
    let at = |needle: &str| lines.iter().position(|l| l == needle).unwrap();
    assert_eq!(
        at("  consent: granted (granted) — kernel denial file_open /tmp/x") + 1,
        at("  escalate(reactive): Granted(\"g0\")")
    );
}

/// The proxy-refusal escalation line exists only with `intercept`.
#[cfg(feature = "intercept")]
#[tokio::test]
async fn the_proxy_escalation_line() {
    let lines = progress(
        vec![tool_turn(None, &[("c1", SCRIPTED)])],
        vec![Attempt::error("refused"), Attempt::ok("200 OK")],
        vec![Box::new(bee::grants::escalate::ProxyRefusalHook {
            enabled: true,
        })],
        http_policy(&["10.0.0.9:80"]),
        |sb, hooks| {
            hooks.push("c1", vec![refusal("c1", "10.0.0.9", 80)]);
            sb.set_http_scope_hook(Arc::new(FakeHttpScope::default()));
        },
    )
    .await;
    let expected = [
        "episode 'progress' · mock/scripted · tools: scripted,bash",
        "turn 0",
        "  call scripted {}",
        "  escalate(proxy): Granted(\"g0\")",
        "  result ok: 200 OK",
        "turn 1",
        "  text: all done",
        "done: completed · 2 turns · Nms",
    ];
    assert_eq!(lines, expected);
}

/// One turn's lines for a `scripted` call with `{}` arguments and a one-line result.
fn call_lines(index: u32, result: &str) -> Vec<String> {
    vec![
        format!("turn {index}"),
        "  call scripted {}".into(),
        format!("  result {result}"),
    ]
}

const REMINDER: &str = "  [bee] You have called scripted with the same arguments 5 times in a row";

/// 025 US2: the reminder line, emitted where the note joins the conversation — before the next
/// model turn.
#[tokio::test]
async fn the_reminder_line() {
    let lines = progress(
        (0..5)
            .map(|i| tool_turn(None, &[(&format!("c{i}"), SCRIPTED)]))
            .collect(),
        Vec::new(),
        Vec::new(),
        policy(&[]),
        |_, _| {},
    )
    .await;
    let mut expected =
        vec!["episode 'progress' · mock/scripted · tools: scripted,bash".to_string()];
    for i in 0..5 {
        expected.extend(call_lines(i, "ok: unscripted"));
    }
    expected.push(format!(
        "{REMINDER}. Repeating it is unlikely to give a different result. Try a different \
         approach: check your assumptions, inspect the error, or use another tool."
    ));
    expected.extend([
        "turn 5".to_string(),
        "  text: all done".into(),
        "done: completed · 6 turns · Nms".into(),
    ]);
    assert_eq!(lines, expected);
}

/// 025 US2: the stuck line, and the status it ends the run with.
#[tokio::test]
async fn the_stuck_line() {
    let lines = progress(
        (0..8)
            .map(|i| tool_turn(None, &[(&format!("c{i}"), SCRIPTED)]))
            .collect(),
        (0..8).map(|_| Attempt::error("nope")).collect(),
        Vec::new(),
        policy(&[]),
        |_, _| {},
    )
    .await;
    let mut expected =
        vec!["episode 'progress' · mock/scripted · tools: scripted,bash".to_string()];
    for i in 0..8 {
        if i == 5 {
            expected.push(format!(
                "{REMINDER}, and it failed each time. Repeating it is unlikely to give a different \
                 result. Try a different approach: check your assumptions, inspect the error, or use \
                 another tool."
            ));
        }
        expected.extend(call_lines(i, "ERR: nope"));
    }
    expected.extend([
        "  stuck: scripted repeated 8 times with the same failing result — ending run".to_string(),
        "done: stuck · 8 turns · Nms".into(),
    ]);
    assert_eq!(lines, expected);
}

/// 025 US1: the context lines (contracts/context.md "Progress and info lines"). The loop prints each
/// as `  {line}`; context_compaction checks that it does.
#[test]
fn the_context_lines() {
    use bee::transcript::{CompactionEvent, CompactionKind};
    let event = |kind, items, turns, error: Option<&str>| CompactionEvent {
        turn: 9,
        kind,
        items,
        turns,
        before_tokens: 6_012,
        after_tokens: 3_480,
        usage: None,
        error: error.map(str::to_string),
    };
    let d = |e: &CompactionEvent| bee::context::describe(e, 7_004);
    assert_eq!(
        d(&event(CompactionKind::Elided, 4, None, None)),
        "context: elided 4 results (6.0k → 3.5k tokens of 7.0k)"
    );
    assert_eq!(
        d(&event(CompactionKind::Summarized, 11, Some((0, 10)), None)),
        "context: summarized turns 0–10 (6.0k → 3.5k tokens of 7.0k)"
    );
    assert_eq!(
        d(&event(
            CompactionKind::Removed,
            11,
            Some((0, 10)),
            Some("provider rejected request: down")
        )),
        "context: removed 11 turns after summary failure: provider rejected request: down"
    );
}
