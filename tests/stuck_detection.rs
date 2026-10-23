//! Stuck detection through both loops (025 US2, quickstart Phase C, contracts/stuck.md).
//!
//! A model that repeats one call gets one reminder; one that keeps repeating a failing call is
//! stopped. Inputs are scripted (024 research R1): the `scripted` tool's results and kernel audit
//! through `Sandbox::host_scripted`, proxy refusals through `FakeCallHooks`.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::episode::{run_loop, LoopOptions};
use bee::grants::escalate::{DenialEscalationHook, LoopEscalation};
use bee::grants::Ttl;
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Message, StopReason, ToolCall, Turn};
use bee::repl::{run_exchange, ExchangeOutcome, ExchangeResult, ReplConfig, ReplOutput};
use bee::sandbox::{Sandbox, ScriptedAudit};
use bee::tools::{ToolRegistry, ToolResult};
use bee::transcript::{EpisodeStatus, EpisodeTranscript, NoteKind, TranscriptTurn};
use bee_core::{Access, AuditEvent};
use fixtures::*;
use scripted::*;
use serde_json::{json, Value};

// ── Inputs ──────────────────────────────────────────────────────────────────────────────────────

/// A model turn calling `scripted` once with `args`, as call `id`.
fn turn(id: &str, args: Value) -> Turn {
    turns_of(&[(id, args)])
}

/// A model turn calling `scripted` once per `(id, args)`.
fn turns_of(calls: &[(&str, Value)]) -> Turn {
    Turn {
        text: None,
        tool_calls: calls
            .iter()
            .map(|(id, args)| ToolCall {
                id: id.to_string(),
                name: SCRIPTED.into(),
                arguments: args.clone(),
            })
            .collect(),
        stop: StopReason::ToolUse,
        usage: None,
    }
}

/// `n` turns, each calling `scripted` once with `args`.
fn repeat(n: usize, args: Value) -> Vec<Turn> {
    (0..n)
        .map(|i| turn(&format!("c{i}"), args.clone()))
        .collect()
}

fn denial() -> AuditEvent {
    ev("file_open", "/etc/shadow", "denied", None)
}

fn denied_attempt() -> Attempt {
    Attempt::error("permission denied").with_audit(vec![denial()])
}

/// A host sandbox whose tool-scope audit the `scripted` tool feeds.
fn setup(attempts: Vec<Attempt>) -> (Sandbox, ToolRegistry, Arc<FakeCallHooks>) {
    let audit = Arc::new(ScriptedAudit::default());
    let mut sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let hooks = Arc::new(FakeCallHooks::default());
    sb.set_call_hooks(hooks.clone());
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(ScriptedTool::new(audit, attempts)));
    (sb, registry, hooks)
}

// ── The episode loop ────────────────────────────────────────────────────────────────────────────

struct Episode {
    t: EpisodeTranscript,
    lines: Vec<String>,
}

async fn episode_with(
    turns: Vec<Turn>,
    attempts: Vec<Attempt>,
    opts: LoopOptions,
    prep: impl FnOnce(&FakeCallHooks),
) -> Episode {
    let (mut sb, mut registry, hooks) = setup(attempts);
    prep(&hooks);
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let opts = LoopOptions {
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        ..opts
    };
    let t = run_loop(
        &MockModel::scripted(turns),
        &scenario("stuck", &[SCRIPTED], 30, 60),
        &mut registry,
        &mut sb,
        &opts,
    )
    .await;
    let lines = lines.lock().unwrap().clone();
    Episode { t, lines }
}

async fn episode(turns: Vec<Turn>, attempts: Vec<Attempt>) -> Episode {
    episode_with(turns, attempts, LoopOptions::default(), |_| {}).await
}

/// Every reminder as `(turn index, kind, text)`.
fn notes(turns: &[TranscriptTurn]) -> Vec<(u32, NoteKind, String)> {
    turns
        .iter()
        .flat_map(|t| {
            t.notes
                .iter()
                .map(move |n| (t.index, n.kind, n.text.clone()))
        })
        .filter(|(_, k, _)| matches!(k, NoteKind::StuckGeneral | NoteKind::StuckPolicy))
        .collect()
}

// ── US2 ─────────────────────────────────────────────────────────────────────────────────────────

/// US2 AS-1: the fifth identical call earns one reminder, delivered before the next model turn.
#[tokio::test]
async fn reminder_once_at_five() {
    let e = episode(repeat(9, json!({"q": 1})), Vec::new()).await;
    let n = notes(&e.t.turns);
    assert_eq!(n.len(), 1, "{n:?}");
    let (turn, kind, text) = &n[0];
    assert_eq!((*turn, *kind), (5, NoteKind::StuckGeneral));
    assert!(
        text.starts_with(
            "[bee] You have called scripted with the same arguments 5 times in a row. Repeating"
        ),
        "{text}"
    );
    assert_eq!(
        e.t.status,
        EpisodeStatus::Completed,
        "a succeeding repeat is never stopped"
    );
}

/// US2 AS-2, SC-006: the eighth identical failing call ends the run, well before the turn limit.
#[tokio::test]
async fn stops_at_eight_failing() {
    let attempts = (0..20).map(|_| Attempt::error("no such file")).collect();
    let e = episode(repeat(20, json!({"path": "/x"})), attempts).await;
    assert_eq!(
        e.t.status,
        EpisodeStatus::Stuck {
            tool: SCRIPTED.into(),
            arguments: json!({"path": "/x"}),
            repeats: 8
        }
    );
    assert_eq!(
        e.t.turns.len(),
        8,
        "the eighth call's turn is recorded, and nothing after it"
    );
    assert!(e.lines.iter().any(
        |l| l == "  stuck: scripted repeated 8 times with the same failing result — ending run"
    ));
    assert_eq!(
        bee::episode::exit_code(&e.t.status, false),
        bee::episode::EXIT_INCOMPLETE
    );
    let n = notes(&e.t.turns);
    assert_eq!(n.len(), 1);
    assert!(
        n[0].2
            .contains("5 times in a row, and it failed each time."),
        "{}",
        n[0].2
    );
}

/// US2 AS-3: a different call starts a new streak.
#[tokio::test]
async fn different_call_resets() {
    let mut turns = repeat(4, json!({"q": 1}));
    turns.push(turn("other", json!({"q": 2})));
    turns.extend(repeat(4, json!({"q": 1})));
    let attempts = (0..9).map(|_| Attempt::error("nope")).collect();
    let e = episode(turns, attempts).await;
    assert_eq!(notes(&e.t.turns), vec![]);
    assert_eq!(e.t.status, EpisodeStatus::Completed);
}

/// FR-023: argument key order and whitespace do not make two calls differ.
#[tokio::test]
async fn key_order_is_irrelevant() {
    let a = json!({"a": 1, "b": [1, 2]});
    let b: Value = serde_json::from_str(r#"{ "b" : [1,2], "a":1 }"#).unwrap();
    let turns = (0..5)
        .map(|i| {
            turn(
                &format!("c{i}"),
                if i % 2 == 0 { a.clone() } else { b.clone() },
            )
        })
        .collect();
    let e = episode(turns, Vec::new()).await;
    let n = notes(&e.t.turns);
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0].1, NoteKind::StuckGeneral);
}

/// Edge case: only consecutive failures count toward the stop.
#[tokio::test]
async fn alternating_success_does_not_stop() {
    let attempts = (0..24)
        .map(|i| {
            if i % 2 == 0 {
                Attempt::error("flaky")
            } else {
                Attempt::ok("fine")
            }
        })
        .collect();
    let e = episode(repeat(24, json!({})), attempts).await;
    assert!(
        !matches!(e.t.status, EpisodeStatus::Stuck { .. }),
        "{:?}",
        e.t.status
    );
}

/// US2 AS-4, SC-007: a call the kernel keeps denying gets the policy reminder at the second repeat.
#[tokio::test]
async fn denied_repeat_gets_policy_reminder_at_two() {
    let attempts = (0..3).map(|_| denied_attempt()).collect();
    let e = episode(repeat(3, json!({"path": "/etc/shadow"})), attempts).await;
    let n = notes(&e.t.turns);
    assert_eq!(n.len(), 1, "{n:?}");
    let (turn, kind, text) = &n[0];
    assert_eq!((*turn, *kind), (2, NoteKind::StuckPolicy));
    assert!(
        text.starts_with(
            "[bee] scripted with these arguments was denied 2 times by the session's security \
             policy (file_open on /etc/shadow). This is a policy decision"
        ),
        "{text}"
    );
}

/// FR-026, the proxy layer: a request refused as out of scope is a denial too.
#[cfg(feature = "intercept")]
#[tokio::test]
async fn proxy_refused_repeat_gets_policy_reminder() {
    let attempts = (0..3).map(|_| Attempt::error("403 out of scope")).collect();
    let e = episode_with(
        repeat(3, json!({"url": "https://evil.test/"})),
        attempts,
        LoopOptions::default(),
        |hooks| {
            for i in 0..3 {
                let id = format!("c{i}");
                hooks.push(&id, vec![refusal(&id, "evil.test", 443)]);
            }
        },
    )
    .await;
    let n = notes(&e.t.turns);
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0].1, NoteKind::StuckPolicy);
    assert!(
        n[0].2
            .contains("(a request to evil.test:443 outside the target scope)"),
        "{}",
        n[0].2
    );
}

/// Edge case: a denial that was granted and retried is not a policy denial, even when the same call
/// is denied again on every turn (the one-turn lease keeps lapsing).
#[tokio::test]
async fn granted_retry_is_not_a_denied_repeat() {
    let base = policy(&[]);
    let ceiling = policy(&[("/tmp", Access::Write)]);
    let esc = LoopEscalation {
        base,
        ceiling,
        hooks: vec![Box::new(DenialEscalationHook { enabled: true })],
        operator: bee::operator::Operator::with_consent(
            bee::operator::OperatorKind::Autonomous,
            RecordingConsent::new(true),
        )
        .with_timeout(Duration::from_secs(5)),
        default_ttl: Ttl::Turns(1),
    };
    let attempts = (0..3)
        .flat_map(|_| {
            [
                Attempt::error("EACCES").with_audit(vec![ev(
                    "file_open",
                    "/tmp/x",
                    "denied",
                    None,
                )]),
                Attempt::ok("written"),
            ]
        })
        .collect();
    let e = episode_with(
        repeat(3, json!({"path": "/tmp/x"})),
        attempts,
        LoopOptions {
            escalation: Some(esc),
            ..LoopOptions::default()
        },
        |_| {},
    )
    .await;
    let retried =
        e.t.turns
            .iter()
            .flat_map(|t| &t.calls)
            .filter(|c| c.retried)
            .count();
    assert_eq!(retried, 3, "each call was denied, granted and retried");
    assert_eq!(notes(&e.t.turns), vec![], "no policy reminder");
}

// ── The REPL ────────────────────────────────────────────────────────────────────────────────────

/// Keeps the error lines; the assertions read the exchange result.
#[derive(Default)]
struct Errors(Mutex<Vec<String>>);

impl ReplOutput for Errors {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[AuditEvent]) {}
    fn error(&self, m: &str) {
        self.0.lock().unwrap().push(m.to_string());
    }
    fn info(&self, _: &str) {}
}

async fn exchange(
    model: &MockModel,
    convo: &mut Conversation,
    registry: &mut ToolRegistry,
    sb: &mut Sandbox,
    config: &ReplConfig,
    out: &Errors,
) -> ExchangeResult {
    let steering = Arc::new(Mutex::new(VecDeque::new()));
    run_exchange(
        "go", model, convo, registry, sb, config, out, &steering, None,
    )
    .await
}

/// US2 AS-5, FR-029: in the REPL a stop ends the exchange, not the session. A call the stop kept
/// from running still gets a result, so the conversation stays well formed.
#[tokio::test]
async fn repl_stop_ends_exchange_not_session() {
    let mut turns = repeat(7, json!({"q": 1}));
    turns.push(turns_of(&[
        ("c7", json!({"q": 1})),
        ("skipped", json!({"q": 2})),
    ]));
    turns.push(text_turn("never reached in the first exchange"));
    let model = MockModel::scripted(turns);
    let attempts = (0..8).map(|_| Attempt::error("boom")).collect();
    let (mut sb, mut registry, _) = setup(attempts);
    let config = ReplConfig {
        agent_turn_budget: 20,
        ..ReplConfig::default()
    };
    let mut convo = Conversation::new("test", "");
    let out = Errors::default();

    let r = exchange(&model, &mut convo, &mut registry, &mut sb, &config, &out).await;
    assert_eq!(
        r.outcome,
        ExchangeOutcome::Stuck {
            tool: SCRIPTED.into(),
            repeats: 8
        }
    );
    assert_eq!(
        out.0.lock().unwrap().as_slice(),
        ["stopped: scripted was repeated 8 times with the same failing result"]
    );
    let skipped = convo.messages.iter().find_map(|m| match m {
        Message::ToolResult {
            call_id, content, ..
        } if call_id == "skipped" => Some(content.clone()),
        _ => None,
    });
    assert!(
        skipped
            .as_deref()
            .is_some_and(|c| c.starts_with("[bee] not run:")),
        "{skipped:?}"
    );

    // The session goes on: the next exchange runs normally.
    let r = exchange(&model, &mut convo, &mut registry, &mut sb, &config, &out).await;
    assert_eq!(r.outcome, ExchangeOutcome::Responded);
}

/// FR-028: reminders are recorded on the turn they precede, in both loops, and in the transcript.
#[tokio::test]
async fn reminders_are_recorded() {
    // The episode: the note is on the turn, and it serializes by kind.
    let e = episode(repeat(6, json!({})), Vec::new()).await;
    let json = serde_json::to_string(&e.t).unwrap();
    assert!(json.contains(r#""kind":"stuck_general""#), "{json}");

    // The REPL: a streak spans exchanges, and the note is recorded on the turn after the fifth call.
    let model = MockModel::scripted({
        let mut t = repeat(3, json!({}));
        t.push(text_turn("pause"));
        t.extend(repeat(3, json!({})));
        t
    });
    let (mut sb, mut registry, _) = setup(Vec::new());
    let config = ReplConfig::default();
    let mut convo = Conversation::new("test", "");
    let out = Errors::default();
    let first = exchange(&model, &mut convo, &mut registry, &mut sb, &config, &out).await;
    assert_eq!(notes(&first.turns), vec![]);
    let second = exchange(&model, &mut convo, &mut registry, &mut sb, &config, &out).await;
    let n = notes(&second.turns);
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0].1, NoteKind::StuckGeneral);
    assert_eq!(
        n[0].0, 2,
        "recorded on the turn after the streak's fifth call"
    );
}
