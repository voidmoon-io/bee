//! Compaction through the episode loop and the REPL (025 US1, quickstart Phase E,
//! contracts/context.md).
//!
//! A small window (8192 tokens, 1024 for the reply) and tools that return a known number of bytes
//! cross the thresholds deterministically. The test model scripts the agent by call count, answers
//! the summary call (recognised by its system prompt, and offered no tools), and checks the
//! conversation invariants on every agent request.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bee::context::{ContextConfig, ContextInputs};
use bee::episode::{run_loop, LoopOptions};
use bee::provider::{
    Conversation, Message, Model, ModelError, StopReason, ToolCall, ToolSchema, Turn, Usage,
};
use bee::repl::{run_exchange, ReplConfig, ReplOutput};
use bee::sandbox::{Sandbox, ScriptedAudit};
use bee::tools::{ToolRegistry, ToolResult};
use bee::transcript::{CompactionKind, EpisodeStatus, EpisodeTranscript};
use bee_core::AuditEvent;
use fixtures::*;
use scripted::*;
use serde_json::json;

const SUMMARY_PROMPT: &str = "You maintain a running summary";

// ── The model ───────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Summary {
    Ok,
    Fail,
    /// Answer, and bill each summary call this much.
    Billed(Usage),
}

/// One request the model saw.
#[derive(Clone)]
struct Seen {
    messages: Vec<Message>,
    tools: Vec<String>,
    summary: bool,
}

struct TestModel {
    /// Tool-calling agent turns before the closing text turn.
    calls: usize,
    summary: Summary,
    agent_calls: AtomicUsize,
    summary_calls: AtomicUsize,
    seen: Mutex<Vec<Seen>>,
    /// The content each call's result must have when it is verbatim.
    content: fn(&str) -> String,
}

impl TestModel {
    fn new(calls: usize, summary: Summary, content: fn(&str) -> String) -> TestModel {
        TestModel {
            calls,
            summary,
            agent_calls: AtomicUsize::new(0),
            summary_calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            content,
        }
    }

    fn summaries(&self) -> usize {
        self.summary_calls.load(Ordering::SeqCst)
    }

    fn agent_requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| !s.summary)
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl Model for TestModel {
    fn id(&self) -> &str {
        "mock/compaction"
    }

    async fn complete(
        &self,
        convo: &Conversation,
        tools: &[ToolSchema],
    ) -> Result<Turn, ModelError> {
        let summary = convo.system.starts_with(SUMMARY_PROMPT);
        self.seen.lock().unwrap().push(Seen {
            messages: convo.messages.clone(),
            tools: tools.iter().map(|t| t.name.clone()).collect(),
            summary,
        });
        if summary {
            let n = self.summary_calls.fetch_add(1, Ordering::SeqCst);
            return match self.summary {
                Summary::Fail => Err(ModelError::Request("summary service down".into())),
                Summary::Ok => Ok(text(&format!("summary #{n}"), None)),
                Summary::Billed(u) => Ok(text(&format!("summary #{n}"), Some(u))),
            };
        }
        assert_invariants(convo, self.content);
        let k = self.agent_calls.fetch_add(1, Ordering::SeqCst);
        if k < self.calls {
            Ok(Turn {
                text: None,
                tool_calls: vec![ToolCall {
                    id: format!("c{k}"),
                    name: SCRIPTED.into(),
                    arguments: json!({ "k": k }),
                }],
                stop: StopReason::ToolUse,
                usage: None,
            })
        } else {
            Ok(text("done", None))
        }
    }
}

fn text(t: &str, usage: Option<Usage>) -> Turn {
    Turn {
        text: Some(t.into()),
        tool_calls: Vec::new(),
        stop: StopReason::EndTurn,
        usage,
    }
}

/// The invariants in contracts/context.md, on one agent request.
fn assert_invariants(convo: &Conversation, content: fn(&str) -> String) {
    let m = &convo.messages;
    // The preamble is the task, untouched.
    assert!(
        matches!(&m[0], Message::User { text } if text == "go"),
        "preamble changed"
    );
    // Every call has exactly one result after it and before the next assistant message.
    let mut i = 0;
    while i < m.len() {
        if let Message::Assistant { tool_calls, .. } = &m[i] {
            let next = m[i + 1..]
                .iter()
                .position(|x| matches!(x, Message::Assistant { .. }))
                .map_or(m.len(), |p| i + 1 + p);
            for c in tool_calls {
                let n = m[i + 1..next]
                    .iter()
                    .filter(
                        |x| matches!(x, Message::ToolResult { call_id, .. } if call_id == &c.id),
                    )
                    .count();
                assert_eq!(n, 1, "call {} has {n} results", c.id);
            }
            i = next;
        } else {
            i += 1;
        }
    }
    // The newest two turns are verbatim.
    let assistants: Vec<usize> = m
        .iter()
        .enumerate()
        .filter(|(_, x)| matches!(x, Message::Assistant { .. }))
        .map(|(i, _)| i)
        .collect();
    let from = assistants.len().checked_sub(2).map_or(0, |k| assistants[k]);
    for x in &m[from..] {
        if let Message::ToolResult {
            call_id,
            content: c,
            ..
        } = x
        {
            assert_eq!(c, &content(call_id), "recent result {call_id} was edited");
        }
    }
    // The head is only ever bee's summary and marker, and elision never touched them.
    for x in m.iter().skip(1).take(2) {
        if let Message::User { text } = x {
            if text.starts_with("[bee: summary of turns") {
                assert!(text.contains("<untrusted-data source=\"bee:summary\" nonce=\""));
            }
        }
    }
}

// ── Running it ──────────────────────────────────────────────────────────────────────────────────

/// `bytes` of output for call `c{k}`, prefixed so each is distinct.
fn content_2k(id: &str) -> String {
    format!("{id}:{}", "x".repeat(2000))
}

fn content_600(id: &str) -> String {
    format!("{id}:{}", "y".repeat(600))
}

fn inputs(window: u32, compaction: bool) -> ContextInputs {
    ContextInputs {
        config: ContextConfig {
            window_tokens: Some(window),
            compaction: Some(compaction),
            ..ContextConfig::default()
        },
        provider_window: None,
        max_tokens: Some(1024),
    }
}

fn tool_for(model: &TestModel) -> (Sandbox, ToolRegistry) {
    tool_with(model, |_| None)
}

/// A sandbox and the `scripted` tool, whose call `c{k}` returns `content("c{k}")`, or what `custom`
/// gives for `k`.
fn tool_with(model: &TestModel, custom: fn(usize) -> Option<Attempt>) -> (Sandbox, ToolRegistry) {
    let audit = Arc::new(ScriptedAudit::default());
    let sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let attempts = (0..model.calls)
        .map(|k| custom(k).unwrap_or_else(|| Attempt::ok(&(model.content)(&format!("c{k}")))))
        .collect();
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(ScriptedTool::new(audit, attempts)));
    (sb, registry)
}

struct Run {
    t: EpisodeTranscript,
    lines: Vec<String>,
}

async fn episode(model: &TestModel, ctx: ContextInputs) -> Run {
    let (sb, registry) = tool_for(model);
    episode_in(model, ctx, sb, registry).await
}

async fn episode_in(
    model: &TestModel,
    ctx: ContextInputs,
    mut sb: Sandbox,
    mut registry: ToolRegistry,
) -> Run {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let opts = LoopOptions {
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        context: ctx,
        // Every call here has its own arguments, so no streak; keep stuck detection out of it anyway.
        stuck: bee::stuck::StuckConfig {
            stop: Some(false),
            ..Default::default()
        },
        ..LoopOptions::default()
    };
    let t = run_loop(
        model,
        &scenario("compaction", &[SCRIPTED], 80, 120),
        &mut registry,
        &mut sb,
        &opts,
    )
    .await;
    let lines = lines.lock().unwrap().clone();
    Run { t, lines }
}

fn kinds(t: &EpisodeTranscript) -> Vec<CompactionKind> {
    t.compactions.iter().map(|e| e.kind).collect()
}

/// FR-016: whatever was compacted, the model was offered only the session's tools.
fn assert_no_recall_tool(model: &TestModel) {
    for s in model.seen.lock().unwrap().iter() {
        if s.summary {
            assert!(s.tools.is_empty(), "the summary call was offered tools");
        } else {
            assert_eq!(s.tools, vec![SCRIPTED.to_string()]);
        }
    }
}

// ── US1 ─────────────────────────────────────────────────────────────────────────────────────────

/// US1 AS-5, SC-009: below `soft`, nothing is touched.
#[tokio::test]
async fn below_soft_is_untouched() {
    let m = TestModel::new(3, Summary::Ok, content_2k);
    let r = episode(&m, inputs(8192, true)).await;
    assert_eq!(r.t.status, EpisodeStatus::Completed);
    assert!(r.t.compactions.is_empty());
    assert_eq!(m.summaries(), 0);
}

/// US1 AS-1, FR-006, SC-003: bulky results are elided, and no summary call is made while that
/// suffices.
#[tokio::test]
async fn elides_before_summarizing() {
    let m = TestModel::new(9, Summary::Ok, content_2k);
    let r = episode(&m, inputs(8192, true)).await;
    assert_eq!(r.t.status, EpisodeStatus::Completed);
    assert!(
        kinds(&r.t).contains(&CompactionKind::Elided),
        "{:?}",
        kinds(&r.t)
    );
    assert!(!kinds(&r.t).contains(&CompactionKind::Summarized));
    assert_eq!(m.summaries(), 0, "SC-003: zero summary calls");
    let last = m.agent_requests().pop().unwrap();
    assert!(last.messages.iter().any(|x| matches!(x,
        Message::ToolResult { content, .. } if content.starts_with("[bee: result elided to save context] scripted({\"k\":0}) → ok, 2003 bytes"))));
    assert_no_recall_tool(&m);
}

/// US1 AS-2: results too small to elide, so the history is folded into a summary, by a call that is
/// offered no tools.
#[tokio::test]
async fn summarizes_above_hard() {
    let m = TestModel::new(40, Summary::Ok, content_600);
    let r = episode(&m, inputs(8192, true)).await;
    assert_eq!(r.t.status, EpisodeStatus::Completed);
    assert!(
        kinds(&r.t).contains(&CompactionKind::Summarized),
        "{:?}",
        kinds(&r.t)
    );
    assert!(
        !kinds(&r.t).contains(&CompactionKind::Elided),
        "nothing was bulky"
    );
    assert!(m.summaries() >= 1);
    assert_no_recall_tool(&m);
}

/// FR-003: the preamble and the recent window are verbatim on every request. The model asserts the
/// invariants on each one; this run crosses both thresholds.
#[tokio::test]
async fn preamble_and_recent_window_verbatim() {
    let m = TestModel::new(40, Summary::Ok, content_600);
    episode(&m, inputs(8192, true)).await;
    let m = TestModel::new(12, Summary::Ok, content_2k);
    episode(&m, inputs(8192, true)).await;
    assert!(m.agent_requests().len() > 10);
}

/// FR-010: a call is never separated from its result, through elision, summary and removal.
#[tokio::test]
async fn calls_and_results_stay_paired() {
    for summary in [Summary::Ok, Summary::Fail] {
        let m = TestModel::new(40, summary, content_600);
        let r = episode(&m, inputs(8192, true)).await;
        assert!(!r.t.compactions.is_empty());
        // `assert_invariants` checked the pairing on every request; check the last explicitly too.
        let last = m.agent_requests().pop().unwrap();
        let calls = last
            .messages
            .iter()
            .filter_map(|x| match x {
                Message::Assistant { tool_calls, .. } => Some(tool_calls.len()),
                _ => None,
            })
            .sum::<usize>();
        let results = last
            .messages
            .iter()
            .filter(|x| matches!(x, Message::ToolResult { .. }))
            .count();
        assert_eq!(calls, results);
    }
}

/// US1 AS-3, SC-004: an elided result's stub still says what was denied.
#[tokio::test]
async fn stub_keeps_denial() {
    let m = TestModel::new(9, Summary::Ok, content_2k);
    let (sb, registry) = tool_with(&m, |k| {
        (k == 0).then(|| {
            Attempt::error(&content_2k("c0")).with_audit(vec![ev(
                "file_open",
                "/etc/shadow",
                "denied",
                None,
            )])
        })
    });
    episode_in(&m, inputs(8192, true), sb, registry).await;
    let last = m.agent_requests().pop().unwrap();
    let stub = last.messages.iter().find_map(|x| match x {
        Message::ToolResult {
            call_id, content, ..
        } if call_id == "c0" => Some(content.clone()),
        _ => None,
    });
    assert_eq!(
        stub.as_deref(),
        Some(
            "[bee: result elided to save context] scripted({\"k\":0}) → denied, 2003 bytes; \
             denied: filesystem:/etc/shadow (open)"
        )
    );
}

/// SC-004, the proxy layer: a refusal survives elision too.
#[cfg(feature = "intercept")]
#[tokio::test]
async fn stub_keeps_proxy_refusal() {
    let m = TestModel::new(9, Summary::Ok, content_2k);
    let (mut sb, registry) = tool_for(&m);
    let hooks = Arc::new(FakeCallHooks::default());
    hooks.push("c0", vec![refusal("c0", "evil.test", 443)]);
    sb.set_call_hooks(hooks);
    episode_in(&m, inputs(8192, true), sb, registry).await;
    let last = m.agent_requests().pop().unwrap();
    assert!(last.messages.iter().any(|x| matches!(x,
        Message::ToolResult { call_id, content, .. }
            if call_id == "c0" && content.ends_with("; denied: proxy refused evil.test:443 (out of scope)"))));
}

/// FR-008: the summary sits right after the preamble, framed as untrusted data.
#[tokio::test]
async fn summary_is_framed_untrusted_after_preamble() {
    let m = TestModel::new(40, Summary::Ok, content_600);
    episode(&m, inputs(8192, true)).await;
    let last = m.agent_requests().pop().unwrap();
    let Message::User { text } = &last.messages[1] else {
        panic!("no summary after the preamble")
    };
    assert!(
        text.starts_with("[bee: summary of turns 0–"),
        "{}",
        &text[..text.len().min(120)]
    );
    assert!(text.contains("written by the model from earlier conversation and tool output]\n<untrusted-data source=\"bee:summary\" nonce=\""));
    assert!(text.contains("summary #"));
}

/// FR-014: when the summary call fails, the oldest turns are removed and a marker says so.
#[tokio::test]
async fn summary_failure_removes_with_marker() {
    let m = TestModel::new(40, Summary::Fail, content_600);
    let r = episode(&m, inputs(8192, true)).await;
    assert_eq!(r.t.status, EpisodeStatus::Completed);
    let removed =
        r.t.compactions
            .iter()
            .find(|e| e.kind == CompactionKind::Removed)
            .expect("a removal");
    assert!(
        removed
            .error
            .as_deref()
            .is_some_and(|e| e.contains("summary service down")),
        "{removed:?}"
    );
    let last = m.agent_requests().pop().unwrap();
    let Message::User { text } = &last.messages[1] else {
        panic!("no marker")
    };
    assert!(
        text.starts_with("[bee] ")
            && text.ends_with(
                " earlier turns were removed to fit the context budget; their record is kept."
            ),
        "{text}"
    );
    assert!(r
        .lines
        .iter()
        .any(|l| l.starts_with("  context: removed ")
            && l.contains(" turns after summary failure: ")));
}

/// FR-014: a request that cannot be brought within budget ends the run, not in a provider error.
#[tokio::test]
async fn cannot_fit_ends_context_exhausted() {
    let m = TestModel::new(3, Summary::Ok, content_2k);
    let (mut sb, mut registry) = tool_for(&m);
    let mut s = scenario("huge", &[SCRIPTED], 5, 30);
    s.task = "z".repeat(40_000);
    let t = run_loop(
        &m,
        &s,
        &mut registry,
        &mut sb,
        &LoopOptions {
            context: inputs(8192, true),
            ..LoopOptions::default()
        },
    )
    .await;
    assert!(
        matches!(t.status, EpisodeStatus::ContextExhausted { .. }),
        "{:?}",
        t.status
    );
    assert_eq!(m.agent_requests().len(), 0, "nothing over budget was sent");
}

/// FR-015: compaction brings the request well below `soft`, so the next turn does not compact again.
#[tokio::test]
async fn no_compaction_next_turn() {
    for (calls, content) in [(12, content_2k as fn(&str) -> String), (40, content_600)] {
        let m = TestModel::new(calls, Summary::Ok, content);
        let r = episode(&m, inputs(8192, true)).await;
        let turns: Vec<u32> = r.t.compactions.iter().map(|e| e.turn).collect();
        assert!(!turns.is_empty());
        for w in turns.windows(2) {
            assert!(
                w[1] != w[0] + 1,
                "compacted on consecutive turns: {turns:?}"
            );
        }
    }
}

/// FR-011, SC-005: the record is the same with compaction on or off.
#[tokio::test]
async fn record_identical_with_and_without() {
    let on = TestModel::new(40, Summary::Ok, content_600);
    let a = episode(&on, inputs(8192, true)).await.t;
    assert!(!a.compactions.is_empty(), "the run compacted");
    let off = TestModel::new(40, Summary::Ok, content_600);
    let b = episode(&off, inputs(200_000, false)).await.t;
    assert!(b.compactions.is_empty());

    let strip = |t: &EpisodeTranscript| {
        let mut v = serde_json::to_value(t).unwrap();
        let o = v.as_object_mut().unwrap();
        for k in ["compactions", "summary_usage", "timing", "usage"] {
            o.remove(k);
        }
        for turn in o["turns"].as_array_mut().unwrap() {
            let turn = turn.as_object_mut().unwrap();
            turn.remove("duration_ms");
            turn.remove("notes");
        }
        v
    };
    assert_eq!(strip(&a), strip(&b));
}

/// SC-001: a run whose output is five times the budget completes.
#[tokio::test]
async fn five_x_budget_run_completes() {
    // ~7k-token budget at 3 bytes per token is ~21 KB; 55 results of 2 KB are over 100 KB.
    let m = TestModel::new(55, Summary::Ok, content_2k);
    let r = episode(&m, inputs(8192, true)).await;
    assert_eq!(r.t.status, EpisodeStatus::Completed);
    let total: usize =
        r.t.turns
            .iter()
            .flat_map(|t| &t.calls)
            .map(|c| c.result.content.len())
            .sum();
    assert!(total > 5 * 21_000, "{total} bytes");
}

/// SC-002: across budgets, no request ever exceeds its budget.
#[tokio::test]
async fn budgets_matrix_zero_overflow() {
    for window in [32_768u32, 65_536, 131_072] {
        let calls = (window / 300) as usize;
        let m = TestModel::new(calls, Summary::Ok, content_2k);
        let (mut sb, mut registry) = tool_for(&m);
        let ctx = inputs(window, true);
        let t = run_loop(
            &m,
            &scenario("matrix", &[SCRIPTED], calls as u32 + 5, 600),
            &mut registry,
            &mut sb,
            &LoopOptions {
                context: ctx,
                stuck: bee::stuck::StuckConfig {
                    stop: Some(false),
                    ..Default::default()
                },
                ..LoopOptions::default()
            },
        )
        .await;
        assert_eq!(t.status, EpisodeStatus::Completed, "window {window}");
        let budget = bee::context::ContextManager::for_session(&ctx, None, m.id())
            .unwrap()
            .0
            .budget()
            .tokens();
        for s in m.agent_requests() {
            let convo = Conversation {
                system: "You are a test agent.".into(),
                messages: s.messages,
            };
            let schemas = registry.schemas();
            let est = bee::context::budget::tokens(
                bee::context::budget::estimate_bytes(&convo, &schemas),
                bee::context::budget::INITIAL_RATIO,
            );
            assert!(est <= budget, "window {window}: {est} > {budget}");
        }
    }
}

/// FR-012, FR-013: the summary calls' cost is recorded apart, and counted in the total.
#[tokio::test]
async fn summary_usage_counted_separately() {
    let bill = Usage {
        input_tokens: 100,
        output_tokens: 50,
        ..Usage::default()
    };
    let m = TestModel::new(40, Summary::Billed(bill), content_600);
    let r = episode(&m, inputs(8192, true)).await;
    let n = m.summaries() as u32;
    assert!(n >= 1);
    let su = r.t.summary_usage.expect("summary usage");
    assert_eq!((su.input_tokens, su.output_tokens), (100 * n, 50 * n));
    assert_eq!(
        r.t.usage,
        Some(su),
        "the agent's turns reported none, so the total is the summaries'"
    );
    let in_events: u32 =
        r.t.compactions
            .iter()
            .filter_map(|e| e.usage)
            .map(|u| u.input_tokens)
            .sum();
    assert_eq!(in_events, 100 * n);
}

struct Lines(Mutex<Vec<String>>);

impl ReplOutput for Lines {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, m: &str) {
        self.0.lock().unwrap().push(m.to_string());
    }
}

/// FR-019: `/clear` forgets the summary and the head; the next compaction starts again from turn 0.
#[tokio::test]
async fn repl_clear_resets() {
    let config = ReplConfig {
        agent_turn_budget: 60,
        context: inputs(8192, true),
        ..ReplConfig::default()
    };
    let steering = Arc::new(Mutex::new(VecDeque::new()));
    let out = Lines(Mutex::new(Vec::new()));
    for round in 0..2 {
        let m = TestModel::new(40, Summary::Ok, content_600);
        let (mut sb, mut registry) = tool_for(&m);
        let mut convo = Conversation {
            system: "test".into(),
            messages: Vec::new(),
        };
        let r = run_exchange(
            "go",
            &m,
            &mut convo,
            &mut registry,
            &mut sb,
            &config,
            &out,
            &steering,
            None,
        )
        .await;
        let summarized: Vec<_> = r
            .compactions
            .iter()
            .filter(|e| e.kind == CompactionKind::Summarized)
            .collect();
        assert!(!summarized.is_empty(), "round {round}");
        assert_eq!(
            summarized[0].turns.map(|t| t.0),
            Some(0),
            "round {round}: the summary starts at the conversation's first turn"
        );
        let Message::User { text } = &convo.messages[1] else {
            panic!("round {round}: no summary after the preamble")
        };
        assert!(
            text.starts_with("[bee: summary of turns 0–"),
            "round {round}"
        );
        // `/clear`: the conversation and the context state both go.
        config.state.lock().unwrap().reset();
    }
    assert!(out
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.starts_with("context: summarized turns 0–")));
}

/// FR-018: each compaction is shown as one progress line, from contracts/context.md.
#[tokio::test]
async fn progress_lines() {
    let m = TestModel::new(40, Summary::Ok, content_600);
    let r = episode(&m, inputs(8192, true)).await;
    let budget = bee::context::ContextManager::for_session(&inputs(8192, true), None, m.id())
        .unwrap()
        .0
        .budget()
        .tokens();
    let shown: Vec<&String> = r
        .lines
        .iter()
        .filter(|l| l.starts_with("  context: "))
        .collect();
    assert_eq!(shown.len(), r.t.compactions.len());
    for (line, e) in shown.iter().zip(&r.t.compactions) {
        assert_eq!(**line, format!("  {}", bee::context::describe(e, budget)));
    }
    let e =
        r.t.compactions
            .iter()
            .find(|e| e.kind == CompactionKind::Summarized)
            .unwrap();
    let (a, b) = e.turns.unwrap();
    let k = |t: u32| format!("{:.1}k", f64::from(t) / 1000.0);
    assert_eq!(
        bee::context::describe(e, budget),
        format!(
            "context: summarized turns {a}–{b} ({} → {} tokens of {})",
            k(e.before_tokens),
            k(e.after_tokens),
            k(budget)
        )
    );
}
