//! 025 PR B (US4) — every session knows its context budget, never sends a request over it, and caps
//! each tool result the model sees; the record keeps the tool's own output
//! (specs/025-long-run-resilience/quickstart.md, Phase B).

#[path = "support/fixtures.rs"]
mod fixtures;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bee::context::{ContextConfig, ContextInputs, ContextManager, WindowSource};
use bee::provider::mock_model::MockModel;
use bee::provider::{Message, ToolSchema, Turn, Usage};
use bee::repl::{run_exchange, ExchangeOutcome, ReplConfig, ReplOutput};
use bee::sandbox::{self, Sandbox};
use bee::tools::{Tool, ToolRegistry, ToolResult};
use bee::transcript::EpisodeStatus;
use bee::{run_loop, LoopOptions};
use fixtures::{call_turn, scenario, text_turn};

/// A tool that returns `n` bytes of `x`.
struct Big(usize);

#[async_trait::async_trait]
impl Tool for Big {
    fn name(&self) -> &'static str {
        "big"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "big".into(),
            description: "returns a lot".into(),
            parameters: serde_json::json!({ "type": "object" }),
        }
    }
    async fn call(&self, _arguments: serde_json::Value, _sandbox: &Sandbox) -> ToolResult {
        ToolResult::ok("x".repeat(self.0))
    }
}

fn inputs(config: ContextConfig) -> ContextInputs {
    ContextInputs {
        config,
        provider_window: None,
        max_tokens: Some(1024),
    }
}

fn window(tokens: u32) -> ContextConfig {
    ContextConfig {
        window_tokens: Some(tokens),
        ..Default::default()
    }
}

/// What the model saw: the content of every tool result in every request.
type Seen = Arc<Mutex<Vec<usize>>>;

fn recording_model(script: Vec<Turn>) -> (MockModel, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let script = Mutex::new(std::collections::VecDeque::from(script));
    let model = MockModel::from_fn(move |convo| {
        for m in &convo.messages {
            if let Message::ToolResult { content, .. } = m {
                log.lock().unwrap().push(content.len());
            }
        }
        script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| text_turn("done"))
    })
    .with_id("mock/recording");
    (model, seen)
}

fn progress() -> (Option<bee::ProgressSink>, Arc<Mutex<Vec<String>>>) {
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = lines.clone();
    (
        Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        lines,
    )
}

#[test]
fn window_from_table_provider_and_config() {
    let table = ContextManager::for_session(
        &inputs(ContextConfig::default()),
        None,
        "anthropic/claude-sonnet-4-6",
    )
    .unwrap()
    .0;
    assert_eq!(table.budget().source, WindowSource::Table);
    assert_eq!(table.budget().window, 200_000);

    let provider = ContextInputs {
        provider_window: Some(131_072),
        ..inputs(ContextConfig::default())
    };
    let m = ContextManager::for_session(&provider, None, "openai-compat/local")
        .unwrap()
        .0;
    assert_eq!(m.budget().source, WindowSource::ProviderFile);

    // User/project config beats the provider file; the scenario beats both.
    let user = ContextInputs {
        config: window(64_000),
        ..provider
    };
    let m = ContextManager::for_session(&user, None, "openai-compat/local")
        .unwrap()
        .0;
    assert_eq!(
        (m.budget().window, m.budget().source),
        (64_000, WindowSource::Config)
    );
    let m = ContextManager::for_session(&user, Some(&window(32_000)), "openai-compat/local")
        .unwrap()
        .0;
    assert_eq!(m.budget().window, 32_000);
}

#[tokio::test]
async fn unknown_model_uses_default_and_says_so_once() {
    let model = MockModel::scripted(vec![
        call_turn("1", "bash"),
        call_turn("2", "bash"),
        text_turn("done"),
    ])
    .with_id("openai-compat/local-model");
    let scn = scenario("unknown-window", &["bash"], 5, 30);
    let mut registry = bee::tools::registry_for(&scn.tools, None);
    let mut sb = Sandbox::host(sandbox::key_vars(None));
    let (sink, lines) = progress();
    let opts = LoopOptions {
        progress: sink,
        ..LoopOptions::default()
    };
    run_loop(&model, &scn, &mut registry, &mut sb, &opts).await;
    let notices: Vec<String> = lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("window unknown"))
        .cloned()
        .collect();
    assert_eq!(
        notices,
        vec![
            "  context: window unknown for openai-compat/local-model; assuming 32000 tokens (set \
             [context] window_tokens)"
                .to_string()
        ]
    );
}

#[test]
fn cap_is_min_of_bytes_and_share() {
    let big = ContextManager::for_session(&inputs(window(200_000)), None, "mock/x")
        .unwrap()
        .0;
    assert_eq!(
        big.result_cap(),
        24_000,
        "the byte cap binds on a large window"
    );
    let small = ContextManager::for_session(&inputs(window(16_000)), None, "mock/x")
        .unwrap()
        .0;
    assert!(
        small.result_cap() < 24_000,
        "10% of a small budget binds instead: {}",
        small.result_cap()
    );
}

#[test]
fn cap_marker_states_original_size() {
    let m = ContextManager::for_session(&inputs(window(200_000)), None, "mock/x")
        .unwrap()
        .0;
    let out = m.cap(&"y".repeat(30_000), None);
    assert!(out.starts_with(&"y".repeat(24_000)));
    assert!(
        out.ends_with(
            "[bee: showing 24000 of 30000 bytes — request a narrower range (line offset, filter, \
             smaller search) to see more]"
        ),
        "{}",
        &out[24_000..]
    );
    // A result the tool already cut reports the tool's original size.
    let out = m.cap(&"y".repeat(30_000), Some(250_000));
    assert!(out.contains("showing 24000 of 250000 bytes"));
}

#[tokio::test]
async fn record_keeps_uncapped_result() {
    let (model, seen) = recording_model(vec![call_turn("1", "big"), text_turn("done")]);
    let scn = scenario("cap", &["big"], 5, 30);
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(Big(60_000)));
    let mut sb = Sandbox::host(sandbox::key_vars(None));
    let t = run_loop(
        &model,
        &scn,
        &mut registry,
        &mut sb,
        &LoopOptions::default(),
    )
    .await;

    let recorded = &t.turns[0].calls[0].result.content;
    assert_eq!(
        recorded.len(),
        60_000,
        "the record keeps the tool's output (FR-022)"
    );
    let sent = seen.lock().unwrap();
    assert_eq!(sent.len(), 1, "the model saw the result once");
    assert!(
        sent[0] > 24_000 && sent[0] < 24_200,
        "the model saw 24,000 bytes plus the marker: {}",
        sent[0]
    );
}

#[tokio::test]
async fn oversize_request_ends_context_exhausted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let model = MockModel::from_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        text_turn("should not be asked")
    });
    let mut scn = scenario("oversize", &["bash"], 5, 30);
    scn.task = "z".repeat(200 * 1024);
    scn.context = window(8_192);
    let mut registry = bee::tools::registry_for(&scn.tools, None);
    let mut sb = Sandbox::host(sandbox::key_vars(None));
    let opts = LoopOptions {
        context: inputs(ContextConfig::default()),
        ..LoopOptions::default()
    };
    let t = run_loop(&model, &scn, &mut registry, &mut sb, &opts).await;

    assert!(
        matches!(&t.status, EpisodeStatus::ContextExhausted { detail } if detail.contains("context budget")),
        "{:?}",
        t.status
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no request over budget was sent"
    );
    assert_eq!(
        bee::episode::exit_code(&t.status),
        bee::episode::EXIT_INCOMPLETE
    );
}

#[test]
fn estimate_calibrates_from_usage() {
    let mut m = ContextManager::for_session(&inputs(window(200_000)), None, "mock/x")
        .unwrap()
        .0;
    assert_eq!(m.ratio(), 3.0);
    let usage = Usage {
        input_tokens: 1_000,
        ..Default::default()
    };
    m.observe(4_000, Some(&usage));
    assert_eq!(m.ratio(), 3.5, "halfway toward the observed 4 bytes/token");
    for _ in 0..20 {
        m.observe(100_000, Some(&usage));
    }
    assert_eq!(m.ratio(), 6.0, "clamped");
    m.observe(4_000, None);
    assert_eq!(m.ratio(), 6.0, "no usage, no change");
}

/// A REPL output that keeps only errors.
#[derive(Default)]
struct Errors(Mutex<Vec<String>>);

impl ReplOutput for Errors {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, msg: &str) {
        self.0.lock().unwrap().push(msg.to_string());
    }
    fn info(&self, _: &str) {}
}

#[tokio::test]
async fn the_repl_refuses_an_oversize_request_too() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let model = MockModel::from_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        text_turn("should not be asked")
    });
    let config = ReplConfig {
        context: inputs(window(8_192)),
        ..ReplConfig::default()
    };
    let mut convo = bee::provider::Conversation {
        system: "s".into(),
        messages: Vec::new(),
    };
    let mut registry = ToolRegistry::new();
    let mut sb = Sandbox::host(sandbox::key_vars(None));
    let out = Errors::default();
    let res = run_exchange(
        &"z".repeat(200 * 1024),
        &model,
        &mut convo,
        &mut registry,
        &mut sb,
        &config,
        &out,
        &Default::default(),
        None,
    )
    .await;
    assert!(
        matches!(res.outcome, ExchangeOutcome::ContextExhausted(_)),
        "{:?}",
        res.outcome
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(out.0.lock().unwrap()[0].starts_with("context exhausted:"));
}
