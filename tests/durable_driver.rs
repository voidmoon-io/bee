#![cfg(feature = "durable-sessions")]
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Message, Model, ToolCall, ToolSchema, Turn};
use bee::repl::{ExchangeOutcome, ReplConfig, ReplOutput};
use bee::session::driver::{DriverError, Limits, RunBinding, Session};
use bee::session::durable::{SessionId, Snapshot};
use bee::tools::{Tool, ToolRegistry, ToolResult};
use bee::{LoopOptions, Sandbox};
use serde_json::json;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn limits() -> Limits {
    Limits {
        turns: 5,
        tool_calls: 1024,
        timeout_ms: 30_000,
        tool_timeout_ms: 10_000,
        model_attempts: 2,
    }
}
async fn session(root: &Path, resume: Option<&str>) -> Arc<Session> {
    Session::open(
        root.join("session"),
        SessionId("driver-fixture".into()),
        "test-config".into(),
        resume.map(str::to_owned),
    )
    .await
    .unwrap()
}
fn snapshot(root: &Path) -> Snapshot {
    let db = rusqlite::Connection::open_with_flags(
        root.join("session/session.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT snapshot FROM session WHERE singleton=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn scenario() -> bee::Scenario {
    bee::Scenario {
        context: Default::default(),
        stuck: Default::default(),
        lease_turns: None,
        finish: false,
        id: "fixture".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "system".into(),
        task: "investigate".into(),
        turn_limit: 5,
        timeout_secs: 30,
        tools: vec!["mutation".into()],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: vec![],
        ceiling_policy_path: None,
        security: Default::default(),
    }
}
fn model() -> MockModel {
    MockModel::from_fn(|convo| {
        if convo
            .messages
            .iter()
            .any(|m| matches!(m, Message::ToolResult { .. }))
        {
            Turn::text("finished")
        } else {
            Turn::calls(vec![ToolCall {
                id: "call".into(),
                name: "mutation".into(),
                arguments: json!({}),
            }])
        }
    })
    .with_id("fixture-model")
}
struct Mutation(PathBuf);
#[async_trait::async_trait]
impl Tool for Mutation {
    fn name(&self) -> &'static str {
        "mutation"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "mutation".into(),
            description: "fixture".into(),
            parameters: json!({"type":"object"}),
        }
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.0.join("effects"))
            .unwrap();
        f.write_all(b"effect\n").unwrap();
        f.sync_all().unwrap();
        if std::env::var("BEE_DRIVER_CRASH_MODE").as_deref() == Ok("after-effect") {
            pause();
        }
        ToolResult::ok("exact observation")
    }
}
fn registry(root: &Path, session: &Session) -> ToolRegistry {
    let mut registry = ToolRegistry::new().with(Box::new(Mutation(root.into())));
    registry.enable_evidence(session.evidence());
    registry
}
#[derive(Default)]
struct Output {
    root: Option<PathBuf>,
    text: Mutex<String>,
    results: Mutex<Vec<ToolResult>>,
    steer: Option<Arc<Session>>,
}
impl ReplOutput for Output {
    fn assistant_delta(&self, text: &str) {
        if let Some(root) = &self.root {
            let snap = snapshot(root);
            let serialized = snap.driver().unwrap().to_string();
            assert!(
                serialized.contains(text),
                "displayed uncommitted text: {text}"
            );
        }
        self.text.lock().unwrap().push_str(text);
        if let Some(session) = &self.steer {
            if text == "first" {
                session.steer("steering arrived".into()).unwrap();
            }
        }
        if std::env::var("BEE_DRIVER_CRASH_MODE").as_deref() == Ok("stream") {
            pause();
        }
    }
    fn assistant_end(&self) {}
    fn busy_start(&self) {
        if std::env::var("BEE_DRIVER_CRASH_MODE").as_deref() == Ok("before-provider-budget") {
            pause();
        }
    }
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, result: &ToolResult, _: &[bee_core::AuditEvent]) {
        self.results.lock().unwrap().push(result.clone());
        if std::env::var("BEE_DRIVER_CRASH_MODE").as_deref() == Ok("after-result") {
            pause();
        }
    }
    fn error(&self, text: &str) {
        self.text.lock().unwrap().push_str(text);
    }
    fn info(&self, text: &str) {
        if std::env::var("BEE_DRIVER_CRASH_MODE").is_ok_and(|s| s.starts_with("backoff"))
            && text.starts_with("provider retry delayed")
        {
            pause();
        }
    }
}

#[tokio::test]
async fn submissions_are_idempotent_and_both_entrypoints_use_the_same_result() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), Some("request")).await;
    let mut registry = registry(root.path(), &session);
    let model = model();
    let options = LoopOptions {
        durable: Some(RunBinding {
            session: session.clone(),
            request_id: "request".into(),
            resume: false,
            tool_call_limit: 1024,
        }),
        ..Default::default()
    };
    let first = bee::run_loop(
        &model,
        &scenario(),
        &mut registry,
        &mut Sandbox::host(vec![]),
        &options,
    )
    .await;
    assert!(
        matches!(first.status, bee::EpisodeStatus::Completed),
        "{:?}",
        first.status
    );
    let config = ReplConfig {
        durable: Some(session.clone()),
        system_prompt: "system".into(),
        ..Default::default()
    };
    let output = Output::default();
    let mut conversation = Conversation::default();
    let result = bee::repl::run_exchange(
        "",
        &model,
        &mut conversation,
        &mut registry,
        &mut Sandbox::host(vec![]),
        &config,
        &output,
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(result.outcome, ExchangeOutcome::Responded);
    assert_eq!(
        serde_json::to_value(&result.turns).unwrap(),
        serde_json::to_value(&first.turns).unwrap()
    );
    assert!(conversation.messages.iter().any(|m| matches!(m, Message::ToolResult { content, .. } if content.contains("exact observation"))));
    assert_eq!(
        std::fs::read(root.path().join("effects")).unwrap(),
        b"effect\n"
    );
    assert!(session
        .run(
            "request",
            Some("different"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &output,
            None
        )
        .await
        .is_err());
}

#[tokio::test]
async fn preloaded_steering_reaches_even_an_immediate_response() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let model = MockModel::from_fn(|conversation| {
        assert!(conversation.messages.iter().any(|message| {
            matches!(message, Message::User { text } if text == "queued steering")
        }));
        Turn::text("done")
    });
    let steering = Arc::new(Mutex::new(std::collections::VecDeque::from([
        "queued steering".into(),
    ])));
    let result = bee::repl::run_exchange(
        "task",
        &model,
        &mut Conversation::default(),
        &mut registry,
        &mut Sandbox::host(vec![]),
        &ReplConfig {
            durable: Some(session),
            ..Default::default()
        },
        &Output::default(),
        &steering,
        None,
    )
    .await;
    assert_eq!(result.outcome, ExchangeOutcome::Responded);
    assert!(steering.lock().unwrap().is_empty());
}

struct DoneOnlyModel(usize);
#[async_trait::async_trait]
impl Model for DoneOnlyModel {
    fn id(&self) -> &str {
        "done-only"
    }
    async fn complete(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<Turn, bee::provider::ModelError> {
        Ok(Turn::text("x".repeat(self.0)))
    }
    async fn stream(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<bee::provider::EventStream, bee::provider::ModelError> {
        Ok(Box::pin(futures_util::stream::iter([Ok(
            bee::provider::StreamEvent::Done(Turn::text("x".repeat(self.0))),
        )])))
    }
}

/// Streams its reply one byte per delta, as a token-at-a-time provider does.
struct TokenModel(usize);
#[async_trait::async_trait]
impl Model for TokenModel {
    fn id(&self) -> &str {
        "tokens"
    }
    async fn complete(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<Turn, bee::provider::ModelError> {
        Ok(Turn::text("x".repeat(self.0)))
    }
    async fn stream(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<bee::provider::EventStream, bee::provider::ModelError> {
        let deltas = (0..self.0).map(|_| Ok(bee::provider::StreamEvent::TextDelta("x".into())));
        let done = Ok(bee::provider::StreamEvent::Done(Turn::text(
            "x".repeat(self.0),
        )));
        Ok(Box::pin(futures_util::stream::iter(
            deltas.chain(std::iter::once(done)),
        )))
    }
}

/// A terminal tool that steers its own session while running, as a user typing mid-call would.
struct SteeredEnding(Arc<Session>);
#[async_trait::async_trait]
impl Tool for SteeredEnding {
    fn name(&self) -> &'static str {
        "ending"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ending".into(),
            description: "fixture".into(),
            parameters: json!({"type":"object"}),
        }
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        self.0.steer("late steering".into()).unwrap();
        // Let the driver admit the steering while this call is still running.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        ToolResult::terminal_ok("ended")
    }
}

#[tokio::test]
async fn steering_left_unread_by_a_terminal_tool_is_reported() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = ToolRegistry::new().with(Box::new(SteeredEnding(session.clone())));
    registry.enable_evidence(session.evidence());
    let model = MockModel::from_fn(|_| {
        Turn::calls(vec![ToolCall {
            id: "end".into(),
            name: "ending".into(),
            arguments: json!({}),
        }])
    })
    .with_id("fixture-model");
    let output = Output::default();
    let (report, conversation) = session
        .run(
            "terminal",
            Some("task"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::Completed);
    assert!(!conversation
        .messages
        .iter()
        .any(|m| matches!(m, Message::User { text } if text == "late steering")));
    let text = output.text.lock().unwrap();
    assert!(text.contains("ended before using it"), "{text}");
}

#[tokio::test]
async fn token_deltas_coalesce_into_bounded_commits() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let output = Output {
        root: Some(root.path().into()),
        ..Default::default()
    };
    let (report, _) = session
        .run(
            "tokens",
            Some("task"),
            "system",
            limits(),
            &TokenModel(10_000),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::NoToolCalls);
    assert_eq!(output.text.lock().unwrap().len(), 10_000);
    // 10,000 deltas are three 4 KiB chunks, not 10,000 checkpoints.
    assert!(snapshot(root.path()).revision() < 32);
    // A completed result is stored once, in its entry, and restored into the phase on load.
    let db = rusqlite::Connection::open(root.path().join("session/session.sqlite3")).unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT snapshot FROM session WHERE singleton=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let completed: Vec<_> = raw["operations"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|op| op["phase"].get("Completed"))
        .collect();
    assert!(!completed.is_empty());
    assert!(completed.iter().all(|phase| phase.get("result").is_none()));
    drop(db);
    drop(registry);
    drop(session);
    let reopened = crate::session(root.path(), None).await;
    let mut registry = crate::registry(root.path(), &reopened);
    let (replayed, _) = reopened
        .run(
            "tokens",
            None,
            "system",
            limits(),
            &TokenModel(10_000),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&replayed.turns).unwrap(),
        serde_json::to_value(&report.turns).unwrap()
    );
}

#[tokio::test]
async fn complete_only_provider_text_uses_the_same_durable_stream_bounds() {
    for size in [5000, 1024 * 1024 + 1] {
        let root = tempfile::tempdir().unwrap();
        let session = session(root.path(), None).await;
        let mut registry = registry(root.path(), &session);
        let output = Output {
            root: Some(root.path().into()),
            ..Default::default()
        };
        let result = session
            .run(
                "done-only",
                Some("task"),
                "system",
                limits(),
                &DoneOnlyModel(size),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &output,
                None,
            )
            .await;
        if size > 1024 * 1024 {
            let (report, _) = result.unwrap();
            assert!(
                matches!(&report.status, bee::EpisodeStatus::Terminated { detail } if detail.contains("limit")),
                "{:?}",
                report.status
            );
            assert!(output.text.lock().unwrap().is_empty());
            // The terminated submission no longer blocks the session.
            let (next, _) = session
                .run(
                    "after-limit",
                    Some("task"),
                    "system",
                    limits(),
                    &DoneOnlyModel(10),
                    &mut registry,
                    &mut Sandbox::host(vec![]),
                    &output,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(next.status, bee::EpisodeStatus::NoToolCalls);
        } else {
            assert_eq!(result.unwrap().0.status, bee::EpisodeStatus::NoToolCalls);
            assert_eq!(output.text.lock().unwrap().len(), size);
        }
    }
}

#[tokio::test]
async fn stream_chunks_and_steering_are_committed_before_acknowledgement_or_use() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let output = Output {
        root: Some(root.path().into()),
        steer: Some(session.clone()),
        ..Default::default()
    };
    let model = MockModel::from_fn(|c| {
        if c.messages
            .iter()
            .any(|m| matches!(m, Message::User { text } if text == "steering arrived"))
        {
            Turn::text("second")
        } else {
            Turn::text("first")
        }
    });
    let (report, conversation) = session
        .run(
            "stream",
            Some("input"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.model_calls, 2);
    assert_eq!(output.text.lock().unwrap().as_str(), "firstsecond");
    assert!(conversation
        .messages
        .iter()
        .any(|m| matches!(m, Message::User { text } if text == "steering arrived")));
    let db = rusqlite::Connection::open(root.path().join("session/session.sqlite3")).unwrap();
    let count: u32 = db
        .query_row("SELECT count(*) FROM submissions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn missing_evidence_and_changed_configuration_block_reopen_without_execution() {
    let root = tempfile::tempdir().unwrap();
    let running = session(root.path(), None).await;
    let mut registry = registry(root.path(), &running);
    let (report, _) = running
        .run(
            "request",
            Some("input"),
            "system",
            limits(),
            &model(),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    let id = report.turns[0].calls[0].result.receipt_id.as_ref().unwrap();
    std::fs::remove_file(
        root.path()
            .join("session/evidence")
            .join(format!("{}.json", &id[7..])),
    )
    .unwrap();
    assert!(running
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None
        )
        .await
        .is_err());
    drop(running);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let changed = Session::open(
        root.path().join("session"),
        SessionId("driver-fixture".into()),
        "changed".into(),
        None,
    )
    .await;
    assert!(
        matches!(&changed, Err(DriverError::Incompatible)),
        "{:?}",
        changed.err()
    );
    assert_eq!(
        std::fs::read(root.path().join("effects")).unwrap(),
        b"effect\n"
    );
}

fn pause() {
    println!("BEE_DRIVER_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child(root: &Path, mode: &str) -> Child {
    let mut process = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "crash_child", "--nocapture"])
        .env("BEE_DRIVER_CRASH_ROOT", root)
        .env("BEE_DRIVER_CRASH_MODE", mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = process.stdout.take().unwrap();
    let child = Child(process);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.is_ok_and(|s| s == "BEE_DRIVER_READY") {
                let _ = tx.send(());
                break;
            }
        }
    });
    rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
    child
}
#[tokio::test]
#[ignore = "SIGKILL fixture called explicitly by parent test"]
async fn crash_child() {
    let root = PathBuf::from(std::env::var_os("BEE_DRIVER_CRASH_ROOT").unwrap());
    let session = session(&root, None).await;
    let mut registry = registry(&root, &session);
    let mode = std::env::var("BEE_DRIVER_CRASH_MODE").unwrap();
    let mut limits = limits();
    if mode == "backoff-expired" {
        limits.timeout_ms = 1500;
    }
    if mode == "before-provider-budget" {
        limits.turns = 1;
    }
    let model: Box<dyn Model> = if mode.starts_with("backoff") {
        Box::new(BackoffModel)
    } else if mode == "stream" {
        Box::new(MockModel::from_fn(|_| Turn::text("partial stream")).with_id("fixture-model"))
    } else {
        Box::new(model())
    };
    session
        .run(
            "request",
            Some("investigate"),
            "system",
            limits,
            model.as_ref(),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output {
                root: Some(root),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    panic!("fixture missed pause");
}
#[tokio::test]
async fn sigkill_result_recovers_into_repl_without_repeating_the_effect() {
    let root = tempfile::tempdir().unwrap();
    let mut child = child(root.path(), "after-result");
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let before = snapshot(root.path());
    let original = before
        .entries()
        .iter()
        .find(|e| e.result.receipt.is_some())
        .unwrap()
        .result
        .clone();
    let session = session(root.path(), None).await;
    assert_eq!(session.resume_request(), Some("request"));
    let mut registry = registry(root.path(), &session);
    let config = ReplConfig {
        durable: Some(session),
        system_prompt: "system".into(),
        ..Default::default()
    };
    let output = Output::default();
    let mut conversation = Conversation::default();
    let result = bee::repl::run_exchange(
        "",
        &model(),
        &mut conversation,
        &mut registry,
        &mut Sandbox::host(vec![]),
        &config,
        &output,
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(
        result.outcome,
        ExchangeOutcome::Responded,
        "{}",
        output.text.lock().unwrap()
    );
    assert_eq!(
        serde_json::to_value(&result.turns[0].calls[0].result).unwrap(),
        original.output
    );
    let after = snapshot(root.path());
    assert_eq!(
        after
            .entries()
            .iter()
            .find(|e| e.result.receipt.is_some())
            .unwrap()
            .result,
        original
    );
    assert_eq!(
        std::fs::read(root.path().join("effects")).unwrap(),
        b"effect\n"
    );
}
#[tokio::test]
async fn sigkill_unknown_effect_stays_unresolved_and_partial_stream_never_dispatches() {
    for mode in ["after-effect", "stream"] {
        let root = tempfile::tempdir().unwrap();
        let mut child = child(root.path(), mode);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        if mode == "stream" {
            // The child pauses after presenting text, so that text was committed before the kill.
            let step = snapshot(root.path()).driver().unwrap()["active"]["step"].clone();
            assert!(step.to_string().contains("partial"), "{step}");
        }
        let running = session(root.path(), None).await;
        let mut registry = registry(root.path(), &running);
        let resumed = running
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None,
            )
            .await;
        if mode == "after-effect" {
            assert!(matches!(resumed, Err(DriverError::Unresolved(_))));
            assert_eq!(
                std::fs::read(root.path().join("effects")).unwrap(),
                b"effect\n"
            );
        } else {
            assert!(resumed.is_ok(), "{resumed:?}");
            assert_eq!(
                std::fs::read(root.path().join("effects")).unwrap(),
                b"effect\n"
            );
        }
    }
}

struct CancelProbe(PathBuf);
struct CleanupProbe(PathBuf);
impl Drop for CleanupProbe {
    fn drop(&mut self) {
        let snap = snapshot(&self.0);
        let persisted = snap
            .operations()
            .values()
            .any(|op| matches!(op.phase, bee::session::durable::Phase::Cancelling { .. }));
        std::fs::write(
            self.0.join("cleanup"),
            if persisted {
                "committed-cancel"
            } else {
                "missing-cancel"
            },
        )
        .unwrap();
    }
}
#[async_trait::async_trait]
impl Tool for CancelProbe {
    fn name(&self) -> &'static str {
        "cancel_probe"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "cancellation fixture".into(),
            parameters: json!({}),
        }
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        let _cleanup = CleanupProbe(self.0.clone());
        std::fs::write(self.0.join("started"), "started").unwrap();
        std::future::pending().await
    }
}
async fn wait_file(path: &Path) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn cancellation_intent_is_durable_before_the_tool_future_is_dropped() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = ToolRegistry::new().with(Box::new(CancelProbe(root.path().into())));
    registry.enable_evidence(session.evidence());
    let model = MockModel::from_fn(|_| {
        Turn::calls(vec![ToolCall {
            id: "call".into(),
            name: "cancel_probe".into(),
            arguments: json!({}),
        }])
    });
    let cancelling = session.clone();
    let path = root.path().join("started");
    let cancel = tokio::spawn(async move {
        wait_file(&path).await;
        cancelling.cancel().unwrap();
    });
    let (report, conversation) = session
        .run(
            "cancel",
            Some("task"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    cancel.await.unwrap();
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(
        std::fs::read_to_string(root.path().join("cleanup")).unwrap(),
        "committed-cancel"
    );
    assert!(snapshot(root.path())
        .operations()
        .values()
        .any(|op| matches!(op.phase, bee::session::durable::Phase::Stopped { .. })));
    assert!(matches!(
        conversation.messages.last(),
        Some(Message::ToolResult { is_error: true, .. })
    ));
}

#[tokio::test]
async fn cancellation_cleans_up_a_native_tool_child() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = bee::tools::registry_for(&["bash".into()], None);
    registry.enable_evidence(session.evidence());
    let pid_file = root.path().join("child-pid");
    let command = format!("printf '%s' \"$$\" > '{}'; sleep 30", pid_file.display());
    let model = MockModel::from_fn(move |_| {
        Turn::calls(vec![ToolCall {
            id: "child".into(),
            name: "bash".into(),
            arguments: json!({"command":command}),
        }])
    });
    let cancelling = session.clone();
    let path = pid_file.clone();
    let cancel = tokio::spawn(async move {
        wait_file(&path).await;
        cancelling.cancel().unwrap();
    });
    let (report, _) = session
        .run(
            "cancel-child",
            Some("task"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    cancel.await.unwrap();
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    let pid: u32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
    assert!(
        !PathBuf::from(format!("/proc/{pid}")).exists(),
        "tool leader survived cancellation"
    );
}

struct SlowModel(std::sync::atomic::AtomicU32);
#[async_trait::async_trait]
impl Model for SlowModel {
    fn id(&self) -> &str {
        "slow"
    }
    async fn complete(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<Turn, bee::provider::ModelError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        Ok(Turn::text("too late"))
    }
}
#[tokio::test]
async fn deadlines_and_spent_model_calls_do_not_reset_on_reopen() {
    let root = tempfile::tempdir().unwrap();
    let running = session(root.path(), None).await;
    let mut registry = registry(root.path(), &running);
    let model = SlowModel(std::sync::atomic::AtomicU32::new(0));
    let mut budget = limits();
    budget.timeout_ms = 2000;
    let (report, _) = running
        .run(
            "deadline",
            Some("task"),
            "system",
            budget,
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::Timeout);
    drop(running);
    let reopened = session(root.path(), Some("deadline")).await;
    let (replayed, _) = reopened
        .run(
            "deadline",
            None,
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        serde_json::to_value(replayed).unwrap()
    );
    assert_eq!(model.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

struct TransientModel(std::sync::atomic::AtomicU32);

struct BackoffModel;

async fn wait_past_wall_deadline(deadline: u64) {
    let watchdog = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while bee::session::driver::now_ms() <= deadline {
        assert!(
            std::time::Instant::now() < watchdog,
            "wall deadline did not advance"
        );
        // A timer notification alone does not establish the persisted wall-clock condition.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
#[async_trait::async_trait]
impl Model for BackoffModel {
    fn id(&self) -> &str {
        "fixture-model"
    }
    async fn complete(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<Turn, bee::provider::ModelError> {
        Err(bee::provider::ModelError::Transient {
            status: 429,
            retry_after: Some(std::time::Duration::from_secs(2)),
        })
    }
}

#[tokio::test]
async fn sigkill_preserves_retry_deadlines_and_settles_each_charge_once() {
    use bee::session::driver::Charge;
    for already_due in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut child = child(root.path(), "backoff");
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let saved = snapshot(root.path());
        let wake = saved.driver().unwrap()["active"]["wake"].clone();
        let deadline = wake["deadline_ms"].as_u64().unwrap();
        if already_due {
            wait_past_wall_deadline(deadline).await;
        }
        let reopened = session(root.path(), None).await;
        assert_eq!(
            snapshot(root.path()).driver().unwrap()["active"]["wake"],
            wake
        );
        let mut registry = registry(root.path(), &reopened);
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count = calls.clone();
        let model = MockModel::from_fn(move |_| {
            assert!(
                bee::session::driver::now_ms() >= deadline,
                "retry launched before persisted deadline {deadline}, wall {}",
                bee::session::driver::now_ms()
            );
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut turn = Turn::text("settled");
            turn.usage = Some(bee::provider::Usage {
                input_tokens: 17,
                output_tokens: 3,
                ..Default::default()
            });
            turn
        })
        .with_id("fixture-model");
        let started = std::time::Instant::now();
        let (report, _) = reopened
            .run(
                "request",
                None,
                "system",
                limits(),
                &model,
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None,
            )
            .await
            .unwrap();
        if already_due {
            assert!(
                started.elapsed() < std::time::Duration::from_millis(1500),
                "restart reset an expired retry delay: {:?}, deadline {deadline}, now {}",
                started.elapsed(),
                bee::session::driver::now_ms()
            );
        }
        assert_eq!(report.model_calls, 2);
        assert_eq!(report.budget.reservations[0].charge, Charge::Unresolved);
        assert!(matches!(
            report.budget.reservations[1].charge,
            Charge::Settled { .. }
        ));
        assert_eq!(report.budget.unreported_model_usage(), 1);
        assert_eq!(report.usage.unwrap().input_tokens, 17);
        let (replay, _) = reopened
            .run(
                "request",
                None,
                "system",
                limits(),
                &model,
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(replay.budget, report.budget);
        assert_eq!(replay.usage, report.usage);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn expired_or_cancelled_retry_wakes_do_not_dispatch_new_work() {
    for expire in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut child = child(
            root.path(),
            if expire { "backoff-expired" } else { "backoff" },
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        if expire {
            let saved = snapshot(root.path());
            let deadline = saved.driver().unwrap()["active"]["deadline_ms"]
                .as_u64()
                .unwrap();
            wait_past_wall_deadline(deadline).await;
        }
        let reopened = session(root.path(), None).await;
        let reopened = if expire {
            // Activation itself can expire work. Another crash must preserve that cleanup state.
            drop(reopened);
            session(root.path(), None).await
        } else {
            reopened
        };
        let cancelling = reopened.clone();
        let cancel = tokio::spawn(async move {
            if !expire {
                for _ in 0..1000 {
                    if cancelling.cancel().is_ok() {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                panic!("submission never accepted cancellation");
            }
        });
        let mut registry = registry(root.path(), &reopened);
        let model = MockModel::from_fn(|_| panic!("stopped retry dispatched a provider call"))
            .with_id("fixture-model");
        let (report, _) = reopened
            .run(
                "request",
                None,
                "system",
                limits(),
                &model,
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None,
            )
            .await
            .unwrap();
        cancel.await.unwrap();
        if expire {
            assert_eq!(report.status, bee::EpisodeStatus::Timeout);
        } else {
            assert!(matches!(
                report.status,
                bee::EpisodeStatus::Terminated { .. }
            ));
        }
        assert_eq!(report.model_calls, 1);
        assert_eq!(report.budget.unresolved(), 1);
    }
}

#[tokio::test]
async fn sigkill_after_reservation_cannot_refund_even_an_unlaunched_call() {
    let root = tempfile::tempdir().unwrap();
    let mut child = child(root.path(), "before-provider-budget");
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let saved = snapshot(root.path());
    assert_eq!(
        saved.driver().unwrap()["active"]["budget"]["reservations"][0]["charge"],
        "Reserved"
    );
    let reopened = session(root.path(), None).await;
    let mut registry = registry(root.path(), &reopened);
    let model = MockModel::from_fn(|_| panic!("reopen refunded a committed charge"))
        .with_id("fixture-model");
    let (report, _) = reopened
        .run(
            "request",
            None,
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::Timeout);
    assert_eq!(report.model_calls, 1);
    assert_eq!(report.budget.unresolved(), 1);
    assert_eq!(report.usage, None);
}

#[tokio::test]
async fn exhausted_model_and_tool_budgets_never_dispatch_or_reset_on_replay() {
    for model_budget in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let running = session(root.path(), None).await;
        let mut registry = registry(root.path(), &running);
        let mut budget_limits = limits();
        let provider: Box<dyn Model> = if model_budget {
            budget_limits.turns = 1;
            Box::new(BackoffModel)
        } else {
            budget_limits.tool_calls = 0;
            Box::new(model())
        };
        let (report, _) = running
            .run(
                "budget",
                Some("task"),
                "system",
                budget_limits,
                provider.as_ref(),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(report.status, bee::EpisodeStatus::Timeout);
        assert_eq!(report.model_calls, 1);
        assert_eq!(
            report.budget.charged(bee::session::durable::WorkKind::Tool),
            0
        );
        assert!(!root.path().join("effects").exists());
        drop(running);
        let reopened = session(root.path(), None).await;
        let (replayed, _) = reopened
            .run(
                "budget",
                None,
                "system",
                limits(),
                provider.as_ref(),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(replayed.budget, report.budget);
        assert_eq!(replayed.status, report.status);
    }
}

#[async_trait::async_trait]
impl Model for TransientModel {
    fn id(&self) -> &str {
        "transient"
    }
    async fn complete(
        &self,
        _: &Conversation,
        _: &[ToolSchema],
    ) -> Result<Turn, bee::provider::ModelError> {
        if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Err(bee::provider::ModelError::Transient {
                status: 429,
                retry_after: Some(std::time::Duration::from_millis(1)),
            })
        } else {
            Ok(Turn::text("recovered"))
        }
    }
}
#[tokio::test]
async fn transient_provider_retries_keep_the_operation_and_consume_another_attempt() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let model = TransientModel(std::sync::atomic::AtomicU32::new(0));
    let (report, _) = session
        .run(
            "retry",
            Some("input"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.model_calls, 2);
    let snapshot = snapshot(root.path());
    assert_eq!(snapshot.operations().len(), 1);
    assert_eq!(snapshot.operations().values().next().unwrap().attempts, 2);
}

struct BreakStorage {
    root: PathBuf,
    delivered: std::sync::atomic::AtomicU32,
}
impl ReplOutput for BreakStorage {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {
        std::fs::rename(self.root.join("session"), self.root.join("moved-session")).unwrap();
    }
    fn tool_result(&self, _: &ToolResult, _: &[bee_core::AuditEvent]) {
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}
#[tokio::test]
async fn a_storage_failure_after_execution_releases_no_result_and_requires_reconciliation() {
    let root = tempfile::tempdir().unwrap();
    let running = session(root.path(), None).await;
    let mut registry = registry(root.path(), &running);
    let output = BreakStorage {
        root: root.path().into(),
        delivered: std::sync::atomic::AtomicU32::new(0),
    };
    let result = running
        .run(
            "failure",
            Some("input"),
            "system",
            limits(),
            &model(),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &output,
            None,
        )
        .await;
    assert!(result.is_err());
    let budget = running.budget("failure").await.unwrap().unwrap();
    assert_eq!(budget.charged(bee::session::durable::WorkKind::Tool), 1);
    assert_eq!(budget.unresolved(), 1);
    assert_eq!(
        output.delivered.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    std::fs::rename(
        root.path().join("moved-session"),
        root.path().join("session"),
    )
    .unwrap();
    drop(running);
    let recovered = session(root.path(), None).await;
    assert!(matches!(
        recovered
            .run(
                "failure",
                None,
                "system",
                limits(),
                &model(),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output::default(),
                None
            )
            .await,
        Err(DriverError::Unresolved(_))
    ));
    assert_eq!(
        std::fs::read(root.path().join("effects")).unwrap(),
        b"effect\n"
    );
}

struct GrantTemporaryTool;
#[async_trait::async_trait]
impl bee::hooks::LoopHook for GrantTemporaryTool {
    async fn on_event(&self, event: &bee::hooks::StepEvent<'_>) -> bee::hooks::Flow {
        if matches!(event, bee::hooks::StepEvent::BeforeToolCall(_)) {
            bee::hooks::Flow::Escalate(bee::grants::GrantDelta {
                tools: vec!["give_up".into()],
                ..Default::default()
            })
        } else {
            bee::hooks::Flow::Continue
        }
    }
}
#[tokio::test]
async fn durable_submission_releases_granted_tools_before_reusing_the_sandbox() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let base = bee_core::Policy::from_toml("[policy]\nname='leases'\n").unwrap();
    let hooks = bee::grants::escalate::LoopEscalation {
        base: base.clone(),
        ceiling: base,
        hooks: vec![Box::new(GrantTemporaryTool)],
        operator: bee::operator::Operator::autonomous(Arc::new(bee::operator::NullOutput)),
        default_ttl: bee::grants::Ttl::Forever,
    };
    let model = MockModel::from_fn(|c| {
        if c.messages
            .iter()
            .any(|m| matches!(m, Message::ToolResult { .. }))
        {
            Turn::text("done")
        } else {
            Turn::calls(vec![ToolCall {
                id: "call".into(),
                name: "mutation".into(),
                arguments: json!({}),
            }])
        }
    });
    let mut sandbox = Sandbox::host(vec![]);
    let (report, _) = session
        .run(
            "one",
            Some("work"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut sandbox,
            &Output::default(),
            Some(&hooks),
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::Completed);
    assert!(hooks
        .operator
        .log()
        .iter()
        .any(|d| d.reason == bee::operator::Reason::Granted));
    assert!(
        !registry.contains("give_up"),
        "submission leaked a granted tool into the retained sandbox"
    );
    session
        .run(
            "two",
            Some("continue"),
            "system",
            limits(),
            &model,
            &mut registry,
            &mut sandbox,
            &Output::default(),
            Some(&hooks),
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn shared_driver_refuses_call_scoped_services_before_admitting_work() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let mut sandbox = Sandbox::host(vec![]);
    sandbox.set_env_provider(Box::new(|_| bee::sandbox::EnvOverlay::new(vec![]).unwrap()));
    let result = session
        .run(
            "request",
            Some("work"),
            "system",
            limits(),
            &model(),
            &mut registry,
            &mut sandbox,
            &Output::default(),
            None,
        )
        .await;
    assert!(matches!(result, Err(DriverError::Refused(_))));
    assert!(!root.path().join("effects").exists());
    assert!(session.budget("request").await.unwrap().is_none());
}

#[tokio::test]
async fn library_entrypoints_refuse_unsupported_settings_before_admitting_work() {
    let root = tempfile::tempdir().unwrap();
    let session = session(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let mut sandbox = Sandbox::host(vec![]);
    let mut scenario = scenario();
    scenario.stuck.stop = Some(false);
    let options = LoopOptions {
        durable: Some(RunBinding {
            session: session.clone(),
            request_id: "request".into(),
            resume: false,
            tool_call_limit: 10,
        }),
        ..Default::default()
    };
    let report = bee::run_loop(&model(), &scenario, &mut registry, &mut sandbox, &options).await;
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::InfraError { .. }
    ));
    assert!(session.budget("request").await.unwrap().is_none());
    let config = ReplConfig {
        durable: Some(session.clone()),
        stuck: bee::stuck::ResolvedStuck {
            stop: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = bee::repl::run_exchange(
        "work",
        &model(),
        &mut Conversation::new("system", ""),
        &mut registry,
        &mut sandbox,
        &config,
        &Output::default(),
        &Default::default(),
        None,
    )
    .await;
    assert!(
        matches!(result.outcome, ExchangeOutcome::Terminated(ref detail) if detail.contains("context/stuck"))
    );
    assert!(!root.path().join("effects").exists());
}
