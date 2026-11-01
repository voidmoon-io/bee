#![cfg(feature = "durable-sessions")]
use bee::provider::{mock_model::MockModel, Message, ToolCall, ToolSchema, Turn};
use bee::repl::ReplOutput;
use bee::session::driver::{Limits, Observer, Session};
use bee::session::durable::{Commit, Phase, SessionId, WorkKind};
use bee::tools::{Tool, ToolRegistry, ToolResult};
use bee::Sandbox;
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
struct Output;
impl ReplOutput for Output {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}
// A trusted fixture under an allowed name makes repeated effects observable.
struct Read(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl Tool for Read {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "fixture".into(),
            parameters: json!({"type":"object"}),
        }
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        ToolResult::ok((self.0.fetch_add(1, Ordering::SeqCst) + 1).to_string())
    }
}
fn limits() -> Limits {
    Limits {
        turns: 5,
        tool_calls: 100,
        timeout_ms: 30_000,
        tool_timeout_ms: 10_000,
        model_attempts: 2,
    }
}
fn model(source: &str) -> MockModel {
    let source = source.to_string();
    MockModel::from_fn(move |conversation| {
        if conversation
            .messages
            .iter()
            .any(|m| matches!(m, Message::ToolResult { .. }))
        {
            Turn::text("done")
        } else {
            Turn::calls(vec![ToolCall {
                id: "outer".into(),
                name: "codemode".into(),
                arguments: json!({"source":source}),
            }])
        }
    })
    .with_id("codemode-fixture")
}
const TWO: &str = "a = call_tool('read_file', {})\nb = call_tool('read_file', {'previous': a['content']})\n[a['content'], b['content']]";
async fn open(path: &std::path::Path, observer: Option<Arc<dyn Observer>>) -> Arc<Session> {
    Session::open_observed(
        path.join("session"),
        SessionId("code".into()),
        "config".into(),
        None,
        observer,
    )
    .await
    .unwrap()
}
fn registry(session: &Session, count: Arc<AtomicUsize>) -> ToolRegistry {
    let mut r = ToolRegistry::new().with(Box::new(Read(count)));
    r.enable_evidence(session.evidence());
    r
}

#[tokio::test]
async fn sequential_calls_charge_and_preserve_child_receipts_without_extra_model_messages() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let (report, conversation) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(TWO),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(report.budget.charged(WorkKind::Tool), 3);
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].parent_call_id.as_deref(), Some("outer"));
    assert!(calls[0].result.receipt_id.is_some());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&calls[2].result.content).unwrap()["value"],
        json!([calls[0].result.content, calls[1].result.content])
    );
    assert_eq!(
        conversation
            .messages
            .iter()
            .filter(|m| matches!(m, Message::ToolResult { .. }))
            .count(),
        1
    );
    drop(session);
    let resumed = open(root.path(), None).await;
    resumed
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(TWO),
            &mut registry(&resumed, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

struct Crash {
    point: &'static str,
    fired: AtomicBool,
}
impl Observer for Crash {
    fn committed(&self, commit: &Commit) {
        let s = &commit.snapshot;
        let hit =
            match self.point {
                "worker" => s.driver().is_some_and(|d| {
                    d["active"]["scripts"][0]["runs"] == 1
                        && d["active"]["scripts"][0]["pending"] == serde_json::json!([])
                }),
                "suspend" => s.scripts().values().any(|s| s.suspensions.len() == 1),
                "publishing" => s.operations().values().any(|o| {
                    matches!(o.spec.name.as_str(), "read_file" | "write_file")
                        && matches!(o.phase, Phase::Publishing { .. })
                }),
                "child" => s.operations().values().any(|o| {
                    matches!(o.spec.name.as_str(), "read_file" | "write_file")
                        && matches!(o.phase, Phase::Completed { .. })
                }),
                "root" => s.operations().values().any(|o| {
                    o.spec.name == "codemode" && matches!(o.phase, Phase::Completed { .. })
                }),
                "running-second-child" => {
                    s.operations().values().any(|o| {
                        o.spec.name == "read_file" && matches!(o.phase, Phase::Completed { .. })
                    }) && s.operations().values().any(|o| {
                        o.spec.name == "read_file" && matches!(o.phase, Phase::Running { .. })
                    })
                }
                "running-child" => s.operations().values().any(|o| {
                    matches!(o.spec.name.as_str(), "read_file" | "write_file")
                        && matches!(o.phase, Phase::Running { .. })
                }),
                _ => false,
            };
        if hit && !self.fired.swap(true, Ordering::SeqCst) {
            panic!("injected lost commit acknowledgement: {}", self.point);
        }
    }
}
#[tokio::test]
async fn lost_acknowledgements_restore_without_repeating_committed_calls() {
    for point in ["worker", "suspend", "child", "root"] {
        let root = tempfile::tempdir().unwrap();
        let crash = Arc::new(Crash {
            point,
            fired: AtomicBool::new(false),
        });
        let session = open(root.path(), Some(crash.clone())).await;
        let count = Arc::new(AtomicUsize::new(0));
        let result = session
            .run(
                "request",
                Some("go"),
                "system",
                limits(),
                &model(TWO),
                &mut registry(&session, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await;
        assert!(result.is_err(), "{point}");
        assert!(crash.fired.load(Ordering::SeqCst));
        drop(session);
        let resumed = open(root.path(), None).await;
        let (report, _) = resumed
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(TWO),
                &mut registry(&resumed, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2, "{point}");
        assert_eq!(report.budget.charged(WorkKind::Tool), 3);
        assert_eq!(report.budget.unresolved(), 0);
        assert_eq!(report.turns[0].calls.len(), 3);
        if point == "worker" {
            let body: serde_json::Value =
                serde_json::from_str(&report.turns[0].calls[2].result.content).unwrap();
            assert_eq!(body["worker_invocations"], 4);
            assert!(body["worker_time_charge_ms"].as_u64().unwrap() >= 4_000);
        }
    }
}
#[tokio::test]
async fn uncertain_child_blocks_python_and_never_refunds_its_charge() {
    let root = tempfile::tempdir().unwrap();
    let crash = Arc::new(Crash {
        point: "running-child",
        fired: AtomicBool::new(false),
    });
    let session = open(root.path(), Some(crash)).await;
    let count = Arc::new(AtomicUsize::new(0));
    assert!(session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(TWO),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None
        )
        .await
        .is_err());
    drop(session);
    let resumed = open(root.path(), None).await;
    let events = Events::default();
    let result = resumed
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(TWO),
            &mut registry(&resumed, count.clone()),
            &mut Sandbox::host(vec![]),
            &events,
            None,
        )
        .await;
    assert!(matches!(
        result,
        Err(bee::session::driver::DriverError::Unresolved(_))
    ));
    assert!(events
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.context.parent.is_some()
            && matches!(
                e.outcome,
                bee::repl::presentation::CallOutcome::Unresolved { .. }
            )));
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(
        resumed
            .budget("request")
            .await
            .unwrap()
            .unwrap()
            .charged(WorkKind::Tool),
        2
    );
}
#[tokio::test]
async fn forbidden_calls_errors_and_session_budget_keep_prior_results() {
    for (source, limit, expected_calls) in [
        ("call_tool('bash', {})", 100, 0),
        ("a = call_tool('read_file', {})\n1 / 0", 100, 1),
        (
            "a = call_tool('read_file', {})\ncall_tool('give_up', {})",
            100,
            1,
        ),
        (TWO, 2, 1),
    ] {
        let root = tempfile::tempdir().unwrap();
        let session = open(root.path(), None).await;
        let count = Arc::new(AtomicUsize::new(0));
        let mut bound = limits();
        bound.tool_calls = limit;
        let (report, _) = session
            .run(
                "request",
                Some("go"),
                "system",
                bound,
                &model(source),
                &mut registry(&session, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), expected_calls);
        assert!(report.turns[0].calls.last().unwrap().result.is_error);
        assert_eq!(
            report.turns[0]
                .calls
                .iter()
                .filter(|c| c.parent_call_id.is_some())
                .count(),
            expected_calls
        );
        drop(session);
        open(root.path(), None).await;
    }
}

#[tokio::test]
async fn parent_deadline_cancels_a_running_python_worker_and_survives_reopen() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let mut bound = limits();
    bound.tool_timeout_ms = 50;
    let started = std::time::Instant::now();
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            bound,
            &model("while True: pass"),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(report.status, bee::EpisodeStatus::Timeout));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(session);
    open(root.path(), None).await;
}

struct Block(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl Tool for Block {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn schema(&self) -> ToolSchema {
        Read(self.0.clone()).schema()
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}
#[tokio::test]
async fn cancellation_stops_both_parent_and_child_without_dispatching_the_next_call() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let active = session.clone();
    let calls = count.clone();
    let task = tokio::spawn(async move {
        let mut registry = ToolRegistry::new().with(Box::new(Block(calls)));
        registry.enable_evidence(active.evidence());
        active
            .run(
                "request",
                Some("go"),
                "system",
                limits(),
                &model(TWO),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while count.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    session.cancel().unwrap();
    let (report, _) = task.await.unwrap().unwrap();
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(report.budget.charged(WorkKind::Tool), 2);
    drop(session);
    open(root.path(), None).await;
}

#[tokio::test]
async fn call_limit_and_large_outputs_are_reported_as_script_errors() {
    for (source, expected) in [
        ("for i in range(33):\n    call_tool('read_file', {})", 32),
        ("'x' * 70000", 0),
    ] {
        let root = tempfile::tempdir().unwrap();
        let session = open(root.path(), None).await;
        let count = Arc::new(AtomicUsize::new(0));
        let (report, _) = session
            .run(
                "request",
                Some("go"),
                "system",
                Limits {
                    timeout_ms: 90_000,
                    tool_timeout_ms: 60_000,
                    ..limits()
                },
                &model(source),
                &mut registry(&session, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), expected);
        let outer = report.turns[0].calls.last().unwrap();
        assert!(outer.result.is_error);
        let body: serde_json::Value = serde_json::from_str(&outer.result.content).unwrap();
        assert!(body["worker_invocations"].as_u64().unwrap() > 0);
    }
}

struct CatalogModel(MockModel);
#[async_trait::async_trait]
impl bee::Model for CatalogModel {
    fn id(&self) -> &str {
        self.0.id()
    }
    async fn complete(
        &self,
        conversation: &bee::Conversation,
        tools: &[ToolSchema],
    ) -> Result<Turn, bee::provider::ModelError> {
        let schema = tools
            .iter()
            .find(|s| s.name == "codemode")
            .expect("durable catalog");
        assert!(schema.description.contains("read_file"));
        assert!(!schema.description.contains("write_file"));
        self.0.complete(conversation, tools).await
    }
}
#[tokio::test]
async fn shipping_read_tool_works_through_batch_and_repl() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data.txt");
    std::fs::write(&path, "hello durable python").unwrap();
    let source=format!("a = call_tool('read_file', {{'path': {}}})\nb = call_tool('read_file', {{'path': {}}})\na['content'] == b['content']",json!(path),json!(path));
    // Receipt labels intentionally differ per call, so compare the actual observed text instead.
    let source = source.replace(
        "a['content'] == b['content']",
        "'hello durable python' in a['content'] and 'hello durable python' in b['content']",
    );
    let session = Session::open(
        root.path().join("session"),
        SessionId("code".into()),
        "config".into(),
        Some("request".into()),
    )
    .await
    .unwrap();
    let mut registry = bee::tools::registry_for(&["read_file".into()], None);
    assert!(
        !registry.schemas().iter().any(|s| s.name == "codemode"),
        "ordinary registry must not advertise durable-only scheduling"
    );
    registry.enable_evidence(session.evidence());
    let model = CatalogModel(model(&source));
    let scenario = bee::Scenario {
        context: Default::default(),
        stuck: Default::default(),
        lease_turns: None,
        finish: false,
        id: "code".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "system".into(),
        task: "read twice".into(),
        turn_limit: 5,
        timeout_secs: 30,
        tools: vec!["read_file".into()],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: vec![],
        ceiling_policy_path: None,
        security: Default::default(),
    };
    let options = bee::LoopOptions {
        durable: Some(bee::session::driver::RunBinding {
            session: session.clone(),
            request_id: "request".into(),
            resume: false,
            tool_call_limit: 100,
        }),
        ..Default::default()
    };
    let batch = bee::run_loop(
        &model,
        &scenario,
        &mut registry,
        &mut Sandbox::host(vec![]),
        &options,
    )
    .await;
    assert!(
        matches!(batch.status, bee::EpisodeStatus::Completed),
        "{:?}",
        batch.status
    );
    assert_eq!(batch.turns[0].calls.len(), 3);
    let value: serde_json::Value =
        serde_json::from_str(&batch.turns[0].calls[2].result.content).unwrap();
    assert_eq!(value["value"], true);
    let config = bee::ReplConfig {
        durable: Some(session.clone()),
        system_prompt: "system".into(),
        ..Default::default()
    };
    let mut conversation = bee::Conversation::default();
    let repl = bee::repl::run_exchange(
        "",
        &model,
        &mut conversation,
        &mut registry,
        &mut Sandbox::host(vec![]),
        &config,
        &Output,
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(
        serde_json::to_value(repl.turns).unwrap(),
        serde_json::to_value(batch.turns).unwrap()
    );
    let fresh = open(&root.path().join("fresh"), None).await;
    let mut fresh_registry = bee::tools::registry_for(&["read_file".into()], None);
    fresh_registry.enable_evidence(fresh.evidence());
    let config = bee::ReplConfig {
        durable: Some(fresh),
        system_prompt: "system".into(),
        ..Default::default()
    };
    let fresh_repl = bee::repl::run_exchange(
        "read twice",
        &model,
        &mut bee::Conversation::default(),
        &mut fresh_registry,
        &mut Sandbox::host(vec![]),
        &config,
        &Output,
        &Default::default(),
        None,
    )
    .await;
    assert_eq!(fresh_repl.turns[0].calls.len(), 3);
    let result: serde_json::Value =
        serde_json::from_str(&fresh_repl.turns[0].calls[2].result.content).unwrap();
    assert_eq!(result["value"], true);
}

struct ChangedRead(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl Tool for ChangedRead {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn schema(&self) -> ToolSchema {
        Read(self.0.clone()).schema()
    }
    fn durable_contract(&self) -> bee::tools::ToolContract {
        bee::tools::ToolContract {
            version: 2,
            recovery: bee::session::durable::RecoveryPolicy::NeverReplay,
        }
    }
    async fn call(&self, args: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        Read(self.0.clone()).call(args, sandbox).await
    }
}
#[tokio::test]
async fn changed_tool_contract_refuses_a_saved_python_continuation() {
    let root = tempfile::tempdir().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let session = open(
        root.path(),
        Some(Arc::new(Crash {
            point: "suspend",
            fired: AtomicBool::new(false),
        })),
    )
    .await;
    assert!(session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(TWO),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None
        )
        .await
        .is_err());
    drop(session);
    let resumed = open(root.path(), None).await;
    let mut changed = ToolRegistry::new().with(Box::new(ChangedRead(count.clone())));
    changed.enable_evidence(resumed.evidence());
    let result = resumed
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(TWO),
            &mut changed,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await;
    assert!(matches!(
        result,
        Err(bee::session::driver::DriverError::Incompatible)
    ));
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

// Inject loss after the shipping mutation returns, before durable completion.
struct WriteFixture {
    lose_result: bool,
}
#[async_trait::async_trait]
impl Tool for WriteFixture {
    fn name(&self) -> &'static str {
        "write_file"
    }
    fn schema(&self) -> ToolSchema {
        let mut schema = bee::tools::files::WriteFile.schema();
        schema.name = self.name().into();
        schema
    }
    fn durable_contract(&self) -> bee::tools::ToolContract {
        bee::tools::files::WriteFile.durable_contract()
    }
    async fn call(&self, args: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let result = bee::tools::files::WriteFile.call(args, sandbox).await;
        assert!(!result.is_error, "{}", result.content);
        if self.lose_result {
            panic!("lost result after actual tee write");
        }
        result
    }
}
fn write_registry(session: &Session, lose_result: bool) -> ToolRegistry {
    let mut registry = ToolRegistry::new().with(Box::new(WriteFixture { lose_result }));
    registry.enable_evidence(session.evidence());
    registry
}
#[tokio::test]
async fn shipping_write_recovery_preserves_effects_and_blocks_ambiguity() {
    use futures_util::FutureExt;
    for point in [
        "suspend",
        "running-child",
        "effect",
        "publishing",
        "child",
        "root",
    ] {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        let code = format!("a = call_tool('write_file', {{'path': {}, 'content': 'FIRST'}})\ncall_tool('write_file', {{'path': {}, 'content': a['content']}})", json!(first), json!(second));
        let crash = Arc::new(Crash {
            point,
            fired: AtomicBool::new(false),
        });
        let session = open(root.path(), Some(crash.clone())).await;
        assert!(matches!(
            bee::tools::files::WriteFile.durable_contract().recovery,
            bee::session::durable::RecoveryPolicy::NeverReplay
        ));
        let result = std::panic::AssertUnwindSafe(session.run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&code),
            &mut write_registry(&session, point == "effect"),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        ))
        .catch_unwind()
        .await;
        assert!(result.is_err() || result.unwrap().is_err(), "{point}");
        if point != "effect" {
            assert!(crash.fired.load(Ordering::SeqCst));
        }
        let effect_happened = matches!(point, "effect" | "publishing" | "child" | "root");
        assert_eq!(first.exists(), effect_happened, "{point}");
        if effect_happened {
            assert_eq!(std::fs::read_to_string(&first).unwrap(), "FIRST");
            std::fs::write(&first, "CHANGED AFTER CRASH").unwrap();
        }
        if point != "root" {
            assert!(!second.exists(), "{point}");
        }
        drop(session);
        let resumed = open(root.path(), None).await;
        let result = resumed
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(&code),
                &mut write_registry(&resumed, false),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await;
        if matches!(point, "effect" | "running-child") {
            assert!(
                matches!(
                    result,
                    Err(bee::session::driver::DriverError::Unresolved(_))
                ),
                "{point}: {result:?}"
            );
            assert!(!second.exists());
            assert_eq!(
                resumed
                    .budget("request")
                    .await
                    .unwrap()
                    .unwrap()
                    .charged(WorkKind::Tool),
                2
            );
        } else {
            let (report, _) = result.unwrap();
            assert_eq!(report.budget.charged(WorkKind::Tool), 3);
            assert_eq!(report.budget.unresolved(), 0);
            assert!(std::fs::read_to_string(&second)
                .unwrap()
                .contains("wrote 5 bytes"));
            assert!(report.turns[0].calls[..2]
                .iter()
                .all(|c| c.result.receipt_id.is_some()));
        }
        if effect_happened {
            assert_eq!(
                std::fs::read_to_string(&first).unwrap(),
                "CHANGED AFTER CRASH"
            );
        }
    }
}

#[tokio::test]
async fn shipping_write_catalog_and_sequential_read() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let mut registry = bee::tools::registry_for(&["write_file".into(), "read_file".into()], None);
    registry.enable_evidence(session.evidence());
    let path = root.path().join("written");
    let code = format!("a = call_tool('write_file', {{'path': {}, 'content': 'durable mutation'}})\nb = call_tool('read_file', {{'path': {}}})\n'durable mutation' in b['content']", json!(path), json!(path));
    let events = Events::default();
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&code),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &events,
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.budget.charged(WorkKind::Tool), 3);
    let calls = &report.turns[0].calls;
    assert_eq!(calls[0].call.name, "write_file");
    assert!(calls[..2]
        .iter()
        .all(|c| !c.result.is_error && c.result.receipt_id.is_some()));
    let value: serde_json::Value = serde_json::from_str(&calls[2].result.content).unwrap();
    assert_eq!(value["value"], true);
    let events = events.0.lock().unwrap();
    let children: Vec<_> = events
        .iter()
        .filter(|e| {
            e.context.parent.is_some()
                && matches!(
                    e.outcome,
                    bee::repl::presentation::CallOutcome::Completed { .. }
                )
        })
        .collect();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].call.name, "write_file");
    assert_eq!(children[1].call.name, "read_file");
    assert!(children.iter().all(|e| e.text().contains("receipt:")));
}

#[tokio::test]
async fn shipping_shell_effect_is_receipted_and_not_repeated_on_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("shell-effect");
    let command = format!("printf x >> '{}'", path.display());
    let source = format!("call_tool('bash', {{'command': {}}})", json!(command));
    for replay in [false, true] {
        let session = open(root.path(), None).await;
        let mut registry = bee::tools::registry_for(&["bash".into()], None);
        registry.enable_evidence(session.evidence());
        let spec = registry
            .durable_spec(
                &ToolCall {
                    id: "contract".into(),
                    name: "bash".into(),
                    arguments: json!({}),
                },
                "config",
                1,
            )
            .unwrap();
        assert_eq!(
            spec.recovery,
            bee::session::durable::RecoveryPolicy::NeverReplay
        );
        let (report, conversation) = session
            .run(
                "request",
                if replay { None } else { Some("go") },
                "system",
                limits(),
                &model(&source),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap();
        assert_eq!(report.budget.charged(WorkKind::Tool), 2);
        let calls = &report.turns[0].calls;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].call.name, "bash");
        assert_eq!(calls[0].parent_call_id.as_deref(), Some("outer"));
        assert!(!calls[0].result.is_error);
        assert!(calls[0].result.receipt_id.is_some());
        assert_eq!(
            conversation
                .messages
                .iter()
                .filter(|m| matches!(m, Message::ToolResult { .. }))
                .count(),
            1
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
    }
}

#[derive(Default)]
struct Events(std::sync::Mutex<Vec<bee::repl::presentation::CallEvent>>);
impl ReplOutput for Events {
    fn tool_event(&self, event: &bee::repl::presentation::CallEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}

#[tokio::test]
async fn grouped_events_preserve_children_and_receipts_on_live_and_replay() {
    use bee::repl::presentation::CallOutcome;
    let nested = format!(
        "call_tool('codemode', {{'source': {}}})",
        json!(format!(
            "call_tool('codemode', {{'source': {}}})",
            json!(TWO)
        ))
    );
    for source in [TWO, "call_tool('read_file', {})\n1 / 0", nested.as_str()] {
        let root = tempfile::tempdir().unwrap();
        let session = open(root.path(), None).await;
        let count = Arc::new(AtomicUsize::new(0));
        let live = Events::default();
        session
            .run(
                "grouped",
                Some("go"),
                "system",
                limits(),
                &model(source),
                &mut registry(&session, count.clone()),
                &mut Sandbox::host(vec![]),
                &live,
                None,
            )
            .await
            .unwrap();
        drop(session);
        let reopened = open(root.path(), None).await;
        let replay = Events::default();
        reopened
            .run(
                "grouped",
                Some("go"),
                "system",
                limits(),
                &model(source),
                &mut registry(&reopened, count.clone()),
                &mut Sandbox::host(vec![]),
                &replay,
                None,
            )
            .await
            .unwrap();
        let completed = |events: &Events| {
            events
                .0
                .lock()
                .unwrap()
                .iter()
                .filter_map(|event| {
                    if let CallOutcome::Completed { result, .. } = &event.outcome {
                        Some((
                            event.context.invocation.clone(),
                            event.context.parent.clone(),
                            result.content.clone(),
                            result.receipt_id.clone(),
                            event.context.depth,
                            event.text().replace(" [replay]", ""),
                        ))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        let original = completed(&live);
        assert_eq!(original, completed(&replay));
        if source == nested {
            assert_eq!(original[0].4, 3);
        }
        assert!(original[0].1.is_some());
        assert!(original[0].3.is_some());
        assert!(original.last().unwrap().1.is_none());
        assert!(replay.0.lock().unwrap().iter().all(|e| e.context.replay));
    }
}

#[tokio::test]
async fn unresolved_recovery_exposes_validated_prior_children_in_partial_report() {
    let root = tempfile::tempdir().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let session = open(
        root.path(),
        Some(Arc::new(Crash {
            point: "running-second-child",
            fired: AtomicBool::new(false),
        })),
    )
    .await;
    assert!(session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(TWO),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None
        )
        .await
        .is_err());
    drop(session);
    let session = open(root.path(), None).await;
    let mut registry = registry(&session, count.clone());
    let events = Events::default();
    assert!(matches!(
        session
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(TWO),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &events,
                None
            )
            .await,
        Err(bee::session::driver::DriverError::Unresolved(_))
    ));
    let partial = session
        .partial_report("request", &registry)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(partial.turns[0].calls.len(), 1);
    assert!(partial.turns[0].calls[0].result.receipt_id.is_some());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let events = events.0.lock().unwrap();
    assert!(events.iter().any(|e| matches!(
        e.outcome,
        bee::repl::presentation::CallOutcome::Completed { .. }
    )));
    assert!(events.iter().any(|e| matches!(
        e.outcome,
        bee::repl::presentation::CallOutcome::Unresolved { .. }
    )));
}

/// Leaf contents carry a receipt header line; compare only the tool output.
fn contents(body: &serde_json::Value) -> Vec<String> {
    body["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().rsplit('\n').next().unwrap().to_string())
        .collect()
}

const BATCH: &str = "r = call_tools([{'name': 'read_file', 'arguments': {'i': 1}}, {'name': 'read_file', 'arguments': {'i': 2}}, {'name': 'read_file', 'arguments': {'i': 3}}])\n[x['content'] for x in r]";

#[tokio::test]
async fn batch_admits_children_together_and_resumes_with_ordered_results() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let (report, conversation) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(BATCH),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(report.budget.charged(WorkKind::Tool), 4);
    let calls = &report.turns[0].calls;
    let ids: Vec<_> = calls.iter().map(|c| c.call.id.as_str()).collect();
    assert_eq!(ids, ["outer/1", "outer/2", "outer/3", "outer"]);
    assert!(calls[..3]
        .iter()
        .all(|c| c.parent_call_id.as_deref() == Some("outer") && c.result.receipt_id.is_some()));
    let body: serde_json::Value = serde_json::from_str(&calls[3].result.content).unwrap();
    assert_eq!(contents(&body), ["1", "2", "3"]);
    assert_eq!(body["worker_invocations"], 2);
    assert_eq!(
        conversation
            .messages
            .iter()
            .filter(|m| matches!(m, Message::ToolResult { .. }))
            .count(),
        1
    );
}

struct Batch {
    point: &'static str,
    fired: AtomicBool,
}
impl Observer for Batch {
    fn committed(&self, commit: &Commit) {
        let s = &commit.snapshot;
        let completed = s
            .operations()
            .values()
            .filter(|o| o.spec.name == "read_file" && matches!(o.phase, Phase::Completed { .. }))
            .count();
        let hit = match self.point {
            // All three children are admitted by the same commit as the checkpoint.
            "admitted" => s
                .scripts()
                .values()
                .any(|s| s.suspensions.last().is_some_and(|l| l.children.len() == 3)),
            "first-result" => completed == 1,
            "second-result" => completed == 2,
            "all-results" => completed == 3,
            _ => false,
        };
        if hit && !self.fired.swap(true, Ordering::SeqCst) {
            panic!("injected lost commit acknowledgement: {}", self.point);
        }
    }
}

#[tokio::test]
async fn batch_crashes_never_repeat_completed_siblings() {
    for point in ["admitted", "first-result", "second-result", "all-results"] {
        let root = tempfile::tempdir().unwrap();
        let crash = Arc::new(Batch {
            point,
            fired: AtomicBool::new(false),
        });
        let session = open(root.path(), Some(crash.clone())).await;
        let count = Arc::new(AtomicUsize::new(0));
        let result = session
            .run(
                "request",
                Some("go"),
                "system",
                limits(),
                &model(BATCH),
                &mut registry(&session, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await;
        assert!(result.is_err(), "{point}");
        assert!(crash.fired.load(Ordering::SeqCst), "{point}");
        let before = count.load(Ordering::SeqCst);
        drop(session);
        let resumed = open(root.path(), None).await;
        let (report, _) = resumed
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(BATCH),
                &mut registry(&resumed, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "{point} ran {before} before"
        );
        assert_eq!(report.budget.charged(WorkKind::Tool), 4, "{point}");
        assert_eq!(report.budget.unresolved(), 0, "{point}");
        let outer = report.turns[0].calls.last().unwrap();
        let body: serde_json::Value = serde_json::from_str(&outer.result.content).unwrap();
        assert_eq!(contents(&body), ["1", "2", "3"], "{point}");
    }
}

#[tokio::test]
async fn nested_scripts_share_limits_and_keep_ancestry() {
    let inner = "call_tool('read_file', {'inner': True})['content']";
    let middle = format!(
        "x = call_tool('codemode', {{'source': {}}})\n[x['content'], call_tool('read_file', {{}})['content']]",
        json!(inner)
    );
    let outer = format!(
        "call_tool('codemode', {{'source': {}}})['content']",
        json!(middle)
    );
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let (report, conversation) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&outer),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // Root, two nested scripts and two leaves each charge once.
    assert_eq!(report.budget.charged(WorkKind::Tool), 5);
    let calls: Vec<_> = report.turns[0]
        .calls
        .iter()
        .map(|c| (c.call.id.as_str(), c.parent_call_id.as_deref()))
        .collect();
    assert_eq!(
        calls,
        [
            ("outer/1/1/1", Some("outer/1/1")),
            ("outer/1/1", Some("outer/1")),
            ("outer/1/2", Some("outer/1")),
            ("outer/1", Some("outer")),
            ("outer", None),
        ]
    );
    let body: serde_json::Value =
        serde_json::from_str(&report.turns[0].calls[4].result.content).unwrap();
    assert_eq!(body["status"], "completed");
    // One root, two nested worker starts and resumes: 2 + 3 + 2.
    assert_eq!(body["worker_invocations"], 7);
    assert_eq!(
        conversation
            .messages
            .iter()
            .filter(|m| matches!(m, Message::ToolResult { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn nesting_depth_is_bounded() {
    // Five levels: the fourth level's codemode request is refused.
    let mut source = "1".to_string();
    for _ in 0..4 {
        source = format!(
            "r = call_tool('codemode', {{'source': {}}})\nr",
            json!(source)
        );
    }
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&source),
            &mut registry(&session, count),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    let calls = &report.turns[0].calls;
    let deepest = calls.iter().find(|c| c.call.id == "outer/1/1/1").unwrap();
    assert!(deepest.result.is_error, "{}", deepest.result.content);
    assert!(deepest.result.content.contains("nesting limit"));
    assert!(calls.iter().all(|c| c.call.id.matches('/').count() <= 3));
}

struct When {
    hit: Box<dyn Fn(&Commit) -> bool + Send + Sync>,
    fired: AtomicBool,
}
impl Observer for When {
    fn committed(&self, commit: &Commit) {
        if (self.hit)(commit) && !self.fired.swap(true, Ordering::SeqCst) {
            panic!("injected lost commit acknowledgement");
        }
    }
}

fn nested_source() -> String {
    let inner = "a = call_tool('read_file', {'n': 1})['content']\nb = call_tools([{'name': 'read_file', 'arguments': {'n': 2}}, {'name': 'read_file', 'arguments': {'n': 3}}])\n[a] + [x['content'] for x in b]";
    format!(
        "r = call_tool('codemode', {{'source': {}}})\n[r['content'], call_tool('read_file', {{'n': 4}})['content']]",
        json!(inner)
    )
}

#[tokio::test]
async fn nested_crashes_preserve_ancestry_and_never_repeat_effects() {
    type Point = fn(&Commit) -> bool;
    let points: [(&str, Point); 5] = [
        ("nested-started", |c| c.snapshot.scripts().len() == 2),
        ("nested-batch-admitted", |c| {
            c.snapshot
                .scripts()
                .values()
                .any(|s| s.parent.is_some() && s.suspensions.len() == 2)
        }),
        ("nested-finished", |c| {
            c.snapshot.scripts().values().any(|s| {
                s.parent.is_some()
                    && matches!(
                        s.phase,
                        bee::session::durable::composition::ScriptPhase::Completed(_)
                    )
            })
        }),
        ("nested-op-completed", |c| {
            c.snapshot.operations().iter().any(|(id, o)| {
                o.spec.name == "codemode" && id.0 > 1 && matches!(o.phase, Phase::Completed { .. })
            })
        }),
        ("parent-leaf-running", |c| {
            c.snapshot.operations().values().any(|o| {
                o.spec.input["call"]["arguments"]["n"] == 4
                    && matches!(o.phase, Phase::Running { .. })
            })
        }),
    ];
    for (name, point) in points {
        let root = tempfile::tempdir().unwrap();
        let crash = Arc::new(When {
            hit: Box::new(point),
            fired: AtomicBool::new(false),
        });
        let session = open(root.path(), Some(crash.clone())).await;
        let count = Arc::new(AtomicUsize::new(0));
        let source = nested_source();
        let result = session
            .run(
                "request",
                Some("go"),
                "system",
                limits(),
                &model(&source),
                &mut registry(&session, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await;
        assert!(result.is_err(), "{name}");
        assert!(crash.fired.load(Ordering::SeqCst), "{name}");
        drop(session);
        let resumed = open(root.path(), None).await;
        let result = resumed
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(&source),
                &mut registry(&resumed, count.clone()),
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await;
        if name == "parent-leaf-running" {
            // The authorization ack was lost: the leaf's outcome is unknown, so it never reruns.
            assert!(
                matches!(
                    result,
                    Err(bee::session::driver::DriverError::Unresolved(_))
                ),
                "{name}"
            );
            assert_eq!(count.load(Ordering::SeqCst), 3, "{name}");
            continue;
        }
        let (report, _) = result.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4, "{name}");
        assert_eq!(report.budget.charged(WorkKind::Tool), 6, "{name}");
        assert_eq!(report.budget.unresolved(), 0, "{name}");
        let calls: Vec<_> = report.turns[0]
            .calls
            .iter()
            .map(|c| (c.call.id.as_str(), c.parent_call_id.as_deref()))
            .collect();
        assert_eq!(
            calls,
            [
                ("outer/1/1", Some("outer/1")),
                ("outer/1/2", Some("outer/1")),
                ("outer/1/3", Some("outer/1")),
                ("outer/1", Some("outer")),
                ("outer/2", Some("outer")),
                ("outer", None),
            ],
            "{name}"
        );
        let body: serde_json::Value =
            serde_json::from_str(&report.turns[0].calls[5].result.content).unwrap();
        assert_eq!(body["status"], "completed", "{name}");
    }
}

#[tokio::test]
async fn nested_failure_is_a_result_and_keeps_prior_receipts() {
    let inner = "call_tool('read_file', {})\n1 / 0";
    let source = format!(
        "r = call_tool('codemode', {{'source': {}}})\n[r['is_error'], r['content']]",
        json!(inner)
    );
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&source),
            &mut registry(&session, count.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3);
    assert!(calls[0].result.receipt_id.is_some());
    assert!(calls[1].result.is_error);
    assert_eq!(calls[1].parent_call_id.as_deref(), Some("outer"));
    let body: serde_json::Value = serde_json::from_str(&calls[2].result.content).unwrap();
    assert_eq!(body["status"], "completed");
    assert_eq!(body["value"][0], true);
}

#[tokio::test]
async fn cancellation_inside_a_nested_batch_stops_every_level_and_admits_nothing_new() {
    let inner = "call_tools([{'name': 'read_file', 'arguments': {'n': 1}}, {'name': 'read_file', 'arguments': {'n': 2}}])";
    let source = format!(
        "call_tool('codemode', {{'source': {}}})\ncall_tool('read_file', {{'n': 3}})",
        json!(inner)
    );
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let count = Arc::new(AtomicUsize::new(0));
    let active = session.clone();
    let calls = count.clone();
    let task = tokio::spawn(async move {
        let mut registry = ToolRegistry::new().with(Box::new(Block(calls)));
        registry.enable_evidence(active.evidence());
        active
            .run(
                "request",
                Some("go"),
                "system",
                limits(),
                &model(&source),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while count.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    session.cancel().unwrap();
    let (report, _) = task.await.unwrap().unwrap();
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    // Both overlapped batch leaves ran; the parent's next call never dispatched.
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // Root, nested script and the two leaf attempts.
    assert_eq!(report.budget.charged(WorkKind::Tool), 4);
    let calls: Vec<_> = report.turns[0]
        .calls
        .iter()
        .map(|c| {
            (
                c.call.id.as_str(),
                c.parent_call_id.as_deref(),
                c.result.is_error,
            )
        })
        .collect();
    assert_eq!(
        calls,
        [
            ("outer/1/1", Some("outer/1"), true),
            ("outer/1/2", Some("outer/1"), true),
            ("outer/1", Some("outer"), true),
            ("outer", None, true),
        ]
    );
    drop(session);
    open(root.path(), None).await;
}

/// Overlap probe: records concurrency and completion order. `wait` blocks until `need`
/// calls are in flight together, failing instead of deadlocking when execution is serial.
#[derive(Default)]
struct Probe {
    started: AtomicUsize,
    inflight: AtomicUsize,
    peak: AtomicUsize,
    order: std::sync::Mutex<Vec<u64>>,
}
struct Overlap(Arc<Probe>);
#[async_trait::async_trait]
impl Tool for Overlap {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "fixture".into(),
            parameters: json!({"type":"object"}),
        }
    }
    async fn call(&self, arguments: serde_json::Value, _: &Sandbox) -> ToolResult {
        let p = &self.0;
        p.started.fetch_add(1, Ordering::SeqCst);
        let now = p.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        p.peak.fetch_max(now, Ordering::SeqCst);
        let need = arguments["need"].as_u64().unwrap_or(1) as usize;
        let met = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while p.peak.load(Ordering::SeqCst) < need {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .is_ok();
        if let Some(ms) = arguments["sleep"].as_u64() {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        if arguments["block"] == true {
            std::future::pending::<()>().await;
        }
        let n = arguments["n"].as_u64().unwrap_or(0);
        p.order.lock().unwrap().push(n);
        p.inflight.fetch_sub(1, Ordering::SeqCst);
        if met {
            ToolResult::ok(n.to_string())
        } else {
            ToolResult::error("no overlap")
        }
    }
}
fn overlap_registry(session: &Session, probe: Arc<Probe>) -> ToolRegistry {
    let mut r = ToolRegistry::new().with(Box::new(Overlap(probe)));
    r.enable_evidence(session.evidence());
    r
}
fn batch_source(arguments: &[serde_json::Value]) -> String {
    let calls: Vec<_> = arguments
        .iter()
        .map(|a| json!({"name": "read_file", "arguments": a}))
        .collect();
    format!(
        "r = call_tools({})\n[[x['is_error'], x['content']] for x in r]",
        serde_json::to_string(&calls)
            .unwrap()
            .replace("true", "True")
    )
}

#[tokio::test]
async fn batch_leaves_overlap_and_keep_input_order_when_completion_reverses() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let probe = Arc::new(Probe::default());
    // The first call needs its sibling in flight and then finishes last.
    let source = batch_source(&[
        json!({"n": 1, "need": 2, "sleep": 150}),
        json!({"n": 2, "need": 2}),
    ]);
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&source),
            &mut overlap_registry(&session, probe.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(probe.peak.load(Ordering::SeqCst), 2);
    assert_eq!(*probe.order.lock().unwrap(), [2, 1]);
    let calls = &report.turns[0].calls;
    let ids: Vec<_> = calls.iter().map(|c| c.call.id.as_str()).collect();
    assert_eq!(ids, ["outer/1", "outer/2", "outer"]);
    assert!(calls[..2].iter().all(|c| c.result.receipt_id.is_some()));
    let body: serde_json::Value = serde_json::from_str(&calls[2].result.content).unwrap();
    let values: Vec<_> = body["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            assert_eq!(v[0], false, "{v}");
            v[1].as_str()
                .unwrap()
                .rsplit('\n')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(values, ["1", "2"]);
    assert_eq!(report.budget.charged(WorkKind::Tool), 3);
}

#[tokio::test]
async fn batch_width_is_four() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let probe = Arc::new(Probe::default());
    let args: Vec<_> = (1..=4).map(|n| json!({"n": n, "need": 4})).collect();
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&batch_source(&args)),
            &mut overlap_registry(&session, probe.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(probe.peak.load(Ordering::SeqCst), 4);
    assert!(report.turns[0].calls[..4]
        .iter()
        .all(|c| !c.result.is_error));
    // A fifth call is rejected by the guest before any admission.
    let args: Vec<_> = (1..=5).map(|n| json!({"n": n})).collect();
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let probe = Arc::new(Probe::default());
    let (report, _) = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&batch_source(&args)),
            &mut overlap_registry(&session, probe.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(probe.started.load(Ordering::SeqCst), 0);
    assert!(report.turns[0].calls[0].result.is_error);
}

#[tokio::test]
async fn cancelling_overlapped_leaves_cleans_every_sibling() {
    let root = tempfile::tempdir().unwrap();
    let session = open(root.path(), None).await;
    let probe = Arc::new(Probe::default());
    let source = batch_source(&[
        json!({"n": 1, "block": true}),
        json!({"n": 2, "block": true}),
        json!({"n": 3, "block": true}),
    ]);
    let active = session.clone();
    let tool = probe.clone();
    let task = tokio::spawn(async move {
        let mut registry = overlap_registry(&active, tool);
        active
            .run(
                "request",
                Some("go"),
                "system",
                limits(),
                &model(&source),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while probe.started.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    session.cancel().unwrap();
    let (report, _) = task.await.unwrap().unwrap();
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(report.budget.charged(WorkKind::Tool), 4);
    drop(session);
    // Reopen validates: no sibling is left cancelling without cleanup.
    let reopened = open(root.path(), None).await;
    drop(reopened);
}

#[tokio::test]
async fn crash_during_overlap_keeps_completed_siblings_and_blocks_on_ambiguity() {
    let root = tempfile::tempdir().unwrap();
    let crash = Arc::new(When {
        // One sibling's result is committed while the other is still running.
        hit: Box::new(|c: &Commit| {
            let ops = c.snapshot.operations();
            ops.values()
                .any(|o| matches!(o.phase, Phase::Publishing { .. }))
                && ops
                    .values()
                    .any(|o| o.spec.name == "read_file" && matches!(o.phase, Phase::Running { .. }))
        }),
        fired: AtomicBool::new(false),
    });
    let session = open(root.path(), Some(crash.clone())).await;
    let probe = Arc::new(Probe::default());
    let source = batch_source(&[json!({"n": 1, "need": 2}), json!({"n": 2, "need": 2})]);
    let result = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&source),
            &mut overlap_registry(&session, probe.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await;
    assert!(result.is_err());
    assert_eq!(probe.started.load(Ordering::SeqCst), 2);
    drop(session);
    let resumed = open(root.path(), None).await;
    let result = resumed
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(&source),
            &mut overlap_registry(&resumed, probe.clone()),
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await;
    // The second sibling's result was never committed; its outcome is unknown and never rerun.
    assert!(
        matches!(
            result,
            Err(bee::session::driver::DriverError::Unresolved(_))
        ),
        "{result:?}"
    );
    assert_eq!(probe.started.load(Ordering::SeqCst), 2);
}
