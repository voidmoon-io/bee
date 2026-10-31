#![cfg(all(feature = "durable-sessions", feature = "enforce"))]
use bee::provider::mock_model::MockModel;
use bee::provider::{Message, ToolCall, ToolSchema, Turn};
use bee::session::driver::{Limits, Session};
use bee::session::durable::{RecoveryPolicy, SessionId};
use bee::tools::{Tool, ToolContract, ToolRegistry, ToolResult};
use bee::Sandbox;
use serde_json::json;
use std::path::{Path, PathBuf};

fn sandbox() -> Sandbox {
    use bee_userspace::{EnforcementPlan, Engine, ScopeMode, SystemResolver};
    let policy = bee_core::Policy::from_toml("[policy]\nname='durable-kernel'\n").unwrap();
    let plan = EnforcementPlan::prepare(
        &policy.compile(&SystemResolver::current()).unwrap(),
        ScopeMode::Enforce,
    )
    .unwrap();
    let mut engine = Engine::init().expect("BPF-LSM kernel and root required");
    let scope = engine
        .create_scope(
            &format!("durable-{}", std::process::id()),
            bee_userspace::cgroup::DEFAULT_PARENT,
            &plan,
        )
        .unwrap();
    let reader = engine.take_audit_reader("durable-kernel").unwrap();
    Sandbox::enforced(engine, scope, reader, vec![])
}
struct RetryRead(PathBuf);
#[async_trait::async_trait]
impl Tool for RetryRead {
    fn name(&self) -> &'static str {
        "retry_read"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "trusted retry fixture".into(),
            parameters: json!({"type":"object"}),
        }
    }
    fn durable_contract(&self) -> ToolContract {
        ToolContract {
            version: 1,
            recovery: RecoveryPolicy::RetrySafe { max_attempts: 2 },
        }
    }
    async fn call(&self, _: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        if self.0.join("ready").exists() {
            let old_scope = std::fs::read_to_string(self.0.join("scope")).unwrap();
            let events =
                std::fs::read_to_string(Path::new(&old_scope).join("cgroup.events")).unwrap();
            assert!(
                events.lines().any(|line| line == "populated 0"),
                "replacement ran while old executor was populated"
            );
            if !self.0.join("hold-replacement").exists() {
                std::fs::write(self.0.join("resumed"), "old scope was empty").unwrap();
                return ToolResult::ok("reconciled read");
            }
        }
        let suffix = if self.0.join("ready").exists() {
            "2"
        } else {
            ""
        };
        if let Sandbox::Enforced(scope) = sandbox {
            std::fs::write(
                self.0.join(format!("scope{suffix}")),
                scope.scope.path.to_str().unwrap(),
            )
            .unwrap();
        }
        let script = format!(
            "setsid sh -c 'echo $$ > {0}/pid{suffix}; touch {0}/ready{suffix}; while :; do sleep 1; done' & wait",
            self.0.display()
        );
        bee::tools::exec::run_child(sandbox, "/bin/sh", &["-c".into(), script], None, 4096).await
    }
}
struct Output;
impl bee::repl::ReplOutput for Output {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}
fn model() -> MockModel {
    MockModel::from_fn(|c| {
        if c.messages
            .iter()
            .any(|m| matches!(m, Message::ToolResult { .. }))
        {
            Turn::text("finished")
        } else {
            Turn::calls(vec![ToolCall {
                id: "call".into(),
                name: "retry_read".into(),
                arguments: json!({}),
            }])
        }
    })
}
async fn run(root: &Path) -> bee::session::driver::Report {
    run_with(root, None).await
}
async fn run_with(
    root: &Path,
    hooks: Option<&bee::grants::escalate::LoopEscalation>,
) -> bee::session::driver::Report {
    let base = bee_core::Policy::from_toml("[policy]\nname='durable-kernel'\n").unwrap();
    let baseline = bee::grants::escalate::LoopEscalation {
        ceiling: base.clone(),
        base,
        hooks: vec![],
        operator: bee::operator::Operator::autonomous(std::sync::Arc::new(
            bee::operator::NullOutput,
        )),
        default_ttl: bee::grants::Ttl::Forever,
    };
    let hooks = Some(hooks.unwrap_or(&baseline));
    let session = Session::open(
        root.join("session"),
        SessionId("kernel".into()),
        "kernel-fixture".into(),
        None,
    )
    .await
    .unwrap();
    let mut registry = ToolRegistry::new().with(Box::new(RetryRead(root.into())));
    registry.enable_evidence(session.evidence());
    let mut sandbox = sandbox();
    let (report, _) = session
        .run(
            "request",
            Some("read"),
            "system",
            Limits {
                turns: 4,
                tool_calls: 3,
                model_attempts: 2,
                timeout_ms: 60_000,
                tool_timeout_ms: if root.join("short-tool").exists() {
                    5_000
                } else {
                    60_000
                },
            },
            &model(),
            &mut registry,
            &mut sandbox,
            &Output,
            hooks,
        )
        .await
        .unwrap();
    sandbox.teardown().unwrap();
    report
}
#[tokio::test]
#[ignore = "subprocess fixture for the enforced recovery test"]
async fn kernel_child() {
    run(Path::new(&std::env::var("BEE_KERNEL_ROOT").unwrap())).await;
    panic!("expected SIGKILL");
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel; run in the VM"]
async fn kernel_recovery_stops_detached_descendants_before_replacement() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .split(',')
        .any(|s| s.trim() == "bpf"));
    let root = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "kernel_child", "--nocapture"])
        .env("BEE_KERNEL_ROOT", root.path())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !root.path().join("ready").exists() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("executor did not start");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let old_scope = PathBuf::from(std::fs::read_to_string(root.path().join("scope")).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        std::fs::read_to_string(old_scope.join("cgroup.events"))
            .unwrap()
            .contains("populated 1"),
        "fixture did not leave a live detached executor"
    );
    let report = run(root.path()).await;
    assert_eq!(report.status, bee::EpisodeStatus::Completed);
    assert_eq!(
        report.budget.charged(bee::session::durable::WorkKind::Tool),
        2
    );
    assert_eq!(report.budget.unresolved(), 1);
    assert!(root.path().join("resumed").exists());
    assert!(std::fs::read_to_string(old_scope.join("cgroup.events"))
        .unwrap()
        .contains("populated 0"));
    // The crashed scope has no owner left to remove its empty hierarchy.
    remove(&old_scope);
}

fn remove(path: &Path) {
    for entry in std::fs::read_dir(path).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            remove(&entry.path());
        }
    }
    std::fs::remove_dir(path).unwrap();
}

async fn kill_executor(root: &Path, marker: &str) -> PathBuf {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "kernel_child", "--nocapture"])
        .env("BEE_KERNEL_ROOT", root)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    while !root.join(marker).exists() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("executor did not start");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let name = if marker == "ready2" {
        "scope2"
    } else {
        "scope"
    };
    let scope = PathBuf::from(std::fs::read_to_string(root.join(name)).unwrap());
    assert!(std::fs::read_to_string(scope.join("cgroup.events"))
        .unwrap()
        .contains("populated 1"));
    scope
}
struct DenyReplacement;
#[async_trait::async_trait]
impl bee::hooks::LoopHook for DenyReplacement {
    async fn on_event(&self, event: &bee::hooks::StepEvent<'_>) -> bee::hooks::Flow {
        if matches!(event, bee::hooks::StepEvent::BeforeToolCall(_)) {
            bee::hooks::Flow::Deny("current authorization refuses replacement".into())
        } else {
            bee::hooks::Flow::Continue
        }
    }
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel; run in the VM"]
async fn kernel_recovery_rechecks_authorization_after_reconciliation() {
    let root = tempfile::tempdir().unwrap();
    let scope = kill_executor(root.path(), "ready").await;
    let base = bee_core::Policy::from_toml("[policy]\nname='durable-kernel'\n").unwrap();
    let hooks = bee::grants::escalate::LoopEscalation {
        ceiling: base.clone(),
        base,
        hooks: vec![Box::new(DenyReplacement)],
        operator: bee::operator::Operator::autonomous(std::sync::Arc::new(
            bee::operator::NullOutput,
        )),
        default_ttl: bee::grants::Ttl::Forever,
    };
    let report = run_with(root.path(), Some(&hooks)).await;
    assert!(
        !root.path().join("resumed").exists(),
        "denied replacement executed"
    );
    assert!(report
        .turns
        .iter()
        .flat_map(|t| &t.calls)
        .any(|c| c.result.is_error && c.result.content.contains("current authorization")));
    assert!(std::fs::read_to_string(scope.join("cgroup.events"))
        .unwrap()
        .contains("populated 0"));
    remove(&scope);
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel; run in the VM"]
async fn kernel_recovery_cancels_the_replacement_executor_after_a_second_crash() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("hold-replacement"), "hold").unwrap();
    let first = kill_executor(root.path(), "ready").await;
    let second = kill_executor(root.path(), "ready2").await;
    assert_ne!(first, second);
    let mut store = bee::session::durable::store::Store::open(
        &root.path().join("session"),
        SessionId("kernel".into()),
    )
    .unwrap();
    store
        .admit(
            "cancel",
            &serde_json::json!({"kind":"Cancel","parent":"request"}),
        )
        .unwrap();
    drop(store);
    let report = run(root.path()).await;
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(
        report.budget.charged(bee::session::durable::WorkKind::Tool),
        2
    );
    assert_eq!(report.budget.unresolved(), 2);
    assert!(
        std::fs::read_to_string(second.join("cgroup.events"))
            .unwrap()
            .contains("populated 0"),
        "replacement descendants survived cancellation"
    );
    remove(&first);
    remove(&second);
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel; run in the VM"]
async fn kernel_recovery_cleans_up_an_expired_tool_before_submission_expiry() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("short-tool"), "short").unwrap();
    let scope = kill_executor(root.path(), "ready").await;
    let mut store = bee::session::durable::store::Store::open(
        &root.path().join("session"),
        SessionId("kernel".into()),
    )
    .unwrap();
    let snap = store.load().unwrap();
    drop(store);
    let deadline = snap
        .operations()
        .values()
        .find(|o| o.spec.name == "retry_read")
        .unwrap()
        .spec
        .deadline_ms;
    while bee::session::driver::now_ms() <= deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let report = run(root.path()).await;
    assert_eq!(report.status, bee::EpisodeStatus::Timeout);
    assert_eq!(
        report.budget.charged(bee::session::durable::WorkKind::Tool),
        1
    );
    assert!(!root.path().join("resumed").exists());
    assert!(std::fs::read_to_string(scope.join("cgroup.events"))
        .unwrap()
        .contains("populated 0"));
    remove(&scope);
}
