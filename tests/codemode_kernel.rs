#![cfg(all(feature = "durable-sessions", feature = "enforce"))]
//! Real BPF-LSM tests. The VM runner supplies a sibling `bee` binary above this harness's deps/.
use bee::provider::{mock_model::MockModel, Message, ToolCall, Turn};
use bee::session::driver::{DriverError, Limits, Observer, Report, Session};
use bee::session::durable::{Commit, Phase, SessionId, WorkKind};
use bee::tools::{Tool, ToolRegistry};
use bee::Sandbox;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn substrate() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "root required");
    assert!(
        std::fs::read_to_string("/sys/kernel/security/lsm")
            .unwrap()
            .split(',')
            .any(|s| s.trim() == "bpf"),
        "active BPF LSM required"
    );
}
fn policy(root: &Path, worker: bool, cat: bool) -> bee_core::Policy {
    let mut allow = vec![
        "ls".to_string(),
        "sleep".to_string(),
        "tee".to_string(),
        // Unpinned exec rules match the executed file's path; `sh` is a symlink (e.g. to dash).
        std::fs::canonicalize(bee_userspace::spawn::resolve_in_path("sh").unwrap())
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    ];
    if worker {
        allow.push(
            bee::python::executable()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
    }
    if cat {
        allow.push("cat".into());
    }
    bee_core::Policy::from_toml(&format!("[policy]\nname='codemode-kernel'\nmode='enforce'\n[policy.exec]\nallow={}\n[policy.filesystem]\n{}='deny'\n",json!(allow),json!(root.join("denied").to_string_lossy()))).unwrap()
}
fn sandbox(root: &Path, worker: bool, cat: bool) -> Sandbox {
    use bee_userspace::{EnforcementPlan, Engine, ScopeMode, SystemResolver};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    substrate();
    let policy = policy(root, worker, cat);
    let plan = EnforcementPlan::prepare(
        &policy.compile(&SystemResolver::current()).unwrap(),
        ScopeMode::Enforce,
    )
    .unwrap();
    let mut engine = Engine::init().unwrap();
    let scope = engine
        .create_scope(
            &format!(
                "codemode-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ),
            bee_userspace::cgroup::DEFAULT_PARENT,
            &plan,
        )
        .unwrap();
    let reader = engine.take_audit_reader("codemode-kernel").unwrap();
    Sandbox::enforced(engine, scope, reader, vec![])
}
fn scope(sandbox: &Sandbox) -> PathBuf {
    let Sandbox::Enforced(e) = sandbox else {
        panic!("enforced scope required")
    };
    e.scope.path.clone()
}
fn processes(path: &Path) -> Vec<i32> {
    let mut out = std::fs::read_to_string(path.join("cgroup.procs"))
        .unwrap()
        .lines()
        .map(|s| s.parse().unwrap())
        .collect::<Vec<_>>();
    for entry in std::fs::read_dir(path).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            out.extend(processes(&entry.path()));
        }
    }
    out
}
fn named_process(path: &Path, name: &str) -> Option<i32> {
    processes(path).into_iter().find(|pid| {
        std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|s| {
            s.split(|b| *b == 0).any(|arg| arg == name.as_bytes())
                || s.split(|b| *b == 0).next().is_some_and(|arg| {
                    Path::new(std::str::from_utf8(arg).unwrap_or(""))
                        .file_name()
                        .is_some_and(|file| file == name)
                })
        })
    })
}
fn empty(path: &Path) {
    assert!(
        std::fs::read_to_string(path.join("cgroup.events"))
            .unwrap()
            .lines()
            .any(|s| s == "populated 0"),
        "populated scope: {}",
        path.display()
    );
    assert!(processes(path).is_empty());
}
fn removed_invocations(path: &Path) {
    empty(path);
    assert!(
        std::fs::read_dir(path)
            .unwrap()
            .flatten()
            .all(|e| !e.file_type().unwrap().is_dir()),
        "invocation cgroup leaked"
    );
}
fn remove_empty(path: &Path) {
    empty(path);
    for entry in std::fs::read_dir(path).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            remove_empty(&entry.path());
        }
    }
    std::fs::remove_dir(path).unwrap();
}
fn prepare(root: &Path) {
    std::fs::write(root.join("allowed"), "BEFORE").unwrap();
    std::fs::create_dir(root.join("denied")).unwrap();
    std::fs::write(root.join("denied/secret"), "NEVER-LEAK").unwrap();
    let fifo = std::ffi::CString::new(root.join("fifo").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
}
fn source(root: &Path, mode: &str) -> String {
    let allowed = json!(root.join("allowed").to_str().unwrap());
    match mode {
        "write" | "write-lost" | "write-blocked" => {
            let first = if mode == "write-blocked" { root.join("fifo") } else { root.join("allowed") };
            let content = if mode == "write-lost" { "LOST" } else { "WRITTEN" };
            format!("a = call_tool('write_file', {{'path': {}, 'content': {}}})\ncall_tool('write_file', {{'path': {}, 'content': a['content']}})", json!(first), json!(content), json!(root.join("second")))
        },
        "cpu"=>"while True: pass".into(),
        "blocked"=>format!("call_tool('read_file', {{'path': {}}})\ncall_tool('read_file', {{'path': {allowed}}})",json!(root.join("fifo").to_str().unwrap())),
        "batch"=>format!("r = call_tools([{{'name': 'read_file', 'arguments': {{'path': {allowed}}}}}, {{'name': 'read_file', 'arguments': {{'path': {allowed}}}}}])\n[x['content'] for x in r]"),
        "two"=>format!("a = call_tool('read_file', {{'path': {allowed}}})\nb = call_tool('read_file', {{'path': {allowed}}})\n[a['content'], b['content']]"),
        _=>panic!("unknown fixture"),
    }
}
fn model(source: &str) -> MockModel {
    let source = source.to_string();
    MockModel::from_fn(move |c| {
        if c.messages
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
    .with_id("kernel-codemode")
}
#[derive(Default)]
struct Output;
impl bee::repl::ReplOutput for Output {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &bee::ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}
fn limits() -> Limits {
    Limits {
        turns: 4,
        tool_calls: 10,
        timeout_ms: 60_000,
        tool_timeout_ms: 30_000,
        model_attempts: 2,
    }
}
async fn session(root: &Path, observer: Option<Arc<dyn Observer>>) -> Arc<Session> {
    Session::open_observed(
        root.join("session"),
        SessionId("kernel-codemode".into()),
        "kernel-fixture".into(),
        None,
        observer,
    )
    .await
    .unwrap()
}
fn registry(session: &Session) -> ToolRegistry {
    let mut r = bee::tools::registry_for(
        &["read_file".into(), "list_directory".into(), "bash".into()],
        None,
    );
    r.insert(Box::new(WriteFixture));
    r.enable_evidence(session.evidence());
    r
}
async fn run(root: &Path, code: &str, sandbox: &mut Sandbox) -> Report {
    let session = session(root, None).await;
    session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(code),
            &mut registry(&session),
            sandbox,
            &Output,
            None,
        )
        .await
        .unwrap()
        .0
}
fn denied(audit: &[bee_core::AuditEvent], operation: &str) -> bool {
    audit
        .iter()
        .any(|e| e.decision == "denied" && e.op == operation)
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_file_policy() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let code=format!("a = call_tool('read_file', {{'path': {}}})\nb = call_tool('read_file', {{'path': {}}})\nc = call_tool('list_directory', {{'path': {}}})\n[b['is_error'], 'BEFORE' in a['content'], 'allowed' in c['content']]",json!(root.path().join("allowed").to_str().unwrap()),json!(root.path().join("denied/secret").to_str().unwrap()),json!(root.path().to_str().unwrap()));
    let report = run(root.path(), &code, &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(!calls[0].result.is_error);
    assert!(calls[1].result.is_error);
    assert!(!calls[2].result.is_error);
    assert!(denied(&calls[1].audit, "file_open"), "{:?}", calls[1].audit);
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("NEVER-LEAK"));
    assert!(calls[..3]
        .iter()
        .all(|c| c.parent_call_id.as_deref() == Some("outer") && c.result.receipt_id.is_some()));
    let value: serde_json::Value = serde_json::from_str(&calls[3].result.content).unwrap();
    assert_eq!(value["value"], json!([true, true, true]));
    removed_invocations(&path);
    sb.teardown().unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_worker_exec_denied() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), false, true);
    let path = scope(&sb);
    let report = run(root.path(), "42", &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 1);
    assert!(calls[0].result.is_error, "{:?}", calls[0]);
    assert!(
        denied(&calls[0].audit, "exec"),
        "worker denial missing from its durable result: {:?}",
        calls[0].audit
    );
    assert_eq!(report.budget.charged(WorkKind::Tool), 1);
    let replay = run(root.path(), "42", &mut sb).await;
    assert_eq!(replay.turns[0].calls[0].audit, calls[0].audit);
    removed_invocations(&path);
    sb.teardown().unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_inner_exec_denied() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, false);
    let path = scope(&sb);
    let report = run(root.path(), &source(root.path(), "two"), &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3, "{calls:?}");
    for call in &calls[..2] {
        assert!(call.result.is_error);
        assert!(denied(&call.audit, "exec"), "{:?}", call.audit);
    }
    assert!(
        !calls[2].result.is_error,
        "Python should receive committed error results"
    );
    removed_invocations(&path);
    sb.teardown().unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_worker_timeout() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let session = session(root.path(), None).await;
    let mut r = registry(&session);
    let m = model("while True: pass");
    let bounded = Limits {
        tool_timeout_ms: 500,
        ..limits()
    };
    let future = session.run(
        "request",
        Some("go"),
        "system",
        bounded,
        &m,
        &mut r,
        &mut sb,
        &Output,
        None,
    );
    tokio::pin!(future);
    let mut observed = false;
    let (report, _) = loop {
        tokio::select! { result=&mut future=>break result.unwrap(), _=tokio::time::sleep(Duration::from_millis(5))=>{observed |= named_process(&path,"python-worker").is_some();} }
    };
    assert!(observed, "never observed worker inside the enforced scope");
    assert_eq!(report.status, bee::EpisodeStatus::Timeout);
    removed_invocations(&path);
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_cancel_child() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let sibling = sandbox(root.path(), true, true);
    let sibling_path = scope(&sibling);
    let mut command =
        tokio::process::Command::from(sibling.tool_command("sleep", &["30".into()]).unwrap());
    command.kill_on_drop(true);
    let mut sibling_child = command.spawn().unwrap();
    let session = session(root.path(), None).await;
    let mut r = registry(&session);
    let m = model(&source(root.path(), "blocked"));
    let future = session.run(
        "request",
        Some("go"),
        "system",
        limits(),
        &m,
        &mut r,
        &mut sb,
        &Output,
        None,
    );
    tokio::pin!(future);
    let mut cancelled = false;
    let started = Instant::now();
    let (report, _) = loop {
        tokio::select! { result=&mut future=>break result.unwrap(), _=tokio::time::sleep(Duration::from_millis(5))=>{
            assert!(started.elapsed()<Duration::from_secs(10),"cat did not start");
            if !cancelled && named_process(&path,"cat").is_some() { session.cancel().unwrap();cancelled=true; }
        } }
    };
    assert!(cancelled);
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(report.budget.charged(WorkKind::Tool), 2);
    removed_invocations(&path);
    assert!(
        sibling_child.try_wait().unwrap().is_none(),
        "cancellation killed a sibling"
    );
    assert!(!processes(&sibling_path).is_empty());
    sibling.teardown().unwrap();
    sibling_child.wait().await.unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_memory_cleanup() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let report = run(root.path(), "'x' * 100_000_000", &mut sb).await;
    let result = &report.turns[0].calls.last().unwrap().result;
    assert!(result.is_error);
    assert!(
        result.content.to_lowercase().contains("memory"),
        "{}",
        result.content
    );
    removed_invocations(&path);
    sb.teardown().unwrap();
}

struct Pause(PathBuf);
impl Observer for Pause {
    fn committed(&self, commit: &Commit) {
        if commit.snapshot.operations().values().any(|o| {
            matches!(o.spec.name.as_str(), "read_file" | "write_file")
                && matches!(o.phase, Phase::Completed { .. })
        }) {
            std::fs::write(self.0.join("ready"), "committed").unwrap();
            loop {
                std::thread::park();
            }
        }
    }
}
#[tokio::test]
#[ignore = "subprocess fixture, not a standalone gate"]
async fn subprocess_fixture() {
    let root = PathBuf::from(std::env::var("BEE_CODEMODE_ROOT").unwrap());
    let mode = std::env::var("BEE_CODEMODE_MODE").unwrap();
    let mut sb = sandbox(&root, true, true);
    std::fs::write(root.join("scope"), scope(&sb).to_str().unwrap()).unwrap();
    let observer = if matches!(mode.as_str(), "two" | "write" | "batch") {
        Some(Arc::new(Pause(root.clone())) as Arc<dyn Observer>)
    } else {
        None
    };
    let session = session(&root, observer).await;
    session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&source(&root, &mode)),
            &mut registry(&session),
            &mut sb,
            &Output,
            None,
        )
        .await
        .unwrap();
    panic!("fixture expected to be killed");
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn start(root: &Path, mode: &str) -> (Child, PathBuf) {
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "subprocess_fixture", "--nocapture"])
            .env("BEE_CODEMODE_ROOT", root)
            .env("BEE_CODEMODE_MODE", mode)
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "fixture exited early"
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "fixture did not start"
        );
        if let Ok(path) = std::fs::read_to_string(root.join("scope")) {
            if !path.is_empty() {
                return (child, PathBuf::from(path));
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn wait_for(mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "fixture timed out"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_committed_recovery() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let (mut child, old) = start(root.path(), "two").await;
    wait_for(|| root.path().join("ready").exists()).await;
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    empty(&old);
    std::fs::write(root.path().join("allowed"), "AFTER").unwrap();
    let mut sb = sandbox(root.path(), true, true);
    let report = run(root.path(), &source(root.path(), "two"), &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3);
    assert!(calls[0].result.content.ends_with("BEFORE"));
    assert!(calls[1].result.content.ends_with("AFTER"));
    assert_eq!(report.budget.charged(WorkKind::Tool), 3);
    assert_eq!(report.budget.unresolved(), 0);
    removed_invocations(&scope(&sb));
    sb.teardown().unwrap();
    remove_empty(&old);
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_parent_death() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let (mut child, old) = start(root.path(), "cpu").await;
    let mut pid = None;
    wait_for(|| {
        pid = named_process(&old, "python-worker");
        pid.is_some()
    })
    .await;
    let pid = pid.unwrap();
    assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    wait_for(|| processes(&old).is_empty()).await;
    empty(&old);
    let mut sb = sandbox(root.path(), true, true);
    let report = run(root.path(), &source(root.path(), "cpu"), &mut sb).await;
    assert_eq!(report.budget.charged(WorkKind::Tool), 1);
    let result = &report.turns[0].calls.last().unwrap().result;
    assert!(result.is_error);
    let body: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(body["worker_invocations"], 2);
    assert!(body["worker_time_charge_ms"].as_u64().unwrap() >= 4000);
    removed_invocations(&scope(&sb));
    sb.teardown().unwrap();
    remove_empty(&old);
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_unknown_child() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let (mut child, old) = start(root.path(), "blocked").await;
    wait_for(|| named_process(&old, "cat").is_some()).await;
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(
        !processes(&old).is_empty(),
        "cat did not survive the parent"
    );
    let mut sb = sandbox(root.path(), true, true);
    let session = session(root.path(), None).await;
    let result = session
        .run(
            "request",
            Some("go"),
            "system",
            limits(),
            &model(&source(root.path(), "blocked")),
            &mut registry(&session),
            &mut sb,
            &Output,
            None,
        )
        .await;
    assert!(
        matches!(result, Err(DriverError::Unresolved(_))),
        "{result:?}"
    );
    empty(&old);
    removed_invocations(&scope(&sb));
    assert_eq!(
        session
            .budget("request")
            .await
            .unwrap()
            .unwrap()
            .charged(WorkKind::Tool),
        2
    );
    sb.teardown().unwrap();
    remove_empty(&old);
}

// Hold the real write result to exercise loss before completion is committed.
struct WriteFixture;
#[async_trait::async_trait]
impl Tool for WriteFixture {
    fn name(&self) -> &'static str {
        "write_file"
    }
    fn schema(&self) -> bee::provider::ToolSchema {
        let mut schema = bee::tools::files::WriteFile.schema();
        schema.name = self.name().into();
        schema
    }
    fn durable_contract(&self) -> bee::tools::ToolContract {
        bee::tools::files::WriteFile.durable_contract()
    }
    async fn call(&self, args: serde_json::Value, sandbox: &Sandbox) -> bee::ToolResult {
        let result = bee::tools::files::WriteFile
            .call(args.clone(), sandbox)
            .await;
        if args["content"] == "LOST" && !result.is_error {
            std::future::pending::<()>().await;
        }
        result
    }
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_write_policy() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let code = format!("a = call_tool('write_file', {{'path': {}, 'content': 'UPDATED'}})\nb = call_tool('write_file', {{'path': {}, 'content': 'FORBIDDEN'}})\n1 / 0", json!(root.path().join("allowed")), json!(root.path().join("denied/secret")));
    let report = run(root.path(), &code, &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3);
    assert!(!calls[0].result.is_error);
    assert!(calls[1].result.is_error);
    assert!(calls[2].result.is_error);
    assert!(denied(&calls[1].audit, "file_open"));
    assert!(calls[..2]
        .iter()
        .all(|c| c.result.receipt_id.is_some() && c.parent_call_id.as_deref() == Some("outer")));
    assert_eq!(
        std::fs::read_to_string(root.path().join("allowed")).unwrap(),
        "UPDATED"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("denied/secret")).unwrap(),
        "NEVER-LEAK"
    );
    removed_invocations(&scope(&sb));
    sb.teardown().unwrap();
}
#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_write_recovery() {
    for mode in ["write", "write-lost", "write-blocked"] {
        let root = tempfile::tempdir().unwrap();
        prepare(root.path());
        let (mut child, old) = start(root.path(), mode).await;
        wait_for(|| match mode {
            "write" => root.path().join("ready").exists(),
            "write-lost" => {
                std::fs::read_to_string(root.path().join("allowed")).is_ok_and(|s| s == "LOST")
            }
            _ => named_process(&old, "tee").is_some(),
        })
        .await;
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!root.path().join("second").exists());
        std::fs::write(root.path().join("allowed"), "AFTER CRASH").unwrap();
        let mut sb = sandbox(root.path(), true, true);
        let session = session(root.path(), None).await;
        let result = session
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(&source(root.path(), mode)),
                &mut registry(&session),
                &mut sb,
                &Output,
                None,
            )
            .await;
        if mode == "write" {
            let (report, _) = result.unwrap();
            assert_eq!(report.budget.charged(WorkKind::Tool), 3);
            assert!(report.turns[0].calls[..2]
                .iter()
                .all(|c| c.result.receipt_id.is_some()));
            assert!(std::fs::read_to_string(root.path().join("second"))
                .unwrap()
                .contains("wrote 7 bytes"));
        } else {
            assert!(
                matches!(result, Err(DriverError::Unresolved(_))),
                "{result:?}"
            );
            assert!(!root.path().join("second").exists());
            assert_eq!(
                session
                    .budget("request")
                    .await
                    .unwrap()
                    .unwrap()
                    .charged(WorkKind::Tool),
                2
            );
        }
        assert_eq!(
            std::fs::read_to_string(root.path().join("allowed")).unwrap(),
            "AFTER CRASH"
        );
        empty(&old);
        removed_invocations(&scope(&sb));
        sb.teardown().unwrap();
        remove_empty(&old);
    }
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_cancel_write() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let sibling = sandbox(root.path(), true, true);
    let sibling_path = scope(&sibling);
    let mut command =
        tokio::process::Command::from(sibling.tool_command("sleep", &["30".into()]).unwrap());
    command.kill_on_drop(true);
    let mut sibling_child = command.spawn().unwrap();
    let session = session(root.path(), None).await;
    let mut r = registry(&session);
    let m = model(&source(root.path(), "write-blocked"));
    let future = session.run(
        "request",
        Some("go"),
        "system",
        limits(),
        &m,
        &mut r,
        &mut sb,
        &Output,
        None,
    );
    tokio::pin!(future);
    let mut cancelled = false;
    let started = Instant::now();
    let (report, _) = loop {
        tokio::select! { result=&mut future=>break result.unwrap(), _=tokio::time::sleep(Duration::from_millis(5))=>{
            assert!(started.elapsed()<Duration::from_secs(10),"tee did not start");
            if !cancelled && named_process(&path,"tee").is_some() { session.cancel().unwrap();cancelled=true; }
        } }
    };
    assert!(cancelled);
    assert!(!root.path().join("second").exists());
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(report.budget.charged(WorkKind::Tool), 2);
    removed_invocations(&path);
    assert!(
        sibling_child.try_wait().unwrap().is_none(),
        "cancellation killed a sibling"
    );
    assert!(!processes(&sibling_path).is_empty());
    sibling.teardown().unwrap();
    sibling_child.wait().await.unwrap();
}

fn ids(report: &Report) -> Vec<(String, Option<String>)> {
    report.turns[0]
        .calls
        .iter()
        .map(|c| (c.call.id.clone(), c.parent_call_id.clone()))
        .collect()
}
fn owned(pairs: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
    pairs
        .iter()
        .map(|(id, parent)| (id.to_string(), parent.map(str::to_string)))
        .collect()
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_shell_policy() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let allowed = root.path().join("allowed");
    let secret = root.path().join("denied/secret");
    let shell = root.path().join("shell");
    let code = format!(
        "a = call_tool('bash', {{'command': {}}})\nb = call_tool('bash', {{'command': {}}})\n[a['is_error'], b['is_error']]",
        json!(format!("cat '{}' && printf S > '{}'", allowed.display(), shell.display())),
        json!(format!("cat '{}'", secret.display())),
    );
    let report = run(root.path(), &code, &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(!calls[0].result.is_error, "{:?}", calls[0].result);
    assert!(calls[0].result.content.contains("BEFORE"));
    assert!(
        !denied(&calls[0].audit, "file_open"),
        "{:?}",
        calls[0].audit
    );
    assert!(denied(&calls[1].audit, "file_open"), "{:?}", calls[1].audit);
    assert_eq!(std::fs::read_to_string(&shell).unwrap(), "S");
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("NEVER-LEAK"));
    assert!(calls[..2]
        .iter()
        .all(|c| c.result.receipt_id.is_some() && c.parent_call_id.as_deref() == Some("outer")));
    // Reopen replays the completed session without repeating the shell effect.
    std::fs::write(&shell, "").unwrap();
    let replay = run(root.path(), &code, &mut sb).await;
    assert_eq!(replay.turns[0].calls.len(), 3);
    assert_eq!(std::fs::read_to_string(&shell).unwrap(), "");
    removed_invocations(&path);
    sb.teardown().unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_batch_attribution() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let code = format!(
        "r = call_tools([{{'name': 'read_file', 'arguments': {{'path': {a}}}}}, {{'name': 'read_file', 'arguments': {{'path': {s}}}}}, {{'name': 'read_file', 'arguments': {{'path': {a}}}}}])\n[x['is_error'] for x in r]",
        a = json!(root.path().join("allowed")),
        s = json!(root.path().join("denied/secret")),
    );
    let report = run(root.path(), &code, &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(
        ids(&report),
        owned(&[
            ("outer/1", Some("outer")),
            ("outer/2", Some("outer")),
            ("outer/3", Some("outer")),
            ("outer", None),
        ])
    );
    // Each kernel decision belongs to exactly the call that caused it.
    assert!(
        !denied(&calls[0].audit, "file_open"),
        "{:?}",
        calls[0].audit
    );
    assert!(denied(&calls[1].audit, "file_open"), "{:?}", calls[1].audit);
    assert!(
        !denied(&calls[2].audit, "file_open"),
        "{:?}",
        calls[2].audit
    );
    assert!(
        !denied(&calls[3].audit, "file_open"),
        "{:?}",
        calls[3].audit
    );
    let value: serde_json::Value = serde_json::from_str(&calls[3].result.content).unwrap();
    assert_eq!(value["value"], json!([false, true, false]));
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("NEVER-LEAK"));
    assert_eq!(report.budget.charged(WorkKind::Tool), 4);
    removed_invocations(&path);
    sb.teardown().unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_nested_effects() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let inner = format!(
        "w = call_tool('write_file', {{'path': {}, 'content': 'NESTED'}})\nd = call_tool('read_file', {{'path': {}}})\n[w['is_error'], d['is_error']]",
        json!(root.path().join("allowed")),
        json!(root.path().join("denied/secret")),
    );
    let code = format!(
        "n = call_tool('codemode', {{'source': {}}})\nr = call_tool('read_file', {{'path': {}}})\n[n['is_error'], r['content']]",
        json!(inner),
        json!(root.path().join("allowed")),
    );
    let report = run(root.path(), &code, &mut sb).await;
    let calls = &report.turns[0].calls;
    assert_eq!(
        ids(&report),
        owned(&[
            ("outer/1/1", Some("outer/1")),
            ("outer/1/2", Some("outer/1")),
            ("outer/1", Some("outer")),
            ("outer/2", Some("outer")),
            ("outer", None),
        ])
    );
    assert!(!calls[0].result.is_error);
    assert!(denied(&calls[1].audit, "file_open"), "{:?}", calls[1].audit);
    assert!(
        !denied(&calls[3].audit, "file_open"),
        "{:?}",
        calls[3].audit
    );
    assert!(calls[3].result.content.ends_with("NESTED"));
    assert_eq!(report.budget.charged(WorkKind::Tool), 5);
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("NEVER-LEAK"));
    removed_invocations(&path);
    sb.teardown().unwrap();
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_nested_cancel() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let mut sb = sandbox(root.path(), true, true);
    let path = scope(&sb);
    let inner = format!(
        "call_tools([{{'name': 'read_file', 'arguments': {{'path': {}}}}}, {{'name': 'read_file', 'arguments': {{'path': {}}}}}])",
        json!(root.path().join("fifo")),
        json!(root.path().join("allowed")),
    );
    let code = format!(
        "call_tool('codemode', {{'source': {}}})\ncall_tool('write_file', {{'path': {}, 'content': 'NEXT'}})",
        json!(inner),
        json!(root.path().join("second")),
    );
    let session = session(root.path(), None).await;
    let mut r = registry(&session);
    let m = model(&code);
    let report = {
        let future = session.run(
            "request",
            Some("go"),
            "system",
            limits(),
            &m,
            &mut r,
            &mut sb,
            &Output,
            None,
        );
        tokio::pin!(future);
        let mut cancelled = false;
        let started = Instant::now();
        let (report, _) = loop {
            tokio::select! { result=&mut future=>break result.unwrap(), _=tokio::time::sleep(Duration::from_millis(5))=>{
                assert!(started.elapsed()<Duration::from_secs(10),"cat did not start");
                if !cancelled && named_process(&path,"cat").is_some() { session.cancel().unwrap();cancelled=true; }
            } }
        };
        assert!(cancelled);
        report
    };
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    // Enforced batches run one leaf at a time: only the blocked read was attempted.
    assert_eq!(report.budget.charged(WorkKind::Tool), 3);
    assert!(!root.path().join("second").exists());
    assert_eq!(
        ids(&report),
        owned(&[
            ("outer/1/1", Some("outer/1")),
            ("outer/1", Some("outer")),
            ("outer", None),
        ])
    );
    assert!(report.turns[0].calls.iter().all(|c| c.result.is_error));
    removed_invocations(&path);
    drop(r);
    drop(session);
    // Reopen validates the stopped tree.
    let reopened = session_reopen(root.path()).await;
    drop(reopened);
    sb.teardown().unwrap();
}
async fn session_reopen(root: &Path) -> Arc<Session> {
    session(root, None).await
}

#[tokio::test]
#[ignore = "requires root and BPF-LSM kernel"]
async fn kernel_codemode_batch_kill_recovery() {
    let root = tempfile::tempdir().unwrap();
    prepare(root.path());
    let (mut child, old) = start(root.path(), "batch").await;
    wait_for(|| root.path().join("ready").exists()).await;
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    empty(&old);
    std::fs::write(root.path().join("allowed"), "AFTER").unwrap();
    let mut sb = sandbox(root.path(), true, true);
    let session = session(root.path(), None).await;
    let (report, _) = session
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(&source(root.path(), "batch")),
            &mut registry(&session),
            &mut sb,
            &Output,
            None,
        )
        .await
        .unwrap();
    let calls = &report.turns[0].calls;
    assert_eq!(calls.len(), 3);
    // The committed sibling is not repeated; only the unstarted one runs after reopen.
    assert!(calls[0].result.content.ends_with("BEFORE"));
    assert!(calls[1].result.content.ends_with("AFTER"));
    assert_eq!(report.budget.charged(WorkKind::Tool), 3);
    assert_eq!(report.budget.unresolved(), 0);
    removed_invocations(&scope(&sb));
    sb.teardown().unwrap();
    remove_empty(&old);
}
