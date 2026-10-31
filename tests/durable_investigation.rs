#![cfg(all(feature = "durable-sessions", feature = "repro"))]
use bee::findings::{Finding, FindingSource, Ledger, LedgerEvent, Sighting, Verdict, VerdictState};
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Message, ToolCall, Turn};
use bee::repl::ReplOutput;
use bee::session::driver::{DriverError, Limits, Observer, Session};
use bee::session::durable::{store::journal::WorkerRecord, Commit, Phase, SessionId, Snapshot};
use bee::tools::{repro::ReproRun, source::SourceTool, ToolRegistry};
use bee::Sandbox;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("target.sh"), "read -r value\nprintf '%s\\n' \"$value\" >> \"$1/effects\"\nif [ -f \"$1/hold-probe\" ]; then\n  touch \"$1/probe-ready\"\n  while [ -f \"$1/hold-probe\" ]; do sleep 0.05; done\nfi\nif [ \"$value\" = positive ]; then printf SIGNAL; fi\nexit 0\n").unwrap();
    git(&repo, &["add", "target.sh"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "target",
        ],
    );
    std::fs::write(
        root.path().join("commit"),
        git(&repo, &["rev-parse", "HEAD"]),
    )
    .unwrap();
    std::fs::write(repo.join("target.sh"), "exit 99\n").unwrap();
    let ledger = Ledger::at(root.path().join("findings"));
    let finding = Finding::new(
        "target.sh".into(),
        "fixture-behavior".into(),
        "Controlled signal".into(),
        "Human baseline".into(),
        FindingSource::Tool("fixture".into()),
    );
    let id = bee::findings::record(
        &ledger,
        finding,
        Sighting {
            evidence_refs: vec![],
            run_id: "baseline".into(),
            at: time::OffsetDateTime::UNIX_EPOCH,
            line: None,
            end_line: None,
            rule_id: None,
        },
    )
    .unwrap();
    ledger
        .append(&LedgerEvent::Adjudicated {
            id,
            verdict: Verdict {
                state: VerdictState::FalsePositive,
                by: "human".into(),
                at: time::OffsetDateTime::UNIX_EPOCH,
                note: Some("Behavior is not security impact".into()),
            },
        })
        .unwrap();
    root
}
fn limits() -> Limits {
    Limits {
        turns: 12,
        tool_calls: 8,
        timeout_ms: 60_000,
        tool_timeout_ms: 30_000,
        model_attempts: 2,
    }
}
fn registry(root: &Path, session: &Session) -> ToolRegistry {
    let mut registry = bee::tools::registry_for(
        &[
            "source_pin",
            "source_read",
            "hunt_checkpoint",
            "repro_run",
            "record_finding",
        ]
        .map(str::to_owned),
        None,
    );
    registry.enable_evidence(session.evidence());
    registry.set_deps(std::sync::Arc::new(
        (**registry.deps()).clone().with_security(
            &bee::security::SecurityConfig {
                findings_dir: Some(root.join("findings")),
                ..Default::default()
            },
            None,
            "investigation",
        ),
    ));
    for name in ["source_pin", "source_read"] {
        registry.insert(Box::new(
            SourceTool::new(name, Some(session.evidence()))
                .with_executable(env!("CARGO_BIN_EXE_bee").into()),
        ));
    }
    registry.insert(Box::new(ReproRun {
        profiles: [(
            "fixture".into(),
            bee::security::ReproductionProfile {
                program: "/bin/sh".into(),
                args: vec!["target.sh".into(), root.to_str().unwrap().into()],
                timeout_secs: 10,
                max_repetitions: 2,
            },
        )]
        .into(),
        evidence: Some(session.evidence()),
        source_worker: Some(env!("CARGO_BIN_EXE_bee").into()),
    }));
    registry
}
fn model(root: &Path) -> MockModel {
    let repo = root.join("repo");
    let commit = std::fs::read_to_string(root.join("commit")).unwrap();
    MockModel::from_fn(move |conversation: &Conversation| {
        let results: Vec<_> = conversation.messages.iter().filter_map(|m| if let Message::ToolResult { name, content, is_error, .. } = m { assert!(!is_error, "{name}: {content}"); Some((name, content)) } else { None }).collect();
        let receipt = |name: &str| -> String {
            let content = results.iter().find(|(n, _)| *n == name).unwrap().1;
            content.strip_prefix("[Bee receipt: ").unwrap().split(';').next().unwrap().into()
        };
        let (name, args) = match results.len() {
            0 => ("source_pin", json!({"repository":repo,"commit":commit})),
            1 => ("source_read", json!({"snapshot":receipt("source_pin"),"path":"target.sh","start_line":1,"end_line":1})),
            2 => ("hunt_checkpoint", json!({"snapshot":receipt("source_pin"),"title":"Controlled signal","actor":"Fixture caller","invariant":"Controls do not trigger the signal","hypothesis":"Positive input fires SIGNAL","countercheck":"Use a negative control","observation":"Read the committed entry point","next_action":"Run controlled probes","unknowns":["Security impact"],"status":"exploring","evidence":[{"receipt_id":receipt("source_read"),"role":"entrypoint"}]})),
            3 => ("repro_run", json!({"profile":"fixture","input":"positive\n","control_input":"control\n","stdout_contains":"SIGNAL","repetitions":2,"snapshot":receipt("source_pin")})),
            4 => ("record_finding", json!({"path":"target.sh","class":"fixture-behavior","title":"Controlled signal","evidence":"Controlled behavior only; security impact remains unknown","evidence_refs":[receipt("source_read"),receipt("hunt_checkpoint"),receipt("repro_run")]})),
            _ => return Turn::text("Behavior reproduced; security impact remains unknown. Human verdict retained."),
        };
        Turn::calls(vec![ToolCall { id: format!("call-{}", results.len()), name: name.into(), arguments: args }])
    }).with_id("investigation-script")
}
struct Output;
impl ReplOutput for Output {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &Value) {}
    fn tool_result(&self, _: &bee::ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}
fn pause() {
    println!("JOURNAL_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
struct CrashAt(String);
impl Observer for CrashAt {
    fn worker_committed(&self, record: &WorkerRecord) {
        let first = record.probes.len() == 1;
        if (self.0 == "probe-intent" && first && record.pending())
            || (matches!(self.0.as_str(), "probe-result" | "consent-expiry")
                && first
                && !record.pending())
            || (matches!(self.0.as_str(), "worker-result" | "expired-result")
                && record.completion.is_some())
        {
            pause();
        }
    }
    fn before_commit(&self, commit: &Commit) {
        if commit.snapshot.operations().values().any(|op| {
            op.spec.name == "repro_run"
                && ((self.0 == "before-admission" && matches!(op.phase, Phase::Ready))
                    || (self.0 == "before-result" && matches!(op.phase, Phase::Publishing { .. }))
                    || (self.0 == "after-publication"
                        && matches!(op.phase, Phase::Completed { .. })))
        }) {
            pause();
        }
    }
    fn committed(&self, commit: &Commit) {
        if commit.snapshot.operations().values().any(|op| {
            (self.0 == "after-result"
                && op.spec.name == "repro_run"
                && matches!(op.phase, Phase::Publishing { .. }))
                || (self.0 == "finding-result"
                    && op.spec.name == "record_finding"
                    && matches!(op.phase, Phase::Publishing { .. }))
        }) {
            pause();
        }
        if self.0 == "after-delivery"
            && commit.snapshot.driver().is_some_and(|j| {
                j["active"]["turns"].as_array().is_some_and(|turns| {
                    turns.last().is_some_and(|t| {
                        t["calls"].as_array().is_some_and(|calls| {
                            calls
                                .last()
                                .is_some_and(|c| c["call"]["name"] == "repro_run")
                        })
                    })
                })
            })
        {
            pause();
        }
    }
}
async fn open(root: &Path, observer: Option<Arc<dyn Observer>>) -> Arc<Session> {
    Session::open_observed(
        root.join("session"),
        SessionId("investigation".into()),
        "fixture-config".into(),
        None,
        observer,
    )
    .await
    .unwrap()
}
#[tokio::test]
#[ignore = "subprocess fixture invoked explicitly by crash tests"]
async fn investigation_child() {
    let root = PathBuf::from(std::env::var_os("BEE_INVESTIGATION_ROOT").unwrap());
    let mode = std::env::var("BEE_INVESTIGATION_MODE").unwrap();
    let mut requested_limits = limits();
    if mode == "expired-result" {
        requested_limits.timeout_ms = 5_000;
    }
    if mode == "consent-expiry" {
        requested_limits.tool_timeout_ms = 5_000;
    }
    let session = open(&root, Some(Arc::new(CrashAt(mode)))).await;
    let mut registry = registry(&root, &session);
    session
        .run(
            "request",
            Some("Investigate"),
            "system",
            requested_limits,
            &model(&root),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    panic!("missed crash boundary");
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn kill_at(root: &Path, mode: &str) {
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "investigation_child", "--nocapture"])
            .env("BEE_INVESTIGATION_ROOT", root)
            .env("BEE_INVESTIGATION_MODE", mode)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.is_ok_and(|s| s == "JOURNAL_READY") {
                let _ = tx.send(());
                break;
            }
        }
    });
    if mode == "probe-effect" {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !root.join("probe-ready").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    } else {
        rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
}
fn worker(root: &Path) -> WorkerRecord {
    let db = rusqlite::Connection::open_with_flags(
        root.join("session/session.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT payload FROM workers", [], |r| r.get(0))
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn snapshot(root: &Path) -> Snapshot {
    let db = rusqlite::Connection::open_with_flags(
        root.join("session/session.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT snapshot FROM session", [], |r| r.get(0))
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
#[tokio::test]
async fn full_investigation_survives_every_recording_boundary_without_repeating_probes() {
    for mode in [
        "probe-result",
        "worker-result",
        "before-result",
        "after-result",
        "after-publication",
        "after-delivery",
        "finding-result",
    ] {
        let root = fixture();
        kill_at(root.path(), mode);
        let before = worker(root.path());
        let session = open(root.path(), None).await;
        let mut registry = registry(root.path(), &session);
        let (report, _) = session
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(root.path()),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{mode}: {e}"));
        assert_eq!(report.status, bee::EpisodeStatus::Completed, "{mode}");
        assert_eq!(
            std::fs::read_to_string(root.path().join("effects")).unwrap(),
            "positive\npositive\ncontrol\ncontrol\n",
            "{mode}"
        );
        assert_eq!(
            report.budget.charged(bee::session::durable::WorkKind::Tool),
            5
        );
        assert_eq!(report.budget.unresolved(), 0);
        let after = worker(root.path());
        assert_eq!(before.probes, after.probes[..before.probes.len()]);
        if let Some(result) = before.completion {
            assert_eq!(after.completion.as_ref(), Some(&result));
        }
        let result = after.completion.unwrap();
        let receipt = session
            .evidence()
            .get(&result.receipt.as_ref().unwrap().id)
            .unwrap();
        let reproduction: bee::reproduction::Report =
            serde_json::from_str(&receipt.result.content).unwrap();
        assert_eq!(
            reproduction.decision,
            bee::reproduction::Decision::Reproduced
        );
        assert_eq!(reproduction.impact_supported, "unknown");
        assert!(reproduction
            .attempts
            .iter()
            .all(|p| p.materialization.is_some()));
        let entry = snapshot(root.path())
            .entries()
            .iter()
            .find(|e| e.attempt.operation == after.attempt.operation)
            .unwrap()
            .clone();
        assert_eq!(entry.result, result);
        let ledger = bee::findings::fold(&Ledger::at(root.path().join("findings"))).unwrap();
        assert_eq!(ledger.findings.len(), 1);
        assert_eq!(ledger.findings[0].sightings.len(), 2);
        assert_eq!(
            ledger.findings[0].verdict.as_ref().unwrap().state,
            VerdictState::FalsePositive
        );
        assert_eq!(ledger.findings[0].evidence_refs.len(), 3);
        let (again, _) = session
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(root.path()),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await
            .unwrap();
        assert_eq!(again.budget, report.budget);
    }
}
#[tokio::test]
async fn unrecorded_probe_intent_or_effect_stays_unresolved_without_reexecution() {
    for mode in ["probe-intent", "probe-effect"] {
        let root = fixture();
        if mode == "probe-effect" {
            std::fs::write(root.path().join("hold-probe"), "hold").unwrap();
        }
        kill_at(root.path(), mode);
        if mode == "probe-effect" {
            std::fs::remove_file(root.path().join("hold-probe")).unwrap();
        }
        let before = worker(root.path());
        assert!(before.pending());
        let session = open(root.path(), None).await;
        let mut registry = registry(root.path(), &session);
        let result = session
            .run(
                "request",
                None,
                "system",
                limits(),
                &model(root.path()),
                &mut registry,
                &mut Sandbox::host(vec![]),
                &Output,
                None,
            )
            .await;
        assert!(
            matches!(result, Err(DriverError::Unresolved(_))),
            "{result:?}"
        );
        assert_eq!(worker(root.path()), before);
        assert_eq!(
            std::fs::read_to_string(root.path().join("effects")).unwrap_or_default(),
            if mode == "probe-effect" {
                "positive\n"
            } else {
                ""
            }
        );
        assert_eq!(
            session
                .budget("request")
                .await
                .unwrap()
                .unwrap()
                .unresolved(),
            1
        );
    }
}

#[derive(Default)]
struct CancelWhenRecorded(std::sync::Mutex<std::sync::Weak<Session>>);
impl Observer for CancelWhenRecorded {
    fn worker_committed(&self, record: &WorkerRecord) {
        if record.completion.is_some() {
            self.0.lock().unwrap().upgrade().unwrap().cancel().unwrap();
        }
    }
}
#[tokio::test]
async fn cancellation_imports_a_worker_result_before_finishing_cleanup() {
    let root = fixture();
    let observer = Arc::new(CancelWhenRecorded::default());
    let session = open(root.path(), Some(observer.clone())).await;
    *observer.0.lock().unwrap() = Arc::downgrade(&session);
    let mut registry = registry(root.path(), &session);
    let (report, _) = session
        .run(
            "request",
            Some("Investigate"),
            "system",
            limits(),
            &model(root.path()),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert_eq!(report.budget.unresolved(), 0);
    let recorded = worker(root.path()).completion.unwrap();
    let delivered = &report.turns.last().unwrap().calls.last().unwrap().result;
    assert_eq!(serde_json::to_value(delivered).unwrap(), recorded.output);
    assert_eq!(
        std::fs::read_to_string(root.path().join("effects"))
            .unwrap()
            .lines()
            .count(),
        4
    );
    assert_eq!(
        bee::findings::fold(&Ledger::at(root.path().join("findings")))
            .unwrap()
            .findings[0]
            .sightings
            .len(),
        1
    );
}
#[tokio::test]
async fn corrupted_worker_progress_blocks_recovery_without_new_probes() {
    let root = fixture();
    kill_at(root.path(), "probe-result");
    let db = rusqlite::Connection::open(root.path().join("session/session.sqlite3")).unwrap();
    db.execute("UPDATE workers SET payload=?1", [b"{}".as_slice()])
        .unwrap();
    drop(db);
    let session = open(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let result = session
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(root.path()),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await;
    assert!(matches!(result, Err(DriverError::Store(_))));
    assert_eq!(
        std::fs::read_to_string(root.path().join("effects")).unwrap(),
        "positive\n"
    );
}
#[tokio::test]
async fn changed_probe_profile_cannot_mix_old_observations_with_new_execution() {
    let root = fixture();
    kill_at(root.path(), "probe-result");
    let session = open(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    registry.insert(Box::new(ReproRun {
        profiles: [(
            "fixture".into(),
            bee::security::ReproductionProfile {
                program: "/bin/sh".into(),
                args: vec![
                    "target.sh".into(),
                    root.path().to_str().unwrap().into(),
                    "changed".into(),
                ],
                timeout_secs: 10,
                max_repetitions: 2,
            },
        )]
        .into(),
        evidence: Some(session.evidence()),
        source_worker: Some(env!("CARGO_BIN_EXE_bee").into()),
    }));
    let result = session
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(root.path()),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await;
    assert!(
        matches!(result, Err(DriverError::Incompatible)),
        "{result:?}"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("effects")).unwrap(),
        "positive\n"
    );
}

#[tokio::test]
async fn expired_submission_imports_recorded_observation_without_new_work() {
    let root = fixture();
    kill_at(root.path(), "expired-result");
    let recorded = worker(root.path());
    let deadline = recorded.spec.deadline_ms;
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        <= u128::from(deadline)
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let session = open(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let no_model = MockModel::from_fn(|_| panic!("expired submission called provider"))
        .with_id("investigation-script");
    let (report, _) = session
        .run(
            "request",
            None,
            "system",
            limits(),
            &no_model,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::Timeout);
    assert_eq!(report.budget.unresolved(), 0);
    assert_eq!(worker(root.path()), recorded);
    assert_eq!(
        serde_json::to_value(&report.turns.last().unwrap().calls.last().unwrap().result).unwrap(),
        recorded.completion.unwrap().output
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("effects"))
            .unwrap()
            .lines()
            .count(),
        4
    );
    assert_eq!(
        bee::findings::fold(&Ledger::at(root.path().join("findings")))
            .unwrap()
            .findings[0]
            .sightings
            .len(),
        1
    );
}

#[tokio::test]
async fn crash_before_tool_admission_resumes_without_orphaned_operation() {
    let root = fixture();
    kill_at(root.path(), "before-admission");
    assert!(!root.path().join("effects").exists());
    let session = open(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let (report, _) = session
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(root.path()),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.status, bee::EpisodeStatus::Completed);
    assert_eq!(report.budget.unresolved(), 0);
    assert_eq!(
        std::fs::read_to_string(root.path().join("effects"))
            .unwrap()
            .lines()
            .count(),
        4
    );
}

struct WaitForAuthorization(Arc<std::sync::atomic::AtomicBool>);
#[async_trait::async_trait]
impl bee::hooks::LoopHook for WaitForAuthorization {
    async fn on_event(&self, event: &bee::hooks::StepEvent<'_>) -> bee::hooks::Flow {
        if matches!(event, bee::hooks::StepEvent::BeforeToolCall(_)) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
        bee::hooks::Flow::Continue
    }
}
#[tokio::test]
async fn recovery_authorization_expiring_the_tool_deadline_enters_cleanup() {
    let root = fixture();
    kill_at(root.path(), "consent-expiry");
    let session = open(root.path(), None).await;
    let mut registry = registry(root.path(), &session);
    let base = bee_core::Policy::from_toml("[policy]\nname='consent-expiry'\n").unwrap();
    let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hooks = bee::grants::escalate::LoopEscalation {
        ceiling: base.clone(),
        base,
        hooks: vec![Box::new(WaitForAuthorization(asked.clone()))],
        operator: bee::operator::Operator::autonomous(Arc::new(bee::operator::NullOutput)),
        default_ttl: bee::grants::Ttl::Forever,
    };
    let result = session
        .run(
            "request",
            None,
            "system",
            limits(),
            &model(root.path()),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &Output,
            Some(&hooks),
        )
        .await;
    assert!(asked.load(std::sync::atomic::Ordering::SeqCst));
    // Host recovery cannot prove the old executor stopped, but expiry must commit cancellation.
    assert!(
        matches!(result, Err(DriverError::Unresolved(_))),
        "{result:?}"
    );
    assert!(snapshot(root.path())
        .operations()
        .values()
        .any(|operation| operation.spec.name == "repro_run"
            && matches!(operation.phase, Phase::Cancelling { .. })));
    assert_eq!(
        std::fs::read_to_string(root.path().join("effects")).unwrap(),
        "positive\n"
    );
    assert_eq!(
        session
            .budget("request")
            .await
            .unwrap()
            .unwrap()
            .unresolved(),
        1
    );
}
