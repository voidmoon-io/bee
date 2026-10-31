#![cfg(feature = "repro")]

use bee::evidence::EvidenceStore;
use bee::provider::ToolCall;
use bee::reproduction::{Decision, Report};
use bee::source::{query, Request, SourcePin};
use bee::tools::{registry_for, repro::ReproRun, ToolResult};
use bee::Sandbox;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}

fn commit(root: &Path, source: &str) -> SourcePin {
    std::fs::write(root.join("target.sh"), source).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "fixture"]);
    serde_json::from_value(
        query(Request::Pin {
            repository: root.display().to_string(),
            commit: git(root, &["rev-parse", "HEAD"]),
        })
        .unwrap(),
    )
    .unwrap()
}

fn call(name: &str, arguments: Value) -> ToolCall {
    ToolCall {
        id: "fixture".into(),
        name: name.into(),
        arguments,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    store: EvidenceStore,
    registry: bee::ToolRegistry,
    target: SourcePin,
    fixed: SourcePin,
    target_id: String,
    fixed_id: String,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "--quiet"]);
        let target = commit(root.path(), "test ! -e marker || exit 9\ntouch marker\nread -r value\nif [ \"$value\" = positive ]; then printf SIGNAL; fi\nexit 0\n");
        let fixed = commit(
            root.path(),
            "test ! -e marker || exit 9\ntouch marker\nread -r value\nexit 0\n",
        );
        // Neither current HEAD nor dirty files may replace either selected revision.
        std::fs::write(root.path().join("target.sh"), "exit 88\n").unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = EvidenceStore::new(state.path(), "repro-fixture");
        let target_id = store
            .record(
                &call("source_pin", json!({})),
                &ToolResult::ok(serde_json::to_string(&target).unwrap()),
            )
            .unwrap();
        let fixed_id = store
            .record(
                &call("source_pin", json!({})),
                &ToolResult::ok(serde_json::to_string(&fixed).unwrap()),
            )
            .unwrap();
        let mut registry = registry_for(&["repro_run".into()], None);
        registry.enable_evidence(store.clone());
        registry.insert(Box::new(ReproRun {
            profiles: [(
                "fixture".into(),
                bee::security::ReproductionProfile {
                    program: "/bin/sh".into(),
                    args: vec!["target.sh".into()],
                    timeout_secs: 2,
                    max_repetitions: 3,
                },
            )]
            .into(),
            evidence: Some(store.clone()),
            source_worker: Some(env!("CARGO_BIN_EXE_bee").into()),
        }));
        Self {
            root,
            _state: state,
            store,
            registry,
            target,
            fixed,
            target_id,
            fixed_id,
        }
    }
    fn plan(&self) -> Value {
        json!({"profile":"fixture","input":"positive\n","control_input":"control\n","stdout_contains":"SIGNAL","repetitions":2,"snapshot":self.target_id,"comparison_snapshot":self.fixed_id})
    }
    async fn report(&self, plan: Value) -> Report {
        let result = self
            .registry
            .execute(&call("repro_run", plan), &Sandbox::host(vec![]))
            .await;
        assert!(!result.is_error, "{}", result.content);
        serde_json::from_str(
            &self
                .store
                .get(&result.receipt_id.unwrap())
                .unwrap()
                .result
                .content,
        )
        .unwrap()
    }
    fn receipt(&self, pin: &SourcePin) -> String {
        self.store
            .record(
                &call("source_pin", json!({})),
                &ToolResult::ok(serde_json::to_string(pin).unwrap()),
            )
            .unwrap()
    }
}

#[tokio::test]
async fn target_only_keeps_comparison_optional_and_old_reports_readable() {
    let f = Fixture::new();
    let mut plan = f.plan();
    plan.as_object_mut().unwrap().remove("comparison_snapshot");
    let report = f.report(plan).await;
    assert_eq!(report.decision, Decision::Reproduced);
    assert_eq!(report.source_binding, "materialized-pin");
    assert!(report.comparison.is_none());
    assert_eq!(report.attempts.len(), 4);

    // Earlier receipts have no snapshot or per-attempt materialization fields.
    let mut legacy = serde_json::to_value(&report).unwrap();
    let object = legacy.as_object_mut().unwrap();
    object.remove("snapshot");
    object.remove("comparison_snapshot");
    object.remove("comparison");
    object.insert("schema_version".into(), json!(1));
    object.insert("source_binding".into(), json!("unbound"));
    for attempt in object["attempts"].as_array_mut().unwrap() {
        attempt.as_object_mut().unwrap().remove("materialization");
    }
    let restored: Report = serde_json::from_value(legacy).unwrap();
    assert_eq!(restored.schema_version, 1);
    assert_eq!(restored.source_binding, "unbound");
    assert!(restored.snapshot.is_none());
    assert!(restored.comparison_snapshot.is_none());
    assert!(restored.comparison.is_none());
    assert!(restored
        .attempts
        .iter()
        .all(|a| a.materialization.is_none()));
}

#[tokio::test]
async fn exact_target_and_fixed_revision_run_in_fresh_workspaces() {
    let f = Fixture::new();
    let report = f.report(f.plan()).await;
    assert_eq!(report.schema_version, 2);
    assert_eq!(report.decision, Decision::Reproduced);
    assert!(report.behavior_reproduced);
    assert_eq!(report.source_binding, "materialized-pin");
    assert_eq!(report.comparison.as_deref(), Some("passed"));
    assert_eq!(report.impact_supported, "unknown");
    assert_eq!(report.attempts.len(), 8);
    let target_digest = &report.attempts[0]
        .materialization
        .as_ref()
        .unwrap()
        .manifest_sha256;
    let comparison_digest = &report.attempts[4]
        .materialization
        .as_ref()
        .unwrap()
        .manifest_sha256;
    assert_ne!(target_digest, comparison_digest);
    for attempt in &report.attempts {
        let staged = attempt.materialization.as_ref().unwrap();
        assert_eq!(
            staged.pin,
            if attempt.role.starts_with("comparison") {
                f.fixed.clone()
            } else {
                f.target.clone()
            }
        );
        assert_eq!(attempt.exit_code, Some(0));
        assert_eq!(staged.files, 1);
    }
    assert_eq!(
        std::fs::read_to_string(f.root.path().join("target.sh")).unwrap(),
        "exit 88\n"
    );
    assert!(!f.root.path().join("marker").exists());
}

#[tokio::test]
async fn comparison_signal_or_failure_does_not_erase_target_behavior() {
    let f = Fixture::new();
    let bad = commit(f.root.path(), "read -r value\nprintf SIGNAL\nexit 0\n");
    let mut plan = f.plan();
    plan["comparison_snapshot"] = json!(f.receipt(&bad));
    let report = f.report(plan).await;
    assert_eq!(report.decision, Decision::NotReproduced);
    assert!(report.behavior_reproduced);
    assert_eq!(report.comparison.as_deref(), Some("signal-fired"));
    let broken = commit(f.root.path(), "exit 3\n");
    let mut plan = f.plan();
    plan["comparison_snapshot"] = json!(f.receipt(&broken));
    let report = f.report(plan).await;
    assert_eq!(report.decision, Decision::UnableToRun);
    assert!(report.behavior_reproduced);
    assert_eq!(report.comparison.as_deref(), Some("not-completed"));
}

#[tokio::test]
async fn malformed_bindings_are_refused_and_missing_objects_are_unavailable() {
    let f = Fixture::new();
    let mut plan = f.plan();
    plan["comparison_snapshot"] = json!(f.target_id);
    assert!(
        f.registry
            .execute(&call("repro_run", plan), &Sandbox::host(vec![]))
            .await
            .is_error
    );
    let mut plan = f.plan();
    plan.as_object_mut().unwrap().remove("snapshot");
    assert!(
        f.registry
            .execute(&call("repro_run", plan), &Sandbox::host(vec![]))
            .await
            .is_error
    );
    let bogus = f
        .store
        .record(&call("source_read", json!({})), &ToolResult::ok("{}"))
        .unwrap();
    let mut plan = f.plan();
    plan["snapshot"] = json!(bogus);
    assert!(
        f.registry
            .execute(&call("repro_run", plan), &Sandbox::host(vec![]))
            .await
            .is_error
    );
    let mut missing = f.target.clone();
    missing.repository = f.root.path().join("missing").display().to_string();
    let mut plan = f.plan();
    plan["snapshot"] = json!(f.receipt(&missing));
    plan.as_object_mut().unwrap().remove("comparison_snapshot");
    let report = f.report(plan).await;
    assert_eq!(report.decision, Decision::UnableToRun);
    assert_eq!(report.source_binding, "incomplete");
    assert!(report.attempts[0].exit_code.is_none());
}

#[test]
fn extraction_refuses_symlinks_existing_destinations_and_traversal() {
    let f = Fixture::new();
    let destination = tempfile::tempdir().unwrap();
    let request = || Request::Materialize {
        pin: f.target.clone(),
        destination: destination.path().into(),
    };
    query(request()).unwrap();
    assert!(query(request()).is_err());
    let alias = f.root.path().join("alias");
    std::os::unix::fs::symlink(destination.path(), &alias).unwrap();
    assert!(query(Request::Materialize {
        pin: f.target.clone(),
        destination: alias
    })
    .is_err());
    std::os::unix::fs::symlink("/etc/passwd", f.root.path().join("escape")).unwrap();
    let unsafe_pin = commit(f.root.path(), "exit 0\n");
    let clean = tempfile::tempdir().unwrap();
    assert!(query(Request::Materialize {
        pin: unsafe_pin,
        destination: clean.path().into()
    })
    .unwrap_err()
    .contains("symlink"));
    assert!(!clean.path().join("source/escape").exists());
    assert!(query(Request::Materialize {
        pin: f.target,
        destination: clean.path().join("../escape")
    })
    .is_err());
}
