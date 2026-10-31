#![cfg(feature = "repro")]

use bee::reproduction::{run, Decision, Plan, Report};
use bee::security::ReproductionProfile;
use bee::Sandbox;
use serde_json::json;
use sha2::{Digest, Sha256};

fn profile(command: &str) -> ReproductionProfile {
    ReproductionProfile {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), command.into()],
        timeout_secs: 1,
        max_repetitions: 3,
    }
}
fn plan() -> Plan {
    Plan {
        snapshot: None,
        comparison_snapshot: None,
        profile: "fixture".into(),
        input: "positive\n".into(),
        control_input: "control\n".into(),
        stdout_contains: "SIGNAL".into(),
        repetitions: 3,
    }
}

#[tokio::test]
async fn requires_every_positive_and_healthy_negative_control_with_fresh_workspaces() {
    let command = "test ! -e marker || exit 7; test \"$HOME\" = \"$PWD\" || exit 8; test \"$TMPDIR\" = \"$PWD\" || exit 9; touch marker; read -r value; printf '%s\\n' \"$PWD\"; if [ \"$value\" = positive ]; then printf SIGNAL; fi";
    let report = run(plan(), profile(command), &Sandbox::host(vec![]))
        .await
        .unwrap();
    assert_eq!(report.decision, Decision::Reproduced);
    assert!(report.behavior_reproduced);
    assert_eq!(report.impact_supported, "unknown");
    assert_eq!(report.source_binding, "unbound");
    assert_eq!(report.execution_posture, "host");
    assert_eq!(report.attempts.len(), 6);
    let mut paths = std::collections::HashSet::new();
    for attempt in &report.attempts {
        let path = attempt.stdout_excerpt.lines().next().unwrap();
        assert!(paths.insert(path));
        assert!(
            !std::path::Path::new(path).exists(),
            "scratch should be removed"
        );
        assert_eq!(
            attempt.stdout_sha256.as_ref().unwrap(),
            &format!("{:x}", Sha256::digest(attempt.stdout_excerpt.as_bytes()))
        );
    }
}

#[tokio::test]
async fn signal_misses_and_controls_that_fire_are_not_reproduced() {
    for command in [
        "printf clean",
        "printf SIGNAL",
        "read -r value; if [ \"$value\" = positive ]; then exit 2; fi",
    ] {
        let report = run(plan(), profile(command), &Sandbox::host(vec![]))
            .await
            .unwrap();
        assert_eq!(report.decision, Decision::NotReproduced);
        assert!(!report.behavior_reproduced);
    }
}

#[tokio::test]
async fn a_single_positive_success_does_not_verify_the_repetitions() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("already-fired");
    let command = format!("read -r value; if [ \"$value\" = positive ] && [ ! -e '{}' ]; then touch '{}'; printf SIGNAL; fi; exit 0", marker.display(), marker.display());
    let report = run(plan(), profile(&command), &Sandbox::host(vec![]))
        .await
        .unwrap();
    assert_eq!(report.decision, Decision::NotReproduced);
    assert_eq!(report.attempts.iter().filter(|a| a.signal_fired).count(), 1);
    assert_eq!(report.attempts.len(), 6);
}

#[tokio::test]
async fn unavailable_execution_and_unhealthy_controls_never_refute_the_hypothesis() {
    let mut missing = profile("");
    missing.program = "/nonexistent/bee-repro-fixture".into();
    let report = run(plan(), missing, &Sandbox::host(vec![])).await.unwrap();
    assert_eq!(report.decision, Decision::UnableToRun);
    assert!(report.attempts[0].error.is_some());
    for command in [
        "sleep 5",
        "read -r value; if [ \"$value\" = positive ]; then printf SIGNAL; else exit 3; fi",
        "head -c 70000 /dev/zero",
    ] {
        let report = run(plan(), profile(command), &Sandbox::host(vec![]))
            .await
            .unwrap();
        assert_eq!(report.decision, Decision::UnableToRun, "{command}");
        assert!(!report.behavior_reproduced);
    }
}

#[test]
fn malformed_plans_are_refused_before_execution() {
    let config = profile("exit 0");
    let mut p = plan();
    p.stdout_contains.clear();
    assert!(bee::reproduction::validate(&p, &config).is_err());
    let mut p = plan();
    p.control_input = p.input.clone();
    assert!(bee::reproduction::validate(&p, &config).is_err());
    for repetitions in [0, 1, 4, u32::MAX] {
        let mut p = plan();
        p.repetitions = repetitions;
        assert!(bee::reproduction::validate(&p, &config).is_err());
    }
    let mut p = plan();
    p.input = "x".repeat(65537);
    assert!(bee::reproduction::validate(&p, &config).is_err());
    let mut invalid = config;
    invalid.timeout_secs = 61;
    assert!(bee::reproduction::validate(&plan(), &invalid).is_err());
}

#[tokio::test]
async fn cancellation_cleans_up_the_current_scratch_workspace() {
    let root = tempfile::tempdir().unwrap();
    let path_file = root.path().join("scratch-path");
    let command = format!("printf '%s' \"$PWD\" > '{}'; sleep 5", path_file.display());
    let sandbox = Sandbox::host(vec![]);
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        run(plan(), profile(&command), &sandbox),
    )
    .await;
    assert!(result.is_err());
    let scratch = std::fs::read_to_string(path_file).unwrap();
    assert!(!std::path::Path::new(&scratch).exists());
    assert!(sandbox.check_cleanup().is_ok());
}

#[test]
fn reproduction_profiles_round_trip_through_security_configuration() {
    let config: bee::security::SecurityConfig = toml::from_str(
        r#"
[reproductions.fixture]
program = "/bin/sh"
args = ["-c", "read value; printf '%s' \"$value\""]
timeout_secs = 2
max_repetitions = 3
"#,
    )
    .unwrap();
    assert_eq!(config.reproductions["fixture"].timeout_secs, 2);
    let serialized = toml::to_string(&config).unwrap();
    assert_eq!(
        toml::from_str::<bee::security::SecurityConfig>(&serialized).unwrap(),
        config
    );
}

#[tokio::test]
async fn native_tool_persists_the_plan_and_report_and_accepts_evidence_citations() {
    use bee::provider::ToolCall;
    use bee::tools::registry_for;
    let root = tempfile::tempdir().unwrap();
    let mut registry = registry_for(&["repro_run".into(), "record_finding".into()], None);
    let mut config = bee::security::SecurityConfig {
        findings_dir: Some(root.path().join("findings")),
        ..Default::default()
    };
    config.reproductions.insert(
        "fixture".into(),
        profile("read -r value; if [ \"$value\" = positive ]; then printf SIGNAL; fi"),
    );
    registry.set_deps(std::sync::Arc::new(
        (**registry.deps())
            .clone()
            .with_security(&config, None, "repro-test"),
    ));
    let call = |name: &str, arguments| ToolCall {
        id: "fixture".into(),
        name: name.into(),
        arguments,
    };
    let result = registry
        .execute(
            &call("repro_run", serde_json::to_value(plan()).unwrap()),
            &Sandbox::host(vec![]),
        )
        .await;
    assert!(!result.is_error, "{}", result.content);
    let id = result.receipt_id.unwrap();
    let store =
        bee::evidence::EvidenceStore::new(root.path().join("findings/evidence"), "reviewer");
    let receipt = store.get(&id).unwrap();
    let report: Report = serde_json::from_str(&receipt.result.content).unwrap();
    assert!(report.behavior_reproduced);
    assert_eq!(receipt.arguments["control_input"], "control\n");
    let finding = registry.execute(&call("record_finding", json!({"path":"fixture","title":"Behavior only","class":"fixture","evidence":"Impact remains unknown","evidence_refs":[id]})), &Sandbox::host(vec![])).await;
    assert!(!finding.is_error, "{}", finding.content);
    let view =
        bee::findings::fold(&bee::findings::Ledger::at(root.path().join("findings"))).unwrap();
    assert!(view.findings[0].verdict.is_none());
    for args in [
        json!({"profile":"fixture","input":"positive","stdout_contains":"SIGNAL","repetitions":3}),
        json!({"profile":"unknown","input":"positive","control_input":"negative","stdout_contains":"SIGNAL","repetitions":3}),
    ] {
        assert!(
            registry
                .execute(&call("repro_run", args), &Sandbox::host(vec![]))
                .await
                .is_error
        );
    }
}
