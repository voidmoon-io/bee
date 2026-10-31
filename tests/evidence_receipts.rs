#![cfg(feature = "findings")]

use bee::evidence::EvidenceStore;
use bee::findings::{fold, Ledger, LedgerEvent, Verdict, VerdictState};
use bee::provider::ToolCall;
use bee::tools::{registry_for, ToolResult};
use bee::{Sandbox, ToolRegistry};
use serde_json::json;

fn call(name: &str, arguments: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "call-1".into(),
        name: name.into(),
        arguments,
    }
}

fn configured(root: &std::path::Path) -> ToolRegistry {
    let mut registry = registry_for(
        &["bash".into(), "receipt_get".into(), "record_finding".into()],
        None,
    );
    let config = bee::security::SecurityConfig {
        findings_dir: Some(root.join("findings")),
        ..Default::default()
    };
    registry.set_deps(std::sync::Arc::new(
        (**registry.deps())
            .clone()
            .with_security(&config, None, "fixture"),
    ));
    registry
}

#[tokio::test]
async fn executed_output_is_durable_citable_and_does_not_override_a_verdict() {
    let root = tempfile::tempdir().unwrap();
    let registry = configured(root.path());
    let sandbox = Sandbox::host(Vec::new());
    let result = registry
        .execute(
            &call("bash", json!({"command":"printf 'fixture observation'"})),
            &sandbox,
        )
        .await;
    assert!(!result.is_error, "{}", result.content);
    let id = result.receipt_id.unwrap();
    let store = EvidenceStore::new(root.path().join("findings/evidence"), "reviewer");
    let receipt = store.get(&id).unwrap();
    assert_eq!(receipt.tool, "bash");
    assert_eq!(receipt.result.content, "fixture observation");
    assert!(receipt.result.receipt_id.is_none());

    let record = call(
        "record_finding",
        json!({"path":"fixture.rs", "class":"test", "title":"Test observation", "evidence":"Analyst interpretation", "evidence_refs":[id]}),
    );
    let saved = registry.execute(&record, &sandbox).await;
    assert!(!saved.is_error, "{}", saved.content);
    let ledger = Ledger::at(root.path().join("findings"));
    let finding = fold(&ledger).unwrap().findings.remove(0);
    assert_eq!(finding.evidence_refs, vec![id.clone()]);
    ledger
        .append(&LedgerEvent::Adjudicated {
            id: finding.id.clone(),
            verdict: Verdict {
                state: VerdictState::FalsePositive,
                by: "human".into(),
                at: time::OffsetDateTime::now_utc(),
                note: Some("fixture only".into()),
            },
        })
        .unwrap();
    let again = registry.execute(&record, &sandbox).await;
    assert!(!again.is_error, "{}", again.content);
    let view = fold(&ledger).unwrap();
    assert_eq!(view.findings.len(), 1);
    assert_eq!(view.findings[0].evidence_refs, vec![id.clone()]);
    assert_eq!(
        view.findings[0].verdict.as_ref().unwrap().state,
        VerdictState::FalsePositive
    );

    // New sessions can inspect old evidence but cannot silently claim they observed it.
    let restarted = configured(root.path());
    let retrieved = restarted
        .execute(&call("receipt_get", json!({"id":id})), &sandbox)
        .await;
    assert!(!retrieved.is_error, "{}", retrieved.content);
    let refused = restarted.execute(&record, &sandbox).await;
    assert!(refused.is_error);
    assert!(refused.content.contains("different session"));
    assert_eq!(fold(&ledger).unwrap().findings[0].sightings.len(), 2);
}

#[tokio::test]
async fn invented_citations_are_refused_before_a_finding_is_written() {
    let root = tempfile::tempdir().unwrap();
    let registry = configured(root.path());
    let result = registry
        .execute(
            &call(
                "record_finding",
                json!({
                    "path":"a.rs", "class":"test", "title":"Fake", "evidence":"claim",
                    "evidence_refs":[format!("sha256:{}", "a".repeat(64))]
                }),
            ),
            &Sandbox::host(Vec::new()),
        )
        .await;
    assert!(result.is_error);
    assert!(fold(&Ledger::at(root.path().join("findings")))
        .unwrap()
        .findings
        .is_empty());
}

#[test]
fn corruption_missing_data_and_path_traversal_cannot_resolve_as_evidence() {
    let root = tempfile::tempdir().unwrap();
    let store = EvidenceStore::new(root.path(), "session");
    let id = store
        .record(&call("test", json!({})), &ToolResult::ok("observed"))
        .unwrap();
    assert!(store.get("../../outside").is_err());
    let path = root
        .path()
        .join(format!("{}.json", id.strip_prefix("sha256:").unwrap()));
    std::fs::write(&path, b"{}").unwrap();
    assert!(store
        .get(&id)
        .unwrap_err()
        .to_string()
        .contains("digest mismatch"));
    std::fs::remove_file(&path).unwrap();
    assert!(store.get(&id).is_err());
}

#[test]
fn symlinks_and_hardlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("linked")).unwrap();
    let store = EvidenceStore::new(root.path().join("linked/evidence"), "session");
    assert!(store
        .record(&call("test", json!({})), &ToolResult::ok("data"))
        .is_err());
    assert!(!outside.path().join("evidence").exists());

    let store = EvidenceStore::new(root.path().join("safe"), "session");
    let id = store
        .record(&call("test", json!({})), &ToolResult::ok("data"))
        .unwrap();
    let path = root.path().join("safe").join(format!("{}.json", &id[7..]));
    std::fs::hard_link(&path, outside.path().join("alias")).unwrap();
    assert!(store.get(&id).is_err());
}

#[tokio::test]
async fn persistence_failure_reports_the_executed_effect_without_a_receipt() {
    let root = tempfile::tempdir().unwrap();
    let blocked = root.path().join("not-a-directory");
    std::fs::write(&blocked, b"occupied").unwrap();
    let mut registry = registry_for(&["bash".into()], None);
    registry.enable_evidence(EvidenceStore::new(blocked, "session"));
    let result = registry
        .execute(
            &call("bash", json!({"command":"printf 'effect happened'"})),
            &Sandbox::host(Vec::new()),
        )
        .await;
    // The call succeeded: reporting it as failed would invite a retry of the effect.
    assert!(!result.is_error, "{}", result.content);
    assert!(result.receipt_id.is_none());
    assert!(
        result.content.ends_with("effect happened"),
        "{}",
        result.content
    );
    assert!(result.content.contains("cannot be cited"));
    assert!(result.content.contains("do not retry"));
}

#[test]
fn legacy_tool_results_deserialize_without_receipt_ids() {
    let mut old = serde_json::to_value(ToolResult::ok("old output")).unwrap();
    old.as_object_mut().unwrap().remove("receipt_id");
    let result: ToolResult = serde_json::from_value(old).unwrap();
    assert!(result.receipt_id.is_none());
}

#[test]
fn concurrent_observations_have_distinct_ids_and_preserve_error_and_truncation() {
    let root = tempfile::tempdir().unwrap();
    let store = EvidenceStore::new(root.path(), "session");
    let mut result = ToolResult::error("partial output");
    result.truncated = true;
    result.original_len = Some(100_000);
    let ids = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = &store;
                let result = &result;
                scope.spawn(move || store.record(&call("test", json!({})), result).unwrap())
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 8);
    for id in ids {
        let receipt = store.get(&id).unwrap();
        assert!(receipt.result.is_error);
        assert!(receipt.result.truncated);
        assert_eq!(receipt.result.original_len, Some(100_000));
    }
    let oversized = ToolResult::ok("x".repeat(bee::evidence::MAX_RECEIPT_BYTES));
    assert!(store.record(&call("test", json!({})), &oversized).is_err());
}

#[tokio::test]
async fn episode_transcript_preserves_resolvable_receipt_ids() {
    use bee::provider::{mock_model::MockModel, Turn};
    let root = tempfile::tempdir().unwrap();
    let mut registry = configured(root.path());
    let scenario = bee::Scenario {
        context: Default::default(),
        stuck: Default::default(),
        lease_turns: None,
        finish: false,
        id: "receipts".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "Test".into(),
        task: "observe".into(),
        turn_limit: 2,
        timeout_secs: 30,
        tools: vec!["bash".into(), "receipt_get".into()],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: vec![],
        ceiling_policy_path: None,
        security: Default::default(),
    };
    let model = MockModel::scripted(vec![
        Turn::calls(vec![call(
            "bash",
            json!({"command":"printf transcript-evidence"}),
        )]),
        Turn::text("finished"),
    ]);
    let transcript = bee::run_loop(
        &model,
        &scenario,
        &mut registry,
        &mut Sandbox::host(Vec::new()),
        &bee::LoopOptions::default(),
    )
    .await;
    assert_eq!(transcript.status, bee::EpisodeStatus::Completed);
    let serialized = serde_json::to_vec(&transcript).unwrap();
    let restored: bee::EpisodeTranscript = serde_json::from_slice(&serialized).unwrap();
    let id = restored.turns[0].calls[0]
        .result
        .receipt_id
        .as_ref()
        .unwrap();
    let store = EvidenceStore::new(root.path().join("findings/evidence"), "reviewer");
    assert_eq!(store.get(id).unwrap().result.content, "transcript-evidence");
}
