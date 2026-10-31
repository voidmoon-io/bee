#![cfg(feature = "source")]

use bee::evidence::EvidenceStore;
use bee::provider::ToolCall;
use bee::tools::{registry_for, ToolResult};
use bee::{Sandbox, ToolRegistry};
use serde_json::{json, Value};

fn call(name: &str, arguments: Value) -> ToolCall {
    ToolCall {
        id: "fixture".into(),
        name: name.into(),
        arguments,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    store: EvidenceStore,
    registry: ToolRegistry,
    snapshot: String,
    source: String,
}

fn registry(store: &EvidenceStore, root: &std::path::Path) -> ToolRegistry {
    let mut registry = registry_for(&["hunt_checkpoint".into(), "hunt_resume".into()], None);
    registry.enable_evidence(store.clone());
    registry.set_deps(std::sync::Arc::new(
        (**registry.deps()).clone().with_security(
            &bee::security::SecurityConfig {
                findings_dir: Some(root.join("findings")),
                ..Default::default()
            },
            None,
            "hunt-test",
        ),
    ));
    registry
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = EvidenceStore::new(root.path().join("evidence"), "first-session");
        let pin = json!({"repository":"/fixture", "commit":"a".repeat(40), "tree":"b".repeat(40)});
        // Fixture producer receipts. Real scoped source production is tested in pinned_source.
        let snapshot = store
            .record(
                &call("source_pin", json!({})),
                &ToolResult::ok(pin.to_string()),
            )
            .unwrap();
        let source = store
            .record(
                &call("source_read", json!({})),
                &ToolResult::ok(
                    json!({
                        "pin":pin,"path":"src/auth.rs","blob":"c".repeat(40),
                        "file_sha256":"d".repeat(64),"range_sha256":"e".repeat(64),
                        "start_line":1,"end_line":2,"total_lines":2,"content":"guard\neffect\n"
                    })
                    .to_string(),
                ),
            )
            .unwrap();
        let registry = registry(&store, root.path());
        Self {
            root,
            store,
            registry,
            snapshot,
            source,
        }
    }

    fn input(&self) -> Value {
        json!({"snapshot":self.snapshot,"title":"Authorization boundary","actor":"Unauthenticated caller",
            "invariant":"Only owners may mutate records","hypothesis":"Alternate route skips guard",
            "countercheck":"Trace the alternate route's middleware","observation":"Found a guard and a write",
            "next_action":"Trace caller registration","unknowns":["Whether middleware is shared"],
            "status":"exploring","evidence":[{"receipt_id":self.source,"role":"guard"}]})
    }

    async fn save(&self, input: Value) -> String {
        let result = self
            .registry
            .execute(&call("hunt_checkpoint", input), &Sandbox::host(vec![]))
            .await;
        assert!(!result.is_error, "{}", result.content);
        result.receipt_id.unwrap()
    }

    fn remove(&self, id: &str) {
        std::fs::remove_file(
            self.root
                .path()
                .join("evidence")
                .join(format!("{}.json", &id[7..])),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn branches_survive_restart_and_history_pages_without_duplication() {
    let f = Fixture::new();
    let root = f.save(f.input()).await;
    let mut input = f.input();
    input["parent_id"] = json!(root);
    let left = f.save(input.clone()).await;
    input["observation"] = json!("Independent investigation branch");
    let right = f.save(input.clone()).await;
    input["parent_id"] = json!(left);
    let tip = f.save(input).await;
    let restarted_store = EvidenceStore::new(f.root.path().join("evidence"), "second-session");
    let restarted = registry(&restarted_store, f.root.path());
    let resumed = restarted
        .execute(
            &call("hunt_resume", json!({"id":tip,"limit":2})),
            &Sandbox::host(vec![]),
        )
        .await;
    assert!(!resumed.is_error, "{}", resumed.content);
    let page: Value = serde_json::from_str(
        &restarted_store
            .get(&resumed.receipt_id.unwrap())
            .unwrap()
            .result
            .content,
    )
    .unwrap();
    assert_eq!(page["history"][0]["id"], left);
    assert_eq!(page["history"][1]["id"], tip);
    assert_eq!(page["older_checkpoint_id"], root);
    let older = bee::hunt::resume(
        &restarted_store,
        bee::hunt::ResumeInput {
            id: root.clone(),
            limit: 2,
        },
    )
    .unwrap();
    assert_eq!(older.history.len(), 1);
    assert!(older.older_checkpoint_id.is_none());
    let branch = bee::hunt::resume(
        &restarted_store,
        bee::hunt::ResumeInput {
            id: right.clone(),
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(
        branch
            .history
            .iter()
            .map(|e| e.id.as_str())
            .collect::<Vec<_>>(),
        vec![root.as_str(), right.as_str()]
    );
    let mut continuation = f.input();
    continuation["parent_id"] = json!(tip);
    let continued = restarted
        .execute(
            &call("hunt_checkpoint", continuation),
            &Sandbox::host(vec![]),
        )
        .await;
    assert!(!continued.is_error, "{}", continued.content);
    assert!(!f.root.path().join("findings/ledger.jsonl").exists());
}

#[tokio::test]
async fn rejects_forged_evidence_cross_pin_parents_and_unearned_status() {
    let f = Fixture::new();
    let root = f.save(f.input()).await;
    let mut cases = Vec::new();
    let mut input = f.input();
    input["evidence"][0]["receipt_id"] = json!(root);
    cases.push(input);
    let mut input = f.input();
    input["status"] = json!("source-supported");
    cases.push(input);
    let mut input = f.input();
    input["status"] = json!("rejected");
    cases.push(input);
    let mut input = f.input();
    input["status"] = json!("verified");
    cases.push(input);
    let mut input = f.input();
    input["actor"] = json!("  ");
    cases.push(input);
    let mut input = f.input();
    input["title"] = json!("x".repeat(257));
    cases.push(input);
    let mut input = f.input();
    input["parent_id"] = json!(format!("sha256:{}", "0".repeat(64)));
    cases.push(input);
    let other_pin = f
        .store
        .record(
            &call("source_pin", json!({})),
            &ToolResult::ok(
                json!({
                    "repository":"/fixture","commit":"f".repeat(40),"tree":"b".repeat(40)
                })
                .to_string(),
            ),
        )
        .unwrap();
    let mut input = f.input();
    input["snapshot"] = json!(other_pin);
    cases.push(input.clone());
    input["parent_id"] = json!(root);
    input["evidence"] = json!([]);
    cases.push(input);
    for input in cases {
        let result = f
            .registry
            .execute(&call("hunt_checkpoint", input), &Sandbox::host(vec![]))
            .await;
        assert!(result.is_error, "{}", result.content);
    }
    let mut supported = f.input();
    supported["status"] = json!("source-supported");
    supported["evidence"] = json!(["entrypoint", "effect", "countercheck"]
        .map(|role| json!({"receipt_id":f.source,"role":role})));
    let id = f.save(supported).await;
    let checkpoint: bee::hunt::Checkpoint =
        serde_json::from_str(&f.store.get(&id).unwrap().result.content).unwrap();
    assert_eq!(checkpoint.input.status, bee::hunt::Status::SourceSupported);
    assert_eq!(checkpoint.anchors[0].path, "src/auth.rs");
    assert!(!f.root.path().join("findings/ledger.jsonl").exists());
}

#[tokio::test]
async fn missing_evidence_is_visible_and_missing_history_is_an_error() {
    let f = Fixture::new();
    let root = f.save(f.input()).await;
    let mut input = f.input();
    input["parent_id"] = json!(root);
    let tip = f.save(input).await;
    f.remove(&f.source);
    let page = bee::hunt::resume(
        &f.store,
        bee::hunt::ResumeInput {
            id: tip.clone(),
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(page.history[0].evidence_problems[0].receipt_id, f.source);
    assert_eq!(page.history.len(), 2);
    f.remove(&root);
    assert!(bee::hunt::resume(&f.store, bee::hunt::ResumeInput { id: tip, limit: 10 }).is_err());
    assert!(bee::hunt::resume(
        &f.store,
        bee::hunt::ResumeInput {
            id: f.snapshot.clone(),
            limit: 10
        }
    )
    .is_err());
}

#[tokio::test]
async fn byte_budget_produces_a_cursor_and_oversize_checkpoints_are_refused() {
    let f = Fixture::new();
    let mut input = f.input();
    input["unknowns"] = json!(vec!["x".repeat(1024); 10]);
    let mut latest = f.save(input.clone()).await;
    for _ in 0..7 {
        input["parent_id"] = json!(latest);
        latest = f.save(input.clone()).await;
    }
    let page = bee::hunt::resume(
        &f.store,
        bee::hunt::ResumeInput {
            id: latest,
            limit: 10,
        },
    )
    .unwrap();
    assert!(page.history.len() < 8);
    assert!(page.older_checkpoint_id.is_some());
    assert!(serde_json::to_vec(&page).unwrap().len() <= 64 * 1024);
    input["unknowns"] = json!(vec!["x".repeat(1024); 20]);
    let refused = f
        .registry
        .execute(&call("hunt_checkpoint", input), &Sandbox::host(vec![]))
        .await;
    assert!(refused.is_error);
    assert!(refused.content.contains("16 KiB"));
}

#[tokio::test]
async fn normal_session_setup_enables_capture_for_hunt_tools() {
    let f = Fixture::new();
    let mut tools = registry_for(&["hunt_checkpoint".into(), "hunt_resume".into()], None);
    tools.set_deps(std::sync::Arc::new((**tools.deps()).clone().with_security(
        &bee::security::SecurityConfig {
            findings_dir: Some(f.root.path().into()),
            ..Default::default()
        },
        None,
        "normal-session",
    )));
    let result = tools
        .execute(&call("hunt_checkpoint", f.input()), &Sandbox::host(vec![]))
        .await;
    assert!(!result.is_error, "{}", result.content);
    let id = result.receipt_id.unwrap();
    assert_eq!(f.store.get(&id).unwrap().tool, "hunt_checkpoint");
    assert!(tools.contains("receipt_get"));
    for limit in [0, 11] {
        let refused = tools
            .execute(
                &call("hunt_resume", json!({"id":id,"limit":limit})),
                &Sandbox::host(vec![]),
            )
            .await;
        assert!(refused.is_error);
    }
    let mut input = f.input();
    input["verified"] = json!(true);
    let refused = tools
        .execute(&call("hunt_checkpoint", input), &Sandbox::host(vec![]))
        .await;
    assert!(refused.is_error);
}
