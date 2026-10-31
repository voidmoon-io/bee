#![cfg(all(feature = "durable-store", feature = "findings"))]

use bee::evidence::EvidenceStore;
use bee::provider::{ToolCall, ToolSchema};
use bee::session::durable::store::Store;
use bee::session::durable::*;
use bee::tools::durable::AdapterError;
use bee::tools::{Tool, ToolRegistry, ToolResult};
use bee::Sandbox;
use serde_json::json;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn session() -> SessionId {
    SessionId("durable-evidence-fixture".into())
}

struct Mutation {
    count: PathBuf,
}
#[async_trait::async_trait]
impl Tool for Mutation {
    fn name(&self) -> &'static str {
        "fixture_mutation"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "Test effect".into(),
            parameters: json!({"type":"object"}),
        }
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.count)
            .unwrap();
        file.write_all(b"effect\n").unwrap();
        file.sync_all().unwrap();
        if std::env::var("BEE_EVIDENCE_CRASH_MODE").as_deref() == Ok("after-effect") {
            pause_for_kill();
        }
        let mut result = ToolResult::error("exact partial observation");
        result.exit_code = Some(7);
        result.truncated = true;
        result.original_len = Some(200_000);
        result
    }
}

fn registry(root: &Path) -> ToolRegistry {
    let mut registry = ToolRegistry::new().with(Box::new(Mutation {
        count: root.join("count"),
    }));
    registry
        .enable_evidence(EvidenceStore::for_session(root.join("evidence"), &session()).unwrap());
    registry
}
fn apply(store: &mut Store, state: &mut State, event: Event) -> Vec<Effect> {
    let effects = on_event(state, event).unwrap();
    if let [Effect::Persist(commit)] = effects.as_slice() {
        let id = store.commit(commit).unwrap();
        on_event(state, Event::Committed(id)).unwrap()
    } else {
        effects
    }
}
fn activate(store: &mut Store) -> (State, Vec<Effect>) {
    let mut state = State::open(store.load().unwrap(), store.activation()).unwrap();
    let effects = apply(store, &mut state, Event::Activate { now_ms: 1 });
    (state, effects)
}
fn spec(registry: &ToolRegistry) -> OperationSpec {
    registry
        .durable_spec(
            &ToolCall {
                id: "provider-call".into(),
                name: "fixture_mutation".into(),
                arguments: json!({"recovery":"RetrySafe"}),
            },
            "host-config-v1",
            1000,
        )
        .unwrap()
}
fn start(store: &mut Store, state: &mut State, registry: &ToolRegistry) -> Attempt {
    apply(
        store,
        state,
        Event::Submit {
            id: OperationId(1),
            spec: spec(registry),
        },
    );
    let effects = apply(
        store,
        state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 2,
        },
    );
    let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
        panic!("{effects:?}")
    };
    attempt.clone()
}
async fn execute(registry: &ToolRegistry, state: &State, attempt: &Attempt) -> Completion {
    registry
        .execute_durable(state, attempt, "host-config-v1", 3, &Sandbox::host(vec![]))
        .await
        .unwrap()
}
fn publication_path(root: &Path, result: &Completion) -> PathBuf {
    root.join("evidence").join(format!(
        "{}.json",
        &result.receipt.as_ref().unwrap().id[7..]
    ))
}

#[tokio::test]
async fn intent_and_publication_commits_gate_execution_and_evidence_delivery() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry(root.path());
    let mut store = Store::open(&root.path().join("session"), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    apply(
        &mut store,
        &mut state,
        Event::Submit {
            id: OperationId(1),
            spec: spec(&registry),
        },
    );
    let pending = on_event(
        &mut state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 2,
        },
    )
    .unwrap();
    let [Effect::Persist(commit)] = pending.as_slice() else {
        panic!()
    };
    let Phase::Running { attempt } = &commit.snapshot.operation(OperationId(1)).unwrap().phase
    else {
        panic!()
    };
    assert!(matches!(
        registry
            .execute_durable(&state, attempt, "host-config-v1", 3, &Sandbox::host(vec![]))
            .await,
        Err(AdapterError::Core(Error::Busy))
    ));
    assert!(!root.path().join("count").exists());
    let attempt = attempt.clone();
    let id = store.commit(commit).unwrap();
    on_event(&mut state, Event::Committed(id)).unwrap();
    let result = execute(&registry, &state, &attempt).await;
    assert!(!publication_path(root.path(), &result).exists());
    let effects = apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt: attempt.clone(),
            result: result.clone(),
        },
    );
    let [Effect::Publish { token, .. }] = effects.as_slice() else {
        panic!()
    };
    assert!(state.committed().entries().is_empty());
    let published = registry.publish_durable(&state, token).unwrap();
    assert_eq!(
        std::fs::read_to_string(publication_path(root.path(), &result)).unwrap(),
        result.receipt.as_ref().unwrap().bytes
    );
    assert!(state.committed().entries().is_empty());
    let release = apply(&mut store, &mut state, published);
    let [Effect::Deliver(entry)] = release.as_slice() else {
        panic!()
    };
    let delivered = registry.deliver_durable(&state, entry).unwrap();
    assert_eq!(serde_json::to_value(&delivered).unwrap(), result.output);
    assert_eq!(delivered.exit_code, Some(7));
    assert!(delivered.is_error && delivered.truncated);
    assert_eq!(delivered.original_len, Some(200_000));
    let evidence = EvidenceStore::for_session(root.path().join("evidence"), &session()).unwrap();
    let id = delivered.receipt_id.unwrap();
    assert_eq!(evidence.get(&id).unwrap().attempt, Some(attempt));
    evidence
        .validate_citations(std::slice::from_ref(&id))
        .unwrap();
    let other =
        EvidenceStore::for_session(root.path().join("evidence"), &SessionId("unrelated".into()))
            .unwrap();
    assert!(other.validate_citations(&[id]).is_err());
    assert_eq!(
        std::fs::read(root.path().join("count")).unwrap(),
        b"effect\n"
    );
}

#[tokio::test]
async fn current_contract_configuration_and_deadline_are_checked_before_execution() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry(root.path());
    let original = spec(&registry);
    assert_eq!(original.recovery, RecoveryPolicy::NeverReplay);
    for changed in ["version", "policy", "schema", "name"] {
        let mut incompatible = original.clone();
        match changed {
            "version" => incompatible.version += 1,
            "policy" => incompatible.recovery = RecoveryPolicy::RetrySafe { max_attempts: 10 },
            "schema" => incompatible.input["schema"] = json!({}),
            "name" => incompatible.name = "different".into(),
            _ => unreachable!(),
        }
        assert!(registry
            .check_durable_compatibility(&incompatible, "host-config-v1")
            .is_err());
    }
    let mut store = Store::open(&root.path().join("session"), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let attempt = start(&mut store, &mut state, &registry);
    let sandbox = Sandbox::host(vec![]);
    assert!(matches!(
        registry
            .execute_durable(&state, &attempt, "tightened-config", 3, &sandbox)
            .await,
        Err(AdapterError::Incompatible)
    ));
    assert!(matches!(
        registry
            .execute_durable(&state, &attempt, "host-config-v1", 1000, &sandbox)
            .await,
        Err(AdapterError::Expired)
    ));
    assert!(!root.path().join("count").exists());
    drop(store);
    let mut reopened = Store::open(&root.path().join("session"), session()).unwrap();
    let (recovered, _) = activate(&mut reopened);
    assert!(matches!(
        registry
            .execute_durable(&recovered, &attempt, "host-config-v1", 4, &sandbox)
            .await,
        Err(AdapterError::Core(Error::Stale))
    ));
}

#[tokio::test]
async fn corrupt_publication_and_missing_replayed_evidence_block_delivery_without_rerun() {
    let root = tempfile::tempdir().unwrap();
    let registry = registry(root.path());
    let mut store = Store::open(&root.path().join("session"), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let attempt = start(&mut store, &mut state, &registry);
    let result = execute(&registry, &state, &attempt).await;
    let effects = apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt,
            result: result.clone(),
        },
    );
    let [Effect::Publish { token, .. }] = effects.as_slice() else {
        panic!()
    };
    let event = registry.publish_durable(&state, token).unwrap();
    let path = publication_path(root.path(), &result);
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(registry.publish_durable(&state, token).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
    assert!(state.committed().entries().is_empty());
    std::fs::remove_file(&path).unwrap();
    assert_eq!(registry.publish_durable(&state, token).unwrap(), event);
    let delivered = apply(&mut store, &mut state, event);
    let [Effect::Deliver(entry)] = delivered.as_slice() else {
        panic!()
    };
    assert!(registry.deliver_durable(&state, entry).is_ok());
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(registry.deliver_durable(&state, entry).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(registry.deliver_durable(&state, entry).is_err());
    drop(store);
    let mut reopened = Store::open(&root.path().join("session"), session()).unwrap();
    let (state, effects) = activate(&mut reopened);
    let [Effect::Deliver(replayed)] = effects.as_slice() else {
        panic!()
    };
    assert_eq!(replayed, entry);
    assert!(registry.deliver_durable(&state, replayed).is_err());
    assert_eq!(
        std::fs::read(root.path().join("count")).unwrap(),
        b"effect\n"
    );
}

#[tokio::test]
async fn mismatched_attempt_or_result_bytes_cannot_be_published() {
    for tampering in ["attempt", "result", "digest"] {
        let root = tempfile::tempdir().unwrap();
        let registry = registry(root.path());
        let mut store = Store::open(&root.path().join("session"), session()).unwrap();
        let (mut state, _) = activate(&mut store);
        let attempt = start(&mut store, &mut state, &registry);
        let mut result = execute(&registry, &state, &attempt).await;
        match tampering {
            "attempt" => {
                let evidence =
                    EvidenceStore::for_session(root.path().join("evidence"), &session()).unwrap();
                let mut wrong = attempt.clone();
                wrong.number += 1;
                result.receipt = Some(
                    evidence
                        .prepare(
                            &wrong,
                            &ToolCall {
                                id: "provider-call".into(),
                                name: "fixture_mutation".into(),
                                arguments: json!({"recovery":"RetrySafe"}),
                            },
                            &ToolResult::ok("other"),
                            "3".into(),
                        )
                        .unwrap(),
                );
            }
            "result" => result.output["content"] = json!("invented"),
            "digest" => result.receipt.as_mut().unwrap().bytes.push(' '),
            _ => unreachable!(),
        }
        let effects = apply(&mut store, &mut state, Event::Completed { attempt, result });
        let [Effect::Publish { token, .. }] = effects.as_slice() else {
            panic!()
        };
        assert!(
            registry.publish_durable(&state, token).is_err(),
            "{tampering}"
        );
        assert!(state.committed().entries().is_empty());
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn pause_for_kill() {
    println!("BEE_EVIDENCE_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
fn paused_child(root: &Path, mode: &str) -> ChildGuard {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "crash_child", "--nocapture"])
        .env("BEE_EVIDENCE_CRASH_PATH", root)
        .env("BEE_EVIDENCE_CRASH_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let guard = ChildGuard(child);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.is_ok_and(|line| line == "BEE_EVIDENCE_READY") {
                let _ = sender.send(());
                break;
            }
        }
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("child did not reach crash point");
    guard
}

#[tokio::test]
#[ignore = "subprocess fixture invoked by crash tests"]
async fn crash_child() {
    let root = PathBuf::from(std::env::var_os("BEE_EVIDENCE_CRASH_PATH").unwrap());
    let mode = std::env::var("BEE_EVIDENCE_CRASH_MODE").unwrap();
    let registry = registry(&root);
    let mut store = Store::open(&root.join("session"), session()).unwrap();
    store.admit("request", &json!({"task":"observe"})).unwrap();
    let (mut state, _) = activate(&mut store);
    let attempt = start(&mut store, &mut state, &registry);
    let result = execute(&registry, &state, &attempt).await;
    // Test oracle only: recovery reads the session database, never this fixture file.
    std::fs::write(
        root.join("expected.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    if mode == "before-result" {
        pause_for_kill();
    }
    let effects = apply(&mut store, &mut state, Event::Completed { attempt, result });
    if mode == "after-result" {
        pause_for_kill();
    }
    let [Effect::Publish { token, .. }] = effects.as_slice() else {
        panic!()
    };
    let event = registry.publish_durable(&state, token).unwrap();
    if mode == "after-publication" {
        pause_for_kill();
    }
    let effects = apply(&mut store, &mut state, event);
    assert!(matches!(effects.as_slice(), [Effect::Deliver(_)]));
    if mode == "after-transcript" {
        pause_for_kill();
    }
    panic!("unknown mode: {mode}");
}

#[test]
fn sigkill_recovers_exact_receipts_and_never_repeats_uncertain_mutations() {
    for mode in [
        "after-effect",
        "before-result",
        "after-result",
        "after-publication",
        "after-transcript",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut child = paused_child(root.path(), mode);
        child.0.kill().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        let registry = registry(root.path());
        let mut store = Store::open(&root.path().join("session"), session()).unwrap();
        assert_eq!(store.submissions(0, 100).unwrap().len(), 1);
        let (mut state, effects) = activate(&mut store);
        if matches!(mode, "after-effect" | "before-result") {
            let [Effect::Inspect(token)] = effects.as_slice() else {
                panic!("{effects:?}")
            };
            // The fixture ran in the killed process, so its executor is proven stopped. The
            // append still may have happened; quiescence cannot make a mutation retry-safe.
            let outcome = apply(
                &mut store,
                &mut state,
                Event::Recovered {
                    token: token.clone(),
                    outcome: RecoveryOutcome::Quiescent,
                    now_ms: 4,
                },
            );
            assert_eq!(
                outcome,
                vec![Effect::Unresolved {
                    id: OperationId(1),
                    reason: UnresolvedReason::UnknownOutcome
                }]
            );
            assert!(state.committed().entries().is_empty());
        } else {
            let expected: Completion =
                serde_json::from_slice(&std::fs::read(root.path().join("expected.json")).unwrap())
                    .unwrap();
            let delivery = if let [Effect::Publish { token, result }] = effects.as_slice() {
                assert_eq!(result, &expected, "{mode}");
                let event = registry.publish_durable(&state, token).unwrap();
                apply(&mut store, &mut state, event)
            } else {
                effects
            };
            let [Effect::Deliver(entry)] = delivery.as_slice() else {
                panic!("{delivery:?}")
            };
            assert_eq!(entry.result, expected);
            let result = registry.deliver_durable(&state, entry).unwrap();
            assert_eq!(serde_json::to_value(result).unwrap(), expected.output);
            assert_eq!(
                std::fs::read_to_string(publication_path(root.path(), &expected)).unwrap(),
                expected.receipt.as_ref().unwrap().bytes
            );
            drop(store);
            let mut reopened = Store::open(&root.path().join("session"), session()).unwrap();
            let (state, replay) = activate(&mut reopened);
            assert_eq!(replay, delivery);
            registry.deliver_durable(&state, entry).unwrap();
        }
        assert_eq!(
            std::fs::read(root.path().join("count")).unwrap(),
            b"effect\n",
            "{mode}"
        );
    }
}

#[cfg(feature = "repro")]
#[test]
fn built_tool_recovery_contracts_are_conservative_and_not_model_selected() {
    let registry = bee::tools::registry_for(
        &[
            "bash",
            "write_file",
            "record_finding",
            "repro_run",
            "hunt_checkpoint",
            "hunt_resume",
            "source_pin",
            "source_read",
            "receipt_get",
        ]
        .map(str::to_owned),
        None,
    );
    for schema in registry.schemas() {
        let spec = registry
            .durable_spec(
                &ToolCall {
                    id: "call".into(),
                    name: schema.name.clone(),
                    arguments: json!({"recovery":"RetrySafe","max_attempts":999}),
                },
                "configuration",
                1000,
            )
            .unwrap();
        let expected = if matches!(
            schema.name.as_str(),
            "source_pin" | "source_read" | "receipt_get"
        ) {
            RecoveryPolicy::RetrySafe { max_attempts: 2 }
        } else if cfg!(feature = "durable-sessions") && schema.name == "repro_run" {
            RecoveryPolicy::Reconcile
        } else {
            RecoveryPolicy::NeverReplay
        };
        assert_eq!(spec.recovery, expected, "{}", schema.name);
    }
}
