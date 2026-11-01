use super::*;
use crate::session::durable::*;
use serde_json::json;
use std::io::{BufRead, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Child, Command, Stdio};

fn session() -> SessionId {
    SessionId("store-fixture".into())
}

fn private_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn spec() -> OperationSpec {
    OperationSpec {
        kind: WorkKind::Tool,
        name: "fixture".into(),
        version: 1,
        input: json!({"x":1}),
        recovery: RecoveryPolicy::NeverReplay,
        deadline_ms: 1000,
    }
}
fn result() -> Completion {
    Completion {
        duration_ms: 0,
        audit: vec![],
        receipt: None,
        output: json!({"stdout":"observed"}),
    }
}

fn proposed(state: &mut State, event: Event) -> Commit {
    let mut effects = on_event(state, event).unwrap();
    let Effect::Persist(commit) = effects.remove(0) else {
        panic!("expected persistence")
    };
    assert!(effects.is_empty());
    *commit
}

fn apply(store: &mut Store, state: &mut State, event: Event) -> Vec<Effect> {
    let effects = on_event(state, event).unwrap();
    if let [Effect::Persist(commit)] = effects.as_slice() {
        match store.commit(commit) {
            Ok(id) => on_event(state, Event::Committed(id)).unwrap(),
            Err(error) => {
                assert_eq!(
                    on_event(state, Event::CommitFailed(commit.id.clone())).unwrap(),
                    vec![Effect::Suspended]
                );
                panic!("commit failed: {error}")
            }
        }
    } else {
        effects
    }
}

fn activate(store: &mut Store) -> (State, Vec<Effect>) {
    let mut state = State::open(store.load().unwrap(), store.activation()).unwrap();
    let effects = apply(store, &mut state, Event::Activate { now_ms: 1 });
    (state, effects)
}

#[test]
fn commits_round_trip_and_reopen_fences_old_activations() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let activation = store.activation();
    let (mut state, _) = activate(&mut store);
    apply(
        &mut store,
        &mut state,
        Event::Submit {
            id: OperationId(1),
            spec: spec(),
        },
    );
    let commit = proposed(
        &mut state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 2,
        },
    );
    let id = store.commit(&commit).unwrap();
    assert_eq!(store.commit(&commit).unwrap(), id); // identical repeated acknowledgement
    let effects = on_event(&mut state, Event::Committed(id)).unwrap();
    let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
        panic!()
    };
    apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt: attempt.clone(),
            result: result(),
        },
    );
    let expected = store.load().unwrap();
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_ne!(store.activation(), activation);
    assert_eq!(store.load().unwrap(), expected);
    assert!(matches!(store.commit(&commit), Err(StoreError::Stale)));
    let (_, effects) = activate(&mut store);
    assert_eq!(
        effects,
        vec![Effect::Deliver(expected.entries()[0].clone())]
    );
}

#[test]
fn admission_is_idempotent_canonical_bounded_and_paged() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let input = serde_json::from_str(r#"{"b":[{"z":1,"a":2}],"a":true}"#).unwrap();
    let first = store.admit("request-1", &input).unwrap();
    assert_eq!(
        store
            .admit("request-1", &json!({"a":true,"b":[{"a":2,"z":1}]}))
            .unwrap(),
        first
    );
    assert!(matches!(
        store.admit("request-1", &json!("changed")),
        Err(StoreError::Conflict)
    ));
    assert!(!store.is_suspended());
    let second = store.admit("request-2", &json!("next")).unwrap();
    assert_eq!(store.submissions(0, 1).unwrap(), vec![first.clone()]);
    assert_eq!(
        store.submissions(first.sequence, 1).unwrap(),
        vec![second.clone()]
    );
    assert!(store.submissions(second.sequence, 100).unwrap().is_empty());
    assert!(matches!(
        store.submissions(0, 101),
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        store.admit("", &json!(null)),
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        store.admit("too-large", &json!("x".repeat(MAX_PAYLOAD_BYTES))),
        Err(StoreError::InvalidInput)
    ));
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(store.admit("request-1", &input).unwrap(), first);
    assert_eq!(store.submissions(0, 100).unwrap(), vec![first, second]);
}

#[test]
fn pruning_retires_admissions_atomically_and_refuses_them_forever() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let old = store.admit("old", &json!("first")).unwrap();
    let kept = store.admit("kept", &json!("second")).unwrap();
    for id in [1, 2] {
        apply(
            &mut store,
            &mut state,
            Event::Submit {
                id: OperationId(id),
                spec: spec(),
            },
        );
        let effects = apply(
            &mut store,
            &mut state,
            Event::Authorize {
                id: OperationId(id),
                now_ms: 2,
            },
        );
        let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
            panic!()
        };
        apply(
            &mut store,
            &mut state,
            Event::Completed {
                attempt: attempt.clone(),
                result: result(),
            },
        );
    }
    let before = store.load().unwrap();
    let prune = proposed(
        &mut state,
        Event::Prune {
            operations: vec![OperationId(1)],
        },
    );
    // Retiring an unknown admission rolls back the snapshot too.
    assert!(matches!(
        store.commit_retiring(&prune, &["missing".into()]),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.load().unwrap(), before);
    assert_eq!(
        store.submissions(0, 100).unwrap(),
        vec![old.clone(), kept.clone()]
    );
    let id = store.commit_retiring(&prune, &["old".into()]).unwrap();
    on_event(&mut state, Event::Committed(id)).unwrap();
    assert!(store.load().unwrap().operation(OperationId(1)).is_none());
    assert_eq!(store.submissions(0, 100).unwrap(), vec![kept.clone()]);
    for input in [json!("first"), json!("changed")] {
        assert!(matches!(
            store.admit("old", &input),
            Err(StoreError::Retired)
        ));
    }
    assert!(!store.is_suspended());
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert!(matches!(
        store.admit("old", &json!("first")),
        Err(StoreError::Retired)
    ));
    assert_eq!(store.submissions(0, 100).unwrap(), vec![kept]);
    let next = store.admit("next", &json!("third")).unwrap();
    assert!(next.sequence > old.sequence);
}

#[test]
fn invalid_and_conflicting_commits_do_not_advance_storage() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let commit = proposed(
        &mut state,
        Event::Submit {
            id: OperationId(1),
            spec: spec(),
        },
    );
    let before = store.load().unwrap();
    let mut invalid = commit.clone();
    invalid.expected_revision = 999;
    assert!(matches!(
        store.commit(&invalid),
        Err(StoreError::InvalidInput)
    ));
    assert_eq!(store.load().unwrap(), before);
    store.commit(&commit).unwrap();
    let mut conflicting = commit.clone();
    conflicting
        .snapshot
        .operations
        .get_mut(&OperationId(1))
        .unwrap()
        .spec
        .input = json!("different");
    assert!(matches!(
        store.commit(&conflicting),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.load().unwrap(), commit.snapshot);
    assert!(!store.is_suspended());
}

#[test]
fn private_permissions_symlinks_and_hardlinks_are_enforced() {
    for filename in [
        "session.sqlite3",
        "session.sqlite3-wal",
        "session.sqlite3-shm",
        "session.sqlite3-journal",
    ] {
        for hardlink in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("state");
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let outside = root.path().join("outside");
            std::fs::write(&outside, b"untouched").unwrap();
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
            if hardlink {
                std::fs::hard_link(&outside, dir.join(filename)).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, dir.join(filename)).unwrap();
            }
            assert!(Store::open(&dir, session()).is_err());
            assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        }
    }
    let root = tempfile::tempdir().unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias).unwrap();
    assert!(Store::open(&alias.join("state"), session()).is_err());
    assert!(Store::open(&root.path().join("../state"), session()).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Store::open(root.path(), session()),
        Err(StoreError::UnsafePath)
    ));
}

#[test]
fn schema_and_identity_mismatches_never_reset_existing_data() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    store.admit("preserve", &json!("saved")).unwrap();
    drop(store);
    assert!(matches!(
        Store::open(dir.path(), SessionId("other".into())),
        Err(StoreError::WrongSession)
    ));
    for version in [1, 2, 3, 4, 999] {
        let db = Connection::open(dir.path().join("session.sqlite3")).unwrap();
        db.pragma_update(None, "user_version", version).unwrap();
        drop(db);
        assert!(matches!(
            Store::open(dir.path(), session()),
            Err(StoreError::Unsupported)
        ));
    }
    let db = Connection::open(dir.path().join("session.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM submissions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    db.pragma_update(None, "user_version", STORE_VERSION)
        .unwrap();
    db.execute("UPDATE session SET snapshot=x'7b7d'", [])
        .unwrap();
    drop(db);
    assert!(Store::open(dir.path(), session()).is_err());
}

#[test]
fn full_database_rolls_back_and_suspends_the_writer_and_core() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    apply(
        &mut store,
        &mut state,
        Event::Submit {
            id: OperationId(1),
            spec: spec(),
        },
    );
    let effects = apply(
        &mut store,
        &mut state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 2,
        },
    );
    let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
        panic!()
    };
    let before = state.committed().clone();
    let pages: i64 = store
        .conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    store
        .conn
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let commit = proposed(
        &mut state,
        Event::Completed {
            attempt: attempt.clone(),
            result: Completion {
                duration_ms: 0,
                audit: vec![],
                receipt: None,
                output: json!("x".repeat(50_000)),
            },
        },
    );
    let error = store.commit(&commit).unwrap_err();
    assert!(
        matches!(error, StoreError::Sqlite(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::DiskFull)
    );
    assert!(store.is_suspended());
    assert_eq!(
        on_event(&mut state, Event::CommitFailed(commit.id)).unwrap(),
        vec![Effect::Suspended]
    );
    assert_eq!(state.committed(), &before);
    assert!(matches!(store.load(), Err(StoreError::Suspended)));
    drop(store);
    let mut reopened = Store::open(dir.path(), session()).unwrap();
    assert_eq!(reopened.load().unwrap(), before);
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn paused_child(path: &Path, mode: &str) -> ChildGuard {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "session::durable::store::tests::crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("BEE_STORE_CRASH_PATH", path)
        .env("BEE_STORE_CRASH_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let guard = ChildGuard(child);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.is_ok_and(|line| line == "BEE_STORE_READY") {
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

fn pause_for_kill() {
    println!("BEE_STORE_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
#[ignore = "subprocess fixture, invoked explicitly by crash tests"]
fn crash_child() {
    let path = std::env::var_os("BEE_STORE_CRASH_PATH").expect("fixture path");
    let path = Path::new(&path);
    let mode = std::env::var("BEE_STORE_CRASH_MODE").unwrap();
    if mode.starts_with("gc-") {
        composition::crash_reclamation(path, &mode);
        return;
    }
    // SAFETY: isolated test subprocess; proves permissions do not depend on a restrictive umask.
    unsafe {
        libc::umask(0);
    }
    if mode == "migration" {
        let directory = Directory::open(path).unwrap();
        let mut conn = Connection::open(directory.database()).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute_batch(SCHEMA_V1).unwrap();
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        tx.pragma_update(None, "user_version", STORE_VERSION)
            .unwrap();
        pause_for_kill();
        drop(tx);
    }
    let mut store = Store::open(path, session()).unwrap();
    store.admit("input", &json!({"task":"fixture"})).unwrap();
    if mode == "admission" {
        pause_for_kill();
    }
    let (mut state, _) = activate(&mut store);
    apply(
        &mut store,
        &mut state,
        Event::Submit {
            id: OperationId(1),
            spec: spec(),
        },
    );
    let intent = proposed(
        &mut state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 2,
        },
    );
    if mode == "before-intent" {
        pause_for_kill();
    }
    store.commit(&intent).unwrap();
    if mode == "after-intent" {
        pause_for_kill();
    }
    let effects = on_event(&mut state, Event::Committed(intent.id)).unwrap();
    let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
        panic!()
    };
    let mut effect = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path.join("effect-count"))
        .unwrap();
    effect.write_all(b"effect\n").unwrap();
    effect.sync_all().unwrap();
    if mode == "after-effect" {
        pause_for_kill();
    }
    let completed = proposed(
        &mut state,
        Event::Completed {
            attempt: attempt.clone(),
            result: result(),
        },
    );
    if mode == "transaction" {
        // Kill with a real uncommitted WAL transaction; neither update may survive.
        store.conn.pragma_update(None, "cache_size", 1).unwrap();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE session SET revision=?1, snapshot=?2",
            params![
                i64::try_from(completed.id.revision).unwrap(),
                serde_json::to_vec(&completed.snapshot).unwrap()
            ],
        )
        .unwrap();
        tx.execute("INSERT INTO submissions(request_id,input,digest) VALUES('uncommitted',?1,'uncommitted')", [vec![b'x'; 100_000]]).unwrap();
        pause_for_kill();
        drop(tx);
    }
    store.commit(&completed).unwrap();
    if mode == "after-result" {
        pause_for_kill();
    }
    panic!("unknown crash mode: {mode}");
}

#[test]
fn process_crashes_recover_only_committed_state_and_keep_effects_ambiguous() {
    for mode in [
        "before-intent",
        "after-intent",
        "after-effect",
        "transaction",
        "after-result",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session");
        let mut child = paused_child(&path, mode);
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let mut store = Store::open(&path, session()).unwrap();
        assert_eq!(store.submissions(0, 100).unwrap().len(), 1, "{mode}");
        let (mut state, effects) = activate(&mut store);
        let count = std::fs::read(path.join("effect-count")).unwrap_or_default();
        if mode == "before-intent" {
            assert_eq!(effects, vec![Effect::Ready(OperationId(1))]);
            assert!(count.is_empty());
        } else if mode == "after-result" {
            let [Effect::Deliver(entry)] = effects.as_slice() else {
                panic!("{effects:?}")
            };
            assert_eq!(entry.result, result());
            assert_eq!(entry.sequence, 1);
            assert_eq!(count, b"effect\n");
            assert_eq!(
                apply(&mut store, &mut state, Event::Replay { after_sequence: 0 }),
                effects
            );
        } else {
            let [Effect::Inspect(token)] = effects.as_slice() else {
                panic!("{effects:?}")
            };
            assert_eq!(
                apply(
                    &mut store,
                    &mut state,
                    Event::Recovered {
                        token: token.clone(),
                        outcome: RecoveryOutcome::Unknown,
                        now_ms: 3
                    }
                ),
                vec![Effect::Unresolved {
                    id: OperationId(1),
                    reason: UnresolvedReason::UnknownOutcome
                }]
            );
            assert!(store.load().unwrap().entries().is_empty());
            if mode == "after-intent" {
                assert!(count.is_empty());
            } else {
                assert_eq!(count, b"effect\n");
            }
        }
        assert_eq!(
            std::fs::read(path.join("effect-count")).unwrap_or_default(),
            count
        );
    }
}

#[test]
fn interrupted_schema_creation_rolls_back_and_can_be_initialized_again() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session");
    let mut child = paused_child(&path, "migration");
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut store = Store::open(&path, session()).unwrap();
    assert_eq!(store.load().unwrap(), Snapshot::empty(session()));
    assert!(store.submissions(0, 100).unwrap().is_empty());
    store
        .admit("input", &json!("admitted after migration"))
        .unwrap();
}

#[test]
fn writer_lock_and_admitted_input_survive_real_process_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session");
    let mut child = paused_child(&path, "admission");
    assert!(matches!(
        Store::open(&path, session()),
        Err(StoreError::Locked)
    ));
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    for name in [
        "session.sqlite3",
        "session.sqlite3-wal",
        "session.sqlite3-shm",
    ] {
        assert_eq!(
            std::fs::metadata(path.join(name)).unwrap().mode() & 0o777,
            0o600
        );
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut store = Store::open(&path, session()).unwrap();
    let input = store.submissions(0, 1).unwrap().remove(0);
    assert_eq!(
        store.admit("input", &json!({"task":"fixture"})).unwrap(),
        input
    );
    assert!(matches!(
        store.admit("input", &json!("different")),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        Store::open(&path, session()),
        Err(StoreError::Locked)
    ));
}

#[test]
fn worker_journal_is_append_only_attempt_bound_and_detects_corruption() {
    use super::journal::{Probe, ProbeResult, WorkerRecord};
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let mut spec = spec();
    spec.recovery = RecoveryPolicy::Reconcile;
    spec.deadline_ms = u64::MAX;
    apply(
        &mut store,
        &mut state,
        Event::Submit {
            id: OperationId(1),
            spec: spec.clone(),
        },
    );
    let effects = apply(
        &mut store,
        &mut state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 2,
        },
    );
    let Effect::Dispatch { attempt, .. } = &effects[0] else {
        panic!("not dispatched")
    };
    let mut record = WorkerRecord {
        version: 1,
        revision: 1,
        attempt: attempt.clone(),
        spec,
        probes: vec![],
        completion: None,
    };
    store.worker_write(&record).unwrap();
    record.revision += 1;
    record.probes.push(Probe {
        key: "positive:1".into(),
        input_sha256: "a".repeat(64),
        result: None,
    });
    store.worker_write(&record).unwrap();
    let mut invalid = record.clone();
    invalid.revision += 1;
    invalid.probes.push(Probe {
        key: "positive:2".into(),
        input_sha256: "b".repeat(64),
        result: None,
    });
    assert!(matches!(
        store.worker_write(&invalid),
        Err(StoreError::Conflict)
    ));
    record.revision += 1;
    record.probes[0].result = Some(ProbeResult {
        output: json!({"observed":"once"}),
        duration_ms: 12,
        audit: vec![],
    });
    store.worker_write(&record).unwrap();
    store.worker_write(&record).unwrap();
    invalid = record.clone();
    invalid.revision += 1;
    invalid.probes[0].result.as_mut().unwrap().output = json!("changed");
    assert!(matches!(
        store.worker_write(&invalid),
        Err(StoreError::Conflict)
    ));
    invalid = record.clone();
    invalid.attempt.activation = ActivationId(0);
    assert!(matches!(
        store.worker_write(&invalid),
        Err(StoreError::Corrupt)
    ));
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(
        store.worker_load(&record.attempt).unwrap(),
        Some(record.clone())
    );
    store
        .conn
        .execute("UPDATE workers SET payload=?1", [b"{}".as_slice()])
        .unwrap();
    assert!(matches!(
        store.worker_load(&record.attempt),
        Err(StoreError::Corrupt)
    ));
    assert!(store.is_suspended());
}

#[test]
fn archived_messages_append_with_their_commit_and_only_in_order() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let rows = |from: u64, n: u64| -> Vec<Append> {
        (from..from + n)
            .map(|position| Append {
                position,
                message: format!("{{\"m\":{position}}}").into_bytes(),
            })
            .collect()
    };
    let first = proposed(&mut state, Event::Checkpoint(json!({"n": 1})));
    // A gap, a reordering, or rows past the end roll the snapshot back with them.
    let before = store.load().unwrap();
    for bad in [
        rows(1, 2),
        vec![rows(0, 2)[1].clone(), rows(0, 2)[0].clone()],
    ] {
        assert!(store.commit_appending(&first, &[], &bad).is_err());
        assert_eq!(store.load().unwrap(), before);
        assert!(store.conversation().unwrap().is_empty());
    }
    let id = store.commit_appending(&first, &[], &rows(0, 3)).unwrap();
    // An acknowledged retry names exactly the rows it stored.
    assert_eq!(
        store.commit_appending(&first, &[], &rows(0, 3)).unwrap(),
        id
    );
    assert!(matches!(
        store.commit_appending(&first, &[], &rows(0, 4)),
        Err(StoreError::Conflict)
    ));
    on_event(&mut state, Event::Committed(id)).unwrap();
    let second = proposed(&mut state, Event::Checkpoint(json!({"n": 2})));
    assert!(matches!(
        store.commit_appending(&second, &[], &rows(0, 1)),
        Err(StoreError::Conflict)
    ));
    let id = store.commit_appending(&second, &[], &rows(3, 2)).unwrap();
    on_event(&mut state, Event::Committed(id)).unwrap();
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    let stored = store.conversation().unwrap();
    assert_eq!(
        stored,
        rows(0, 5)
            .into_iter()
            .map(|a| a.message)
            .collect::<Vec<_>>()
    );
    drop(store);
    let db = Connection::open(dir.path().join("session.sqlite3")).unwrap();
    db.execute(
        "UPDATE conversation SET message=x'7b7d' WHERE position=2",
        [],
    )
    .unwrap();
    drop(db);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert!(matches!(store.conversation(), Err(StoreError::Corrupt)));
}

#[test]
fn a_version_5_store_gains_the_conversation_table_on_open() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    store.admit("kept", &json!("saved")).unwrap();
    drop(store);
    let db = Connection::open(dir.path().join("session.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE conversation; DROP TABLE checkpoints; PRAGMA user_version=5;")
        .unwrap();
    drop(db);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert!(store.conversation().unwrap().is_empty());
    assert_eq!(store.submissions(0, 100).unwrap().len(), 1);
    drop(store);
    let db = Connection::open(dir.path().join("session.sqlite3")).unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, STORE_VERSION);
}

#[test]
fn immediate_reopen_while_fork_child_holds_inherited_descriptors() {
    use std::os::fd::{AsRawFd, FromRawFd};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session");
    let session = SessionId("fork-lock".into());
    let store = Store::open(&path, session.clone()).unwrap();
    let mut pipe = [0; 2];
    // SAFETY: writable two-descriptor buffer.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: both descriptors were freshly allocated by pipe2.
    let (reader, writer) = unsafe {
        (
            std::fs::File::from_raw_fd(pipe[0]),
            std::fs::File::from_raw_fd(pipe[1]),
        )
    };
    // SAFETY: the child executes only async-signal-safe syscalls and never
    // returns to Rust, touches SQLite, or runs inherited destructors.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::close(writer.as_raw_fd());
            let mut byte = 0u8;
            libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    drop(reader);
    assert!(matches!(
        Store::open(&path, session.clone()),
        Err(StoreError::Locked)
    ));
    drop(store);
    let reopened = Store::open(&path, session.clone());
    // Release and reap even when the regression assertion below fails.
    drop(writer);
    let mut status = 0;
    // SAFETY: pid is our child and status is writable.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    let reopened = reopened.expect("a pre-exec child must not retain the closed writer's lock");
    assert!(matches!(
        Store::open(&path, session),
        Err(StoreError::Locked)
    ));
    drop(reopened);
}

mod composition;
