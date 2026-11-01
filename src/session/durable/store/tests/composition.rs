use super::*;
use crate::session::durable::composition::{
    CheckpointRef, ScriptEvent, ScriptParent, ScriptPhase, ScriptResume, ScriptSpec,
    MAX_CHECKPOINT_BYTES,
};

fn script_spec() -> ScriptSpec {
    ScriptSpec {
        source_input_sha256: "a".repeat(64),
        runtime: "monty-1.4.0/postcard-1".into(),
        compatibility: "fixture-v1".into(),
        deadline_ms: 1000,
        max_calls: 2,
    }
}
fn script_event(state: &State, event: ScriptEvent) -> Event {
    Event::Script {
        activation: state.activation(),
        now_ms: 2,
        event,
    }
}
fn start(store: &mut Store, state: &mut State) {
    let event = script_event(
        state,
        ScriptEvent::Start {
            id: "script".into(),
            spec: script_spec(),
            parent: None,
        },
    );
    apply(store, state, event);
}
fn suspension(state: &State, checkpoint: CheckpointRef, child: u64, generation: u32) -> Event {
    script_event(
        state,
        ScriptEvent::Suspend {
            id: "script".into(),
            generation,
            checkpoint,
            children: vec![(OperationId(child), spec())],
            batch: false,
        },
    )
}
fn authorize(store: &mut Store, state: &mut State) -> Attempt {
    let effects = apply(
        store,
        state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 3,
        },
    );
    let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
        panic!("no dispatch: {effects:?}")
    };
    attempt.clone()
}

#[test]
fn checkpoint_child_binding_is_atomic_and_completed_effect_is_not_redispatched() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store
        .put_checkpoint(state.activation(), b"continuation")
        .unwrap();
    let event = suspension(&state, reference.clone(), 1, 0);
    let proposal = proposed(&mut state, event);
    // Until commit both the operation and its binding are absent from authoritative storage.
    assert!(store.load().unwrap().operation(OperationId(1)).is_none());
    assert!(store.load().unwrap().scripts()["script"]
        .suspensions
        .is_empty());
    let id = store.commit(&proposal).unwrap();
    let effects = on_event(&mut state, Event::Committed(id)).unwrap();
    assert_eq!(
        effects,
        vec![
            Effect::Accepted(OperationId(1)),
            Effect::Ready(OperationId(1))
        ]
    );
    let attempt = authorize(&mut store, &mut state);
    let effect_file = dir.path().join("effect");
    std::fs::write(&effect_file, b"one mutation").unwrap();
    apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt,
            result: result(),
        },
    );
    let stale_activation = state.activation();
    drop(store);
    // Simulate losing the completion acknowledgement and the interpreter process.
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, effects) = activate(&mut store);
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Dispatch { .. } | Effect::Ready(_))));
    assert_eq!(store.load_checkpoint(&reference).unwrap(), b"continuation");
    let expected = result();
    assert_eq!(
        state
            .committed()
            .resume_script("script", &script_spec(), 4)
            .unwrap(),
        ScriptResume::Continue {
            checkpoint: &reference,
            children: vec![(OperationId(1), &expected)],
            batch: false,
        }
    );
    assert_eq!(std::fs::read(effect_file).unwrap(), b"one mutation");
    assert!(matches!(
        store.put_checkpoint(stale_activation, b"late"),
        Err(StoreError::Stale)
    ));
    let stale = Event::Script {
        activation: stale_activation,
        now_ms: 4,
        event: ScriptEvent::Finish {
            id: "script".into(),
            generation: 1,
            output: json!(42),
        },
    };
    assert_eq!(on_event(&mut state, stale), Err(Error::Stale));
    let finish = script_event(
        &state,
        ScriptEvent::Finish {
            id: "script".into(),
            generation: 1,
            output: json!(42),
        },
    );
    apply(&mut store, &mut state, finish);
    assert_eq!(
        store
            .load()
            .unwrap()
            .resume_script("script", &script_spec(), 4)
            .unwrap(),
        ScriptResume::Completed(&json!(42))
    );
}

#[test]
fn uncertain_child_blocks_next_checkpoint_and_completion() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store
        .put_checkpoint(state.activation(), b"before effect")
        .unwrap();
    let event = suspension(&state, reference.clone(), 1, 0);
    apply(&mut store, &mut state, event);
    authorize(&mut store, &mut state);
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, effects) = activate(&mut store);
    let [Effect::Inspect(token)] = effects.as_slice() else {
        panic!("{effects:?}")
    };
    apply(
        &mut store,
        &mut state,
        Event::Recovered {
            token: token.clone(),
            outcome: RecoveryOutcome::Quiescent,
            now_ms: 4,
        },
    );
    assert_eq!(
        state
            .committed()
            .resume_script("script", &script_spec(), 4)
            .unwrap(),
        ScriptResume::Unresolved {
            child: OperationId(1),
            reason: UnresolvedReason::UnknownOutcome
        }
    );
    let event = suspension(&state, reference, 2, 1);
    assert_eq!(on_event(&mut state, event), Err(Error::InvalidPhase));
    let event = script_event(
        &state,
        ScriptEvent::Finish {
            id: "script".into(),
            generation: 1,
            output: json!(42),
        },
    );
    assert_eq!(on_event(&mut state, event), Err(Error::InvalidPhase));
}

#[test]
fn missing_checkpoint_never_commits_child_and_suspends_store() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let event = suspension(
        &state,
        CheckpointRef {
            sha256: "b".repeat(64),
            bytes: 4,
        },
        1,
        0,
    );
    let commit = proposed(&mut state, event);
    assert!(matches!(store.commit(&commit), Err(StoreError::Corrupt)));
    assert!(store.is_suspended());
    assert_eq!(
        on_event(&mut state, Event::CommitFailed(commit.id)).unwrap(),
        vec![Effect::Suspended]
    );
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert!(store.load().unwrap().operation(OperationId(1)).is_none());
}

#[test]
fn checkpoint_corruption_is_detected_on_reopen() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store
        .put_checkpoint(state.activation(), b"snapshot")
        .unwrap();
    let event = suspension(&state, reference, 1, 0);
    apply(&mut store, &mut state, event);
    store
        .conn
        .execute("UPDATE checkpoints SET bytes=?1", [b"tampered".as_slice()])
        .unwrap();
    drop(store);
    assert!(matches!(
        Store::open(dir.path(), session()),
        Err(StoreError::Corrupt)
    ));
}

#[test]
fn stop_deadline_generation_and_compatibility_are_enforced() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store
        .put_checkpoint(state.activation(), b"snapshot")
        .unwrap();
    let event = suspension(&state, reference.clone(), 1, 1);
    assert_eq!(on_event(&mut state, event), Err(Error::Stale));
    let mut wrong = script_spec();
    wrong.runtime = "different engine".into();
    assert_eq!(
        state.committed().resume_script("script", &wrong, 2),
        Err(Error::Conflict)
    );
    assert_eq!(
        state
            .committed()
            .resume_script("script", &script_spec(), 1000)
            .unwrap(),
        ScriptResume::Stopped(StopReason::Deadline)
    );
    let event = suspension(&state, reference.clone(), 1, 0);
    apply(&mut store, &mut state, event);
    let stop = script_event(
        &state,
        ScriptEvent::Stop {
            id: "script".into(),
        },
    );
    apply(&mut store, &mut state, stop);
    assert!(matches!(
        state.committed().operation(OperationId(1)).unwrap().phase,
        Phase::Stopped { .. }
    ));
    let event = suspension(&state, reference, 2, 1);
    assert_eq!(on_event(&mut state, event), Err(Error::Stale));
}

#[test]
fn blobs_are_idempotent_and_bounded() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let first = store.put_checkpoint(store.activation(), b"same").unwrap();
    assert_eq!(
        store.put_checkpoint(store.activation(), b"same").unwrap(),
        first
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM checkpoints", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(matches!(
        store.put_checkpoint(store.activation(), &[]),
        Err(StoreError::Limit)
    ));
    assert!(matches!(
        store.put_checkpoint(store.activation(), &vec![0; MAX_CHECKPOINT_BYTES + 1]),
        Err(StoreError::Limit)
    ));
    assert!(!store.is_suspended());
}

#[test]
fn receipt_publication_gates_resume_and_call_budget_survives_reopen() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let mut one_call = script_spec();
    one_call.max_calls = 1;
    let event = script_event(
        &state,
        ScriptEvent::Start {
            id: "script".into(),
            spec: one_call.clone(),
            parent: None,
        },
    );
    apply(&mut store, &mut state, event);
    let reference = store
        .put_checkpoint(state.activation(), b"before receipt")
        .unwrap();
    let event = suspension(&state, reference.clone(), 1, 0);
    apply(&mut store, &mut state, event);
    let attempt = authorize(&mut store, &mut state);
    let mut completion = result();
    completion.receipt = Some(ReceiptPublication {
        id: format!("sha256:{}", "f".repeat(64)),
        bytes: "exact receipt".into(),
    });
    let effects = apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt,
            result: completion,
        },
    );
    let [Effect::Publish { token, result }] = effects.as_slice() else {
        panic!("{effects:?}");
    };
    assert_eq!(
        state
            .committed()
            .resume_script("script", &one_call, 4)
            .unwrap(),
        ScriptResume::Waiting(OperationId(1))
    );
    apply(
        &mut store,
        &mut state,
        Event::Published {
            token: token.clone(),
            receipt_id: result.receipt.as_ref().unwrap().id.clone(),
        },
    );
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    assert!(matches!(
        state
            .committed()
            .resume_script("script", &one_call, 4)
            .unwrap(),
        ScriptResume::Continue { .. }
    ));
    let event = suspension(&state, reference, 2, 1);
    assert_eq!(on_event(&mut state, event), Err(Error::Limit));
    assert_eq!(state.committed().scripts()["script"].suspensions.len(), 1);
}

#[test]
fn checkpoint_storage_has_an_aggregate_bound() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let mut bytes = vec![0u8; MAX_CHECKPOINT_BYTES];
    for index in 0..16 {
        bytes[0] = index;
        store.put_checkpoint(store.activation(), &bytes).unwrap();
    }
    bytes[0] = 16;
    assert!(matches!(
        store.put_checkpoint(store.activation(), &bytes),
        Err(StoreError::Limit)
    ));
    assert!(!store.is_suspended());
}

fn blob_count(store: &Store) -> i64 {
    store
        .conn
        .query_row("SELECT count(*) FROM checkpoints", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn staging_survives_unrelated_commits_and_is_reclaimed_after_abandon_or_reopen() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let staged = store
        .put_checkpoint(state.activation(), b"pending")
        .unwrap();
    start(&mut store, &mut state);
    assert_eq!(store.load_checkpoint(&staged).unwrap(), b"pending");
    store
        .abandon_checkpoint(state.activation(), &staged)
        .unwrap();
    assert_eq!(blob_count(&store), 0);
    store
        .put_checkpoint(state.activation(), b"abandoned by crash")
        .unwrap();
    drop(store);
    let store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(blob_count(&store), 0);
}

#[test]
fn next_suspension_and_terminal_commit_release_only_obsolete_blobs() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let first = store.put_checkpoint(state.activation(), b"first").unwrap();
    let event = suspension(&state, first.clone(), 1, 0);
    apply(&mut store, &mut state, event);
    let attempt = authorize(&mut store, &mut state);
    apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt,
            result: result(),
        },
    );
    let next = store.put_checkpoint(state.activation(), b"next").unwrap();
    let event = suspension(&state, next.clone(), 2, 1);
    let proposal = proposed(&mut state, event);
    assert_eq!(blob_count(&store), 2);
    assert_eq!(store.load_checkpoint(&first).unwrap(), b"first");
    store.commit(&proposal).unwrap();
    // Lose the acknowledgement: recovery must see the new suspension and blob together.
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    assert_eq!(blob_count(&store), 1);
    assert_eq!(store.load_checkpoint(&next).unwrap(), b"next");
    assert_eq!(state.committed().scripts()["script"].suspensions.len(), 2);
    let stop = script_event(
        &state,
        ScriptEvent::Stop {
            id: "script".into(),
        },
    );
    let proposal = proposed(&mut state, stop);
    assert_eq!(blob_count(&store), 1);
    store.commit(&proposal).unwrap();
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(blob_count(&store), 0);
    assert_eq!(
        store.load().unwrap().scripts()["script"].suspensions.len(),
        2
    );
}

#[test]
fn shared_digest_survives_until_the_last_active_script_stops() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let reference = store.put_checkpoint(state.activation(), b"shared").unwrap();
    for (id, child) in [("one", 1), ("two", 2)] {
        let event = script_event(
            &state,
            ScriptEvent::Start {
                id: id.into(),
                spec: script_spec(),
                parent: None,
            },
        );
        apply(&mut store, &mut state, event);
        let event = script_event(
            &state,
            ScriptEvent::Suspend {
                id: id.into(),
                generation: 0,
                checkpoint: reference.clone(),
                children: vec![(OperationId(child), spec())],
                batch: false,
            },
        );
        apply(&mut store, &mut state, event);
    }
    for (id, expected) in [("one", 1), ("two", 0)] {
        let event = script_event(&state, ScriptEvent::Stop { id: id.into() });
        apply(&mut store, &mut state, event);
        assert_eq!(blob_count(&store), expected);
    }
}

#[test]
fn reclamation_failure_rolls_back_terminal_snapshot_and_keeps_continuation() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store.put_checkpoint(state.activation(), b"keep").unwrap();
    let event = suspension(&state, reference.clone(), 1, 0);
    apply(&mut store, &mut state, event);
    store.conn.execute_batch("CREATE TRIGGER reject_gc BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected GC failure'); END;").unwrap();
    let event = script_event(
        &state,
        ScriptEvent::Stop {
            id: "script".into(),
        },
    );
    let proposal = proposed(&mut state, event);
    assert!(store.commit(&proposal).is_err());
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(
        store.load().unwrap().scripts()["script"].phase,
        crate::session::durable::composition::ScriptPhase::Active
    );
    assert_eq!(store.load_checkpoint(&reference).unwrap(), b"keep");
}

#[test]
fn repeated_stopped_programs_reuse_checkpoint_quota() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let mut bytes = vec![0u8; MAX_CHECKPOINT_BYTES];
    for index in 0..20 {
        let id = format!("script-{index}");
        let event = script_event(
            &state,
            ScriptEvent::Start {
                id: id.clone(),
                spec: script_spec(),
                parent: None,
            },
        );
        apply(&mut store, &mut state, event);
        bytes[0] = index;
        let checkpoint = store.put_checkpoint(state.activation(), &bytes).unwrap();
        let event = script_event(
            &state,
            ScriptEvent::Suspend {
                id: id.clone(),
                generation: 0,
                checkpoint,
                children: vec![(OperationId(u64::from(index) + 1), spec())],
                batch: false,
            },
        );
        apply(&mut store, &mut state, event);
        let event = script_event(&state, ScriptEvent::Stop { id });
        apply(&mut store, &mut state, event);
        assert_eq!(blob_count(&store), 0);
    }
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(store.load().unwrap().scripts().len(), 20);
}

#[test]
fn restaging_a_live_digest_survives_an_unrelated_commit_and_release() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store
        .put_checkpoint(state.activation(), b"shared pending")
        .unwrap();
    let event = suspension(&state, reference.clone(), 1, 0);
    apply(&mut store, &mut state, event);
    store
        .put_checkpoint(state.activation(), b"shared pending")
        .unwrap();
    let event = script_event(
        &state,
        ScriptEvent::Start {
            id: "next".into(),
            spec: script_spec(),
            parent: None,
        },
    );
    apply(&mut store, &mut state, event);
    let event = script_event(
        &state,
        ScriptEvent::Stop {
            id: "script".into(),
        },
    );
    apply(&mut store, &mut state, event);
    assert_eq!(
        store.load_checkpoint(&reference).unwrap(),
        b"shared pending"
    );
    let event = script_event(
        &state,
        ScriptEvent::Suspend {
            id: "next".into(),
            generation: 0,
            checkpoint: reference,
            children: vec![(OperationId(2), spec())],
            batch: false,
        },
    );
    apply(&mut store, &mut state, event);
    assert_eq!(blob_count(&store), 1);
}

pub(super) fn crash_reclamation(path: &Path, mode: &str) {
    let mut store = Store::open(path, session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    if mode == "gc-before-blob" {
        pause_for_kill();
    }
    let reference = store
        .put_checkpoint(state.activation(), b"crash continuation")
        .unwrap();
    if mode == "gc-after-blob" {
        pause_for_kill();
    }
    let event = suspension(&state, reference, 1, 0);
    apply(&mut store, &mut state, event);
    if mode == "gc-after-suspend" {
        pause_for_kill();
    }
    let attempt = authorize(&mut store, &mut state);
    apply(
        &mut store,
        &mut state,
        Event::Completed {
            attempt,
            result: result(),
        },
    );
    let event = script_event(
        &state,
        ScriptEvent::Finish {
            id: "script".into(),
            generation: 1,
            output: json!("done"),
        },
    );
    let proposal = proposed(&mut state, event);
    if mode == "gc-before-finish" {
        pause_for_kill();
    }
    if mode == "gc-transaction" {
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE session SET revision=?1, snapshot=?2",
            params![
                i64::try_from(proposal.id.revision).unwrap(),
                serde_json::to_vec(&proposal.snapshot).unwrap()
            ],
        )
        .unwrap();
        checkpoints::reclaim(&tx, &proposal.snapshot, &Default::default()).unwrap();
        pause_for_kill();
        drop(tx);
    }
    store.commit(&proposal).unwrap();
    if mode == "gc-after-finish" {
        pause_for_kill();
    }
    panic!("unknown crash point {mode}");
}

#[test]
fn process_death_preserves_required_continuations_and_reclaims_orphans() {
    for (mode, blobs) in [
        ("gc-before-blob", 0),
        ("gc-after-blob", 0),
        ("gc-after-suspend", 1),
        ("gc-before-finish", 1),
        ("gc-transaction", 1),
        ("gc-after-finish", 0),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session");
        let mut child = paused_child(&path, mode);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let mut store = Store::open(&path, session()).unwrap();
        assert_eq!(blob_count(&store), blobs, "{mode}");
        let snapshot = store.load().unwrap();
        for reference in snapshot.required_checkpoints() {
            assert_eq!(
                store.load_checkpoint(reference).unwrap(),
                b"crash continuation",
                "{mode}"
            );
        }
        if mode == "gc-after-finish" {
            assert_eq!(
                snapshot.resume_script("script", &script_spec(), 4).unwrap(),
                ScriptResume::Completed(&json!("done"))
            );
        }
    }
}

fn batch_event(state: &State, id: &str, checkpoint: CheckpointRef, children: &[u64]) -> Event {
    script_event(
        state,
        ScriptEvent::Suspend {
            id: id.into(),
            generation: 0,
            checkpoint,
            children: children.iter().map(|&c| (OperationId(c), spec())).collect(),
            batch: true,
        },
    )
}

fn wide_spec() -> ScriptSpec {
    ScriptSpec {
        max_calls: 8,
        ..script_spec()
    }
}

#[test]
fn batch_admission_is_atomic_bounded_and_resumes_in_input_order() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let event = script_event(
        &state,
        ScriptEvent::Start {
            id: "script".into(),
            spec: wide_spec(),
            parent: None,
        },
    );
    apply(&mut store, &mut state, event);
    let reference = store.put_checkpoint(state.activation(), b"batch").unwrap();
    for (children, batch) in [
        (vec![], true),
        (vec![1, 2, 3, 4, 5], true),
        (vec![1, 2], false),
        (vec![1, 1], true),
    ] {
        let event = script_event(
            &state,
            ScriptEvent::Suspend {
                id: "script".into(),
                generation: 0,
                checkpoint: reference.clone(),
                children: children.iter().map(|&c| (OperationId(c), spec())).collect(),
                batch,
            },
        );
        assert!(on_event(&mut state, event).is_err(), "{children:?}");
    }
    let event = batch_event(&state, "script", reference.clone(), &[3, 1, 2]);
    let proposal = proposed(&mut state, event);
    assert!(store.load().unwrap().operations().is_empty());
    let id = store.commit(&proposal).unwrap();
    let effects = on_event(&mut state, Event::Committed(id)).unwrap();
    assert_eq!(effects.len(), 6);
    // Complete out of order; resume waits for every sibling then preserves admission order.
    let mut outputs = std::collections::BTreeMap::new();
    for child in [2, 3, 1] {
        assert!(matches!(
            state
                .committed()
                .resume_script("script", &wide_spec(), 4)
                .unwrap(),
            ScriptResume::Waiting(_)
        ));
        let effects = apply(
            &mut store,
            &mut state,
            Event::Authorize {
                id: OperationId(child),
                now_ms: 3,
            },
        );
        let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
            panic!("no dispatch")
        };
        let mut done = result();
        done.output = json!(child);
        outputs.insert(child, done.clone());
        apply(
            &mut store,
            &mut state,
            Event::Completed {
                attempt: attempt.clone(),
                result: done,
            },
        );
    }
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (state, _) = activate(&mut store);
    let ScriptResume::Continue {
        children, batch, ..
    } = state
        .committed()
        .resume_script("script", &wide_spec(), 4)
        .unwrap()
    else {
        panic!("expected continuation")
    };
    assert!(batch);
    let order: Vec<_> = children
        .iter()
        .map(|(id, r)| (id.0, r.output.clone()))
        .collect();
    assert_eq!(order, [(3, json!(3)), (1, json!(1)), (2, json!(2))]);
}

#[test]
fn nested_scripts_share_call_limits_cascade_stops_and_are_depth_bounded() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let reference = store.put_checkpoint(state.activation(), b"tree").unwrap();
    let start = |state: &State, id: &str, parent: Option<(&str, u64)>| {
        script_event(
            state,
            ScriptEvent::Start {
                id: id.into(),
                spec: ScriptSpec {
                    max_calls: 4,
                    ..script_spec()
                },
                parent: parent.map(|(script, child)| ScriptParent {
                    script: script.into(),
                    child: OperationId(child),
                }),
            },
        )
    };
    let event = start(&state, "s0", None);
    apply(&mut store, &mut state, event);
    // Each level admits one child that hosts the next level.
    for depth in 0..3u64 {
        let event = batch_event(
            &state,
            &format!("s{depth}"),
            reference.clone(),
            &[depth + 1],
        );
        apply(&mut store, &mut state, event);
        let event = start(
            &state,
            &format!("s{}", depth + 1),
            Some((&format!("s{depth}"), depth + 1)),
        );
        apply(&mut store, &mut state, event);
    }
    // A fifth level exceeds the depth bound.
    let event = batch_event(&state, "s3", reference.clone(), &[4]);
    apply(&mut store, &mut state, event);
    let event = start(&state, "s4", Some(("s3", 4)));
    assert_eq!(on_event(&mut state, event), Err(Error::Limit));
    // All four calls of the tree's budget are spent; any new admission is refused.
    assert_eq!(state.committed().tree_calls("s3").unwrap(), 4);
    // A second owner cannot claim an already-bound child.
    let event = start(&state, "dup", Some(("s0", 1)));
    assert!(on_event(&mut state, event).is_err());
    // Stopping the root stops every descendant and its admitted children.
    let event = script_event(&state, ScriptEvent::Stop { id: "s0".into() });
    let effects = apply(&mut store, &mut state, event);
    assert_eq!(effects.len(), 4);
    for id in ["s0", "s1", "s2", "s3"] {
        assert_eq!(
            state.committed().scripts()[id].phase,
            ScriptPhase::Stopped(StopReason::Cancelled)
        );
    }
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert_eq!(store.load().unwrap().scripts().len(), 4);
}

#[test]
fn tree_call_limit_counts_every_level() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    let reference = store.put_checkpoint(state.activation(), b"tree").unwrap();
    let event = script_event(
        &state,
        ScriptEvent::Start {
            id: "root".into(),
            spec: ScriptSpec {
                max_calls: 3,
                ..script_spec()
            },
            parent: None,
        },
    );
    apply(&mut store, &mut state, event);
    let event = batch_event(&state, "root", reference.clone(), &[1, 2]);
    apply(&mut store, &mut state, event);
    let event = script_event(
        &state,
        ScriptEvent::Start {
            id: "child".into(),
            spec: wide_spec(),
            parent: Some(ScriptParent {
                script: "root".into(),
                child: OperationId(1),
            }),
        },
    );
    apply(&mut store, &mut state, event);
    // The child's own spec allows eight, but the root's three is shared.
    let event = batch_event(&state, "child", reference.clone(), &[3, 4]);
    assert_eq!(on_event(&mut state, event), Err(Error::Limit));
    let event = batch_event(&state, "child", reference, &[3]);
    apply(&mut store, &mut state, event);
}

/// Rewrite the stored snapshot's version without a `serde_json::Value` round trip, which
/// would lose the u128 activation.
fn stored_version(store: &Store, version: u32) {
    let bytes: Vec<u8> = store
        .conn
        .query_row("SELECT snapshot FROM session", [], |r| r.get(0))
        .unwrap();
    let text = String::from_utf8(bytes).unwrap().replace(
        &format!("\"schema_version\":{SCHEMA_VERSION}"),
        &format!("\"schema_version\":{version}"),
    );
    store
        .conn
        .execute("UPDATE session SET snapshot=?1", [text.into_bytes()])
        .unwrap();
}

#[test]
fn v6_store_gains_checkpoints_and_rolls_back_on_invalid_scripts() {
    for corrupt in [false, true] {
        let dir = private_dir();
        let mut store = Store::open(dir.path(), session()).unwrap();
        store.admit("keep", &json!("existing submission")).unwrap();
        let (mut state, _) = activate(&mut store);
        if corrupt {
            // A pre-composition snapshot cannot carry scripts.
            start(&mut store, &mut state);
        }
        stored_version(&store, 6);
        store
            .conn
            .execute_batch("DROP TABLE checkpoints; PRAGMA user_version=6;")
            .unwrap();
        drop(store);
        let reopened = Store::open(dir.path(), session());
        let conn = Connection::open(dir.path().join("session.sqlite3")).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        if corrupt {
            assert!(matches!(
                reopened,
                Err(StoreError::Corrupt | StoreError::Json(_))
            ));
            assert_eq!(version, 6);
            continue;
        }
        let mut store = reopened.unwrap();
        assert_eq!(version, STORE_VERSION);
        assert_eq!(store.submissions(0, 100).unwrap()[0].request_id, "keep");
        assert!(store.load().unwrap().scripts().is_empty());
        let reference = store.put_checkpoint(store.activation(), b"new").unwrap();
        assert_eq!(store.load_checkpoint(&reference).unwrap(), b"new");
    }
}

#[test]
fn forget_drops_a_finished_tree_and_prune_drops_scripts_with_their_operations() {
    let dir = private_dir();
    let mut store = Store::open(dir.path(), session()).unwrap();
    let (mut state, _) = activate(&mut store);
    start(&mut store, &mut state);
    let reference = store.put_checkpoint(state.activation(), b"tree").unwrap();
    let event = suspension(&state, reference, 1, 0);
    apply(&mut store, &mut state, event);
    // An active script cannot be forgotten.
    let event = script_event(
        &state,
        ScriptEvent::Forget {
            id: "script".into(),
        },
    );
    assert_eq!(on_event(&mut state, event), Err(Error::InvalidPhase));
    let event = script_event(
        &state,
        ScriptEvent::Stop {
            id: "script".into(),
        },
    );
    apply(&mut store, &mut state, event);
    // Pruning the stopped child also drops its finished script.
    apply(
        &mut store,
        &mut state,
        Event::Prune {
            operations: vec![OperationId(1)],
        },
    );
    assert!(state.committed().scripts().is_empty());
    start(&mut store, &mut state);
    let event = script_event(
        &state,
        ScriptEvent::Finish {
            id: "script".into(),
            generation: 0,
            output: json!("done"),
        },
    );
    apply(&mut store, &mut state, event);
    let event = script_event(
        &state,
        ScriptEvent::Forget {
            id: "script".into(),
        },
    );
    apply(&mut store, &mut state, event);
    assert!(state.committed().scripts().is_empty());
    drop(store);
    let mut store = Store::open(dir.path(), session()).unwrap();
    assert!(store.load().unwrap().scripts().is_empty());
}
