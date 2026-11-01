use std::{
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Run {
    output: Output,
    killed: bool,
}

fn worker(args: &[&str], deadline: Duration) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bee-monty-spike"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut killed = false;
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() >= deadline {
            child.kill().unwrap();
            killed = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    // This fixture emits bounded diagnostics only; arbitrary guest printing is disabled.
    Run {
        output: child.wait_with_output().unwrap(),
        killed,
    }
}

fn succeeds(args: &[&str]) -> String {
    let run = worker(args, Duration::from_secs(10));
    assert!(!run.killed, "worker exceeded deadline");
    assert!(
        run.output.status.success(),
        "{}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    String::from_utf8(run.output.stdout).unwrap()
}

#[test]
fn continuation_survives_two_process_exits_and_preserves_locals() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.bin");
    let second = dir.path().join("second.bin");
    let unused = dir.path().join("unused.bin");
    let first = first.to_str().unwrap();
    let second = second.to_str().unwrap();
    let unused = unused.to_str().unwrap();
    assert!(succeeds(&["start", first]).contains("Int(3)"));
    assert!(succeeds(&["resume", first, "21", second]).contains("Int(28)"));
    assert!(succeeds(&["resume", second, "14", unused]).contains("Int(42)"));
    assert!(!std::path::Path::new(unused).exists());
    // Reinjecting the committed result repeats only local computation; no host effect is run here.
    assert!(succeeds(&["resume", second, "14", unused]).contains("Int(42)"));
}

#[test]
fn interpreter_memory_and_time_limits_fire() {
    for (mode, expected) in [("memory", "MemoryError"), ("timeout", "TimeoutError")] {
        let run = worker(&[mode], Duration::from_secs(10));
        assert!(!run.killed);
        assert!(!run.output.status.success());
        let stderr = String::from_utf8_lossy(&run.output.stderr);
        assert!(stderr.contains(expected), "{mode}: {stderr}");
    }
}

#[test]
fn allocator_ceiling_terminates_worker() {
    let run = worker(&["allocator"], Duration::from_secs(10));
    assert!(!run.killed);
    assert_eq!(run.output.status.code(), Some(monty_types::OOM_EXIT_CODE));
}

#[test]
fn parent_kills_and_reaps_non_yielding_worker() {
    let run = worker(&["watchdog"], Duration::from_millis(200));
    assert!(run.killed);
    assert!(!run.output.status.success());
    assert!(run.output.stderr.is_empty());
}

#[test]
fn incompatible_and_oversized_checkpoints_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("bad.bin");
    let output = dir.path().join("unused.bin");
    for (bytes, expected) in [
        (b"wrong version".to_vec(), "incompatible snapshot"),
        (vec![0; 5 * 1024 * 1024], "snapshot too large"),
    ] {
        std::fs::write(&input, bytes).unwrap();
        let run = worker(
            &[
                "resume",
                input.to_str().unwrap(),
                "1",
                output.to_str().unwrap(),
            ],
            Duration::from_secs(10),
        );
        assert!(!run.killed);
        assert!(!run.output.status.success());
        assert!(String::from_utf8_lossy(&run.output.stderr).contains(expected));
        assert!(!output.exists());
    }
}

#[test]
fn monty_resumes_committed_effect_after_store_and_worker_restart() {
    use bee::session::durable::{composition::*, store::Store, *};
    use serde_json::json;

    fn commit(store: &mut Store, state: &mut State, event: Event) -> Vec<Effect> {
        let effects = on_event(state, event).unwrap();
        let [Effect::Persist(candidate)] = effects.as_slice() else {
            return effects;
        };
        let id = store.commit(candidate).unwrap();
        on_event(state, Event::Committed(id)).unwrap()
    }
    fn activate(store: &mut Store) -> State {
        let mut state = State::open(store.load().unwrap(), store.activation()).unwrap();
        let effects = commit(store, &mut state, Event::Activate { now_ms: 1 });
        assert!(!effects.iter().any(|e| matches!(e, Effect::Dispatch { .. })));
        state
    }
    fn script(state: &State, event: ScriptEvent) -> Event {
        Event::Script {
            activation: state.activation(),
            now_ms: 2,
            event,
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let session_directory = directory.path().join("session");
    std::fs::create_dir(&session_directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&session_directory, std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let first = directory.path().join("first.bin");
    let second = directory.path().join("second.bin");
    let unused = directory.path().join("unused.bin");
    let session = SessionId("monty-effect-fixture".into());
    let spec = ScriptSpec {
        source_input_sha256: "a".repeat(64),
        runtime: "monty-1.4.0/postcard-1".into(),
        compatibility: "fixture-1".into(),
        deadline_ms: 1000,
        max_calls: 2,
    };
    let mut store = Store::open(&session_directory, session.clone()).unwrap();
    let mut state = activate(&mut store);
    let event = script(
        &state,
        ScriptEvent::Start {
            id: "script".into(),
            spec: spec.clone(),
        },
    );
    commit(&mut store, &mut state, event);
    succeeds(&["start", first.to_str().unwrap()]);
    let bytes = std::fs::read(&first).unwrap();
    let reference = store.put_checkpoint(state.activation(), &bytes).unwrap();
    let event = script(
        &state,
        ScriptEvent::Suspend {
            id: "script".into(),
            generation: 0,
            checkpoint: reference,
            child: OperationId(1),
            spec: OperationSpec {
                kind: WorkKind::Tool,
                name: "controlled_mutation".into(),
                version: 1,
                input: json!({"argument":3}),
                recovery: RecoveryPolicy::NeverReplay,
                deadline_ms: 1000,
            },
        },
    );
    commit(&mut store, &mut state, event);
    let effects = commit(
        &mut store,
        &mut state,
        Event::Authorize {
            id: OperationId(1),
            now_ms: 3,
        },
    );
    let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
        panic!("expected dispatch");
    };
    let effect = directory.path().join("mutation.txt");
    std::fs::write(&effect, "mutation\n").unwrap();
    let effects = on_event(
        &mut state,
        Event::Completed {
            attempt: attempt.clone(),
            result: Completion {
                duration_ms: 0,
                audit: vec![],
                receipt: None,
                output: json!(21),
            },
        },
    )
    .unwrap();
    let [Effect::Persist(candidate)] = effects.as_slice() else {
        panic!("expected commit");
    };
    store.commit(candidate).unwrap();
    // Lose the acknowledgement and exit before the result reaches Python.
    drop(state);
    drop(store);
    std::fs::remove_file(&first).unwrap();

    let mut store = Store::open(&session_directory, session).unwrap();
    let state = activate(&mut store);
    let ScriptResume::Continue {
        checkpoint,
        child,
        result,
    } = state.committed().resume_script("script", &spec, 4).unwrap()
    else {
        panic!("expected durable continuation");
    };
    assert_eq!(child, OperationId(1));
    assert_eq!(result.output, json!(21));
    std::fs::write(&first, store.load_checkpoint(checkpoint).unwrap()).unwrap();
    let supplied = result.output.as_i64().unwrap().to_string();
    assert!(
        succeeds(&[
            "resume",
            first.to_str().unwrap(),
            &supplied,
            second.to_str().unwrap()
        ])
        .contains("Int(28)")
    );
    assert_eq!(std::fs::read_to_string(effect).unwrap(), "mutation\n");
    assert!(
        succeeds(&[
            "resume",
            second.to_str().unwrap(),
            "14",
            unused.to_str().unwrap()
        ])
        .contains("Int(42)")
    );
}
