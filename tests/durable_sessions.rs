//! A deterministic effect executor with independently crashable memory and storage.
//! This proves protocol behavior, not SQLite durability or process cleanup.

use bee::session::durable::*;
use proptest::prelude::*;
use serde_json::json;

struct Simulator {
    state: State,
    disk: Snapshot,
    write: Option<Commit>,
    released: Vec<Effect>,
    activation: u128,
    executions: Vec<Attempt>,
}

impl Simulator {
    fn new() -> Self {
        let disk = Snapshot::empty(SessionId("fixture".into()));
        let state = State::open(disk.clone(), ActivationId(1)).unwrap();
        let mut sim = Self {
            state,
            disk,
            write: None,
            released: vec![],
            activation: 1,
            executions: vec![],
        };
        sim.apply(Event::Activate { now_ms: 0 });
        sim
    }

    fn send(&mut self, event: Event) -> Result<(), Error> {
        let effects = on_event(&mut self.state, event)?;
        for effect in effects {
            match effect {
                Effect::Persist(commit) => {
                    assert!(self.write.is_none());
                    assert_eq!(commit.expected_revision, self.disk.revision());
                    assert_eq!(commit.id.revision, commit.snapshot.revision());
                    self.write = Some(*commit);
                }
                effect => {
                    // Every visible effect must be justified by the simulated durable store.
                    match &effect {
                        Effect::Dispatch { attempt, spec } => {
                            let operation = self.disk.operation(attempt.operation).unwrap();
                            assert_eq!(
                                operation.phase,
                                Phase::Running {
                                    attempt: attempt.clone()
                                }
                            );
                            assert_eq!(&operation.spec, spec);
                            assert!(
                                !self.executions.contains(attempt),
                                "attempt dispatched twice"
                            );
                            self.executions.push(attempt.clone());
                        }
                        Effect::Deliver(entry) => assert!(self.disk.entries().contains(entry)),
                        Effect::Accepted(id) => assert!(self.disk.operation(*id).is_some()),
                        Effect::Ready(id) => {
                            assert_eq!(self.disk.operation(*id).unwrap().phase, Phase::Ready)
                        }
                        Effect::Inspect(token) => assert_eq!(
                            self.disk.operation(token.attempt.operation).unwrap().phase,
                            Phase::Recovering {
                                attempt: token.attempt.clone()
                            }
                        ),
                        Effect::Stop(token) => assert!(
                            matches!(&self.disk.operation(token.attempt.operation).unwrap().phase, Phase::Cancelling { attempt, .. } if attempt == &token.attempt)
                        ),
                        Effect::Stopped { id, reason } => assert!(matches!(
                            &self.disk.operation(*id).unwrap().phase,
                            Phase::Stopped { reason: actual, .. } if actual == reason
                        )),
                        Effect::Unresolved { id, reason } => assert!(
                            matches!(&self.disk.operation(*id).unwrap().phase, Phase::Unresolved { reason: actual, .. } if actual == reason)
                        ),
                        Effect::Suspended => assert!(self.state.is_suspended()),
                        Effect::Publish { token, result } => assert_eq!(
                            &self.disk.operation(token.attempt.operation).unwrap().phase,
                            &Phase::Publishing {
                                attempt: token.attempt.clone(),
                                result: result.clone()
                            }
                        ),
                        Effect::Persist(_) => unreachable!(),
                    }
                    self.released.push(effect);
                }
            }
        }
        Ok(())
    }

    fn store_without_ack(&mut self) -> CommitId {
        let commit = self.write.take().unwrap();
        assert_eq!(commit.expected_revision, self.disk.revision());
        // The next process sees serialized state, not a clone of runtime-owned handles.
        self.disk = serde_json::from_slice(&serde_json::to_vec(&commit.snapshot).unwrap()).unwrap();
        commit.id
    }

    fn commit(&mut self) {
        let id = self.store_without_ack();
        self.send(Event::Committed(id)).unwrap();
    }

    fn apply(&mut self, event: Event) -> Vec<Effect> {
        self.released.clear();
        self.send(event).unwrap();
        if self.write.is_some() {
            self.commit();
        }
        std::mem::take(&mut self.released)
    }

    fn crash(&mut self, now_ms: u64) -> Vec<Effect> {
        self.write = None;
        self.activation += 1;
        self.state = State::open(self.disk.clone(), ActivationId(self.activation)).unwrap();
        self.apply(Event::Activate { now_ms })
    }

    fn submit(&mut self, id: u64, policy: RecoveryPolicy) {
        self.apply(Event::Submit {
            id: OperationId(id),
            spec: spec(policy),
        });
    }

    fn start(&mut self, id: u64) -> Attempt {
        let effects = self.apply(Event::Authorize {
            id: OperationId(id),
            now_ms: 1,
        });
        let [Effect::Dispatch { attempt, .. }] = effects.as_slice() else {
            panic!("{effects:?}")
        };
        attempt.clone()
    }
}

fn spec(recovery: RecoveryPolicy) -> OperationSpec {
    OperationSpec {
        kind: WorkKind::Tool,
        name: "fixture".into(),
        version: 1,
        input: json!({"input":"x"}),
        recovery,
        deadline_ms: 100,
    }
}

fn result() -> Completion {
    Completion {
        duration_ms: 0,
        audit: vec![],
        receipt: None,
        output: json!({"stdout":"observed", "exit_code":0}),
    }
}

fn inspection(effects: &[Effect]) -> RecoveryToken {
    effects
        .iter()
        .find_map(|e| {
            if let Effect::Inspect(token) = e {
                Some(token.clone())
            } else {
                None
            }
        })
        .unwrap()
}

#[test]
fn accounting_and_lifecycle_share_the_same_commit_and_failure_gate() {
    for commit_result in [false, true] {
        let mut sim = Simulator::new();
        sim.submit(1, RecoveryPolicy::NeverReplay);
        let effects = on_event_with_checkpoint(
            &mut sim.state,
            Event::Authorize {
                id: OperationId(1),
                now_ms: 1,
            },
            json!({"charge":"reserved"}),
        )
        .unwrap();
        let [Effect::Persist(commit)] = effects.as_slice() else {
            panic!("dispatch escaped commit gate")
        };
        assert_eq!(sim.state.committed().driver(), None);
        assert_eq!(commit.snapshot.driver().unwrap()["charge"], "reserved");
        let Phase::Running { attempt } = &commit.snapshot.operation(OperationId(1)).unwrap().phase
        else {
            panic!("missing dispatch intent")
        };
        let attempt = attempt.clone();
        sim.disk = commit.snapshot.clone();
        let effects = on_event(&mut sim.state, Event::Committed(commit.id.clone())).unwrap();
        assert!(matches!(&effects[..], [Effect::Dispatch { .. }]));
        let effects = on_event_with_checkpoint(
            &mut sim.state,
            Event::Completed {
                attempt,
                result: result(),
            },
            json!({"charge":"settled"}),
        )
        .unwrap();
        let [Effect::Persist(commit)] = effects.as_slice() else {
            panic!("result escaped commit gate")
        };
        assert_eq!(commit.snapshot.driver().unwrap()["charge"], "settled");
        assert_eq!(commit.snapshot.entries().len(), 1);
        if commit_result {
            sim.disk = commit.snapshot.clone();
            assert!(matches!(
                &on_event(&mut sim.state, Event::Committed(commit.id.clone())).unwrap()[..],
                [Effect::Deliver(_)]
            ));
        } else {
            assert_eq!(
                on_event(&mut sim.state, Event::CommitFailed(commit.id.clone())).unwrap(),
                vec![Effect::Suspended]
            );
        }
        sim.crash(2);
        assert_eq!(
            sim.disk.driver().unwrap()["charge"],
            if commit_result { "settled" } else { "reserved" }
        );
        assert_eq!(sim.disk.entries().len(), usize::from(commit_result));
    }
}

#[test]
fn admission_dispatch_and_delivery_wait_for_matching_commits() {
    let mut sim = Simulator::new();
    let submit = Event::Submit {
        id: OperationId(1),
        spec: spec(RecoveryPolicy::NeverReplay),
    };
    let before = sim.state.committed().clone();
    sim.send(submit.clone()).unwrap();
    assert_eq!(sim.state.committed(), &before);
    assert!(sim.released.is_empty());
    assert_eq!(sim.send(submit.clone()), Err(Error::Busy));
    let mut wrong = sim.write.as_ref().unwrap().id.clone();
    wrong.activation = ActivationId(999);
    assert_eq!(sim.send(Event::Committed(wrong)), Err(Error::Stale));
    sim.commit();
    assert_eq!(sim.apply(submit), vec![Effect::Accepted(OperationId(1))]);
    let mut changed = spec(RecoveryPolicy::NeverReplay);
    changed.input = json!("different");
    assert_eq!(
        sim.send(Event::Submit {
            id: OperationId(1),
            spec: changed
        }),
        Err(Error::Conflict)
    );

    sim.released.clear();
    sim.send(Event::Authorize {
        id: OperationId(1),
        now_ms: 1,
    })
    .unwrap();
    assert!(sim.executions.is_empty());
    sim.commit();
    let attempt = sim.executions[0].clone();
    sim.released.clear();
    sim.send(Event::Completed {
        attempt: attempt.clone(),
        result: result(),
    })
    .unwrap();
    assert!(sim.released.is_empty());
    assert!(sim.state.committed().entries().is_empty());
    sim.commit();
    assert!(matches!(sim.released.as_slice(), [Effect::Deliver(_)]));
    assert!(sim
        .apply(Event::Completed {
            attempt: attempt.clone(),
            result: result()
        })
        .is_empty());
    assert_eq!(
        sim.send(Event::Completed {
            attempt,
            result: Completion {
                duration_ms: 0,
                audit: vec![],
                receipt: None,
                output: json!("conflict")
            }
        }),
        Err(Error::Conflict)
    );
    assert!(sim.apply(Event::Replay { after_sequence: 1 }).is_empty());
    assert_eq!(sim.apply(Event::Replay { after_sequence: 0 }).len(), 1);
}

#[test]
fn crashes_on_either_side_of_result_commit_do_not_invent_execution_knowledge() {
    for stored in [false, true] {
        let mut sim = Simulator::new();
        sim.submit(1, RecoveryPolicy::NeverReplay);
        let attempt = sim.start(1);
        sim.send(Event::Completed {
            attempt: attempt.clone(),
            result: result(),
        })
        .unwrap();
        if stored {
            sim.store_without_ack();
        }
        let effects = sim.crash(2);
        assert_eq!(sim.executions.len(), 1);
        if stored {
            assert_eq!(
                effects,
                vec![Effect::Deliver(Entry {
                    sequence: 1,
                    attempt,
                    result: result()
                })]
            );
            assert_eq!(sim.crash(3), effects); // replay uses the same cursor and exact payload
        } else {
            let token = inspection(&effects);
            assert_eq!(
                sim.apply(Event::Recovered {
                    token,
                    outcome: RecoveryOutcome::Quiescent,
                    now_ms: 2
                }),
                vec![Effect::Unresolved {
                    id: OperationId(1),
                    reason: UnresolvedReason::UnknownOutcome
                }]
            );
            assert!(sim.disk.entries().is_empty());
        }
    }
}

#[test]
fn committed_dispatch_intent_without_launch_is_still_ambiguous_after_crash() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::Reconcile);
    sim.send(Event::Authorize {
        id: OperationId(1),
        now_ms: 1,
    })
    .unwrap();
    sim.store_without_ack();
    assert!(sim.executions.is_empty());
    let token = inspection(&sim.crash(2));
    let effects = sim.apply(Event::Recovered {
        token,
        outcome: RecoveryOutcome::Quiescent,
        now_ms: 2,
    });
    assert_eq!(
        effects,
        vec![Effect::Unresolved {
            id: OperationId(1),
            reason: UnresolvedReason::ReconciliationRequired
        }]
    );
    assert!(sim.executions.is_empty());
}

#[test]
fn reconciliation_recovers_a_result_and_fences_old_callbacks() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::Reconcile);
    let attempt = sim.start(1);
    let old_token = inspection(&sim.crash(2));
    let token = inspection(&sim.crash(3));
    let before = sim.state.committed().clone();
    assert_eq!(
        sim.send(Event::Completed {
            attempt: attempt.clone(),
            result: result()
        }),
        Err(Error::Stale)
    );
    assert_eq!(
        sim.send(Event::Recovered {
            token: old_token,
            outcome: RecoveryOutcome::Found(result()),
            now_ms: 3
        }),
        Err(Error::Stale)
    );
    assert_eq!(sim.state.committed(), &before);
    assert_eq!(
        sim.apply(Event::Recovered {
            token,
            outcome: RecoveryOutcome::Found(result()),
            now_ms: 3
        }),
        vec![Effect::Deliver(Entry {
            sequence: 1,
            attempt,
            result: result()
        })]
    );
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn retries_require_quiescence_fresh_authorization_and_respect_attempt_limit() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::RetrySafe { max_attempts: 2 });
    let original = sim.start(1);
    let token = inspection(&sim.crash(2));
    sim.send(Event::Recovered {
        token,
        outcome: RecoveryOutcome::Quiescent,
        now_ms: 2,
    })
    .unwrap();
    assert_eq!(sim.executions.len(), 1);
    sim.commit();
    assert_eq!(sim.executions.len(), 1);
    let retried = sim.start(1);
    assert_eq!(retried.number, 2);
    assert_ne!(retried.activation, original.activation);
    assert_eq!(
        sim.send(Event::Completed {
            attempt: original,
            result: result()
        }),
        Err(Error::Stale)
    );
    let token = inspection(&sim.crash(3));
    assert_eq!(
        sim.apply(Event::Recovered {
            token,
            outcome: RecoveryOutcome::Quiescent,
            now_ms: 3
        }),
        vec![Effect::Unresolved {
            id: OperationId(1),
            reason: UnresolvedReason::RetryLimit
        }]
    );
    assert_eq!(
        sim.send(Event::Authorize {
            id: OperationId(1),
            now_ms: 4
        }),
        Err(Error::InvalidPhase)
    );
    assert_eq!(sim.executions.len(), 2);
}

#[test]
fn unknown_recovery_never_retries_even_retry_safe_work() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::RetrySafe { max_attempts: 4 });
    sim.start(1);
    let token = inspection(&sim.crash(2));
    assert_eq!(
        sim.apply(Event::Recovered {
            token,
            outcome: RecoveryOutcome::Unknown,
            now_ms: 2
        }),
        vec![Effect::Unresolved {
            id: OperationId(1),
            reason: UnresolvedReason::UnknownOutcome
        }]
    );
    assert!(matches!(
        sim.crash(3).as_slice(),
        [Effect::Unresolved { .. }]
    ));
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn cancellation_is_committed_before_signalling_and_survives_reopen() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::RetrySafe { max_attempts: 3 });
    let attempt = sim.start(1);
    sim.released.clear();
    sim.send(Event::Cancel { id: OperationId(1) }).unwrap();
    assert!(sim.released.is_empty());
    sim.commit();
    let [Effect::Stop(old_token)] = sim.released.as_slice() else {
        panic!()
    };
    let old_token = old_token.clone();
    let effects = sim.crash(2);
    let [Effect::Stop(token)] = effects.as_slice() else {
        panic!("{effects:?}")
    };
    assert_eq!(
        sim.send(Event::Cleaned { token: old_token }),
        Err(Error::Stale)
    );
    assert_eq!(
        sim.send(Event::Completed {
            attempt,
            result: result()
        }),
        Err(Error::Stale)
    );
    sim.send(Event::Cleaned {
        token: token.clone(),
    })
    .unwrap();
    // Crash after cleanup commit but before its acknowledgement must not restart work.
    sim.store_without_ack();
    assert_eq!(
        sim.crash(3),
        vec![Effect::Stopped {
            id: OperationId(1),
            reason: StopReason::Cancelled
        }]
    );
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn deadline_and_clock_rollback_never_create_more_execution_time() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::RetrySafe { max_attempts: 3 });
    sim.start(1);
    let effects = sim.crash(100);
    let [Effect::Stop(token)] = effects.as_slice() else {
        panic!("{effects:?}")
    };
    assert_eq!(
        sim.apply(Event::Cleaned {
            token: token.clone()
        }),
        vec![Effect::Stopped {
            id: OperationId(1),
            reason: StopReason::Deadline
        }]
    );
    sim.submit(2, RecoveryPolicy::NeverReplay);
    assert_eq!(
        sim.apply(Event::Authorize {
            id: OperationId(2),
            now_ms: 0
        }),
        vec![Effect::Stopped {
            id: OperationId(2),
            reason: StopReason::Deadline
        }]
    );
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn stopping_work_preserves_uncertainty_and_completed_results() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::NeverReplay);
    assert_eq!(
        sim.apply(Event::Cancel { id: OperationId(1) }),
        vec![Effect::Stopped {
            id: OperationId(1),
            reason: StopReason::Cancelled
        }]
    );
    assert!(sim.executions.is_empty());
    sim.submit(2, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(2);
    let token = inspection(&sim.crash(2));
    sim.apply(Event::Recovered {
        token,
        outcome: RecoveryOutcome::Unknown,
        now_ms: 2,
    });
    let effects = sim.apply(Event::Cancel { id: OperationId(2) });
    let [Effect::Stop(token)] = effects.as_slice() else {
        panic!()
    };
    // Cancelling retries cleanup, but proving the executor stopped does not settle the outcome.
    assert_eq!(
        sim.apply(Event::Cleaned {
            token: token.clone(),
        }),
        vec![Effect::Unresolved {
            id: OperationId(2),
            reason: UnresolvedReason::UnknownOutcome
        }]
    );
    assert_eq!(
        sim.disk.operation(OperationId(2)).unwrap().phase,
        Phase::Unresolved {
            reason: UnresolvedReason::UnknownOutcome,
            attempt: attempt.clone()
        }
    );

    assert!(sim.disk.entries().is_empty()); // cleanup is not a successful tool result

    sim.submit(3, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(3);
    sim.apply(Event::Completed {
        attempt,
        result: result(),
    });
    let before = sim.disk.clone();
    assert!(sim.apply(Event::Cancel { id: OperationId(3) }).is_empty());
    assert_eq!(sim.disk, before);
}

#[test]
fn a_recovery_that_outlives_the_deadline_cannot_retry() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::RetrySafe { max_attempts: 3 });
    let attempt = sim.start(1);
    let token = inspection(&sim.crash(2));
    assert_eq!(
        sim.apply(Event::Recovered {
            token,
            outcome: RecoveryOutcome::Quiescent,
            now_ms: 100
        }),
        vec![Effect::Stopped {
            id: OperationId(1),
            reason: StopReason::Deadline
        }]
    );
    assert_eq!(
        sim.disk.operation(OperationId(1)).unwrap().phase,
        Phase::Stopped {
            reason: StopReason::Deadline,
            attempt: Some(attempt)
        }
    );
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn independent_completions_can_arrive_in_any_order_without_being_lost() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::NeverReplay);
    sim.submit(2, RecoveryPolicy::NeverReplay);
    let first = sim.start(1);
    let second = sim.start(2);
    let first_done = Event::Completed {
        attempt: first.clone(),
        result: result(),
    };
    sim.send(Event::Completed {
        attempt: second.clone(),
        result: result(),
    })
    .unwrap();
    assert_eq!(sim.send(first_done.clone()), Err(Error::Busy));
    sim.commit();
    sim.apply(first_done);
    assert_eq!(
        sim.disk
            .entries()
            .iter()
            .map(|entry| entry.attempt.clone())
            .collect::<Vec<_>>(),
        vec![second, first]
    );
    assert_eq!(sim.crash(3).len(), 2);
}

#[test]
fn failed_commits_suspend_every_transition_without_releasing_its_effects() {
    for case in 0..8 {
        let mut sim = Simulator::new();
        sim.submit(1, RecoveryPolicy::RetrySafe { max_attempts: 3 });
        let event = match case {
            0 => Event::Submit {
                id: OperationId(2),
                spec: spec(RecoveryPolicy::NeverReplay),
            },
            1 => Event::Authorize {
                id: OperationId(1),
                now_ms: 1,
            },
            2 => {
                let attempt = sim.start(1);
                Event::Completed {
                    attempt,
                    result: result(),
                }
            }
            3 => {
                sim.start(1);
                Event::Cancel { id: OperationId(1) }
            }
            4 => {
                sim.start(1);
                let token = inspection(&sim.crash(2));
                Event::Recovered {
                    token,
                    outcome: RecoveryOutcome::Quiescent,
                    now_ms: 2,
                }
            }
            5 => {
                sim.start(1);
                let effects = sim.apply(Event::Cancel { id: OperationId(1) });
                let [Effect::Stop(token)] = effects.as_slice() else {
                    panic!()
                };
                Event::Cleaned {
                    token: token.clone(),
                }
            }
            6 => {
                sim.start(1);
                Event::Tick { now_ms: 100 }
            }
            _ => {
                sim.activation += 1;
                sim.state = State::open(sim.disk.clone(), ActivationId(sim.activation)).unwrap();
                Event::Activate { now_ms: 1 }
            }
        };
        sim.released.clear();
        let before = sim.state.committed().clone();
        sim.send(event).unwrap();
        let id = sim.write.take().unwrap().id;
        sim.send(Event::CommitFailed(id.clone())).unwrap();
        assert_eq!(sim.released, vec![Effect::Suspended], "case {case}");
        assert_eq!(sim.state.committed(), &before);
        assert_eq!(
            sim.send(Event::Replay { after_sequence: 0 }),
            Err(Error::Suspended)
        );
        assert_eq!(sim.send(Event::Committed(id)), Err(Error::Stale));
        sim.crash(3);
    }
}

#[test]
fn ambiguous_commit_failure_requires_loading_storage_even_if_it_applied() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(1);
    sim.send(Event::Completed {
        attempt,
        result: result(),
    })
    .unwrap();
    let id = sim.store_without_ack();
    sim.send(Event::CommitFailed(id)).unwrap();
    assert!(sim.state.committed().entries().is_empty());
    assert!(matches!(sim.crash(2).as_slice(), [Effect::Deliver(_)]));
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn invalid_input_and_incompatible_snapshots_are_refused_without_progress() {
    let mut sim = Simulator::new();
    let before = sim.state.committed().clone();
    assert_eq!(
        sim.send(Event::Submit {
            id: OperationId(1),
            spec: spec(RecoveryPolicy::RetrySafe { max_attempts: 0 })
        }),
        Err(Error::InvalidInput)
    );
    let mut oversized = spec(RecoveryPolicy::NeverReplay);
    oversized.input = json!("x".repeat(MAX_PAYLOAD_BYTES));
    assert_eq!(
        sim.send(Event::Submit {
            id: OperationId(1),
            spec: oversized
        }),
        Err(Error::InvalidInput)
    );
    assert_eq!(sim.state.committed(), &before);
    assert!(sim.write.is_none());
    for version in [1, 2, 3, 4, 5, 999] {
        let mut snapshot = serde_json::to_value(sim.disk.clone()).unwrap();
        snapshot["schema_version"] = json!(version);
        assert!(serde_json::from_value::<Snapshot>(snapshot).is_err());
    }
    assert!(matches!(
        State::open(sim.disk.clone(), ActivationId(1)),
        Err(Error::Stale)
    ));
    sim.submit(1, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(1);
    sim.apply(Event::Completed {
        attempt,
        result: result(),
    });
    let mut snapshot = serde_json::to_value(sim.disk.clone()).unwrap();
    // The result is stored once, in the entry; a phase that still carries a different one is refused.
    assert!(snapshot["operations"]["1"]["phase"]["Completed"]
        .get("result")
        .is_none());
    let mut forged = snapshot["entries"][0]["result"].clone();
    forged["output"] = json!("forged mismatch");
    snapshot["operations"]["1"]["phase"]["Completed"]["result"] = forged;
    assert!(matches!(
        State::open(serde_json::from_value(snapshot).unwrap(), ActivationId(5)),
        Err(Error::InvalidSnapshot)
    ));
}

proptest! {
    #[test]
    fn fault_schedules_preserve_commit_and_generation_invariants(actions in prop::collection::vec(any::<u8>(), 1..100)) {
        let mut sim = Simulator::new();
        for id in 0..3 { sim.submit(id, RecoveryPolicy::RetrySafe { max_attempts: 3 }); }
        for action in actions {
            if sim.state.is_suspended() { sim.crash(2); }
            if sim.write.is_some() {
                match action % 4 {
                    0 => { let id = sim.write.take().unwrap().id; sim.send(Event::CommitFailed(id)).unwrap(); }
                    1 => { sim.store_without_ack(); sim.crash(2); }
                    2 => { sim.crash(2); }
                    _ => sim.commit(),
                }
                continue;
            }
            let id = OperationId(u64::from(action % 3));
            let phase = sim.disk.operation(id).unwrap().phase.clone();
            let event = match (action % 7, phase) {
                (0, _) => Event::Authorize { id, now_ms: 1 },
                (1, Phase::Running { attempt }) => Event::Completed { attempt, result: if action & 8 == 0 { result() } else { receipted_result() } },
                (2, _) => Event::Cancel { id },
                (3, _) => { sim.crash(2); continue; }
                (4, Phase::Recovering { attempt }) => Event::Recovered { token: RecoveryToken { activation: ActivationId(sim.activation), attempt }, outcome: RecoveryOutcome::Quiescent, now_ms: 2 },
                (5, Phase::Cancelling { attempt, .. }) => Event::Cleaned { token: RecoveryToken { activation: ActivationId(sim.activation), attempt } },
                (6, Phase::Publishing { attempt, result }) => Event::Published { token: RecoveryToken { activation: ActivationId(sim.activation), attempt }, receipt_id: result.receipt.unwrap().id },
                (6, _) => Event::Tick { now_ms: 100 },
                _ => Event::Replay { after_sequence: 0 },
            };
            let _ = sim.send(event);
        }
        sim.crash(101);
        prop_assert!(sim.disk.entries().len() <= 3);
    }
}

fn receipted_result() -> Completion {
    Completion {
        duration_ms: 0,
        audit: vec![],
        output: json!({"content":"exact output"}),
        receipt: Some(ReceiptPublication {
            id: format!("sha256:{}", "a".repeat(64)),
            bytes: "opaque receipt bytes validated by the host".into(),
        }),
    }
}

#[test]
fn publication_and_delivery_have_separate_commit_gates_and_fenced_acknowledgements() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(1);
    sim.send(Event::Completed {
        attempt: attempt.clone(),
        result: receipted_result(),
    })
    .unwrap();
    assert!(sim.released.is_empty());
    assert!(sim.disk.entries().is_empty());
    sim.commit();
    let [Effect::Publish { token, result }] = sim.released.as_slice() else {
        panic!()
    };
    let token = token.clone();
    let receipt_id = result.receipt.as_ref().unwrap().id.clone();
    assert!(sim.disk.entries().is_empty());
    assert!(sim
        .apply(Event::Completed {
            attempt: attempt.clone(),
            result: receipted_result()
        })
        .is_empty());
    assert_eq!(
        sim.send(Event::Completed {
            attempt,
            result: result_without_receipt()
        }),
        Err(Error::Conflict)
    );
    assert_eq!(
        sim.send(Event::Published {
            token: token.clone(),
            receipt_id: "wrong".into()
        }),
        Err(Error::Conflict)
    );
    sim.send(Event::Published {
        token: token.clone(),
        receipt_id: receipt_id.clone(),
    })
    .unwrap();
    assert!(sim.released.is_empty());
    assert!(sim.disk.entries().is_empty());
    sim.commit();
    assert!(matches!(sim.released.as_slice(), [Effect::Deliver(_)]));
    assert!(sim
        .apply(Event::Published {
            token: token.clone(),
            receipt_id: receipt_id.clone()
        })
        .is_empty());
    let replay = sim.crash(3);
    assert!(matches!(replay.as_slice(), [Effect::Deliver(_)]));
    assert_eq!(
        sim.send(Event::Published { token, receipt_id }),
        Err(Error::Stale)
    );
    assert_eq!(sim.executions.len(), 1);
}

fn result_without_receipt() -> Completion {
    Completion {
        duration_ms: 0,
        audit: vec![],
        output: json!({"content":"exact output"}),
        receipt: None,
    }
}

#[test]
fn publication_survives_reopen_cancellation_and_deadline_without_reexecution() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(1);
    sim.apply(Event::Completed {
        attempt,
        result: receipted_result(),
    });
    let effects = sim.crash(200);
    let [Effect::Publish { token, result }] = effects.as_slice() else {
        panic!()
    };
    assert_eq!(result, &receipted_result());
    assert!(sim
        .apply(Event::Cancel { id: OperationId(1) })
        .iter()
        .all(|e| matches!(e, Effect::Publish { .. })));
    assert!(sim.apply(Event::Replay { after_sequence: 0 }).is_empty());
    let release = sim.apply(Event::Published {
        token: token.clone(),
        receipt_id: result.receipt.as_ref().unwrap().id.clone(),
    });
    assert!(matches!(release.as_slice(), [Effect::Deliver(_)]));
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn failed_publication_commit_releases_no_delivery_and_reopen_repeats_publication() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(1);
    let effects = sim.apply(Event::Completed {
        attempt,
        result: receipted_result(),
    });
    let [Effect::Publish { token, result }] = effects.as_slice() else {
        panic!()
    };
    sim.send(Event::Published {
        token: token.clone(),
        receipt_id: result.receipt.as_ref().unwrap().id.clone(),
    })
    .unwrap();
    let pending = sim.write.take().unwrap();
    sim.send(Event::CommitFailed(pending.id)).unwrap();
    assert_eq!(sim.released, vec![Effect::Suspended]);
    assert!(sim.disk.entries().is_empty());
    assert!(matches!(sim.crash(3).as_slice(), [Effect::Publish { .. }]));
    assert_eq!(sim.executions.len(), 1);
}

#[test]
fn resuming_reconciliation_requires_commit_and_current_generation() {
    let mut sim = Simulator::new();
    sim.submit(1, RecoveryPolicy::Reconcile);
    let attempt = sim.start(1);
    let effects = sim.crash(2);
    let [Effect::Inspect(token)] = effects.as_slice() else {
        panic!()
    };
    sim.send(Event::ResumeReconciliation {
        token: token.clone(),
        now_ms: 3,
    })
    .unwrap();
    assert!(sim.released.is_empty());
    assert!(sim.write.is_some());
    sim.commit();
    assert_eq!(sim.released, vec![Effect::Inspect(token.clone())]);
    assert_eq!(sim.executions, vec![attempt]);
    sim.crash(4);
    assert_eq!(
        sim.send(Event::ResumeReconciliation {
            token: token.clone(),
            now_ms: 5
        }),
        Err(Error::Stale)
    );
    let token = RecoveryToken {
        activation: sim.state.activation(),
        attempt: token.attempt.clone(),
    };
    assert_eq!(
        sim.send(Event::ResumeReconciliation {
            token: token.clone(),
            now_ms: 200
        }),
        Err(Error::InvalidPhase)
    );
    sim.apply(Event::Cancel { id: OperationId(1) });
    assert_eq!(
        sim.send(Event::ResumeReconciliation {
            token: token.clone(),
            now_ms: 5
        }),
        Err(Error::InvalidPhase)
    );
    let result = result_without_receipt();
    let delivered = sim.apply(Event::Recovered {
        token,
        outcome: RecoveryOutcome::Found(result.clone()),
        now_ms: 200,
    });
    assert!(matches!(delivered.as_slice(), [Effect::Deliver(entry)] if entry.result == result));
}

#[test]
fn cancelling_an_interrupted_mutation_leaves_it_unresolved_not_stopped() {
    for (policy, expected) in [
        (
            RecoveryPolicy::NeverReplay,
            Some(UnresolvedReason::UnknownOutcome),
        ),
        (
            RecoveryPolicy::Reconcile,
            Some(UnresolvedReason::ReconciliationRequired),
        ),
        (RecoveryPolicy::RetrySafe { max_attempts: 3 }, None),
    ] {
        for reason in [StopReason::Cancelled, StopReason::Deadline] {
            let mut sim = Simulator::new();
            sim.submit(1, policy);
            let attempt = sim.start(1);
            let now = if reason == StopReason::Deadline {
                100
            } else {
                2
            };
            let effects = sim.crash(now);
            let effects = if reason == StopReason::Cancelled {
                assert!(matches!(effects.as_slice(), [Effect::Inspect(_)]));
                sim.apply(Event::Cancel { id: OperationId(1) })
            } else {
                effects
            };
            let [Effect::Stop(token)] = effects.as_slice() else {
                panic!("{effects:?}")
            };
            let effects = sim.apply(Event::Cleaned {
                token: token.clone(),
            });
            let phase = sim.disk.operation(OperationId(1)).unwrap().phase.clone();
            match expected {
                Some(unresolved) => {
                    assert_eq!(
                        effects,
                        vec![Effect::Unresolved {
                            id: OperationId(1),
                            reason: unresolved
                        }]
                    );
                    assert_eq!(
                        phase,
                        Phase::Unresolved {
                            attempt: attempt.clone(),
                            reason: unresolved
                        }
                    );
                }
                None => assert_eq!(
                    phase,
                    Phase::Stopped {
                        reason,
                        attempt: Some(attempt.clone())
                    }
                ),
            }
            // A later deadline neither stops nor relabels it; a reopen keeps it; nothing reruns.
            sim.apply(Event::Tick { now_ms: 200 });
            assert_eq!(sim.disk.operation(OperationId(1)).unwrap().phase, phase);
            sim.crash(201);
            assert_eq!(sim.disk.operation(OperationId(1)).unwrap().phase, phase);
            assert_eq!(sim.executions.len(), 1);
        }
    }
}

fn complete(sim: &mut Simulator, id: u64) {
    sim.submit(id, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(id);
    sim.apply(Event::Completed {
        attempt,
        result: result(),
    });
}

#[test]
fn pruning_lets_a_session_outlive_its_operation_bound() {
    let mut sim = Simulator::new();
    let total = MAX_OPERATIONS as u64 + 300;
    for id in 1..=total {
        // Pruning early keeps each simulated commit small; the bound itself is unchanged.
        if sim.disk.operations().len() == 64 {
            let operations: Vec<_> = sim.disk.operations().keys().copied().take(48).collect();
            sim.apply(Event::Prune { operations });
        }
        complete(&mut sim, id);
    }
    assert!(sim.disk.operations().len() <= MAX_OPERATIONS);
    assert_eq!(sim.executions.len() as u64, total);
    // Entry sequences keep counting across pruning, so a delivery cursor never repeats.
    let last = sim.disk.entries().last().unwrap();
    assert_eq!(last.sequence, total);
    assert_eq!(last.attempt.operation, OperationId(total));
    assert!(sim
        .apply(Event::Replay {
            after_sequence: total
        })
        .is_empty());
    // A pruned ID can never be admitted again, even with its original input.
    assert_eq!(
        sim.send(Event::Submit {
            id: OperationId(1),
            spec: spec(RecoveryPolicy::NeverReplay)
        }),
        Err(Error::Stale)
    );
    // The pruned snapshot survives a reopen.
    sim.crash(2);
    assert_eq!(sim.disk.entries().last().unwrap().sequence, total);
    complete(&mut sim, total + 1);
    assert_eq!(sim.disk.entries().last().unwrap().sequence, total + 1);
}

#[test]
fn pruning_never_forgets_live_unknown_or_undelivered_work() {
    let mut sim = Simulator::new();
    complete(&mut sim, 1);
    sim.submit(2, RecoveryPolicy::NeverReplay);
    sim.submit(3, RecoveryPolicy::NeverReplay);
    sim.start(3);
    sim.submit(4, RecoveryPolicy::NeverReplay);
    sim.start(4);
    let token = inspection(&sim.crash(2));
    sim.apply(Event::Recovered {
        token,
        outcome: RecoveryOutcome::Unknown,
        now_ms: 2,
    });
    sim.submit(5, RecoveryPolicy::NeverReplay);
    let attempt = sim.start(5);
    let mut published = result();
    published.receipt = Some(ReceiptPublication {
        id: format!("sha256:{}", "a".repeat(64)),
        bytes: "receipt".into(),
    });
    sim.apply(Event::Completed {
        attempt,
        result: published,
    });
    sim.submit(6, RecoveryPolicy::NeverReplay);
    sim.start(6);
    sim.apply(Event::Cancel { id: OperationId(6) });
    // Ready, Recovering, Unresolved, Publishing, and Cancelling all refuse.
    for id in [2, 3, 4, 5, 6] {
        let phase = &sim.disk.operation(OperationId(id)).unwrap().phase;
        assert!(
            !matches!(phase, Phase::Completed { .. } | Phase::Stopped { .. }),
            "{phase:?}"
        );
        let before = sim.disk.clone();
        assert_eq!(
            sim.send(Event::Prune {
                operations: vec![OperationId(1), OperationId(id)]
            }),
            Err(Error::InvalidPhase),
            "{id}"
        );
        assert_eq!(sim.disk, before);
        assert!(sim.write.is_none());
    }
    sim.apply(Event::Prune {
        operations: vec![OperationId(1)],
    });
    assert!(sim.disk.operation(OperationId(1)).is_none());
    assert!(sim.disk.entries().is_empty());
    for id in 2..=6 {
        assert!(sim.disk.operation(OperationId(id)).is_some());
    }
    assert_eq!(
        sim.send(Event::Prune {
            operations: vec![OperationId(1)]
        }),
        Err(Error::NotFound)
    );
}

#[test]
fn prepruning_snapshots_load_with_their_counters_derived() {
    let mut sim = Simulator::new();
    complete(&mut sim, 1);
    complete(&mut sim, 2);
    let mut stored = serde_json::to_value(sim.disk.clone()).unwrap();
    let object = stored.as_object_mut().unwrap();
    object.remove("sequence");
    object.remove("horizon");
    object.insert("schema_version".into(), json!(5));
    let loaded: Snapshot = serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(loaded, sim.disk);
    // A current-version snapshot must carry the counters.
    stored["schema_version"] = json!(SCHEMA_VERSION);
    assert!(serde_json::from_value::<Snapshot>(stored).is_err());
}
