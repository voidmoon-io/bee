//! Pure decision core for the first durable-session slice.
//!
//! The host supplies fresh activation IDs, time, policy authorization, and I/O outcomes.
//! A `Persist` effect is a proposal: only its matching `Committed` event promotes the
//! candidate and releases effects. Failed/ambiguous commits suspend this instance.
//! While a commit is pending the host must retain incoming events and redeliver them.
//!
//! The opt-in `store` module supplies SQLite persistence. The shared driver couples
//! its accounting journal to lifecycle commits. Receipt publication has a separate commit gate.
//! Results are bounded opaque JSON. `Inspect`/`Stop` acknowledgements
//! are trusted executor assertions, not evidence inferred from process IDs or timeouts.

pub mod composition;
mod types;
pub use types::*;
#[cfg(feature = "durable-store")]
pub mod store;

#[derive(Debug, Clone)]
struct Pending {
    commit: Commit,
    release: Vec<Effect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Inactive,
    Active,
    Suspended,
}

#[derive(Debug, Clone)]
pub struct State {
    committed: Snapshot,
    activation: ActivationId,
    mode: Mode,
    pending: Option<Pending>,
}

impl State {
    /// Call only after obtaining exclusive ownership and loading authoritative storage.
    /// Activation must be globally fresh even if a prior activation failed to commit.
    pub fn open(snapshot: Snapshot, activation: ActivationId) -> Result<Self, Error> {
        validate_snapshot(&snapshot)?;
        if snapshot.activation == Some(activation) {
            return Err(Error::Stale);
        }
        Ok(Self {
            committed: snapshot,
            activation,
            mode: Mode::Inactive,
            pending: None,
        })
    }

    pub fn committed(&self) -> &Snapshot {
        &self.committed
    }
    pub fn activation(&self) -> ActivationId {
        self.activation
    }

    pub fn is_suspended(&self) -> bool {
        self.mode == Mode::Suspended
    }

    #[cfg(feature = "findings")]
    pub(crate) fn check_active(&self) -> Result<(), Error> {
        if self.mode == Mode::Suspended {
            Err(Error::Suspended)
        } else if self.mode != Mode::Active {
            Err(Error::Inactive)
        } else if self.pending.is_some() {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }

    fn token(&self, attempt: &Attempt) -> RecoveryToken {
        RecoveryToken {
            activation: self.activation,
            attempt: attempt.clone(),
        }
    }

    pub(crate) fn check_token(&self, token: &RecoveryToken) -> Result<(), Error> {
        if token.activation != self.activation || token.attempt.session != self.committed.session {
            return Err(Error::Stale);
        }
        Ok(())
    }

    fn settle(&mut self, id: CommitId, success: bool) -> Result<Vec<Effect>, Error> {
        if self.pending.as_ref().is_none_or(|p| p.commit.id != id) {
            return Err(Error::Stale);
        }
        let pending = self.pending.take().expect("matching pending commit");
        if !success {
            self.mode = Mode::Suspended;
            return Ok(vec![Effect::Suspended]);
        }
        self.committed = pending.commit.snapshot;
        self.mode = Mode::Active;
        Ok(pending.release)
    }

    fn propose(
        &mut self,
        mut snapshot: Snapshot,
        release: Vec<Effect>,
    ) -> Result<Vec<Effect>, Error> {
        snapshot.revision = self.committed.revision.checked_add(1).ok_or(Error::Limit)?;
        let commit = Commit {
            id: CommitId {
                session: snapshot.session.clone(),
                activation: self.activation,
                revision: snapshot.revision,
            },
            expected_revision: self.committed.revision,
            snapshot,
        };
        self.pending = Some(Pending {
            commit: commit.clone(),
            release,
        });
        Ok(vec![Effect::Persist(Box::new(commit))])
    }
}

/// Couple a host journal update to a lifecycle transition under the same commit gate.
/// Acknowledgements and replay cannot be combined with journal changes.
pub fn on_event_with_checkpoint(
    state: &mut State,
    event: Event,
    checkpoint: serde_json::Value,
) -> Result<Vec<Effect>, Error> {
    if matches!(
        event,
        Event::Committed(_) | Event::CommitFailed(_) | Event::Replay { .. }
    ) {
        return Err(Error::InvalidPhase);
    }
    validate_driver(&checkpoint)?;
    let mut candidate = state.clone();
    let effects = on_event(&mut candidate, event)?;
    let effects = if let Some(pending) = &mut candidate.pending {
        pending.commit.snapshot.driver = Some(checkpoint);
        vec![Effect::Persist(Box::new(pending.commit.clone()))]
    } else {
        let mut snapshot = candidate.committed.clone();
        snapshot.driver = Some(checkpoint);
        candidate.propose(snapshot, effects)?
    };
    *state = candidate;
    Ok(effects)
}

/// Advance decisions only. Every externally visible mutation passes through `Persist`.
pub fn on_event(state: &mut State, event: Event) -> Result<Vec<Effect>, Error> {
    match event {
        Event::Committed(id) => return state.settle(id, true),
        Event::CommitFailed(id) => return state.settle(id, false),
        _ => {}
    }
    if state.mode == Mode::Suspended {
        return Err(Error::Suspended);
    }
    if state.pending.is_some() {
        return Err(Error::Busy);
    }
    if state.mode == Mode::Inactive && !matches!(event, Event::Activate { .. }) {
        return Err(Error::Inactive);
    }
    let mut next = state.committed.clone();
    let mut release = Vec::new();
    match event {
        Event::Script {
            activation,
            now_ms,
            event,
        } => {
            if activation != state.activation {
                return Err(Error::Stale);
            }
            next.observed_ms = next.observed_ms.max(now_ms);
            release.extend(composition::apply(state, &mut next, event)?);
        }
        Event::ResumeReconciliation { token, now_ms } => {
            state.check_token(&token)?;
            let operation = next
                .operations
                .get(&token.attempt.operation)
                .ok_or(Error::NotFound)?;
            if operation.spec.recovery != RecoveryPolicy::Reconcile
                || !matches!(&operation.phase, Phase::Recovering { attempt } if attempt == &token.attempt)
                || now_ms.max(next.observed_ms) >= operation.spec.deadline_ms
            {
                return Err(Error::InvalidPhase);
            }
            next.observed_ms = next.observed_ms.max(now_ms);
            release.push(Effect::Inspect(token));
        }
        Event::Interrupted { attempt } => {
            if attempt.activation != state.activation || attempt.session != next.session {
                return Err(Error::Stale);
            }
            let operation = next
                .operations
                .get_mut(&attempt.operation)
                .ok_or(Error::NotFound)?;
            if !matches!(&operation.phase, Phase::Running { attempt: original } if original == &attempt)
            {
                return Err(Error::Stale);
            }
            operation.phase = Phase::Recovering {
                attempt: attempt.clone(),
            };
            release.push(Effect::Inspect(state.token(&attempt)));
        }
        Event::Checkpoint(value) => {
            validate_driver(&value)?;
            next.driver = Some(value);
        }
        Event::Activate { now_ms } => {
            if state.mode != Mode::Inactive {
                return Err(Error::AlreadyActive);
            }
            next.activation = Some(state.activation);
            next.observed_ms = next.observed_ms.max(now_ms);
            for (&id, operation) in &mut next.operations {
                if let Phase::Running { attempt } = &operation.phase {
                    operation.phase = Phase::Recovering {
                        attempt: attempt.clone(),
                    };
                }
                expire(operation, next.observed_ms);
                release.extend(notification(state, id, &operation.phase));
            }
            release.extend(next.entries.iter().cloned().map(Effect::Deliver));
        }
        Event::Submit { id, spec } => {
            validate_spec(&spec)?;
            if let Some(existing) = next.operations.get(&id) {
                return if existing.spec == spec {
                    Ok(vec![Effect::Accepted(id)])
                } else {
                    Err(Error::Conflict)
                };
            }
            if id < next.horizon {
                return Err(Error::Stale);
            }
            if next.operations.len() >= MAX_OPERATIONS {
                return Err(Error::Limit);
            }
            next.operations.insert(
                id,
                Operation {
                    spec,
                    attempts: 0,
                    phase: Phase::Ready,
                },
            );
            release.extend([Effect::Accepted(id), Effect::Ready(id)]);
        }
        Event::Authorize { id, now_ms } => {
            next.observed_ms = next.observed_ms.max(now_ms);
            let operation = next.operations.get_mut(&id).ok_or(Error::NotFound)?;
            if operation.phase != Phase::Ready {
                return Err(Error::InvalidPhase);
            }
            if expire(operation, next.observed_ms) {
                release.extend(notification(state, id, &operation.phase));
            } else {
                operation.attempts = operation.attempts.checked_add(1).ok_or(Error::Limit)?;
                let attempt = Attempt {
                    session: next.session.clone(),
                    activation: state.activation,
                    operation: id,
                    number: operation.attempts,
                };
                operation.phase = Phase::Running {
                    attempt: attempt.clone(),
                };
                release.push(Effect::Dispatch {
                    attempt,
                    spec: operation.spec.clone(),
                });
            }
        }
        Event::Completed { attempt, result } => {
            if attempt.activation != state.activation || attempt.session != next.session {
                return Err(Error::Stale);
            }
            let operation = next
                .operations
                .get(&attempt.operation)
                .ok_or(Error::NotFound)?;
            match &operation.phase {
                Phase::Publishing {
                    attempt: original,
                    result: previous,
                }
                | Phase::Completed {
                    attempt: original,
                    result: previous,
                } if original == &attempt => {
                    return if previous == &result {
                        Ok(vec![])
                    } else {
                        Err(Error::Conflict)
                    };
                }
                Phase::Running { attempt: original } if original == &attempt => {}
                _ => return Err(Error::Stale),
            }
            release.push(record_result(state, &mut next, attempt, result)?);
        }
        Event::Published { token, receipt_id } => {
            state.check_token(&token)?;
            let operation = next
                .operations
                .get(&token.attempt.operation)
                .ok_or(Error::NotFound)?;
            let result = match &operation.phase {
                Phase::Publishing { attempt, result } | Phase::Completed { attempt, result }
                    if attempt == &token.attempt =>
                {
                    result
                }
                _ => return Err(Error::Stale),
            };
            if result
                .receipt
                .as_ref()
                .is_none_or(|receipt| receipt.id != receipt_id)
            {
                return Err(Error::Conflict);
            }
            if matches!(operation.phase, Phase::Completed { .. }) {
                return Ok(vec![]);
            }
            let result = result.clone();
            release.push(complete(&mut next, token.attempt, result)?);
        }
        Event::Recovered {
            token,
            outcome,
            now_ms,
        } => {
            state.check_token(&token)?;
            next.observed_ms = next.observed_ms.max(now_ms);
            let id = token.attempt.operation;
            let operation = next.operations.get_mut(&id).ok_or(Error::NotFound)?;
            let accepts = match &operation.phase {
                Phase::Recovering { attempt } => attempt == &token.attempt,
                Phase::Cancelling { attempt, .. } => {
                    attempt == &token.attempt && matches!(&outcome, RecoveryOutcome::Found(_))
                }
                _ => false,
            };
            if !accepts {
                return Err(Error::Stale);
            }
            match outcome {
                RecoveryOutcome::Found(result) => {
                    release.push(record_result(state, &mut next, token.attempt, result)?);
                }
                RecoveryOutcome::Quiescent => {
                    operation.phase = if next.observed_ms >= operation.spec.deadline_ms {
                        Phase::Stopped {
                            reason: StopReason::Deadline,
                            attempt: Some(token.attempt),
                        }
                    } else {
                        match operation.spec.recovery {
                            RecoveryPolicy::RetrySafe { max_attempts }
                                if operation.attempts < max_attempts =>
                            {
                                Phase::Ready
                            }
                            RecoveryPolicy::RetrySafe { .. } => Phase::Unresolved {
                                attempt: token.attempt,
                                reason: UnresolvedReason::RetryLimit,
                            },
                            RecoveryPolicy::Reconcile => Phase::Unresolved {
                                attempt: token.attempt,
                                reason: UnresolvedReason::ReconciliationRequired,
                            },
                            RecoveryPolicy::NeverReplay => Phase::Unresolved {
                                attempt: token.attempt,
                                reason: UnresolvedReason::UnknownOutcome,
                            },
                        }
                    };
                    release.extend(notification(state, id, &operation.phase));
                }
                RecoveryOutcome::Unknown => {
                    operation.phase = Phase::Unresolved {
                        attempt: token.attempt,
                        reason: UnresolvedReason::UnknownOutcome,
                    };
                    release.extend(notification(state, id, &operation.phase));
                }
            }
        }
        Event::Cancel { id } | Event::Expire { id } => {
            let reason = match event {
                Event::Expire { .. } => StopReason::Deadline,
                _ => StopReason::Cancelled,
            };
            let operation = next.operations.get_mut(&id).ok_or(Error::NotFound)?;
            stop(operation, reason);
            release.extend(notification(state, id, &operation.phase));
        }
        Event::Prune { operations } => {
            if operations.is_empty() || operations.len() > MAX_OPERATIONS {
                return Err(Error::InvalidInput);
            }
            let mut forget = std::collections::BTreeSet::new();
            for id in operations {
                let operation = next.operations.get(&id).ok_or(Error::NotFound)?;
                if !matches!(
                    operation.phase,
                    Phase::Completed { .. } | Phase::Stopped { .. }
                ) || !forget.insert(id)
                {
                    return Err(Error::InvalidPhase);
                }
            }
            next.operations.retain(|id, _| !forget.contains(id));
            next.entries
                .retain(|entry| !forget.contains(&entry.attempt.operation));
            composition::forget_pruned(&mut next);
            let last = *forget.last().expect("nonempty prune");
            next.horizon = next
                .horizon
                .max(OperationId(last.0.checked_add(1).ok_or(Error::Limit)?));
        }
        Event::Cleaned { token } => {
            state.check_token(&token)?;
            let id = token.attempt.operation;
            let operation = next.operations.get_mut(&id).ok_or(Error::NotFound)?;
            let Phase::Cancelling {
                attempt,
                reason,
                unresolved,
            } = &operation.phase
            else {
                return Err(Error::Stale);
            };
            if attempt != &token.attempt {
                return Err(Error::Stale);
            }
            // Proving the executor stopped does not reveal what an interrupted effect did.
            operation.phase = match unresolved {
                Some(unresolved) => Phase::Unresolved {
                    attempt: attempt.clone(),
                    reason: *unresolved,
                },
                None => Phase::Stopped {
                    reason: *reason,
                    attempt: Some(attempt.clone()),
                },
            };
            release.extend(notification(state, id, &operation.phase));
        }
        Event::Tick { now_ms } => {
            next.observed_ms = next.observed_ms.max(now_ms);
            for (&id, operation) in &mut next.operations {
                if expire(operation, next.observed_ms) {
                    release.extend(notification(state, id, &operation.phase));
                }
            }
        }
        Event::Replay { after_sequence } => {
            return Ok(next
                .entries
                .into_iter()
                .filter(|e| e.sequence > after_sequence)
                .map(Effect::Deliver)
                .collect());
        }
        Event::Committed(_) | Event::CommitFailed(_) => unreachable!("handled above"),
    }
    if next == state.committed {
        return Ok(release);
    }
    state.propose(next, release)
}

fn record_result(
    state: &State,
    snapshot: &mut Snapshot,
    attempt: Attempt,
    result: Completion,
) -> Result<Effect, Error> {
    validate_completion(&result)?;
    if result.receipt.is_none() {
        return complete(snapshot, attempt, result);
    }
    snapshot
        .operations
        .get_mut(&attempt.operation)
        .ok_or(Error::NotFound)?
        .phase = Phase::Publishing {
        attempt: attempt.clone(),
        result: result.clone(),
    };
    Ok(Effect::Publish {
        token: state.token(&attempt),
        result,
    })
}

fn complete(
    snapshot: &mut Snapshot,
    attempt: Attempt,
    result: Completion,
) -> Result<Effect, Error> {
    validate_completion(&result)?;
    let operation = snapshot
        .operations
        .get_mut(&attempt.operation)
        .ok_or(Error::NotFound)?;
    operation.phase = Phase::Completed {
        attempt: attempt.clone(),
        result: result.clone(),
    };
    snapshot.sequence = snapshot.sequence.checked_add(1).ok_or(Error::Limit)?;
    let entry = Entry {
        sequence: snapshot.sequence,
        attempt,
        result,
    };
    snapshot.entries.push(entry.clone());
    Ok(Effect::Deliver(entry))
}

fn notification(state: &State, id: OperationId, phase: &Phase) -> Option<Effect> {
    match phase {
        Phase::Ready => Some(Effect::Ready(id)),
        Phase::Recovering { attempt } => Some(Effect::Inspect(state.token(attempt))),
        Phase::Cancelling { attempt, .. } => Some(Effect::Stop(state.token(attempt))),
        Phase::Publishing { attempt, result } => Some(Effect::Publish {
            token: state.token(attempt),
            result: result.clone(),
        }),
        Phase::Unresolved { reason, .. } => Some(Effect::Unresolved {
            id,
            reason: *reason,
        }),
        Phase::Stopped { reason, .. } => Some(Effect::Stopped {
            id,
            reason: *reason,
        }),
        Phase::Running { .. } | Phase::Completed { .. } => None,
    }
}

/// Cancellation and expiry stop work; they never turn an unknown outcome into a known stop.
/// Cancelling an `Unresolved` attempt retries cleanup and then returns it to `Unresolved`; an
/// interrupted attempt whose policy cannot replay it becomes `Unresolved` once cleanup proves its
/// executor stopped. Expiry leaves `Unresolved` alone: time reveals nothing new about it.
fn stop(operation: &mut Operation, reason: StopReason) {
    operation.phase = match &operation.phase {
        Phase::Ready => Phase::Stopped {
            reason,
            attempt: None,
        },
        Phase::Running { attempt } => Phase::Cancelling {
            attempt: attempt.clone(),
            reason,
            unresolved: None,
        },
        Phase::Unresolved {
            attempt,
            reason: unresolved,
        } => Phase::Cancelling {
            attempt: attempt.clone(),
            reason,
            unresolved: Some(*unresolved),
        },
        Phase::Recovering { attempt } => Phase::Cancelling {
            attempt: attempt.clone(),
            reason,
            unresolved: match operation.spec.recovery {
                RecoveryPolicy::RetrySafe { .. } => None,
                RecoveryPolicy::Reconcile => Some(UnresolvedReason::ReconciliationRequired),
                RecoveryPolicy::NeverReplay => Some(UnresolvedReason::UnknownOutcome),
            },
        },
        other => other.clone(),
    };
}

fn expire(operation: &mut Operation, now_ms: u64) -> bool {
    if now_ms < operation.spec.deadline_ms || matches!(operation.phase, Phase::Unresolved { .. }) {
        return false;
    }
    let before = operation.phase.clone();
    stop(operation, StopReason::Deadline);
    operation.phase != before
}

fn validate_payload(value: &serde_json::Value) -> Result<(), Error> {
    if serde_json::to_vec(value)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > MAX_PAYLOAD_BYTES
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub(crate) fn validate_spec(spec: &OperationSpec) -> Result<(), Error> {
    if spec.name.is_empty()
        || spec.name.len() > 256
        || spec.version == 0
        || matches!(spec.recovery, RecoveryPolicy::RetrySafe { max_attempts: 0 })
    {
        return Err(Error::InvalidInput);
    }
    validate_payload(&spec.input)
}

pub(crate) fn validate_completion(result: &Completion) -> Result<(), Error> {
    if serde_json::to_vec(&result.audit)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > MAX_PAYLOAD_BYTES
    {
        return Err(Error::InvalidInput);
    }
    // Tool output can use the existing 100 KiB cap; JSON escaping and render data count too.
    if serde_json::to_vec(&result.output)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > MAX_RECEIPT_BYTES
    {
        return Err(Error::InvalidInput);
    }
    if let Some(receipt) = &result.receipt {
        if receipt.bytes.is_empty()
            || receipt.bytes.len() > MAX_RECEIPT_BYTES
            || !receipt.id.strip_prefix("sha256:").is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), Error> {
    composition::validate(snapshot).map_err(|_| Error::InvalidSnapshot)?;
    if let Some(driver) = &snapshot.driver {
        validate_driver(driver).map_err(|_| Error::InvalidSnapshot)?;
    }
    if snapshot.schema_version != SCHEMA_VERSION
        || snapshot.session.0.is_empty()
        || snapshot.session.0.len() > 256
        || snapshot.operations.len() > MAX_OPERATIONS
        || snapshot.entries.len() > snapshot.operations.len()
        || (snapshot.activation.is_none()
            && (snapshot.revision != 0 || !snapshot.operations.is_empty()))
        || (snapshot.activation.is_some() && snapshot.revision == 0)
    {
        return Err(Error::InvalidSnapshot);
    }
    let mut completed = 0;
    for (&id, operation) in &snapshot.operations {
        validate_spec(&operation.spec).map_err(|_| Error::InvalidSnapshot)?;
        let attempt_limit = match operation.spec.recovery {
            RecoveryPolicy::RetrySafe { max_attempts } => max_attempts,
            RecoveryPolicy::NeverReplay | RecoveryPolicy::Reconcile => 1,
        };
        if operation.attempts > attempt_limit {
            return Err(Error::InvalidSnapshot);
        }
        let attempt = match &operation.phase {
            Phase::Ready => {
                if operation.attempts != 0
                    && !matches!(operation.spec.recovery, RecoveryPolicy::RetrySafe { max_attempts } if operation.attempts < max_attempts)
                {
                    return Err(Error::InvalidSnapshot);
                }
                None
            }
            Phase::Stopped { attempt, .. } => attempt.as_ref(),
            Phase::Running { attempt } => {
                if Some(attempt.activation) != snapshot.activation {
                    return Err(Error::InvalidSnapshot);
                }
                Some(attempt)
            }
            Phase::Recovering { attempt }
            | Phase::Cancelling { attempt, .. }
            | Phase::Unresolved { attempt, .. } => Some(attempt),
            Phase::Publishing { attempt, result } => {
                if result.receipt.is_none() {
                    return Err(Error::InvalidSnapshot);
                }
                validate_completion(result).map_err(|_| Error::InvalidSnapshot)?;
                Some(attempt)
            }
            Phase::Completed { attempt, result } => {
                completed += 1;
                validate_completion(result).map_err(|_| Error::InvalidSnapshot)?;
                Some(attempt)
            }
        };
        if let Some(attempt) = attempt {
            if attempt.session != snapshot.session
                || attempt.operation != id
                || attempt.number == 0
                || attempt.number != operation.attempts
            {
                return Err(Error::InvalidSnapshot);
            }
        }
    }
    if completed != snapshot.entries.len() {
        return Err(Error::InvalidSnapshot);
    }
    if snapshot.entries.len() as u64 > snapshot.sequence
        || (snapshot.horizon.0 == 0 && snapshot.sequence != snapshot.entries.len() as u64)
    {
        return Err(Error::InvalidSnapshot);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut previous = 0;
    for entry in &snapshot.entries {
        if entry.sequence <= previous
            || entry.sequence > snapshot.sequence
            || !seen.insert(entry.attempt.operation)
            || !snapshot.operations.get(&entry.attempt.operation).is_some_and(|op| {
                matches!(&op.phase, Phase::Completed { attempt, result } if attempt == &entry.attempt && result == &entry.result)
            }) {
            return Err(Error::InvalidSnapshot);
        }
        previous = entry.sequence;
    }
    Ok(())
}

fn validate_driver(value: &serde_json::Value) -> Result<(), Error> {
    if serde_json::to_vec(value)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > 16 * 1024 * 1024
    {
        return Err(Error::Limit);
    }
    Ok(())
}
