use super::executor::Executor;
use crate::provider::Usage;
use crate::session::durable::OperationId;
use crate::transcript::{EpisodeStatus, TranscriptTurn};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub turns: u32,
    pub tool_calls: u32,
    pub timeout_ms: u64,
    pub tool_timeout_ms: u64,
    pub model_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub request_id: String,
    pub status: EpisodeStatus,
    pub turns: Vec<TranscriptTurn>,
    pub usage: Option<Usage>,
    pub started_ms: u64,
    pub ended_ms: u64,
    pub model_calls: u32,
    pub budget: super::Budget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Input {
    Submission {
        text: String,
        limits: Limits,
        started_ms: u64,
    },
    Steering {
        parent: String,
        text: String,
    },
    Cancel {
        parent: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum Step {
    Model {
        operation: Option<OperationId>,
        chunks: Vec<String>,
    },
    Tools {
        model_operation: OperationId,
        next: usize,
        operation: Option<OperationId>,
        executor: Option<Executor>,
        executor_activation: Option<String>,
    },
}
impl Step {
    pub fn operation(&self) -> Option<OperationId> {
        match self {
            Self::Model { operation, .. } | Self::Tools { operation, .. } => *operation,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Active {
    pub request_id: String,
    pub limits: Limits,
    pub started_ms: u64,
    pub deadline_ms: u64,
    pub turns: Vec<TranscriptTurn>,
    pub usage: Option<Usage>,
    pub model_calls: u32,
    pub step: Step,
    pub consumed_inputs: u64,
    pub cancelling: bool,
    pub timed_out: bool,
    pub budget: super::Budget,
    pub wake: Option<super::wake::Wake>,
    /// Root-to-innermost codemode scripts for the current tool call (023).
    #[serde(default)]
    pub scripts: Vec<super::codemode::Cursor>,
}
/// Version 3 adds the codemode script stack; version-2 journals carry none.
pub(super) const JOURNAL_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Journal {
    pub version: u32,
    pub compatibility: String,
    pub runtime: String,
    /// Only its bounded tail is serialized; older messages live in the store's conversation table.
    pub conversation: super::conversation::StoredConversation,
    pub next_operation: u64,
    pub next_wake_generation: u64,
    pub observed_ms: u64,
    pub active: Option<Active>,
    pub finished: BTreeMap<String, Report>,
    /// Receipt IDs this session committed, oldest first. The only citable evidence; a receipt
    /// file alone proves nothing. Bounded: the oldest ID is evicted (and becomes uncitable) first.
    #[serde(default)]
    pub receipts: VecDeque<String>,
}

/// Receipts a durable session can cite. Independent of the operation log, which may be pruned.
pub(super) const MAX_COMMITTED_RECEIPTS: usize = 1024;

fn is_receipt_id(id: &str) -> bool {
    id.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

impl Journal {
    /// Record a committed receipt, returning the ID evicted to stay within the bound.
    pub(super) fn commit_receipt(&mut self, id: &str) -> Option<String> {
        if self.receipts.iter().any(|known| known == id) {
            return None;
        }
        self.receipts.push_back(id.to_string());
        if self.receipts.len() > MAX_COMMITTED_RECEIPTS {
            return self.receipts.pop_front();
        }
        None
    }

    pub(super) fn validate(
        &self,
        snapshot: &crate::session::durable::Snapshot,
        inbox: &[crate::session::durable::store::Submission],
    ) -> Result<(), super::DriverError> {
        use crate::session::durable::{Error, Phase, WorkKind};
        if self.version != JOURNAL_VERSION
            || self.next_operation == 0
            || self.next_wake_generation == 0
            || snapshot
                .operations()
                .keys()
                .any(|id| id.0 >= self.next_operation)
            || self.finished.len() > 1024
            || self.receipts.len() > MAX_COMMITTED_RECEIPTS
            || self.receipts.iter().any(|id| !is_receipt_id(id))
        {
            return Err(Error::InvalidSnapshot.into());
        }
        let mut charges = std::collections::BTreeSet::new();
        for budget in self
            .finished
            .values()
            .map(|r| &r.budget)
            .chain(self.active.iter().map(|a| &a.budget))
        {
            for r in &budget.reservations {
                if !charges.insert((r.attempt.operation, r.attempt.number)) {
                    return Err(Error::InvalidSnapshot.into());
                }
            }
        }
        for (id, operation) in snapshot.operations() {
            if (1..=operation.attempts).any(|number| !charges.contains(&(*id, number))) {
                return Err(Error::InvalidSnapshot.into());
            }
        }
        for (id, report) in &self.finished {
            if id != &report.request_id || !inbox.iter().any(|s| &s.request_id == id) {
                return Err(Error::InvalidSnapshot.into());
            }
            let input = inbox
                .iter()
                .find(|s| &s.request_id == id)
                .ok_or(Error::InvalidSnapshot)?;
            let Input::Submission { limits, .. } = serde_json::from_value(input.input.clone())?
            else {
                return Err(Error::InvalidSnapshot.into());
            };
            report
                .budget
                .validate(snapshot, limits.turns, limits.tool_calls)?;
            if report.model_calls != report.budget.charged(WorkKind::Model)
                || report.usage != report.budget.known_usage()?
            {
                return Err(Error::InvalidSnapshot.into());
            }
        }
        if let Some(active) = &self.active {
            super::codemode::Cursor::validate_stack(
                &active.scripts,
                active,
                snapshot,
                self.next_operation,
            )?;
            active
                .budget
                .validate(snapshot, active.limits.turns, active.limits.tool_calls)?;
            if active.model_calls != active.budget.charged(WorkKind::Model)
                || active.usage != active.budget.known_usage()?
            {
                return Err(Error::InvalidSnapshot.into());
            }
            if let Some(wake) = &active.wake {
                let operation = snapshot
                    .operation(wake.attempt.operation)
                    .ok_or(Error::InvalidSnapshot)?;
                if wake.generation == 0
                    || wake.generation >= self.next_wake_generation
                    || active.step.operation() != Some(wake.attempt.operation)
                    || wake.attempt.number != operation.attempts
                    || operation.spec.kind != WorkKind::Model
                    || !active
                        .budget
                        .reservations
                        .iter()
                        .any(|r| r.attempt == wake.attempt && r.charge == super::Charge::Unresolved)
                    || !match &operation.phase {
                        Phase::Recovering { attempt }
                        | Phase::Cancelling { attempt, .. }
                        | Phase::Unresolved { attempt, .. }
                        | Phase::Stopped {
                            attempt: Some(attempt),
                            ..
                        } => attempt == &wake.attempt,
                        Phase::Ready => wake.ready,
                        _ => false,
                    }
                {
                    return Err(Error::InvalidSnapshot.into());
                }
            }
            let admitted = inbox
                .iter()
                .find(|s| s.request_id == active.request_id)
                .ok_or(Error::InvalidSnapshot)?;
            let Input::Submission {
                limits, started_ms, ..
            } = serde_json::from_value(admitted.input.clone())?
            else {
                return Err(Error::InvalidSnapshot.into());
            };
            if active.started_ms != started_ms
                || serde_json::to_value(&active.limits)? != serde_json::to_value(limits)?
                || active.deadline_ms
                    != started_ms
                        .checked_add(active.limits.timeout_ms)
                        .ok_or(Error::InvalidSnapshot)?
                || active.turns.len() > active.model_calls as usize
                || self.finished.contains_key(&active.request_id)
            {
                return Err(Error::InvalidSnapshot.into());
            }
            if let Some(id) = active.step.operation() {
                if id.0 >= self.next_operation {
                    return Err(Error::InvalidSnapshot.into());
                }
                if let Some(operation) = snapshot.operation(id) {
                    let expected = if matches!(active.step, Step::Model { .. }) {
                        WorkKind::Model
                    } else {
                        WorkKind::Tool
                    };
                    if operation.spec.kind != expected {
                        return Err(Error::InvalidSnapshot.into());
                    }
                }
            }
            if let Step::Tools {
                model_operation,
                next,
                ..
            } = active.step
            {
                let operation = snapshot
                    .operation(model_operation)
                    .ok_or(Error::InvalidSnapshot)?;
                let Phase::Completed { result, .. } = &operation.phase else {
                    return Err(Error::InvalidSnapshot.into());
                };
                let turn: crate::provider::Turn = serde_json::from_value(result.output.clone())?;
                if operation.spec.kind != WorkKind::Model
                    || next > turn.tool_calls.len()
                    || active.turns.is_empty()
                {
                    return Err(Error::InvalidSnapshot.into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> Journal {
        Journal {
            version: JOURNAL_VERSION,
            compatibility: String::new(),
            runtime: String::new(),
            conversation: super::super::conversation::StoredConversation::new(String::new()),
            next_operation: 1,
            next_wake_generation: 1,
            observed_ms: 0,
            active: None,
            finished: BTreeMap::new(),
            receipts: VecDeque::new(),
        }
    }

    #[test]
    fn committed_receipts_stay_bounded_and_evict_the_oldest_first() {
        let mut journal = journal();
        let id = |n: usize| format!("sha256:{n:064x}");
        for n in 0..MAX_COMMITTED_RECEIPTS {
            assert_eq!(journal.commit_receipt(&id(n)), None);
        }
        assert_eq!(journal.commit_receipt(&id(0)), None, "already known");
        assert_eq!(
            journal.commit_receipt(&id(MAX_COMMITTED_RECEIPTS)),
            Some(id(0))
        );
        assert_eq!(journal.receipts.len(), MAX_COMMITTED_RECEIPTS);
        assert!(journal.receipts.iter().all(|r| is_receipt_id(r)));
        assert!(!is_receipt_id("sha256:../../etc/passwd"));
    }
}
