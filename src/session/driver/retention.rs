//! Pruning keeps a long session inside its live-state bounds. Only finished submissions whose
//! every charged operation is `Completed` or `Stopped` are forgotten; an unknown outcome keeps its
//! whole submission. A pruned request ID stays admitted as a tombstone, so repeating it is refused
//! rather than rerun. Receipt files stay on disk.
use super::*;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Prune once operations, finished reports, or live admissions reach this many.
    pub trigger: usize,
    /// The newest finished reports kept for replay after pruning.
    pub keep: usize,
    /// Prune once the serialized journal reaches this many bytes.
    pub journal_bytes: usize,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            trigger: 768,
            keep: 256,
            journal_bytes: 12 * 1024 * 1024,
        }
    }
}

impl Driver {
    /// Runs only between submissions, before admitting a new one.
    pub(super) async fn prune(&mut self) -> Result<(), DriverError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let snapshot = self.state.committed();
        let retention = self.retention;
        if journal.active.is_some()
            || (snapshot.operations().len() < retention.trigger
                && journal.finished.len() < retention.trigger
                && self.inbox.len() < retention.trigger
                && serde_json::to_vec(journal)?.len() < retention.journal_bytes)
        {
            return Ok(());
        }
        let admitted = |id: &str| {
            self.inbox
                .iter()
                .find(|s| s.request_id == id)
                .map(|s| s.sequence)
                .ok_or(core::Error::InvalidSnapshot)
        };
        let mut order = Vec::with_capacity(journal.finished.len());
        for id in journal.finished.keys() {
            order.push((admitted(id)?, id.clone()));
        }
        order.sort();
        let old = order.len().saturating_sub(retention.keep);
        let mut retire = Vec::new();
        let mut kept_ops = BTreeSet::new();
        for (index, (_, id)) in order.iter().enumerate() {
            let ops: BTreeSet<_> = journal.finished[id]
                .budget
                .reservations
                .iter()
                .map(|r| r.attempt.operation)
                .collect();
            let finished = ops.iter().all(|op| {
                snapshot.operation(*op).is_some_and(|o| {
                    matches!(o.phase, Phase::Completed { .. } | Phase::Stopped { .. })
                })
            });
            if index < old && finished {
                retire.push(id.clone());
            } else {
                kept_ops.extend(ops);
            }
        }
        let operations: Vec<_> = snapshot
            .operations()
            .iter()
            .filter(|(id, op)| {
                !kept_ops.contains(id)
                    && matches!(op.phase, Phase::Completed { .. } | Phase::Stopped { .. })
            })
            .map(|(id, _)| *id)
            .collect();
        if retire.is_empty() && operations.is_empty() {
            return Ok(());
        }
        let pruned: BTreeSet<_> = retire.iter().cloned().collect();
        let mut admissions = Vec::new();
        for entry in &self.inbox {
            let parent = match serde_json::from_value::<Input>(entry.input.clone())? {
                Input::Submission { .. } => entry.request_id.clone(),
                Input::Steering { parent, .. } | Input::Cancel { parent } => parent,
            };
            if pruned.contains(&parent) {
                admissions.push(entry.request_id.clone());
            }
        }
        for id in &retire {
            self.journal_mut().finished.remove(id);
        }
        let event = if operations.is_empty() {
            Event::Checkpoint(serde_json::to_value(self.journal())?)
        } else {
            Event::Prune { operations }
        };
        self.apply_retiring(event, admissions.clone()).await?;
        let admissions: BTreeSet<_> = admissions.into_iter().collect();
        self.inbox.retain(|s| !admissions.contains(&s.request_id));
        Ok(())
    }
}
