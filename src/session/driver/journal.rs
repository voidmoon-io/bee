//! Capability passed only to trusted journal-aware tools; never exposed in model arguments.
use super::{storage::Request, DriverError};
use crate::session::durable::{
    store::journal::{Probe, ProbeResult, WorkerRecord},
    Attempt, Completion, OperationSpec,
};
use tokio::sync::{mpsc, oneshot};

pub struct Journal {
    sender: mpsc::WeakSender<Request>,
    record: WorkerRecord,
    deadline: std::time::Instant,
    read_only: bool,
}
impl Journal {
    pub(super) async fn open(
        sender: mpsc::WeakSender<Request>,
        attempt: Attempt,
        spec: OperationSpec,
        loaded: Option<WorkerRecord>,
    ) -> Result<Self, DriverError> {
        let fresh = loaded.is_none();
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(spec.deadline_ms.saturating_sub(super::now_ms()));
        let record = loaded.unwrap_or(WorkerRecord {
            version: 1,
            revision: 0,
            attempt: attempt.clone(),
            spec: spec.clone(),
            probes: vec![],
            completion: None,
        });
        if record.attempt != attempt || record.spec != spec {
            return Err(DriverError::Incompatible);
        }
        let mut journal = Self {
            sender,
            record,
            deadline,
            read_only: false,
        };
        if fresh {
            journal.save().await?;
        }
        Ok(journal)
    }
    pub fn record(&self) -> &WorkerRecord {
        &self.record
    }
    pub(super) fn read_only(&mut self) {
        self.read_only = true;
    }
    async fn save(&mut self) -> Result<(), DriverError> {
        self.record.revision = self
            .record
            .revision
            .checked_add(1)
            .ok_or(crate::session::durable::Error::Limit)?;
        let (tx, rx) = oneshot::channel();
        self.sender
            .upgrade()
            .ok_or(DriverError::StorageClosed)?
            .send(Request::WorkerWrite(Box::new(self.record.clone()), tx))
            .await
            .map_err(|_| DriverError::StorageClosed)?;
        rx.await.map_err(|_| DriverError::StorageClosed)?
    }
    /// A prior completed probe is immutable. A prior intent without a result is never rerun.
    pub async fn begin(
        &mut self,
        key: String,
        input: &impl serde::Serialize,
    ) -> Result<Option<ProbeResult>, DriverError> {
        let digest = super::fingerprint(input)?;
        if let Some(probe) = self.record.probes.iter().find(|p| p.key == key) {
            if probe.input_sha256 != digest {
                return Err(DriverError::Incompatible);
            }
            return probe
                .result
                .clone()
                .map(Some)
                .ok_or(DriverError::Unresolved(self.record.attempt.operation.0));
        }
        if self.record.pending() || self.record.completion.is_some() {
            return Err(DriverError::Unresolved(self.record.attempt.operation.0));
        }
        if self.read_only
            || std::time::Instant::now() >= self.deadline
            || super::now_ms() >= self.record.spec.deadline_ms
        {
            return Err(DriverError::Expired);
        }
        self.record.probes.push(Probe {
            key,
            input_sha256: digest,
            result: None,
        });
        self.save().await?;
        Ok(None)
    }
    pub async fn complete(&mut self, key: &str, result: ProbeResult) -> Result<(), DriverError> {
        let probe = self
            .record
            .probes
            .last_mut()
            .ok_or(crate::session::durable::Error::InvalidPhase)?;
        if probe.key != key || probe.result.is_some() {
            return Err(crate::session::durable::Error::Conflict.into());
        }
        probe.result = Some(result);
        self.save().await
    }
    pub(crate) async fn finish(&mut self, result: Completion) -> Result<(), DriverError> {
        self.record.completion = Some(result);
        self.save().await
    }
}
