//! Append-only probe progress owned by the same SQLite writer as the session.
use super::*;
use crate::session::durable::{validate_completion, Attempt, Completion, OperationSpec, Phase};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub output: Value,
    pub duration_ms: u64,
    pub audit: Vec<bee_core::AuditEvent>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub key: String,
    pub input_sha256: String,
    pub result: Option<ProbeResult>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRecord {
    pub version: u32,
    pub revision: u64,
    pub attempt: Attempt,
    pub spec: OperationSpec,
    pub probes: Vec<Probe>,
    pub completion: Option<Completion>,
}
impl WorkerRecord {
    pub fn pending(&self) -> bool {
        self.probes.iter().any(|p| p.result.is_none())
    }
    fn follows(&self, old: &Self) -> bool {
        if self.attempt != old.attempt || self.spec != old.spec || old.completion.is_some() {
            return false;
        }
        if self.probes == old.probes && self.completion.is_some() {
            return !self.pending();
        }
        if self.completion.is_some() {
            return false;
        }
        if self.probes.len() == old.probes.len() + 1 {
            return !old.pending()
                && self.probes[..old.probes.len()] == old.probes
                && self.probes.last().is_some_and(|p| p.result.is_none());
        }
        if self.probes.len() == old.probes.len() && !self.probes.is_empty() {
            let n = self.probes.len() - 1;
            return self.probes[..n] == old.probes[..n]
                && old.probes[n].result.is_none()
                && self.probes[n].result.is_some()
                && self.probes[n].key == old.probes[n].key
                && self.probes[n].input_sha256 == old.probes[n].input_sha256;
        }
        false
    }
}

impl Store {
    pub fn worker_load(&mut self, attempt: &Attempt) -> Result<Option<WorkerRecord>, StoreError> {
        let result = (|| {
            self.check()?;
            let stored: Option<(Vec<u8>, String)> = self
                .conn
                .query_row(
                    "SELECT payload,digest FROM workers WHERE operation=?1",
                    [i64::try_from(attempt.operation.0).map_err(|_| StoreError::Limit)?],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let record = if let Some((bytes, digest)) = stored {
                if format!("{:x}", Sha256::digest(&bytes)) != digest {
                    return Err(StoreError::Corrupt);
                }
                Some(serde_json::from_slice::<WorkerRecord>(&bytes)?)
            } else {
                None
            };
            if record
                .as_ref()
                .is_some_and(|r| &r.attempt != attempt || r.version != 1)
            {
                return Err(StoreError::Corrupt);
            }
            Ok(record)
        })();
        self.finish(result)
    }
    pub fn worker_write(&mut self, record: &WorkerRecord) -> Result<(), StoreError> {
        let result = self.worker_write_inner(record);
        self.finish(result)
    }
    fn worker_write_inner(&mut self, record: &WorkerRecord) -> Result<(), StoreError> {
        self.check()?;
        let bytes = serde_json::to_vec(record)?;
        if record.version != 1 || bytes.len() > 4 * 1024 * 1024 || record.probes.len() > 20 {
            return Err(StoreError::Limit);
        }
        let mut keys = std::collections::BTreeSet::new();
        if record
            .probes
            .iter()
            .any(|p| p.key.len() > 64 || p.input_sha256.len() != 64 || !keys.insert(&p.key))
        {
            return Err(StoreError::InvalidInput);
        }
        if let Some(result) = &record.completion {
            validate_completion(result).map_err(|_| StoreError::InvalidInput)?;
        }
        let old = self.worker_load(&record.attempt)?;
        if old.as_ref() == Some(record) {
            return Ok(());
        }
        if record.revision
            != old
                .as_ref()
                .map_or(Some(1), |r| r.revision.checked_add(1))
                .ok_or(StoreError::Limit)?
            || old.as_ref().is_some_and(|r| !record.follows(r))
            || (old.is_none() && (!record.probes.is_empty() || record.completion.is_some()))
        {
            return Err(StoreError::Conflict);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner: String =
            tx.query_row("SELECT owner FROM session WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if owner != self.activation.0.to_string() {
            return Err(StoreError::Stale);
        }
        let snapshot = read_snapshot(&tx, &self.session)?;
        let operation = snapshot
            .operation(record.attempt.operation)
            .ok_or(StoreError::Stale)?;
        let adds_probe = old
            .as_ref()
            .is_some_and(|old| record.probes.len() > old.probes.len());
        let wall_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        if adds_probe
            && (matches!(operation.phase, Phase::Cancelling { .. })
                || wall_ms.max(snapshot.observed_ms()) >= operation.spec.deadline_ms)
        {
            return Err(StoreError::Stale);
        }
        if record.spec != operation.spec
            || operation.spec.recovery != crate::session::durable::RecoveryPolicy::Reconcile
            || record.attempt.session != self.session
            || !matches!(&operation.phase, Phase::Running { attempt } | Phase::Recovering { attempt } | Phase::Cancelling { attempt, .. } if attempt == &record.attempt)
        {
            return Err(StoreError::Stale);
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        tx.execute("INSERT INTO workers(operation,payload,digest) VALUES(?1,?2,?3) ON CONFLICT(operation) DO UPDATE SET payload=excluded.payload,digest=excluded.digest", params![i64::try_from(record.attempt.operation.0).map_err(|_| StoreError::Limit)?, bytes, digest])?;
        tx.commit()?;
        Ok(())
    }
}
