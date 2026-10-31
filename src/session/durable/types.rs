use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: u32 = 5;
pub const MAX_OPERATIONS: usize = 1024;
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionId(pub String);

/// Fresh identity supplied by the host on every open, including failed activations.
/// The host must never reuse it; a persisted counter alone cannot cover failed commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationId(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperationId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub session: SessionId,
    pub activation: ActivationId,
    pub operation: OperationId,
    pub number: u32,
}

/// Recovery and cleanup address an old attempt through the current activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryToken {
    pub activation: ActivationId,
    pub attempt: Attempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkKind {
    Model,
    Tool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPolicy {
    /// The executor may still recover a recorded result, but never redispatch automatically.
    NeverReplay,
    RetrySafe {
        max_attempts: u32,
    },
    Reconcile,
}

/// Trusted registration data, not model-selected replay authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSpec {
    pub kind: WorkKind,
    pub name: String,
    pub version: u32,
    pub input: Value,
    pub recovery: RecoveryPolicy,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub audit: Vec<bee_core::AuditEvent>,
    pub output: Value,
    pub receipt: Option<ReceiptPublication>,
}

/// Exact UTF-8 receipt bytes prepared once by the trusted evidence adapter.
/// Retained through publication and delivery so recovery never regenerates provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptPublication {
    pub id: String,
    pub bytes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    Cancelled,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnresolvedReason {
    UnknownOutcome,
    ReconciliationRequired,
    RetryLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Ready,
    Running {
        attempt: Attempt,
    },
    Recovering {
        attempt: Attempt,
    },
    Cancelling {
        attempt: Attempt,
        reason: StopReason,
    },
    Unresolved {
        attempt: Attempt,
        reason: UnresolvedReason,
    },
    Publishing {
        attempt: Attempt,
        result: Completion,
    },
    Completed {
        attempt: Attempt,
        /// Stored once, in the operation's entry; loading restores it from there.
        #[serde(default, skip_serializing)]
        result: Completion,
    },
    Stopped {
        reason: StopReason,
        /// Cleanup ended this attempt; its external outcome can still be unknown.
        attempt: Option<Attempt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub spec: OperationSpec,
    pub attempts: u32,
    pub phase: Phase,
}

/// Sequence is the client deduplication cursor. Delivery is at least once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub sequence: u64,
    pub attempt: Attempt,
    pub result: Completion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "StoredSnapshot")]
pub struct Snapshot {
    pub(super) schema_version: u32,
    pub(super) session: SessionId,
    pub(super) activation: Option<ActivationId>,
    pub(super) revision: u64,
    pub(super) observed_ms: u64,
    pub(super) operations: BTreeMap<OperationId, Operation>,
    pub(super) entries: Vec<Entry>,
    pub(super) driver: Option<Value>,
}

/// A snapshot as stored: a completed operation's result is written only in its entry, not twice.
/// Snapshots that still carry the result in the phase load unchanged; validation compares both.
#[derive(Deserialize)]
struct StoredSnapshot {
    schema_version: u32,
    session: SessionId,
    activation: Option<ActivationId>,
    revision: u64,
    observed_ms: u64,
    operations: BTreeMap<OperationId, Operation>,
    entries: Vec<Entry>,
    driver: Option<Value>,
}

impl From<StoredSnapshot> for Snapshot {
    fn from(stored: StoredSnapshot) -> Self {
        let mut operations = stored.operations;
        for entry in &stored.entries {
            if let Some(Operation {
                phase: Phase::Completed { attempt, result },
                ..
            }) = operations.get_mut(&entry.attempt.operation)
            {
                if attempt == &entry.attempt && *result == Completion::default() {
                    *result = entry.result.clone();
                }
            }
        }
        Self {
            schema_version: stored.schema_version,
            session: stored.session,
            activation: stored.activation,
            revision: stored.revision,
            observed_ms: stored.observed_ms,
            operations,
            entries: stored.entries,
            driver: stored.driver,
        }
    }
}

impl Snapshot {
    pub fn empty(session: SessionId) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            session,
            activation: None,
            revision: 0,
            observed_ms: 0,
            operations: BTreeMap::new(),
            entries: Vec::new(),
            driver: None,
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn observed_ms(&self) -> u64 {
        self.observed_ms
    }
    pub fn session(&self) -> &SessionId {
        &self.session
    }
    pub fn operation(&self, id: OperationId) -> Option<&Operation> {
        self.operations.get(&id)
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    pub fn driver(&self) -> Option<&Value> {
        self.driver.as_ref()
    }
    pub fn operations(&self) -> &BTreeMap<OperationId, Operation> {
        &self.operations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitId {
    pub session: SessionId,
    pub activation: ActivationId,
    pub revision: u64,
}

/// Store the entire candidate atomically only if expected_revision still matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub id: CommitId,
    pub expected_revision: u64,
    pub snapshot: Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Executor proves this exact attempt has a durable result and is quiescent.
    Found(Completion),
    /// No result is recoverable, but the old executor is proven stopped.
    Quiescent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Trusted checkpoint executor resumes only never-started subwork, not an uncertain effect.
    ResumeReconciliation {
        token: RecoveryToken,
        now_ms: u64,
    },
    /// The host dropped this activation's executor after an interrupted request.
    Interrupted {
        attempt: Attempt,
    },
    /// Bounded host-owned conversation checkpoint, committed through the same output gate.
    Checkpoint(Value),
    /// Host has published and validated the exact committed receipt bytes.
    Published {
        token: RecoveryToken,
        receipt_id: String,
    },
    Activate {
        now_ms: u64,
    },
    Submit {
        id: OperationId,
        spec: OperationSpec,
    },
    /// Host has checked current configuration, policy, and execution availability.
    Authorize {
        id: OperationId,
        now_ms: u64,
    },
    Completed {
        attempt: Attempt,
        result: Completion,
    },
    Recovered {
        token: RecoveryToken,
        outcome: RecoveryOutcome,
        now_ms: u64,
    },
    Cancel {
        id: OperationId,
    },
    Cleaned {
        token: RecoveryToken,
    },
    Tick {
        now_ms: u64,
    },
    Replay {
        after_sequence: u64,
    },
    Committed(CommitId),
    /// Includes ambiguous acknowledgement loss: reopen storage before doing more work.
    CommitFailed(CommitId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Persist(Box<Commit>),
    Accepted(OperationId),
    Ready(OperationId),
    Dispatch {
        attempt: Attempt,
        spec: OperationSpec,
    },
    Inspect(RecoveryToken),
    Stop(RecoveryToken),
    Publish {
        token: RecoveryToken,
        result: Completion,
    },
    /// Evidence-bearing entries must be validated by the evidence adapter on every delivery.
    Deliver(Entry),
    Stopped {
        id: OperationId,
        reason: StopReason,
    },
    Unresolved {
        id: OperationId,
        reason: UnresolvedReason,
    },
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("session needs activation")]
    Inactive,
    #[error("session is already active")]
    AlreadyActive,
    #[error("commit pending; retain and redeliver this event after acknowledgement")]
    Busy,
    #[error("storage state uncertain; reopen before continuing")]
    Suspended,
    #[error("stale or foreign event")]
    Stale,
    #[error("operation not found")]
    NotFound,
    #[error("event does not apply to this phase")]
    InvalidPhase,
    #[error("identifier already has different input or result")]
    Conflict,
    #[error("invalid or unsupported persisted state")]
    InvalidSnapshot,
    #[error("invalid operation or payload")]
    InvalidInput,
    #[error("session limit reached")]
    Limit,
}
