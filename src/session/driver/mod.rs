//! Opt-in shared durable conversation driver. SQLite and the core have one serialized owner.
//! UI callbacks are observations of committed state; admission IDs survive process restarts.
mod budget;
mod conversation;
mod execution;
mod executor;
pub mod journal;
mod presentation;
mod recovery;
mod retention;
mod storage;
mod types;
mod wake;
pub use budget::{Budget, Charge, Reservation};
pub use presentation::{exchange, run_episode, RunBinding};
pub use retention::Retention;
pub use types::{Limits, Report};

/// Optional diagnostics/fault-injection observer. Called on the storage owner thread;
/// implementations must not wait on session APIs or acknowledge external work.
pub trait Observer: Send + Sync {
    fn before_commit(&self, _commit: &core::Commit) {}
    fn committed(&self, _commit: &core::Commit) {}
    fn worker_committed(&self, _record: &core::store::journal::WorkerRecord) {}
}

use crate::evidence::EvidenceStore;
use crate::provider::{Conversation, Message, Model, StreamEvent, Turn};
use crate::repl::ReplOutput;
use crate::session::durable::{self as core, store::Submission, *};
use crate::tools::{ToolRegistry, ToolResult};
use crate::transcript::{EpisodeStatus, RecordedCall, TranscriptTurn};
use crate::Sandbox;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use types::{Active, Input, Journal, Step};

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error(transparent)]
    Provider(#[from] crate::provider::ModelError),
    #[error(transparent)]
    Core(#[from] core::Error),
    #[error(transparent)]
    Store(#[from] core::store::StoreError),
    #[error(transparent)]
    Adapter(#[from] crate::tools::durable::AdapterError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("session storage owner stopped; reopen the session")]
    StorageClosed,
    #[error("durable session configuration changed; reopen with compatible current configuration")]
    Incompatible,
    #[error("session driver was interrupted; reopen before continuing")]
    Interrupted,
    #[error("submission cancelled; interrupted effects may have an unknown outcome")]
    Cancelled,
    #[error("submission deadline exceeded")]
    Expired,
    #[error("submission call budget exhausted")]
    BudgetExhausted,
    #[error("unresolved operation {0}: old executor/result could not be reconciled; no tool was replayed")]
    Unresolved(u64),
    #[error("{0}")]
    Refused(String),
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
pub fn fingerprint(value: &impl serde::Serialize) -> Result<String, DriverError> {
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
pub fn request_id() -> Result<String, DriverError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| DriverError::Refused(error.to_string()))?;
    Ok(format!("{:032x}", u128::from_le_bytes(bytes)))
}

struct Control {
    id: String,
    input: Input,
}

/// Shared by the driver and UI. Sending a control queues it; only the driver's acknowledgement
/// means it was durably admitted. The bounded queue rejects overload rather than dropping input.
pub struct Session {
    driver: tokio::sync::Mutex<Driver>,
    controls: mpsc::Sender<Control>,
    current: Arc<Mutex<Option<String>>>,
    resume: Option<String>,
    evidence: EvidenceStore,
}
impl Session {
    pub async fn open(
        path: PathBuf,
        id: SessionId,
        compatibility: String,
        resume: Option<String>,
    ) -> Result<Arc<Self>, DriverError> {
        Self::open_observed(path, id, compatibility, resume, None).await
    }
    pub async fn open_observed(
        path: PathBuf,
        id: SessionId,
        compatibility: String,
        resume: Option<String>,
        observer: Option<Arc<dyn Observer>>,
    ) -> Result<Arc<Self>, DriverError> {
        let evidence = EvidenceStore::for_session(path.join("evidence"), &id)?;
        let (storage, snapshot, activation, inbox, archived) =
            storage::Storage::open(path, id, observer).await?;
        let mut journal: Option<Journal> = snapshot
            .driver()
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        match &mut journal {
            Some(journal) => journal.conversation.restore(archived)?,
            None if !archived.is_empty() => return Err(core::Error::InvalidSnapshot.into()),
            None => {}
        }
        if let Some(journal) = &journal {
            journal.validate(&snapshot, &inbox)?;
        } else if !snapshot.operations().is_empty() {
            return Err(DriverError::Incompatible);
        }
        if journal
            .as_ref()
            .is_some_and(|j| j.version != 2 || j.compatibility != compatibility)
        {
            return Err(DriverError::Incompatible);
        }
        if let Some(active) = journal.as_mut().and_then(|j| j.active.as_mut()) {
            active.budget.interrupt();
        }
        if let Some(journal) = journal.as_mut() {
            // Sessions from before the journal kept receipt IDs still have them in their entries.
            for entry in snapshot.entries() {
                if let Some(receipt) = &entry.result.receipt {
                    journal.commit_receipt(&receipt.id);
                }
            }
            evidence.admit_committed(&journal.receipts);
        }
        let resume = resume
            .or_else(|| {
                journal
                    .as_ref()
                    .and_then(|j| j.active.as_ref().map(|a| a.request_id.clone()))
            })
            .or_else(|| {
                inbox
                    .iter()
                    .find(|s| {
                        matches!(
                            serde_json::from_value::<Input>(s.input.clone()),
                            Ok(Input::Submission { .. })
                        ) && journal
                            .as_ref()
                            .is_none_or(|j| !j.finished.contains_key(&s.request_id))
                    })
                    .map(|s| s.request_id.clone())
            });
        let (controls, rx) = mpsc::channel(16);
        let current = Arc::new(Mutex::new(None));
        let clock_epoch_ms = now_ms()
            .max(snapshot.observed_ms())
            .max(journal.as_ref().map_or(0, |j| j.observed_ms));
        let mut driver = Driver {
            storage,
            state: State::open(snapshot, activation)?,
            journal,
            compatibility,
            inbox,
            controls: rx,
            current: current.clone(),
            evidence: evidence.clone(),
            interrupted: false,
            clock_epoch_ms,
            clock_start: std::time::Instant::now(),
            retention: Retention::default(),
        };
        driver.apply(Event::Activate { now_ms: now_ms() }).await?;
        Ok(Arc::new(Self {
            driver: tokio::sync::Mutex::new(driver),
            controls,
            current,
            resume,
            evidence,
        }))
    }
    pub fn evidence(&self) -> EvidenceStore {
        self.evidence.clone()
    }
    /// Replace when finished submissions are pruned. The default suits real sessions.
    pub async fn set_retention(&self, retention: Retention) -> Result<(), DriverError> {
        if retention.keep >= retention.trigger || retention.trigger > MAX_OPERATIONS {
            return Err(DriverError::Refused("invalid retention".into()));
        }
        self.driver.lock().await.retention = retention;
        Ok(())
    }
    pub fn resume_request(&self) -> Option<&str> {
        self.resume.as_deref()
    }
    /// Read accounting from the last acknowledged checkpoint, including after a failed run.
    pub async fn budget(&self, request: &str) -> Result<Option<Budget>, DriverError> {
        let driver = self.driver.lock().await;
        let Some(value) = driver.state.committed().driver() else {
            return Ok(None);
        };
        let journal: Journal = serde_json::from_value(value.clone())?;
        let mut budget = journal
            .finished
            .get(request)
            .map(|r| r.budget.clone())
            .or_else(|| {
                journal
                    .active
                    .filter(|a| a.request_id == request)
                    .map(|a| a.budget)
            });
        if driver.interrupted {
            if let Some(budget) = &mut budget {
                budget.interrupt();
            }
        }
        Ok(budget)
    }
    pub fn steer(&self, text: String) -> Result<(), DriverError> {
        if text.len() > 16 * 1024 {
            return Err(DriverError::Refused("steering input exceeds 16 KiB".into()));
        }
        let parent = self
            .current
            .lock()
            .expect("current submission")
            .clone()
            .ok_or_else(|| DriverError::Refused("no active submission".into()))?;
        self.send(Input::Steering { parent, text })
    }
    pub fn cancel(&self) -> Result<(), DriverError> {
        let parent = self
            .current
            .lock()
            .expect("current submission")
            .clone()
            .ok_or_else(|| DriverError::Refused("no active submission".into()))?;
        self.send(Input::Cancel { parent })
    }
    fn send(&self, input: Input) -> Result<(), DriverError> {
        self.controls
            .try_send(Control {
                id: request_id()?,
                input,
            })
            .map_err(|_| {
                DriverError::Refused(
                    "session control queue full or closed; input was not acknowledged".into(),
                )
            })
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        request: &str,
        text: Option<&str>,
        system: &str,
        limits: Limits,
        model: &dyn Model,
        registry: &mut ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
        hooks: Option<&crate::grants::escalate::LoopEscalation>,
    ) -> Result<(Report, Conversation), DriverError> {
        let mut driver = self.driver.lock().await;
        if driver.interrupted {
            return Err(DriverError::Interrupted);
        }
        driver.interrupted = true;
        let result = driver
            .run(
                request, text, system, limits, model, registry, sandbox, output, hooks,
            )
            .await;
        // Failed storage or a dropped future cannot be resumed in memory. A retired request is
        // refused before anything is admitted, so it leaves the session usable.
        driver.interrupted = result.is_err()
            && !matches!(
                result,
                Err(DriverError::Store(core::store::StoreError::Retired))
            );
        *self.current.lock().expect("current submission") = None;
        while driver.controls.try_recv().is_ok() {
            output.error("input was not admitted: its submission already ended; submit it again");
        }
        result
    }
}

/// The first path in a session directory that a tool under `policy` could write, if any. A session
/// directory a tool can write is not a record of what tools did. Decided with the kernel's own
/// matcher; `resolver` supplies `:project_root` and `~`. An observe-mode policy blocks nothing.
pub fn tool_writable_path(
    policy: &bee_core::Policy,
    dir: &std::path::Path,
    resolver: &dyn bee_core::Resolver,
) -> Result<Option<PathBuf>, String> {
    use std::os::unix::ffi::OsStrExt;
    if policy.mode == bee_core::Mode::Observe {
        return Ok(Some(dir.to_path_buf()));
    }
    let rules = policy
        .compile_filesystem(resolver)
        .map_err(|e| e.to_string())?;
    let default_deny = policy.denies_unmatched_writes();
    let evidence = dir.join("evidence");
    // Receipt names are digests; both extremes stand in for any suffix rule over hex.
    let candidates = [
        dir.to_path_buf(),
        dir.join("session.sqlite3"),
        dir.join("session.sqlite3-wal"),
        dir.join("session.sqlite3-shm"),
        dir.join("session.sqlite3-journal"),
        evidence.join(format!("{}.json", "0".repeat(64))),
        evidence.join(format!("{}.json", "f".repeat(64))),
        evidence,
    ];
    for path in candidates {
        let writable = bee_userspace::filesystem_allows_write(
            &rules,
            default_deny,
            path.as_os_str().as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        if writable {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

struct Driver {
    storage: storage::Storage,
    state: State,
    journal: Option<Journal>,
    compatibility: String,
    inbox: Vec<Submission>,
    controls: mpsc::Receiver<Control>,
    current: Arc<Mutex<Option<String>>>,
    evidence: EvidenceStore,
    interrupted: bool,
    clock_epoch_ms: u64,
    clock_start: std::time::Instant,
    retention: Retention,
}
impl Driver {
    fn journal(&self) -> &Journal {
        self.journal.as_ref().expect("initialized journal")
    }
    fn journal_mut(&mut self) -> &mut Journal {
        self.journal.as_mut().expect("initialized journal")
    }
    fn active(&self) -> &Active {
        self.journal().active.as_ref().expect("active submission")
    }
    fn active_mut(&mut self) -> &mut Active {
        self.journal_mut()
            .active
            .as_mut()
            .expect("active submission")
    }
    async fn apply(&mut self, event: Event) -> Result<Vec<Effect>, DriverError> {
        // A publication commits its receipt ID atomically with the journal checkpoint below.
        let published = match (&event, &self.journal) {
            (Event::Published { receipt_id, .. }, Some(_)) => Some(receipt_id.clone()),
            _ => None,
        };
        let Some(id) = published else {
            return self.apply_retiring(event, Vec::new()).await;
        };
        let before = self.journal().receipts.clone();
        let evicted = self.journal_mut().commit_receipt(&id);
        match self.apply_retiring(event, Vec::new()).await {
            Ok(effects) => {
                self.evidence.admit_committed([&id]);
                if let Some(evicted) = evicted {
                    self.evidence.forget_committed(&evicted);
                }
                Ok(effects)
            }
            Err(error) => {
                self.journal_mut().receipts = before;
                Err(error)
            }
        }
    }
    async fn apply_retiring(
        &mut self,
        event: Event,
        retire: Vec<String>,
    ) -> Result<Vec<Effect>, DriverError> {
        // An over-long tail moves to the conversation table with this commit, or not at all.
        let archival = match &mut self.journal {
            Some(journal) => journal.conversation.archive()?,
            None => None,
        };
        let result = self.commit_event(event, retire, archival.as_ref()).await;
        if let (Err(_), Some(archival)) = (&result, &archival) {
            self.journal_mut().conversation.unarchive(archival);
        }
        result
    }
    async fn commit_event(
        &mut self,
        event: Event,
        retire: Vec<String>,
        archival: Option<&conversation::Archival>,
    ) -> Result<Vec<Effect>, DriverError> {
        let effects = if let Some(journal) = &self.journal {
            core::on_event_with_checkpoint(&mut self.state, event, serde_json::to_value(journal)?)?
        } else {
            on_event(&mut self.state, event)?
        };
        if let [Effect::Persist(commit)] = effects.as_slice() {
            let appends = archival.map(|a| a.appends.clone()).unwrap_or_default();
            match self.storage.commit(*commit.clone(), retire, appends).await {
                Ok(id) => Ok(on_event(&mut self.state, Event::Committed(id))?),
                Err(error) => {
                    on_event(&mut self.state, Event::CommitFailed(commit.id.clone()))?;
                    Err(error)
                }
            }
        } else {
            debug_assert!(archival.is_none(), "an archival needs a commit");
            Ok(effects)
        }
    }
    async fn save(&mut self) -> Result<(), DriverError> {
        // The checkpoint commit carries the serialized journal; this payload is replaced.
        self.apply(Event::Checkpoint(serde_json::Value::Null))
            .await?;
        Ok(())
    }
    async fn admit(&mut self, id: String, input: Input) -> Result<Submission, DriverError> {
        let submission = self.storage.admit(id, serde_json::to_value(input)?).await?;
        if !self.inbox.iter().any(|s| s.sequence == submission.sequence) {
            self.inbox.push(submission.clone());
        }
        Ok(submission)
    }
    fn time(&mut self) -> u64 {
        let now = observed_time(
            now_ms(),
            self.journal()
                .observed_ms
                .max(self.state.committed().observed_ms()),
            self.clock_epoch_ms,
            self.clock_start
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        self.journal_mut().observed_ms = now;
        now
    }
    async fn begin(
        &mut self,
        request: &str,
        text: Option<&str>,
        system: &str,
        limits: Limits,
        runtime: String,
    ) -> Result<Option<Report>, DriverError> {
        if limits.turns == 0
            || limits.timeout_ms == 0
            || limits.tool_timeout_ms == 0
            || limits.model_attempts == 0
            || limits.model_attempts > 10
        {
            return Err(DriverError::Refused(
                "invalid durable submission limits".into(),
            ));
        }
        if self.journal.is_none() {
            self.journal = Some(Journal {
                version: 2,
                compatibility: self.compatibility.clone(),
                runtime: runtime.clone(),
                conversation: conversation::StoredConversation::new(system.into()),
                next_operation: 1,
                next_wake_generation: 1,
                observed_ms: now_ms(),
                active: None,
                finished: BTreeMap::new(),
                receipts: Default::default(),
            });
        }
        if self.journal().conversation.system != system || self.journal().runtime != runtime {
            return Err(DriverError::Incompatible);
        }
        if self
            .journal()
            .active
            .as_ref()
            .is_some_and(|a| a.request_id != request)
        {
            return Err(DriverError::Refused(
                "resume the unfinished submission before admitting another".into(),
            ));
        }
        let admitted = if let Some(existing) = self.inbox.iter().find(|s| s.request_id == request) {
            let Input::Submission { text: saved, .. } =
                serde_json::from_value(existing.input.clone())?
            else {
                return Err(DriverError::Refused(
                    "request ID belongs to a control input".into(),
                ));
            };
            if text.is_some_and(|text| text != saved) {
                return Err(core::store::StoreError::Conflict.into());
            }
            existing.clone()
        } else {
            let text =
                text.ok_or_else(|| DriverError::Refused("resume request not found".into()))?;
            self.prune().await?;
            let bytes = self.journal().conversation.total_bytes()?;
            if bytes >= self.retention.conversation_bytes {
                return Err(DriverError::Refused(format!(
                    "this session's conversation is full ({} of {} MiB); it takes no new \
                     submissions, so continue in a new session",
                    bytes / (1024 * 1024),
                    self.retention.conversation_bytes / (1024 * 1024)
                )));
            }
            let started_ms = self.time();
            self.admit(
                request.into(),
                Input::Submission {
                    text: text.into(),
                    limits,
                    started_ms,
                },
            )
            .await?
        };
        if let Some(report) = self.journal().finished.get(request) {
            return Ok(Some(report.clone()));
        }
        if self.journal().active.is_none() {
            let Input::Submission {
                text,
                limits,
                started_ms,
            } = serde_json::from_value(admitted.input)?
            else {
                unreachable!()
            };
            let deadline_ms = started_ms
                .checked_add(limits.timeout_ms)
                .ok_or(core::Error::Limit)?;
            self.journal_mut().conversation.push(Message::User { text });
            self.journal_mut().active = Some(Active {
                request_id: request.into(),
                limits,
                started_ms,
                deadline_ms,
                turns: vec![],
                usage: None,
                model_calls: 0,
                step: Step::Model {
                    operation: None,
                    chunks: vec![],
                },
                consumed_inputs: admitted.sequence,
                cancelling: false,
                timed_out: false,
                budget: Budget::default(),
                wake: None,
            });
            self.save().await?;
        }
        *self.current.lock().expect("current submission") = Some(request.into());
        Ok(None)
    }
    async fn control(
        &mut self,
        control: Control,
        output: &dyn ReplOutput,
    ) -> Result<(), DriverError> {
        let parent = match &control.input {
            Input::Steering { parent, .. } | Input::Cancel { parent } => parent,
            _ => unreachable!(),
        };
        if parent != &self.active().request_id {
            output.error("input was not admitted: its submission already ended");
            return Ok(());
        }
        let cancel = matches!(control.input, Input::Cancel { .. });
        let admitted = self.admit(control.id, control.input).await?;
        output.steering(&format!("admitted input {}", admitted.request_id));
        if cancel {
            self.cancel_intent().await?;
        }
        Ok(())
    }
    async fn cancel_intent(&mut self) -> Result<(), DriverError> {
        self.active_mut().cancelling = true;
        self.active_mut().budget.interrupt();
        self.active_mut().wake = None;
        self.save().await?;
        if let Some(id) = self.active().step.operation() {
            if self.state.committed().operation(id).is_some() {
                // A stop the deadline forced is recorded as one, not as an operator cancel.
                let event = if self.active().timed_out {
                    Event::Expire { id }
                } else {
                    Event::Cancel { id }
                };
                self.apply(event).await?;
            }
        }
        Ok(())
    }
    async fn sync_inputs(
        &mut self,
        output: &dyn ReplOutput,
        inject: bool,
    ) -> Result<(), DriverError> {
        self.consume_inputs(output, inject).await?;
        self.check_stopping().await
    }
    async fn consume_inputs(
        &mut self,
        output: &dyn ReplOutput,
        inject: bool,
    ) -> Result<(), DriverError> {
        while let Ok(control) = self.controls.try_recv() {
            self.control(control, output).await?;
        }
        let parent = self.active().request_id.clone();
        let entries: Vec<_> = self
            .inbox
            .iter()
            .filter(|s| s.sequence > self.active().consumed_inputs)
            .cloned()
            .collect();
        for entry in entries {
            match serde_json::from_value::<Input>(entry.input)? {
                Input::Cancel { parent: p } if p == parent => {
                    self.cancel_intent().await?;
                }
                Input::Steering { parent: p, text } if p == parent && inject => {
                    self.journal_mut().conversation.push(Message::User { text });
                    self.active_mut().consumed_inputs = entry.sequence;
                    self.save().await?;
                }
                _ => {}
            }
        }
        Ok(())
    }
    async fn check_stopping(&mut self) -> Result<(), DriverError> {
        let committed_result = self
            .active()
            .step
            .operation()
            .and_then(|id| self.state.committed().operation(id))
            .is_some_and(|op| {
                matches!(op.phase, Phase::Publishing { .. } | Phase::Completed { .. })
            });
        let completed_response = match &self.active().step {
            Step::Tools {
                model_operation,
                operation: None,
                ..
            } => {
                let op = self
                    .state
                    .committed()
                    .operation(*model_operation)
                    .ok_or(core::Error::InvalidSnapshot)?;
                if let Phase::Completed { result, .. } = &op.phase {
                    serde_json::from_value::<Turn>(result.output.clone())?
                        .tool_calls
                        .is_empty()
                        || self
                            .active()
                            .turns
                            .last()
                            .and_then(|t| t.calls.last())
                            .is_some_and(|c| c.result.terminal)
                } else {
                    false
                }
            }
            _ => false,
        };
        if !committed_result && !completed_response {
            if self.active().timed_out {
                return Err(DriverError::Expired);
            }
            if self.active().cancelling {
                return Err(DriverError::Cancelled);
            }
            if self.time() >= self.active().deadline_ms {
                self.active_mut().timed_out = true;
                self.cancel_intent().await?;
                return Err(DriverError::Expired);
            }
        }
        Ok(())
    }
    async fn wait<T>(
        &mut self,
        future: impl std::future::Future<Output = T>,
        deadline: u64,
        output: &dyn ReplOutput,
    ) -> Result<T, DriverError> {
        let remaining = deadline.saturating_sub(self.time());
        if remaining == 0 {
            self.active_mut().timed_out = true;
            self.cancel_intent().await?;
            return Err(DriverError::Expired);
        }
        let timer = tokio::time::sleep(Duration::from_millis(remaining));
        tokio::pin!(timer);
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                control = self.controls.recv() => if let Some(control) = control {
                    self.control(control, output).await?;
                    if self.active().cancelling { return Err(DriverError::Cancelled); }
                },
                _ = &mut timer => {
                    let remaining = deadline.saturating_sub(self.time());
                    if remaining != 0 {
                        timer.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(remaining));
                        continue;
                    }
                    self.active_mut().timed_out = true;
                    self.cancel_intent().await?;
                    return Err(DriverError::Expired);
                }
                result = &mut future => return Ok(result),
            }
        }
    }
    async fn operation(
        &mut self,
        spec: OperationSpec,
        model: bool,
        sandbox: &Sandbox,
    ) -> Result<OperationId, DriverError> {
        let id = match self.active().step.operation() {
            Some(id) => id,
            None => {
                let id = OperationId(self.journal().next_operation);
                self.journal_mut().next_operation =
                    id.0.checked_add(1).ok_or(core::Error::Limit)?;
                match &mut self.active_mut().step {
                    Step::Model { operation, .. } => *operation = Some(id),
                    Step::Tools {
                        operation,
                        executor,
                        ..
                    } => {
                        *operation = Some(id);
                        *executor = executor::Executor::capture(sandbox)?;
                    }
                }
                id
            }
        };
        if self.state.committed().operation(id).is_none() {
            self.apply(Event::Submit { id, spec }).await?;
        }
        let phase = self.state.committed().operation(id).unwrap().phase.clone();
        if let Phase::Recovering { attempt } = phase {
            let stopped = if model {
                true
            } else {
                match &self.active().step {
                    Step::Tools {
                        executor: Some(executor),
                        ..
                    } => executor.stop().await.unwrap_or(false),
                    _ => false,
                }
            };
            let now_ms = self.time();
            self.apply(Event::Recovered {
                token: RecoveryToken {
                    activation: self.state.activation(),
                    attempt,
                },
                outcome: if stopped {
                    RecoveryOutcome::Quiescent
                } else {
                    RecoveryOutcome::Unknown
                },
                now_ms,
            })
            .await?;
        }
        match self.state.committed().operation(id).unwrap().phase {
            Phase::Cancelling { reason, .. } | Phase::Stopped { reason, .. } => {
                return Err(match reason {
                    core::StopReason::Deadline => DriverError::Expired,
                    core::StopReason::Cancelled => DriverError::Cancelled,
                });
            }
            Phase::Unresolved { .. } | Phase::Recovering { .. } => {
                return Err(DriverError::Unresolved(id.0))
            }
            _ => {}
        }
        Ok(id)
    }
    async fn authorize(&mut self, id: OperationId) -> Result<Attempt, DriverError> {
        let now = self.time();
        let operation = self
            .state
            .committed()
            .operation(id)
            .ok_or(core::Error::NotFound)?;
        if now < operation.spec.deadline_ms {
            let kind = operation.spec.kind;
            let limit = if kind == WorkKind::Model {
                self.active().limits.turns
            } else {
                self.active().limits.tool_calls
            };
            if self.active().budget.charged(kind) >= limit {
                return Err(DriverError::BudgetExhausted);
            }
            let attempt = Attempt {
                session: self.state.committed().session().clone(),
                activation: self.state.activation(),
                operation: id,
                number: operation
                    .attempts
                    .checked_add(1)
                    .ok_or(core::Error::Limit)?,
            };
            self.active_mut().budget.reserve(attempt, kind, limit)?;
            self.active_mut().model_calls = self.active().budget.charged(WorkKind::Model);
            self.active_mut().wake = None;
        }
        self.apply(Event::Authorize { id, now_ms: now }).await?;
        match &self.state.committed().operation(id).unwrap().phase {
            Phase::Running { attempt } => Ok(attempt.clone()),
            _ => Err(DriverError::Expired),
        }
    }
    async fn finish(
        &mut self,
        status: EpisodeStatus,
        output: &dyn ReplOutput,
    ) -> Result<Report, DriverError> {
        let ended_ms = self.time();
        // Admitted steering is acknowledged, so an ending that leaves it unread (a terminal tool,
        // cancellation, a deadline) says so rather than dropping it silently.
        let request = self.active().request_id.clone();
        for entry in self
            .inbox
            .iter()
            .filter(|s| s.sequence > self.active().consumed_inputs)
        {
            if let Ok(Input::Steering { parent, .. }) = serde_json::from_value(entry.input.clone())
            {
                if parent == request {
                    output.error(&format!(
                        "input {} was admitted but the submission ended before using it; submit it again",
                        entry.request_id
                    ));
                }
            }
        }
        if self.active().cancelling {
            if let Step::Tools {
                model_operation,
                next,
                ..
            } = self.active().step.clone()
            {
                if let Some(Operation {
                    phase: Phase::Completed { result, .. },
                    ..
                }) = self.state.committed().operation(model_operation)
                {
                    let turn: Turn = serde_json::from_value(result.output.clone())?;
                    for call in turn.tool_calls.into_iter().skip(next) {
                        let result = ToolResult::error("submission stopped; no committed tool result is available and its external outcome may be unknown");
                        self.journal_mut().conversation.push(Message::ToolResult {
                            provenance: result.provenance.clone(),
                            call_id: call.id.clone(),
                            name: call.name.clone(),
                            content: result.content.clone(),
                            is_error: true,
                        });
                        if let Some(turn) = self.active_mut().turns.last_mut() {
                            turn.calls.push(RecordedCall {
                                proxy_events: vec![],
                                denied_attempt_audit: vec![],
                                denied_attempt_proxy_events: vec![],
                                escalations: vec![],
                                retried: false,
                                timed_out: false,
                                not_run: false,
                                refused_by_hook: None,
                                call,
                                result,
                                audit: vec![],
                            });
                        }
                    }
                }
            }
        }
        let active = self.active().clone();
        let report = Report {
            request_id: active.request_id.clone(),
            status,
            turns: active.turns,
            usage: active.usage,
            started_ms: active.started_ms,
            ended_ms,
            model_calls: active.model_calls,
            budget: active.budget,
        };
        self.journal_mut()
            .finished
            .insert(active.request_id, report.clone());
        self.journal_mut().active = None;
        self.save().await?;
        Ok(report)
    }
    async fn cleanup_cancelled(&mut self, sandbox: &Sandbox) -> Result<(), DriverError> {
        let Some(id) = self.active().step.operation() else {
            return Ok(());
        };
        let Some(operation) = self.state.committed().operation(id) else {
            return Ok(());
        };
        let Phase::Cancelling { attempt, .. } = &operation.phase else {
            return Ok(());
        };
        let attempt = attempt.clone();
        let resumed_here = matches!(&self.active().step, Step::Tools { executor_activation: Some(activation), .. } if activation == &self.state.activation().0.to_string());
        if attempt.activation != self.state.activation() && !resumed_here {
            let stopped = match &self.active().step {
                Step::Model { .. } => true,
                Step::Tools {
                    executor: Some(executor),
                    ..
                } => executor.stop().await.unwrap_or(false),
                _ => false,
            };
            if !stopped {
                return Err(DriverError::Unresolved(id.0));
            }
        }
        sandbox.check_cleanup().map_err(DriverError::Refused)?;
        self.apply(Event::Cleaned {
            token: RecoveryToken {
                activation: self.state.activation(),
                attempt,
            },
        })
        .await?;
        Ok(())
    }
}

fn observed_time(wall_ms: u64, previous_ms: u64, epoch_ms: u64, elapsed_ms: u64) -> u64 {
    wall_ms
        .max(previous_ms)
        .max(epoch_ms.saturating_add(elapsed_ms))
}

#[cfg(test)]
mod clock_tests {
    use super::observed_time;

    #[test]
    fn clock_rollback_and_reactivation_do_not_restore_remaining_time() {
        let mut observed = 100;
        let mut remaining = 100;
        for (wall, elapsed) in [(110, 10), (40, 20), (20, 30), (150, 35), (0, 60)] {
            observed = observed_time(wall, observed, 100, elapsed);
            let next = 200u64.saturating_sub(observed);
            assert!(next <= remaining);
            assert!(observed >= 100 + elapsed);
            remaining = next;
        }
        let reopened_epoch = observed;
        assert_eq!(observed_time(0, observed, reopened_epoch, 0), observed);
        assert_eq!(observed_time(0, observed, reopened_epoch, 5), observed + 5);
        assert_eq!(observed_time(0, 0, u64::MAX - 1, 2), u64::MAX);
    }
}
