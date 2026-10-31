//! One blocking owner for SQLite. Dropping an awaiting request cannot cancel a commit;
//! its caller must reopen before trusting an uncertain acknowledgement.
use super::DriverError;
use crate::session::durable::{store::journal::WorkerRecord, Attempt};
use crate::session::durable::{
    store::{Store, Submission},
    ActivationId, Commit, CommitId, SessionId, Snapshot,
};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

pub(super) struct Storage {
    tx: Option<mpsc::Sender<Request>>,
    owner: Option<std::thread::JoinHandle<()>>,
}
pub(super) enum Request {
    Commit(Box<Commit>, oneshot::Sender<Result<CommitId, DriverError>>),
    Admit(
        String,
        serde_json::Value,
        oneshot::Sender<Result<Submission, DriverError>>,
    ),
    WorkerLoad(
        Attempt,
        oneshot::Sender<Result<Option<WorkerRecord>, DriverError>>,
    ),
    WorkerWrite(Box<WorkerRecord>, oneshot::Sender<Result<(), DriverError>>),
}
impl Storage {
    pub async fn open(
        path: PathBuf,
        session: SessionId,
        observer: Option<std::sync::Arc<dyn super::Observer>>,
    ) -> Result<(Self, Snapshot, ActivationId, Vec<Submission>), DriverError> {
        let (tx, mut rx) = mpsc::channel(16);
        let (opened, ready) = oneshot::channel();
        let owner = std::thread::Builder::new()
            .name("bee-session-store".into())
            .spawn(move || {
                let prepared = (|| {
                    let mut store = Store::open(&path, session)?;
                    let snapshot = store.load()?;
                    let mut inbox = Vec::new();
                    loop {
                        let after = inbox.last().map_or(0, |s: &Submission| s.sequence);
                        let page = store.submissions(after, 100)?;
                        if page.is_empty() {
                            break;
                        }
                        inbox.extend(page);
                    }
                    Ok::<_, DriverError>((store, snapshot, inbox))
                })();
                let (mut store, snapshot, inbox) = match prepared {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = opened.send(Err(error));
                        return;
                    }
                };
                if opened
                    .send(Ok((snapshot, store.activation(), inbox)))
                    .is_err()
                {
                    return;
                }
                while let Some(request) = rx.blocking_recv() {
                    match request {
                        Request::Commit(commit, reply) => {
                            if let Some(observer) = &observer {
                                observer.before_commit(&commit);
                            }
                            let result = store.commit(&commit).map_err(Into::into);
                            if result.is_ok() {
                                if let Some(observer) = &observer {
                                    observer.committed(&commit);
                                }
                            }
                            let _ = reply.send(result);
                        }
                        Request::Admit(id, input, reply) => {
                            let _ = reply.send(store.admit(&id, &input).map_err(Into::into));
                        }
                        Request::WorkerLoad(attempt, reply) => {
                            let _ = reply.send(store.worker_load(&attempt).map_err(Into::into));
                        }
                        Request::WorkerWrite(record, reply) => {
                            let result = store.worker_write(&record).map_err(Into::into);
                            if result.is_ok() {
                                if let Some(observer) = &observer {
                                    observer.worker_committed(&record);
                                }
                            }
                            let _ = reply.send(result);
                        }
                    }
                }
            })?;
        let (snapshot, activation, inbox) =
            ready.await.map_err(|_| DriverError::StorageClosed)??;
        Ok((
            Self {
                tx: Some(tx),
                owner: Some(owner),
            },
            snapshot,
            activation,
            inbox,
        ))
    }
    pub async fn commit(&self, commit: Commit) -> Result<CommitId, DriverError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .as_ref()
            .expect("live storage")
            .send(Request::Commit(Box::new(commit), tx))
            .await
            .map_err(|_| DriverError::StorageClosed)?;
        rx.await.map_err(|_| DriverError::StorageClosed)?
    }
    pub(super) async fn worker(
        &self,
        attempt: Attempt,
        spec: crate::session::durable::OperationSpec,
    ) -> Result<super::journal::Journal, DriverError> {
        let sender = self.tx.as_ref().expect("live storage");
        let (tx, rx) = oneshot::channel();
        sender
            .send(Request::WorkerLoad(attempt.clone(), tx))
            .await
            .map_err(|_| DriverError::StorageClosed)?;
        let loaded = rx.await.map_err(|_| DriverError::StorageClosed)??;
        super::journal::Journal::open(sender.downgrade(), attempt, spec, loaded).await
    }
    pub async fn admit(
        &self,
        id: String,
        value: serde_json::Value,
    ) -> Result<Submission, DriverError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .as_ref()
            .expect("live storage")
            .send(Request::Admit(id, value, tx))
            .await
            .map_err(|_| DriverError::StorageClosed)?;
        rx.await.map_err(|_| DriverError::StorageClosed)?
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}
