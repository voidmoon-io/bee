//! Audit demultiplexer (US4, `tokio` feature). The kernel has **one** `AUDIT_RB` ring for all
//! scopes; concurrent episodes each need to see only their own events. The demux owns the single
//! [`AsyncAuditStream`], reads it in a background task, and routes each event to a per-`cgroup_id`
//! subscriber channel. Events for an unsubscribed cgroup are dropped. This routing — not the raw
//! async I/O — is the substance of US4 (research H5).

#![cfg(feature = "tokio")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const QUEUE_CAPACITY: usize = 1024;

struct Subscriber {
    tx: mpsc::Sender<AuditEvent>,
    dropped: Arc<AtomicU64>,
}

fn channel() -> (Subscriber, mpsc::Receiver<AuditEvent>) {
    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    (
        Subscriber {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        },
        rx,
    )
}

use bee_core::AuditEvent;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::async_events::AsyncAuditStream;

/// Shared subscriber table: `cgroup_id → sender`. `std::sync::RwLock` (not tokio's) so `subscribe`/
/// `unsubscribe` stay non-async; the dispatch task only ever holds the read guard across the
/// synchronous fan-out of one batch (never across an `.await`).
type SubMap = Arc<RwLock<HashMap<u64, Subscriber>>>;

/// One episode's view of the audit stream: only events for its scope's `cgroup_id`.
pub struct AuditSubscription {
    pub rx: mpsc::Receiver<AuditEvent>,
    pub dropped: Arc<AtomicU64>,
    pub stream_failed: Arc<AtomicBool>,
}

/// Routes the single audit stream to per-scope subscribers by `cgroup_id`.
pub struct AuditDemux {
    subs: SubMap,
    failed: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl AuditDemux {
    /// Start the demux task, taking ownership of the stream.
    pub fn start(stream: AsyncAuditStream) -> Self {
        let subs: SubMap = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task_subs = subs.clone();
        let failed = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(dispatch_loop(
            stream,
            task_subs,
            shutdown_rx,
            failed.clone(),
        ));
        AuditDemux {
            subs,
            failed,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        }
    }

    /// Subscribe to events for a `cgroup_id`. Call **before** starting the episode so no early
    /// events are missed. A second subscribe for the same cgroup replaces the first.
    pub fn subscribe(&self, cgroup_id: u64) -> AuditSubscription {
        let (tx, rx) = channel();
        let dropped = tx.dropped.clone();
        self.subs
            .write()
            .expect("demux subs lock poisoned")
            .insert(cgroup_id, tx);
        AuditSubscription {
            rx,
            dropped,
            stream_failed: self.failed.clone(),
        }
    }

    /// Stop routing events for `cgroup_id` (drops the sender; later events are discarded).
    pub fn unsubscribe(&self, cgroup_id: u64) {
        self.subs
            .write()
            .expect("demux subs lock poisoned")
            .remove(&cgroup_id);
    }

    /// Shut the demux task down cleanly and wait for it to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for AuditDemux {
    fn drop(&mut self) {
        // Safety net if `shutdown()` was not called: signal, then abort so the task and its fd do
        // not leak. (When `shutdown()` ran, both fields are already `None`.)
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            self.failed.store(true, Ordering::Relaxed);
            h.abort();
        }
    }
}

/// The background dispatch loop: drain batches from the stream and fan each out to subscribers until
/// shutdown is signalled or the stream errors.
async fn dispatch_loop(
    mut stream: AsyncAuditStream,
    subs: SubMap,
    mut shutdown: oneshot::Receiver<()>,
    failed: Arc<AtomicBool>,
) {
    loop {
        tokio::select! {
            batch = stream.next_batch() => match batch {
                Ok(events) => dispatch_batch(&subs, events),
                Err(_) => { failed.store(true, Ordering::Relaxed); break; }
            },
            _ = &mut shutdown => break,
        }
    }
}

/// Fan one batch out to subscribers, keyed by each event's `cgroup_id`. Events with no subscriber
/// are dropped. Holds the read guard only across this synchronous loop (no `.await` inside).
fn dispatch_batch(subs: &SubMap, events: Vec<AuditEvent>) {
    let map = subs.read().expect("demux subs lock poisoned");
    for ev in events {
        if let Some(tx) = map.get(&ev.cgroup_id) {
            // Receiver dropped ⇒ send fails ⇒ drop the event. Not our problem to retry.
            if let Err(mpsc::error::TrySendError::Full(_)) = tx.tx.try_send(ev) {
                tx.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_is_visible_and_does_not_block_other_scopes() {
        let subs: SubMap = Arc::new(RwLock::new(HashMap::new()));
        let (slow, _slow_rx) = channel();
        let dropped = slow.dropped.clone();
        let (healthy, mut healthy_rx) = channel();
        subs.write().unwrap().insert(1, slow);
        subs.write().unwrap().insert(2, healthy);
        for _ in 0..QUEUE_CAPACITY + 7 {
            dispatch_batch(&subs, vec![event(1, "/noisy")]);
        }
        dispatch_batch(&subs, vec![event(2, "/healthy")]);
        assert_eq!(dropped.load(Ordering::Relaxed), 7);
        assert_eq!(healthy_rx.try_recv().unwrap().target, "/healthy");
    }

    fn event(cgroup_id: u64, target: &str) -> AuditEvent {
        AuditEvent {
            ts: "1970-01-01T00:00:00Z".into(),
            scope_id: None,
            cgroup_id,
            pid: None,
            tgid: None,
            op: "file_open".into(),
            decision: "denied".into(),
            errno: 13,
            target: target.into(),
        }
    }

    #[test]
    fn demux_routes_by_cgroup_id() {
        let subs: SubMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx1, mut rx1) = channel();
        let (tx2, mut rx2) = channel();
        subs.write().unwrap().insert(1, tx1);
        subs.write().unwrap().insert(2, tx2);

        dispatch_batch(
            &subs,
            vec![
                event(1, "/a"),
                event(2, "/b"),
                event(1, "/c"),
                event(2, "/d"),
            ],
        );

        // Subscriber 1 sees only its own events, in order.
        assert_eq!(rx1.try_recv().unwrap().target, "/a");
        assert_eq!(rx1.try_recv().unwrap().target, "/c");
        assert!(rx1.try_recv().is_err());
        // Subscriber 2 likewise.
        assert_eq!(rx2.try_recv().unwrap().target, "/b");
        assert_eq!(rx2.try_recv().unwrap().target, "/d");
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn demux_drops_unsubscribed() {
        let subs: SubMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx1, mut rx1) = channel();
        subs.write().unwrap().insert(1, tx1);

        // Events for cgroup 99 have no subscriber: silently dropped, no panic, subscriber 1 sees
        // only its own event.
        dispatch_batch(
            &subs,
            vec![event(99, "/x"), event(1, "/y"), event(99, "/z")],
        );

        assert_eq!(rx1.try_recv().unwrap().target, "/y");
        assert!(rx1.try_recv().is_err());
    }
}
