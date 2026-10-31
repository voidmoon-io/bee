//! Async ring-buffer audit consumer (US4, `tokio` feature). Wraps the `AUDIT_RB` file descriptor in
//! tokio's reactor so many episodes can await audit readiness without a thread-per-episode `poll()`
//! (FR-012). Strictly additive to the sync [`crate::events::AuditReader`], which is unchanged.

#![cfg(feature = "tokio")]

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use aya::maps::{MapData, RingBuf};
use bee_common::AuditRecord;
use bee_core::AuditEvent;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// A newtype that exposes the ring buffer's fd to [`AsyncFd`]. The real fd is **owned** by the
/// `RingBuf` held alongside it; this only borrows the integer, so it has no `Drop` and must never
/// close the fd (that would double-close the map).
struct RingBufFd(RawFd);

impl AsRawFd for RingBufFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// An async stream over the `AUDIT_RB` ring buffer. Register readiness with [`AsyncFd`]; drain with
/// the same non-blocking `RingBuf::next()` the sync reader uses.
pub struct AsyncAuditStream {
    async_fd: AsyncFd<RingBufFd>,
    rb: RingBuf<MapData>,
    scope_id: String,
}

impl AsyncAuditStream {
    /// Wrap a ring buffer for async consumption. Registers the fd with tokio's reactor for read
    /// readiness.
    pub fn new(rb: RingBuf<MapData>, scope_id: String) -> io::Result<Self> {
        let raw = rb.as_raw_fd();
        // SAFETY: rb owns this fixed fd and is never replaced. async_fd is declared before rb,
        // so its registration is dropped before the ring buffer closes the fd.
        let async_fd =
            unsafe { AsyncFd::register_with_interest(RingBufFd(raw), Interest::READABLE)? };
        Ok(AsyncAuditStream {
            async_fd,
            rb,
            scope_id,
        })
    }

    /// Wait until the ring has data, then return a bounded batch of events. A
    /// spurious readiness wake (no records yet) loops rather than returning an empty batch.
    pub async fn next_batch(&mut self) -> io::Result<Vec<AuditEvent>> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            // `self.rb` and `self.scope_id` are disjoint from `self.async_fd`, so draining here does
            // not conflict with the readiness guard borrowing `async_fd`.
            let (events, exhausted) = drain_into(&mut self.rb, &self.scope_id);
            if exhausted {
                guard.clear_ready();
            }
            if !events.is_empty() {
                return Ok(events);
            }
        }
    }

    /// The scope id these events are tagged with.
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
}

/// Drain at most 256 records from `rb` into a `Vec` (non-blocking). Same record decode
/// as [`crate::events::AuditReader::drain`], collected instead of dispatched via a sink.
fn drain_into(rb: &mut RingBuf<MapData>, scope_id: &str) -> (Vec<AuditEvent>, bool) {
    let mut out = Vec::new();
    for _ in 0..256 {
        let Some(item) = rb.next() else {
            return (out, true);
        };
        if item.len() >= core::mem::size_of::<AuditRecord>() {
            // SAFETY: the ring holds a full AuditRecord written by the eBPF side.
            let rec = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const AuditRecord) };
            out.push(AuditEvent::from_record(
                &rec,
                Some(scope_id.to_string()),
                time::OffsetDateTime::now_utc(),
            ));
        }
    }
    (out, false)
}
