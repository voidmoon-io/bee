//! Ring-buffer audit consumer (enforce feature only). Exposes a synchronous, blocking reader — no
//! async runtime (NFR-005, research R9).

#![cfg(feature = "enforce")]

use std::io;
use std::os::fd::AsRawFd;

use aya::maps::{MapData, RingBuf};
use bee_common::AuditRecord;
use bee_core::AuditEvent;

/// Synchronous reader over the `AUDIT_RB` ring buffer.
pub struct AuditReader {
    rb: RingBuf<MapData>,
    scope_id: String,
}

impl AuditReader {
    pub fn new(rb: RingBuf<MapData>, scope_id: String) -> Self {
        AuditReader { rb, scope_id }
    }

    /// Drain at most 4096 records. Returns true only after observing an empty ring.
    pub fn drain(&mut self, sink: &mut dyn FnMut(AuditEvent)) -> bool {
        for _ in 0..4096 {
            let Some(item) = self.rb.next() else {
                return true;
            };
            if item.len() >= core::mem::size_of::<AuditRecord>() {
                // SAFETY: the ring holds a full AuditRecord written by the eBPF side.
                let rec = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const AuditRecord) };
                let ev = AuditEvent::from_record(
                    &rec,
                    Some(self.scope_id.clone()),
                    time::OffsetDateTime::now_utc(),
                );
                sink(ev);
            }
        }
        false
    }

    /// Block up to `timeout_ms` (or indefinitely if negative) for the ring to become readable.
    pub fn poll(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.rb.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(rc > 0)
    }
}
