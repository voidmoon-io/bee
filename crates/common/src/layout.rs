//! `#[repr(C)]` map layouts shared verbatim between `bee-ebpf` and `bee-userspace`.
//!
//! Every struct here is a Plain-Old-Data value with a fixed size. Layouts MUST be identical on
//! both sides of the kernel boundary. When the `aya` feature is enabled (user-space), each type
//! also gets `unsafe impl aya::Pod`, which is required to use it as a BPF map key/value.

use crate::TARGET_MAX;

/// Per-scope metadata keyed by cgroup id in the `SCOPES` map. Presence of a key means the cgroup
/// is bee-managed; absence means "not ours — do not enforce".
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeMeta {
    /// `ScopeMode` as `u8` (0 = enforce, 1 = observe).
    pub mode: u8,
    /// Reserved flags (e.g. exfil-sensitive-read latch, post-MVP).
    pub flags: u8,
    pub _pad: [u8; 6],
}

/// Max bytes of a file rule pattern compared in-kernel.
pub const DENY_PREFIX_MAX: usize = 128;
/// Max file rules carried per scope. Grants (`read`/`write`) now share this list with denies, so the
/// cap must cover the four always-injected protected defaults (FR-008) plus explicit rules. Kept at 8
/// because `file_open` scans every rule (128-byte compare each) on each open: at 8 rules the single
/// pass fits the verifier's 1M-instruction budget with margin; 16 blows it. A full LPM trie
/// (constant-time lookup, no per-rule scan) is the path to a higher cap — see research R6.
pub const DENY_MAX_RULES: usize = 8;

// Filesystem rule kinds installed by the current eBPF backend.
pub const FS_KIND_SUBTREE: u8 = 0; // exact path or directory subtree (prefix + boundary)
pub const FS_KIND_POSTFIX: u8 = 1; // path ends with `bytes` (from `*.ext`)

/// A single file rule (matched against a resolved path by `kind`), consulted by `file_open`.
///
/// Despite the historical name, this now carries `read`/`write` grants as well as denies: `mode`
/// holds the `AccessMode` bits so `file_open` can enforce read-only subtrees (block write-opens of a
/// `read`-marked path) and grant writes where a `write` rule applies. `mode` is ignored for the
/// executable allowlist (`EXEC_ALLOW`), which is pure membership.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenyRule {
    /// One of `FS_KIND_*`.
    pub kind: u8,
    /// `AccessMode` bits for this rule (`READ`/`WRITE`/`DENY`). Unused for `EXEC_ALLOW`.
    pub mode: u8,
    /// Number of valid bytes in `bytes`.
    pub len: u16,
    /// The kernel's `s_dev` for a pinned rule. Meaningless when `ino == 0`.
    pub dev: u32,
    /// The pinned inode number, or **0 for an unpinned rule** — no real file has inode 0, so the
    /// sentinel costs no expressiveness and keeps the hot path a single comparison (017 FR-002).
    ///
    /// A pinned rule is matched on `(ino, dev)` alone: `bytes` is retained for the audit line and
    /// for the diagnostics an operator reads, but it does **not** participate in the decision. That
    /// is the point — the grant was made to a file, not to a name, and a name can be re-pointed
    /// between the grant and the exec.
    pub ino: u64,
    pub bytes: [u8; DENY_PREFIX_MAX],
}

impl DenyRule {
    pub const EMPTY: DenyRule = DenyRule {
        kind: 0,
        mode: 0,
        len: 0,
        dev: 0,
        ino: 0,
        bytes: [0; DENY_PREFIX_MAX],
    };

    /// Whether this rule is decided by identity rather than by path.
    pub const fn is_pinned(&self) -> bool {
        self.ino != 0
    }
}

/// The set of file rules for one scope, stored in `FS_DENY` keyed by cgroup id.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenyList {
    /// Number of valid entries in `rules` (≤ `DENY_MAX_RULES`).
    pub count: u32,
    pub _pad: [u8; 4],
    pub rules: [DenyRule; DENY_MAX_RULES],
}

impl DenyList {
    pub const EMPTY: DenyList = DenyList {
        count: 0,
        _pad: [0; 4],
        rules: [DenyRule::EMPTY; DENY_MAX_RULES],
    };
}

/// Key for the network egress allowlist (`NET_ALLOW`). `addr` holds 4 bytes (v4) or 16 (v6).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetKey {
    pub cgroup_id: u64,
    /// AF_INET (2) or AF_INET6 (10).
    pub family: u16,
    /// Destination port in host byte order.
    pub port: u16,
    pub _pad: [u8; 4],
    pub addr: [u8; 16],
}

/// Audit record emitted from an LSM hook to the `AUDIT_RB` ring buffer. Fixed size for the ring.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuditRecord {
    /// Kernel monotonic time (`bpf_ktime_get_ns`).
    pub ts_ns: u64,
    pub cgroup_id: u64,
    /// Immediate child of the policy scope, or the scope itself for direct children.
    pub executor_cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    /// `Op` as `u8`.
    pub op: u8,
    /// `Decision` as `u8`.
    pub decision: u8,
    pub _pad: [u8; 2],
    /// Negated errno returned on deny (e.g. -13). 0 in observe mode.
    pub errno: i32,
    /// Number of valid bytes in `target`.
    pub target_len: u16,
    pub _pad2: [u8; 6],
    /// Resolved path or "addr:port", truncated to `TARGET_MAX`.
    pub target: [u8; TARGET_MAX],
}

// User-space only: mark the layouts as BPF-usable POD.
#[cfg(feature = "aya")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for ScopeMeta {}
    unsafe impl aya::Pod for DenyRule {}
    unsafe impl aya::Pod for DenyList {}
    unsafe impl aya::Pod for NetKey {}
    unsafe impl aya::Pod for AuditRecord {}
}
