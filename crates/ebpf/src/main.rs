#![no_std]
#![no_main]

//! bee eBPF LSM programs.
//!
//! Programs are attached globally (`BPF_LSM_MAC`) and scope enforcement per cgroup by filtering on
//! `bpf_get_current_cgroup_id()`. Return `0` to allow, a negative errno to deny.
//!
//! Two hooks:
//! * `socket_connect` — deny outbound connections for a bee-managed cgroup (no struct reads).
//! * `file_open` — resolve the path with `bpf_d_path` and apply the per-scope rule list: deny
//!   subtrees/patterns, and enforce read-only (`read`-marked paths block write-opens) plus
//!   deny-by-default writes for scopes that declare a writable surface. The requested access is the
//!   `FMODE_WRITE` bit of `file->f_mode`, read by a direct load at a constant offset.
//!
//! **A hook that cannot evaluate an operation refuses it** ([`deny_unevaluated`]). Null arguments,
//! an unavailable scratch buffer, a `bpf_d_path` failure, and an address family the hook does not
//! decode all return the denial errno rather than `0`, and all emit an audit record. The trigger is
//! reachable by an attacker — a directory chain longer than the 4KB path buffer, a pathless memfd
//! image, an AF_UNIX destination the `host:port` policy language cannot describe — so allowing on
//! failure handed out exactly the operation the scope exists to mediate. This only applies once the
//! scope has been shown to enforce that dimension; an unenforced scope still returns `0` early.
//!
//! `bpf_d_path` needs a `*mut path`; we get it as `&file->f_path`. The `file`/`path`/`linux_binprm`
//! structs in `aya-ebpf-bindings` are opaque, so we read fields at compile-time-constant offsets (the
//! BPF verifier requires *constant* offsets into a BTF pointer, so these cannot be made
//! runtime-configurable — full kernel portability requires CO-RE relocation of these offsets).
//!
//! The offsets live in [`bee_common::offsets`] (shared source of truth) and target kernel 6.8 x86_64.
//! Because a wrong offset reads the wrong field and fails **open**, user space validates them against
//! the running kernel's BTF at startup and refuses to enforce on a mismatch (`bee-userspace::kbtf`).
//! To retarget another kernel, update `bee_common::offsets` from its BTF: `pahole -C file | grep -E
//! 'f_mode|f_path'` and `pahole -C linux_binprm | grep file`.
//!
//! NOTE on CO-RE: true auto-relocating CO-RE is not currently achievable here. `aya-tool`/bindgen
//! generate plain `#[repr(C)]` bindings with **no `preserve_access_index`**, so aya-ebpf field access
//! compiles to fixed offsets and emits no BPF_CORE_FIELD relocations — functionally identical to
//! these constants. (aya's *loader* can apply CO-RE relocations, but the probe side doesn't emit
//! them.) Porting across kernels therefore means updating these two constants until the Rust eBPF
//! toolchain gains `preserve_access_index` field-relocation support.

use core::ffi::c_void;

use aya_ebpf::{
    bindings::path,
    helpers::{
        bpf_d_path, bpf_get_current_ancestor_cgroup_id, bpf_get_current_cgroup_id,
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use bee_common::{
    layout::{DenyList, DenyRule, NetKey, ScopeMeta, FS_KIND_POSTFIX, FS_KIND_SUBTREE},
    AccessMode, AuditRecord, Decision, Op, ScopeMode, DENY_MAX_RULES, DENY_PREFIX_MAX, PATH_MAX,
    TARGET_MAX,
};

const EPERM: i32 = 1;
const EACCES: i32 = 13;

/// Kernel struct field offsets (target 6.8 x86_64), shared with user space so its startup guard can
/// validate them against the running kernel's BTF (see `bee_common::offsets` and module docs).
use bee_common::offsets::{BINPRM_FILE as BINPRM_FILE_OFF, FILE_F_INODE as FILE_F_INODE_OFF, FILE_F_MODE as FILE_F_MODE_OFF, FILE_F_PATH as FILE_F_PATH_OFF, INODE_I_INO as INODE_I_INO_OFF, INODE_I_SB as INODE_I_SB_OFF, SUPER_BLOCK_S_DEV as SUPER_BLOCK_S_DEV_OFF};

/// `FMODE_WRITE` (UAPI-stable): the open requests write access. Set for `O_WRONLY`/`O_RDWR`.
const FMODE_WRITE: u32 = 0x2;

use bee_common::{FLAG_FS_WRITE_DEFAULT_DENY, FLAG_NET_ENFORCED};

// UAPI address families (stable ABI).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Cgroups bee manages, keyed by cgroup id → mode/flags. Absence ⇒ not ours ⇒ do not enforce.
#[map]
static SCOPES: HashMap<u64, ScopeMeta> = HashMap::with_max_entries(1024, 0);

/// How many cgroup ancestor levels [`resolve_scope`] walks. A bee scope lives at
/// `/sys/fs/cgroup/bee/<id>` — three or four levels from the root — so the scope is always well
/// within this bound; the levels *below* it (the sub-cgroups a migrating process would create) do
/// not need to be reached, only the scope itself. Kept small so the walk fits the verifier budget.
const MAX_CGROUP_DEPTH: i32 = 16;

/// Resolve the bee scope governing the current task, returning its **scope** cgroup id (the map key
/// for every per-scope rule list) and metadata.
///
/// The exact current cgroup id is tried first — the common case, a tool child sitting directly in
/// its scope. If that is not a bee scope, walk the cgroup ancestors: a process that was privileged
/// enough to `mkdir` a child cgroup and migrate into it has a *different* current cgroup id, which
/// an exact-match lookup misses — and a miss means "not ours, allow", i.e. the process walks out of
/// enforcement. Checking ancestors closes that: the scope is still an ancestor of wherever it moved.
///
/// Every caller must key `FS_DENY` / `EXEC_ALLOW` / `NET_ALLOW` and audit records off the returned
/// scope id, not `bpf_get_current_cgroup_id()`, or a migrated task's rules would not be found.
fn resolve_scope() -> Option<(u64, ScopeMeta)> {
    let cur = unsafe { bpf_get_current_cgroup_id() };
    if let Some(meta) = unsafe { SCOPES.get(&cur) } {
        return Some((cur, *meta));
    }
    // `bpf_get_current_ancestor_cgroup_id(level)` counts levels from the root (level 0). We do not
    // know the current task's depth, so probe each level up to the bound; levels past the task's own
    // depth return 0 and are skipped. The scope, being an ancestor, appears at its (shallow) level.
    let mut level: i32 = 0;
    while level < MAX_CGROUP_DEPTH {
        let id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if id != 0 && id != cur {
            if let Some(meta) = unsafe { SCOPES.get(&id) } {
                return Some((id, *meta));
            }
        }
        level += 1;
    }
    None
}

/// Per-cgroup file deny prefixes.
#[map]
static FS_DENY: HashMap<u64, DenyList> = HashMap::with_max_entries(1024, 0);

/// Allowed network destinations, keyed by `{cgroup_id, family, port, addr}`. Presence ⇒ allowed.
#[map]
static NET_ALLOW: HashMap<NetKey, u8> = HashMap::with_max_entries(4096, 0);

/// Per-cgroup executable allowlist (path prefixes). Presence of an entry ⇒ exec is enforced.
#[map]
static EXEC_ALLOW: HashMap<u64, DenyList> = HashMap::with_max_entries(1024, 0);

/// Scratch buffer for `bpf_d_path` output (PATH_MAX won't fit on the 512-byte stack).
#[map]
static PATHBUF: PerCpuArray<[u8; PATH_MAX]> = PerCpuArray::with_max_entries(1, 0);

/// Audit records streamed to user space.
#[map]
static AUDIT_RB: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Refuse an operation the hook enforces but could not evaluate — a null argument, an unreadable
/// struct field, an unresolvable path, an address family with no allowlist to check against.
///
/// Constitution I is unconditional: "cannot tell" is "no". Every one of these branches used to
/// `return 0`, which meant an attacker who could *provoke* the failure — a directory chain longer
/// than `bpf_d_path`'s buffer, a socket family the hook does not decode — got an unenforced
/// operation out of an enforcing scope. Reaching one of these is either an attack or a bug in bee,
/// and both deserve the audit record this emits.
///
/// Only ever called after the scope has been shown to enforce the dimension in question (a network
/// flag, a deny list, an exec allowlist), so an unenforced scope is unaffected. `errno` is negative,
/// as returned; observe mode records without blocking, exactly as a policy denial does.
fn deny_unevaluated(cgid: u64, meta: ScopeMeta, op: Op, errno: i32) -> i32 {
    let observe = meta.mode == ScopeMode::Observe as u8;
    emit_audit(cgid, op, observe, errno, None);
    if observe {
        0
    } else {
        errno
    }
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    let (cgid, meta) = match resolve_scope() {
        Some(s) => s,
        None => return 0,
    };
    if meta.flags & FLAG_NET_ENFORCED == 0 {
        return 0; // network not enforced for this scope
    }

    // arg1 of socket_connect is `struct sockaddr *address` (UAPI-stable layout).
    let addr: *const u8 = ctx.arg(1);
    if addr.is_null() {
        return deny_unevaluated(cgid, meta, Op::Connect, -EPERM);
    }
    let family = unsafe { bpf_probe_read_kernel(addr as *const u16).unwrap_or(0) };

    let mut key = NetKey { cgroup_id: cgid, family, port: 0, _pad: [0; 4], addr: [0; 16] };
    match family {
        AF_INET => {
            // sockaddr_in: sin_port @2 (be16), sin_addr @4 (4 bytes).
            let port_be = unsafe { bpf_probe_read_kernel((addr as usize + 2) as *const u16).unwrap_or(0) };
            let a = unsafe { bpf_probe_read_kernel((addr as usize + 4) as *const [u8; 4]).unwrap_or([0; 4]) };
            key.port = u16::from_be(port_be);
            key.addr[..4].copy_from_slice(&a);
        }
        AF_INET6 => {
            // sockaddr_in6: sin6_port @2 (be16), sin6_addr @8 (16 bytes).
            let port_be = unsafe { bpf_probe_read_kernel((addr as usize + 2) as *const u16).unwrap_or(0) };
            let a = unsafe { bpf_probe_read_kernel((addr as usize + 8) as *const [u8; 16]).unwrap_or([0; 16]) };
            key.port = u16::from_be(port_be);
            key.addr = a;
        }
        // A non-IP family (unix, netlink, …). The policy language describes destinations as
        // `host:port`, so there is no rule that could ever allow one — and "no rule matches" in an
        // enforcing scope means deny, not allow. An AF_UNIX connect to a local agent socket is
        // egress just as surely as a TCP one; letting it through because the allowlist cannot spell
        // it is the enforcement gap, not the policy's silence.
        _ => return deny_unevaluated(cgid, meta, Op::Connect, -EPERM),
    }

    if unsafe { NET_ALLOW.get(&key) }.is_some() {
        return 0; // destination is on the allowlist
    }

    let observe = meta.mode == ScopeMode::Observe as u8;
    // Name the destination (019 P5, FR-009): a denial that does not say where it was going can be
    // neither acted on by the operator nor turned into a grant by reactive escalation.
    emit_audit_connect(cgid, observe, -EPERM, &key);
    if observe {
        0
    } else {
        -EPERM
    }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let (cgid, meta) = match resolve_scope() {
        Some(s) => s,
        None => return 0,
    };
    let list = match unsafe { FS_DENY.get(&cgid) } {
        Some(l) => l,
        None => return 0, // scope has no file deny rules
    };

    // Resolve the path into the per-CPU buffer.
    let buf_ptr = match PATHBUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return deny_unevaluated(cgid, meta, Op::FileOpen, -EACCES),
    };
    // arg0 of file_open is `struct file *`.
    let file: *const c_void = ctx.arg(0);
    if file.is_null() {
        return deny_unevaluated(cgid, meta, Op::FileOpen, -EACCES);
    }
    // Requested access: direct load of `file->f_mode` (a scalar field on a trusted LSM BTF pointer,
    // so the verifier maps offset 20 to the u32 field — same mechanism as `bprm->file` below).
    let f_mode = unsafe { *((file as usize + FILE_F_MODE_OFF) as *const u32) };
    let is_write = f_mode & FMODE_WRITE != 0;

    let path_ptr = (file as usize + FILE_F_PATH_OFF) as *mut path;
    // SAFETY: bpf_d_path writes up to PATH_MAX bytes into buf_ptr and returns the length (incl. NUL).
    let ret = unsafe { bpf_d_path(path_ptr, buf_ptr as *mut i8, PATH_MAX as u32) };
    if ret <= 0 {
        // Unresolvable (most often a resolved path longer than the 4KB buffer). A rule list cannot
        // be applied to a path we do not have, and a scope with deny rules does not get to skip them
        // because an attacker nested the target deeply enough.
        return deny_unevaluated(cgid, meta, Op::FileOpen, -EACCES);
    }
    let plen = resolved_len(ret);

    // SAFETY: buf_ptr points at a valid [u8; PATH_MAX] map value.
    let buf = unsafe { &*buf_ptr };
    let write_default_deny = meta.flags & FLAG_FS_WRITE_DEFAULT_DENY != 0;
    if !fs_should_block(buf, plen, list, is_write, write_default_deny) {
        return 0; // access permitted by the rule list
    }

    let observe = meta.mode == ScopeMode::Observe as u8;
    emit_audit(cgid, Op::FileOpen, observe, -EACCES, Some(buf));
    if observe {
        0
    } else {
        -EACCES
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let (cgid, meta) = match resolve_scope() {
        Some(s) => s,
        None => return 0,
    };
    // No exec allowlist for this scope ⇒ exec is not enforced.
    let allow = match unsafe { EXEC_ALLOW.get(&cgid) } {
        Some(a) => a,
        None => return 0,
    };

    // arg0 of bprm_check_security is `struct linux_binprm *`; read bprm->file (a `struct file*`).
    let bprm: *const u8 = ctx.arg(0);
    if bprm.is_null() {
        return deny_unevaluated(cgid, meta, Op::Exec, -EACCES);
    }
    // Direct load of bprm->file. Because `bprm` is a trusted LSM BTF pointer, the verifier maps
    // offset 64 to the `file*` field and keeps the loaded value a trusted pointer (which
    // `bpf_d_path` requires) — unlike `bpf_probe_read`, which would yield an untyped scalar.
    let file_val = unsafe { *((bprm as usize + BINPRM_FILE_OFF) as *const usize) };
    if file_val == 0 {
        return deny_unevaluated(cgid, meta, Op::Exec, -EACCES);
    }

    // Identity first, path second (017). A pinned rule names a *file*, and this hook holds the very
    // file the kernel is about to load — so the decision needs no name at all, and cannot be raced
    // by re-pointing one. It is also the cheaper question: three loads against a path resolution.
    let (ino, dev) = file_identity(file_val);
    if allow_pins(allow, ino, dev) {
        return 0; // this exact image was granted
    }

    let buf_ptr = match PATHBUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return deny_unevaluated(cgid, meta, Op::Exec, -EACCES),
    };
    let path_ptr = (file_val + FILE_F_PATH_OFF) as *mut path;
    let ret = unsafe { bpf_d_path(path_ptr, buf_ptr as *mut i8, PATH_MAX as u32) };
    if ret <= 0 {
        // An allowlist names paths; an image whose path will not resolve cannot be on it. This is
        // the sharpest of the four — a >4KB directory chain, or a memfd image with no path at all,
        // was the way to exec anything at all out of an exec-enforced scope.
        return deny_unevaluated(cgid, meta, Op::Exec, -EACCES);
    }
    let plen = resolved_len(ret);
    let buf = unsafe { &*buf_ptr };
    if matches_any(buf, plen, allow) {
        return 0; // executable is allowlisted
    }

    let observe = meta.mode == ScopeMode::Observe as u8;
    emit_audit(cgid, Op::Exec, observe, -EACCES, Some(buf));
    if observe {
        0
    } else {
        -EACCES
    }
}

/// Convert `bpf_d_path`'s return (bytes written, including the trailing NUL) to the path length,
/// clamped into `[0, PATH_MAX-1]` so downstream indexing stays in bounds.
fn resolved_len(ret: i64) -> usize {
    let n = if ret > 0 { ret as usize } else { 0 };
    let n = n.saturating_sub(1); // drop the trailing NUL
    if n < PATH_MAX {
        n
    } else {
        PATH_MAX - 1
    }
}

/// Does `buf` (a resolved path of length `plen`) match `rule`, dispatched on its kind? `plen` comes
/// from `bpf_d_path`'s return value — scanning the 4KB buffer for a NUL blows the verifier's
/// instruction budget, so we never do that. Segment / bounded-star kinds never reach a scope's list
/// (user space fails closed on them), so an unknown kind is treated as no-match.
fn rule_matches(buf: &[u8; PATH_MAX], plen: usize, rule: &DenyRule) -> bool {
    match rule.kind {
        FS_KIND_SUBTREE => match_subtree(buf, plen, rule),
        FS_KIND_POSTFIX => match_postfix(buf, plen, rule),
        _ => false,
    }
}

/// The identity of the file being executed: `(i_ino, s_dev)`, reached from the `struct file *` the
/// exec hook already holds.
///
/// Direct loads at constant offsets, the same mechanism `f_mode` uses: because `file` came out of a
/// trusted LSM BTF pointer, the verifier maps each offset to its field and keeps the intermediate
/// `inode *` / `super_block *` loads typed. `bpf_probe_read` would hand back untyped scalars and the
/// chain would not verify.
///
/// A zero inode means the chain gave nothing — the caller must treat that as "matches no pin",
/// never as "matches every pin", which is why [`allow_pins`] tests it explicitly.
#[inline(always)]
fn file_identity(file_val: usize) -> (u64, u32) {
    let inode = unsafe { *((file_val + FILE_F_INODE_OFF) as *const usize) };
    if inode == 0 {
        return (0, 0);
    }
    let ino = unsafe { *((inode + INODE_I_INO_OFF) as *const u64) };
    let sb = unsafe { *((inode + INODE_I_SB_OFF) as *const usize) };
    if sb == 0 {
        return (0, 0);
    }
    let dev = unsafe { *((sb + SUPER_BLOCK_S_DEV_OFF) as *const u32) };
    (ino, dev)
}

/// Does any **pinned** rule in `list` admit `(ino, dev)`? Bounded, early-returning, verifier-safe —
/// the same shape as [`matches_any`], which handles the unpinned half of the same list.
fn allow_pins(list: &DenyList, ino: u64, dev: u32) -> bool {
    if ino == 0 {
        // No identity, no identity-based grant. An image whose inode the hook cannot read is left to
        // the path scan, which fails closed on an unresolvable path.
        return false;
    }
    let count = if (list.count as usize) < DENY_MAX_RULES {
        list.count as usize
    } else {
        DENY_MAX_RULES
    };
    let mut i = 0usize;
    while i < DENY_MAX_RULES {
        if i >= count {
            break;
        }
        let rule = &list.rules[i];
        if rule.ino != 0 && rule.ino == ino && rule.dev == dev {
            return true;
        }
        i += 1;
    }
    false
}

/// Does any rule in `list` match `buf`? Used for the executable allowlist (pure membership, mode
/// ignored). Bounded, verifier-safe.
///
/// **Pinned rules are skipped here.** They were already decided on identity by [`allow_pins`], and a
/// pin that also matched its own path would silently degrade to a path rule the moment the file it
/// named was replaced — which is the one thing a pin exists to prevent (017 FR-002).
fn matches_any(buf: &[u8; PATH_MAX], plen: usize, list: &DenyList) -> bool {
    let count = if (list.count as usize) < DENY_MAX_RULES {
        list.count as usize
    } else {
        DENY_MAX_RULES
    };
    let mut i = 0usize;
    while i < DENY_MAX_RULES {
        if i >= count {
            break;
        }
        let rule = &list.rules[i];
        if rule.ino == 0 && rule_matches(buf, plen, rule) {
            return true;
        }
        i += 1;
    }
    false
}

/// The `file_open` access decision (returns `true` ⇒ block). Verifier-safe, buffer-indexed mirror
/// of `bee_common::matcher::fs_open_blocked` (see there and `contracts/policy.schema.md` / R13 for
/// the precedence).
///
/// The rule list is **pre-sorted most-specific-first (deny breaking ties)** by user space
/// (`bee_common::matcher::rule_sort_key`), so the **first matching rule is the most specific** and
/// this is a single **early-returning** scan — the same shape as the exec allowlist match, which is
/// why it stays within the verifier's 1M-instruction budget. Tracking a "best specificity" scalar
/// across all rules instead (no early return) explodes the verifier state and overruns the budget.
///
/// First matching rule decides: `deny` ⇒ block; a grant ⇒ block iff it does not grant the requested
/// access (read for a read-open, write for a write-open — grants always include read, so reads are
/// only ever blocked by a `deny`). With no matching rule: reads are allowed; writes are denied only
/// where the scope manages its write surface (`write_default_deny`).
fn fs_should_block(
    buf: &[u8; PATH_MAX],
    plen: usize,
    list: &DenyList,
    is_write: bool,
    write_default_deny: bool,
) -> bool {
    let count = if (list.count as usize) < DENY_MAX_RULES {
        list.count as usize
    } else {
        DENY_MAX_RULES
    };

    let mut i = 0usize;
    while i < DENY_MAX_RULES {
        if i >= count {
            break;
        }
        let rule = &list.rules[i];
        if rule_matches(buf, plen, rule) {
            let mode = AccessMode(rule.mode);
            if mode.is_deny() {
                return true;
            }
            let requested = if is_write { AccessMode::WRITE } else { AccessMode::READ };
            return !mode.contains(requested);
        }
        i += 1;
    }

    // No rule matched: allow reads; deny writes only where the scope manages its write surface.
    if !is_write {
        return false;
    }
    write_default_deny
}

/// Path ends with `rule.bytes[..len]` (compiled from `*.ext`). Compares from the end; buffer indices
/// are masked with `& (PATH_MAX-1)` so the verifier can bound the (runtime-derived) access.
fn match_postfix(buf: &[u8; PATH_MAX], plen: usize, rule: &DenyRule) -> bool {
    let rl = rule.len as usize;
    if rl == 0 || rl > DENY_PREFIX_MAX || plen < rl {
        return false;
    }
    let mut i = 0usize;
    while i < DENY_PREFIX_MAX {
        if i >= rl {
            break;
        }
        // plen > i (since plen >= rl > i), so these are non-negative; mask keeps the verifier happy.
        let pidx = (plen - 1 - i) & (PATH_MAX - 1);
        let ridx = (rl - 1 - i) & (DENY_PREFIX_MAX - 1);
        if buf[pidx] != rule.bytes[ridx] {
            return false;
        }
        i += 1;
    }
    true
}

/// Subtree/exact match (verifier-safe): does `buf` start with `rule.bytes[..rule.len]` at a path
/// boundary (exact match or the next byte is `/`)?
fn match_subtree(buf: &[u8; PATH_MAX], plen: usize, rule: &DenyRule) -> bool {
    let len = rule.len as usize;
    if len == 0 || len > DENY_PREFIX_MAX || len > plen {
        return false;
    }
    let mut i = 0usize;
    while i < DENY_PREFIX_MAX {
        if i >= len {
            break;
        }
        if buf[i] != rule.bytes[i] {
            return false;
        }
        i += 1;
    }
    // Boundary: exact match (len == plen) or the next byte is a separator.
    len == plen || buf[len & (PATH_MAX - 1)] == b'/'
}

// Preserve the policy scope for routing, and separately identify the executor beneath it.
// Looking up the ancestor while the task is alive also covers invocation cgroups removed
// before userspace drains the ring.
fn executor_cgroup_id(scope: u64) -> u64 {
    let mut level = 0;
    while level < MAX_CGROUP_DEPTH - 1 {
        if unsafe { bpf_get_current_ancestor_cgroup_id(level) } == scope {
            let child = unsafe { bpf_get_current_ancestor_cgroup_id(level + 1) };
            return if child == 0 { scope } else { child };
        }
        level += 1;
    }
    scope
}

fn emit_audit(cgid: u64, op: Op, observe: bool, errno: i32, path: Option<&[u8; PATH_MAX]>) {
    if let Some(mut slot) = AUDIT_RB.reserve::<AuditRecord>(0) {
        let pidtgid = bpf_get_current_pid_tgid();
        let mut target = [0u8; TARGET_MAX];
        let mut tlen = 0u16;
        if let Some(p) = path {
            let mut i = 0usize;
            while i < TARGET_MAX - 1 {
                let b = p[i];
                if b == 0 {
                    break;
                }
                target[i] = b;
                i += 1;
            }
            tlen = i as u16;
        }
        let rec = AuditRecord {
            ts_ns: unsafe { bpf_ktime_get_ns() },
            cgroup_id: cgid,
            executor_cgroup_id: executor_cgroup_id(cgid),
            pid: pidtgid as u32,
            tgid: (pidtgid >> 32) as u32,
            op: op as u8,
            decision: if observe { Decision::Observed as u8 } else { Decision::Denied as u8 },
            _pad: [0; 2],
            errno: if observe { 0 } else { errno },
            target_len: tlen,
            _pad2: [0; 6],
            target,
        };
        // SAFETY: the reserved slot is sized for AuditRecord.
        unsafe { core::ptr::write_unaligned(slot.as_mut_ptr(), rec) };
        slot.submit(0);
    }
}

/// Emit a connect audit record whose target is the decoded destination, as a fixed 20-byte binary
/// encoding: `family: u16 LE`, `port: u16 BE`, then `addr: [u8; 16]` exactly as in `NetKey.addr`
/// (IPv4 in `addr[0..4]`, the rest zero; IPv6 in all 16). User space formats it as `ip:port`
/// (`bee_core::AuditEvent::from_record`). Binary rather than text because formatting an address in
/// the kernel would cost verifier budget for no gain — and the `AuditRecord` layout is unchanged.
fn emit_audit_connect(cgid: u64, observe: bool, errno: i32, key: &NetKey) {
    if let Some(mut slot) = AUDIT_RB.reserve::<AuditRecord>(0) {
        let pidtgid = bpf_get_current_pid_tgid();
        let mut target = [0u8; TARGET_MAX];
        let fam = key.family.to_le_bytes();
        let port = key.port.to_be_bytes();
        target[0] = fam[0];
        target[1] = fam[1];
        target[2] = port[0];
        target[3] = port[1];
        let mut i = 0usize;
        while i < 16 {
            target[4 + i] = key.addr[i];
            i += 1;
        }
        let rec = AuditRecord {
            ts_ns: unsafe { bpf_ktime_get_ns() },
            cgroup_id: cgid,
            executor_cgroup_id: executor_cgroup_id(cgid),
            pid: pidtgid as u32,
            tgid: (pidtgid >> 32) as u32,
            op: Op::Connect as u8,
            decision: if observe { Decision::Observed as u8 } else { Decision::Denied as u8 },
            _pad: [0; 2],
            errno: if observe { 0 } else { errno },
            target_len: 20,
            _pad2: [0; 6],
            target,
        };
        // SAFETY: the reserved slot is sized for AuditRecord.
        unsafe { core::ptr::write_unaligned(slot.as_mut_ptr(), rec) };
        slot.submit(0);
    }
}

#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
