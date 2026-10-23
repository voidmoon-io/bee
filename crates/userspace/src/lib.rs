//! `bee-userspace` — kernel-facing loader, scope lifecycle, and process launcher.
//!
//! ## Build modes
//!
//! * **default (stable toolchain)** — host-verifiable logic only: support detection ([`detect`]),
//!   cgroup id/lifecycle ([`cgroup`]), the hardened launcher ([`spawn`]). [`Engine::init`] runs the
//!   fail-closed support gate but returns [`EngineError::EnforceFeatureDisabled`], since no BPF
//!   object is embedded.
//! * **`--features enforce` (nightly bpf toolchain + BPF-LSM kernel)** — additionally compiles and
//!   embeds the eBPF programs, attaches the LSM hooks ([`loader`]), populates per-scope maps, and
//!   streams audit events ([`events`]).

pub mod cgroup;
pub mod detect;
pub mod events;
// Pre-exec / pre-main process hardening (FR-011). Was its own package until consolidation issue
// 07: one source file, one consumer (`spawn`), and none of the runtime, kernel, `no_std`, or
// BPF-target constraints that earn the other crates their separation.
pub mod hardening;
pub mod kbtf;
pub mod loader;
pub mod plan;
pub mod reload;
pub mod resolve;
pub mod spawn;

#[cfg(feature = "tokio")]
pub mod async_events;
#[cfg(feature = "tokio")]
pub mod audit_demux;

pub use bee_common::ScopeMode;
pub use detect::{detect, Support};
pub use plan::{EnforcementPlan, PlanError};
pub use reload::ReloadError;
pub use resolve::SystemResolver;
pub use spawn::{hardened_command, SpawnError};

#[cfg(feature = "tokio")]
pub use async_events::AsyncAuditStream;
#[cfg(feature = "tokio")]
pub use audit_demux::{AuditDemux, AuditSubscription};

use thiserror::Error;

/// Errors from bringing up the enforcement engine.
#[derive(Debug, Error)]
pub enum EngineError {
    /// The kernel cannot enforce (missing BPF LSM / cgroup v2). Fail-closed (FR-009 / SC-007).
    #[error("bee cannot enforce on this kernel:\n{0}")]
    Unsupported(String),
    /// Built without the `enforce` feature, so no BPF object is embedded to attach.
    #[error(
        "bee-userspace was built without the `enforce` feature; rebuild with `--features enforce` \
         on a BPF-LSM-capable kernel and the nightly bpf toolchain to attach enforcement"
    )]
    EnforceFeatureDisabled,
    /// Loading or attaching the eBPF object failed.
    #[error("eBPF load/attach failed: {0}")]
    Load(String),
}

/// Errors from creating or managing a scope.
#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("cgroup error: {0}")]
    Cgroup(#[from] std::io::Error),
    #[error("map error: {0}")]
    Map(String),
}

/// The process-wide enforcement engine.
pub struct Engine {
    // Read via `support()` and by the enforce-path loader; unused in the default build.
    #[allow(dead_code)]
    support: Support,
    #[cfg(feature = "enforce")]
    ebpf: std::mem::ManuallyDrop<aya::Ebpf>,
    #[cfg(feature = "enforce")]
    scope_paths: Vec<std::path::PathBuf>,
}

#[cfg(feature = "enforce")]
impl Drop for Engine {
    fn drop(&mut self) {
        for path in &self.scope_paths {
            if !path.exists() {
                continue;
            }
            if let Err(error) = cgroup::kill_scope_cgroup(path) {
                // Detaching would remove enforcement from surviving children. Keep the link
                // descriptors open for the rest of this process's lifetime instead.
                eprintln!("bee: retaining enforcement after failed scope cleanup: {error}");
                return;
            }
            let _ = cgroup::teardown_scope_cgroup(path);
        }
        // SAFETY: this is the sole owner, and all owned scopes are confirmed empty.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut self.ebpf);
        }
    }
}

impl Engine {
    /// Probe kernel support without attaching anything (backs `bee check`).
    pub fn supported() -> Support {
        detect::detect()
    }

    /// Initialize the engine. **Fail-closed**: returns `Err(Unsupported)` on any kernel that cannot
    /// enforce, never a no-op engine (SC-007).
    pub fn init() -> Result<Engine, EngineError> {
        let support = Self::supported();
        if !support.is_supported() {
            return Err(EngineError::Unsupported(support.to_string()));
        }

        #[cfg(feature = "enforce")]
        {
            let ebpf = loader::load_and_attach()?;
            Ok(Engine {
                support,
                ebpf: std::mem::ManuallyDrop::new(ebpf),
                scope_paths: Vec::new(),
            })
        }
        #[cfg(not(feature = "enforce"))]
        {
            Err(EngineError::EnforceFeatureDisabled)
        }
    }

    /// The support probe this engine was initialized against.
    pub fn support(&self) -> &Support {
        &self.support
    }

    /// Install a completed enforcement plan into a new cgroup and the eBPF maps.
    #[cfg(feature = "enforce")]
    pub fn create_scope(
        &mut self,
        scope_id: &str,
        parent_cgroup: &str,
        plan: &EnforcementPlan,
    ) -> Result<Scope, ScopeError> {
        let path = cgroup::create_scope_cgroup(parent_cgroup, scope_id)?;
        self.scope_paths.push(path.clone());
        let cgroup_id = cgroup::cgroup_id(&path)?;

        // Planning has already validated all capabilities and encoded the mode/flags.
        {
            let map = self
                .ebpf
                .map_mut("SCOPES")
                .ok_or_else(|| ScopeError::Map("SCOPES map missing".into()))?;
            let mut scopes: aya::maps::HashMap<_, u64, bee_common::layout::ScopeMeta> =
                aya::maps::HashMap::try_from(map).map_err(|e| ScopeError::Map(e.to_string()))?;
            scopes
                .insert(cgroup_id, plan.meta, 0)
                .map_err(|e| ScopeError::Map(e.to_string()))?;
        }

        // Populate the network egress allowlist. Nothing records which keys went in: a later reload
        // reads them back from the map (see `reload`).
        if !plan.net_rules.is_empty() {
            use bee_common::layout::NetKey;
            let map = self
                .ebpf
                .map_mut("NET_ALLOW")
                .ok_or_else(|| ScopeError::Map("NET_ALLOW map missing".into()))?;
            let mut net: aya::maps::HashMap<_, NetKey, u8> =
                aya::maps::HashMap::try_from(map).map_err(|e| ScopeError::Map(e.to_string()))?;
            for template in &plan.net_rules {
                let mut key = *template;
                key.cgroup_id = cgroup_id;
                net.insert(key, 1u8, 0)
                    .map_err(|e| ScopeError::Map(e.to_string()))?;
            }
        }

        if plan.has_fs_rules {
            let map = self
                .ebpf
                .map_mut("FS_DENY")
                .ok_or_else(|| ScopeError::Map("FS_DENY map missing".into()))?;
            let mut deny: aya::maps::HashMap<_, u64, bee_common::layout::DenyList> =
                aya::maps::HashMap::try_from(map).map_err(|e| ScopeError::Map(e.to_string()))?;
            deny.insert(cgroup_id, plan.fs_rules, 0)
                .map_err(|e| ScopeError::Map(e.to_string()))?;
        }

        if plan.has_exec_rules {
            let map = self
                .ebpf
                .map_mut("EXEC_ALLOW")
                .ok_or_else(|| ScopeError::Map("EXEC_ALLOW map missing".into()))?;
            let mut execs: aya::maps::HashMap<_, u64, bee_common::layout::DenyList> =
                aya::maps::HashMap::try_from(map).map_err(|e| ScopeError::Map(e.to_string()))?;
            execs
                .insert(cgroup_id, plan.exec_rules, 0)
                .map_err(|e| ScopeError::Map(e.to_string()))?;
        }

        Ok(Scope { path, cgroup_id })
    }

    /// Re-populate an already-created scope's rule maps from `plan` (007-dynamic-grants), supporting
    /// both widening (added rules) and narrowing (removed rules). The LSM programs stay attached;
    /// only map contents change.
    ///
    /// All or nothing: on [`ReloadError::Refused`] the scope's rules are exactly what they were. On
    /// [`ReloadError::Inconsistent`] they are unknown and the caller must run nothing further in the
    /// scope. The installed egress keys are read back from `NET_ALLOW` rather than passed in, so no
    /// earlier failure can leave a key that this reload fails to see. See [`reload`].
    ///
    /// Caller preconditions: no sandboxed child is executing in this scope (a turn boundary), and
    /// `plan` was compiled from a policy already validated `⊆ ceiling`. See
    /// `specs/007-dynamic-grants/contracts/reload-api.md`.
    #[cfg(feature = "enforce")]
    pub fn reload_scope(
        &mut self,
        cgroup_id: u64,
        plan: &EnforcementPlan,
    ) -> Result<(), ReloadError> {
        reload::apply(&mut AyaScopeMaps(&mut self.ebpf), cgroup_id, plan)
    }

    /// Take ownership of the audit ring buffer as a synchronous reader (call once). (enforce feature)
    #[cfg(feature = "enforce")]
    pub fn take_audit_reader(&mut self, scope_id: &str) -> Result<events::AuditReader, ScopeError> {
        let map = self
            .ebpf
            .take_map("AUDIT_RB")
            .ok_or_else(|| ScopeError::Map("AUDIT_RB map missing".into()))?;
        let rb = aya::maps::RingBuf::try_from(map).map_err(|e| ScopeError::Map(e.to_string()))?;
        Ok(events::AuditReader::new(rb, scope_id.to_string()))
    }

    /// Take ownership of the audit ring buffer as an **async** stream (US4, `tokio` feature). Like
    /// [`take_audit_reader`](Self::take_audit_reader), the underlying map is `take_map` — it can be
    /// taken **once**, so an engine serves either the sync reader OR the async stream for its
    /// lifetime, never both. Pick one when the engine is created.
    #[cfg(feature = "tokio")]
    pub fn take_async_audit_stream(
        &mut self,
        scope_id: &str,
    ) -> Result<async_events::AsyncAuditStream, ScopeError> {
        let map = self
            .ebpf
            .take_map("AUDIT_RB")
            .ok_or_else(|| ScopeError::Map("AUDIT_RB map missing (already taken?)".into()))?;
        let rb = aya::maps::RingBuf::try_from(map).map_err(|e| ScopeError::Map(e.to_string()))?;
        async_events::AsyncAuditStream::new(rb, scope_id.to_string())
            .map_err(|e| ScopeError::Map(format!("async audit stream: {e}")))
    }
}

/// The loaded object's rule maps, as [`reload::ScopeMaps`]. (enforce feature)
#[cfg(feature = "enforce")]
struct AyaScopeMaps<'a>(&'a mut aya::Ebpf);

#[cfg(feature = "enforce")]
impl AyaScopeMaps<'_> {
    fn map<K: aya::Pod, V: aya::Pod>(
        &self,
        name: &str,
    ) -> Result<aya::maps::HashMap<&aya::maps::MapData, K, V>, String> {
        let map = self
            .0
            .map(name)
            .ok_or_else(|| format!("{name} map missing"))?;
        aya::maps::HashMap::try_from(map).map_err(|e| format!("{name}: {e}"))
    }

    fn map_mut<K: aya::Pod, V: aya::Pod>(
        &mut self,
        name: &str,
    ) -> Result<aya::maps::HashMap<&mut aya::maps::MapData, K, V>, String> {
        let map = self
            .0
            .map_mut(name)
            .ok_or_else(|| format!("{name} map missing"))?;
        aya::maps::HashMap::try_from(map).map_err(|e| format!("{name}: {e}"))
    }

    fn get<V: aya::Pod>(&self, name: &str, cgroup_id: u64) -> Result<Option<V>, String> {
        match self.map::<u64, V>(name)?.get(&cgroup_id, 0) {
            Ok(v) => Ok(Some(v)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(format!("{name} read: {e}")),
        }
    }

    fn set<V: aya::Pod>(&mut self, name: &str, cgroup_id: u64, v: V) -> Result<(), String> {
        self.map_mut::<u64, V>(name)?
            .insert(cgroup_id, v, 0)
            .map_err(|e| format!("{name} insert: {e}"))
    }

    /// Remove, treating an already-absent key as done. aya reports a delete of an absent key as the
    /// raw `bpf_map_delete_elem` ENOENT, not `KeyNotFound` (that is only `get`'s).
    fn remove<K: aya::Pod, V: aya::Pod>(&mut self, name: &str, key: &K) -> Result<(), String> {
        match self.map_mut::<K, V>(name)?.remove(key) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(aya::maps::MapError::SyscallError(e))
                if e.io_error.raw_os_error() == Some(libc::ENOENT) =>
            {
                Ok(())
            }
            Err(e) => Err(format!("{name} remove: {e}")),
        }
    }
}

#[cfg(feature = "enforce")]
impl reload::ScopeMaps for AyaScopeMaps<'_> {
    fn meta(&self, cgroup_id: u64) -> Result<Option<bee_common::layout::ScopeMeta>, String> {
        self.get("SCOPES", cgroup_id)
    }
    fn set_meta(
        &mut self,
        cgroup_id: u64,
        meta: bee_common::layout::ScopeMeta,
    ) -> Result<(), String> {
        self.set("SCOPES", cgroup_id, meta)
    }
    fn fs(&self, cgroup_id: u64) -> Result<Option<bee_common::layout::DenyList>, String> {
        self.get("FS_DENY", cgroup_id)
    }
    fn set_fs(
        &mut self,
        cgroup_id: u64,
        rules: bee_common::layout::DenyList,
    ) -> Result<(), String> {
        self.set("FS_DENY", cgroup_id, rules)
    }
    fn remove_fs(&mut self, cgroup_id: u64) -> Result<(), String> {
        self.remove::<u64, bee_common::layout::DenyList>("FS_DENY", &cgroup_id)
    }
    fn exec(&self, cgroup_id: u64) -> Result<Option<bee_common::layout::DenyList>, String> {
        self.get("EXEC_ALLOW", cgroup_id)
    }
    fn set_exec(
        &mut self,
        cgroup_id: u64,
        rules: bee_common::layout::DenyList,
    ) -> Result<(), String> {
        self.set("EXEC_ALLOW", cgroup_id, rules)
    }
    fn remove_exec(&mut self, cgroup_id: u64) -> Result<(), String> {
        self.remove::<u64, bee_common::layout::DenyList>("EXEC_ALLOW", &cgroup_id)
    }
    fn net_keys(&self, cgroup_id: u64) -> Result<Vec<bee_common::layout::NetKey>, String> {
        let net = self.map::<bee_common::layout::NetKey, u8>("NET_ALLOW")?;
        let mut keys = Vec::new();
        for k in net.keys() {
            let k = k.map_err(|e| format!("NET_ALLOW iterate: {e}"))?;
            if k.cgroup_id == cgroup_id {
                keys.push(k);
            }
        }
        Ok(keys)
    }
    fn insert_net(&mut self, key: bee_common::layout::NetKey) -> Result<(), String> {
        self.map_mut::<bee_common::layout::NetKey, u8>("NET_ALLOW")?
            .insert(key, 1u8, 0)
            .map_err(|e| format!("NET_ALLOW insert: {e}"))
    }
    fn remove_net(&mut self, key: &bee_common::layout::NetKey) -> Result<(), String> {
        self.remove::<bee_common::layout::NetKey, u8>("NET_ALLOW", key)
    }
}

/// A live scope = one bee-managed cgroup registered for enforcement. (enforce feature)
#[cfg(feature = "enforce")]
pub struct Scope {
    pub path: std::path::PathBuf,
    pub cgroup_id: u64,
}

#[cfg(feature = "enforce")]
impl Scope {
    /// A fork-safe `pre_exec` closure that joins the calling process to this scope's cgroup.
    pub fn join_closure(
        &self,
    ) -> Result<impl Fn() -> std::io::Result<()> + Send + Sync + 'static, ScopeError> {
        let procs = cgroup::procs_path_c(&self.path)?;
        Ok(move || cgroup::raw_join_self(&procs))
    }

    /// Kill everything still running in the scope, then remove its cgroup.
    ///
    /// The kill is not optional and not best-effort: the caller is about to drop the [`Engine`],
    /// which detaches the LSM programs, so any process left alive here keeps running *without
    /// enforcement*. Removing the directory of a cgroup that still holds processes fails with
    /// `EBUSY` anyway — the error was previously discarded, which turned this escape into a silent
    /// one.
    pub fn teardown(&self) -> std::io::Result<()> {
        cgroup::kill_scope_cgroup(&self.path)?;
        cgroup::teardown_scope_cgroup(&self.path)
    }
}

#[cfg(all(test, not(feature = "enforce")))]
mod tests {
    use super::*;

    #[test]
    fn init_is_fail_closed_on_unsupported_kernel() {
        match Engine::init() {
            Err(EngineError::Unsupported(_)) => {} // non-BPF-LSM kernel
            Err(EngineError::EnforceFeatureDisabled) => {} // supported, but no embedded object
            Err(EngineError::Load(_)) => {}
            Ok(_) => panic!("Engine::init must never succeed without the enforce feature"),
        }
    }
}
