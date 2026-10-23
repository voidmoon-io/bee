//! Where a tool child runs: hardened + credential-stripped, optionally confined to a bee scope.
//!
//! This is the seam that lets one loop serve both builds (research H6):
//! * [`Sandbox::Host`] — a hardened, credential-stripped host process with **no** kernel scope.
//!   Default build; used by offline (`MockModel`) tests and the live-provider smoke.
//! * `Sandbox::Enforced` — the tool child joins a real bee scope cgroup and kernel denials are
//!   drained from the audit ring (`--features enforce`; the VM enforcement case).
//!
//! A tool never pre-checks paths against policy (contracts/tool-contracts.md): it attempts the
//! operation in the sandbox and reports whatever the kernel decided (Constitution III).

use std::io;
use std::process::Command;

use bee_core::AuditEvent;
use bee_userspace::{hardened_command, SpawnError};

/// Credential env vars stripped from **every** tool child regardless of config (FR-018). The
/// configured `api_key_env` is appended to this set at construction.
///
/// These names are now redundant with [`INHERITED_ENV_VARS`] — nothing outside that allowlist
/// reaches a child either way — but they are kept as an explicit subtraction so that adding a name
/// to the allowlist can never silently re-expose a provider key.
pub const DEFAULT_KEY_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GROQ_API_KEY",
];

/// The only environment variables a tool child inherits. Everything else is cleared.
///
/// This is an allowlist rather than a denylist on purpose. The denylist it replaces named four
/// provider keys, which meant a model-driven `bash` call could read `AWS_SECRET_ACCESS_KEY`,
/// `GITHUB_TOKEN`, `KUBECONFIG`, `SSH_AUTH_SOCK` — anything ambient in the operator's shell — and
/// return it to the model in a tool result. A tool child needs enough environment to run a program
/// and write to a temp dir; it does not need the operator's credentials, and there is no list of
/// credential names that stays complete.
///
/// `LC_*` is allowed by prefix alongside these. An MCP stdio server that needs more sets it
/// explicitly through its `env` config, which is applied after this clear (see
/// [`crate::mcp::transport`]).
pub const INHERITED_ENV_VARS: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "TMPDIR", "TERM", "TZ", "LANG",
];

/// A hardened host process with no kernel scope.
pub struct HostSandbox {
    strip_env: Vec<String>,
}

/// A tool child confined to a live bee scope, with its audit ring.
#[cfg(feature = "enforce")]
pub struct EnforcedSandbox {
    // The engine owns the loaded eBPF object; it MUST stay alive for the episode or the LSM
    // programs detach and the scope's map rules stop being enforced. Read mutably by `reload`
    // (007-dynamic-grants) to re-populate the scope's maps on a grant/narrow.
    engine: bee_userspace::Engine,
    pub scope: bee_userspace::Scope,
    pub reader: bee_userspace::events::AuditReader,
    strip_env: Vec<String>,
    /// Set when a reload failed and could not be rolled back: the scope's rules are then a mixture
    /// that may be wider than any policy anyone approved, so no further tool child may start in it.
    poisoned: Option<String>,
}

/// A tool child confined to a live bee scope whose audit events arrive via a demux subscription
/// (US4). Unlike [`EnforcedSandbox`] it does **not** own the engine — the concurrent runner owns one
/// shared engine for all episodes — and it drains an mpsc channel instead of the ring buffer.
#[cfg(feature = "concurrent")]
pub struct ConcurrentSandbox {
    pub scope: bee_userspace::Scope,
    pub subscription: bee_userspace::AuditSubscription,
    strip_env: Vec<String>,
}

/// The execution environment handed to every [`crate::tools::Tool`].
pub enum Sandbox {
    Host(HostSandbox),
    #[cfg(feature = "enforce")]
    Enforced(Box<EnforcedSandbox>),
    #[cfg(feature = "concurrent")]
    Concurrent(Box<ConcurrentSandbox>),
}

impl Sandbox {
    /// Recompile `policy` and re-populate the live scope's rule maps (007-dynamic-grants). Host is a
    /// no-op (no kernel scope). A concurrent sandbox cannot reload through here — the runner owns the
    /// engine — so it returns an error (fail-closed: escalation refuses rather than under-enforce).
    #[cfg_attr(not(feature = "enforce"), allow(unused_variables))]
    pub fn reload(&mut self, policy: &bee_core::Policy) -> Result<(), String> {
        match self {
            Sandbox::Host(_) => Ok(()),
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => e.reload(policy),
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(_) => Err(
                "reload unsupported on a concurrent sandbox (engine owned by the runner)"
                    .to_string(),
            ),
        }
    }
}

#[cfg(feature = "enforce")]
impl EnforcedSandbox {
    /// Compile `policy` and hand the fresh plan to `Engine::reload_scope`. On a refused reload the
    /// prior enforced maps are left in place; on one that could not be rolled back the sandbox is
    /// poisoned and refuses every further tool child.
    fn reload(&mut self, policy: &bee_core::Policy) -> Result<(), String> {
        use bee_userspace::{EnforcementPlan, ScopeMode, SystemResolver};
        let resolver = SystemResolver::current();
        let compiled = policy
            .compile(&resolver)
            .map_err(|e| format!("reload compile: {e}"))?;
        let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce)
            .map_err(|e| format!("reload plan: {e}"))?;
        if let Some(why) = &self.poisoned {
            return Err(format!("reload scope: already in an unknown state: {why}"));
        }
        match self.engine.reload_scope(self.scope.cgroup_id, &plan) {
            Ok(()) => Ok(()),
            Err(e @ bee_userspace::ReloadError::Refused(_)) => Err(format!("reload scope: {e}")),
            Err(e @ bee_userspace::ReloadError::Inconsistent(_)) => {
                let msg = e.to_string();
                self.poisoned = Some(msg.clone());
                Err(format!("reload scope: {msg}"))
            }
        }
    }
}

/// Build the credential strip-list: the default provider key vars plus any configured key var name.
pub fn key_vars(api_key_env: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = DEFAULT_KEY_VARS.iter().map(|s| s.to_string()).collect();
    if let Some(k) = api_key_env {
        if !k.is_empty() && !v.iter().any(|e| e == k) {
            v.push(k.to_string());
        }
    }
    v
}

impl Sandbox {
    /// A no-scope sandbox that strips `strip_env` from every child.
    pub fn host(strip_env: Vec<String>) -> Self {
        Sandbox::Host(HostSandbox { strip_env })
    }

    /// A scope-confined sandbox. Takes ownership of the `engine` so the loaded eBPF programs stay
    /// attached for the episode's lifetime (`--features enforce`).
    #[cfg(feature = "enforce")]
    pub fn enforced(
        engine: bee_userspace::Engine,
        scope: bee_userspace::Scope,
        reader: bee_userspace::events::AuditReader,
        strip_env: Vec<String>,
    ) -> Self {
        Sandbox::Enforced(Box::new(EnforcedSandbox {
            engine,
            scope,
            reader,
            strip_env,
            poisoned: None,
        }))
    }

    /// A scope-confined sandbox that receives audit events from a demux subscription (US4). The
    /// engine is owned elsewhere (the concurrent runner), shared across all episodes.
    #[cfg(feature = "concurrent")]
    pub fn concurrent(
        scope: bee_userspace::Scope,
        subscription: bee_userspace::AuditSubscription,
        strip_env: Vec<String>,
    ) -> Self {
        Sandbox::Concurrent(Box::new(ConcurrentSandbox {
            scope,
            subscription,
            strip_env,
        }))
    }

    /// The scope's cgroup id, when enforcing (used to filter audit events).
    #[cfg(feature = "enforce")]
    pub fn cgroup_id(&self) -> Option<u64> {
        match self {
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => Some(c.scope.cgroup_id),
            Sandbox::Enforced(e) => Some(e.scope.cgroup_id),
            _ => None,
        }
    }

    /// Build a hardened, credential-stripped [`Command`] for a tool child. Under `enforce` the child
    /// also joins the scope cgroup before exec. The caller runs/waits on it (async, via tokio).
    pub fn tool_command(&self, program: &str, args: &[String]) -> Result<Command, SpawnError> {
        match self {
            Sandbox::Host(h) => {
                // No cgroup join; hardening + env strip only.
                let mut cmd = hardened_command::<fn() -> io::Result<()>>(program, args, None)?;
                restrict_env(&mut cmd, &h.strip_env);
                Ok(cmd)
            }
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => {
                if let Some(why) = &e.poisoned {
                    return Err(SpawnError::Io(io::Error::other(format!(
                        "scope is in an unknown state after a failed reload; refusing to run: {why}"
                    ))));
                }
                let join = e
                    .scope
                    .join_closure()
                    .map_err(|err| SpawnError::Io(io::Error::other(err.to_string())))?;
                let mut cmd = hardened_command(program, args, Some(join))?;
                restrict_env(&mut cmd, &e.strip_env);
                Ok(cmd)
            }
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => {
                let join = c
                    .scope
                    .join_closure()
                    .map_err(|err| SpawnError::Io(io::Error::other(err.to_string())))?;
                let mut cmd = hardened_command(program, args, Some(join))?;
                restrict_env(&mut cmd, &c.strip_env);
                Ok(cmd)
            }
        }
    }

    /// Give the async audit path a moment to deliver this call's events before a drain. No-op for
    /// `Host`/`Enforced` (their drains read a source that is already up to date — the ring directly);
    /// for `Concurrent` the events travel kernel→ring→demux task→channel, so we yield briefly so the
    /// demux can dispatch before [`drain_audit`](Self::drain_audit) reads the channel (US4 AS-2 —
    /// still well within the 100ms budget).
    pub async fn settle(&mut self) {
        #[cfg(feature = "concurrent")]
        if let Sandbox::Concurrent(_) = self {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Drain and return the audit events for this scope since the last drain (empty for `Host`).
    /// Non-blocking (research H5): the records are already buffered in the ring (sync) or channel
    /// (async).
    pub fn drain_audit(&mut self) -> Vec<AuditEvent> {
        match self {
            Sandbox::Host(_) => Vec::new(),
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => {
                let cg = e.scope.cgroup_id;
                let mut out = Vec::new();
                e.reader.drain(&mut |ev| {
                    if ev.cgroup_id == cg {
                        out.push(ev);
                    }
                });
                out
            }
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => {
                // The demux already routes only this scope's events here; re-filter by cgroup_id
                // anyway as a fail-safe against cross-contamination (SC-004).
                let cg = c.scope.cgroup_id;
                let mut out = Vec::new();
                while let Ok(ev) = c.subscription.rx.try_recv() {
                    if ev.cgroup_id == cg {
                        out.push(ev);
                    }
                }
                out
            }
        }
    }

    /// Kill everything left in the scope and tear down its cgroup (no-op for `Host`).
    ///
    /// A failure here is reported, never swallowed. Teardown is followed by the engine being
    /// dropped, which detaches the LSM programs — so a scope that could not be emptied means a
    /// surviving process just lost its enforcement, and that has to be visible to the operator
    /// rather than inferred later from an `EBUSY` nobody saw.
    pub fn teardown(&self) -> Result<(), String> {
        #[cfg(feature = "enforce")]
        if let Sandbox::Enforced(e) = self {
            return e
                .scope
                .teardown()
                .map_err(|err| format!("scope teardown failed: {err}"));
        }
        #[cfg(feature = "concurrent")]
        if let Sandbox::Concurrent(c) = self {
            return c
                .scope
                .teardown()
                .map_err(|err| format!("scope teardown failed: {err}"));
        }
        Ok(())
    }
}

/// Reduce a child command's environment to [`INHERITED_ENV_VARS`] (plus `LC_*`) minus `keys`.
///
/// Done in the parent before spawn, so it is fork-safe: reading the environment takes locks and
/// allocates, which is not safe between `fork` and `exec`.
fn restrict_env(cmd: &mut Command, keys: &[String]) {
    let inherited: Vec<(String, std::ffi::OsString)> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let name = k.into_string().ok()?;
            let allowed = INHERITED_ENV_VARS.contains(&name.as_str()) || name.starts_with("LC_");
            (allowed && !keys.contains(&name)).then_some((name, v))
        })
        .collect();
    cmd.env_clear();
    for (k, v) in inherited {
        cmd.env(k, v);
    }
}
