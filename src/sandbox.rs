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

/// Which tool call a child is running for (019-http-intercept P3, research R6).
///
/// Set by the loop around each `ToolRegistry::execute`, so whatever the call spawns can be attributed
/// to it — today by the interception proxy, through a per-call credential the [`EnvOverlay`] provider
/// puts in the child's `HTTP_PROXY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContext {
    /// The provider's tool-call id (`ToolCall.id`).
    pub call_id: String,
    /// The turn the call belongs to.
    pub turn: u32,
    pub origin: CallOrigin,
}

/// What initiated the traffic a credential is issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOrigin {
    /// A model tool call.
    Tool,
    /// A long-lived MCP stdio server, named.
    Mcp(String),
    /// An `http_fuzz` run.
    Fuzz(String),
}

/// Extra environment variables for one tool child, applied **after** [`restrict_env`] (research R6).
///
/// Construction refuses any key that could re-expose a credential or subvert the loader: the
/// provider key vars in [`DEFAULT_KEY_VARS`] and every `LD_*`. The sandbox re-checks against its own,
/// configured strip list at spawn, which a bare constructor cannot know.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvOverlay(Vec<(String, String)>);

impl EnvOverlay {
    pub fn new(vars: Vec<(String, String)>) -> Result<Self, String> {
        for (k, _) in &vars {
            refused_overlay_key(k, &[])?;
        }
        Ok(EnvOverlay(vars))
    }

    pub fn vars(&self) -> &[(String, String)] {
        &self.0
    }
}

/// `Err` naming `key` when an overlay may not set it.
fn refused_overlay_key(key: &str, strip_env: &[String]) -> Result<(), String> {
    if key.is_empty() || key.contains('=') || key.contains('\0') {
        return Err(format!("env overlay: invalid variable name {key:?}"));
    }
    if key.starts_with("LD_") {
        return Err(format!(
            "env overlay: {key} is a loader variable and is always stripped"
        ));
    }
    if DEFAULT_KEY_VARS.contains(&key) || strip_env.iter().any(|k| k == key) {
        return Err(format!(
            "env overlay: {key} is a stripped credential variable"
        ));
    }
    Ok(())
}

/// Computes the [`EnvOverlay`] for a call. Installed by the harness only (019 interception).
pub type EnvProvider = Box<dyn Fn(&CallContext) -> EnvOverlay + Send + Sync>;

/// Everything that decides a tool child's environment: what is stripped, and what — for the current
/// call — is added back.
#[derive(Default)]
struct ChildEnv {
    strip_env: Vec<String>,
    call: Option<CallContext>,
    provider: Option<EnvProvider>,
}

impl ChildEnv {
    fn new(strip_env: Vec<String>) -> Self {
        ChildEnv {
            strip_env,
            ..Default::default()
        }
    }

    /// Clear `cmd`'s environment to the inherited allowlist, then apply this call's overlay.
    fn apply(&self, cmd: &mut Command) -> Result<(), SpawnError> {
        restrict_env(cmd, &self.strip_env);
        if let (Some(provider), Some(call)) = (&self.provider, &self.call) {
            for (k, v) in provider(call).vars() {
                refused_overlay_key(k, &self.strip_env)
                    .map_err(|e| SpawnError::Io(io::Error::other(e)))?;
                cmd.env(k, v);
            }
        }
        Ok(())
    }
}

/// A hardened host process with no kernel scope.
pub struct HostSandbox {
    env: ChildEnv,
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
    env: ChildEnv,
}

/// A tool child confined to a live bee scope whose audit events arrive via a demux subscription
/// (US4). Unlike [`EnforcedSandbox`] it does **not** own the engine — the concurrent runner owns one
/// shared engine for all episodes — and it drains an mpsc channel instead of the ring buffer.
#[cfg(feature = "concurrent")]
pub struct ConcurrentSandbox {
    pub scope: bee_userspace::Scope,
    pub subscription: bee_userspace::AuditSubscription,
    env: ChildEnv,
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
    /// Compile `policy` and hand the fresh plan to `Engine::reload_scope`, updating the scope's
    /// tracked `NET_ALLOW` keys. On any error the prior enforced maps are left in place.
    fn reload(&mut self, policy: &bee_core::Policy) -> Result<(), String> {
        use bee_userspace::{EnforcementPlan, ScopeMode, SystemResolver};
        let resolver = SystemResolver::current();
        let compiled = policy
            .compile(&resolver)
            .map_err(|e| format!("reload compile: {e}"))?;
        let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce)
            .map_err(|e| format!("reload plan: {e}"))?;
        let new_keys = self
            .engine
            .reload_scope(self.scope.cgroup_id, &plan, &self.scope.net_keys)
            .map_err(|e| format!("reload scope: {e}"))?;
        self.scope.net_keys = new_keys;
        Ok(())
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
        Sandbox::Host(HostSandbox {
            env: ChildEnv::new(strip_env),
        })
    }

    fn child_env(&self) -> &ChildEnv {
        match self {
            Sandbox::Host(h) => &h.env,
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => &e.env,
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => &c.env,
        }
    }

    fn child_env_mut(&mut self) -> &mut ChildEnv {
        match self {
            Sandbox::Host(h) => &mut h.env,
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => &mut e.env,
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => &mut c.env,
        }
    }

    /// Mark which tool call the next children are spawned for; `None` once it returns (019 P3). The
    /// loop sets this around every `ToolRegistry::execute`.
    pub fn set_call_context(&mut self, call: Option<CallContext>) {
        self.child_env_mut().call = call;
    }

    /// The tool call currently executing, if any.
    pub fn call_context(&self) -> Option<&CallContext> {
        self.child_env().call.as_ref()
    }

    /// Install the per-call environment overlay (harness only — e.g. the interception proxy's
    /// `HTTP_PROXY` credential). Applied to every child spawned while a call context is set.
    pub fn set_env_provider(&mut self, provider: EnvProvider) {
        self.child_env_mut().provider = Some(provider);
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
            env: ChildEnv::new(strip_env),
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
            env: ChildEnv::new(strip_env),
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
                h.env.apply(&mut cmd)?;
                Ok(cmd)
            }
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => {
                let join = e
                    .scope
                    .join_closure()
                    .map_err(|err| SpawnError::Io(io::Error::other(err.to_string())))?;
                let mut cmd = hardened_command(program, args, Some(join))?;
                e.env.apply(&mut cmd)?;
                Ok(cmd)
            }
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => {
                let join = c
                    .scope
                    .join_closure()
                    .map_err(|err| SpawnError::Io(io::Error::other(err.to_string())))?;
                let mut cmd = hardened_command(program, args, Some(join))?;
                c.env.apply(&mut cmd)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(cmd: &Command) -> Vec<(String, Option<String>)> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    fn ctx(id: &str) -> CallContext {
        CallContext {
            call_id: id.into(),
            turn: 3,
            origin: CallOrigin::Tool,
        }
    }

    // 019 P3 (T013): with a call context and an overlay provider set, the overlay's variables reach
    // the child, applied after `restrict_env` cleared everything else.
    #[test]
    fn an_overlay_reaches_the_child_after_restrict_env() {
        let mut sb = Sandbox::host(key_vars(None));
        sb.set_env_provider(Box::new(|c: &CallContext| {
            EnvOverlay::new(vec![(
                "HTTP_PROXY".into(),
                format!("http://{}:tok@127.0.0.1:9", c.call_id),
            )])
            .expect("valid overlay")
        }));
        sb.set_call_context(Some(ctx("call-7")));
        let cmd = sb.tool_command("true", &[]).expect("command");
        let env = env_of(&cmd);
        assert!(
            env.contains(&(
                "HTTP_PROXY".into(),
                Some("http://call-7:tok@127.0.0.1:9".into())
            )),
            "{env:?}"
        );

        // Cleared context ⇒ no overlay, even with the provider still installed.
        sb.set_call_context(None);
        let cmd = sb.tool_command("true", &[]).expect("command");
        assert!(!env_of(&cmd).iter().any(|(k, _)| k == "HTTP_PROXY"));
    }

    #[test]
    fn a_stripped_key_is_refused_at_overlay_construction() {
        for bad in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
        ] {
            assert!(
                EnvOverlay::new(vec![(bad.into(), "x".into())]).is_err(),
                "{bad} accepted"
            );
        }
        assert!(EnvOverlay::new(vec![("HTTPS_PROXY".into(), "x".into())]).is_ok());
    }

    /// The sandbox's own strip list includes the configured provider key var, which a bare
    /// `EnvOverlay::new` cannot know. A provider that hands back such a key fails the spawn closed.
    #[test]
    fn an_overlay_naming_the_configured_key_var_fails_the_spawn() {
        let mut sb = Sandbox::host(key_vars(Some("MY_PROVIDER_KEY")));
        sb.set_env_provider(Box::new(|_: &CallContext| {
            EnvOverlay::new(vec![("MY_PROVIDER_KEY".into(), "leak".into())]).unwrap()
        }));
        sb.set_call_context(Some(ctx("c")));
        assert!(sb.tool_command("true", &[]).is_err());
    }

    #[test]
    fn without_an_overlay_the_environment_is_unchanged() {
        let strip = key_vars(None);
        let mut expected = Command::new("true");
        restrict_env(&mut expected, &strip);

        let mut sb = Sandbox::host(strip.clone());
        let plain = env_of(&sb.tool_command("true", &[]).unwrap());
        // A context with no provider installed changes nothing either.
        sb.set_call_context(Some(ctx("c")));
        let with_ctx = env_of(&sb.tool_command("true", &[]).unwrap());

        let mut want = env_of(&expected);
        // `hardened_command` adds its `LD_*` removals on top of what `restrict_env` sets.
        let mut plain_sorted = plain.clone();
        plain_sorted.retain(|(k, _)| !k.starts_with("LD_"));
        want.sort();
        plain_sorted.sort();
        assert_eq!(plain_sorted, want);
        assert_eq!(plain, with_ctx);
    }
}
