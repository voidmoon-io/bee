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

/// What the interception session plugs into the sandbox so a consented target-scope widening
/// reaches the proxy (019 US3): compile the widened policy's proxy scope, and push the worker's new
/// scope. The kernel half — reloading the sidecar — is the sandbox's own.
pub trait HttpScopeHook: Send + Sync {
    /// The proxy scope's kernel policy and the worker's scope for `policy`.
    fn compile(
        &self,
        policy: &bee_core::Policy,
    ) -> Result<(bee_core::CompiledPolicy, bee_core::compiler::HttpScope), String>;
    /// Tell the worker; `Err` if it did not acknowledge.
    fn update<'a>(
        &'a self,
        scope: bee_core::compiler::HttpScope,
    ) -> futures_util::future::BoxFuture<'a, Result<(), String>>;
}

/// Computes the [`EnvOverlay`] for a call. Installed by the harness only (019 interception).
pub type EnvProvider = Box<dyn Fn(&CallContext) -> EnvOverlay + Send + Sync>;

/// Work the harness does at the edges of every tool call, awaited before the call's children can
/// spawn and after they are done (019 P3). The interception proxy issues the call's credential in
/// `begin` and revokes it in `end`; `begin` must finish first, or a child could reach the proxy
/// before its credential exists.
pub trait CallHooks: Send + Sync {
    fn begin<'a>(&'a self, call: &'a CallContext) -> futures_util::future::BoxFuture<'a, ()>;
    fn end<'a>(&'a self, call: &'a CallContext) -> futures_util::future::BoxFuture<'a, ()>;
    /// Proxy-layer events the call produced, collected once [`CallHooks::end`] has returned.
    fn take_events(&self, _call: &CallContext) -> Vec<crate::proxy_event::ProxyEvent> {
        Vec::new()
    }
    /// Lines bee itself adds to the conversation at the top of a turn — e.g. "3 new passive leads"
    /// (019 US8). Bee's own words only: never text from a target.
    fn turn_notes(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Everything that decides a tool child's environment: what is stripped, and what — for the current
/// call — is added back.
#[derive(Default)]
struct ChildEnv {
    strip_env: Vec<String>,
    call: Option<CallContext>,
    provider: Option<EnvProvider>,
    hooks: Option<std::sync::Arc<dyn CallHooks>>,
    http_scope: Option<std::sync::Arc<dyn HttpScopeHook>>,
}

impl ChildEnv {
    fn new(strip_env: Vec<String>) -> Self {
        ChildEnv {
            strip_env,
            ..Default::default()
        }
    }

    /// Clear `cmd`'s environment to the inherited allowlist, then apply the overlay for `call` (the
    /// current tool call unless one is named).
    fn apply(&self, cmd: &mut Command, call: Option<&CallContext>) -> Result<(), SpawnError> {
        restrict_env(cmd, &self.strip_env);
        if let (Some(provider), Some(call)) = (&self.provider, call.or(self.call.as_ref())) {
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
    /// Scripted audit batches, popped one per drain (024 R1). Test-only: a batch can fabricate the
    /// denials that drive grants, so this never compiles into a shipping build.
    #[cfg(feature = "test-support")]
    scripted: Option<std::sync::Arc<ScriptedAudit>>,
}

/// Audit batches a host test hands the sandbox in place of a kernel (024 R1, `test-support` only).
///
/// Each [`Sandbox::drain_audit`] pops one batch from `tool`, and each
/// [`Sandbox::drain_sidecar_audit`] one from `proxy`; an empty queue drains nothing, as a real host
/// sandbox does.
///
/// **Dangerous outside tests.** A host sandbox has no kernel to override, but a scripted denial is
/// read exactly like a kernel one: it drives reactive escalation, which grants within the ceiling,
/// reloads the policy and retries the call. Fabricated audit is fabricated authority, which is why
/// this compiles only under `test-support` and never ships.
///
/// **A simplification of the real drains.** A kernel drain returns everything buffered, and the
/// enforced sidecar drain also moves pending tool-scope events aside for the next tool drain. Here
/// each drain returns exactly one queued batch, so a test controls *which* drain sees an event (how
/// the late-event cases are written). A batch queued beyond the drains a call makes is not lost: it
/// is returned to the next call's first drain.
#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct ScriptedAudit {
    tool: std::sync::Mutex<std::collections::VecDeque<Vec<AuditEvent>>>,
    proxy: std::sync::Mutex<std::collections::VecDeque<Vec<AuditEvent>>>,
}

#[cfg(feature = "test-support")]
impl ScriptedAudit {
    /// Queue the batch the next tool-scope drain returns.
    pub fn push_tool(&self, batch: Vec<AuditEvent>) {
        self.tool.lock().expect("scripted audit").push_back(batch);
    }

    /// Queue the batch the next sidecar (proxy-scope) drain returns.
    pub fn push_proxy(&self, batch: Vec<AuditEvent>) {
        self.proxy.lock().expect("scripted audit").push_back(batch);
    }

    fn pop_tool(&self) -> Vec<AuditEvent> {
        self.tool
            .lock()
            .expect("scripted audit")
            .pop_front()
            .unwrap_or_default()
    }

    fn pop_proxy(&self) -> Vec<AuditEvent> {
        self.proxy
            .lock()
            .expect("scripted audit")
            .pop_front()
            .unwrap_or_default()
    }
}

/// A second kernel scope beside the tool scope, holding one long-lived harness child (019 P4,
/// research R2) — today the interception proxy worker, in its *proxy scope*.
///
/// A bridge: the 018 Supervisor generalises "several scopes per session" and absorbs this, deleting
/// the field (task T092). Until then exactly one sidecar is supported, on [`EnforcedSandbox`] only.
#[cfg(feature = "enforce")]
pub struct SidecarScope {
    /// Tags this scope's audit events (`"proxy"`).
    pub label: String,
    pub scope: bee_userspace::Scope,
    /// The plan currently installed, kept so a failed widening can be rolled back to it.
    pub plan: bee_userspace::EnforcementPlan,
}

/// Why a sandbox cannot host a sidecar scope. Refusing is the fail-closed answer: a proxy that no
/// kernel scope confines is an unconfined deputy (Constitution III).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("sidecar scope unsupported: {reason}")]
pub struct SidecarUnsupported {
    pub reason: &'static str,
}

/// An audit event from the drain, tagged with the scope it came from: `None` for the tool scope,
/// the sidecar's label otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedAudit {
    pub event: AuditEvent,
    pub scope_label: Option<String>,
}

/// Route one drained event (019 P4). The tool scope's events pass untagged; the sidecar's are tagged
/// with its label, which also becomes the event's `scope_id` so the tag survives into transcripts;
/// every other cgroup's are dropped. With no sidecar this is exactly the single-scope filter it
/// replaces.
pub fn route_audit(
    ev: &AuditEvent,
    tool_cg: u64,
    sidecar: Option<(u64, &str)>,
) -> Option<TaggedAudit> {
    if ev.cgroup_id == tool_cg {
        return Some(TaggedAudit {
            event: ev.clone(),
            scope_label: None,
        });
    }
    match sidecar {
        Some((cg, label)) if ev.cgroup_id == cg => {
            let mut event = ev.clone();
            event.scope_id = Some(label.to_string());
            Some(TaggedAudit {
                event,
                scope_label: Some(label.to_string()),
            })
        }
        _ => None,
    }
}

/// The cgroup a sidecar reload writes to. Never falls back to the tool scope: reloading the tool
/// scope with the proxy scope's rules would hand tool children the targets directly.
pub fn sidecar_reload_target(_tool_cg: u64, sidecar_cg: Option<u64>) -> Result<u64, String> {
    sidecar_cg.ok_or_else(|| "no sidecar scope to reload".to_string())
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
    /// The optional second scope (019 P4). Its events are drained alongside the tool scope's and
    /// buffered here until [`Sandbox::drain_sidecar_audit`] collects them.
    sidecar: Option<SidecarScope>,
    sidecar_audit: Vec<AuditEvent>,
    /// Tool-scope events a sidecar drain pulled off the shared ring, held for the next
    /// [`Sandbox::drain_audit`] — dropping them would hide denials from the audit trail and from
    /// reactive escalation.
    tool_audit: Vec<AuditEvent>,
    /// The session proxy's loopback port, when `[policy.http]` is active (019). Every recompile of
    /// the tool scope — a grant's reload included — re-applies it as the scope's only network rule;
    /// without it the plan refuses to install (`ProxyLoopbackMissing`).
    proxy_port: Option<u16>,
    /// The session CA bundle the tool scope must be able to read (019 US4), re-granted on reload.
    ca_bundle: Option<std::path::PathBuf>,
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
    /// Drain the ring once: return the tool scope's events, buffer the sidecar's (019 P4).
    fn drain_into_buffers(&mut self) -> Vec<AuditEvent> {
        let tool_cg = self.scope.cgroup_id;
        let side = self
            .sidecar
            .as_ref()
            .map(|s| (s.scope.cgroup_id, s.label.clone()));
        let mut tool = Vec::new();
        let sidecar_buf = &mut self.sidecar_audit;
        self.reader.drain(&mut |ev| {
            let routed = route_audit(&ev, tool_cg, side.as_ref().map(|(c, l)| (*c, l.as_str())));
            match routed {
                Some(TaggedAudit {
                    event,
                    scope_label: None,
                }) => tool.push(event),
                Some(TaggedAudit { event, .. }) => sidecar_buf.push(event),
                None => {}
            }
        });
        tool
    }

    fn reload_sidecar(&mut self, policy: &bee_core::CompiledPolicy) -> Result<(), String> {
        use bee_userspace::{EnforcementPlan, ScopeMode};
        let plan = EnforcementPlan::prepare(policy, ScopeMode::Enforce)
            .map_err(|e| format!("sidecar reload plan: {e}"))?;
        self.install_sidecar_plan(plan)
    }

    fn install_sidecar_plan(&mut self, plan: bee_userspace::EnforcementPlan) -> Result<(), String> {
        let target = sidecar_reload_target(
            self.scope.cgroup_id,
            self.sidecar.as_ref().map(|s| s.scope.cgroup_id),
        )?;
        let side = self.sidecar.as_mut().expect("target implies a sidecar");
        let new_keys = self
            .engine
            .reload_scope(target, &plan, &side.scope.net_keys)
            .map_err(|e| format!("sidecar reload scope: {e}"))?;
        side.scope.net_keys = new_keys;
        side.plan = plan;
        Ok(())
    }

    /// Compile `policy` and hand the fresh plan to `Engine::reload_scope`, updating the scope's
    /// tracked `NET_ALLOW` keys. On any error the prior enforced maps are left in place.
    fn reload(&mut self, policy: &bee_core::Policy) -> Result<(), String> {
        use bee_userspace::{EnforcementPlan, ScopeMode, SystemResolver};
        let resolver = SystemResolver::current();
        let mut compiled = policy
            .compile(&resolver)
            .map_err(|e| format!("reload compile: {e}"))?;
        if let Some(port) = self.proxy_port {
            compiled = bee_core::compiler::with_proxy_loopback(compiled, port);
        }
        if let Some(b) = &self.ca_bundle {
            compiled.fs.push(bee_core::FsPrimitive::read_grant(b));
        }
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
            #[cfg(feature = "test-support")]
            scripted: None,
        })
    }

    /// A host sandbox whose drains return `audit`'s scripted batches (024 R1). Test-only.
    #[cfg(feature = "test-support")]
    pub fn host_scripted(strip_env: Vec<String>, audit: std::sync::Arc<ScriptedAudit>) -> Self {
        Sandbox::Host(HostSandbox {
            env: ChildEnv::new(strip_env),
            scripted: Some(audit),
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

    /// Start a tool call: set its context, then run the harness's [`CallHooks::begin`] (019). The loop
    /// calls this before `ToolRegistry::execute` and [`end_call`](Self::end_call) after the call and
    /// its one possible retry.
    pub async fn begin_call(&mut self, call: CallContext) {
        let hooks = self.child_env().hooks.clone();
        if let Some(h) = &hooks {
            h.begin(&call).await;
        }
        self.child_env_mut().call = Some(call);
    }

    /// End the current tool call: run [`CallHooks::end`], clear the context, and return the proxy
    /// events the call produced (019 T045) — kept apart from kernel audit by type.
    pub async fn end_call(&mut self) -> Vec<crate::proxy_event::ProxyEvent> {
        let hooks = self.child_env().hooks.clone();
        let call = self.child_env_mut().call.take();
        match (&hooks, &call) {
            (Some(h), Some(c)) => {
                h.end(c).await;
                h.take_events(c)
            }
            _ => Vec::new(),
        }
    }

    /// Install the interception session's scope hook (019 US3).
    pub fn set_http_scope_hook(&mut self, hook: std::sync::Arc<dyn HttpScopeHook>) {
        self.child_env_mut().http_scope = Some(hook);
    }

    /// Apply `policy`'s `[policy.http]` to the running proxy, atomically across both layers: reload
    /// the sidecar scope's kernel rules, then update the worker; if the worker update fails, put the
    /// previous kernel plan back and return the error (019 T065). Advisory sessions have no sidecar,
    /// so only the worker is updated.
    pub async fn apply_http_scope(&mut self, policy: &bee_core::Policy) -> Result<(), String> {
        let hook = self
            .child_env()
            .http_scope
            .clone()
            .ok_or("this session has no interception proxy")?;
        let (proxy_scope, scope) = hook.compile(policy)?;
        #[cfg(feature = "enforce")]
        let previous = self.sidecar_plan().cloned();
        #[cfg(feature = "enforce")]
        if previous.is_some() {
            self.reload_sidecar(&proxy_scope)?;
        }
        #[cfg(not(feature = "enforce"))]
        let _ = proxy_scope;
        let updated = hook.update(scope).await;
        #[cfg(feature = "enforce")]
        if let (Err(e), Some(p)) = (&updated, previous) {
            if let Err(r) = self.reload_sidecar_plan(&p) {
                return Err(format!(
                    "{e}; and the proxy scope rollback also failed: {r}"
                ));
            }
        }
        updated
    }

    /// Harness notes for the top of the next turn (019 US8).
    pub fn turn_notes(&self) -> Vec<String> {
        self.child_env()
            .hooks
            .as_ref()
            .map(|h| h.turn_notes())
            .unwrap_or_default()
    }

    /// Install the harness's per-call hooks (019 interception).
    pub fn set_call_hooks(&mut self, hooks: std::sync::Arc<dyn CallHooks>) {
        self.child_env_mut().hooks = Some(hooks);
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
            sidecar: None,
            sidecar_audit: Vec::new(),
            tool_audit: Vec::new(),
            proxy_port: None,
            ca_bundle: None,
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

    /// Whether this sandbox can host a sidecar scope (019 P4). Only an [`EnforcedSandbox`] can: a host
    /// sandbox has no kernel scope to give it, and the concurrent runner's engine is shared and owned
    /// elsewhere (018 generalises this).
    pub fn sidecar_supported(&self) -> Result<(), SidecarUnsupported> {
        match self {
            Sandbox::Host(_) => Err(SidecarUnsupported {
                reason: "host sandbox has no kernel scope",
            }),
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(_) => Ok(()),
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(_) => Err(SidecarUnsupported {
                reason: "concurrent runner; see specs/018",
            }),
        }
    }

    /// Attach a sidecar scope created on this sandbox's engine before it moved in (019 P4). Refused,
    /// fail-closed, on any sandbox that cannot host one; the scope is handed back so the caller can
    /// tear it down.
    #[cfg(feature = "enforce")]
    #[allow(clippy::result_large_err)]
    pub fn with_sidecar(
        self,
        sidecar: SidecarScope,
    ) -> Result<Self, (Self, SidecarScope, SidecarUnsupported)> {
        if let Err(e) = self.sidecar_supported() {
            return Err((self, sidecar, e));
        }
        match self {
            Sandbox::Enforced(mut e) => {
                e.sidecar = Some(sidecar);
                Ok(Sandbox::Enforced(e))
            }
            other => {
                let e = SidecarUnsupported {
                    reason: "not an enforced sandbox",
                };
                Err((other, sidecar, e))
            }
        }
    }

    /// Record the session proxy's loopback port so a reload of the tool scope keeps it as the only
    /// network rule (019). A no-op on a sandbox with no kernel scope.
    #[cfg_attr(not(feature = "enforce"), allow(unused_variables))]
    pub fn set_proxy_loopback(&mut self, port: u16, ca_bundle: Option<std::path::PathBuf>) {
        #[cfg(feature = "enforce")]
        if let Sandbox::Enforced(e) = self {
            e.proxy_port = Some(port);
            e.ca_bundle = ca_bundle;
        }
        #[cfg(not(feature = "enforce"))]
        let _ = ca_bundle;
    }

    /// The sidecar's cgroup id, when one is attached.
    #[cfg(feature = "enforce")]
    pub fn sidecar_cgroup_id(&self) -> Option<u64> {
        match self {
            Sandbox::Enforced(e) => e.sidecar.as_ref().map(|s| s.scope.cgroup_id),
            _ => None,
        }
    }

    /// A fork-safe `pre_exec` closure joining the sidecar scope — what the sidecar's one child is
    /// spawned with. `Err` when there is no sidecar.
    #[cfg(feature = "enforce")]
    pub fn sidecar_join_closure(
        &self,
    ) -> Result<impl Fn() -> io::Result<()> + Send + Sync + 'static, String> {
        match self {
            Sandbox::Enforced(e) => match &e.sidecar {
                Some(s) => s.scope.join_closure().map_err(|err| err.to_string()),
                None => Err("no sidecar scope".into()),
            },
            _ => Err("no sidecar scope".into()),
        }
    }

    /// Recompile `policy` into the **sidecar** scope's maps (019 US3). On error the prior maps stay
    /// in place, exactly as [`Sandbox::reload`] does for the tool scope.
    #[cfg_attr(not(feature = "enforce"), allow(unused_variables))]
    pub fn reload_sidecar(&mut self, policy: &bee_core::CompiledPolicy) -> Result<(), String> {
        match self {
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => e.reload_sidecar(policy),
            _ => Err("no sidecar scope to reload".into()),
        }
    }

    /// Restore the sidecar's previous plan — the rollback after a widening the worker could not
    /// apply (019 US3). Reinstalls exactly what was there.
    #[cfg(feature = "enforce")]
    pub fn reload_sidecar_plan(
        &mut self,
        plan: &bee_userspace::EnforcementPlan,
    ) -> Result<(), String> {
        match self {
            Sandbox::Enforced(e) => e.install_sidecar_plan(plan.clone()),
            _ => Err("no sidecar scope to reload".into()),
        }
    }

    /// The sidecar's currently installed plan, for a caller that wants to roll back to it.
    #[cfg(feature = "enforce")]
    pub fn sidecar_plan(&self) -> Option<&bee_userspace::EnforcementPlan> {
        match self {
            Sandbox::Enforced(e) => e.sidecar.as_ref().map(|s| &s.plan),
            _ => None,
        }
    }

    /// The sidecar scope's kernel events drained since the last call, each with `scope_id` set to
    /// the sidecar's label. Kept apart from [`drain_audit`](Self::drain_audit) on purpose: a proxy
    /// scope denial is not the tool call's denial and must never drive tool-scope escalation.
    pub fn drain_sidecar_audit(&mut self) -> Vec<AuditEvent> {
        match self {
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => {
                let tool = e.drain_into_buffers();
                e.tool_audit.extend(tool);
                std::mem::take(&mut e.sidecar_audit)
            }
            #[cfg(feature = "test-support")]
            Sandbox::Host(HostSandbox {
                scripted: Some(s), ..
            }) => s.pop_proxy(),
            _ => Vec::new(),
        }
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
        self.tool_command_for(None, program, args)
    }

    /// [`tool_command`](Self::tool_command) for a child that belongs to `call` rather than to the
    /// current tool call — a long-lived MCP stdio server, attributed `mcp:<server>` (019 T042). Same
    /// scope, same hardening, same environment rules.
    pub fn tool_command_as(
        &self,
        call: &CallContext,
        program: &str,
        args: &[String],
    ) -> Result<Command, SpawnError> {
        self.tool_command_for(Some(call), program, args)
    }

    /// Run [`CallHooks::begin`] for a side call (not the loop's current one) — e.g. issue an MCP
    /// server's proxy credential before it spawns.
    pub async fn begin_side_call(&self, call: &CallContext) {
        if let Some(h) = self.child_env().hooks.clone() {
            h.begin(call).await;
        }
    }

    fn tool_command_for(
        &self,
        call: Option<&CallContext>,
        program: &str,
        args: &[String],
    ) -> Result<Command, SpawnError> {
        match self {
            Sandbox::Host(h) => {
                // No cgroup join; hardening + env strip only.
                let mut cmd = hardened_command::<fn() -> io::Result<()>>(program, args, None)?;
                h.env.apply(&mut cmd, call)?;
                Ok(cmd)
            }
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => {
                let join = e
                    .scope
                    .join_closure()
                    .map_err(|err| SpawnError::Io(io::Error::other(err.to_string())))?;
                let mut cmd = hardened_command(program, args, Some(join))?;
                e.env.apply(&mut cmd, call)?;
                Ok(cmd)
            }
            #[cfg(feature = "concurrent")]
            Sandbox::Concurrent(c) => {
                let join = c
                    .scope
                    .join_closure()
                    .map_err(|err| SpawnError::Io(io::Error::other(err.to_string())))?;
                let mut cmd = hardened_command(program, args, Some(join))?;
                c.env.apply(&mut cmd, call)?;
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
            #[cfg(feature = "test-support")]
            Sandbox::Host(HostSandbox {
                scripted: Some(s), ..
            }) => s.pop_tool(),
            Sandbox::Host(_) => Vec::new(),
            #[cfg(feature = "enforce")]
            Sandbox::Enforced(e) => {
                let mut out = std::mem::take(&mut e.tool_audit);
                out.extend(e.drain_into_buffers());
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
            // Sidecar scope first, then the tool scope (019 P4). The caller has already stopped the
            // sidecar's process; the kill here is the backstop for anything it left behind. A
            // sidecar failure is reported, but the tool scope is still torn down — leaving it up
            // would compound one escape with a second.
            let side = e.sidecar.as_ref().map(|s| {
                s.scope
                    .teardown()
                    .map_err(|err| format!("sidecar scope teardown failed: {err}"))
            });
            let tool = e
                .scope
                .teardown()
                .map_err(|err| format!("scope teardown failed: {err}"));
            return match (side, tool) {
                (Some(Err(a)), Err(b)) => Err(format!("{a}; {b}")),
                (Some(Err(a)), Ok(())) => Err(a),
                (_, r) => r,
            };
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

    fn ev(cg: u64) -> AuditEvent {
        AuditEvent {
            ts: "1970-01-01T00:00:00Z".into(),
            scope_id: Some("bee-session-1".into()),
            cgroup_id: cg,
            pid: Some(1),
            tgid: Some(1),
            op: "connect".into(),
            decision: "denied".into(),
            errno: -1,
            target: "10.0.0.5:443".into(),
        }
    }

    // 019 P4 (T016): the drain keeps the tool scope's events untagged, tags the sidecar's with its
    // label, and drops every other cgroup's — so a second scope can never contaminate the first's
    // audit, and nothing from an unrelated scope leaks into either.
    #[test]
    fn route_audit_separates_tool_and_sidecar_scopes() {
        let side = Some((20u64, "proxy"));
        let t = route_audit(&ev(10), 10, side).expect("tool event kept");
        assert_eq!(t.scope_label, None);
        assert_eq!(t.event.cgroup_id, 10);

        let s = route_audit(&ev(20), 10, side).expect("sidecar event kept");
        assert_eq!(s.scope_label.as_deref(), Some("proxy"));
        assert_eq!(s.event.scope_id.as_deref(), Some("proxy"));

        assert!(
            route_audit(&ev(30), 10, side).is_none(),
            "foreign cgroup dropped"
        );
    }

    #[test]
    fn route_audit_without_a_sidecar_is_the_single_scope_filter() {
        assert!(route_audit(&ev(10), 10, None).is_some());
        assert!(route_audit(&ev(20), 10, None).is_none());
        assert_eq!(route_audit(&ev(10), 10, None).unwrap().event, ev(10));
    }

    #[test]
    fn a_sidecar_reload_targets_the_sidecar_cgroup() {
        assert_eq!(sidecar_reload_target(10, Some(20)), Ok(20));
        assert_ne!(sidecar_reload_target(10, Some(20)), Ok(10));
        assert!(
            sidecar_reload_target(10, None).is_err(),
            "no sidecar ⇒ refuse, never the tool scope"
        );
    }

    // T018: the concurrent runner and the host sandbox refuse a sidecar — fail closed rather than run
    // a proxy that no kernel scope confines.
    #[test]
    fn a_host_sandbox_refuses_a_sidecar_scope() {
        let sb = Sandbox::host(Vec::new());
        assert!(matches!(
            sb.sidecar_supported(),
            Err(SidecarUnsupported { .. })
        ));
    }

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
