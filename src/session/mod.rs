//! The Session builder (024 FR-006–FR-012, contracts/session-builder.md, research R5).
//!
//! One library function, [`build`], turns a [`SessionSpec`] into a running [`Session`]: skill grants,
//! the `[policy.http]` advisory, the sandbox, the Interceptor, the tool surface, MCP servers,
//! escalation and the system prompt, in one order, for every entry point. Entry points differ only in
//! what they put in the spec. [`Session::shutdown`] tears the parts down in one order — MCP servers,
//! then the Interceptor, then the scopes — and a `Drop` guard does what it can of that if a session is
//! dropped without it.
//!
//! The loops (`run_loop`, `run_exchange`) still take the session's parts — its registry, sandbox and
//! escalation — rather than the session itself; routing them through `Session` would rewrite both
//! loops again for no change in behaviour.

pub mod parts;
pub mod spec;

pub use parts::http_advisory;
pub use spec::{refuse_unsupported, BuildError, Enforcement, EntryPoint, SessionSpec};

use std::sync::Arc;

use crate::grants::escalate::{
    DenialEscalationHook, LoopEscalation, ProxyRefusalHook, SkillEscalationHook,
};
use crate::grants::Ttl;
use crate::hooks::LoopHook;
use crate::sandbox::Sandbox;
use crate::skills::SkillRegistry;
use crate::tools::{ToolDeps, ToolRegistry};
use crate::turn::ToolRefresh;

/// A serializable view of a [`Session`] (see [`Session::snapshot`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionSnapshot {
    pub tools: Vec<crate::tools::SurfaceEntry>,
    pub policy_fs: Option<Vec<String>>,
    pub ceiling_fs: Option<Vec<String>>,
    pub escalation_timeout_secs: Option<u64>,
    pub lease_turns: Option<u32>,
    pub system_prompt: String,
    pub http_advisory: Option<String>,
}

/// A running session: what the loops run on, and what must be torn down after.
pub struct Session {
    pub sandbox: Sandbox,
    pub registry: ToolRegistry,
    /// Escalation: the floor, the ceiling, the hooks that propose grants, and who decides them.
    pub escalation: Option<LoopEscalation>,
    pub skills: Arc<SkillRegistry>,
    /// The base prompt plus the notes for the tools the session holds — the same for every entry point.
    pub system_prompt: String,
    /// Why `[policy.http]` is enforced by the proxy alone, when it is.
    pub http_advisory: Option<String>,
    /// The source MCP tools are refreshed from at turn start.
    pub tool_refresh: Option<Arc<dyn ToolRefresh>>,
    #[cfg(feature = "intercept")]
    pub http: Option<crate::intercept::session::HttpSession>,
    #[cfg(feature = "mcp")]
    pub mcp: Option<Arc<crate::mcp::McpBridge>>,
    closed: bool,
    /// Each teardown stage, in the order it ran (`test-support` only).
    #[cfg(feature = "test-support")]
    pub teardown_log: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl Session {
    /// Tear the session down in its one order (FR-012): MCP servers — whose children live in the tool
    /// scope — then the Interceptor, whose proxy scope goes before the tool scope, then the scopes. A
    /// scope that will not empty is returned, never swallowed: something outlived enforcement.
    pub async fn shutdown(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.stage("mcp");
        self.tool_refresh = None;
        #[cfg(feature = "mcp")]
        drop(self.mcp.take());
        self.stage("interceptor");
        #[cfg(feature = "intercept")]
        if let Some(h) = self.http.take() {
            h.shutdown().await;
        }
        self.stage("scopes");
        self.sandbox.teardown().map_err(|e| e.to_string())
    }

    /// What every entry point's session must agree on (SC-001): the tools and their dependencies, the
    /// escalation floor and ceiling, how grants are decided, and the system prompt. Serializable, so
    /// two sessions compare as data; the Operator — the one thing allowed to differ — is not in it.
    pub fn snapshot(&self) -> SessionSnapshot {
        let esc = self.escalation.as_ref();
        SessionSnapshot {
            tools: self.registry.surface(),
            policy_fs: esc.map(|e| e.base.filesystem.keys().cloned().collect()),
            ceiling_fs: esc.map(|e| e.ceiling.filesystem.keys().cloned().collect()),
            escalation_timeout_secs: esc.map(|e| e.timeout.as_secs()),
            lease_turns: esc.and_then(|e| match e.default_ttl {
                Ttl::Turns(n) => Some(n),
                Ttl::Forever => None,
            }),
            system_prompt: self.system_prompt.clone(),
            http_advisory: self.http_advisory.clone(),
        }
    }

    /// The `[policy.http]` record for a transcript (019 T044).
    pub fn http_header(&self) -> Option<crate::transcript::HttpSessionHeader> {
        #[cfg(feature = "intercept")]
        if let Some(h) = &self.http {
            return Some(crate::transcript::HttpSessionHeader {
                enforcement: h.interceptor.enforcement().label().into(),
                advisory_reason: self.http_advisory.clone(),
                advisory_acknowledged: self.http_advisory.is_some(),
            });
        }
        None
    }

    #[cfg_attr(not(feature = "test-support"), allow(unused_variables))]
    fn stage(&self, name: &'static str) {
        #[cfg(feature = "test-support")]
        self.teardown_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(name);
    }
}

impl Drop for Session {
    /// A session dropped without [`Session::shutdown`] — an error path — still releases its parts in
    /// the same order, as far as that can be done without awaiting: MCP servers, then the scopes. The
    /// proxy worker is reaped when its handle drops.
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.stage("mcp");
        self.tool_refresh = None;
        #[cfg(feature = "mcp")]
        drop(self.mcp.take());
        self.stage("interceptor");
        #[cfg(feature = "intercept")]
        drop(self.http.take());
        self.stage("scopes");
        let _ = self.sandbox.teardown();
    }
}

/// Build a session from `spec` (contracts/session-builder.md). `report` receives the lines an operator
/// should see while it is built — skill warnings, grant outcomes, the advisory banner — in the
/// wording the headless progress stream has always used. Every refusal happens before a scope exists.
pub async fn build(spec: SessionSpec, report: &dyn Fn(&str)) -> Result<Session, BuildError> {
    // 1. Refuse what this entry point cannot provide.
    refuse_unsupported(&spec)?;

    // 2. Skills, the same discovery for every entry point. A malformed skill warns; it never aborts.
    let skills = Arc::new(SkillRegistry::discover(&spec.skill_roots));
    for w in skills.warnings() {
        report(&format!(
            "skill warning: {}: {}",
            w.path.display(),
            w.reason
        ));
    }

    // 3. Start-up grants, before the scope compiles, so the widened policy is what gets enforced.
    let grants = parts::resolve_grants(&spec, &skills).await;
    for name in &grants.granted {
        report(&format!(
            "skill grant: '{name}' capabilities granted (within ceiling)"
        ));
    }
    for (name, reason) in &grants.refused {
        report(&format!("skill grant: '{name}' refused — {reason}"));
    }

    // 4. The `[policy.http]` advisory, once.
    let http_advisory = http_advisory(&grants.policy, spec.enforcement, spec.http_scope_advisory)?;
    #[cfg(feature = "intercept")]
    if let Some(reason) = &http_advisory {
        report(&crate::intercept::session::advisory_banner(reason));
    }

    // 5. The tool surface, built from the session's dependencies (FR-013). The Interceptor joins
    //    below, once it is running; `set_deps` rebuilds the tools named before it.
    let run_id = format!("{}-{}", spec.label, std::process::id());
    // The struct update supplies the feature-gated fields, which a slim build does not have.
    #[allow(clippy::needless_update)]
    let deps = ToolDeps {
        ctf_flag: spec.ctf_flag.clone(),
        // Only model-facing skills make a `skill` tool worth offering.
        skills: skills
            .model_facing()
            .next()
            .is_some()
            .then(|| skills.clone()),
        ..ToolDeps::default()
    }
    .with_security(&spec.security, Some(&grants.policy), &run_id);
    let mut registry = ToolRegistry::with_deps(Arc::new(deps));
    for tool in spec.tools.iter().chain(&grants.tools) {
        // Validation rejected unknown names before a session was asked for.
        let _ = registry.register(tool);
    }
    let _ = registry.register("skill");

    // 6. The escalation floor is the grant-widened policy, before it moves into the scope.
    let escalation = escalation(&spec, &grants.policy, &skills);

    // 7. The sandbox, and with `[policy.http]` the proxy listener and proxy scope.
    let label = parts::sanitize(&spec.label);
    let scope_id = match spec.entry {
        EntryPoint::Repl | EntryPoint::Tui => format!("bee-session-{}", std::process::id()),
        EntryPoint::Headless | EntryPoint::Batch { .. } => {
            format!("bee-episode-{label}-{}", std::process::id())
        }
    };
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut, unused_variables))]
    let (mut sandbox, http_prepared) =
        parts::build_sandbox(&spec, &grants.policy, &scope_id).map_err(BuildError)?;

    // 8. The proxy worker, in its sidecar scope or advisory, and the HTTP tools' handle on it.
    #[cfg(feature = "intercept")]
    let http = match http_prepared {
        Some(prepared) => {
            let enforcement = match &http_advisory {
                Some(reason) => crate::intercept::sidecar::Enforcement::Advisory {
                    reason: reason.clone(),
                },
                None => crate::intercept::sidecar::Enforcement::Kernel,
            };
            let session_id = format!("{label}-{}", std::process::id());
            match crate::intercept::session::start(
                prepared,
                &mut sandbox,
                &session_id,
                &spec.workdir,
                enforcement,
            )
            .await
            {
                Ok(h) => {
                    let deps = (**registry.deps())
                        .clone()
                        .with_interceptor(h.interceptor.clone());
                    registry.set_deps(Arc::new(deps));
                    Some(h)
                }
                Err(detail) => {
                    let _ = sandbox.teardown();
                    return Err(BuildError(format!("HTTP interception: {detail}")));
                }
            }
        }
        None => None,
    };

    // 9. MCP servers, once the sandbox exists: their stdio children run in its scope.
    #[cfg(feature = "mcp")]
    let mcp = if spec.mcp.enabled {
        let bridge = Arc::new(crate::mcp::McpBridge::connect(spec.mcp.clone(), &sandbox).await);
        bridge.register_into(&mut registry);
        Some(bridge)
    } else {
        None
    };
    #[cfg(feature = "mcp")]
    let tool_refresh = mcp.clone().map(|b| b as Arc<dyn ToolRefresh>);
    #[cfg(not(feature = "mcp"))]
    let tool_refresh = None;

    // 10. The system prompt, with the notes for the tools the session actually holds.
    let system_prompt = crate::repl::effective_system_prompt(&spec.system_prompt, &registry);

    Ok(Session {
        sandbox,
        registry,
        escalation: Some(escalation),
        skills,
        system_prompt,
        http_advisory,
        tool_refresh,
        #[cfg(feature = "intercept")]
        http,
        #[cfg(feature = "mcp")]
        mcp,
        closed: false,
        #[cfg(feature = "test-support")]
        teardown_log: Arc::default(),
    })
}

/// Escalation for a session (007). Widening on a kernel denial or a proxy refusal needs a declared
/// ceiling — the operator's authorization; a skill's `requires` can always be proposed. The ceiling
/// admits each skill directory as readable, as the floor already does.
fn escalation(
    spec: &SessionSpec,
    floor: &bee_core::Policy,
    skills: &Arc<SkillRegistry>,
) -> LoopEscalation {
    let mut ceiling = spec.ceiling.clone().unwrap_or_else(|| floor.clone());
    for s in skills.iter() {
        if let Some(dir) = s.dir.to_str() {
            ceiling
                .filesystem
                .entry(dir.to_string())
                .or_insert(bee_core::Access::Read);
        }
    }
    let widening = spec.ceiling.is_some();
    let hooks: Vec<Box<dyn LoopHook>> = vec![
        Box::new(DenialEscalationHook { enabled: widening }),
        // 019 US3: a proxy refusal proposes exactly the refused host:port, within the ceiling's
        // `[policy.http]`.
        Box::new(ProxyRefusalHook { enabled: widening }),
        Box::new(SkillEscalationHook::new(skills.clone())),
    ];
    LoopEscalation {
        base: floor.clone(),
        ceiling,
        hooks,
        consent: spec.consent.clone(),
        timeout: spec.consent_timeout,
        default_ttl: spec.lease_turns.map_or(Ttl::Forever, Ttl::Turns),
    }
}
