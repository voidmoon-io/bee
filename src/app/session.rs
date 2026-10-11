//! Session construction, shared by `bee run` and `bee repl` (consolidation issue 03).
//!
//! `bee-episode` and `bee-repl` each built a session from scratch: set the process non-dumpable,
//! resolve and install the theme, load the provider, read the key from its named variable, build
//! the model. Two copies, in two orders, with two sets of error strings — and when they drifted,
//! the enforcement behaviour of a headless run and an interactive run drifted with them.
//!
//! This is that sequence, once. It takes an [`EffectiveConfig`] and returns the pieces a session
//! runs on. What it deliberately does *not* do is decide anything: the presentation choices, the
//! consent prompting, and the sandbox lifetime belong to the command, because those are the parts
//! that genuinely differ between headless and interactive.

use std::path::Path;
use std::process::ExitCode;

use bee::{model_from_config, set_non_dumpable, Model};

use crate::app::config::EffectiveConfig;

/// Exit codes, from `sysexits.h` — the ones the harness binaries have always used. A CI harness
/// somewhere is reading these, so they are an interface rather than an implementation detail.
pub const EX_USAGE: u8 = 64;
pub const EX_DATAERR: u8 = 65;
// EX_UNAVAILABLE (69) is now chosen in the library, by `bee::episode::exit_code`.
pub const EX_SOFTWARE: u8 = 70;
pub const EX_IOERR: u8 = 74;

/// The constructed pieces of a session: a model to talk to and the name of the variable holding its
/// key, which tool children must not inherit.
pub struct Session {
    pub model: Box<dyn Model>,
    /// The provider's `api_key_env`, or `None` for a keyless provider (`mock`, a local endpoint).
    /// Carried separately because stripping it from tool children is a security property, not a
    /// detail of the model.
    pub key_env: Option<String>,
}

/// Why a session could not be built. Each is a refusal before the provider is contacted.
pub struct SessionError {
    pub detail: String,
    pub code: u8,
}

impl SessionError {
    fn new(detail: impl Into<String>, code: u8) -> Self {
        SessionError {
            detail: detail.into(),
            code,
        }
    }
}

/// Harden the process, install the presentation, and build the model.
///
/// The ordering matters and is the reason this is one function rather than a handful of helpers a
/// command could call in any sequence:
///
/// 1. Non-dumpable first, before anything can read the key out of `/proc/<pid>/environ` (FR-018).
/// 2. The visual gate before anything can render, because the render tool reads the level
///    process-globally and the gate must be in place before the first script evaluates.
/// 3. The theme before anything draws.
/// 4. The model last — it is the first thing that could touch the network.
pub fn build(cfg: &EffectiveConfig, command: &str) -> Result<Session, SessionError> {
    // Non-fatal: env-stripping remains the primary defence, and refusing to start because a
    // hardening nicety failed would trade a real session for a marginal gain.
    if let Err(e) = set_non_dumpable() {
        eprintln!("{command}: warning: could not set non-dumpable: {e}");
    }

    bee::visual_gate::set(cfg.visual);

    if let Some(w) = &cfg.theme_warning {
        eprintln!("{command}: {w}");
    }
    bee::viz::theme::init_theme(cfg.theme.clone());

    // The key comes from its named variable, never from a config file (FR-018). Empty is fine for
    // local endpoints and for `mock`.
    let key_env = (!cfg.provider.api_key_env.is_empty()).then(|| cfg.provider.api_key_env.clone());
    let api_key = match &key_env {
        Some(name) => std::env::var(name).unwrap_or_default(),
        None => String::new(),
    };

    let model = model_from_config(&cfg.provider, &api_key)
        .map_err(|e| SessionError::new(format!("model error: {e}"), EX_SOFTWARE))?;

    Ok(Session { model, key_env })
}

/// Print a session error the way every command should and turn it into an exit code.
pub fn fail(command: &str, e: &SessionError) -> ExitCode {
    eprintln!("{command}: {}", e.detail);
    ExitCode::from(e.code)
}

// --- skills, grants, and the sandbox ----------------------------------------------------------
//
// These lived in `bee-repl`'s binary. They are here because a headless session has a legitimate
// claim on all of them: scenarios already carry a skills list, grant resolution is the same
// attenuation-bounded operation either way, and both kinds of session need a sandbox. What differs
// is only the *consent sink* — an interactive prompt versus a scenario's declared grants — so that
// is the injected part rather than the whole path being duplicated.

use std::sync::Arc;

use bee::skills::{ConsentSink, Skill};
use bee::{Sandbox, SkillRegistry, ToolRegistry};

/// Discover skills from the project and user roots, printing any malformed-skill warnings. A bad
/// skill warns; it never aborts a session.
pub fn discover_skills(cwd: &Path, command: &str) -> Arc<SkillRegistry> {
    let roots = SkillRegistry::default_roots(cwd);
    let skills = Arc::new(SkillRegistry::discover(&roots));
    for w in skills.warnings() {
        eprintln!(
            "{command}: skill warning: {}: {}",
            w.path.display(),
            w.reason
        );
    }
    skills
}

/// Resolve skill capability grants before the scope compiles, and register whatever was granted.
///
/// The base policy is the session's; the ceiling bounds what a skill may add to it. Each
/// within-ceiling request goes to `consent`; beyond-ceiling requests are refused outright. Returns
/// the widened policy to compile, or `None` when there is no base policy to widen.
pub async fn resolve_grants(
    base: Option<&bee_core::Policy>,
    ceiling: Option<&bee_core::Policy>,
    skills: &SkillRegistry,
    registry: &mut ToolRegistry,
    consent: &dyn ConsentSink,
    command: &str,
) -> Option<bee_core::Policy> {
    let base = base?.clone();
    let ceiling = ceiling.cloned().unwrap_or_else(|| base.clone());

    let skill_refs: Vec<&Skill> = skills.iter().collect();
    let mut outcome = bee::skills::resolve_grants(&skill_refs, &base, &ceiling, consent).await;
    for name in &outcome.granted {
        println!("{command}: skill '{name}' capabilities granted");
    }
    for (name, reason) in &outcome.refused {
        eprintln!("{command}: skill '{name}' refused — {reason}");
    }
    for tool in &outcome.tools {
        bee::tools::register_named(registry, tool, None);
    }
    // Readable-scope: each discovered skill directory becomes readable so bundled resources
    // resolve. Read, never write — a skill's own files are inputs.
    for s in &skill_refs {
        if let Some(dir) = s.dir.to_str() {
            outcome
                .policy
                .filesystem
                .entry(dir.to_string())
                .or_insert(bee_core::Access::Read);
        }
    }
    Some(outcome.policy)
}

/// The environment variables tool children must not inherit: the provider key plus anything else
/// the session names (MCP token variables are added by the caller that knows about them).
pub fn strip_vars(key_env: Option<&str>) -> Vec<String> {
    bee::sandbox::key_vars(key_env)
}

// --- the enforcement invariant ----------------------------------------------------------------
//
// Bee's first design principle is deny-by-default and fail-closed: refuse rather than degrade
// silently. `bee exec` has always honoured it. The sessions did not — an interactive session
// without a policy became a host session, announced by one line of a six-line banner, and a session
// *with* a policy on a build without enforcement had that policy parsed, accepted, and ignored.
//
// After this, unenforced execution is something the operator asks for.

/// What a session will actually run under, once the operator's intent and the build have both had
/// their say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// A kernel-enforced scope.
    Enforced,
    /// Hardened, credential-stripped host processes with no scope — explicitly requested.
    Host,
}

/// Why a session may not start. Three distinct problems, so three distinct messages: an operator
/// who sees the wrong one is sent in the wrong direction.
pub struct EnforcementError {
    pub detail: String,
    pub code: u8,
}

/// Decide what the session runs under, or refuse.
///
/// `policy_configured` is whether *any* source produced a policy for this session — a flag,
/// configuration, or a scenario file's own `policy_path`. `explicit_policy` is narrower: whether
/// the operator asked for one on the command line or in configuration, which is what can contradict
/// `--host`. A scenario file naming a policy does not contradict it: a scenario is a portable
/// artifact, and running one on a host build while saying so is a legitimate thing to do.
pub fn resolve_enforcement(
    policy_configured: bool,
    explicit_policy: bool,
    host: bool,
) -> Result<Enforcement, EnforcementError> {
    if host && explicit_policy {
        return Err(EnforcementError {
            detail: "--host means run with no kernel scope, but a policy was configured. \
                     Asking for a policy and asking to run unenforced are contradictory: \
                     drop one."
                .to_string(),
            code: EX_USAGE,
        });
    }

    // Without the feature there is no enforcement to have, whatever the configuration says.
    if !cfg!(feature = "enforce") {
        if host {
            return Ok(Enforcement::Host);
        }
        let detail = if policy_configured {
            "a policy is configured, but this `bee` was built without enforcement, so nothing \
             would enforce it.\n  Rebuild with `--features enforce` on the nightly bpf toolchain \
             to enforce it,\n  or drop the policy and pass `--host` to run unenforced on purpose."
        } else {
            "refusing to start an unenforced session.\n  This `bee` was built without \
             enforcement, so tools would run as hardened host processes with no kernel scope.\n  \
             Rebuild with `--features enforce` to enforce a policy, or pass `--host` to accept \
             that on purpose."
        };
        return Err(EnforcementError {
            detail: detail.to_string(),
            code: EX_USAGE,
        });
    }

    if host {
        return Ok(Enforcement::Host);
    }
    if !policy_configured {
        return Err(EnforcementError {
            detail: "incomplete configuration:\n  - a policy — what the agent's tools are allowed \
                     to do\n      supply it with --policy <FILE>\n      or `[policy] path` in \
                     project configuration (.bee/config.toml)\n      or `[policy] path` in user \
                     configuration (~/.config/bee/config.toml)\n      or pass --host to run with \
                     no kernel scope on purpose"
                .to_string(),
            code: EX_USAGE,
        });
    }
    Ok(Enforcement::Enforced)
}

/// Refuse before starting if the kernel cannot enforce, the way `bee exec` already does. Without
/// this the sessions discover it half-built and report it as an infrastructure error.
#[cfg(feature = "enforce")]
pub fn require_kernel_support() -> Result<(), EnforcementError> {
    let support = bee_userspace::Engine::supported();
    if support.is_supported() {
        return Ok(());
    }
    Err(EnforcementError {
        detail: format!("refusing to run: kernel cannot enforce (fail-closed)\n{support}"),
        code: EX_UNSUPPORTED,
    })
}

#[cfg(not(feature = "enforce"))]
pub fn require_kernel_support() -> Result<(), EnforcementError> {
    Ok(())
}

/// Say plainly, once, on stderr, that nothing is enforcing. A banner line is not enough: it scrolls
/// past, and it is invisible in a piped log.
pub fn announce_host_mode(command: &str) {
    eprintln!(
        "{command}: HOST MODE — no kernel scope is in effect. Tools run as hardened, \
         credential-stripped host processes with no capability enforcement."
    );
}

/// Exit code for an unsupported kernel, matching `bee exec`. Only reachable on an enforcement
/// build — a host build has no kernel gate to fail.
#[cfg_attr(not(feature = "enforce"), allow(dead_code))]
pub const EX_UNSUPPORTED: u8 = 65;

/// The interception setup a sandbox was built with (019): `Some` when `[policy.http]` is active.
#[cfg(feature = "intercept")]
pub type HttpPrepared = Option<bee::intercept::session::Prepared>;
#[cfg(not(feature = "intercept"))]
pub type HttpPrepared = Option<std::convert::Infallible>;

/// Build the sandbox a session's tools run in, plus a human-readable label for the banner.
///
/// With the enforcement feature and a policy this is a real kernel-enforced scope; otherwise it is
/// a hardened, credential-stripped host sandbox with no scope. With `[policy.http]` active it also
/// binds the proxy listener, makes the proxy port the tool scope's only network rule, and attaches
/// the proxy scope; the caller starts the worker.
#[cfg(feature = "enforce")]
pub fn build_sandbox(
    policy: Option<bee_core::Policy>,
    label_hint: Option<&Path>,
    strip_env: Vec<String>,
) -> Result<(Sandbox, String, HttpPrepared), String> {
    use bee_userspace::{EnforcementPlan, Engine, ScopeMode, SystemResolver};

    let Some(policy) = policy else {
        return Ok((
            Sandbox::host(strip_env),
            "none — host mode (no kernel scope)".to_string(),
            None,
        ));
    };

    let resolver = SystemResolver::current();
    #[cfg(feature = "intercept")]
    let prepared = bee::intercept::session::prepare(&policy, &resolver)?;
    #[cfg(not(feature = "intercept"))]
    let prepared: HttpPrepared = None;
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut compiled = policy
        .compile(&resolver)
        .map_err(|e| format!("policy compile: {e}"))?;
    #[cfg(feature = "intercept")]
    if let Some(p) = &prepared {
        compiled = p.tool_policy(compiled);
    }
    let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce)
        .map_err(|e| format!("enforcement plan: {e}"))?;
    let mut engine = Engine::init().map_err(|e| format!("engine init: {e}"))?;

    let scope_id = format!("bee-session-{}", std::process::id());
    let scope = engine
        .create_scope(&scope_id, bee_userspace::cgroup::DEFAULT_PARENT, &plan)
        .map_err(|e| format!("create scope: {e}"))?;
    let reader = engine
        .take_audit_reader(&scope_id)
        .map_err(|e| format!("audit reader: {e}"))?;
    let label = match label_hint {
        Some(p) => format!("{} (enforced)", p.display()),
        None => "policy (enforced)".to_string(),
    };
    #[cfg(feature = "intercept")]
    let sidecar = match &prepared {
        Some(p) => Some(
            bee::intercept::session::attach_sidecar(&mut engine, &scope_id, &p.compiled)
                .inspect_err(|_| {
                    let _ = scope.teardown();
                })?,
        ),
        None => None,
    };
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut sandbox = Sandbox::enforced(engine, scope, reader, strip_env);
    #[cfg(feature = "intercept")]
    if let Some(sc) = sidecar {
        sandbox = sandbox.with_sidecar(sc).map_err(|(sb, sc, e)| {
            let _ = sc.scope.teardown();
            let _ = sb.teardown();
            e.to_string()
        })?;
    }
    Ok((sandbox, label, prepared))
}

/// Host build: there is no kernel enforcement to apply, so a resolved policy is noted but not
/// enforced. Tools still run hardened and credential-stripped.
#[cfg(not(feature = "enforce"))]
pub fn build_sandbox(
    _policy: Option<bee_core::Policy>,
    label_hint: Option<&Path>,
    strip_env: Vec<String>,
) -> Result<(Sandbox, String, HttpPrepared), String> {
    let label = match label_hint {
        Some(p) => format!(
            "{} — IGNORED (host build; rebuild with --features enforce to enforce it)",
            p.display()
        ),
        None => "none — host mode (no kernel scope)".to_string(),
    };
    // A host build never runs a policy (the enforcement invariant refuses one before this point), so
    // `[policy.http]` cannot be active here; interception has nothing to prepare.
    Ok((Sandbox::host(strip_env), label, None))
}
