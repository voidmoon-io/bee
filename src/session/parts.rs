//! The steps of building a session that each entry point used to do its own way (024 R5): resolving
//! skill grants, the `[policy.http]` advisory check, the scanner report directory, and the sandbox.

use bee_core::{Access, Policy};

use super::spec::{BuildError, Enforcement, SessionSpec, SystemParts};
use crate::sandbox::Sandbox;
use crate::skills::{Skill, SkillRegistry};

/// A policy granting nothing, used when a session has none.
pub(crate) fn empty_policy() -> Policy {
    Policy {
        defaults: Default::default(),
        name: "none".to_string(),
        description: None,
        mode: bee_core::Mode::default(),
        filesystem: std::collections::BTreeMap::new(),
        exec: Default::default(),
        network: Default::default(),
        exfiltration: Default::default(),
        http: None,
    }
}

/// Start-up skill grants and their outcome.
pub(super) struct Grants {
    /// The policy to compile: the spec's, widened by approved grants, skill directories and the
    /// scanner report directory. Empty when the spec has no policy.
    pub policy: Policy,
    /// Tools approved skills asked for.
    pub tools: Vec<String>,
    pub granted: Vec<String>,
    pub refused: Vec<(String, String)>,
}

/// Resolve every discovered skill's `requires` against the policy and ceiling, asking the spec's
/// operator about each within-ceiling request (006). Without a policy there is nothing to widen,
/// and nothing is asked. With one, each skill directory becomes readable, so bundled resources
/// resolve, and a granted scanner's report directory becomes writable (FR-010).
pub(super) async fn resolve_grants(spec: &SessionSpec, skills: &SkillRegistry) -> Grants {
    let Some(base) = &spec.policy else {
        return Grants {
            policy: empty_policy(),
            tools: Vec::new(),
            granted: Vec::new(),
            refused: Vec::new(),
        };
    };
    let ceiling = spec.ceiling.clone().unwrap_or_else(|| base.clone());
    let skill_refs: Vec<&Skill> = skills.iter().collect();
    let mut outcome =
        crate::skills::resolve_grants(&skill_refs, base, &ceiling, &spec.operator).await;
    // Declaring a skills root authorizes reading it: read, never write — a skill's files are inputs.
    for s in &skill_refs {
        if let Some(dir) = s.dir.to_str() {
            outcome
                .policy
                .filesystem
                .entry(dir.to_string())
                .or_insert(Access::Read);
        }
    }
    widen_for_scanner_reports(&mut outcome.policy, &spec.security);
    Grants {
        policy: outcome.policy,
        tools: outcome.tools,
        granted: outcome.granted,
        refused: outcome.refused,
    }
}

/// Granting a scanner authorizes the report exchange the scan is made of (017, FR-010).
///
/// The two-child pipeline has the scanner write SARIF to `.bee/scan/` and `bee sarif-worker` read it
/// back — both tool children, both under the scope. But `:project_root/.bee` is a default protection
/// (`PROTECTED_DEFAULTS`): bee's own state is denied to tool children. So a resolved scanner grant
/// widens the policy by exactly one subtree; more-specific-wins carves `.bee/scan` out while the rest
/// of `.bee` — `findings/` above all — stays denied. Applied for every entry point: the REPL used to
/// skip it, so `scan` failed there under enforcement.
pub(super) fn widen_for_scanner_reports(
    policy: &mut Policy,
    security: &crate::security::SecurityConfig,
) {
    #[cfg(feature = "scanners")]
    {
        if crate::scanners::grants_from_policy(Some(policy), security).is_empty() {
            return;
        }
        policy
            .filesystem
            .entry(format!(":project_root/{}", crate::tools::scanner::SCAN_DIR))
            .or_insert(Access::Write);
    }
    #[cfg(not(feature = "scanners"))]
    {
        let _ = (policy, security);
    }
}

/// The `[policy.http]` advisory check, the one copy for every entry point (FR-011).
///
/// `Ok(None)`: no interception, or interception the kernel backs. `Ok(Some(reason))`: interception
/// enforced by the proxy alone, which the operator accepted with `--http-scope-advisory`. `Err`: the
/// build cannot intercept, or the operator has not accepted the advisory mode.
pub fn http_advisory(
    policy: &Policy,
    enforcement: Enforcement,
    accepted: bool,
) -> Result<Option<String>, BuildError> {
    if !policy.http.as_ref().is_some_and(|h| h.is_active()) {
        return Ok(None);
    }
    #[cfg(not(feature = "intercept"))]
    {
        let _ = (enforcement, accepted);
        Err(BuildError(
            "the policy declares [policy.http] targets, but bee was built without --features \
             intercept; refusing to run its tools with an unenforced scope"
                .into(),
        ))
    }
    #[cfg(feature = "intercept")]
    {
        let kernel_scope = enforcement == Enforcement::Kernel;
        match crate::intercept::session::advisory_reason(policy, kernel_scope) {
            Some(reason) if !accepted => Err(BuildError(
                crate::intercept::session::advisory_refusal(&reason),
            )),
            other => Ok(other),
        }
    }
}

/// The interception setup a sandbox was built with: `Some` when `[policy.http]` is active.
#[cfg(feature = "intercept")]
pub(super) type HttpPrepared = Option<crate::intercept::session::Prepared>;
#[cfg(not(feature = "intercept"))]
pub(super) type HttpPrepared = Option<std::convert::Infallible>;

/// `s` reduced to `[A-Za-z0-9-]`, for scope and session names.
pub(super) fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Build the sandbox the session's tools run in: a kernel scope compiled from `policy`, or a host
/// sandbox. With `[policy.http]` active the proxy listener is bound first, the proxy port becomes the
/// tool scope's only network rule, and (under enforcement) the proxy scope is attached; the caller
/// starts the worker.
pub(super) fn build_sandbox(
    spec: &SessionSpec,
    policy: &Policy,
    scope_id: &str,
    #[cfg_attr(not(feature = "intercept"), allow(unused_variables))] system: &SystemParts,
) -> Result<(Sandbox, HttpPrepared), String> {
    match spec.enforcement {
        Enforcement::Kernel => kernel_sandbox(policy, scope_id, spec.strip_env.clone()),
        Enforcement::Host => {
            #[cfg(feature = "intercept")]
            let prepared = if policy.http.as_ref().is_some_and(|h| h.is_active()) {
                let resolver = crate::intercept::session::WithHosts {
                    system: bee_userspace::SystemResolver::current(),
                    hosts: &system.hosts,
                };
                match &system.worker_exe {
                    Some(exe) => {
                        crate::intercept::session::prepare_for(policy, &resolver, exe.clone())?
                    }
                    None => crate::intercept::session::prepare(policy, &resolver)?,
                }
            } else {
                None
            };
            #[cfg(not(feature = "intercept"))]
            let prepared: HttpPrepared = None;
            Ok((Sandbox::host(spec.strip_env.clone()), prepared))
        }
    }
}

#[cfg(feature = "enforce")]
pub(crate) fn kernel_sandbox(
    policy: &Policy,
    scope_id: &str,
    strip_env: Vec<String>,
) -> Result<(Sandbox, HttpPrepared), String> {
    use bee_userspace::{EnforcementPlan, Engine, ScopeMode, SystemResolver};

    let resolver = SystemResolver::current();
    // 019: bind the proxy listener and compile the proxy scope *before* the tool policy, whose only
    // network rule becomes the proxy port.
    #[cfg(feature = "intercept")]
    let prepared = crate::intercept::session::prepare(policy, &resolver)?;
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
    let scope = engine
        .create_scope(scope_id, bee_userspace::cgroup::DEFAULT_PARENT, &plan)
        .map_err(|e| format!("create scope: {e}"))?;
    let reader = engine
        .take_audit_reader(scope_id)
        .map_err(|e| format!("audit reader: {e}"))?;
    // The proxy scope comes from the same engine, before it moves into the sandbox (019 P4).
    #[cfg(feature = "intercept")]
    let sidecar = match &prepared {
        Some(p) => Some(
            crate::intercept::session::attach_sidecar(&mut engine, scope_id, &p.compiled)
                .inspect_err(|_| {
                    let _ = scope.teardown();
                })?,
        ),
        None => None,
    };
    // `engine` moves into the sandbox so its eBPF programs stay attached for the whole session.
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
    Ok((sandbox, prepared))
}

/// Without the feature there is no kernel scope to build; [`super::spec::refuse_unsupported`] refuses
/// `Enforcement::Kernel` before this point.
#[cfg(not(feature = "enforce"))]
fn kernel_sandbox(
    _policy: &Policy,
    _scope_id: &str,
    _strip_env: Vec<String>,
) -> Result<(Sandbox, HttpPrepared), String> {
    Err("kernel enforcement is not compiled into this bee".into())
}
