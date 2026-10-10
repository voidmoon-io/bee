//! Bringing interception into a session (019 T043) — shared by `bee run`'s episode path and
//! `bee repl`, so both construct it identically.
//!
//! Order matters and is fixed here:
//! 1. compile `[policy.http]` ([`prepare`]): the proxy scope and the worker's HTTP scope;
//! 2. **bind the listener** on `127.0.0.1:0` — before the tool policy compiles, because the port is
//!    the tool scope's only network rule ([`bee_core::compiler::with_proxy_loopback`], research R4);
//! 3. under enforcement, create the proxy scope on the same engine as the tool scope and attach it
//!    as the sandbox's sidecar (done by the caller, which owns the engine);
//! 4. [`start`]: spawn the worker into the sidecar scope with fd 3, wait for `hello`, and install the
//!    per-call credentials on the sandbox.
//!
//! A session whose enforcement does not *block* — host mode, a build without `enforce`, or a policy
//! in `mode = "observe"` — runs interception only when the operator passes `--http-scope-advisory`
//! ([`advisory_reason`]); without it, it refuses (research R17).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bee_core::compiler::CompiledHttp;
use bee_core::{Mode, Policy, Resolver};

use super::creds::ProxyCredentials;
use super::sidecar::{system_resolver, Enforcement, Interceptor, InterceptorConfig, SpawnFn};
use crate::sandbox::Sandbox;

/// The operator flag that accepts proxy-only enforcement. Not readable from any configuration file.
pub const ADVISORY_FLAG: &str = "--http-scope-advisory";

/// Whether `policy` turns interception on.
pub fn wants_interception(policy: Option<&Policy>) -> bool {
    policy
        .and_then(|p| p.http.as_ref())
        .is_some_and(|h| h.is_active())
}

/// Why this session's enforcement does not block, if it does not. `kernel_scope` is whether the
/// session gets a kernel scope at all (an `enforce` build, not host mode).
pub fn advisory_reason(policy: &Policy, kernel_scope: bool) -> Option<String> {
    if !kernel_scope {
        return Some(if cfg!(feature = "enforce") {
            "host mode: no kernel scope".into()
        } else {
            "this bee was built without enforcement".into()
        });
    }
    (policy.mode == Mode::Observe)
        .then(|| "the policy is in observe mode: the kernel audits and then allows".into())
}

/// The refusal for a non-blocking session without the flag (T034).
pub fn advisory_refusal(reason: &str) -> String {
    format!(
        "refusing to start HTTP interception: {reason}.\n  [policy.http] scope would be enforced \
         by the proxy alone — tool children could reach targets directly, and the proxy anything.\n  \
         Pass {ADVISORY_FLAG} to accept that on purpose."
    )
}

/// The banner printed when the operator accepted advisory enforcement.
pub fn advisory_banner(reason: &str) -> String {
    format!(
        "HTTP SCOPE ADVISORY — {reason}. [policy.http] is enforced by the proxy only, not the \
         kernel ({ADVISORY_FLAG})."
    )
}

/// What [`prepare`] produces: the compiled scopes and the bound listener.
pub struct Prepared {
    pub compiled: CompiledHttp,
    pub listener: std::net::TcpListener,
    pub port: u16,
    pub worker_exe: PathBuf,
}

/// Compile `[policy.http]` and bind the proxy listener. `Ok(None)` when interception is off.
pub fn prepare(policy: &Policy, resolver: &dyn Resolver) -> Result<Option<Prepared>, String> {
    let worker_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("cannot resolve the bee binary for the proxy worker: {e}"))?;
    let Some(compiled) = policy
        .compile_http(resolver, &worker_exe)
        .map_err(|e| format!("[policy.http]: {e}"))?
    else {
        return Ok(None);
    };
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("cannot bind the proxy listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("proxy listener: {e}"))?
        .port();
    Ok(Some(Prepared {
        compiled,
        listener,
        port,
        worker_exe,
    }))
}

/// A running interception session: the handle the HTTP tools use, and the credentials installed on
/// the sandbox.
pub struct HttpSession {
    pub interceptor: Interceptor,
    pub credentials: Arc<ProxyCredentials>,
}

impl HttpSession {
    /// Stop the worker. Call before the sandbox is torn down (the sidecar scope goes first).
    pub async fn shutdown(&self) {
        self.interceptor.shutdown().await;
    }
}

/// Spawn the worker and wire it into `sandbox`. Under enforcement the sandbox must already carry the
/// sidecar scope; the worker joins it. In advisory mode the worker is a hardened child with no scope.
pub async fn start(
    prepared: Prepared,
    sandbox: &mut Sandbox,
    session_id: &str,
    project_root: &Path,
    enforcement: Enforcement,
) -> Result<HttpSession, String> {
    let spawn = spawn_fn(sandbox, &prepared.worker_exe, session_id, &enforcement)?;
    sandbox.set_proxy_loopback(prepared.port);
    let interceptor = Interceptor::start(
        InterceptorConfig {
            session_id: session_id.to_string(),
            project_root: project_root.to_path_buf(),
            http_scope: prepared.compiled.http_scope,
            enforcement,
            resolver: system_resolver(),
        },
        prepared.listener,
        spawn,
    )
    .await?;
    let credentials = ProxyCredentials::new(interceptor.clone(), None);
    credentials.install(sandbox);
    Ok(HttpSession {
        interceptor,
        credentials,
    })
}

fn spawn_fn(
    sandbox: &Sandbox,
    exe: &Path,
    session_id: &str,
    enforcement: &Enforcement,
) -> Result<SpawnFn, String> {
    let exe = exe.to_string_lossy().into_owned();
    let args = vec![
        "proxy-worker".to_string(),
        "--session".to_string(),
        session_id.to_string(),
    ];
    match enforcement {
        Enforcement::Advisory { .. } => {
            let _ = sandbox;
            Ok(Box::new(move || {
                bee_userspace::hardened_command::<fn() -> std::io::Result<()>>(&exe, &args, None)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            }))
        }
        Enforcement::Kernel => kernel_spawn_fn(sandbox, exe, args),
    }
}

#[cfg(feature = "enforce")]
fn kernel_spawn_fn(sandbox: &Sandbox, exe: String, args: Vec<String>) -> Result<SpawnFn, String> {
    // The worker joins the proxy scope in `pre_exec`, exactly as a tool child joins the tool scope,
    // then gets the same hardening (non-dumpable, no core, `LD_*` stripped, privileges dropped).
    let join = Arc::new(sandbox.sidecar_join_closure()?);
    Ok(Box::new(move || {
        let j = join.clone();
        bee_userspace::hardened_command(&exe, &args, Some(move || j()))
            .map_err(|e| std::io::Error::other(e.to_string()))
    }))
}

#[cfg(not(feature = "enforce"))]
fn kernel_spawn_fn(_: &Sandbox, _: String, _: Vec<String>) -> Result<SpawnFn, String> {
    Err("kernel enforcement is not compiled into this bee".into())
}

/// Create the proxy scope on `engine` and attach it to `sandbox` (enforce builds).
#[cfg(feature = "enforce")]
pub fn attach_sidecar(
    engine: &mut bee_userspace::Engine,
    sandbox_scope_id: &str,
    compiled: &CompiledHttp,
) -> Result<crate::sandbox::SidecarScope, String> {
    use bee_userspace::{EnforcementPlan, ScopeMode};
    let mode = match compiled.proxy_scope.mode {
        Mode::Enforce => ScopeMode::Enforce,
        Mode::Observe => ScopeMode::Observe,
    };
    let plan = EnforcementPlan::prepare(&compiled.proxy_scope, mode)
        .map_err(|e| format!("proxy scope plan: {e}"))?;
    let scope = engine
        .create_scope(
            &format!("{sandbox_scope_id}-proxy"),
            bee_userspace::cgroup::DEFAULT_PARENT,
            &plan,
        )
        .map_err(|e| format!("create proxy scope: {e}"))?;
    Ok(crate::sandbox::SidecarScope {
        label: "proxy".into(),
        scope,
        plan,
    })
}
