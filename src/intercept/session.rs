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
    /// Where the session CA bundle will be written, when anything is inspected (US4). Chosen now so
    /// the tool policy can grant its read before it compiles; written once the worker says hello.
    pub ca_bundle: Option<PathBuf>,
}

impl Prepared {
    /// The tool scope as a session installs it: the proxy port as its only network rule, plus a
    /// read of the CA bundle when there is one (research R4, R7).
    pub fn tool_policy(&self, compiled: bee_core::CompiledPolicy) -> bee_core::CompiledPolicy {
        let mut c = bee_core::compiler::with_proxy_loopback(compiled, self.port);
        if let Some(b) = &self.ca_bundle {
            c.fs.push(bee_core::FsPrimitive::read_grant(b));
        }
        c
    }
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
    let ca_bundle = if compiled.http_scope.inspect.is_empty() {
        None
    } else {
        Some(ca_bundle_dir()?.join("ca-bundle.pem"))
    };
    Ok(Some(Prepared {
        compiled,
        listener,
        port,
        worker_exe,
        ca_bundle,
    }))
}

/// A running interception session: the handle the HTTP tools use, and the credentials installed on
/// the sandbox.
pub struct HttpSession {
    pub interceptor: Interceptor,
    pub credentials: Arc<ProxyCredentials>,
    /// The session CA bundle on disk, removed at shutdown.
    pub ca_bundle: Option<PathBuf>,
}

impl HttpSession {
    /// Stop the worker and delete the CA bundle. Call before the sandbox is torn down (the sidecar
    /// scope goes first).
    pub async fn shutdown(&self) {
        self.interceptor.shutdown().await;
        if let Some(b) = &self.ca_bundle {
            let _ = std::fs::remove_file(b);
            if let Some(dir) = b.parent() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

/// A fresh private directory for this session's CA bundle: `$XDG_RUNTIME_DIR/bee/<id>/`, or under
/// the temp directory when there is no runtime dir. Outside `.bee/` on purpose — the bundle must be
/// readable by tool children, and `.bee/` is denied to them (research R7).
fn ca_bundle_dir() -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .map(|p| p.join("bee"))
        .unwrap_or_else(|| {
            // SAFETY: getuid has no preconditions and cannot fail.
            std::env::temp_dir().join(format!("bee-{}", unsafe { libc::getuid() }))
        });
    let mut rand = [0u8; 8];
    // SAFETY: `rand` is a valid writable 8-byte buffer.
    unsafe { libc::getrandom(rand.as_mut_ptr().cast(), rand.len(), 0) };
    let id: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    let dir = base.join(format!("session-{}-{id}", std::process::id()));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("CA bundle directory {}: {e}", dir.display()))?;
    Ok(dir)
}

/// System roots plus the session CA. The roots matter: tunnelled hosts present their real
/// certificates, and a bundle of the session CA alone would break every one of them (research R7).
pub fn write_ca_bundle(path: &Path, ca_pem: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let system = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
    .unwrap_or_default();
    let tmp = path.with_extension("pem.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(|e| format!("CA bundle {}: {e}", tmp.display()))?;
    f.write_all(system.as_bytes())
        .and_then(|_| {
            if !system.is_empty() && !system.ends_with('\n') {
                f.write_all(b"\n")?;
            }
            f.write_all(ca_pem.as_bytes())
        })
        .map_err(|e| format!("CA bundle: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("CA bundle: {e}"))
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
    let prepared_exe = prepared.worker_exe.clone();
    let prepared_bundle = prepared.ca_bundle.clone();
    sandbox.set_proxy_loopback(prepared.port, prepared.ca_bundle.clone());
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
    // The CA bundle, when something is inspected: system roots + the session CA certificate.
    let ca_bundle = match (&prepared_bundle, interceptor.ca_cert_pem()) {
        (Some(path), Some(pem)) => {
            if let Err(e) = write_ca_bundle(path, &pem) {
                interceptor.shutdown().await;
                return Err(e);
            }
            Some(path.clone())
        }
        (Some(_), None) => {
            interceptor.shutdown().await;
            return Err(
                "the proxy worker sent no CA certificate, but [policy.http] inspects".into(),
            );
        }
        _ => None,
    };
    let credentials = ProxyCredentials::new(interceptor.clone(), ca_bundle.clone());
    credentials.install(sandbox);
    sandbox.set_http_scope_hook(scope_hook(interceptor.clone(), prepared_exe));
    Ok(HttpSession {
        interceptor,
        credentials,
        ca_bundle,
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

/// The [`crate::sandbox::HttpScopeHook`] for `interceptor`: how a consented target-scope widening
/// reaches this session's proxy (019 US3).
pub fn scope_hook(
    interceptor: Interceptor,
    worker_exe: PathBuf,
) -> Arc<dyn crate::sandbox::HttpScopeHook> {
    Arc::new(ScopeHook {
        interceptor,
        worker_exe,
    })
}

struct ScopeHook {
    interceptor: Interceptor,
    worker_exe: PathBuf,
}

impl crate::sandbox::HttpScopeHook for ScopeHook {
    fn compile(
        &self,
        policy: &Policy,
    ) -> Result<(bee_core::CompiledPolicy, bee_core::compiler::HttpScope), String> {
        let c = policy
            .compile_http(&bee_userspace::SystemResolver::current(), &self.worker_exe)
            .map_err(|e| format!("[policy.http]: {e}"))?
            .ok_or("the widened policy has no [policy.http] targets")?;
        Ok((c.proxy_scope, c.http_scope))
    }

    fn update<'a>(
        &'a self,
        scope: bee_core::compiler::HttpScope,
    ) -> futures_util::future::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.interceptor
                .update_scope(scope)
                .await
                .map_err(|e| e.to_string())
        })
    }
}
