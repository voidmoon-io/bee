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
use super::sidecar::{
    Attribution, Enforcement, HarnessResolver, Interceptor, InterceptorConfig, SpawnFn,
};
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
    prepare_for(policy, resolver, worker_exe)
}

/// [`prepare`], with `worker_exe` run as `bee proxy-worker` instead of this process's binary.
pub fn prepare_for(
    policy: &Policy,
    resolver: &dyn Resolver,
    worker_exe: PathBuf,
) -> Result<Option<Prepared>, String> {
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

/// How a subagent of an intercepting session gets a proxy of its own (026 T058, 019 T092): the
/// session's interception settings, reused for each child's derived `[policy.http]`.
///
/// Each child gets its own listener, its own proxy scope beside its tool scope, its own worker and
/// so its own credential namespace — a sibling's credential names a call the other worker never
/// issued, and the child's tool scope can reach only its own proxy's port anyway — and its own
/// store session, attributed to its scope and delegation.
#[derive(Clone)]
pub struct ChildProxies {
    pub worker_exe: PathBuf,
    /// Names answered before the system resolver (tests only).
    pub hosts: Vec<(String, std::net::IpAddr)>,
    pub project_root: PathBuf,
    /// The session's: a child is enforced exactly as its parent's proxy is, and an advisory parent
    /// was accepted by the operator for the whole session.
    pub enforcement: Enforcement,
}

impl ChildProxies {
    /// Compile a child's `[policy.http]` and bind its listener. `Ok(None)` when it is inactive.
    pub fn prepare(&self, policy: &Policy) -> Result<Option<Prepared>, String> {
        let resolver = WithHosts {
            system: bee_userspace::SystemResolver::current(),
            hosts: &self.hosts,
        };
        prepare_for(policy, &resolver, self.worker_exe.clone())
    }

    /// Whether the child's proxy runs in a kernel scope of its own.
    pub fn kernel(&self) -> bool {
        self.enforcement == Enforcement::Kernel
    }

    /// Start the child's worker into `sandbox` (its proxy scope already attached under kernel
    /// enforcement), recording for `attribution`.
    pub async fn start(
        &self,
        prepared: Prepared,
        sandbox: &mut Sandbox,
        session_id: &str,
        attribution: Attribution,
    ) -> Result<HttpSession, String> {
        start(
            prepared,
            sandbox,
            session_id,
            &self.project_root,
            self.enforcement.clone(),
            worker_resolver(self.hosts.clone()),
            Some(attribution),
        )
        .await
    }
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
        self.remove_ca_bundle();
    }

    /// Delete the CA bundle and its private directory. Synchronous, so a dropped session can too.
    pub fn remove_ca_bundle(&self) {
        if let Some(b) = &self.ca_bundle {
            let _ = std::fs::remove_file(b);
            if let Some(dir) = b.parent() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

/// A session dropped without [`HttpSession::shutdown`] — a subagent whose delegation was cancelled
/// mid-run — still stops its worker (when a runtime is there to do it) and deletes its CA bundle.
/// After an explicit shutdown both are no-ops.
impl Drop for HttpSession {
    fn drop(&mut self) {
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let icpt = self.interceptor.clone();
            rt.spawn(async move { icpt.shutdown().await });
        }
        self.remove_ca_bundle();
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

pub use comb::client::write_ca_bundle;

/// The system resolver, with `hosts` answered first. Only a test names hosts (024 T048).
pub(crate) struct WithHosts<'a> {
    pub system: bee_userspace::SystemResolver,
    pub hosts: &'a [(String, std::net::IpAddr)],
}

impl Resolver for WithHosts<'_> {
    fn project_root(&self) -> &str {
        self.system.project_root()
    }
    fn home(&self) -> &str {
        self.system.home()
    }
    fn resolve_exec(&self, name: &str) -> Result<PathBuf, bee_core::CompileError> {
        self.system.resolve_exec(name)
    }
    fn resolve_exec_identity(
        &self,
        path: &Path,
    ) -> Result<bee_core::ExecIdentity, bee_core::CompileError> {
        self.system.resolve_exec_identity(path)
    }
    fn resolve_host(&self, host: &str) -> Result<Vec<std::net::IpAddr>, bee_core::CompileError> {
        match named(self.hosts, host) {
            Some(addrs) => Ok(addrs),
            None => self.system.resolve_host(host),
        }
    }
}

/// The worker's resolver: [`super::sidecar::system_resolver`], with `hosts` answered first.
pub(crate) fn worker_resolver(hosts: Vec<(String, std::net::IpAddr)>) -> HarnessResolver {
    let system = super::sidecar::system_resolver();
    if hosts.is_empty() {
        return system;
    }
    Arc::new(move |host: &str| match named(&hosts, host) {
        Some(addrs) => Ok(addrs),
        None => system(host),
    })
}

/// The addresses `hosts` gives `host`, if it names it.
fn named(hosts: &[(String, std::net::IpAddr)], host: &str) -> Option<Vec<std::net::IpAddr>> {
    let addrs: Vec<_> = hosts
        .iter()
        .filter(|(h, _)| h == host)
        .map(|(_, a)| *a)
        .collect();
    (!addrs.is_empty()).then_some(addrs)
}

/// Spawn the worker and wire it into `sandbox`. Under enforcement the sandbox must already carry the
/// sidecar scope; the worker joins it, and every name it resolves is admitted into that scope's
/// kernel rules first (026 R9). In advisory mode the worker is a hardened child with no scope.
/// `resolver` is how the worker resolves names ([`super::sidecar::system_resolver`] outside tests).
/// `attribution` names the subagent this proxy records for; `None` for a session's own.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    prepared: Prepared,
    sandbox: &mut Sandbox,
    session_id: &str,
    project_root: &Path,
    enforcement: Enforcement,
    resolver: HarnessResolver,
    attribution: Option<Attribution>,
) -> Result<HttpSession, String> {
    let spawn = spawn_fn(sandbox, &prepared.worker_exe, session_id, &enforcement)?;
    let admit = admitter(sandbox, &enforcement)?;
    let prepared_exe = prepared.worker_exe.clone();
    let prepared_bundle = prepared.ca_bundle.clone();
    sandbox.set_proxy_loopback(prepared.port, prepared.ca_bundle.clone());
    let interceptor = Interceptor::start(
        InterceptorConfig {
            session_id: session_id.to_string(),
            project_root: project_root.to_path_buf(),
            http_scope: prepared.compiled.http_scope,
            enforcement,
            resolver,
            admit,
            attribution,
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

/// Create the proxy scope on the tool scope's supervisor, as its userspace child so it is torn down
/// first (enforce builds).
#[cfg(feature = "enforce")]
pub fn attach_sidecar(
    tool_scope: &crate::supervisor::ScopeHandle,
    compiled: &CompiledHttp,
) -> Result<crate::sandbox::SidecarScope, String> {
    crate::proxy_scope::ProxyScope::create(tool_scope, compiled).map(Arc::new)
}

/// The resolve-and-admit hook for a kernel-enforced worker: its sandbox's proxy scope (026 R9).
/// Advisory has no kernel rules to admit into, so the compile-time addresses stay the only ones.
#[cfg(feature = "enforce")]
fn admitter(
    sandbox: &Sandbox,
    enforcement: &Enforcement,
) -> Result<Option<Arc<dyn super::sidecar::Admit>>, String> {
    match enforcement {
        Enforcement::Advisory { .. } => Ok(None),
        Enforcement::Kernel => {
            let scope = sandbox
                .sidecar_scope()
                .ok_or("a kernel-enforced proxy needs its proxy scope attached first")?;
            Ok(Some(Arc::new(ScopeAdmit(Arc::downgrade(scope)))))
        }
    }
}

#[cfg(not(feature = "enforce"))]
fn admitter(
    _: &Sandbox,
    _: &Enforcement,
) -> Result<Option<Arc<dyn super::sidecar::Admit>>, String> {
    Ok(None)
}

/// Admits into a proxy scope the sandbox owns. Weak: a resolve racing the sandbox's teardown is
/// refused, never a reason to keep the scope alive.
#[cfg(feature = "enforce")]
struct ScopeAdmit(std::sync::Weak<crate::proxy_scope::ProxyScope>);

#[cfg(feature = "enforce")]
impl super::sidecar::Admit for ScopeAdmit {
    fn admit(
        &self,
        host: &str,
        addrs: &[std::net::IpAddr],
    ) -> Result<super::sidecar::AdmitOutcome, String> {
        let scope = self.0.upgrade().ok_or("the proxy scope is gone")?;
        let a = scope.admit(host, addrs)?;
        Ok(super::sidecar::AdmitOutcome {
            addrs: a.answer,
            added: a.added,
            evicted: a.evicted,
        })
    }
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
