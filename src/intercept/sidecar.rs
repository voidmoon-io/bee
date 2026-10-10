//! The harness side of the interception proxy (019 T041, contracts/proxy-control.md).
//!
//! [`Interceptor`] spawns `bee proxy-worker` — joined to the proxy scope under enforcement, merely
//! hardened in advisory mode — with the harness-bound listener as fd 3 and the control channel on
//! stdio. A reader task writes every `exchange`, `tunnel` and refusal into the [`Store`], answers the
//! worker's name lookups, and completes pending requests. If the worker dies, every HTTP tool reports
//! `interceptor_unavailable` and tool children reach nothing (their scope admits only the proxy
//! port); the harness restarts it **once**, announcing it, and then gives up.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, ChildStdin};
use tokio::sync::oneshot;

use bee_core::compiler::HttpScope;

use super::control::{
    ExchangeRecord, FrameReader, FrameWriter, FromWorker, OriginKind, ProxyEvent, RawTarget,
    ToWorker, WireCtx,
};
use super::store::{ExchangeBytes, Store};

/// How long to wait for the worker's `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for an `ack`.
const ACK_TIMEOUT: Duration = Duration::from_secs(5);
/// Restarts allowed per session (contract §Process).
const MAX_RESTARTS: u32 = 1;

/// Whether the session's scope rules are enforced by the kernel or only by the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// Both layers: the proxy runs in its own kernel scope; tool children reach only the proxy.
    Kernel,
    /// Proxy only (`--http-scope-advisory`): host mode, a non-`enforce` build, or `mode = "observe"`.
    Advisory { reason: String },
}

impl Enforcement {
    pub fn label(&self) -> &'static str {
        match self {
            Enforcement::Kernel => "kernel",
            Enforcement::Advisory { .. } => "advisory",
        }
    }
}

/// Builds the worker's command. Under enforcement this joins the proxy scope; in advisory mode it is
/// a hardened command with no join. Called again for the one restart.
pub type SpawnFn = Box<dyn Fn() -> std::io::Result<std::process::Command> + Send + Sync>;

/// Resolves names for the worker (research R2 addendum). The harness is outside every scope.
pub type HarnessResolver = Arc<dyn Fn(&str) -> Result<Vec<IpAddr>, String> + Send + Sync>;

/// The system resolver.
pub fn system_resolver() -> HarnessResolver {
    Arc::new(|host: &str| {
        use std::net::ToSocketAddrs;
        (host, 0)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect())
            .map_err(|e| e.to_string())
    })
}

pub struct InterceptorConfig {
    pub session_id: String,
    pub project_root: PathBuf,
    pub http_scope: HttpScope,
    pub enforcement: Enforcement,
    pub resolver: HarnessResolver,
}

/// Why an HTTP tool could not get an answer from the proxy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InterceptError {
    #[error("interceptor_unavailable: {0}")]
    Unavailable(String),
    #[error("{code}: {message}")]
    Worker { code: String, message: String },
    #[error("store: {0}")]
    Store(String),
}

enum Reply {
    Ack,
    Exchange(String, Box<ExchangeRecord>),
    Error { code: String, message: String },
}

/// What the worker answered a `send`.
#[derive(Debug, Clone)]
pub struct Sent {
    pub exchange_id: String,
    pub record: ExchangeRecord,
}

struct Live {
    writer: Option<FrameWriter<ChildStdin>>,
    child: Option<Child>,
    alive: bool,
    restarts: u32,
}

struct Inner {
    cfg: InterceptorConfig,
    port: u16,
    /// The harness's copy of fd 3. Dropped when the worker is given up on, so a client trying the
    /// proxy is refused at once instead of queueing on a socket nobody will accept from.
    listener: Mutex<Option<std::net::TcpListener>>,
    spawn: SpawnFn,
    live: tokio::sync::Mutex<Live>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_req: AtomicU64,
    store: Mutex<Store>,
    /// call id → its token, while the call is live.
    tokens: Mutex<HashMap<String, String>>,
    /// token → context, re-issued to a restarted worker.
    issued: Mutex<HashMap<String, WireCtx>>,
    /// Proxy events not yet collected, by call id (`""` for unattributed).
    events: Mutex<HashMap<String, Vec<ProxyEvent>>>,
    /// Announcements for the operator (restart, death, eviction).
    notices: Mutex<Vec<String>>,
    ca_cert_pem: Mutex<Option<String>>,
    on_event: Mutex<Option<Box<dyn Fn(&ProxyEvent) + Send + Sync>>>,
    /// The scope the worker currently enforces: the configured one, replaced on each acknowledged
    /// `scope.update` (US3). A restarted worker is initialised with this, not the original.
    scope: Mutex<HttpScope>,
    /// Fuzz runs awaiting their `fuzz.done` (US6).
    fuzz_waiters: Mutex<HashMap<String, oneshot::Sender<FuzzCounts>>>,
    /// Intercept rules installed this session, with hit counts from `rule_fired` events (US7).
    rules: Mutex<Vec<RuleInfo>>,
    /// Requests held right now (US7).
    held: Mutex<Vec<HeldInfo>>,
    next_rule: AtomicU64,
}

/// An installed intercept rule, as the harness tracks it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub spec: serde_json::Value,
    pub hits: u64,
}

/// A request a hold rule is keeping until the model decides (or its deadline passes).
#[derive(Debug, Clone, serde::Serialize)]
pub struct HeldInfo {
    pub hold_id: String,
    pub summary: String,
    pub deadline: String,
}

/// What a fuzz run did, as the worker counted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCounts {
    pub sent: u32,
    pub refused: u32,
    pub failed: u32,
    pub state: String,
}

/// The harness's handle on the session proxy. Cheap to clone.
#[derive(Clone)]
pub struct Interceptor {
    inner: Arc<Inner>,
}

impl Interceptor {
    /// Spawn the worker on `listener` (fd 3), send `init`, and wait for `hello`.
    pub async fn start(
        cfg: InterceptorConfig,
        listener: std::net::TcpListener,
        spawn: SpawnFn,
    ) -> Result<Interceptor, String> {
        let port = listener
            .local_addr()
            .map_err(|e| format!("listener: {e}"))?
            .port();
        let store = Store::open(&cfg.project_root, &cfg.session_id, &cfg.http_scope.limits)
            .map_err(|e| e.to_string())?;
        if store.is_read_only() {
            return Err(
                "the .bee/http store was written by a newer bee; refusing to start interception"
                    .into(),
            );
        }
        let cfg_scope = cfg.http_scope.clone();
        let inner = Arc::new(Inner {
            cfg,
            port,
            listener: Mutex::new(Some(listener)),
            spawn,
            live: tokio::sync::Mutex::new(Live {
                writer: None,
                child: None,
                alive: false,
                restarts: 0,
            }),
            pending: Mutex::new(HashMap::new()),
            next_req: AtomicU64::new(1),
            store: Mutex::new(store),
            tokens: Mutex::new(HashMap::new()),
            issued: Mutex::new(HashMap::new()),
            events: Mutex::new(HashMap::new()),
            notices: Mutex::new(Vec::new()),
            ca_cert_pem: Mutex::new(None),
            on_event: Mutex::new(None),
            scope: Mutex::new(cfg_scope),
            fuzz_waiters: Mutex::new(HashMap::new()),
            rules: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            next_rule: AtomicU64::new(1),
        });
        let me = Interceptor { inner };
        me.launch().await?;
        Ok(me)
    }

    /// The loopback port tool children are pointed at.
    pub fn port(&self) -> u16 {
        self.inner.port
    }

    pub fn session_id(&self) -> &str {
        &self.inner.cfg.session_id
    }

    /// The scope the worker currently enforces.
    pub fn http_scope(&self) -> HttpScope {
        self.inner.scope.lock().expect("scope lock").clone()
    }

    pub fn enforcement(&self) -> &Enforcement {
        &self.inner.cfg.enforcement
    }

    /// The session CA certificate, when `inspect` is non-empty (US4).
    pub fn ca_cert_pem(&self) -> Option<String> {
        self.inner.ca_cert_pem.lock().expect("ca lock").clone()
    }

    /// Run `f` against the store.
    pub fn with_store<T>(&self, f: impl FnOnce(&mut Store) -> T) -> T {
        f(&mut self.inner.store.lock().expect("store lock"))
    }

    /// Called for every proxy event as it arrives (front-ends render refusals live).
    pub fn set_event_sink(&self, f: Box<dyn Fn(&ProxyEvent) + Send + Sync>) {
        *self.inner.on_event.lock().expect("sink lock") = Some(f);
    }

    /// Proxy events recorded for `call_id` since the last call, oldest first.
    pub fn take_events(&self, call_id: &str) -> Vec<ProxyEvent> {
        self.inner
            .events
            .lock()
            .expect("events lock")
            .remove(call_id)
            .unwrap_or_default()
    }

    /// Operator announcements (a restart, the worker giving up, store eviction) since the last call.
    pub fn take_notices(&self) -> Vec<String> {
        std::mem::take(&mut *self.inner.notices.lock().expect("notices lock"))
    }

    pub async fn available(&self) -> bool {
        self.inner.live.lock().await.alive
    }

    /// The live token for `call_id`, if one was issued.
    pub fn token_for(&self, call_id: &str) -> Option<String> {
        self.inner
            .tokens
            .lock()
            .expect("tokens lock")
            .get(call_id)
            .cloned()
    }

    /// Mint a credential for `ctx`, register it with the worker, and wait for the ack.
    pub async fn issue(&self, ctx: WireCtx) -> Result<String, InterceptError> {
        let token = mint_token();
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        self.write(
            &ToWorker::CredsIssue {
                req_id,
                token: token.clone(),
                ctx: ctx.clone(),
            },
            &[],
        )
        .await?;
        self.await_reply(req_id, rx, ACK_TIMEOUT).await?;
        self.inner
            .tokens
            .lock()
            .expect("tokens lock")
            .insert(ctx.call_id.clone(), token.clone());
        self.inner
            .issued
            .lock()
            .expect("issued lock")
            .insert(token.clone(), ctx);
        Ok(token)
    }

    /// Revoke the credential issued for `call_id`. A dead worker has no credentials to revoke.
    pub async fn revoke(&self, call_id: &str) {
        let Some(token) = self
            .inner
            .tokens
            .lock()
            .expect("tokens lock")
            .remove(call_id)
        else {
            return;
        };
        self.inner
            .issued
            .lock()
            .expect("issued lock")
            .remove(&token);
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        if self
            .write(&ToWorker::CredsRevoke { req_id, token }, &[])
            .await
            .is_ok()
        {
            let _ = self.await_reply(req_id, rx, ACK_TIMEOUT).await;
        }
    }

    /// Send `bytes` byte-exact to `raw` through the worker, and record the exchange.
    pub async fn send(
        &self,
        raw: RawTarget,
        bytes: Vec<u8>,
        ctx: WireCtx,
        kind: OriginKind,
        parent: Option<String>,
        tags: Vec<String>,
        timeout: Duration,
    ) -> Result<Sent, InterceptError> {
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        self.write(
            &ToWorker::Send {
                req_id,
                raw,
                timeout_ms: timeout.as_millis() as u64,
                ctx,
                kind,
                parent,
                tags,
            },
            &[&bytes],
        )
        .await?;
        match self
            .await_reply(req_id, rx, timeout + Duration::from_secs(5))
            .await?
        {
            Reply::Exchange(exchange_id, record) => Ok(Sent {
                exchange_id,
                record: *record,
            }),
            _ => Err(InterceptError::Worker {
                code: "protocol".into(),
                message: "send answered without an exchange".into(),
            }),
        }
    }

    /// Run a fuzz run (US6): stream `variants` to the worker in batches of ≤ 256, and wait for its
    /// `fuzz.done`. The worker paces every variant at `min(rps, policy)` and the session's own limit,
    /// re-checks scope on each, and records each as an exchange tagged `fuzz` and `v<index>`.
    #[allow(clippy::too_many_arguments)]
    pub async fn fuzz(
        &self,
        run_id: &str,
        raw: RawTarget,
        variants: Vec<Vec<u8>>,
        ctx: WireCtx,
        rps: u32,
        concurrency: u32,
        timeout: Duration,
        budget: Duration,
    ) -> Result<FuzzCounts, InterceptError> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .fuzz_waiters
            .lock()
            .expect("fuzz lock")
            .insert(run_id.to_string(), tx);
        let total = variants.len();
        let mut offset = 0usize;
        let mut chunks = variants.chunks(256).peekable();
        if chunks.peek().is_none() {
            // Nothing to send still completes the run.
            self.write(
                &ToWorker::FuzzStart {
                    run_id: run_id.into(),
                    raw: raw.clone(),
                    timeout_ms: timeout.as_millis() as u64,
                    ctx: ctx.clone(),
                    count: 0,
                    offset: 0,
                    last: true,
                    rps,
                    concurrency,
                },
                &[],
            )
            .await?;
        }
        while let Some(chunk) = chunks.next() {
            let segs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
            self.write(
                &ToWorker::FuzzStart {
                    run_id: run_id.into(),
                    raw: raw.clone(),
                    timeout_ms: timeout.as_millis() as u64,
                    ctx: ctx.clone(),
                    count: chunk.len() as u32,
                    offset: offset as u32,
                    last: offset + chunk.len() >= total,
                    rps,
                    concurrency,
                },
                &segs,
            )
            .await?;
            offset += chunk.len();
        }
        match tokio::time::timeout(budget, rx).await {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(_)) => Err(InterceptError::Unavailable(
                "the proxy worker exited".into(),
            )),
            Err(_) => {
                let _ = self
                    .write(
                        &ToWorker::FuzzCancel {
                            run_id: run_id.into(),
                        },
                        &[],
                    )
                    .await;
                Err(InterceptError::Worker {
                    code: "timeout".into(),
                    message: format!(
                        "the fuzz run exceeded its {}s budget and was cancelled",
                        budget.as_secs()
                    ),
                })
            }
        }
    }

    /// Install an intercept rule (US7); returns its id. `matcher`/`action` are validated by the worker.
    pub async fn add_rule(
        &self,
        matcher: serde_json::Value,
        action: serde_json::Value,
    ) -> Result<String, InterceptError> {
        let id = format!("R{}", self.inner.next_rule.fetch_add(1, Ordering::Relaxed));
        let spec = serde_json::json!({ "id": id, "matcher": matcher, "action": action });
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        self.write(
            &ToWorker::RuleAdd {
                req_id,
                rule: spec.clone(),
            },
            &[],
        )
        .await?;
        self.await_reply(req_id, rx, ACK_TIMEOUT).await?;
        self.inner.rules.lock().expect("rules lock").push(RuleInfo {
            id: id.clone(),
            spec,
            hits: 0,
        });
        Ok(id)
    }

    pub async fn remove_rule(&self, rule_id: &str) -> Result<(), InterceptError> {
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        self.write(
            &ToWorker::RuleRemove {
                req_id,
                rule_id: rule_id.into(),
            },
            &[],
        )
        .await?;
        self.await_reply(req_id, rx, ACK_TIMEOUT).await?;
        self.inner
            .rules
            .lock()
            .expect("rules lock")
            .retain(|r| r.id != rule_id);
        Ok(())
    }

    /// Decide a held request: `"forward"`, `"drop"`, or `{"forward_edited": [Edit…]}`.
    pub async fn release_hold(
        &self,
        hold_id: &str,
        decision: serde_json::Value,
    ) -> Result<(), InterceptError> {
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        self.write(
            &ToWorker::HoldRelease {
                req_id,
                hold_id: hold_id.into(),
                decision,
            },
            &[],
        )
        .await?;
        self.await_reply(req_id, rx, ACK_TIMEOUT).await?;
        self.inner
            .held
            .lock()
            .expect("held lock")
            .retain(|h| h.hold_id != hold_id);
        Ok(())
    }

    /// Installed rules with hit counts, and the requests held now.
    pub fn rules_and_holds(&self) -> (Vec<RuleInfo>, Vec<HeldInfo>) {
        (
            self.inner.rules.lock().expect("rules lock").clone(),
            self.inner.held.lock().expect("held lock").clone(),
        )
    }

    fn track_rule_event(&self, ev: &ProxyEvent) {
        use crate::proxy_event::ProxyEventKind as K;
        match ev.kind {
            K::RuleFired | K::Held => {
                let ids: Vec<String> = match (&ev.detail["rule_ids"], &ev.detail["rule_id"]) {
                    (serde_json::Value::Array(a), _) => a
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    (_, serde_json::Value::String(s)) => vec![s.clone()],
                    _ => Vec::new(),
                };
                // Count each match once: a hold on `held`; a modify or a drop on `rule_fired`. A held
                // request later dropped by the model reports `drop_held`, which is not a new match.
                let counts = ev.kind == K::Held || ev.detail["action"] != "drop_held";
                if counts {
                    let mut rules = self.inner.rules.lock().expect("rules lock");
                    for r in rules.iter_mut().filter(|r| ids.contains(&r.id)) {
                        r.hits += 1;
                    }
                }
            }
            K::AutoForwarded => {
                if let Some(h) = ev.detail["hold_id"].as_str() {
                    self.inner
                        .held
                        .lock()
                        .expect("held lock")
                        .retain(|x| x.hold_id != h);
                }
            }
            _ => {}
        }
    }

    /// Replace the worker's scope (after the kernel reload, US3) and wait for the ack.
    pub async fn update_scope(&self, scope: HttpScope) -> Result<(), InterceptError> {
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        self.write(
            &ToWorker::ScopeUpdate {
                req_id,
                http_scope: scope.clone(),
            },
            &[],
        )
        .await?;
        self.await_reply(req_id, rx, ACK_TIMEOUT).await?;
        *self.inner.scope.lock().expect("scope lock") = scope;
        Ok(())
    }

    /// VM-test builds only: ask the worker to `connect(2)` to `addr` (or `open(2)` `path`) from inside
    /// the proxy scope, and return the errno (0 = it succeeded). The `http-proxy-scope` and
    /// `http-proxy-fs-deny` VM cases use this to show the kernel confines the proxy itself.
    #[cfg(feature = "vm-test")]
    pub async fn debug_probe(
        &self,
        connect: Option<String>,
        read: Option<String>,
    ) -> Result<i32, InterceptError> {
        let req_id = self.next_req();
        let rx = self.expect(req_id);
        let frame = match (connect, read) {
            (Some(addr), None) => ToWorker::DebugConnect { req_id, addr },
            (None, Some(path)) => ToWorker::DebugRead { req_id, path },
            _ => {
                return Err(InterceptError::Worker {
                    code: "invalid".into(),
                    message: "exactly one of connect/read".into(),
                })
            }
        };
        self.write(&frame, &[]).await?;
        match self.await_reply(req_id, rx, Duration::from_secs(10)).await {
            Err(InterceptError::Worker { code, message }) if code == "errno" => {
                Ok(message.parse().unwrap_or(-1))
            }
            Err(e) => Err(e),
            Ok(_) => Ok(0),
        }
    }

    /// Ask the worker to exit, then make sure it has.
    pub async fn shutdown(&self) {
        let _ = self.write(&ToWorker::Shutdown, &[]).await;
        let mut live = self.inner.live.lock().await;
        live.alive = false;
        live.writer = None;
        if let Some(mut child) = live.child.take() {
            if tokio::time::timeout(Duration::from_secs(2), child.wait())
                .await
                .is_err()
            {
                let _ = child.kill().await;
            }
        }
    }

    /// Test hook: kill the worker without telling it (the fail-closed path).
    #[doc(hidden)]
    pub async fn kill_worker_for_test(&self) {
        let mut live = self.inner.live.lock().await;
        if let Some(child) = live.child.as_mut() {
            let _ = child.kill().await;
        }
    }

    /// Test hook: the worker's pid.
    #[doc(hidden)]
    pub async fn worker_pid(&self) -> Option<u32> {
        self.inner
            .live
            .lock()
            .await
            .child
            .as_ref()
            .and_then(|c| c.id())
    }

    fn next_req(&self) -> u64 {
        self.inner.next_req.fetch_add(1, Ordering::Relaxed)
    }

    fn expect(&self, req_id: u64) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .insert(req_id, tx);
        rx
    }

    async fn await_reply(
        &self,
        req_id: u64,
        rx: oneshot::Receiver<Reply>,
        timeout: Duration,
    ) -> Result<Reply, InterceptError> {
        let r = tokio::time::timeout(timeout, rx).await;
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .remove(&req_id);
        match r {
            Ok(Ok(Reply::Error { code, message })) => Err(InterceptError::Worker { code, message }),
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(InterceptError::Unavailable(
                "the proxy worker exited".into(),
            )),
            Err(_) => Err(InterceptError::Unavailable(
                "the proxy worker did not answer in time".into(),
            )),
        }
    }

    async fn write(&self, msg: &ToWorker, segs: &[&[u8]]) -> Result<(), InterceptError> {
        let mut live = self.inner.live.lock().await;
        if !live.alive {
            return Err(InterceptError::Unavailable(
                "the proxy worker is not running".into(),
            ));
        }
        let Some(w) = live.writer.as_mut() else {
            return Err(InterceptError::Unavailable(
                "the proxy worker is not running".into(),
            ));
        };
        if let Err(e) = w.write(msg, segs).await {
            live.alive = false;
            return Err(InterceptError::Unavailable(format!("control channel: {e}")));
        }
        Ok(())
    }

    /// Spawn the worker, hand it fd 3, send `init`, await `hello`, and start the reader. Boxed with
    /// an explicit `Send`: the reader it starts can call it again (the one restart), and a recursive
    /// `async fn` has no nameable type for the compiler to prove that of.
    fn launch(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(self.launch_inner())
    }

    async fn launch_inner(&self) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let mut cmd = (self.inner.spawn)().map_err(|e| format!("proxy worker command: {e}"))?;
        let fd = match self.inner.listener.lock().expect("listener lock").as_ref() {
            Some(l) => l.as_raw_fd(),
            None => return Err("the proxy listener is closed".into()),
        };
        // SAFETY: runs between fork and exec using only async-signal-safe syscalls (dup2, fcntl).
        // fd 3 becomes the listener and is the only descriptor beyond stdio that survives exec:
        // CLOEXEC is cleared on it alone.
        unsafe {
            cmd.pre_exec(move || {
                if fd != 3 && libc::dup2(fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("spawn proxy worker: {e}"))?;
        let stdin = child.stdin.take().ok_or("worker stdin")?;
        let stdout = child.stdout.take().ok_or("worker stdout")?;
        if let Some(stderr) = child.stderr.take() {
            let inner = Arc::downgrade(&self.inner);
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(stderr).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    if let Some(i) = inner.upgrade() {
                        i.notices
                            .lock()
                            .expect("notices lock")
                            .push(format!("proxy worker: {}", crate::safe_text::safe_line(&l)));
                    }
                }
            });
        }

        let mut writer = FrameWriter::new(stdin);
        writer
            .write(
                &ToWorker::Init {
                    session_id: self.inner.cfg.session_id.clone(),
                    http_scope: self.http_scope(),
                },
                &[],
            )
            .await
            .map_err(|e| format!("init: {e}"))?;
        let mut reader = FrameReader::new(
            stdout,
            self.inner.cfg.http_scope.limits.max_body_bytes + (1 << 20),
        );
        let hello = tokio::time::timeout(HELLO_TIMEOUT, reader.read::<FromWorker>()).await;
        match hello {
            Ok(Ok(Some((FromWorker::Hello { ca_cert_pem, .. }, _)))) => {
                *self.inner.ca_cert_pem.lock().expect("ca lock") = ca_cert_pem;
            }
            Ok(Ok(other)) => {
                let _ = child.kill().await;
                return Err(format!("proxy worker did not say hello: {other:?}"));
            }
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(format!("proxy worker: {e}"));
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err("proxy worker did not start within 10s".into());
            }
        }
        {
            let mut live = self.inner.live.lock().await;
            live.writer = Some(writer);
            live.child = Some(child);
            live.alive = true;
        }
        let me = self.clone();
        tokio::spawn(async move { me.read_loop(reader).await });
        Ok(())
    }

    async fn read_loop(self, mut reader: FrameReader<tokio::process::ChildStdout>) {
        loop {
            match reader.read::<FromWorker>().await {
                Ok(Some((frame, segs))) => self.on_frame(frame, segs).await,
                Ok(None) | Err(_) => break,
            }
        }
        self.on_death().await;
    }

    async fn on_frame(&self, frame: FromWorker, segs: Vec<Vec<u8>>) {
        match frame {
            FromWorker::Hello { .. } => {}
            FromWorker::Ack { req_id } => self.complete(req_id, Reply::Ack),
            FromWorker::Error {
                req_id,
                code,
                message,
            } => match req_id {
                Some(id) => self.complete(id, Reply::Error { code, message }),
                None => self
                    .inner
                    .notices
                    .lock()
                    .expect("notices lock")
                    .push(format!("proxy worker error: {code}: {message}")),
            },
            FromWorker::Exchange(rec) => {
                let bytes = ExchangeBytes::from_segments(segs, rec.has_original);
                let stored = self.with_store(|s| {
                    let id = s.insert_exchange(&rec, &bytes);
                    if let Some(sum) = s.take_eviction_summary() {
                        self.inner.notices.lock().expect("notices lock").push(format!(
                            "exchange store over its cap: evicted {} bodies ({} bytes); their rows remain",
                            sum.blobs, sum.bytes
                        ));
                    }
                    id
                });
                match (stored, rec.req_id) {
                    (Ok(id), Some(req)) => self.complete(req, Reply::Exchange(id, Box::new(rec))),
                    (Ok(_), None) => {}
                    (Err(e), Some(req)) => self.complete(
                        req,
                        Reply::Error {
                            code: "store".into(),
                            message: e.to_string(),
                        },
                    ),
                    (Err(e), None) => self
                        .inner
                        .notices
                        .lock()
                        .expect("notices lock")
                        .push(format!("exchange store: {e}")),
                }
            }
            FromWorker::Tunnel(t) => {
                let _ = self.with_store(|s| s.insert_tunnel(&t));
            }
            FromWorker::ProxyEvent(ev) => {
                if ev.kind.is_refusal() {
                    let _ = self.with_store(|s| s.insert_refusal(&ev));
                }
                self.track_rule_event(&ev);
                if let Some(sink) = self.inner.on_event.lock().expect("sink lock").as_ref() {
                    sink(&ev);
                }
                self.inner
                    .events
                    .lock()
                    .expect("events lock")
                    .entry(ev.call_id.clone().unwrap_or_default())
                    .or_default()
                    .push(ev);
            }
            FromWorker::Resolve { req_id, host } => {
                let resolver = self.inner.cfg.resolver.clone();
                let me = self.clone();
                tokio::spawn(async move {
                    let r = tokio::task::spawn_blocking(move || resolver(&host))
                        .await
                        .unwrap_or_else(|e| Err(e.to_string()));
                    let (addrs, error) = match r {
                        Ok(a) => (a, None),
                        Err(e) => (Vec::new(), Some(e)),
                    };
                    let _ = me
                        .write(
                            &ToWorker::Resolved {
                                req_id,
                                addrs,
                                error,
                            },
                            &[],
                        )
                        .await;
                });
            }
            FromWorker::FuzzDone {
                run_id,
                sent,
                refused,
                failed,
                state,
            } => {
                if let Some(tx) = self
                    .inner
                    .fuzz_waiters
                    .lock()
                    .expect("fuzz lock")
                    .remove(&run_id)
                {
                    let _ = tx.send(FuzzCounts {
                        sent,
                        refused,
                        failed,
                        state,
                    });
                }
            }
            FromWorker::Held {
                hold_id,
                summary,
                deadline,
            } => {
                self.inner.held.lock().expect("held lock").push(HeldInfo {
                    hold_id,
                    summary: crate::safe_text::safe_line(&summary).into_owned(),
                    deadline,
                });
            }
        }
    }

    fn complete(&self, req_id: u64, reply: Reply) {
        if let Some(tx) = self
            .inner
            .pending
            .lock()
            .expect("pending lock")
            .remove(&req_id)
        {
            let _ = tx.send(reply);
        }
    }

    /// The worker is gone. Fail everything pending, then restart once — never silently.
    async fn on_death(&self) {
        let restarts = {
            let mut live = self.inner.live.lock().await;
            if !live.alive && live.writer.is_none() {
                return; // an orderly shutdown
            }
            live.alive = false;
            live.writer = None;
            if let Some(mut c) = live.child.take() {
                let _ = c.kill().await;
            }
            live.restarts
        };
        // Dropping the senders wakes every waiter with "the proxy worker exited".
        self.inner.pending.lock().expect("pending lock").clear();
        self.inner.fuzz_waiters.lock().expect("fuzz lock").clear();
        if restarts >= MAX_RESTARTS {
            self.inner.listener.lock().expect("listener lock").take();
            self.notice(
                "the HTTP interception proxy exited again; HTTP tools are unavailable for the rest \
                 of this session, and tool children can reach no network"
                    .into(),
            );
            return;
        }
        self.inner.live.lock().await.restarts += 1;
        self.notice("the HTTP interception proxy exited; restarting it once".into());
        match self.launch().await {
            Ok(()) => {
                // Re-issue the credentials of calls still in flight.
                let issued: Vec<(String, WireCtx)> = self
                    .inner
                    .issued
                    .lock()
                    .expect("issued lock")
                    .iter()
                    .map(|(t, c)| (t.clone(), c.clone()))
                    .collect();
                for (token, ctx) in issued {
                    let req_id = self.next_req();
                    let rx = self.expect(req_id);
                    if self
                        .write(&ToWorker::CredsIssue { req_id, token, ctx }, &[])
                        .await
                        .is_ok()
                    {
                        let _ = self.await_reply(req_id, rx, ACK_TIMEOUT).await;
                    }
                }
            }
            Err(e) => {
                self.inner.listener.lock().expect("listener lock").take();
                self.notice(format!(
                    "the HTTP interception proxy could not be restarted ({e}); HTTP tools are \
                 unavailable for the rest of this session"
                ))
            }
        }
    }

    fn notice(&self, msg: String) {
        self.inner.notices.lock().expect("notices lock").push(msg);
    }
}

/// 16 random bytes from the kernel CSPRNG, hex.
fn mint_token() -> String {
    let mut b = [0u8; 16];
    // SAFETY: `b` is a valid writable 16-byte buffer for the duration of the call.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    assert_eq!(n, 16, "getrandom failed minting a proxy credential");
    b.iter().map(|x| format!("{x:02x}")).collect()
}
