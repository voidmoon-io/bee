//! The proxy worker: `bee proxy-worker`, running inside the proxy scope (019, contracts/proxy-control.md).
//!
//! One per session. The harness binds the listening socket and hands it over as **fd 3**; the
//! control channel is stdio. The worker:
//! - serves the session proxy on fd 3 ([`listen`]): per-call credentials, CONNECT tunnels with the
//!   SNI check ([`connect`]), plain-HTTP forwarding ([`forward`]);
//! - sends model-originated requests byte-exact through [`raw`], paced by [`pace`];
//! - checks host names, roles and DNS drift in user space ([`scope`]), on top of the kernel's
//!   address rules for its scope;
//! - reports every exchange, tunnel and refusal to the harness, which owns the store.
//!
//! It writes nothing to disk. Name resolution is asked of the harness: the proxy scope admits only
//! the compiled target addresses, and a DNS server is not one of them (research R2 addendum).

pub mod connect;
pub mod forward;
pub mod listen;
pub mod mitm;
pub mod pace;
pub mod raw;
pub mod rules;
pub mod scope;

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use bee_core::policy::HttpLimits;

use super::control::{
    now_rfc3339, ExchangeRecord, FrameReader, FrameWriter, FromWorker, Origin, OriginKind, Outcome,
    ProxyEvent, RawTarget, SendPath, Timing, TlsInfo, ToWorker, WireCtx, PROTOCOL_VERSION,
};
use scope::{HostResolver, Refusal, ScopeChecker};

/// Exit status when fd 3 is not a listening IPv4-loopback TCP socket (contract §Process).
pub const EXIT_BAD_FD: u8 = 2;

/// How long the worker waits for the harness to resolve a name.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Head room above `max_body_bytes` for a control segment: a request head travels beside its body.
const SEGMENT_HEADROOM: u64 = 1 << 20;

type Outgoing = (FromWorker, Vec<Vec<u8>>);

/// State shared by every connection and control handler.
pub struct Worker {
    pub session_id: String,
    scope: RwLock<ScopeChecker>,
    /// token → the call it was issued to. Revoked tokens are removed.
    creds: Mutex<HashMap<String, WireCtx>>,
    out: mpsc::UnboundedSender<Outgoing>,
    resolves: Mutex<HashMap<u64, oneshot::Sender<Result<Vec<IpAddr>, String>>>>,
    next_req: AtomicU64,
    pub pacer: pace::Pacer,
    pub limits: HttpLimits,
    /// The session CA, when `inspect` is non-empty (US4). Its key never leaves this process.
    ca: Option<mitm::SessionCa>,
    /// Fuzz runs in flight (US6).
    fuzz: Mutex<HashMap<String, Arc<FuzzRun>>>,
    /// Intercept rules and held requests (US7). Session-only: worker memory, nothing else.
    pub rules: rules::Rules,
}

impl Worker {
    fn new(
        session_id: String,
        scope: bee_core::compiler::HttpScope,
        out: mpsc::UnboundedSender<Outgoing>,
        ca: Option<mitm::SessionCa>,
    ) -> Self {
        let limits = scope.limits;
        Worker {
            ca,
            fuzz: Mutex::new(HashMap::new()),
            rules: rules::Rules::default(),
            session_id,
            scope: RwLock::new(ScopeChecker::new(scope)),
            creds: Mutex::new(HashMap::new()),
            out,
            resolves: Mutex::new(HashMap::new()),
            next_req: AtomicU64::new(1),
            pacer: pace::Pacer::new(limits.rps, limits.concurrency),
            limits,
        }
    }

    /// A snapshot of the current scope (cheap: it is small, and a snapshot never changes mid-request).
    pub fn scope(&self) -> ScopeChecker {
        self.scope.read().expect("scope lock").clone()
    }

    /// The call a credential was issued to, if it is live.
    pub fn credential(&self, token: &str) -> Option<WireCtx> {
        self.creds.lock().expect("creds lock").get(token).cloned()
    }

    pub fn emit(&self, frame: FromWorker, segments: Vec<Vec<u8>>) {
        // A closed channel means the harness is gone; the worker is about to exit anyway.
        let _ = self.out.send((frame, segments));
    }

    /// Record a refusal as a proxy-layer event (research R14).
    pub fn refuse(&self, r: &Refusal, call_id: Option<&str>) {
        self.emit(
            FromWorker::ProxyEvent(ProxyEvent {
                ts: now_rfc3339(),
                session_id: self.session_id.clone(),
                call_id: call_id.map(str::to_string),
                layer: "proxy".into(),
                kind: r.kind,
                host: r.host.clone(),
                port: r.port,
                detail: r.detail.clone(),
            }),
            Vec::new(),
        );
    }

    /// The session CA, if this session inspects anything.
    pub fn ca(&self) -> Option<&mitm::SessionCa> {
        self.ca.as_ref()
    }

    /// A rule or hold notice as a proxy event (research R14).
    pub fn rule_event(
        &self,
        kind: crate::intercept::control::ProxyEventKind,
        host: &str,
        port: u16,
        ctx: &WireCtx,
        detail: serde_json::Value,
    ) {
        self.emit(
            FromWorker::ProxyEvent(ProxyEvent {
                ts: now_rfc3339(),
                session_id: self.session_id.clone(),
                call_id: Some(ctx.call_id.clone()),
                layer: "proxy".into(),
                kind,
                host: host.to_string(),
                port,
                detail,
            }),
            Vec::new(),
        );
    }

    /// Largest stored body.
    pub fn max_body(&self) -> u64 {
        self.limits.max_body_bytes
    }
}

impl HostResolver for Worker {
    fn resolve(
        &self,
        host: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, String>> + Send + '_>>
    {
        let host = host.to_string();
        Box::pin(async move {
            let req_id = self.next_req.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            self.resolves
                .lock()
                .expect("resolves lock")
                .insert(req_id, tx);
            self.emit(FromWorker::Resolve { req_id, host }, Vec::new());
            match tokio::time::timeout(RESOLVE_TIMEOUT, rx).await {
                Ok(Ok(r)) => r,
                _ => {
                    self.resolves.lock().expect("resolves lock").remove(&req_id);
                    Err("resolution timed out".into())
                }
            }
        })
    }
}

/// `bee proxy-worker --session <id>`.
pub fn run(session: &str) -> ExitCode {
    let listener = match take_fd3() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bee proxy-worker: {e}");
            return ExitCode::from(EXIT_BAD_FD);
        }
    };
    // Explicit, rather than inferred from features: rustls panics on an ambiguous provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("bee proxy-worker: runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let session = session.to_string();
    match rt.block_on(async move {
        let listener =
            tokio::net::TcpListener::from_std(listener).map_err(|e| format!("listener: {e}"))?;
        serve(listener, tokio::io::stdin(), tokio::io::stdout(), &session).await
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bee proxy-worker: {e}");
            ExitCode::from(1)
        }
    }
}

/// The worker proper, over any listener and control streams — `run` uses fd 3 and stdio; tests may
/// drive it in-process.
pub async fn serve<R, W>(
    listener: tokio::net::TcpListener,
    ctl_in: R,
    ctl_out: W,
    session: &str,
) -> Result<(), String>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = FrameReader::new(ctl_in, 1 << 20);
    let (scope, session_id) = match reader.read::<ToWorker>().await {
        Ok(Some((
            ToWorker::Init {
                http_scope,
                session_id,
            },
            _,
        ))) => (http_scope, session_id),
        Ok(Some(_)) => return Err("first control frame was not init".into()),
        Ok(None) => return Err("control channel closed before init".into()),
        Err(e) => return Err(e.to_string()),
    };
    if session_id != session {
        return Err(format!(
            "init names session {session_id:?}, but this worker was started for {session:?}"
        ));
    }
    reader.set_max_segment(scope.limits.max_body_bytes + SEGMENT_HEADROOM);

    let (tx, mut rx) = mpsc::unbounded_channel::<Outgoing>();
    let mut writer = FrameWriter::new(ctl_out);
    let writer_task = tokio::spawn(async move {
        while let Some((frame, segs)) = rx.recv().await {
            let refs: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
            if writer.write(&frame, &refs).await.is_err() {
                break;
            }
        }
    });

    // The CA exists only when something is to be inspected; `hello` carries its certificate and
    // nothing else (proxy-control invariant 1).
    let ca = if scope.inspect.is_empty() {
        None
    } else {
        Some(mitm::SessionCa::generate()?)
    };
    let ca_cert_pem = ca.as_ref().map(|c| c.cert_pem().to_string());
    let worker = Arc::new(Worker::new(session_id, scope, tx, ca));
    worker.emit(
        FromWorker::Hello {
            version: PROTOCOL_VERSION,
            ca_cert_pem,
        },
        Vec::new(),
    );

    let acceptor = {
        let w = worker.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let _ = sock.set_nodelay(true);
                tokio::spawn(listen::serve_conn(w.clone(), sock));
            }
        })
    };

    let result = control_loop(&worker, &mut reader).await;
    acceptor.abort();
    drop(worker);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer_task).await;
    result
}

async fn control_loop<R: AsyncRead + Unpin>(
    worker: &Arc<Worker>,
    reader: &mut FrameReader<R>,
) -> Result<(), String> {
    loop {
        let (frame, segs) = match reader.read::<ToWorker>().await {
            Ok(Some(f)) => f,
            // The harness closed the channel: that is the shutdown signal of last resort.
            Ok(None) => return Ok(()),
            // A malformed frame closes the channel (fail closed).
            Err(e) => return Err(e.to_string()),
        };
        match frame {
            ToWorker::Init { .. } => return Err("duplicate init".into()),
            ToWorker::CredsIssue { req_id, token, ctx } => {
                worker.creds.lock().expect("creds lock").insert(token, ctx);
                worker.emit(FromWorker::Ack { req_id }, Vec::new());
            }
            ToWorker::CredsRevoke { req_id, token } => {
                worker.creds.lock().expect("creds lock").remove(&token);
                worker.emit(FromWorker::Ack { req_id }, Vec::new());
            }
            ToWorker::ScopeUpdate { req_id, http_scope } => {
                worker.scope.write().expect("scope lock").update(http_scope);
                worker.emit(FromWorker::Ack { req_id }, Vec::new());
            }
            ToWorker::Resolved {
                req_id,
                addrs,
                error,
            } => {
                if let Some(tx) = worker
                    .resolves
                    .lock()
                    .expect("resolves lock")
                    .remove(&req_id)
                {
                    let _ = tx.send(match error {
                        Some(e) => Err(e),
                        None => Ok(addrs),
                    });
                }
            }
            ToWorker::Send {
                req_id,
                raw,
                timeout_ms,
                ctx,
                kind,
                parent,
                tags,
            } => {
                let bytes = segs.into_iter().next().unwrap_or_default();
                let w = worker.clone();
                tokio::spawn(async move {
                    send_one(
                        &w,
                        Some(req_id),
                        raw,
                        timeout_ms,
                        ctx,
                        kind,
                        parent,
                        None,
                        tags,
                        bytes,
                    )
                    .await;
                });
            }
            ToWorker::Shutdown => return Ok(()),
            ToWorker::FuzzStart {
                run_id,
                raw,
                timeout_ms,
                ctx,
                count: _,
                offset,
                last,
                rps,
                concurrency,
            } => {
                use std::sync::atomic::Ordering::SeqCst;
                let run = worker.fuzz_run(&run_id, rps, concurrency);
                run.outstanding.fetch_add(1, SeqCst);
                if last {
                    run.last_seen.store(true, SeqCst);
                }
                tokio::spawn(fuzz_batch(
                    worker.clone(),
                    run_id,
                    run,
                    raw,
                    timeout_ms,
                    ctx,
                    offset,
                    segs,
                ));
            }
            ToWorker::FuzzCancel { run_id } => {
                let run = worker.fuzz.lock().expect("fuzz lock").get(&run_id).cloned();
                if let Some(run) = run {
                    run.cancelled
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    worker.maybe_finish(&run_id, &run);
                }
            }
            ToWorker::RuleAdd { req_id, rule } => {
                let r = serde_json::from_value::<rules::RuleSpec>(rule)
                    .map_err(|e| e.to_string())
                    .and_then(|spec| worker.rules.add(spec));
                worker.emit(ack_or_error(req_id, r), Vec::new());
            }
            ToWorker::RuleRemove { req_id, rule_id } => {
                let r = if worker.rules.remove(&rule_id) {
                    Ok(())
                } else {
                    Err(format!("no rule {rule_id}"))
                };
                worker.emit(ack_or_error(req_id, r), Vec::new());
            }
            ToWorker::HoldRelease {
                req_id,
                hold_id,
                decision,
            } => {
                let r = serde_json::from_value::<rules::HoldDecision>(decision)
                    .map_err(|e| e.to_string())
                    .and_then(|d| worker.rules.release(&hold_id, d));
                worker.emit(ack_or_error(req_id, r), Vec::new());
            }
            #[cfg(feature = "vm-test")]
            ToWorker::DebugConnect { req_id, addr } => {
                worker.emit(debug_connect(req_id, &addr).await, Vec::new());
            }
            #[cfg(feature = "vm-test")]
            ToWorker::DebugRead { req_id, path } => {
                worker.emit(debug_read(req_id, &path), Vec::new());
            }
        }
    }
}

/// A model-originated request: re-check scope (proxy-control invariant 2 — the harness may have
/// checked too), pace, resolve with the drift check, then send byte-exact. Shared by `send` and every
/// fuzz variant. Returns how it ended, for a fuzz run's counts.
#[allow(clippy::too_many_arguments)]
async fn send_one(
    worker: &Worker,
    req_id: Option<u64>,
    raw: RawTarget,
    timeout_ms: u64,
    ctx: WireCtx,
    kind: OriginKind,
    parent: Option<String>,
    fuzz_run: Option<String>,
    tags: Vec<String>,
    bytes: Vec<u8>,
) -> SendEnd {
    let (method, target) = raw::request_line(&bytes);
    let (req_head, req_body) = raw::split_head(&bytes);
    let mut rec = ExchangeRecord {
        req_id,
        call_id: Some(ctx.call_id.clone()),
        turn: Some(ctx.turn),
        origin: Origin {
            kind,
            path: SendPath::Raw,
            parent,
            fuzz_run,
            rule_ids: vec![],
        },
        scheme: raw.scheme.clone(),
        host: raw.host.clone(),
        port: raw.port,
        method,
        target,
        status: None,
        tls: TlsInfo::None,
        timing: Timing {
            started: now_rfc3339(),
            ..Timing::default()
        },
        req_bytes: req_body.len() as u64,
        resp_bytes: 0,
        req_truncated: false,
        resp_truncated: false,
        has_original: false,
        outcome: Outcome::Completed,
        tags,
    };
    let refused = |rec: &mut ExchangeRecord, r: Refusal| {
        worker.refuse(&r, Some(&ctx.call_id));
        rec.outcome = Outcome::Refused { kind: r.kind };
    };

    let scope = worker.scope();
    let checked = scope
        .check_testable(&raw.host, raw.port)
        .and_then(|_| scope.check_host_header(&raw::host_headers(&bytes), &raw.host, raw.port));
    let addr = match checked {
        Err(r) => {
            refused(&mut rec, r);
            None
        }
        Ok(()) => match scope.resolve_checked(&raw.host, raw.port, worker).await {
            Err(r) => {
                refused(&mut rec, r);
                None
            }
            Ok(a) => Some(a),
        },
    };
    let mut resp_head = Vec::new();
    let mut resp_body = Vec::new();
    if let Some(addr) = addr {
        let _permit = worker.pacer.acquire().await;
        let tls = (raw.scheme == "https").then(|| raw::TlsUpstream {
            server_name: raw.host.clone(),
            insecure: scope.is_insecure_upstream(&raw.host),
        });
        match raw::send_raw(
            addr,
            tls,
            &bytes,
            worker.max_body(),
            Duration::from_millis(timeout_ms.max(1)),
        )
        .await
        {
            Ok(r) => {
                rec.status = r.status;
                rec.timing.connect_ms = Some(r.connect_ms);
                rec.timing.ttfb_ms = r.ttfb_ms;
                rec.timing.total_ms = Some(r.total_ms);
                rec.resp_bytes = r.body_wire_len;
                rec.resp_truncated = r.truncated;
                if let Some(v) = r.upstream_verified {
                    rec.tls = TlsInfo::Client {
                        upstream_verified: v,
                    };
                }
                if r.truncated {
                    rec.outcome = Outcome::Truncated;
                }
                resp_head = r.head;
                resp_body = r.body;
            }
            Err(e) => rec.outcome = Outcome::Failed { reason: e },
        }
    }
    let end = match &rec.outcome {
        Outcome::Refused { .. } => SendEnd::Refused,
        Outcome::Failed { .. } => SendEnd::Failed,
        _ => SendEnd::Sent,
    };
    worker.emit(
        FromWorker::Exchange(rec),
        vec![req_head.to_vec(), req_body.to_vec(), resp_head, resp_body],
    );
    end
}

/// How one send ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendEnd {
    Sent,
    Refused,
    Failed,
}

/// One fuzz run in the worker (US6): its own pacer — never looser than the policy's, which every
/// variant also passes through — its counts, and its batches in flight.
pub struct FuzzRun {
    pacer: pace::Pacer,
    sent: std::sync::atomic::AtomicU32,
    refused: std::sync::atomic::AtomicU32,
    failed: std::sync::atomic::AtomicU32,
    outstanding: std::sync::atomic::AtomicU32,
    last_seen: std::sync::atomic::AtomicBool,
    cancelled: std::sync::atomic::AtomicBool,
    done: std::sync::atomic::AtomicBool,
}

impl Worker {
    fn fuzz_run(&self, id: &str, rps: u32, concurrency: u32) -> Arc<FuzzRun> {
        self.fuzz
            .lock()
            .expect("fuzz lock")
            .entry(id.to_string())
            .or_insert_with(|| {
                Arc::new(FuzzRun {
                    pacer: pace::Pacer::new(
                        rps.clamp(1, self.limits.rps),
                        concurrency.clamp(1, self.limits.concurrency),
                    ),
                    sent: Default::default(),
                    refused: Default::default(),
                    failed: Default::default(),
                    outstanding: Default::default(),
                    last_seen: Default::default(),
                    cancelled: Default::default(),
                    done: Default::default(),
                })
            })
            .clone()
    }

    /// Emit `fuzz.done` once: when the last batch has arrived and no batch is still running.
    fn maybe_finish(&self, id: &str, run: &FuzzRun) {
        use std::sync::atomic::Ordering::SeqCst;
        let finished = run.outstanding.load(SeqCst) == 0
            && (run.last_seen.load(SeqCst) || run.cancelled.load(SeqCst));
        if finished && !run.done.swap(true, SeqCst) {
            self.fuzz.lock().expect("fuzz lock").remove(id);
            self.emit(
                FromWorker::FuzzDone {
                    run_id: id.to_string(),
                    sent: run.sent.load(SeqCst),
                    refused: run.refused.load(SeqCst),
                    failed: run.failed.load(SeqCst),
                    state: if run.cancelled.load(SeqCst) {
                        "cancelled".into()
                    } else {
                        "completed".into()
                    },
                },
                Vec::new(),
            );
        }
    }
}

/// One batch of a fuzz run: every variant through scope, the run's pacer and the session's, then the
/// raw writer. Variants run concurrently up to the run's concurrency.
#[allow(clippy::too_many_arguments)]
async fn fuzz_batch(
    worker: Arc<Worker>,
    run_id: String,
    run: Arc<FuzzRun>,
    raw: RawTarget,
    timeout_ms: u64,
    ctx: WireCtx,
    offset: u32,
    variants: Vec<Vec<u8>>,
) {
    use std::sync::atomic::Ordering::SeqCst;
    let mut tasks = tokio::task::JoinSet::new();
    for (i, bytes) in variants.into_iter().enumerate() {
        if run.cancelled.load(SeqCst) {
            break;
        }
        let permit = run.pacer.acquire().await;
        let (w, r, raw, ctx, id) = (
            worker.clone(),
            run.clone(),
            raw.clone(),
            ctx.clone(),
            run_id.clone(),
        );
        let idx = offset + i as u32;
        tasks.spawn(async move {
            let _permit = permit;
            let end = send_one(
                &w,
                None,
                raw,
                timeout_ms,
                ctx,
                OriginKind::Fuzz,
                None,
                Some(id),
                vec!["fuzz".into(), format!("v{idx}")],
                bytes,
            )
            .await;
            match end {
                SendEnd::Sent => r.sent.fetch_add(1, SeqCst),
                SendEnd::Refused => r.refused.fetch_add(1, SeqCst),
                SendEnd::Failed => r.failed.fetch_add(1, SeqCst),
            };
        });
    }
    while tasks.join_next().await.is_some() {}
    run.outstanding.fetch_sub(1, SeqCst);
    worker.maybe_finish(&run_id, &run);
}

/// Verify fd 3 is a listening IPv4-loopback TCP socket and take ownership of it.
fn take_fd3() -> Result<std::net::TcpListener, String> {
    use std::os::fd::FromRawFd;
    const FD: libc::c_int = 3;
    // SAFETY: `sockaddr_in` is POD; `getsockname` writes at most `len` bytes into it.
    let (family, addr) = unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockname(FD, (&mut sa as *mut libc::sockaddr_in).cast(), &mut len) != 0 {
            return Err(format!(
                "fd 3 is not a socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        (sa.sin_family, u32::from_be(sa.sin_addr.s_addr))
    };
    if family != libc::AF_INET as libc::sa_family_t {
        return Err("fd 3 is not an IPv4 socket".into());
    }
    if addr != u32::from(std::net::Ipv4Addr::LOCALHOST) {
        return Err("fd 3 is not bound to 127.0.0.1".into());
    }
    let mut listening: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `listening` is a valid c_int out-parameter of the given length.
    let rc = unsafe {
        libc::getsockopt(
            FD,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut listening as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 || listening == 0 {
        return Err("fd 3 is not a listening socket".into());
    }
    // SAFETY: fd 3 was verified above to be a listening TCP socket that this process owns — the
    // harness passed it for exactly this purpose and nothing else in the worker uses it.
    let l = unsafe { std::net::TcpListener::from_raw_fd(FD) };
    l.set_nonblocking(true).map_err(|e| format!("fd 3: {e}"))?;
    Ok(l)
}

#[cfg(feature = "vm-test")]
async fn debug_connect(req_id: u64, addr: &str) -> FromWorker {
    let errno = match addr.parse::<std::net::SocketAddr>() {
        Err(e) => return error_frame(req_id, "bad_addr", e.to_string()),
        Ok(a) => match tokio::net::TcpStream::connect(a).await {
            Ok(_) => 0,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        },
    };
    error_frame(req_id, "errno", errno.to_string())
}

#[cfg(feature = "vm-test")]
fn debug_read(req_id: u64, path: &str) -> FromWorker {
    let errno = match std::fs::File::open(path) {
        Ok(_) => 0,
        Err(e) => e.raw_os_error().unwrap_or(-1),
    };
    error_frame(req_id, "errno", errno.to_string())
}

#[cfg(feature = "vm-test")]
fn error_frame(req_id: u64, code: &str, message: String) -> FromWorker {
    FromWorker::Error {
        req_id: Some(req_id),
        code: code.into(),
        message,
    }
}

fn ack_or_error(req_id: u64, r: Result<(), String>) -> FromWorker {
    match r {
        Ok(()) => FromWorker::Ack { req_id },
        Err(message) => FromWorker::Error {
            req_id: Some(req_id),
            code: "invalid".into(),
            message,
        },
    }
}
