//! 019-http-intercept US1 (T031–T033) — the proxy refuses what is out of scope, unauthenticated,
//! mis-named or drifted, and fails closed when it dies.
//!
//! The real `bee proxy-worker` binary runs in **advisory** mode (no kernel scope; the host tier has
//! no BPF-LSM), driven by the real harness side, against the in-repo `vuln_target` fixture. The kernel
//! half of every guarantee — tool children reach only the proxy, the proxy reaches only the targets —
//! is the VM tier (`http-*` cases in `test/vm/remote-matrix.sh`).

#![cfg(feature = "intercept")]

#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bee::intercept::control::{OriginKind, ProxyEventKind, RawTarget, WireCtx};
use bee::intercept::sidecar::{
    Enforcement, HarnessResolver, InterceptError, Interceptor, InterceptorConfig,
};
use bee_core::compiler::HttpScope;
use bee_core::{CompileError, ExecIdentity, Policy, Resolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ── harness ──────────────────────────────────────────────────────────────────────────────────────

struct Names(HashMap<String, Vec<IpAddr>>);

impl Resolver for Names {
    fn project_root(&self) -> &str {
        "/nonexistent/project"
    }
    fn home(&self) -> &str {
        "/nonexistent/home"
    }
    fn resolve_exec(&self, n: &str) -> Result<PathBuf, CompileError> {
        Ok(PathBuf::from(n))
    }
    fn resolve_exec_identity(&self, _: &Path) -> Result<ExecIdentity, CompileError> {
        unreachable!()
    }
    fn resolve_host(&self, h: &str) -> Result<Vec<IpAddr>, CompileError> {
        if let Ok(ip) = h.parse() {
            return Ok(vec![ip]);
        }
        self.0
            .get(h)
            .cloned()
            .ok_or_else(|| CompileError::UnresolvableHost(h.into(), "unknown".into()))
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Compile a `[policy.http]` body against fixed names.
fn scope(body: &str, names: &[(&str, &str)]) -> HttpScope {
    let p = Policy::from_toml(&format!("[policy]\nname = \"t\"\n[policy.http]\n{body}\n")).unwrap();
    let n = Names(
        names
            .iter()
            .map(|(h, a)| (h.to_string(), vec![ip(a)]))
            .collect(),
    );
    p.compile_http(&n, Path::new("/bin/true"))
        .unwrap()
        .unwrap()
        .http_scope
}

struct Proxy {
    icpt: Interceptor,
    _dir: tempfile::TempDir,
}

impl Proxy {
    async fn start(scope: HttpScope, resolver: HarnessResolver) -> Proxy {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let session = format!("test-{}", std::process::id());
        let sid = session.clone();
        let spawn = Box::new(move || {
            let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_bee"));
            c.args(["proxy-worker", "--session", &sid]);
            Ok(c)
        });
        let icpt = Interceptor::start(
            InterceptorConfig {
                session_id: session,
                project_root: dir.path().to_path_buf(),
                http_scope: scope,
                enforcement: Enforcement::Advisory {
                    reason: "host test".into(),
                },
                resolver,
            },
            listener,
            spawn,
        )
        .await
        .expect("proxy starts");
        Proxy { icpt, _dir: dir }
    }

    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.icpt.port()))
    }

    async fn cred(&self, call: &str) -> String {
        self.icpt
            .issue(WireCtx {
                call_id: call.into(),
                turn: 1,
                origin: "tool".into(),
            })
            .await
            .expect("issue")
    }

    /// Wait for an exchange attributed to `call` to land in the store; its status.
    async fn exchange_status(&self, call: &str) -> Option<u16> {
        for _ in 0..100 {
            let got: Option<Option<u16>> = self.icpt.with_store(|s| {
                s.conn()
                    .query_row(
                        "SELECT status FROM exchanges WHERE call_id = ?1",
                        [call],
                        |r| r.get(0),
                    )
                    .ok()
            });
            if let Some(st) = got {
                return st;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    async fn events(&self, call: &str, kind: ProxyEventKind) -> bool {
        for _ in 0..100 {
            let evs = self.icpt.take_events(call);
            if evs.iter().any(|e| e.kind == kind) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }
}

fn names_resolver(names: &[(&str, &str)]) -> HarnessResolver {
    let m: HashMap<String, Vec<IpAddr>> = names
        .iter()
        .map(|(h, a)| (h.to_string(), vec![ip(a)]))
        .collect();
    Arc::new(move |h: &str| m.get(h).cloned().ok_or_else(|| format!("no such host {h}")))
}

fn basic(call: &str, token: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = format!("{call}:{token}");
    let b = s.as_bytes();
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One request through the proxy; the full response.
async fn through(proxy: SocketAddr, req: String) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn get(url: &str, auth: Option<&str>) -> String {
    let host = url.split('/').nth(2).unwrap();
    let mut r = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(a) = auth {
        r.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
    }
    r.push_str("\r\n");
    r
}

fn status(resp: &str) -> u16 {
    resp.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// ── T031 ─────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_in_scope_request_with_a_credential_is_forwarded_and_recorded() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        names_resolver(&[]),
    )
    .await;
    let tok = p.cred("toolu_a").await;
    let resp = through(
        p.addr(),
        get(
            &format!("http://127.0.0.1:{}/search?q=hi", http.port()),
            Some(&basic("toolu_a", &tok)),
        ),
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    assert!(resp.contains("Results for hi"));
    assert_eq!(p.exchange_status("toolu_a").await, Some(200));
}

#[tokio::test]
async fn an_out_of_scope_request_is_refused_without_connecting() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let (other, _, other_fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        names_resolver(&[]),
    )
    .await;
    let tok = p.cred("toolu_b").await;
    let resp = through(
        p.addr(),
        get(
            &format!("http://127.0.0.1:{}/", other.port()),
            Some(&basic("toolu_b", &tok)),
        ),
    )
    .await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(resp.contains("refused by proxy"), "{resp}");
    assert!(p.events("toolu_b", ProxyEventKind::RefusedOutOfScope).await);
    assert_eq!(
        other_fx
            .counters
            .http_accepts
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no connection reached the out-of-scope destination"
    );
}

#[tokio::test]
async fn a_connect_to_an_out_of_scope_host_is_refused() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        names_resolver(&[]),
    )
    .await;
    let tok = p.cred("toolu_c").await;
    let resp = through(
        p.addr(),
        format!(
            "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("toolu_c", &tok)
        ),
    )
    .await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(p.events("toolu_c", ProxyEventKind::RefusedOutOfScope).await);
}

#[tokio::test]
async fn missing_wrong_and_revoked_credentials_get_407() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        names_resolver(&[]),
    )
    .await;
    let url = format!("http://127.0.0.1:{}/", http.port());
    let tok = p.cred("toolu_d").await;

    for auth in [
        None,
        Some(basic("toolu_d", "00000000000000000000000000000000")),
        Some(basic("toolu_other", &tok)), // right token, wrong call
    ] {
        let resp = through(p.addr(), get(&url, auth.as_deref())).await;
        assert_eq!(status(&resp), 407, "{resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains("proxy-authenticate: basic"),
            "{resp}"
        );
    }
    assert!(p.events("", ProxyEventKind::RefusedBadCredential).await);

    // Valid, then revoked when the call ends: the same token no longer works.
    let ok = through(p.addr(), get(&url, Some(&basic("toolu_d", &tok)))).await;
    assert_eq!(status(&ok), 404, "{ok}"); // fixture: unknown route, but it got there
    p.icpt.revoke("toolu_d").await;
    let resp = through(p.addr(), get(&url, Some(&basic("toolu_d", &tok)))).await;
    assert_eq!(status(&resp), 407, "{resp}");
}

#[tokio::test]
async fn an_egress_host_tunnels_and_is_recorded() {
    let (_, https, _fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let p = Proxy::start(
        scope(
            &format!(
                "targets = [\"app.test:1\"]\negress = [\"egress.test:{}\"]",
                https.port()
            ),
            &[("app.test", "127.0.0.9"), ("egress.test", "127.0.0.1")],
        ),
        names_resolver(&[("egress.test", "127.0.0.1")]),
    )
    .await;
    let tok = p.cred("toolu_e").await;
    let (mut tls, _) = connect_tls(
        p.addr(),
        &format!("egress.test:{}", https.port()),
        "egress.test",
        &basic("toolu_e", &tok),
        None,
    )
    .await;
    tls.write_all(
        b"GET /search?q=tunnel HTTP/1.1\r\nHost: egress.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf).await;
    assert!(String::from_utf8_lossy(&buf).contains("Results for tunnel"));
    drop(tls);

    // The tunnel is recorded; its content is not (it was never decrypted).
    let mut found = false;
    for _ in 0..100 {
        let n: i64 = p.icpt.with_store(|s| {
            s.conn()
                .query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE call_id = 'toolu_e' AND sni = 'egress.test'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        });
        if n == 1 {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(found, "tunnel recorded");
}

#[tokio::test]
async fn an_egress_host_is_not_forwarded_or_testable() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(
            &format!(
                "targets = [\"app.test:1\"]\negress = [\"127.0.0.1:{}\"]",
                http.port()
            ),
            &[("app.test", "127.0.0.9")],
        ),
        names_resolver(&[]),
    )
    .await;
    let tok = p.cred("toolu_f").await;
    let resp = through(
        p.addr(),
        get(
            &format!("http://127.0.0.1:{}/", http.port()),
            Some(&basic("toolu_f", &tok)),
        ),
    )
    .await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(p.events("toolu_f", ProxyEventKind::RefusedEgressOnly).await);

    // And a model-originated send to it is refused the same way (proxy-control invariant 2).
    let sent = p
        .icpt
        .send(
            RawTarget {
                scheme: "http".into(),
                host: "127.0.0.1".into(),
                port: http.port(),
            },
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            WireCtx {
                call_id: "toolu_f2".into(),
                turn: 1,
                origin: "tool".into(),
            },
            OriginKind::Tool,
            None,
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(sent.record.status, None);
    assert!(sent.record.outcome.label().contains("refused_egress_only"));
}

#[tokio::test]
async fn a_websocket_upgrade_gets_501() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        names_resolver(&[]),
    )
    .await;
    let tok = p.cred("toolu_g").await;
    let resp = through(
        p.addr(),
        format!(
            "GET http://127.0.0.1:{}/ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Proxy-Authorization: Basic {}\r\n\r\n",
            http.port(),
            basic("toolu_g", &tok)
        ),
    )
    .await;
    assert_eq!(status(&resp), 501, "{resp}");
}

#[tokio::test]
async fn dns_drift_is_refused_naming_both_addresses() {
    let (http, _, fx) = vuln_target::start_with(false);
    // Compiled: drift.test → 127.0.0.2. Now: the harness resolves it to 127.0.0.3.
    let p = Proxy::start(
        scope(
            &format!("targets = [\"drift.test:{}\"]", http.port()),
            &[("drift.test", "127.0.0.2")],
        ),
        names_resolver(&[("drift.test", "127.0.0.3")]),
    )
    .await;
    let tok = p.cred("toolu_h").await;
    let resp = through(
        p.addr(),
        get(
            &format!("http://drift.test:{}/", http.port()),
            Some(&basic("toolu_h", &tok)),
        ),
    )
    .await;
    assert_eq!(status(&resp), 502, "{resp}");
    let mut drift = None;
    for _ in 0..100 {
        drift = p
            .icpt
            .take_events("toolu_h")
            .into_iter()
            .find(|e| e.kind == ProxyEventKind::RefusedAddressDrift);
        if drift.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let d = drift.expect("refused_address_drift recorded");
    assert_eq!(d.detail["now_resolves_to"][0], "127.0.0.3");
    assert_eq!(d.detail["compiled"][0], "127.0.0.2");
    assert_eq!(
        fx.counters
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no connect was attempted"
    );
}

// ── T032: CONNECT host = SNI ─────────────────────────────────────────────────────────────────────

/// CONNECT through the proxy, then a TLS handshake with `sni`. `trust` = the fixture's cert DER (a
/// verifying client); `None` = accept anything.
async fn connect_tls(
    proxy: SocketAddr,
    authority: &str,
    sni: &str,
    auth: &str,
    trust: Option<&[u8]>,
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert_eq!(status(&head), 200, "{head}");
    let cfg = match trust {
        None => bee::intercept::worker::raw::client_config(true, &[b"http/1.1"]),
        Some(der) => {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(der.to_vec()))
                .unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            Arc::new(
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        }
    };
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let tls = tokio_rustls::TlsConnector::from(cfg)
        .connect(name, s)
        .await
        .expect("handshake");
    (tls, head)
}

#[tokio::test]
async fn a_matching_sni_splices_to_the_real_certificate() {
    let (_, https, fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let p = Proxy::start(
        scope(
            &format!("targets = [\"app.test:{}\"]", https.port()),
            &[("app.test", "127.0.0.1")],
        ),
        names_resolver(&[("app.test", "127.0.0.1")]),
    )
    .await;
    let tok = p.cred("toolu_i").await;
    // A verifying client trusting only the fixture's own cert: the proxy did not interpose.
    let (mut tls, _) = connect_tls(
        p.addr(),
        &format!("app.test:{}", https.port()),
        "app.test",
        &basic("toolu_i", &tok),
        fx.cert_der.as_deref(),
    )
    .await;
    tls.write_all(b"GET /search?q=sni HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf).await;
    assert!(String::from_utf8_lossy(&buf).contains("Results for sni"));
}

#[tokio::test]
async fn a_mismatched_sni_closes_the_tunnel() {
    let (_, https, fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let p = Proxy::start(
        scope(
            &format!("targets = [\"app.test:{}\"]", https.port()),
            &[("app.test", "127.0.0.1")],
        ),
        names_resolver(&[("app.test", "127.0.0.1")]),
    )
    .await;
    let tok = p.cred("toolu_j").await;
    let mut s = TcpStream::connect(p.addr()).await.unwrap();
    s.write_all(
        format!(
            "CONNECT app.test:{port} HTTP/1.1\r\nHost: app.test:{port}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("toolu_j", &tok),
            port = https.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = vec![0u8; 19]; // "HTTP/1.1 200 OK\r\n\r\n"
    s.read_exact(&mut head).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("other.test".to_string()).unwrap();
    let cfg = bee::intercept::worker::raw::client_config(true, &[b"http/1.1"]);
    let r = tokio_rustls::TlsConnector::from(cfg).connect(name, s).await;
    assert!(r.is_err(), "the handshake must not complete");
    assert!(
        p.events("toolu_j", ProxyEventKind::RefusedSniMismatch)
            .await
    );
    assert_eq!(
        fx.counters
            .https_accepts
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the mismatched hello never went upstream"
    );
}

// ── T033: fail closed when the worker dies ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_dead_worker_restarts_once_then_fails_closed() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let p = Proxy::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        names_resolver(&[]),
    )
    .await;
    let send = |call: &'static str| {
        let icpt = p.icpt.clone();
        async move {
            icpt.send(
                RawTarget {
                    scheme: "http".into(),
                    host: "127.0.0.1".into(),
                    port: http.port(),
                },
                format!("GET /search?q={call} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .into_bytes(),
                WireCtx {
                    call_id: call.into(),
                    turn: 1,
                    origin: "tool".into(),
                },
                OriginKind::Tool,
                None,
                vec![],
                Duration::from_secs(5),
            )
            .await
        }
    };
    assert_eq!(send("before").await.unwrap().record.status, Some(200));

    // First death: exactly one restart, announced.
    let first = p.icpt.worker_pid().await.unwrap();
    p.icpt.kill_worker_for_test().await;
    let mut restarted = false;
    for _ in 0..200 {
        if let Some(pid) = p.icpt.worker_pid().await {
            if pid != first && p.icpt.available().await {
                restarted = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(restarted, "restarted once");
    assert!(p
        .icpt
        .take_notices()
        .iter()
        .any(|n| n.contains("restarting it once")));
    assert_eq!(
        send("after-restart").await.unwrap().record.status,
        Some(200)
    );

    // Second death: no more restarts; HTTP tools are unavailable and so is the proxy port.
    p.icpt.kill_worker_for_test().await;
    for _ in 0..100 {
        if !p.icpt.available().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!p.icpt.available().await);
    assert!(matches!(
        send("dead").await,
        Err(InterceptError::Unavailable(_))
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(p.icpt.worker_pid().await.is_none(), "no second restart");
    assert!(p
        .icpt
        .take_notices()
        .iter()
        .any(|n| n.contains("unavailable for the rest of this session")));
    // A client that tries the proxy now is refused at once rather than left hanging.
    let r = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(p.addr())).await;
    assert!(matches!(r, Ok(Err(_))), "{r:?}");
}
