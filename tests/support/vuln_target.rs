//! `vuln_target` — the in-repo fixture target for 019-http-intercept tests (task T006).
//!
//! A deliberately vulnerable HTTP/1.1 server on `127.0.0.1:0`, plus an optional TLS listener with a
//! test-generated self-signed certificate. Every intercept test runs against it, so no test touches
//! a real network host.
//!
//! It is hand-rolled over `httparse` rather than built on hyper because `/echo` must return the
//! request head **byte for byte** — duplicate headers, odd casing, bare `\n` line endings — and that
//! is exactly what a well-behaved HTTP library normalises away. One request per connection
//! (`Connection: close`), which every client and the proxy's forwarder handle.
//!
//! Routes:
//! - `/search?q=` reflects `q` unescaped (reflected-parameter lead, US8).
//! - `/admin` → 200 only with `X-Forwarded-For: 127.0.0.1`, else 403 (replay diff, US5).
//! - `/item?id=` → 500 when `id` contains `'` (fuzz outliers, US6).
//! - `/json` → `{"user":{"role":"guest"},"meta":{"request_id":<random>}}` plus a `Date` header.
//! - `/gzip` → a gzip-encoded body.
//! - `/big` → streams 100 MB.
//! - `/redirect?to=` → 302 to `to`.
//! - `/echo` → the raw request head bytes as the body.
//! - `/bomb` → a gzip decompression bomb (256 MiB of zeros).
//!
//! Included by tests with `#[path = "support/vuln_target.rs"] mod vuln_target;` and by
//! `examples/vuln_target.rs` for the quickstart's manual smoke.

#![allow(dead_code)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// Size of the `/big` body.
pub const BIG_LEN: u64 = 100 * 1024 * 1024;
/// Plain-text body before gzip for `/gzip`.
pub const GZIP_PLAIN: &str = "hello from the gzip route\nline two\nline three\n";

/// Counters a test can read to prove a connection did — or did not — reach the fixture.
#[derive(Default)]
pub struct Counters {
    pub http_accepts: AtomicUsize,
    pub https_accepts: AtomicUsize,
    pub requests: AtomicUsize,
    /// Requests per path, keyed by the request-target's path. Small and lock-guarded: tests only.
    pub by_path: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl Counters {
    pub fn path_hits(&self, path: &str) -> usize {
        self.by_path.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}

/// Keeps the fixture alive; dropping it (or calling [`ShutdownHandle::shutdown`]) stops it.
pub struct ShutdownHandle {
    pub counters: Arc<Counters>,
    /// DER of the TLS listener's self-signed certificate (SANs: `localhost`, `app.test`,
    /// `127.0.0.1`), for clients that should trust the fixture directly.
    pub cert_der: Option<Vec<u8>>,
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ShutdownHandle {
    pub fn shutdown(mut self) {
        self.stop_now();
    }
    fn stop_now(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        self.stop_now();
    }
}

/// Start the fixture with a plain listener and a TLS listener.
pub fn start() -> (SocketAddr, Option<SocketAddr>, ShutdownHandle) {
    start_with(true)
}

/// Start the fixture; `tls` adds the rustls listener.
pub fn start_with(tls: bool) -> (SocketAddr, Option<SocketAddr>, ShutdownHandle) {
    let counters = Arc::new(Counters::default());
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let c = counters.clone();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("fixture runtime");
        rt.block_on(async move {
            let http = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
            let http_addr = http.local_addr().unwrap();
            let (https_addr, cert_der) = if tls {
                let l = TcpListener::bind("127.0.0.1:0").await.expect("bind https");
                let a = l.local_addr().unwrap();
                let (acceptor, der) = tls_acceptor();
                let c2 = c.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok((sock, _)) = l.accept().await else {
                            break;
                        };
                        c2.https_accepts.fetch_add(1, Ordering::SeqCst);
                        let acc = acceptor.clone();
                        let c3 = c2.clone();
                        tokio::spawn(async move {
                            if let Ok(s) = acc.accept(sock).await {
                                let _ = serve(s, c3).await;
                            }
                        });
                    }
                });
                (Some(a), Some(der))
            } else {
                (None, None)
            };
            let c2 = c.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = http.accept().await else {
                        break;
                    };
                    c2.http_accepts.fetch_add(1, Ordering::SeqCst);
                    let c3 = c2.clone();
                    tokio::spawn(async move {
                        let _ = serve(sock, c3).await;
                    });
                }
            });
            addr_tx.send((http_addr, https_addr, cert_der)).unwrap();
            // Park until the handle asks us to stop. The blocking recv runs off the reactor.
            let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
        });
    });
    let (http_addr, https_addr, cert_der) = addr_rx.recv().expect("fixture start");
    (
        http_addr,
        https_addr,
        ShutdownHandle {
            counters,
            cert_der,
            stop: Some(stop_tx),
            thread: Some(thread),
        },
    )
}

fn tls_acceptor() -> (tokio_rustls::TlsAcceptor, Vec<u8>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let ck = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "app.test".into(),
        "127.0.0.1".into(),
    ])
    .expect("self-signed cert");
    let der = ck.cert.der().to_vec();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der.clone())], key)
        .expect("server config");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), der)
}

/// Read one request (head + Content-Length body) and answer it.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    counters: Arc<Counters>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > 1 << 20 {
            return write_simple(&mut s, 431, "text/plain", b"head too large").await;
        }
    };
    let raw_head = buf[..head_end].to_vec();
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(&raw_head).is_err() {
        return write_simple(&mut s, 400, "text/plain", b"bad request").await;
    }
    let method = req.method.unwrap_or("").to_string();
    let target = req.path.unwrap_or("/").to_string();
    let hdr = |name: &str| -> Option<String> {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).into_owned())
    };
    let content_len: usize = hdr("content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let xff = hdr("x-forwarded-for");
    // Drain the body so the client sees a clean close.
    let mut have = buf.len() - head_end;
    while have < content_len {
        let mut chunk = [0u8; 8192];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        have += n;
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    counters.requests.fetch_add(1, Ordering::SeqCst);
    *counters
        .by_path
        .lock()
        .unwrap()
        .entry(path.clone())
        .or_default() += 1;
    let param = |k: &str| -> Option<String> {
        query.split('&').find_map(|kv| {
            let (a, b) = kv.split_once('=').unwrap_or((kv, ""));
            (a == k).then(|| percent_decode(b))
        })
    };
    let _ = method;

    match path.as_str() {
        "/search" => {
            let q = param("q").unwrap_or_default();
            let body = format!("<html><body>Results for {q}</body></html>");
            write_simple(&mut s, 200, "text/html", body.as_bytes()).await
        }
        "/admin" => {
            if xff.as_deref().map(str::trim) == Some("127.0.0.1") {
                write_simple(&mut s, 200, "text/plain", b"welcome, admin").await
            } else {
                write_simple(&mut s, 403, "text/plain", b"forbidden").await
            }
        }
        "/item" => {
            let id = param("id").unwrap_or_default();
            if id.contains('\'') {
                let body = format!("SQL syntax error near '{id}'");
                write_simple(&mut s, 500, "text/plain", body.as_bytes()).await
            } else {
                let body = format!("item {id}");
                write_simple(&mut s, 200, "text/plain", body.as_bytes()).await
            }
        }
        "/json" => {
            static SEQ: AtomicU64 = AtomicU64::new(1);
            let rid = format!(
                "{:x}{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            );
            let body = format!(r#"{{"user":{{"role":"guest"}},"meta":{{"request_id":"{rid}"}}}}"#);
            let date = httpdate_now();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: {date}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            s.write_all(head.as_bytes()).await?;
            s.write_all(body.as_bytes()).await?;
            s.shutdown().await
        }
        "/gzip" => {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(GZIP_PLAIN.as_bytes()).unwrap();
            let gz = enc.finish().unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                gz.len()
            );
            s.write_all(head.as_bytes()).await?;
            s.write_all(&gz).await?;
            s.shutdown().await
        }
        "/big" => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {BIG_LEN}\r\nConnection: close\r\n\r\n"
            );
            s.write_all(head.as_bytes()).await?;
            let chunk = vec![b'A'; 64 * 1024];
            let mut left = BIG_LEN;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                if s.write_all(&chunk[..n]).await.is_err() {
                    return Ok(()); // client gave up early: expected for capped readers
                }
                left -= n as u64;
            }
            s.shutdown().await
        }
        "/redirect" => {
            let to = param("to").unwrap_or_else(|| "/".into());
            let head = format!(
                "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            s.write_all(head.as_bytes()).await?;
            s.shutdown().await
        }
        "/echo" => write_simple(&mut s, 200, "application/octet-stream", &raw_head).await,
        "/bomb" => {
            // 256 MiB of zeros, gzipped (~250 KiB on the wire): a decompression bomb for the
            // bounded decoder. Built once per process.
            static BOMB: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
            let gz = BOMB.get_or_init(|| {
                let mut enc =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
                let zeros = vec![0u8; 1 << 20];
                for _ in 0..256 {
                    enc.write_all(&zeros).unwrap();
                }
                enc.finish().unwrap()
            });
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                gz.len()
            );
            s.write_all(head.as_bytes()).await?;
            s.write_all(gz).await?;
            s.shutdown().await
        }
        _ => write_simple(&mut s, 404, "text/plain", b"not found").await,
    }
}

/// End of the request head, accepting both `\r\n\r\n` and bare `\n\n`.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len() {
        if buf[i..].starts_with(b"\r\n\r\n") {
            return Some(i + 4);
        }
        if buf[i..].starts_with(b"\n\n") {
            return Some(i + 2);
        }
        if buf[i..].starts_with(b"\n\r\n") {
            return Some(i + 3);
        }
    }
    None
}

async fn write_simple<S: AsyncWrite + Unpin>(
    s: &mut S,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    s.shutdown().await
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
                {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An RFC 7231 IMF-fixdate for "now", without a date crate.
fn httpdate_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mn = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(mo - 1) as usize];
    format!("{wd}, {d:02} {mn} {y} {h:02}:{m:02}:{s:02} GMT")
}
