//! SC-007: the latency the interception proxy adds to an in-scope request (019 T093).
//!
//! Direct vs proxied `GET` against the in-repo fixture target, on loopback, through the real worker
//! (advisory mode here — the host has no kernel scope). The **gate** is not this bench: it is the
//! `http-latency` VM case, on the dedicated VM, where shared-runner noise cannot fail a build
//! (research R19a). Host CI only compiles this (`cargo bench --features intercept --no-run`), so it
//! cannot rot.
//!
//! `cargo bench --features intercept --bench intercept_latency` prints criterion's comparison;
//! `BEE_LATENCY_REPORT=1` additionally runs 100 warm-up + 1,000 timed requests per path and prints
//! the median and p95 added latency in milliseconds.

#[path = "../tests/support/vuln_target.rs"]
mod vuln_target;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    target: SocketAddr,
    proxy: SocketAddr,
    auth: String,
    _icpt: bee::intercept::sidecar::Interceptor,
    _fx: vuln_target::ShutdownHandle,
    _dir: tempfile::TempDir,
}

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() {
                T[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

async fn fixture() -> Fixture {
    let (target, _, fx) = vuln_target::start_with(false);
    let dir = tempfile::tempdir().unwrap();
    let policy = bee_core::Policy::from_toml(&format!(
        "[policy]\nname = \"b\"\n[policy.http]\ntargets = [\"127.0.0.1:{}\"]\n[policy.http.limits]\nrps = 100000\nconcurrency = 64\n",
        target.port()
    ))
    .unwrap();
    let scope = policy
        .compile_http(
            &bee_userspace::SystemResolver::current(),
            std::path::Path::new("/bin/true"),
        )
        .unwrap()
        .unwrap()
        .http_scope;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // The bench binary is not `bee`; spawn the built `bee` beside it.
    let bee = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("bee"))
        .unwrap();
    let spawn = Box::new(move || {
        let mut c = std::process::Command::new(&bee);
        c.args(["proxy-worker", "--session", "bench"]);
        Ok(c)
    });
    let icpt = bee::intercept::sidecar::Interceptor::start(
        bee::intercept::sidecar::InterceptorConfig {
            session_id: "bench".into(),
            project_root: dir.path().to_path_buf(),
            http_scope: scope,
            enforcement: bee::intercept::sidecar::Enforcement::Advisory {
                reason: "bench".into(),
            },
            resolver: bee::intercept::sidecar::system_resolver(),
        },
        listener,
        spawn,
    )
    .await
    .expect("worker starts (build `bee` first: cargo build --features intercept)");
    let token = icpt
        .issue(bee::intercept::control::WireCtx {
            call_id: "bench".into(),
            turn: 0,
            origin: "tool".into(),
        })
        .await
        .unwrap();
    Fixture {
        target,
        proxy: SocketAddr::from(([127, 0, 0, 1], icpt.port())),
        auth: b64(&format!("bench:{token}")),
        _icpt: icpt,
        _fx: fx,
        _dir: dir,
    }
}

async fn get(addr: SocketAddr, req: &str) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    assert!(
        buf.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&buf)
    );
}

fn requests(f: &Fixture) -> (String, String) {
    let port = f.target.port();
    (
        format!("GET /search?q=b HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        format!(
            "GET http://127.0.0.1:{port}/search?q=b HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Proxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
            f.auth
        ),
    )
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let f = rt.block_on(fixture());
    let (direct, proxied) = requests(&f);
    let mut g = c.benchmark_group("intercept_latency");
    g.bench_function("direct", |b| {
        b.to_async(&rt).iter(|| get(f.target, &direct))
    });
    g.bench_function("proxied", |b| {
        b.to_async(&rt).iter(|| get(f.proxy, &proxied))
    });
    g.finish();

    if std::env::var_os("BEE_LATENCY_REPORT").is_some() {
        let (median, p95) = rt.block_on(async {
            let sample = |addr: SocketAddr, req: String| async move {
                for _ in 0..100 {
                    get(addr, &req).await;
                }
                let mut v = Vec::with_capacity(1000);
                for _ in 0..1000 {
                    let t = Instant::now();
                    get(addr, &req).await;
                    v.push(t.elapsed());
                }
                v.sort();
                v
            };
            let d = sample(f.target, direct.clone()).await;
            let p = sample(f.proxy, proxied.clone()).await;
            let at = |v: &[Duration], q: f64| v[((v.len() as f64 - 1.0) * q) as usize];
            (
                at(&p, 0.5).saturating_sub(at(&d, 0.5)),
                at(&p, 0.95).saturating_sub(at(&d, 0.95)),
            )
        });
        println!(
            "added_latency_ms median={:.3} p95={:.3}",
            median.as_secs_f64() * 1e3,
            p95.as_secs_f64() * 1e3
        );
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
