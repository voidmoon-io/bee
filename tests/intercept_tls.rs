//! 019-http-intercept US4 (T066) — look inside HTTPS where, and only where, the operator says.
//!
//! Inspected hosts are decrypted with a per-session CA a client can be made to trust; every other
//! in-scope host is a tunnel the proxy never reads. The CA key never leaves worker memory: not in a
//! frame, the store, the transcript, or the bundle (SC-008).

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::net::SocketAddr;
#[cfg(not(feature = "enforce"))]
use std::path::Path;
#[cfg(not(feature = "enforce"))]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use harness::{scope, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// CONNECT through the proxy (with the call's credential), then TLS with `roots`.
async fn tls_through(
    s: &mut Session,
    authority: &str,
    sni: &str,
    roots: rustls::RootCertStore,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let call = "toolu_tls";
    let token = s
        .icpt
        .issue(bee::intercept::control::WireCtx {
            call_id: call.into(),
            turn: 1,
            origin: "tool".into(),
        })
        .await
        .unwrap();
    let auth = {
        let raw = format!("{call}:{token}");
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in raw.as_bytes().chunks(3) {
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
    };
    let proxy = SocketAddr::from(([127, 0, 0, 1], s.icpt.port()));
    let mut sock = TcpStream::connect(proxy).await.unwrap();
    sock.write_all(
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if sock.read(&mut b).await.unwrap() == 0 {
            return Err("proxy closed".into());
        }
        head.push(b[0]);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(
            rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap(),
            sock,
        )
        .await
        .map_err(|e| e.to_string())
}

fn roots_from_pem(pem: &str) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = decode_b64(&b64);
    roots
        .add(rustls::pki_types::CertificateDer::from(der))
        .unwrap();
    roots
}

fn decode_b64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            _ => 63,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

async fn get(tls: &mut tokio_rustls::client::TlsStream<TcpStream>, path: &str) -> String {
    get_as(tls, path, "app.test").await
}

async fn get_as(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    path: &str,
    host: &str,
) -> String {
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

async fn wait_row(s: &Session, sql: &str) -> Option<(Option<u16>, String, Option<bool>)> {
    for _ in 0..100 {
        let r = s.icpt.with_store(|st| {
            st.conn()
                .query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .ok()
        });
        if r.is_some() {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

#[tokio::test]
async fn an_inspected_host_is_decrypted_and_recorded() {
    let (_, https, _fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let mut s = Session::start(
        scope(
            &format!(
                "targets = [\"app.test:{}\"]\ninspect = [\"app.test\"]\ninsecure_upstream = [\"app.test\"]",
                https.port()
            ),
            &[("app.test", "127.0.0.1")],
        ),
        &[("app.test", "127.0.0.1")],
        &[],
    )
    .await;
    let pem = s
        .icpt
        .ca_cert_pem()
        .expect("inspect ⇒ hello carries the CA");
    assert!(!pem.contains("PRIVATE KEY"));
    // A client trusting ONLY the session CA verifies the minted leaf.
    let mut tls = tls_through(
        &mut s,
        &format!("app.test:{}", https.port()),
        "app.test",
        roots_from_pem(&pem),
    )
    .await
    .expect("leaf verifies against the session CA");
    let resp = get(&mut tls, "/search?q=inside").await;
    assert!(resp.contains("Results for inside"), "{resp}");

    let row = wait_row(
        &s,
        "SELECT status, tls, upstream_verified FROM exchanges WHERE target LIKE '/search%'",
    )
    .await
    .expect("the decrypted exchange is recorded");
    assert_eq!(
        row,
        (Some(200), "inspected".into(), Some(false)),
        "insecure_upstream is recorded"
    );
}

#[tokio::test]
async fn without_insecure_upstream_a_self_signed_upstream_fails_verification() {
    let (_, https, _fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let mut s = Session::start(
        scope(
            &format!(
                "targets = [\"app.test:{}\"]\ninspect = [\"app.test\"]",
                https.port()
            ),
            &[("app.test", "127.0.0.1")],
        ),
        &[("app.test", "127.0.0.1")],
        &[],
    )
    .await;
    let pem = s.icpt.ca_cert_pem().unwrap();
    let mut tls = tls_through(
        &mut s,
        &format!("app.test:{}", https.port()),
        "app.test",
        roots_from_pem(&pem),
    )
    .await
    .unwrap();
    let resp = get(&mut tls, "/").await;
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    let row = wait_row(
        &s,
        "SELECT status, outcome, upstream_verified FROM exchanges",
    )
    .await
    .unwrap();
    assert!(row.1.starts_with("failed:"), "{row:?}");
}

#[tokio::test]
async fn a_non_inspected_host_is_only_a_tunnel() {
    let (_, https, fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let mut s = Session::start(
        scope(
            &format!("targets = [\"app.test:{}\"]", https.port()),
            &[("app.test", "127.0.0.1")],
        ),
        &[("app.test", "127.0.0.1")],
        &[],
    )
    .await;
    assert!(s.icpt.ca_cert_pem().is_none(), "no inspect ⇒ no CA at all");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            fx.cert_der.clone().unwrap(),
        ))
        .unwrap();
    let mut tls = tls_through(
        &mut s,
        &format!("app.test:{}", https.port()),
        "app.test",
        roots,
    )
    .await
    .expect("the real certificate, end to end");
    assert!(get(&mut tls, "/search?q=t").await.contains("Results for t"));
    drop(tls);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (ex, tun): (i64, i64) = s.icpt.with_store(|st| {
        (
            st.conn()
                .query_row("SELECT COUNT(*) FROM exchanges", [], |r| r.get(0))
                .unwrap(),
            st.conn()
                .query_row("SELECT COUNT(*) FROM tunnels", [], |r| r.get(0))
                .unwrap(),
        )
    });
    assert_eq!(
        (ex, tun),
        (0, 1),
        "a tunnel record, and no decrypted exchange"
    );
}

#[tokio::test]
async fn an_h2_only_upstream_is_reported_not_passed_through() {
    let (h2, _h) = vuln_target::start_h2_only();
    let mut s = Session::start(
        scope(
            &format!(
                "targets = [\"h2.test:{}\"]\ninspect = [\"h2.test\"]\ninsecure_upstream = [\"h2.test\"]",
                h2.port()
            ),
            &[("h2.test", "127.0.0.1")],
        ),
        &[("h2.test", "127.0.0.1")],
        &[],
    )
    .await;
    let pem = s.icpt.ca_cert_pem().unwrap();
    let mut tls = tls_through(
        &mut s,
        &format!("h2.test:{}", h2.port()),
        "h2.test",
        roots_from_pem(&pem),
    )
    .await
    .unwrap();
    let resp = get_as(&mut tls, "/", "h2.test").await;
    assert!(resp.contains("upstream_protocol_unsupported"), "{resp}");
}

// ── the session bundle and SC-008, through a real `bee run` session ─────────────────────────────

#[cfg(not(feature = "enforce"))]
#[test]
fn the_bundle_holds_system_roots_plus_one_ca_and_no_key_anywhere() {
    let (_, https, _fx) = vuln_target::start_with(true);
    let https = https.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let w = |name: &str, body: String| {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    w(
        "policy.toml",
        format!(
            "[policy]\nname = \"tls\"\n[policy.http]\ntargets = [\"127.0.0.1:{}\"]\ninspect = [\"127.0.0.1\"]\n",
            https.port()
        ),
    );
    let s = w(
        "s.toml",
        "[scenario]\nid = \"tls\"\npolicy_path = \"policy.toml\"\nsystem_prompt = \"t\"\ntask = \"t\"\n\
         turn_limit = 4\ntimeout_secs = 60\ntools = [\"bash\"]\n"
            .into(),
    );
    let probe =
        "echo BUNDLE=$SSL_CERT_FILE; echo CERTS=$(grep -c 'BEGIN CERTIFICATE' $SSL_CERT_FILE); \
                 echo KEYS=$(grep -c 'PRIVATE.KEY' $SSL_CERT_FILE); \
                 echo SAME=$([ \"$SSL_CERT_FILE\" = \"$CURL_CA_BUNDLE\" ] && echo yes)";
    let p = w(
        "p.toml",
        format!(
            "[provider]\nprovider = \"mock\"\nmodel = \"m\"\n[[provider.script]]\ntool = \"bash\"\nargs = {{ command = \"{}\" }}\n[[provider.script]]\ntext = \"done\"\n",
            probe.replace('"', "\\\"")
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_bee"))
        .current_dir(dir.path())
        .args([
            "run",
            "--scenario",
            s.to_str().unwrap(),
            "--provider",
            p.to_str().unwrap(),
            "--host",
            "--http-scope-advisory",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let transcript = String::from_utf8_lossy(&out.stdout).into_owned();
    let t: serde_json::Value = serde_json::from_str(&transcript).unwrap();
    let res = t["turns"][0]["calls"][0]["result"]["content"]
        .as_str()
        .unwrap()
        .to_string();
    let field = |k: &str| {
        res.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("{k} missing:\n{res}"))
            .to_string()
    };
    let bundle = field("BUNDLE");
    let system = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
    .map(|s| s.matches("BEGIN CERTIFICATE").count())
    .unwrap_or(0);
    assert_eq!(
        field("CERTS").parse::<usize>().unwrap(),
        system + 1,
        "system roots + exactly one session CA"
    );
    assert_eq!(field("KEYS"), "0");
    assert_eq!(field("SAME"), "yes");
    assert!(
        !Path::new(&bundle).exists(),
        "the bundle is deleted at teardown"
    );
    assert!(!transcript.contains("PRIVATE KEY"));
    // Nothing in the store carries key material either.
    for entry in walk(&dir.path().join(".bee")) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(
            !bytes.windows(11).any(|w| w == b"PRIVATE KEY"),
            "{} holds key material",
            entry.display()
        );
    }
}

#[cfg(not(feature = "enforce"))]
fn walk(p: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}
