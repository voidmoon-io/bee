//! CONNECT (019 T039, research R7): the authority decides, then the ClientHello is checked.
//!
//! - Host not in `targets ∪ egress` → `403` and `refused_out_of_scope`, with **no** upstream connect.
//! - In scope → resolve with the drift check, answer `200`, take the upgraded stream, and buffer the
//!   client's ClientHello (≤ 16 KiB). Its SNI must equal the CONNECT host (`refused_sni_mismatch`
//!   otherwise, connection closed); a ClientHello without SNI passes only for an IP-literal
//!   authority. Only then is the upstream connected, the buffered bytes written, and the two sides
//!   spliced. A `tunnel` record with byte counts follows on close (FR-024).
//!
//! Hosts in `inspect` are decrypted instead (US4, [`super::mitm`]) — until that lands they tunnel
//! like any other in-scope host, which only ever shows *less*.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::listen::{empty, refusal_response, text, ProxyBody};
use super::scope::{split_authority, Refusal};
use super::Worker;
use crate::intercept::control::{now_rfc3339, FromWorker, ProxyEventKind, TunnelRecord, WireCtx};

/// Largest ClientHello the worker buffers before deciding.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// How long a client may take to send its ClientHello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn handle(
    worker: Arc<Worker>,
    ctx: WireCtx,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let Some((host, port)) = req
        .uri()
        .authority()
        .and_then(|a| split_authority(a.as_str().rsplit('@').next().unwrap_or("")))
    else {
        return text(
            StatusCode::BAD_REQUEST,
            "bee proxy: CONNECT needs host:port\n",
        );
    };
    let scope = worker.scope();
    if let Err(r) = scope.check_target(&host, port) {
        worker.refuse(&r, Some(&ctx.call_id));
        return refusal_response(&r);
    }
    let addr = match scope.resolve_checked(&host, port, worker.as_ref()).await {
        Ok(a) => a,
        Err(r) => {
            worker.refuse(&r, Some(&ctx.call_id));
            return refusal_response(&r);
        }
    };

    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let mut client = TokioIo::new(upgraded);
        let started = now_rfc3339();

        // Buffer the ClientHello and read its SNI before anything goes upstream.
        // A tunnel whose first bytes are not a TLS ClientHello carries nothing the SNI check can
        // vouch for, so it is refused the same way a mismatch is.
        let hello = tokio::time::timeout(HELLO_TIMEOUT, read_client_hello(&mut client)).await;
        let (hello, sni) = match hello {
            Ok(Ok(v)) => v,
            Ok(Err(why)) => return refuse_hello(&worker, &ctx, &host, port, &why),
            Err(_) => {
                return refuse_hello(
                    &worker,
                    &ctx,
                    &host,
                    port,
                    "timed out waiting for a ClientHello",
                )
            }
        };
        if let Err(r) = scope.check_sni(&host, port, sni.as_deref()) {
            worker.refuse(&r, Some(&ctx.call_id));
            let _ = client.shutdown().await;
            return;
        }

        let outcome;
        let (mut up_n, mut down_n) = (0u64, 0u64);
        match tokio::net::TcpStream::connect(addr).await {
            Err(e) => outcome = format!("connect_failed: {e}"),
            Ok(mut upstream) => {
                let _ = upstream.set_nodelay(true);
                if upstream.write_all(&hello).await.is_err() {
                    outcome = "upstream_write_failed".to_string();
                } else {
                    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                        Ok((a, b)) => {
                            up_n = a;
                            down_n = b;
                            outcome = "closed".into();
                        }
                        Err(e) => outcome = format!("error: {e}"),
                    }
                }
            }
        }
        worker.emit(
            FromWorker::Tunnel(TunnelRecord {
                call_id: Some(ctx.call_id.clone()),
                host: host.clone(),
                port,
                sni,
                started,
                ended: now_rfc3339(),
                bytes_up: up_n + hello.len() as u64,
                bytes_down: down_n,
                outcome,
            }),
            Vec::new(),
        );
    });
    let mut resp = Response::new(empty());
    *resp.status_mut() = StatusCode::OK;
    resp
}

fn refuse_hello(worker: &Worker, ctx: &WireCtx, host: &str, port: u16, why: &str) {
    let r = Refusal {
        kind: ProxyEventKind::RefusedSniMismatch,
        host: host.to_string(),
        port,
        detail: serde_json::json!({ "reason": why }),
    };
    worker.refuse(&r, Some(&ctx.call_id));
}

/// Read until rustls has a complete ClientHello; return the bytes read and its SNI.
async fn read_client_hello<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Result<(Vec<u8>, Option<String>), String> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("client closed before a ClientHello".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        // A fresh acceptor over everything buffered so far: cheap, and a partial hello just asks
        // for more.
        let mut acc = rustls::server::Acceptor::default();
        let mut cur = Cursor::new(&buf[..]);
        while (cur.position() as usize) < buf.len() {
            if acc.read_tls(&mut cur).is_err() {
                break;
            }
        }
        match acc.accept() {
            Ok(Some(accepted)) => {
                let sni = accepted.client_hello().server_name().map(str::to_string);
                return Ok((buf, sni));
            }
            Ok(None) => {}
            Err(_) => return Err("not a TLS ClientHello".into()),
        }
        if buf.len() > MAX_CLIENT_HELLO {
            return Err("ClientHello exceeds 16 KiB".into());
        }
    }
}
