//! Plain-HTTP forwarding for traffic from other tools (019 T040, research R1).
//!
//! An absolute-form request (`GET http://host:port/path`) from a tool child is scope-checked — only a
//! **target** may be forwarded; an egress host is reachable as a CONNECT tunnel and nothing else —
//! resolved with the drift check, and sent upstream over a fresh hyper client connection (no pool)
//! that preserves header case. `Proxy-Authorization` and `Proxy-Connection` are stripped. The
//! response streams back to the client while its first `max_body_bytes` are teed into the exchange
//! record, which is emitted when the body ends (or the client gives up).
//!
//! The recorded request head is reconstructed from hyper's parsed request, so it is faithful but not
//! byte-exact; byte-exact requests are the raw writer's job, for model-originated traffic.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use super::listen::{refusal_response, text, ProxyBody};
use super::Worker;
use crate::intercept::control::{
    now_rfc3339, ExchangeRecord, FromWorker, Origin, OriginKind, Outcome, SendPath, Timing,
    TlsInfo, WireCtx,
};

/// Request bodies above this are refused rather than buffered without bound.
const MAX_FORWARD_REQUEST: usize = 64 * 1024 * 1024;

pub async fn handle(
    worker: Arc<Worker>,
    ctx: WireCtx,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let uri = req.uri().clone();
    if uri.scheme_str() != Some("http") {
        return text(
            StatusCode::BAD_REQUEST,
            "bee proxy: only http:// is forwarded; use CONNECT for TLS\n",
        );
    }
    let Some(auth) = uri.authority() else {
        return text(StatusCode::BAD_REQUEST, "bee proxy: no authority\n");
    };
    let host = auth.host().trim_matches(['[', ']']).to_string();
    let port = auth.port_u16().unwrap_or(80);
    let scope = worker.scope();
    if let Err(r) = scope.check_testable(&host, port) {
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

    let started = now_rfc3339();
    let t0 = Instant::now();
    let (mut parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_FORWARD_REQUEST).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return text(
                StatusCode::PAYLOAD_TOO_LARGE,
                "bee proxy: request body too large\n",
            )
        }
    };

    // Origin-form upstream; strip what was meant for the proxy.
    let target = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    parts.uri = target.parse().unwrap_or_default();
    parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);
    parts.headers.remove("proxy-connection");
    if !parts.headers.contains_key(hyper::header::HOST) {
        if let Ok(v) = auth.as_str().rsplit('@').next().unwrap_or("").parse() {
            parts.headers.insert(hyper::header::HOST, v);
        }
    }
    let req_head = head_of_request(&parts);
    let method = parts.method.to_string();

    let mut rec = ExchangeRecord {
        req_id: None,
        call_id: Some(ctx.call_id.clone()),
        turn: Some(ctx.turn),
        origin: Origin {
            kind: OriginKind::Forwarded,
            path: SendPath::Forwarded,
            parent: None,
            fuzz_run: None,
            rule_ids: vec![],
        },
        scheme: "http".into(),
        host,
        port,
        method: Some(method),
        target: Some(target),
        status: None,
        tls: TlsInfo::None,
        timing: Timing {
            started,
            ..Timing::default()
        },
        req_bytes: body.len() as u64,
        resp_bytes: 0,
        req_truncated: false,
        resp_truncated: false,
        has_original: false,
        outcome: Outcome::Completed,
        tags: vec![],
    };
    let cap = worker.max_body() as usize;
    let req_body_rec = body[..body.len().min(cap)].to_vec();
    rec.req_truncated = body.len() > cap;

    let fail = |rec: &mut ExchangeRecord, reason: String| {
        rec.outcome = Outcome::Failed {
            reason: reason.clone(),
        };
        rec.timing.total_ms = Some(t0.elapsed().as_millis() as u64);
        worker.emit(
            FromWorker::Exchange(rec.clone()),
            vec![
                req_head.clone(),
                req_body_rec.clone(),
                Vec::new(),
                Vec::new(),
            ],
        );
        text(
            StatusCode::BAD_GATEWAY,
            &format!("bee proxy: upstream {reason}\n"),
        )
    };

    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => return fail(&mut rec, format!("connect failed: {e}")),
    };
    let _ = stream.set_nodelay(true);
    rec.timing.connect_ms = Some(t0.elapsed().as_millis() as u64);
    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
    {
        Ok(v) => v,
        Err(e) => return fail(&mut rec, format!("handshake failed: {e}")),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = match sender
        .send_request(Request::from_parts(parts, Full::new(body)))
        .await
    {
        Ok(r) => r,
        Err(e) => return fail(&mut rec, format!("request failed: {e}")),
    };
    rec.timing.ttfb_ms = Some(t0.elapsed().as_millis() as u64);
    rec.status = Some(resp.status().as_u16());
    let resp_head = head_of_response(&resp);
    let (rparts, rbody) = resp.into_parts();
    let tee = TeeBody {
        inner: rbody,
        captured: Vec::new(),
        cap,
        total: 0,
        finished: false,
        draft: Some(Draft {
            worker,
            rec,
            req_head,
            req_body: req_body_rec,
            resp_head,
            t0,
        }),
    };
    Response::from_parts(rparts, tee.boxed())
}

struct Draft {
    worker: Arc<Worker>,
    rec: ExchangeRecord,
    req_head: Vec<u8>,
    req_body: Vec<u8>,
    resp_head: Vec<u8>,
    t0: Instant,
}

/// The upstream response body, passed through to the client frame by frame while the first `cap`
/// bytes are copied into the record. The record is emitted exactly once: when the body ends, or —
/// if the client stops reading first — when the body is dropped.
struct TeeBody {
    inner: Incoming,
    captured: Vec<u8>,
    cap: usize,
    total: u64,
    finished: bool,
    draft: Option<Draft>,
}

impl TeeBody {
    fn finish(&mut self, failed: Option<String>) {
        let Some(mut d) = self.draft.take() else {
            return;
        };
        d.rec.resp_bytes = self.total;
        d.rec.resp_truncated = self.total > self.cap as u64;
        d.rec.timing.total_ms = Some(d.t0.elapsed().as_millis() as u64);
        d.rec.outcome = match failed {
            Some(reason) => Outcome::Failed { reason },
            None if d.rec.resp_truncated => Outcome::Truncated,
            None => Outcome::Completed,
        };
        d.worker.emit(
            FromWorker::Exchange(d.rec),
            vec![
                d.req_head,
                d.req_body,
                d.resp_head,
                std::mem::take(&mut self.captured),
            ],
        );
    }
}

impl Body for TeeBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.total += data.len() as u64;
                    let room = this.cap.saturating_sub(this.captured.len());
                    this.captured
                        .extend_from_slice(&data[..data.len().min(room)]);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finished = true;
                this.finish(Some(format!("upstream body: {e}")));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finished = true;
                this.finish(None);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TeeBody {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(Some("client stopped reading the response".into()));
        }
    }
}

fn head_of_request(parts: &hyper::http::request::Parts) -> Vec<u8> {
    let mut s = format!("{} {} HTTP/1.1\r\n", parts.method, parts.uri);
    for (k, v) in &parts.headers {
        s.push_str(k.as_str());
        s.push_str(": ");
        s.push_str(&String::from_utf8_lossy(v.as_bytes()));
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s.into_bytes()
}

fn head_of_response<B>(resp: &Response<B>) -> Vec<u8> {
    let st = resp.status();
    let mut s = format!(
        "HTTP/1.1 {} {}\r\n",
        st.as_u16(),
        st.canonical_reason().unwrap_or("")
    );
    for (k, v) in resp.headers() {
        s.push_str(k.as_str());
        s.push_str(": ");
        s.push_str(&String::from_utf8_lossy(v.as_bytes()));
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s.into_bytes()
}
