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
use super::rules::{HoldDecision, Verdict};
use super::Worker;
use crate::intercept::control::ProxyEventKind;
use crate::intercept::control::{
    now_rfc3339, ExchangeRecord, FromWorker, Origin, OriginKind, Outcome, SendPath, Timing,
    TlsInfo, WireCtx,
};
use crate::intercept::diff::Edit;

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
    let hosts: Vec<String> = req
        .headers()
        .get_all(hyper::header::HOST)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect();
    if let Err(r) = scope
        .check_testable(&host, port)
        .and_then(|_| scope.check_host_header(&hosts, &host, port))
    {
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
    let host_header = auth.as_str().rsplit('@').next().unwrap_or("").to_string();
    relay(
        worker,
        ctx,
        Upstream::Plain(addr),
        host,
        port,
        host_header,
        req,
    )
    .await
}

/// A request decrypted on an inspected CONNECT tunnel (US4): origin-form, already scope-checked
/// at CONNECT time; re-checked here because the tunnel outlives a scope change.
pub async fn handle_inspected(
    worker: Arc<Worker>,
    ctx: WireCtx,
    host: String,
    port: u16,
    sni: String,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let scope = worker.scope();
    let hosts: Vec<String> = req
        .headers()
        .get_all(hyper::header::HOST)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect();
    if let Err(r) = scope
        .check_testable(&host, port)
        .and_then(|_| scope.check_host_header(&hosts, &host, port))
    {
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
    let insecure = scope.is_insecure_upstream(&host);
    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    relay(
        worker,
        ctx,
        Upstream::Tls {
            addr,
            sni,
            insecure,
        },
        host,
        port,
        host_header,
        req,
    )
    .await
}

enum Upstream {
    Plain(std::net::SocketAddr),
    Tls {
        addr: std::net::SocketAddr,
        sni: String,
        insecure: bool,
    },
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> Io for T {}

/// Forward `req` upstream over a fresh connection and stream the response back, teeing the record.
async fn relay(
    worker: Arc<Worker>,
    ctx: WireCtx,
    upstream: Upstream,
    host: String,
    port: u16,
    host_header: String,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let started = now_rfc3339();
    let t0 = Instant::now();
    let uri = req.uri().clone();
    let (mut parts, body) = req.into_parts();
    let mut body = match Limited::new(body, MAX_FORWARD_REQUEST).collect().await {
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
        if let Ok(v) = host_header.parse() {
            parts.headers.insert(hyper::header::HOST, v);
        }
    }
    let mut req_head = head_of_request(&parts);
    let method = parts.method.to_string();
    let (scheme, tls) = match &upstream {
        Upstream::Plain(_) => ("http", TlsInfo::None),
        Upstream::Tls { sni, insecure, .. } => (
            "https",
            TlsInfo::Inspected {
                sni: sni.clone(),
                upstream_verified: !insecure,
            },
        ),
    };

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
        scheme: scheme.into(),
        host,
        port,
        method: Some(method),
        target: Some(target),
        status: None,
        tls,
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
    // Intercept rules (US7): modify, drop or hold the request before it goes upstream.
    let mut original: Option<(Vec<u8>, Vec<u8>)> = None;
    let path = crate::intercept::store::path_of(rec.target.as_deref().unwrap_or("/"));
    let verdict = worker.rules.evaluate(&super::rules::Seen {
        host: &rec.host,
        method: rec.method.as_deref().unwrap_or(""),
        path: &path,
        head: &req_head,
        body: &body,
    });
    let mut to_apply: Option<(Vec<String>, Vec<Edit>)> = None;
    match verdict {
        Verdict::Pass => {}
        Verdict::Modify { rule_ids, edits } => to_apply = Some((rule_ids, edits)),
        Verdict::Drop { rule_id } => {
            return dropped(
                &worker,
                &ctx,
                rec,
                req_head,
                body.to_vec(),
                &rule_id,
                t0,
                "drop",
            )
        }
        Verdict::Hold { rule_id, timeout } => {
            let (hold_id, rx) = worker.rules.hold();
            let deadline = crate::intercept::control::format_ts(
                time::OffsetDateTime::now_utc() + time::Duration::seconds(timeout.as_secs() as i64),
            );
            worker.emit(
                FromWorker::Held {
                    hold_id: hold_id.clone(),
                    summary: format!(
                        "{} {}:{}{}",
                        rec.method.as_deref().unwrap_or(""),
                        rec.host,
                        rec.port,
                        path
                    ),
                    deadline,
                },
                Vec::new(),
            );
            worker.rule_event(
                ProxyEventKind::Held,
                &rec.host,
                rec.port,
                &ctx,
                serde_json::json!({ "rule_id": rule_id, "hold_id": hold_id }),
            );
            rec.origin.rule_ids.push(rule_id.clone());
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(HoldDecision::Forward)) => {}
                Ok(Ok(HoldDecision::Drop)) => {
                    return dropped(
                        &worker,
                        &ctx,
                        rec,
                        req_head,
                        body.to_vec(),
                        &rule_id,
                        t0,
                        "drop_held",
                    )
                }
                Ok(Ok(HoldDecision::ForwardEdited(e))) => to_apply = Some((Vec::new(), e)),
                // The deadline passed (or the decision channel went away): forward unchanged, and
                // say so — a held request is never left waiting (FR-022).
                _ => {
                    worker.rules.expire(&hold_id);
                    worker.rule_event(
                        ProxyEventKind::AutoForwarded,
                        &rec.host,
                        rec.port,
                        &ctx,
                        serde_json::json!({ "rule_id": rule_id, "hold_id": hold_id }),
                    );
                }
            }
        }
    }
    if let Some((rule_ids, edits)) = to_apply {
        let (h, b) = match crate::intercept::diff::apply_edits(&req_head, &body, &edits) {
            Ok(v) => v,
            Err(e) => {
                return text(
                    StatusCode::BAD_GATEWAY,
                    &format!("bee proxy: an intercept rule's edit failed: {e}\n"),
                )
            }
        };
        // A rewritten request is checked again: a rule cannot move traffic out of scope.
        let mut whole = h.clone();
        whole.extend_from_slice(&b);
        if let Err(r) = worker.scope().check_host_header(
            &super::raw::request_authorities(&whole),
            &rec.host,
            rec.port,
        ) {
            worker.refuse(&r, Some(&ctx.call_id));
            return refusal_response(&r);
        }
        if let Err(e) = parts_from_head(&h, &mut parts) {
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("bee proxy: an intercept rule produced an invalid request: {e}\n"),
            );
        }
        original = Some((std::mem::replace(&mut req_head, h), body.to_vec()));
        body = Bytes::from(b);
        rec.req_bytes = body.len() as u64;
        rec.has_original = true;
        if !rule_ids.is_empty() {
            worker.rule_event(
                ProxyEventKind::RuleFired,
                &rec.host,
                rec.port,
                &ctx,
                serde_json::json!({ "rule_ids": rule_ids, "action": "modify" }),
            );
        }
        rec.origin.rule_ids.extend(rule_ids);
    }

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

    let io: Box<dyn Io> = match &upstream {
        Upstream::Plain(addr) => match tokio::net::TcpStream::connect(addr).await {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                Box::new(s)
            }
            Err(e) => return fail(&mut rec, format!("connect failed: {e}")),
        },
        Upstream::Tls {
            addr,
            sni,
            insecure,
        } => {
            let tcp = match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => return fail(&mut rec, format!("connect failed: {e}")),
            };
            let _ = tcp.set_nodelay(true);
            match super::raw::tls_connect(
                tcp,
                &super::raw::TlsUpstream {
                    server_name: sni.clone(),
                    insecure: *insecure,
                },
            )
            .await
            {
                Ok(t) => Box::new(t),
                // The client was offered HTTP/1.1 only; an upstream that will speak nothing else
                // is reported as such, never silently downgraded or passed through (research R18).
                Err(e)
                    if e.contains("NoApplicationProtocol")
                        || e.contains("no_application_protocol") =>
                {
                    return fail(
                        &mut rec,
                        "upstream_protocol_unsupported (HTTP/1.1 only)".into(),
                    )
                }
                Err(e) => return fail(&mut rec, e),
            }
        }
    };
    rec.timing.connect_ms = Some(t0.elapsed().as_millis() as u64);
    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake::<_, Full<Bytes>>(TokioIo::new(io))
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
            original,
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
    /// The request before an intercept rule rewrote it (US7).
    original: Option<(Vec<u8>, Vec<u8>)>,
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
        let mut segs = vec![
            d.req_head,
            d.req_body,
            d.resp_head,
            std::mem::take(&mut self.captured),
        ];
        if let Some((h, b)) = d.original {
            segs.push(h);
            segs.push(b);
        }
        d.worker.emit(FromWorker::Exchange(d.rec), segs);
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
        if self.finished {
            return;
        }
        // A body that was already at its end (HEAD, 204, 304, Content-Length: 0) may be dropped by
        // hyper without ever being polled — that is a completed exchange, not an abandoned one.
        if self.inner.is_end_stream() {
            self.finish(None);
        } else {
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

/// A request an intercept rule dropped: the client gets a 502 naming the rule, the drop is a
/// `rule_fired` event, and the exchange is recorded with no response.
#[allow(clippy::too_many_arguments)]
fn dropped(
    worker: &Worker,
    ctx: &WireCtx,
    mut rec: ExchangeRecord,
    req_head: Vec<u8>,
    req_body: Vec<u8>,
    rule_id: &str,
    t0: Instant,
    action: &str,
) -> Response<ProxyBody> {
    worker.rule_event(
        ProxyEventKind::RuleFired,
        &rec.host,
        rec.port,
        ctx,
        serde_json::json!({ "rule_id": rule_id, "action": action }),
    );
    if !rec.origin.rule_ids.iter().any(|r| r == rule_id) {
        rec.origin.rule_ids.push(rule_id.to_string());
    }
    rec.outcome = Outcome::Failed {
        reason: format!("dropped by intercept rule {rule_id}"),
    };
    rec.timing.total_ms = Some(t0.elapsed().as_millis() as u64);
    worker.emit(
        FromWorker::Exchange(rec),
        vec![req_head, req_body, Vec::new(), Vec::new()],
    );
    text(
        StatusCode::BAD_GATEWAY,
        &format!("bee proxy: request dropped by intercept rule {rule_id}\n"),
    )
}

/// Replace `parts`' method, target and headers with those of a raw request head.
fn parts_from_head(head: &[u8], parts: &mut hyper::http::request::Parts) -> Result<(), String> {
    let mut hs = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut hs);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("the rewritten request head does not parse".into()),
    }
    parts.method = hyper::Method::from_bytes(req.method.unwrap_or("GET").as_bytes())
        .map_err(|e| e.to_string())?;
    parts.uri = req
        .path
        .unwrap_or("/")
        .parse()
        .map_err(|e: hyper::http::uri::InvalidUri| e.to_string())?;
    parts.headers.clear();
    for h in req.headers.iter() {
        let name =
            hyper::header::HeaderName::from_bytes(h.name.as_bytes()).map_err(|e| e.to_string())?;
        let value = hyper::header::HeaderValue::from_bytes(h.value).map_err(|e| e.to_string())?;
        parts.headers.append(name, value);
    }
    Ok(())
}
