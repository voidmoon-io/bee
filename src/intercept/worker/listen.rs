//! The session proxy's front end (019 T037/T038): a hyper HTTP/1.1 server on fd 3.
//!
//! Every request must carry a live per-call credential — `Proxy-Authorization: Basic
//! base64(<call_id>:<token>)`, which is what clients send for `HTTP_PROXY=http://<call_id>:<token>@…`,
//! or userinfo in an absolute-form URI. No credential, a wrong one, or one revoked when its call
//! ended → `407` and `refused_bad_credential` (spec edge case "credential reuse"). Then:
//! `CONNECT` → [`super::connect`]; absolute-form → [`super::forward`]; a WebSocket upgrade → `501`
//! (HTTP/1.1 only, research R18); anything else → `400`.

use std::sync::Arc;

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use super::scope::Refusal;
use super::Worker;
use crate::intercept::control::{ProxyEventKind, WireCtx};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Serve one client connection until it closes.
pub async fn serve_conn(worker: Arc<Worker>, sock: tokio::net::TcpStream) {
    let svc = hyper::service::service_fn(move |req| {
        let w = worker.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(w, req).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(sock), svc)
        .with_upgrades()
        .await;
}

async fn handle(worker: Arc<Worker>, req: Request<Incoming>) -> Response<ProxyBody> {
    let (host, port) = destination(&req);
    let Some(ctx) = authenticate(&worker, &req) else {
        let r = Refusal {
            kind: ProxyEventKind::RefusedBadCredential,
            host: host.clone(),
            port,
            detail: serde_json::Value::Null,
        };
        worker.refuse(&r, None);
        let mut resp = refusal_response(&r);
        resp.headers_mut().insert(
            "proxy-authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"bee\""),
        );
        return resp;
    };

    if req.method() == Method::CONNECT {
        return super::connect::handle(worker, ctx, req).await;
    }
    let ws = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if ws {
        return text(
            StatusCode::NOT_IMPLEMENTED,
            "WebSocket is not supported by the bee proxy (HTTP/1.1 only)\n",
        );
    }
    if req.uri().scheme().is_some() && req.uri().authority().is_some() {
        return super::forward::handle(worker, ctx, req).await;
    }
    text(
        StatusCode::BAD_REQUEST,
        "bee proxy: expected an absolute-form request or CONNECT\n",
    )
}

/// The request's destination, for refusal records: the CONNECT authority, or the absolute URI's.
fn destination(req: &Request<Incoming>) -> (String, u16) {
    let default_port = match req.uri().scheme_str() {
        Some("https") => 443,
        _ => 80,
    };
    match req.uri().authority() {
        Some(a) => (
            a.host().trim_matches(['[', ']']).to_string(),
            a.port_u16().unwrap_or(default_port),
        ),
        None => (String::new(), 0),
    }
}

/// The live call this request's credential belongs to.
fn authenticate(worker: &Worker, req: &Request<Incoming>) -> Option<WireCtx> {
    let (user, token) = credentials(req)?;
    let ctx = worker.credential(&token)?;
    // The token is the secret; the call id must still agree with what it was issued to, so a token
    // can never be replayed under a different call's name.
    (ctx.call_id == user).then_some(ctx)
}

/// `(call_id, token)` from `Proxy-Authorization: Basic …`, or from absolute-form URI userinfo.
fn credentials(req: &Request<Incoming>) -> Option<(String, String)> {
    if let Some(v) = req
        .headers()
        .get(hyper::header::PROXY_AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let (scheme, b64) = v.trim().split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = base64_decode(b64.trim())?;
        let s = String::from_utf8(decoded).ok()?;
        // The token is hex and never holds a colon; the call id may (`mcp:<server>`), and clients
        // percent-decode userinfo before encoding it, so split on the last one.
        let (u, t) = s.rsplit_once(':')?;
        return Some((percent_decode(u), percent_decode(t)));
    }
    let auth = req.uri().authority()?.as_str();
    let (userinfo, _) = auth.rsplit_once('@')?;
    let (u, t) = userinfo.rsplit_once(':')?;
    Some((percent_decode(u), percent_decode(t)))
}

pub fn refusal_response(r: &Refusal) -> Response<ProxyBody> {
    let status = StatusCode::from_u16(r.status()).unwrap_or(StatusCode::FORBIDDEN);
    text(status, &r.message())
}

pub fn text(status: StatusCode, body: &str) -> Response<ProxyBody> {
    let mut resp = Response::new(full(Bytes::from(body.to_string())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

pub fn full(b: Bytes) -> ProxyBody {
    Full::new(b).map_err(|never| match never {}).boxed()
}

pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Standard (padded or unpadded) base64.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Hex digits are read as bytes, never by slicing `s`: the input is client-sent, and a
        // multibyte character after `%` would put a `str` slice off a char boundary and panic.
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_common_userinfo() {
        assert_eq!(
            base64_decode("dG9vbHVfMTphYmNk").as_deref(),
            Some(&b"toolu_1:abcd"[..])
        );
        assert_eq!(base64_decode("YQ==").as_deref(), Some(&b"a"[..]));
        assert_eq!(base64_decode("YWI").as_deref(), Some(&b"ab"[..]));
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%3Ab"), "a:b");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("50%"), "50%");
        // Client-sent; a multibyte char after `%` once panicked on a str slice (review of #21).
        assert_eq!(percent_decode("%aé:tok"), "%aé:tok");
        assert_eq!(percent_decode("x%é"), "x%é");
    }
}
