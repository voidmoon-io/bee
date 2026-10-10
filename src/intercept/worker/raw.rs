//! The raw HTTP/1.1 writer (019 T052, research R1): model-originated requests go upstream **byte for
//! byte** — duplicate headers, odd casing, bare `\n`, whatever the model wrote (FR-018). No HTTP
//! library is in the request path, because every one of them normalises exactly what a tester needs
//! to control.
//!
//! The response is framed with `httparse`: 1xx interim responses are skipped; HEAD, 204 and 304 have
//! no body; otherwise `Transfer-Encoding: chunked` (de-chunked), `Content-Length`, or read-to-close.
//! The stored body stops at `max_body` and is flagged truncated — reading stops there too, so a
//! 100 MB response costs `max_body`, not 100 MB.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Upstream TLS for an `https` request.
#[derive(Debug, Clone)]
pub struct TlsUpstream {
    pub server_name: String,
    /// `insecure_upstream`: accept any certificate, and record that it was not verified.
    pub insecure: bool,
}

/// A response as read off the wire.
#[derive(Debug, Clone, Default)]
pub struct RawResponse {
    /// The status line and headers of the final (non-1xx) response, byte-exact, ending `\r\n\r\n`.
    pub head: Vec<u8>,
    /// The body, de-chunked, at most `max_body` bytes.
    pub body: Vec<u8>,
    /// Body bytes on the wire, when known (Content-Length, or as read).
    pub body_wire_len: u64,
    pub truncated: bool,
    pub status: Option<u16>,
    pub connect_ms: u64,
    pub ttfb_ms: Option<u64>,
    pub total_ms: u64,
    /// `Some` for TLS: whether the upstream certificate was verified.
    pub upstream_verified: Option<bool>,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Send `request` to `addr` exactly as given, and read the response.
pub async fn send_raw(
    addr: SocketAddr,
    tls: Option<TlsUpstream>,
    request: &[u8],
    max_body: u64,
    timeout: Duration,
) -> Result<RawResponse, String> {
    tokio::time::timeout(timeout, send_inner(addr, tls, request, max_body))
        .await
        .map_err(|_| format!("timed out after {}ms", timeout.as_millis()))?
}

async fn send_inner(
    addr: SocketAddr,
    tls: Option<TlsUpstream>,
    request: &[u8],
    max_body: u64,
) -> Result<RawResponse, String> {
    let start = Instant::now();
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let (mut stream, upstream_verified): (Box<dyn Stream>, Option<bool>) = match tls {
        None => (Box::new(tcp), None),
        Some(t) => {
            let s = tls_connect(tcp, &t).await?;
            (Box::new(s), Some(!t.insecure))
        }
    };
    let connect_ms = start.elapsed().as_millis() as u64;
    stream
        .write_all(request)
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("write: {e}"))?;

    let is_head = request
        .split(|b| *b == b' ')
        .next()
        .is_some_and(|m| m.eq_ignore_ascii_case(b"HEAD"));
    let mut resp = read_response(&mut stream, is_head, max_body, start).await?;
    resp.connect_ms = connect_ms;
    resp.upstream_verified = upstream_verified;
    resp.total_ms = start.elapsed().as_millis() as u64;
    Ok(resp)
}

/// Read one response from `s`. Exposed for the forwarding path's tests and the fuzz runner.
async fn read_response<S: AsyncRead + Unpin + ?Sized>(
    s: &mut S,
    is_head: bool,
    max_body: u64,
    start: Instant,
) -> Result<RawResponse, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut ttfb = None;
    // Head(s): skip interim 1xx responses (but not 101, which ends HTTP on this connection).
    let (head, status, framing) = loop {
        let (head_len, status, framing) = loop {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            let mut r = httparse::Response::new(&mut headers);
            match r.parse(&buf) {
                Ok(httparse::Status::Complete(n)) => {
                    let status = r.code.unwrap_or(0);
                    let framing = framing_of(r.headers, status, is_head);
                    break (n, status, framing);
                }
                Ok(httparse::Status::Partial) => {}
                Err(e) => return Err(format!("malformed response head: {e}")),
            }
            if buf.len() > 1 << 20 {
                return Err("response head exceeds 1 MiB".into());
            }
            let n = read_more(s, &mut buf).await?;
            if ttfb.is_none() && n > 0 {
                ttfb = Some(start.elapsed().as_millis() as u64);
            }
            if n == 0 {
                return Err(if buf.is_empty() {
                    "connection closed before a response".into()
                } else {
                    "connection closed mid-head".into()
                });
            }
        };
        let head: Vec<u8> = buf.drain(..head_len).collect();
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        break (head, status, framing);
    };

    let mut body = Vec::new();
    let mut wire: u64 = 0;
    let mut truncated = false;
    let cap = max_body as usize;
    match framing {
        Framing::None => {}
        Framing::Length(n) => {
            wire = n;
            let want = n.min(max_body) as usize;
            while body.len() < want {
                if buf.is_empty() && read_more(s, &mut buf).await? == 0 {
                    break;
                }
                let take = (want - body.len()).min(buf.len());
                body.extend(buf.drain(..take));
            }
            truncated = n > max_body;
        }
        Framing::Chunked => loop {
            let size = loop {
                match httparse::parse_chunk_size(&buf) {
                    Ok(httparse::Status::Complete((idx, size))) => {
                        buf.drain(..idx);
                        break size;
                    }
                    Ok(httparse::Status::Partial) => {
                        if read_more(s, &mut buf).await? == 0 {
                            return Err("connection closed mid-chunk".into());
                        }
                    }
                    Err(_) => return Err("malformed chunk size".into()),
                }
            };
            if size == 0 {
                break;
            }
            wire += size;
            let mut left = size as usize;
            while left > 0 {
                if buf.is_empty() && read_more(s, &mut buf).await? == 0 {
                    return Err("connection closed mid-chunk".into());
                }
                let take = left.min(buf.len());
                let room = cap.saturating_sub(body.len());
                body.extend_from_slice(&buf[..take.min(room)]);
                if take > room {
                    truncated = true;
                }
                buf.drain(..take);
                left -= take;
            }
            if truncated {
                break; // stop reading: the stored body is already full
            }
            // CRLF after the chunk data.
            while buf.len() < 2 {
                if read_more(s, &mut buf).await? == 0 {
                    break;
                }
            }
            if buf.starts_with(b"\r\n") {
                buf.drain(..2);
            } else if buf.starts_with(b"\n") {
                buf.drain(..1);
            }
        },
        Framing::Close => loop {
            let room = cap.saturating_sub(body.len());
            let take = room.min(buf.len());
            body.extend(buf.drain(..take));
            wire += take as u64;
            if !buf.is_empty() {
                truncated = true;
                wire += buf.len() as u64;
                break;
            }
            if read_more(s, &mut buf).await? == 0 {
                break;
            }
        },
    }

    Ok(RawResponse {
        head,
        body,
        body_wire_len: wire,
        truncated,
        status: Some(status),
        ttfb_ms: ttfb,
        ..RawResponse::default()
    })
}

enum Framing {
    None,
    Length(u64),
    Chunked,
    Close,
}

fn framing_of(headers: &[httparse::Header<'_>], status: u16, is_head: bool) -> Framing {
    if is_head || status == 204 || status == 304 || (100..200).contains(&status) {
        return Framing::None;
    }
    let get = |n: &str| {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(n))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_ascii_lowercase())
    };
    if get("transfer-encoding").is_some_and(|v| v.ends_with("chunked")) {
        return Framing::Chunked;
    }
    match get("content-length").and_then(|v| v.parse::<u64>().ok()) {
        Some(n) => Framing::Length(n),
        None => Framing::Close,
    }
}

async fn read_more<S: AsyncRead + Unpin + ?Sized>(
    s: &mut S,
    buf: &mut Vec<u8>,
) -> Result<usize, String> {
    let mut chunk = [0u8; 16 * 1024];
    let n = s.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

/// Connect TLS over `tcp`: webpki roots and real verification, unless `insecure_upstream`.
pub async fn tls_connect(
    tcp: TcpStream,
    t: &TlsUpstream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let cfg = client_config(t.insecure, &[b"http/1.1"]);
    let name = rustls::pki_types::ServerName::try_from(t.server_name.clone())
        .map_err(|e| format!("invalid server name {:?}: {e}", t.server_name))?;
    tokio_rustls::TlsConnector::from(cfg)
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS to {}: {e}", t.server_name))
}

/// A rustls client config for upstream connections.
pub fn client_config(insecure: bool, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions are supported");
    let mut cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// `insecure_upstream` only (operator-listed lab targets): accepts any certificate. Signatures are
/// still checked for well-formedness so a broken handshake fails, but the chain is not.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Parse a raw request's method and request-target, for the record.
pub fn request_line(raw: &[u8]) -> (Option<String>, Option<String>) {
    let line_end = raw.iter().position(|b| *b == b'\n').unwrap_or(raw.len());
    let line = String::from_utf8_lossy(&raw[..line_end]);
    let mut parts = line.trim_end_matches('\r').split(' ');
    let method = parts.next().filter(|m| !m.is_empty()).map(str::to_string);
    let target = parts.next().map(str::to_string);
    (method, target)
}

/// Every `Host` header value in a raw request head.
pub fn host_headers(raw: &[u8]) -> Vec<String> {
    let (head, _) = split_head(raw);
    String::from_utf8_lossy(head)
        .split('\n')
        .skip(1)
        .map(|l| l.trim_end_matches('\r'))
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().to_string())
        .collect()
}

/// Split a raw request into head (through the blank line) and body.
pub fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    for i in 0..raw.len() {
        if raw[i..].starts_with(b"\r\n\r\n") {
            return raw.split_at(i + 4);
        }
        if raw[i..].starts_with(b"\n\n") {
            return raw.split_at(i + 2);
        }
    }
    (raw, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8], head_req: bool, max: u64) -> RawResponse {
        let mut s = bytes;
        read_response(&mut s, head_req, max, Instant::now())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn content_length_body() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA",
            false,
            100,
        )
        .await;
        assert_eq!(r.status, Some(200));
        assert_eq!(r.body, b"abc");
        assert!(r.head.ends_with(b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn chunked_body_is_dechunked() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            false,
            100,
        )
        .await;
        assert_eq!(r.body, b"abcde");
        assert_eq!(r.body_wire_len, 5);
    }

    #[tokio::test]
    async fn interim_responses_are_skipped() {
        let r = parse(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
            false,
            100,
        )
        .await;
        assert_eq!(r.status, Some(201));
        assert!(r.head.starts_with(b"HTTP/1.1 201"));
    }

    #[tokio::test]
    async fn head_204_and_304_have_no_body() {
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", true, 100).await;
        assert!(r.body.is_empty());
        for s in [204, 304] {
            let resp = format!("HTTP/1.1 {s} X\r\nContent-Length: 50\r\n\r\n");
            assert!(parse(resp.as_bytes(), false, 100).await.body.is_empty());
        }
    }

    #[tokio::test]
    async fn close_delimited_body() {
        let r = parse(b"HTTP/1.1 200 OK\r\n\r\nuntil close", false, 100).await;
        assert_eq!(r.body, b"until close");
    }

    #[tokio::test]
    async fn bodies_are_capped_and_flagged() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
            false,
            4,
        )
        .await;
        assert_eq!(r.body, b"0123");
        assert!(r.truncated);
        assert_eq!(r.body_wire_len, 10);
        let r = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
            false,
            4,
        )
        .await;
        assert_eq!(r.body, b"0123");
        assert!(r.truncated);
    }

    #[test]
    fn request_lines_parse() {
        assert_eq!(
            request_line(b"POST /x?y HTTP/1.1\r\n"),
            (Some("POST".into()), Some("/x?y".into()))
        );
        assert_eq!(split_head(b"GET / HTTP/1.1\nA: b\n\nbody").1, b"body");
    }
}
