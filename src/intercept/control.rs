//! The harness ↔ `bee proxy-worker` control channel (contracts/proxy-control.md, research R3).
//!
//! Framing: a 4-byte big-endian length `L`, then `L` bytes of UTF-8 JSON — an envelope
//! `{"msg": <message>, "segments": [len, …]}` — then each declared binary segment, raw, in order.
//! Binary segments carry what JSON cannot carry exactly: request and response heads (byte-exact,
//! FR-018) and bodies. The JSON is capped at [`MAX_JSON`]; a segment at the receiver's
//! `max_segment` (the policy's `max_body_bytes`). Anything malformed is an error, and the caller
//! closes the channel: a desynchronised stream cannot be resynchronised safely (fail closed).
//!
//! Both sides use the same types. The worker never receives, and never sends, CA key material:
//! `hello` carries the CA *certificate* only (invariant 1, SC-008).

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use bee_core::compiler::HttpScope;

/// Largest JSON part of a frame.
pub const MAX_JSON: usize = 1024 * 1024;

/// Protocol version carried in `hello`.
pub const PROTOCOL_VERSION: u32 = 1;

// ── message types ────────────────────────────────────────────────────────────────────────────────

/// Which call traffic is attributed to, as it travels to the worker with a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCtx {
    pub call_id: String,
    pub turn: u32,
    /// `tool`, `mcp:<server>` or `fuzz:<run>`.
    pub origin: String,
}

/// Where a raw request goes. Its bytes are segment 0 of the frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTarget {
    /// `http` or `https`.
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

/// Harness → worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToWorker {
    #[serde(rename = "init")]
    Init {
        session_id: String,
        http_scope: HttpScope,
    },
    /// Acked with `req_id`, and the harness waits for the ack before the call's children spawn:
    /// otherwise a child could reach the proxy before its credential exists, and get a 407.
    #[serde(rename = "creds.issue")]
    CredsIssue {
        req_id: u64,
        token: String,
        ctx: WireCtx,
    },
    #[serde(rename = "creds.revoke")]
    CredsRevoke { req_id: u64, token: String },
    /// After the kernel has been reloaded with the widened proxy scope (US3).
    #[serde(rename = "scope.update")]
    ScopeUpdate { req_id: u64, http_scope: HttpScope },
    /// Send segment 0 as-is to `raw` (model-originated traffic; the worker re-checks scope).
    #[serde(rename = "send")]
    Send {
        req_id: u64,
        raw: RawTarget,
        timeout_ms: u64,
        ctx: WireCtx,
        /// How the exchange is recorded: `tool`, `replay`, `fuzz`.
        kind: OriginKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tags: Vec<String>,
    },
    /// The answer to a worker [`FromWorker::Resolve`]. Name resolution happens in the harness:
    /// the proxy scope's kernel rules admit only the compiled target addresses, and a DNS server is
    /// not one of them (research R2, addendum).
    #[serde(rename = "resolved")]
    Resolved {
        req_id: u64,
        #[serde(default)]
        addrs: Vec<std::net::IpAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// One batch of a fuzz run: `count` variants as segments, each a complete raw request.
    #[serde(rename = "fuzz.start")]
    FuzzStart {
        run_id: String,
        raw: RawTarget,
        timeout_ms: u64,
        ctx: WireCtx,
        count: u32,
        /// Index of this batch's first variant within the run; variant `i` is tagged `v{offset+i}`.
        #[serde(default)]
        offset: u32,
        /// Last batch of the run.
        last: bool,
        /// Effective limits — only ever ≤ the policy's, which the worker also enforces.
        rps: u32,
        concurrency: u32,
    },
    #[serde(rename = "fuzz.cancel")]
    FuzzCancel { run_id: String },
    #[serde(rename = "rule.add")]
    RuleAdd {
        req_id: u64,
        rule: serde_json::Value,
    },
    #[serde(rename = "rule.remove")]
    RuleRemove { req_id: u64, rule_id: String },
    #[serde(rename = "hold.release")]
    HoldRelease {
        req_id: u64,
        hold_id: String,
        decision: serde_json::Value,
    },
    #[serde(rename = "shutdown")]
    Shutdown,
    /// VM-test builds only: a raw `connect(2)` to `addr`, reporting the errno (`http-proxy-scope`).
    #[cfg(feature = "vm-test")]
    #[serde(rename = "debug.connect")]
    DebugConnect { req_id: u64, addr: String },
    /// VM-test builds only: a raw `open(2)` of `path`, reporting the errno (`http-proxy-fs-deny`).
    #[cfg(feature = "vm-test")]
    #[serde(rename = "debug.read")]
    DebugRead { req_id: u64, path: String },
}

/// Who started the traffic an exchange records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    Tool,
    Replay,
    Fuzz,
    Forwarded,
}

impl OriginKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OriginKind::Tool => "tool",
            OriginKind::Replay => "replay",
            OriginKind::Fuzz => "fuzz",
            OriginKind::Forwarded => "forwarded",
        }
    }
}

/// Which worker path sent it: the raw writer (byte-exact) or the forwarding proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendPath {
    Raw,
    Forwarded,
}

impl SendPath {
    pub fn as_str(self) -> &'static str {
        match self {
            SendPath::Raw => "raw",
            SendPath::Forwarded => "forwarded",
        }
    }
}

/// Exchange origin (data-model.md §Exchange).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub kind: OriginKind,
    pub path: SendPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzz_run: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
}

/// TLS handling of an exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsInfo {
    None,
    /// Uninspected: only a [`TunnelRecord`] exists for it.
    Tunnel,
    /// Decrypted by the proxy (host ∈ `inspect`).
    Inspected {
        sni: String,
        upstream_verified: bool,
    },
    /// The raw writer's own upstream TLS (model-originated `https`).
    Client {
        upstream_verified: bool,
    },
}

/// How an exchange ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Refused {
        kind: ProxyEventKind,
    },
    Failed {
        reason: String,
    },
    /// Completed, but a body exceeded `max_body_bytes` and is stored truncated.
    Truncated,
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Outcome::Completed => "completed".into(),
            Outcome::Refused { kind } => format!("refused:{}", kind.as_str()),
            Outcome::Failed { reason } => format!("failed:{reason}"),
            Outcome::Truncated => "truncated".into(),
        }
    }
}

/// Timing, in milliseconds; `started` is RFC 3339.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    pub started: String,
    #[serde(default)]
    pub connect_ms: Option<u64>,
    #[serde(default)]
    pub ttfb_ms: Option<u64>,
    #[serde(default)]
    pub total_ms: Option<u64>,
}

/// An exchange as the worker reports it. Bytes travel as segments, always in this order:
/// `[req_head, req_body, resp_head, resp_body]`, then `[req_original_head, req_original_body]` iff
/// `has_original` (an intercept rule rewrote the request, US7). A missing part is an empty segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeRecord {
    /// The `send`'s `req_id` for model-originated traffic; `None` for forwarded traffic.
    #[serde(default)]
    pub req_id: Option<u64>,
    #[serde(default)]
    pub call_id: Option<String>,
    #[serde(default)]
    pub turn: Option<u32>,
    pub origin: Origin,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub method: Option<String>,
    /// The request-target as sent.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub status: Option<u16>,
    pub tls: TlsInfo,
    pub timing: Timing,
    /// Full wire sizes of the bodies, before any truncation.
    pub req_bytes: u64,
    pub resp_bytes: u64,
    #[serde(default)]
    pub req_truncated: bool,
    #[serde(default)]
    pub resp_truncated: bool,
    #[serde(default)]
    pub has_original: bool,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// An uninspected TLS tunnel (FR-024).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRecord {
    #[serde(default)]
    pub call_id: Option<String>,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub sni: Option<String>,
    pub started: String,
    pub ended: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub outcome: String,
}

pub use crate::proxy_event::{ProxyEvent, ProxyEventKind};

/// Worker → harness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FromWorker {
    #[serde(rename = "hello")]
    Hello {
        version: u32,
        /// The session CA certificate, present iff `inspect` is non-empty. **Certificate only.**
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_cert_pem: Option<String>,
    },
    #[serde(rename = "exchange")]
    Exchange(ExchangeRecord),
    #[serde(rename = "tunnel")]
    Tunnel(TunnelRecord),
    #[serde(rename = "proxy_event")]
    ProxyEvent(ProxyEvent),
    /// The worker needs `host` resolved; the harness answers with [`ToWorker::Resolved`].
    #[serde(rename = "resolve")]
    Resolve { req_id: u64, host: String },
    #[serde(rename = "held")]
    Held {
        hold_id: String,
        summary: String,
        deadline: String,
    },
    #[serde(rename = "fuzz.done")]
    FuzzDone {
        run_id: String,
        sent: u32,
        refused: u32,
        failed: u32,
        state: String,
    },
    #[serde(rename = "ack")]
    Ack { req_id: u64 },
    #[serde(rename = "error")]
    Error {
        #[serde(default)]
        req_id: Option<u64>,
        code: String,
        message: String,
    },
}

// ── codec ────────────────────────────────────────────────────────────────────────────────────────

/// Why a frame could not be read or written. Every variant means: close the channel.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("control channel I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("control frame of {0} bytes exceeds the {MAX_JSON}-byte limit")]
    JsonTooLarge(usize),
    #[error("control frame declared an empty JSON part")]
    EmptyFrame,
    #[error("control frame segment of {got} bytes exceeds the {max}-byte limit")]
    SegmentTooLarge { got: u64, max: u64 },
    #[error("malformed control frame: {0}")]
    Malformed(String),
}

#[derive(Serialize)]
struct EnvelopeOut<'a, T: Serialize> {
    msg: &'a T,
    segments: Vec<u64>,
}

#[derive(Deserialize)]
struct EnvelopeIn<T> {
    msg: T,
    #[serde(default)]
    segments: Vec<u64>,
}

/// Writes frames. One writer per direction; callers serialise access, so a frame is never split.
pub struct FrameWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        FrameWriter { inner }
    }

    /// Write `msg` with `segments` appended, then flush.
    pub async fn write<T: Serialize>(
        &mut self,
        msg: &T,
        segments: &[&[u8]],
    ) -> Result<(), CodecError> {
        let env = EnvelopeOut {
            msg,
            segments: segments.iter().map(|s| s.len() as u64).collect(),
        };
        let json = serde_json::to_vec(&env).map_err(|e| CodecError::Malformed(e.to_string()))?;
        if json.len() > MAX_JSON {
            return Err(CodecError::JsonTooLarge(json.len()));
        }
        self.inner
            .write_all(&(json.len() as u32).to_be_bytes())
            .await?;
        self.inner.write_all(&json).await?;
        for s in segments {
            self.inner.write_all(s).await?;
        }
        self.inner.flush().await?;
        Ok(())
    }
}

/// Reads frames, enforcing both size limits before allocating.
pub struct FrameReader<R> {
    inner: R,
    max_segment: u64,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// `max_segment` is the largest binary segment accepted.
    pub fn new(inner: R, max_segment: u64) -> Self {
        FrameReader { inner, max_segment }
    }

    pub fn set_max_segment(&mut self, max: u64) {
        self.max_segment = max;
    }

    /// The next frame, or `Ok(None)` on a clean end of stream between frames.
    pub async fn read<T: DeserializeOwned>(
        &mut self,
    ) -> Result<Option<(T, Vec<Vec<u8>>)>, CodecError> {
        let mut len = [0u8; 4];
        match self.inner.read_exact(&mut len).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 {
            return Err(CodecError::EmptyFrame);
        }
        if len > MAX_JSON {
            return Err(CodecError::JsonTooLarge(len));
        }
        let mut json = vec![0u8; len];
        self.inner.read_exact(&mut json).await?;
        let env: EnvelopeIn<T> =
            serde_json::from_slice(&json).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut segs = Vec::with_capacity(env.segments.len());
        for &n in &env.segments {
            if n > self.max_segment {
                return Err(CodecError::SegmentTooLarge {
                    got: n,
                    max: self.max_segment,
                });
            }
            let mut buf = vec![0u8; n as usize];
            self.inner.read_exact(&mut buf).await?;
            segs.push(buf);
        }
        Ok(Some((env.msg, segs)))
    }
}

/// Current wall-clock time, RFC 3339 — the timestamp format of every frame.
pub fn now_rfc3339() -> String {
    format_ts(time::OffsetDateTime::now_utc())
}

/// RFC 3339 in UTC with exactly six fractional digits. Fixed width on purpose: the store compares
/// timestamps as text (`since`/`until` filters), and RFC 3339's optional, variable-length fraction
/// would make `…:00Z` sort after `…:00.5Z`.
pub fn format_ts(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.microsecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee_core::policy::HttpLimits;

    fn scope() -> HttpScope {
        HttpScope {
            targets: vec![],
            egress: vec![],
            inspect: vec![],
            insecure_upstream: vec![],
            limits: HttpLimits::default(),
        }
    }

    fn ctx() -> WireCtx {
        WireCtx {
            call_id: "toolu_1".into(),
            turn: 2,
            origin: "tool".into(),
        }
    }

    fn raw() -> RawTarget {
        RawTarget {
            scheme: "https".into(),
            host: "app.test".into(),
            port: 443,
        }
    }

    pub(crate) fn exchange() -> ExchangeRecord {
        ExchangeRecord {
            req_id: Some(7),
            call_id: Some("toolu_1".into()),
            turn: Some(2),
            origin: Origin {
                kind: OriginKind::Tool,
                path: SendPath::Raw,
                parent: None,
                fuzz_run: None,
                rule_ids: vec![],
            },
            scheme: "http".into(),
            host: "app.test".into(),
            port: 80,
            method: Some("GET".into()),
            target: Some("/".into()),
            status: Some(200),
            tls: TlsInfo::None,
            timing: Timing {
                started: now_rfc3339(),
                connect_ms: Some(1),
                ttfb_ms: Some(2),
                total_ms: Some(3),
            },
            req_bytes: 10,
            resp_bytes: 20,
            req_truncated: false,
            resp_truncated: false,
            has_original: false,
            outcome: Outcome::Completed,
            tags: vec![],
        }
    }

    async fn roundtrip<T: Serialize + DeserializeOwned>(
        msg: &T,
        segs: &[&[u8]],
    ) -> (T, Vec<Vec<u8>>) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut w = FrameWriter::new(a);
        let mut r = FrameReader::new(b, 1 << 16);
        w.write(msg, segs).await.unwrap();
        r.read::<T>().await.unwrap().expect("one frame")
    }

    // T027: every frame type survives the codec.
    #[tokio::test]
    async fn every_harness_frame_round_trips() {
        let frames = vec![
            ToWorker::Init {
                session_id: "s".into(),
                http_scope: scope(),
            },
            ToWorker::CredsIssue {
                req_id: 1,
                token: "ab".into(),
                ctx: ctx(),
            },
            ToWorker::CredsRevoke {
                req_id: 2,
                token: "ab".into(),
            },
            ToWorker::ScopeUpdate {
                req_id: 1,
                http_scope: scope(),
            },
            ToWorker::Send {
                req_id: 2,
                raw: raw(),
                timeout_ms: 1000,
                ctx: ctx(),
                kind: OriginKind::Replay,
                parent: Some("E1-1".into()),
                tags: vec!["noise-probe".into()],
            },
            ToWorker::Resolved {
                req_id: 3,
                addrs: vec!["10.0.0.1".parse().unwrap()],
                error: None,
            },
            ToWorker::FuzzStart {
                run_id: "F1".into(),
                raw: raw(),
                timeout_ms: 5,
                ctx: ctx(),
                count: 2,
                offset: 0,
                last: true,
                rps: 1,
                concurrency: 1,
            },
            ToWorker::FuzzCancel {
                run_id: "F1".into(),
            },
            ToWorker::RuleAdd {
                req_id: 4,
                rule: serde_json::json!({"id": "R1"}),
            },
            ToWorker::RuleRemove {
                req_id: 5,
                rule_id: "R1".into(),
            },
            ToWorker::HoldRelease {
                req_id: 6,
                hold_id: "H1".into(),
                decision: serde_json::json!("forward"),
            },
            ToWorker::Shutdown,
        ];
        for f in frames {
            let (back, segs) = roundtrip(&f, &[b"GET / HTTP/1.1\r\n\r\n"]).await;
            assert_eq!(back, f);
            assert_eq!(segs, vec![b"GET / HTTP/1.1\r\n\r\n".to_vec()]);
        }
    }

    #[tokio::test]
    async fn every_worker_frame_round_trips() {
        let frames = vec![
            FromWorker::Hello {
                version: PROTOCOL_VERSION,
                ca_cert_pem: Some("-----BEGIN CERTIFICATE-----".into()),
            },
            FromWorker::Exchange(exchange()),
            FromWorker::Tunnel(TunnelRecord {
                call_id: None,
                host: "h".into(),
                port: 443,
                sni: Some("h".into()),
                started: now_rfc3339(),
                ended: now_rfc3339(),
                bytes_up: 1,
                bytes_down: 2,
                outcome: "closed".into(),
            }),
            FromWorker::ProxyEvent(ProxyEvent {
                ts: now_rfc3339(),
                session_id: "s".into(),
                call_id: None,
                layer: "proxy".into(),
                kind: ProxyEventKind::RefusedAddressDrift,
                host: "drift.test".into(),
                port: 80,
                detail: serde_json::json!({"now_resolves_to": ["127.0.0.3"], "compiled": ["127.0.0.2"]}),
            }),
            FromWorker::Resolve {
                req_id: 9,
                host: "h".into(),
            },
            FromWorker::Held {
                hold_id: "H".into(),
                summary: "GET /".into(),
                deadline: now_rfc3339(),
            },
            FromWorker::FuzzDone {
                run_id: "F".into(),
                sent: 1,
                refused: 0,
                failed: 0,
                state: "completed".into(),
            },
            FromWorker::Ack { req_id: 1 },
            FromWorker::Error {
                req_id: Some(1),
                code: "x".into(),
                message: "y".into(),
            },
        ];
        for f in frames {
            let (back, segs) = roundtrip(&f, &[]).await;
            assert_eq!(back, f);
            assert!(segs.is_empty());
        }
    }

    #[tokio::test]
    async fn segments_arrive_in_order() {
        let segs: [&[u8]; 4] = [b"head", b"", b"resp-head", b"body bytes \x00\xff"];
        let (_, got) = roundtrip(&FromWorker::Exchange(exchange()), &segs).await;
        assert_eq!(got, segs.iter().map(|s| s.to_vec()).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn an_oversize_json_frame_is_refused_both_ways() {
        let big = ToWorker::CredsRevoke {
            req_id: 1,
            token: "x".repeat(MAX_JSON + 1),
        };
        let (a, _b) = tokio::io::duplex(64);
        let mut w = FrameWriter::new(a);
        assert!(matches!(
            w.write(&big, &[]).await,
            Err(CodecError::JsonTooLarge(_))
        ));

        // A peer that declares one anyway is refused before the reader allocates.
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&((MAX_JSON as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        let mut r = FrameReader::new(b, 16);
        assert!(matches!(
            r.read::<ToWorker>().await,
            Err(CodecError::JsonTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn an_oversize_segment_is_refused() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut w = FrameWriter::new(a);
        let mut r = FrameReader::new(b, 8);
        w.write(&ToWorker::Shutdown, &[b"123456789"]).await.unwrap();
        assert!(matches!(
            r.read::<ToWorker>().await,
            Err(CodecError::SegmentTooLarge { got: 9, max: 8 })
        ));
    }

    #[tokio::test]
    async fn a_malformed_frame_closes_the_channel() {
        // Zero length.
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(matches!(
            FrameReader::new(b, 8).read::<ToWorker>().await,
            Err(CodecError::EmptyFrame)
        ));
        // Not JSON.
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&3u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{{{").await.unwrap();
        assert!(matches!(
            FrameReader::new(b, 8).read::<ToWorker>().await,
            Err(CodecError::Malformed(_))
        ));
        // Truncated mid-frame is an error, not a clean end.
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{\"msg\"").await.unwrap();
        drop(a);
        assert!(FrameReader::new(b, 8).read::<ToWorker>().await.is_err());
    }

    /// T048: the VM-test debug frames exist only in `vm-test` builds. Anywhere else they do not
    /// decode, so no shipping worker can be asked to make an arbitrary connect or open.
    #[tokio::test]
    async fn debug_frames_do_not_decode_outside_vm_test() {
        for msg in [
            serde_json::json!({"type": "debug.connect", "req_id": 1, "addr": "1.2.3.4:5"}),
            serde_json::json!({"type": "debug.read", "req_id": 1, "path": "/etc/passwd"}),
        ] {
            let (a, b) = tokio::io::duplex(256);
            FrameWriter::new(a).write(&msg, &[]).await.unwrap();
            let r = FrameReader::new(b, 8).read::<ToWorker>().await;
            #[cfg(not(feature = "vm-test"))]
            assert!(matches!(r, Err(CodecError::Malformed(_))), "{msg} decoded");
            #[cfg(feature = "vm-test")]
            assert!(r.is_ok(), "{msg}");
        }
    }

    #[tokio::test]
    async fn a_clean_end_between_frames_is_none() {
        let (a, b) = tokio::io::duplex(64);
        drop(a);
        assert!(FrameReader::new(b, 8)
            .read::<ToWorker>()
            .await
            .unwrap()
            .is_none());
    }
}
