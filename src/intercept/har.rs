//! HAR 1.2 export of recorded exchanges (019 US9, T091).
//!
//! What leaves bee here is chosen, not dumped: `Proxy-Authorization` is stripped wherever it
//! appears — bee's own per-call credentials never reach the store, but a model-written raw request
//! can carry one — no CA material exists in the store to export (SC-008), and every
//! `Authorization`/`Cookie`/`Set-Cookie` header present is named in `_bee.sensitive`, so whoever
//! shares the file knows what to redact.

use serde::Serialize;

use super::query::{history, HistoryFilter};
use super::store::{Store, StoredExchange};

#[derive(Serialize)]
pub struct Har {
    pub log: Log,
}

#[derive(Serialize)]
pub struct Log {
    pub version: &'static str,
    pub creator: Creator,
    pub entries: Vec<Entry>,
}

#[derive(Serialize)]
pub struct Creator {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub started_date_time: String,
    pub time: u64,
    pub request: Request,
    pub response: Response,
    pub cache: serde_json::Value,
    pub timings: Timings,
    #[serde(rename = "_bee")]
    pub bee: BeeMeta,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<Header>,
    pub query_string: Vec<Header>,
    pub cookies: Vec<serde_json::Value>,
    pub headers_size: i64,
    pub body_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_data: Option<PostData>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<Header>,
    pub cookies: Vec<serde_json::Value>,
    pub content: Content,
    #[serde(rename = "redirectURL")]
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostData {
    pub mime_type: String,
    pub text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    pub size: i64,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
}

#[derive(Serialize)]
pub struct Timings {
    pub send: i64,
    pub wait: i64,
    pub receive: i64,
}

#[derive(Serialize)]
pub struct BeeMeta {
    pub id: String,
    pub call_id: Option<String>,
    pub origin: String,
    pub outcome: String,
    /// Sensitive headers present on this entry, by name, for redaction before sharing.
    pub sensitive: Vec<String>,
}

/// Headers flagged in `_bee.sensitive`.
const SENSITIVE: &[&str] = &["authorization", "cookie", "set-cookie"];

/// Export every exchange matching `filter` (all sessions unless it narrows them).
pub fn export(store: &Store, filter: &HistoryFilter) -> Result<Har, String> {
    let mut f = filter.clone();
    if f.all_sessions.is_none() {
        f.all_sessions = Some(true);
    }
    f.limit = Some(f.limit.unwrap_or(super::query::MAX_LIMIT));
    let rows = history(store, &f).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    for r in rows.rows.iter().rev() {
        if let Some(e) = store.get_exchange(&r.id).map_err(|e| e.to_string())? {
            entries.push(entry(store, &e));
        }
    }
    Ok(Har {
        log: Log {
            version: "1.2",
            creator: Creator {
                name: "bee",
                version: env!("CARGO_PKG_VERSION"),
            },
            entries,
        },
    })
}

fn headers_of(head: &[u8]) -> (String, Vec<Header>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let first = lines.next().unwrap_or("").to_string();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| !k.trim().eq_ignore_ascii_case("proxy-authorization"))
        .map(|(k, v)| Header {
            name: k.trim().to_string(),
            value: v.trim().to_string(),
        })
        .collect();
    (first, headers)
}

fn body(store: &Store, sha: Option<&String>) -> (Vec<u8>, String) {
    let Some(sha) = sha else {
        return (Vec::new(), "identity".into());
    };
    let raw = store.read_blob(sha).ok().flatten().unwrap_or_default();
    let enc = store
        .blob_meta(sha)
        .ok()
        .flatten()
        .map(|m| m.encoding)
        .unwrap_or_else(|| "identity".into());
    let decoded = super::slice::decode(&raw, &enc, super::slice::DECODE_CAP)
        .map(|d| d.bytes)
        .unwrap_or(raw);
    (decoded, enc)
}

fn entry(store: &Store, e: &StoredExchange) -> Entry {
    let (req_line, req_headers) = headers_of(&e.req_head);
    let (status_line, resp_headers) = headers_of(&e.resp_head);
    let mut sensitive: Vec<String> = req_headers
        .iter()
        .chain(&resp_headers)
        .filter(|h| SENSITIVE.contains(&h.name.to_ascii_lowercase().as_str()))
        .map(|h| h.name.to_ascii_lowercase())
        .collect();
    sensitive.sort();
    sensitive.dedup();
    let scheme = match e.tls.as_deref() {
        Some("inspected") | Some("client") => "https",
        _ => e.scheme.as_deref().unwrap_or("http"),
    };
    let target = e.target.clone().unwrap_or_else(|| "/".into());
    let url = if target.contains("://") {
        target.clone()
    } else {
        format!("{scheme}://{}:{}{}", e.host, e.port, target)
    };
    let query: Vec<Header> = target
        .split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter(|s| !s.is_empty())
                .map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    Header {
                        name: k.into(),
                        value: v.into(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let version = |line: &str, at_start: bool| {
        let parts: Vec<&str> = line.split(' ').collect();
        let v = if at_start {
            parts.first()
        } else {
            parts.get(2)
        };
        v.filter(|v| v.starts_with("HTTP/"))
            .unwrap_or(&"HTTP/1.1")
            .to_string()
    };
    let (req_body, _) = body(store, e.req_body.as_ref());
    let (resp_body, _) = body(store, e.resp_body.as_ref());
    let mime = |hs: &[Header]| {
        hs.iter()
            .find(|h| h.name.eq_ignore_ascii_case("content-type"))
            .map(|h| h.value.clone())
            .unwrap_or_default()
    };
    let (text, encoding) = match String::from_utf8(resp_body.clone()) {
        Ok(t) => (Some(t), None),
        Err(_) => (Some(base64(&resp_body)), Some("base64")),
    };
    Entry {
        started_date_time: e.started.clone(),
        time: e.total_ms.unwrap_or(0),
        request: Request {
            method: e.method.clone().unwrap_or_default(),
            url,
            http_version: version(&req_line, false),
            post_data: (!req_body.is_empty()).then(|| PostData {
                mime_type: mime(&req_headers),
                text: String::from_utf8_lossy(&req_body).into_owned(),
            }),
            headers: req_headers,
            query_string: query,
            cookies: Vec::new(),
            headers_size: -1,
            body_size: e.req_bytes.map(|b| b as i64).unwrap_or(-1),
        },
        response: Response {
            status: e.status.unwrap_or(0),
            status_text: status_line.splitn(3, ' ').nth(2).unwrap_or("").to_string(),
            http_version: version(&status_line, true),
            content: Content {
                size: resp_body.len() as i64,
                mime_type: mime(&resp_headers),
                text,
                encoding,
            },
            headers: resp_headers,
            cookies: Vec::new(),
            redirect_url: String::new(),
            headers_size: -1,
            body_size: e.resp_bytes.map(|b| b as i64).unwrap_or(-1),
        },
        cache: serde_json::json!({}),
        timings: Timings {
            send: 0,
            wait: e.ttfb_ms.map(|v| v as i64).unwrap_or(-1),
            receive: match (e.total_ms, e.ttfb_ms) {
                (Some(t), Some(f)) => t.saturating_sub(f) as i64,
                _ => -1,
            },
        },
        bee: BeeMeta {
            id: e.id.clone(),
            call_id: e.call_id.clone(),
            origin: e.origin_kind.clone(),
            outcome: e.outcome.clone(),
            sensitive,
        },
    }
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
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
