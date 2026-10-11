//! Passive checks over recorded exchanges (019 US8, research R16): **leads**, not findings.
//!
//! Each check runs when an exchange is stored, over bodies decoded and capped at 1 MiB, and records
//! a lead — an observation worth a look — in the store's `leads` table. A lead is never written to
//! the finding ledger (FR-028): only the model, citing evidence, records a finding.
//!
//! A lead's summary is a fixed bee template. It carries **no target bytes** — no parameter values,
//! header text or body snippets — so a hostile response cannot speak through a lead; the model reads
//! the exchange itself, as data, when it follows one up.

use super::control::ExchangeRecord;
use super::store::ExchangeBytes;

/// Most bytes of a body any check reads.
pub const BODY_CAP: usize = 1024 * 1024;

/// One lead before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lead {
    pub kind: &'static str,
    pub summary: &'static str,
}

/// Run every check over one stored exchange.
pub fn check(rec: &ExchangeRecord, bytes: &ExchangeBytes, decoded_resp: &[u8]) -> Vec<Lead> {
    let mut out = Vec::new();
    let resp_head = String::from_utf8_lossy(&bytes.resp_head);
    let headers: Vec<(String, String)> = resp_head
        .split('\n')
        .skip(1)
        .map(|l| l.trim_end_matches('\r'))
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    };
    let body = String::from_utf8_lossy(&decoded_resp[..decoded_resp.len().min(BODY_CAP)]);
    let target = rec.target.as_deref().unwrap_or("");

    // 1. A query parameter value reflected verbatim in the response.
    if let Some((_, query)) = target.split_once('?') {
        let reflected = query.split('&').any(|kv| {
            let v = kv.split_once('=').map(|(_, v)| v).unwrap_or("");
            let v = url_decode(v);
            v.len() >= 4 && v.chars().any(|c| !c.is_ascii_alphanumeric()) && body.contains(&v)
                || (v.len() >= 6 && body.contains(&v))
        });
        if reflected {
            out.push(Lead {
                kind: "reflected_parameter",
                summary: "a query parameter's value appears verbatim in the response body",
            });
        }
    }

    // 2. A session-like cookie without HttpOnly, Secure or SameSite.
    for (_, v) in headers.iter().filter(|(k, _)| k == "set-cookie") {
        let name = v.split('=').next().unwrap_or("").to_ascii_lowercase();
        let session_like = ["sess", "sid", "token", "auth", "jwt", "login"]
            .iter()
            .any(|s| name.contains(s));
        let lower = v.to_ascii_lowercase();
        if session_like
            && (!lower.contains("httponly")
                || !lower.contains("secure")
                || !lower.contains("samesite"))
        {
            out.push(Lead {
                kind: "weak_session_cookie",
                summary: "a session-like cookie is set without one of HttpOnly, Secure or SameSite",
            });
            break;
        }
    }

    // 3. A verbose error signature.
    const SIGNATURES: &[&str] = &[
        "Traceback (most recent call last)",
        "SQL syntax",
        "ORA-0",
        "SQLSTATE[",
        "Exception in thread",
        "java.lang.",
        "System.NullReferenceException",
        "Fatal error: ",
        "Stack trace:",
        "at org.",
        "PG::",
        "unterminated quoted string",
    ];
    if SIGNATURES.iter().any(|s| body.contains(s)) {
        out.push(Lead {
            kind: "verbose_error",
            summary: "the response contains an error or stack-trace signature",
        });
    }

    // 4. HTML without common security headers.
    if header("content-type").is_some_and(|c| c.to_ascii_lowercase().contains("text/html"))
        && (header("content-security-policy").is_none()
            || header("x-content-type-options").is_none()
            || (header("x-frame-options").is_none()
                && !header("content-security-policy")
                    .is_some_and(|c| c.contains("frame-ancestors"))))
    {
        out.push(Lead {
            kind: "missing_security_headers",
            summary: "an HTML response lacks one of Content-Security-Policy, X-Content-Type-Options or frame protection",
        });
    }

    // 5. Credentials in the URL.
    let lower_target = target.to_ascii_lowercase();
    let in_userinfo = target
        .split_once("://")
        .is_some_and(|(_, rest)| rest.split('/').next().unwrap_or("").contains('@'));
    let in_query = lower_target.split_once('?').is_some_and(|(_, q)| {
        q.split('&').any(|kv| {
            let k = kv.split('=').next().unwrap_or("");
            [
                "password",
                "passwd",
                "pwd",
                "token",
                "api_key",
                "apikey",
                "secret",
                "access_token",
            ]
            .contains(&k)
        })
    });
    if in_userinfo || in_query {
        out.push(Lead {
            kind: "credentials_in_url",
            summary: "a request carries what looks like a credential in its URL",
        });
    }
    out
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intercept::control::{
        now_rfc3339, Origin, OriginKind, Outcome, SendPath, Timing, TlsInfo,
    };

    fn rec(target: &str) -> ExchangeRecord {
        ExchangeRecord {
            req_id: None,
            call_id: None,
            turn: None,
            origin: Origin {
                kind: OriginKind::Tool,
                path: SendPath::Raw,
                parent: None,
                fuzz_run: None,
                rule_ids: vec![],
            },
            scheme: "http".into(),
            host: "h".into(),
            port: 80,
            method: Some("GET".into()),
            target: Some(target.into()),
            status: Some(200),
            tls: TlsInfo::None,
            timing: Timing {
                started: now_rfc3339(),
                ..Default::default()
            },
            req_bytes: 0,
            resp_bytes: 0,
            req_truncated: false,
            resp_truncated: false,
            has_original: false,
            outcome: Outcome::Completed,
            tags: vec![],
        }
    }

    fn kinds(target: &str, head: &str, body: &str) -> Vec<&'static str> {
        let b = ExchangeBytes {
            resp_head: head.as_bytes().to_vec(),
            ..Default::default()
        };
        check(&rec(target), &b, body.as_bytes())
            .into_iter()
            .map(|l| l.kind)
            .collect()
    }

    #[test]
    fn the_checks_fire_and_their_summaries_carry_no_target_text() {
        let k = kinds(
            "/search?q=%3Cmarker%3E&password=x",
            "HTTP/1.1 500 X\r\nContent-Type: text/html\r\nSet-Cookie: SESSIONID=abc; Path=/\r\n\r\n",
            "<p>Results for <marker></p> Traceback (most recent call last)",
        );
        for want in [
            "reflected_parameter",
            "weak_session_cookie",
            "verbose_error",
            "missing_security_headers",
            "credentials_in_url",
        ] {
            assert!(k.contains(&want), "{want}: {k:?}");
        }
        let b = ExchangeBytes {
            resp_head: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            ..Default::default()
        };
        for l in check(&rec("/x?q=SECRETVALUE"), &b, b"SECRETVALUE") {
            assert!(!l.summary.contains("SECRETVALUE"));
        }
    }

    #[test]
    fn a_short_alphanumeric_value_is_not_a_reflection() {
        assert!(!kinds("/item?id=12", "HTTP/1.1 200 OK\r\n\r\n", "item 12")
            .contains(&"reflected_parameter"));
    }
}
