//! combq through `http_history`'s query (issue 05): the SQL prefilter and the Rust evaluator agree,
//! body/header/raw search reads decoded bodies, and a scan past the cap says so.

use std::io::Write;

use bee_core::policy::HttpLimits;
use comb::control::{
    now_rfc3339, ExchangeRecord, Origin, OriginKind, Outcome, SendPath, Timing, TlsInfo,
};
use comb::query::{history, HistoryFilter, MAX_SCAN};
use comb::store::{ExchangeBytes, Store};
use serde_json::json;

fn rec(method: &str, scheme: &str, target: &str, status: Option<u16>) -> ExchangeRecord {
    ExchangeRecord {
        req_id: None,
        call_id: Some("toolu_1".into()),
        turn: Some(1),
        origin: Origin {
            kind: OriginKind::Tool,
            path: SendPath::Raw,
            parent: None,
            fuzz_run: None,
            rule_ids: vec![],
        },
        scheme: scheme.into(),
        host: "App.Test".into(),
        port: if scheme == "https" { 443 } else { 80 },
        method: Some(method.into()),
        target: Some(target.into()),
        status,
        tls: TlsInfo::None,
        timing: Timing {
            started: now_rfc3339(),
            connect_ms: Some(1),
            ttfb_ms: Some(20),
            total_ms: Some(30),
        },
        req_bytes: 10,
        resp_bytes: 100,
        req_truncated: false,
        resp_truncated: false,
        has_original: false,
        outcome: Outcome::Completed,
        tags: vec![],
    }
}

fn gzip(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

fn bytes(req_head: &str, req_body: &[u8], resp_head: &str, resp_body: &[u8]) -> ExchangeBytes {
    ExchangeBytes {
        req_head: req_head.as_bytes().to_vec(),
        req_body: req_body.to_vec(),
        resp_head: resp_head.as_bytes().to_vec(),
        resp_body: resp_body.to_vec(),
        original: None,
    }
}

/// Five exchanges covering every column kind, a gzip JSON body, a failed exchange with no status,
/// tags, and every origin.
fn fixture() -> (tempfile::TempDir, Store, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path(), "s1", &HttpLimits::default()).unwrap();
    let mut ids = Vec::new();

    let mut r = rec("GET", "http", "/api/users?id=1&debug=true", Some(200));
    r.tags = vec!["baseline".into()];
    r.resp_bytes = 5000;
    ids.push(
        store
            .insert_exchange(
                &r,
                &bytes(
                    "GET /api/users?id=1&debug=true HTTP/1.1\r\nHost: app.test\r\nX-Api-Key: k1\r\n\r\n",
                    b"",
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\n",
                    &gzip(br#"{"users":[{"name":"a","role":"admin"}]}"#),
                ),
            )
            .unwrap(),
    );

    let mut r = rec("POST", "https", "/login", Some(302));
    r.origin.kind = OriginKind::Replay;
    r.turn = Some(2);
    ids.push(
        store
            .insert_exchange(
                &r,
                &bytes(
                    "POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",
                    b"user=alice&pass=hunter2",
                    "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=abc\r\n\r\n",
                    b"",
                ),
            )
            .unwrap(),
    );

    let mut r = rec("GET", "http", "/static/app.min.js", Some(404));
    r.origin.kind = OriginKind::Fuzz;
    r.origin.fuzz_run = Some("F1".into());
    r.timing.total_ms = Some(2500);
    ids.push(
        store
            .insert_exchange(
                &r,
                &bytes(
                    "GET /static/app.min.js HTTP/1.1\r\nHost: app.test\r\n\r\n",
                    b"",
                    "HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n",
                    b"not found",
                ),
            )
            .unwrap(),
    );

    let mut r = rec("GET", "http", "/down", None);
    r.origin.kind = OriginKind::Forwarded;
    r.call_id = None;
    r.turn = None;
    r.outcome = Outcome::Failed {
        reason: "connect refused".into(),
    };
    ids.push(
        store
            .insert_exchange(
                &r,
                &bytes("GET /down HTTP/1.1\r\nHost: app.test\r\n\r\n", b"", "", b""),
            )
            .unwrap(),
    );

    let mut r = rec("GET", "http", "/admin", Some(500));
    r.tags = vec!["baseline".into(), "auth".into()];
    ids.push(
        store
            .insert_exchange(
                &r,
                &bytes(
                    "GET /admin HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer t0ken\r\n\r\n",
                    b"",
                    "HTTP/1.1 500 Internal Server Error\r\nServer: nginx\r\n\r\n",
                    b"Internal error: stack trace at line 42",
                ),
            )
            .unwrap(),
    );
    (dir, store, ids)
}

fn q(store: &Store, query: &str) -> comb::query::HistoryResult {
    let f: HistoryFilter =
        serde_json::from_value(json!({ "q": query, "order": "oldest", "limit": 200 })).unwrap();
    history(store, &f).unwrap_or_else(|e| panic!("{query}: {e}"))
}

/// Which fixture rows (by index) match.
fn hits(store: &Store, ids: &[String], query: &str) -> Vec<usize> {
    let r = q(store, query);
    let mut out: Vec<usize> = r
        .rows
        .iter()
        .map(|row| ids.iter().position(|i| *i == row.id).unwrap())
        .collect();
    out.sort();
    assert_eq!(r.total_matched as usize, out.len(), "{query}");
    out
}

#[test]
fn column_queries_select_the_right_rows() {
    let (_d, s, ids) = fixture();
    let h = |query| hits(&s, &ids, query);
    assert_eq!(h(r#"req.method eq "POST""#), [1]);
    assert_eq!(h(r#"req.host eq "app.test""#), [0, 1, 2, 3, 4]);
    assert_eq!(h("resp.code gte 400"), [2, 4]);
    assert_eq!(
        h("resp.code ne 200"),
        [1, 2, 3, 4],
        "a missing status is not 200"
    );
    assert_eq!(h("not resp.code eq 200"), [1, 2, 3, 4]);
    assert_eq!(h("req.tls eq true"), [1]);
    assert_eq!(h("req.tls eq false"), [0, 2, 3, 4]);
    assert_eq!(h(r#"origin eq "fuzz" or origin eq "replay""#), [1, 2]);
    assert_eq!(h(r#"outcome eq "failed""#), [3]);
    assert_eq!(h(r#"tag eq "baseline""#), [0, 4]);
    assert_eq!(h(r#"not tag eq "baseline""#), [1, 2, 3]);
    assert_eq!(h(r#"fuzz eq "F1""#), [2]);
    assert_eq!(h("turn eq 2"), [1]);
    assert_eq!(h("resp.roundtrip gt 2000"), [2]);
    assert_eq!(h(r#"req.path like "/api/%""#), [0]);
    assert_eq!(h(r#"req.path cont "ADMIN""#), [4], "cont ignores case");
    assert_eq!(h("req.created_at gt -1h"), [0, 1, 2, 3, 4]);
    assert!(
        q(&s, r#"req.method eq "POST""#).scanned.is_none(),
        "exact plans scan nothing"
    );
}

#[test]
fn content_queries_read_headers_bodies_and_raw() {
    let (_d, s, ids) = fixture();
    let h = |query| hits(&s, &ids, query);
    assert_eq!(
        h(r#"resp.body cont "\"role\":\"admin\"""#),
        [0],
        "gzip is decoded"
    );
    assert_eq!(h(r#"resp.body regex "line \\d+""#), [4]);
    assert_eq!(h(r#"req.body cont "hunter2""#), [1]);
    assert_eq!(h(r#"resp.header["server"] eq "nginx""#), [2, 4]);
    assert_eq!(h(r#"resp.header cont "set-cookie""#), [1]);
    assert_eq!(h(r#"req.header["x-api-key"] eq "k1""#), [0]);
    assert_eq!(h(r#"req.query cont "debug=true""#), [0]);
    assert_eq!(h(r#"req.ext eq ".js""#), [2]);
    assert_eq!(h(r#""t0ken""#), [4], "a bare string searches raw requests");
    assert_eq!(h(r#""Not Found""#), [2], "and raw responses");
    assert_eq!(
        h(r#"req.method eq "GET" and not resp.body cont "error""#),
        [0, 2, 3]
    );
    let r = q(&s, r#"resp.body cont "admin""#);
    assert_eq!(r.scanned, Some(5));
    assert!(!r.scan_truncated);
}

/// Every column clause must mean the same in SQL and in Rust. ANDing a clause only Rust can decide
/// (and that is always true) forces the Rust path; the rows must not change.
#[test]
fn sql_and_rust_agree_on_every_column_clause() {
    let (_d, s, ids) = fixture();
    let force = r#" and not resp.body cont "§never§""#;
    for query in [
        r#"req.method eq "GET""#,
        r#"req.method ne "GET""#,
        r#"req.host eq "APP.test""#,
        r#"req.host cont "PP.T""#,
        "req.port eq 443",
        r#"req.path like "/%/%""#,
        r#"req.path nlike "/a%""#,
        "req.tls eq true",
        "req.tls ne true",
        "req.len gte 10",
        "req.created_at lt -1h",
        "resp.code gt 300",
        "resp.code lte 302",
        "resp.code ne 404",
        "resp.len lt 1000",
        "resp.roundtrip eq 30",
        "resp.ttfb ne 20",
        r#"origin eq "forwarded""#,
        r#"origin ncont "o""#,
        r#"call eq "toolu_1""#,
        r#"call ne "toolu_1""#,
        r#"tag eq "auth""#,
        r#"tag ne "auth""#,
        r#"outcome eq "completed""#,
        r#"outcome ne "failed""#,
        r#"fuzz ne "F1""#,
        "turn eq 1",
        "turn ne 1",
        r#"not (origin eq "tool" and resp.code eq 200)"#,
    ] {
        let exact = hits(&s, &ids, query);
        let forced = hits(&s, &ids, &format!("({query}){force}"));
        assert_eq!(exact, forced, "{query}");
    }
}

#[test]
fn q_ands_with_the_json_fields() {
    let (_d, s, _ids) = fixture();
    let f: HistoryFilter = serde_json::from_value(json!({
        "method": "GET",
        "q": r#"resp.header["server"] eq "nginx""#,
    }))
    .unwrap();
    let r = history(&s, &f).unwrap();
    assert_eq!(r.total_matched, 2);
    let f: HistoryFilter =
        serde_json::from_value(json!({ "status": 500, "q": r#"resp.body cont "stack""# })).unwrap();
    assert_eq!(history(&s, &f).unwrap().total_matched, 1);
}

#[test]
fn a_bad_q_is_an_error_with_a_caret() {
    let (_d, s, _ids) = fixture();
    let f: HistoryFilter = serde_json::from_value(json!({ "q": "resp.code cont 5" })).unwrap();
    let e = history(&s, &f).unwrap_err().to_string();
    assert!(e.contains("does not apply to a number field"), "{e}");
    assert!(e.contains("resp.code cont 5") && e.contains('^'), "{e}");
}

#[test]
fn a_scan_past_the_cap_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), "s1", &HttpLimits::default()).unwrap();
    for i in 0..MAX_SCAN + 5 {
        let r = rec("GET", "http", &format!("/{i}"), Some(200));
        s.insert_exchange(
            &r,
            &bytes(
                &format!("GET /{i} HTTP/1.1\r\nHost: app.test\r\n\r\n"),
                b"",
                "HTTP/1.1 200 OK\r\n\r\n",
                b"same",
            ),
        )
        .unwrap();
    }
    let r = q(&s, r#"resp.body cont "same""#);
    assert!(r.scan_truncated);
    assert_eq!(r.scanned, Some(MAX_SCAN as u64));
    assert_eq!(
        r.total_matched, MAX_SCAN as u64,
        "a lower bound: the matches it read"
    );
    assert_eq!(r.returned, 200);
}
