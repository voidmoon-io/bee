//! 019-http-intercept US2 (T049–T051) — `http_send`, `http_history`, `http_get` against the in-repo
//! fixture, through the real worker and harness, with every bound and refusal checked.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use bee::tools::Provenance;
use harness::{scope, Session};
use serde_json::json;

const TOOLS: &[&str] = &[
    "http_send",
    "http_get",
    "http_history",
    "http_scope",
    "bash",
];

async fn session_for(http: std::net::SocketAddr, extra: &str) -> Session {
    Session::start(
        scope(
            &format!("targets = [\"127.0.0.1:{}\"]\n{extra}", http.port()),
            &[],
        ),
        &[],
        TOOLS,
    )
    .await
}

// ── T049: http_send ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_structured_post_returns_a_bounded_summary() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": {
                "method": "POST",
                "url": format!("http://127.0.0.1:{}/echo", http.port()),
                "headers": [["Content-Type", "text/plain"]],
                "body": "hello"
            }}),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    assert!(r.content.len() <= 4 * 1024, "{}", r.content.len());
    let v = Session::json(&r);
    assert!(v["id"].as_str().unwrap().starts_with('E'));
    assert_eq!(v["status"], 200);
    assert!(v["resp_bytes"].as_u64().unwrap() > 0);
    assert!(v["elapsed_ms"].is_u64());
    let preview = v["body_preview"].as_str().unwrap();
    assert!(preview.starts_with("POST /echo HTTP/1.1"), "{preview}");
    assert!(preview.len() <= 1024 + 4);
    assert_eq!(
        r.provenance,
        Provenance::Remote {
            source: format!("http:{}", v["id"].as_str().unwrap())
        }
    );
}

#[tokio::test]
async fn raw_bytes_arrive_byte_for_byte() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let raw = format!(
        "GET /echo HTTP/1.1\nHost: 127.0.0.1:{}\nX-Dup: 1\nx-DUP: 2\nWeIrD-CaSe:  spaced\n\n",
        http.port()
    );
    let (r, _) = s
        .call(
            "http_send",
            json!({ "raw": { "scheme": "http", "host": "127.0.0.1", "port": http.port(), "bytes": raw.clone() } }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    let id = Session::json(&r)["id"].as_str().unwrap().to_string();
    let (g, _) = s
        .call(
            "http_get",
            json!({ "id": id, "view": { "range": { "start": 0, "len": 4096 } } }),
        )
        .await;
    assert_eq!(Session::json(&g)["content"], raw, "{}", g.content);
    // And the request head the store recorded is the same bytes.
    let (h, _) = s
        .call(
            "http_get",
            json!({ "id": id, "part": "request", "view": { "raw_head": true } }),
        )
        .await;
    assert_eq!(Session::json(&h)["content"], raw);
}

#[tokio::test]
async fn a_redirect_out_of_scope_stops_and_reports_the_hop() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let (other, _, other_fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let (r, _) = s
        .call(
            "http_send",
            json!({
                "request": { "url": format!(
                    "http://127.0.0.1:{}/redirect?to=http://127.0.0.1:{}/search", http.port(), other.port()) },
                "follow_redirects": 2
            }),
        )
        .await;
    let v = Session::json(&r);
    assert_eq!(v["status"], 302, "{}", r.content);
    let hops = v["redirects"].as_array().unwrap();
    assert_eq!(hops.len(), 1);
    assert!(
        hops[0]["stopped"]
            .as_str()
            .unwrap()
            .contains("out of scope"),
        "{hops:?}"
    );
    assert_eq!(
        other_fx
            .counters
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn an_in_scope_redirect_is_followed() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let (r, _) = s
        .call(
            "http_send",
            json!({
                "request": { "url": format!("http://127.0.0.1:{0}/redirect?to=http://127.0.0.1:{0}/search%3Fq%3Dhop", http.port()) },
                "follow_redirects": 2
            }),
        )
        .await;
    let v = Session::json(&r);
    assert_eq!(v["status"], 200, "{}", r.content);
    assert_eq!(v["redirects"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_egress_host_is_refused_with_egress_only() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = Session::start(
        scope(
            &format!(
                "targets = [\"app.test:1\"]\negress = [\"127.0.0.1:{}\"]",
                http.port()
            ),
            &[("app.test", "127.0.0.9")],
        ),
        &[],
        TOOLS,
    )
    .await;
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": { "url": format!("http://127.0.0.1:{}/", http.port()) } }),
        )
        .await;
    assert!(r.is_error);
    assert!(r.content.contains("egress host"), "{}", r.content);
}

#[tokio::test]
async fn an_out_of_scope_send_is_refused_naming_the_layer() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": { "url": "http://example.com/" } }),
        )
        .await;
    assert!(r.is_error);
    assert!(
        r.content.contains("outside the target scope"),
        "{}",
        r.content
    );
    assert!(r.content.contains("proxy"), "{}", r.content);
}

// ── T050: http_history ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn history_filters_and_attributes() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let base = format!("http://127.0.0.1:{}", http.port());
    for i in 0..14 {
        let path = match i % 3 {
            0 => format!("/search?q={i}"),
            1 => format!("/item?id={i}'"), // 500
            _ => "/nope".to_string(),      // 404
        };
        s.call(
            "http_send",
            json!({ "request": { "url": format!("{base}{path}"), "tags": [] } }),
        )
        .await;
    }
    for i in 0..5 {
        s.call(
            "http_send",
            json!({ "request": { "method": "POST", "url": format!("{base}/echo"), "body": format!("{i}") }, "tags": ["authz"] }),
        )
        .await;
    }
    // One forwarded exchange from another tool, through the proxy credential in its environment.
    let (curl, curl_call) = s
        .call(
            "bash",
            json!({ "command": format!("curl -sS -o /dev/null -w '%{{http_code}}' {base}/search?q=curl") }),
        )
        .await;
    assert_eq!(curl.content.trim(), "200", "{}", curl.content);

    assert_eq!(q(&mut s, json!({})).await["total_matched"], 20);
    assert_eq!(
        q(&mut s, json!({ "method": "POST" })).await["total_matched"],
        5
    );
    assert_eq!(
        q(&mut s, json!({ "status": [500] })).await["total_matched"],
        5
    );
    assert_eq!(
        q(&mut s, json!({ "status_range": [400, 499] })).await["total_matched"],
        4
    );
    assert_eq!(
        q(&mut s, json!({ "path_prefix": "/search" })).await["total_matched"],
        6
    );
    assert_eq!(
        q(&mut s, json!({ "since": "-10m" })).await["total_matched"],
        20
    );
    assert_eq!(
        q(&mut s, json!({ "tags": ["authz"] })).await["total_matched"],
        5
    );
    let fwd = q(&mut s, json!({ "origin": "forwarded" })).await;
    assert_eq!(fwd["total_matched"], 1);
    assert_eq!(fwd["rows"][0]["call_id"], curl_call);
    let tool = q(&mut s, json!({ "origin": "tool", "limit": 3 })).await;
    assert_eq!(tool["total_matched"], 19);
    assert_eq!(tool["returned"], 3);
    assert_ne!(tool["rows"][0]["call_id"], curl_call);
    assert_eq!(
        q(&mut s, json!({ "call_id": curl_call })).await["total_matched"],
        1
    );

    let (bad, _) = s.call("http_history", json!({ "metod": "GET" })).await;
    assert!(
        bad.is_error && bad.content.contains("metod"),
        "{}",
        bad.content
    );
}

// ── T051: http_get ───────────────────────────────────────────────────────────────────────────────

async fn q(s: &mut Session, f: serde_json::Value) -> serde_json::Value {
    let (r, _) = s.call("http_history", f).await;
    assert!(!r.is_error, "{}", r.content);
    assert!(r.content.len() <= 24 * 1024);
    Session::json(&r)
}

async fn send(s: &mut Session, base: &str, path: &str) -> String {
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": { "url": format!("{base}{path}") } }),
        )
        .await;
    Session::json(&r)["id"].as_str().unwrap().to_string()
}

async fn get(s: &mut Session, id: &str, view: serde_json::Value) -> bee::tools::ToolResult {
    let (r, _) = s.call("http_get", json!({ "id": id, "view": view })).await;
    assert!(r.content.len() <= 32 * 1024, "{}", r.content.len());
    if !r.is_error {
        assert_eq!(
            r.provenance,
            Provenance::Remote {
                source: format!("http:{id}")
            }
        );
    }
    r
}

#[tokio::test]
async fn get_views_are_bounded_and_remote() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let base = format!("http://127.0.0.1:{}", http.port());
    let gzip = send(&mut s, &base, "/gzip").await;
    let jsn = send(&mut s, &base, "/json").await;
    let big = send(&mut s, &base, "/big").await;
    let bomb = send(&mut s, &base, "/bomb").await;

    let h = Session::json(&get(&mut s, &gzip, json!({ "headers": true })).await);
    assert!(h["content"]
        .as_str()
        .unwrap()
        .contains("Content-Encoding: gzip"));

    let r = Session::json(&get(&mut s, &gzip, json!({ "range": { "start": 6, "len": 9 } })).await);
    assert_eq!(r["content"], "from the ");
    assert_eq!(r["total_decoded_bytes"], vuln_target::GZIP_PLAIN.len());

    let g = Session::json(
        &get(
            &mut s,
            &gzip,
            json!({ "grep": { "pattern": "two", "context_lines": 1 } }),
        )
        .await,
    );
    let c = g["content"].as_str().unwrap();
    assert!(
        c.contains("2: line two") && c.contains("1- hello") && c.contains("3- line three"),
        "{c}"
    );

    let p = Session::json(&get(&mut s, &jsn, json!({ "json_pointer": "/user/role" })).await);
    assert_eq!(p["content"], "\"guest\"");

    let raw = Session::json(&get(&mut s, &jsn, json!({ "raw_head": true })).await);
    assert!(raw["content"]
        .as_str()
        .unwrap()
        .starts_with("HTTP/1.1 200 OK\r\n"));

    let b = Session::json(
        &get(
            &mut s,
            &big,
            json!({ "range": { "start": 0, "len": 10000000 } }),
        )
        .await,
    );
    assert!(b["content"].as_str().unwrap().len() <= 32 * 1024);
    assert_eq!(b["truncated"], true, "stored truncated at max_body_bytes");
    assert_eq!(b["total_decoded_bytes"], 16 * 1024 * 1024);

    let m = Session::json(&get(&mut s, &bomb, json!({ "range": { "start": 0, "len": 16 } })).await);
    assert_eq!(m["decoded_truncated"], true, "{m}");
    assert_eq!(m["total_decoded_bytes"], 64 * 1024 * 1024);
}

#[tokio::test]
async fn http_scope_reports_layers_and_advisory() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session_for(http, "").await;
    let (r, _) = s.call("http_scope", json!({})).await;
    assert!(r.content.len() <= 8 * 1024);
    let v = Session::json(&r);
    assert_eq!(v["enforcement"], "advisory");
    assert_eq!(v["widening"], "requires operator approval");
    let layers = v["entries"][0]["enforced_by"].as_array().unwrap();
    assert!(layers
        .iter()
        .any(|l| l["layer"] == "kernel" && l["installed"] == false));
    assert!(layers.iter().any(|l| l["layer"] == "proxy"));
}
