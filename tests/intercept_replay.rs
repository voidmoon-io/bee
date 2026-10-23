//! 019-http-intercept US5 (T070) — replay with a measured diff, and a map of what has been seen.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use harness::{scope, Session};
use serde_json::json;

const TOOLS: &[&str] = &["http_send", "http_replay", "http_sitemap"];

async fn session(http: std::net::SocketAddr) -> Session {
    Session::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        &[],
        TOOLS,
    )
    .await
}

async fn send(s: &mut Session, req: serde_json::Value) -> String {
    let (r, _) = s.call("http_send", json!({ "request": req })).await;
    assert!(!r.is_error, "{}", r.content);
    Session::json(&r)["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_json_edit_reports_the_changed_path_and_suppresses_the_volatile_ones() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let url = format!("http://127.0.0.1:{}/json", http.port());
    let orig = send(
        &mut s,
        json!({ "method": "POST", "url": url, "headers": [["Content-Type", "application/json"]],
                "body": "{\"user\":{\"role\":\"guest\"}}" }),
    )
    .await;
    let (r, _) = s
        .call(
            "http_replay",
            json!({ "id": orig, "edits": [{ "json_set": { "pointer": "/user/role", "value": "admin" } }] }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    assert!(r.content.len() <= 16 * 1024);
    let v = Session::json(&r);
    assert_eq!(v["parent"], orig);
    assert!(v["probe"].is_string(), "a noise probe ran");
    assert_ne!(v["id"], v["probe"]);
    let d = &v["diff"];
    assert_eq!(d["body"]["kind"], "json");
    assert_eq!(
        d["body"]["json_paths_changed"],
        json!(["/user/role"]),
        "{d}"
    );
    let vol = d["volatile_suppressed"]["paths"].as_array().unwrap();
    assert!(vol.contains(&json!("header:date")), "{vol:?}");
    assert!(vol.contains(&json!("/meta/request_id")), "{vol:?}");
}

#[tokio::test]
async fn a_header_edit_shows_the_status_change() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let orig = send(
        &mut s,
        json!({ "url": format!("http://127.0.0.1:{}/admin", http.port()) }),
    )
    .await;
    let (r, _) = s
        .call(
            "http_replay",
            json!({ "id": orig, "edits": [{ "set_header": { "name": "X-Forwarded-For", "value": "127.0.0.1" } }] }),
        )
        .await;
    assert_eq!(
        Session::json(&r)["diff"]["status"],
        json!([403, 200]),
        "{}",
        r.content
    );
}

#[tokio::test]
async fn without_a_probe_exactly_one_request_is_sent() {
    let (http, _, fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let orig = send(
        &mut s,
        json!({ "url": format!("http://127.0.0.1:{}/search?q=a", http.port()) }),
    )
    .await;
    let before = fx.counters.path_hits("/search");
    let (r, _) = s
        .call("http_replay", json!({ "id": orig, "noise_probe": false, "edits": [{ "set_query": { "name": "q", "value": "b" } }] }))
        .await;
    assert!(Session::json(&r)["probe"].is_null(), "{}", r.content);
    assert_eq!(fx.counters.path_hits("/search") - before, 1);
}

#[tokio::test]
async fn send_with_a_baseline_returns_the_same_diff_shape() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let base = send(
        &mut s,
        json!({ "url": format!("http://127.0.0.1:{}/admin", http.port()) }),
    )
    .await;
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": { "url": format!("http://127.0.0.1:{}/admin", http.port()),
                                 "headers": [["X-Forwarded-For", "127.0.0.1"]] },
                    "baseline": base }),
        )
        .await;
    assert!(r.content.len() <= 16 * 1024);
    let v = Session::json(&r);
    assert_eq!(v["diff"]["status"], json!([403, 200]), "{}", r.content);
    assert!(v["diff"]["volatile_suppressed"].is_object());
}

#[tokio::test]
async fn the_sitemap_lists_every_path_and_parameter() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let base = format!("http://127.0.0.1:{}", http.port());
    for path in [
        "/search?q=1",
        "/search?q=2&page=3",
        "/item?id=1",
        "/item?id=2",
        "/admin",
        "/json",
        "/a/b/c",
        "/a/b/d",
        "/gzip",
        "/echo",
    ] {
        send(&mut s, json!({ "url": format!("{base}{path}") })).await;
    }
    send(
        &mut s,
        json!({ "method": "POST", "url": format!("{base}/form"),
                "headers": [["Content-Type", "application/x-www-form-urlencoded"]], "body": "user=a&pass=b" }),
    )
    .await;
    let (r, _) = s.call("http_sitemap", json!({})).await;
    assert!(r.content.len() <= 24 * 1024);
    let text = r.content.clone();
    for seg in [
        "search", "item", "admin", "json", "\"a\"", "\"b\"", "\"c\"", "\"d\"", "gzip", "echo",
        "form",
    ] {
        assert!(text.contains(seg), "missing {seg}: {text}");
    }
    for p in ["\"q\"", "\"page\"", "\"id\"", "\"user\"", "\"pass\""] {
        assert!(text.contains(p), "missing param {p}: {text}");
    }
}
