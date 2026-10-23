//! 019-http-intercept US7 (T080) — shape other tools' traffic with rules, not clicks.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::net::SocketAddr;
use std::time::Duration;

use bee::intercept::control::WireCtx;
use harness::{scope, Session};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn session(http: SocketAddr) -> Session {
    Session::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        &[],
        &["http_intercept", "http_get"],
    )
    .await
}

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
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

/// A forwarded request from "another tool": plain HTTP through the proxy with a credential.
async fn forwarded(proxy: u16, token: &str, call: &str, port: u16, path: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", proxy))
        .await
        .unwrap();
    s.write_all(
        format!(
            "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Proxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
            b64(&format!("{call}:{token}"))
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

async fn token(s: &Session, call: &str) -> String {
    s.icpt
        .issue(WireCtx {
            call_id: call.into(),
            turn: 1,
            origin: "tool".into(),
        })
        .await
        .unwrap()
}

async fn add(s: &mut Session, rule: serde_json::Value) -> String {
    let (r, _) = s
        .call(
            "http_intercept",
            json!({ "action": "add_rule", "rule": rule }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    Session::json(&r)["rule_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_modify_rule_rewrites_and_keeps_the_original() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    add(
        &mut s,
        json!({ "matcher": { "path_prefix": "/echo" },
                "action": { "modify": [{ "set_header": { "name": "X-Injected", "value": "yes" } }] } }),
    )
    .await;
    let tok = token(&s, "c1").await;
    let resp = forwarded(s.icpt.port(), &tok, "c1", http.port(), "/echo").await;
    // Header names are case-insensitive; a rebuilt request carries them lowercase.
    assert!(
        resp.to_ascii_lowercase().contains("x-injected: yes"),
        "upstream saw the rewrite: {resp}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (orig, now): (Option<Vec<u8>>, Vec<u8>) = s.icpt.with_store(|st| {
        st.conn()
            .query_row(
                "SELECT req_original_head, req_head FROM exchanges WHERE call_id = 'c1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    });
    let orig = String::from_utf8(orig.expect("original kept")).unwrap();
    assert!(!orig.to_ascii_lowercase().contains("x-injected"));
    assert!(String::from_utf8_lossy(&now)
        .to_ascii_lowercase()
        .contains("x-injected: yes"));
}

#[tokio::test]
async fn a_drop_rule_answers_502_naming_the_rule() {
    let (http, _, fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let id = add(
        &mut s,
        json!({ "matcher": { "path_prefix": "/admin" }, "action": "drop" }),
    )
    .await;
    let tok = token(&s, "c2").await;
    let resp = forwarded(s.icpt.port(), &tok, "c2", http.port(), "/admin").await;
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    assert!(resp.contains(&id), "{resp}");
    assert_eq!(fx.counters.path_hits("/admin"), 0);
    let mut fired = false;
    for _ in 0..50 {
        if s.icpt
            .take_events("c2")
            .iter()
            .any(|e| e.kind == bee::proxy_event::ProxyEventKind::RuleFired)
        {
            fired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(fired, "rule_fired recorded");
    let (r, _) = s.call("http_intercept", json!({ "action": "list" })).await;
    assert_eq!(Session::json(&r)["rules"][0]["hits"], 1, "{}", r.content);
}

#[tokio::test]
async fn a_hold_released_with_edits_applies_them_and_another_auto_forwards() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    add(
        &mut s,
        json!({ "matcher": { "path_prefix": "/echo" }, "action": { "hold": { "timeout_s": 1 } } }),
    )
    .await;
    let port = s.icpt.port();
    let tok = token(&s, "c3").await;

    // First request: released with an edit.
    let t = tok.clone();
    let first = tokio::spawn(async move { forwarded(port, &t, "c3", http.port(), "/echo").await });
    let mut hold = None;
    for _ in 0..50 {
        let (r, _) = s.call("http_intercept", json!({ "action": "list" })).await;
        if let Some(h) = Session::json(&r)["held"][0]["hold_id"].as_str() {
            hold = Some(h.to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let hold = hold.expect("the request is held");
    let (r, _) = s
        .call(
            "http_intercept",
            json!({ "action": "release", "hold_id": hold,
                    "decision": { "forward_edited": [{ "set_header": { "name": "X-Edited", "value": "1" } }] } }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    let resp = first.await.unwrap();
    assert!(resp.to_ascii_lowercase().contains("x-edited: 1"), "{resp}");

    // Second request: nobody answers, so it goes through unchanged at the deadline.
    let t = tok.clone();
    let resp = forwarded(port, &t, "c3", http.port(), "/echo").await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(!resp.to_ascii_lowercase().contains("x-edited"));
    let mut auto = false;
    for _ in 0..50 {
        if s.icpt
            .take_events("c3")
            .iter()
            .any(|e| e.kind == bee::proxy_event::ProxyEventKind::AutoForwarded)
        {
            auto = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(auto, "auto_forwarded recorded");
}

#[tokio::test]
async fn a_rule_cannot_rewrite_traffic_out_of_scope() {
    let (http, _, fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    add(
        &mut s,
        json!({ "matcher": {}, "action": { "modify": [{ "set_header": { "name": "Host", "value": "evil.test" } }] } }),
    )
    .await;
    let tok = token(&s, "c4").await;
    let resp = forwarded(s.icpt.port(), &tok, "c4", http.port(), "/search?q=x").await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(
        fx.counters
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn rules_are_session_only_and_holds_are_bounded() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    add(&mut s, json!({ "matcher": {}, "action": "drop" })).await;
    let (r, _) = s
        .call("http_intercept", json!({ "action": "add_rule", "rule": { "matcher": {}, "action": { "hold": { "timeout_s": 301 } } } }))
        .await;
    assert!(
        r.is_error && r.content.contains("invalid arguments"),
        "{}",
        r.content
    );

    // A fresh session (a fresh worker) has no rules.
    let mut fresh = session(http).await;
    let (r, _) = fresh
        .call("http_intercept", json!({ "action": "list" }))
        .await;
    assert_eq!(Session::json(&r)["rules"], json!([]));
}
