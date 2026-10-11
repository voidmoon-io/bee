//! 024 US6 (T063) — the Interceptor's operations, called directly with an explicit call context, give
//! what the `http_*` tools give: no tool, no `Sandbox`.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::time::Duration;

use bee::intercept::diff::Edit;
use bee::intercept::ops::{self, CallCtx, ReplaySpec, SendSpec, SitemapQuery, StructuredRequest};
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

fn ctx() -> CallCtx {
    CallCtx {
        call_id: "ops-test".into(),
        turn: 1,
        origin: "tool".into(),
    }
}

fn get(url: String, follow_redirects: u32) -> SendSpec {
    let (target, bytes) = ops::build_request(StructuredRequest {
        method: "GET".into(),
        url,
        headers: Vec::new(),
        body: Vec::new(),
    })
    .unwrap();
    SendSpec {
        target,
        bytes,
        follow_redirects,
        timeout: Duration::from_secs(15),
        tags: Vec::new(),
        baseline: None,
    }
}

#[tokio::test]
async fn an_out_of_scope_redirect_stops_at_that_hop() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let (other, _, other_fx) = vuln_target::start_with(false);
    let s = session(http).await;
    let url = format!(
        "http://127.0.0.1:{}/redirect?to=http://127.0.0.1:{}/search",
        http.port(),
        other.port()
    );
    let r = ops::send(&s.icpt, &ctx(), get(url, 2)).await.unwrap();
    assert!(r.refused.is_none());
    assert_eq!(r.last.record.status, Some(302));
    assert_eq!(r.hops.len(), 1);
    assert!(
        r.hops[0]
            .stopped
            .as_deref()
            .unwrap()
            .contains("out of scope"),
        "{:?}",
        r.hops
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
    let s = session(http).await;
    let url = format!(
        "http://127.0.0.1:{0}/redirect?to=http://127.0.0.1:{0}/search%3Fq%3Dhop",
        http.port()
    );
    let r = ops::send(&s.icpt, &ctx(), get(url, 2)).await.unwrap();
    assert_eq!(r.last.record.status, Some(200));
    assert_eq!(r.hops.len(), 1);
    assert!(r.hops[0].stopped.is_none());
    // The exchange is attributed to the context the caller passed, not to any sandbox call.
    let e = s
        .icpt
        .with_store(|st| st.get_exchange(&r.last.exchange_id))
        .unwrap()
        .unwrap();
    assert_eq!(e.call_id.as_deref(), Some("ops-test"));
}

#[tokio::test]
async fn replay_with_an_edit_gives_the_tool_diff_shape() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let s = session(http).await;
    let (target, bytes) = ops::build_request(StructuredRequest {
        method: "POST".into(),
        url: format!("http://127.0.0.1:{}/json", http.port()),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"user":{"role":"guest"}}"#.to_vec(),
    })
    .unwrap();
    let orig = ops::send(
        &s.icpt,
        &ctx(),
        SendSpec {
            target,
            bytes,
            follow_redirects: 0,
            timeout: Duration::from_secs(15),
            tags: Vec::new(),
            baseline: None,
        },
    )
    .await
    .unwrap()
    .last
    .exchange_id;
    let edits: Vec<Edit> = serde_json::from_value(
        json!([{ "json_set": { "pointer": "/user/role", "value": "admin" } }]),
    )
    .unwrap();
    let r = ops::replay(
        &s.icpt,
        &ctx(),
        ReplaySpec {
            id: orig.clone(),
            edits,
            noise_probe: true,
            timeout: Duration::from_secs(15),
        },
    )
    .await
    .unwrap();
    assert_eq!(r.parent, orig);
    assert!(r.probe.is_some(), "a noise probe ran");
    assert_eq!(r.diff["body"]["kind"], "json");
    assert_eq!(r.diff["body"]["json_paths_changed"], json!(["/user/role"]));
    let vol = r.diff["volatile_suppressed"]["paths"].as_array().unwrap();
    assert!(vol.contains(&json!("header:date")), "{vol:?}");
    assert!(vol.contains(&json!("/meta/request_id")), "{vol:?}");
}

#[tokio::test]
async fn the_sitemap_op_matches_the_tool() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http).await;
    let base = format!("http://127.0.0.1:{}", http.port());
    for path in ["/search?q=1", "/item?id=2", "/a/b/c", "/a/b/d"] {
        ops::send(&s.icpt, &ctx(), get(format!("{base}{path}"), 0))
            .await
            .unwrap();
    }
    let direct = ops::sitemap(
        &s.icpt,
        SitemapQuery {
            host: None,
            path_prefix: "/".into(),
            depth: 4,
        },
        ops::sitemap::BOUND,
    )
    .unwrap();
    let (r, _) = s.call("http_sitemap", json!({})).await;
    assert!(!r.is_error, "{}", r.content);
    assert_eq!(Session::json(&r), direct);
}
