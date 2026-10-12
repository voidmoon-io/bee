//! 024 US6 (T063) — the Interceptor's operations, called directly with an explicit call context, give
//! what the `http_*` tools give: no tool, no `Sandbox`.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::time::Duration;

use bee::intercept::diff::Edit;
use bee::intercept::ops::{
    self, CallCtx, OpError, Part, Refusal, ReplaySpec, SendSpec, SitemapQuery, StructuredRequest,
};
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

#[tokio::test]
async fn a_same_origin_redirect_with_a_url_in_its_query_is_followed() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let s = session(http).await;
    let url = format!(
        "http://127.0.0.1:{}/redirect?to=/search%3Fq%3Dhttp://elsewhere.test/",
        http.port()
    );
    let r = ops::send(&s.icpt, &ctx(), get(url, 2)).await.unwrap();
    assert_eq!(r.hops.len(), 1);
    assert!(r.hops[0].stopped.is_none(), "{:?}", r.hops);
    assert_eq!(r.last.record.status, Some(200));
}

#[tokio::test]
async fn an_invalid_edit_sends_nothing() {
    let (http, _, fx) = vuln_target::start_with(false);
    let s = session(http).await;
    let orig = ops::send(
        &s.icpt,
        &ctx(),
        get(format!("http://127.0.0.1:{}/search?q=1", http.port()), 0),
    )
    .await
    .unwrap()
    .last
    .exchange_id;
    let sent_before = fx
        .counters
        .requests
        .load(std::sync::atomic::Ordering::SeqCst);
    let stored_before = s.icpt.with_store(|st| st.count_exchanges()).unwrap();
    let edits: Vec<Edit> =
        serde_json::from_value(json!([{ "json_set": { "pointer": "/a", "value": 1 } }])).unwrap();
    let r = ops::replay(
        &s.icpt,
        &ctx(),
        ReplaySpec {
            id: orig,
            edits,
            noise_probe: true,
            timeout: Duration::from_secs(15),
        },
    )
    .await;
    assert!(matches!(r, Err(OpError::Invalid(_))), "{r:?}");
    assert_eq!(
        fx.counters
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        sent_before,
        "no noise probe went out"
    );
    assert_eq!(
        s.icpt.with_store(|st| st.count_exchanges()).unwrap(),
        stored_before
    );
}

#[tokio::test]
async fn a_refused_replay_is_a_typed_refusal() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let s = session(http).await;
    let orig = ops::send(
        &s.icpt,
        &ctx(),
        get(format!("http://127.0.0.1:{}/search?q=1", http.port()), 0),
    )
    .await
    .unwrap()
    .last
    .exchange_id;
    // Point the stored exchange at a port outside the scope, as if the scope had narrowed since.
    s.icpt.with_store(|st| {
        st.conn()
            .execute("UPDATE exchanges SET port = 1 WHERE id = ?1", [&orig])
            .unwrap()
    });
    let r = ops::replay(
        &s.icpt,
        &ctx(),
        ReplaySpec {
            id: orig,
            edits: Vec::new(),
            noise_probe: false,
            timeout: Duration::from_secs(15),
        },
    )
    .await;
    match r {
        Err(OpError::Refused {
            reason: Refusal::OutOfScope { port: 1, .. },
            ..
        }) => {}
        other => panic!("expected an out-of-scope refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn read_exchange_gives_the_tool_view() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = Session::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        &[],
        &["http_get"],
    )
    .await;
    let id = ops::send(
        &s.icpt,
        &ctx(),
        get(format!("http://127.0.0.1:{}/json", http.port()), 0),
    )
    .await
    .unwrap()
    .last
    .exchange_id;
    let view =
        bee::intercept::slice::View::parse(&json!({ "json_pointer": "/user/role" })).unwrap();
    let direct = ops::read_exchange(&s.icpt, &id, Part::Response, &view, 31 * 1024).unwrap();
    assert_eq!(direct["content"], json!("\"guest\""), "{direct}");
    let (r, _) = s
        .call(
            "http_get",
            json!({ "id": id, "view": { "json_pointer": "/user/role" } }),
        )
        .await;
    assert_eq!(Session::json(&r), direct);

    let head = bee::intercept::slice::View::parse(&json!({ "raw_head": true })).unwrap();
    let req = ops::read_exchange(&s.icpt, &id, Part::Request, &head, 31 * 1024).unwrap();
    assert_eq!(req["part"], "request");
    assert!(req["content"]
        .as_str()
        .unwrap()
        .starts_with("GET /json HTTP/1.1\r\n"));
}
