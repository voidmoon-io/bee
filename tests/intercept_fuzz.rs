//! 019-http-intercept US6 (T075) — fuzz and see only what stands out (SC-006).

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::time::Instant;

use harness::{scope, Session};
use serde_json::json;

async fn session(http: std::net::SocketAddr, limits: &str) -> Session {
    Session::start(
        scope(
            &format!(
                "targets = [\"127.0.0.1:{}\"]\n[policy.http.limits]\n{limits}",
                http.port()
            ),
            &[],
        ),
        &[],
        &["http_fuzz", "http_send"],
    )
    .await
}

/// 1,000 payloads, exactly two of which the target answers with a 500.
fn payloads_with_two_bad() -> Vec<String> {
    (0..1000)
        .map(|i| match i {
            137 => "137'".to_string(),
            802 => "x'OR1".to_string(),
            _ => i.to_string(),
        })
        .collect()
}

fn template(port: u16) -> serde_json::Value {
    json!({ "raw": {
        "scheme": "http", "host": "127.0.0.1", "port": port,
        "bytes": format!("GET /item?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
    }})
}

#[tokio::test]
async fn a_thousand_variants_cluster_and_the_two_errors_stand_out() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http, "rps = 2000\nconcurrency = 32").await;
    let (r, _) = s
        .call(
            "http_fuzz",
            json!({ "template": template(http.port()), "payloads": [{ "inline": payloads_with_two_bad() }] }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    assert!(
        r.content.len() <= 16 * 1024,
        "summary is bounded: {}",
        r.content.len()
    );
    let v = Session::json(&r);
    assert_eq!(v["counts"]["planned"], 1000);
    assert_eq!(v["counts"]["sent"], 1000, "{v}");
    let outliers = v["outliers"].as_array().unwrap();
    let five_hundreds: Vec<_> = outliers
        .iter()
        .filter(|g| g["key"]["status"] == 500)
        .collect();
    assert!(!five_hundreds.is_empty(), "the 500s are outliers: {v}");
    let size: u64 = five_hundreds
        .iter()
        .map(|g| g["size"].as_u64().unwrap())
        .sum();
    assert_eq!(size, 2);
    let samples = serde_json::to_string(&five_hundreds).unwrap();
    assert!(
        samples.contains("137'") && samples.contains("x'OR1"),
        "{samples}"
    );
    // The common responses are a group, not a thousand rows.
    assert!(v["common"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["key"]["status"] == 200));
}

#[tokio::test]
async fn over_the_run_limit_is_refused_before_any_request() {
    let (http, _, fx) = vuln_target::start_with(false);
    let mut s = session(http, "max_requests_per_run = 100").await;
    let (r, _) = s
        .call(
            "http_fuzz",
            json!({ "template": template(http.port()), "payloads": [{ "range": { "from": 1, "to": 101 } }] }),
        )
        .await;
    assert!(r.is_error);
    assert!(r.content.contains("max_requests_per_run"), "{}", r.content);
    assert_eq!(
        fx.counters
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn the_rate_is_held_to_the_limit_and_arguments_only_lower_it() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http, "rps = 50\nconcurrency = 8").await;
    let t0 = Instant::now();
    let (r, _) = s
        .call(
            "http_fuzz",
            // Asking for more than the policy allows is clamped, never honoured.
            json!({ "template": template(http.port()), "payloads": [{ "range": { "from": 1, "to": 150 } }], "rps": 10000 }),
        )
        .await;
    let elapsed = t0.elapsed();
    let v = Session::json(&r);
    assert_eq!(v["effective"]["rps"], 50, "{v}");
    // 150 requests at 50/s, 50 of them as the initial burst: at least ~2 s.
    assert!(elapsed.as_secs_f64() >= 1.8, "{elapsed:?}");

    let (r, _) = s
        .call(
            "http_fuzz",
            json!({ "template": template(http.port()), "payloads": [{ "range": { "from": 1, "to": 3 } }], "rps": 5 }),
        )
        .await;
    assert_eq!(Session::json(&r)["effective"]["rps"], 5);
}

#[tokio::test]
async fn an_out_of_scope_variant_is_refused_and_not_counted_as_a_response() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http, "").await;
    let port = http.port();
    let (r, _) = s
        .call(
            "http_fuzz",
            json!({
                "template": { "raw": { "scheme": "http", "host": "127.0.0.1", "port": port,
                    "bytes": format!("GET / HTTP/1.1\r\nHost: §127.0.0.1:{port}§\r\nConnection: close\r\n\r\n") } },
                "payloads": [{ "inline": [format!("127.0.0.1:{port}"), "evil.test".to_string()] }]
            }),
        )
        .await;
    let v = Session::json(&r);
    assert_eq!(v["counts"]["refused"], 1, "{v}");
    assert_eq!(v["counts"]["sent"], 1);
    assert_eq!(v["variants"], 1, "only the answered variant is clustered");
}

#[tokio::test]
async fn a_from_template_marks_positions_and_a_project_file_is_read_in_scope() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http, "").await;
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": { "url": format!("http://127.0.0.1:{}/item?id=1", http.port()) } }),
        )
        .await;
    let id = Session::json(&r)["id"].as_str().unwrap().to_string();
    let list = s.dir.path().join("words.txt");
    std::fs::write(&list, "1\n2\n3'\n").unwrap();
    let (r, _) = s
        .call(
            "http_fuzz",
            json!({
                "template": { "from": id, "mark": ["id=1"] },
                "payloads": [{ "project_file": list.display().to_string() }]
            }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    // The marked text is `id=1`, so payloads replace the whole `id=…` pair.
    let v = Session::json(&r);
    assert_eq!(v["counts"]["planned"], 3, "{v}");
}

#[tokio::test]
async fn bad_specs_are_invalid_args() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = session(http, "").await;
    for args in [
        json!({ "template": template(http.port()), "payloads": [{ "builtin": "nope" }] }),
        json!({ "template": template(http.port()), "payloads": [{ "inline": ["a"] }], "mode": "pitchfork_x" }),
        json!({ "template": { "raw": { "scheme": "http", "host": "127.0.0.1", "port": http.port(), "bytes": "GET / HTTP/1.1\r\n\r\n" } },
                "payloads": [{ "inline": ["a"] }] }),
    ] {
        let (r, _) = s.call("http_fuzz", args).await;
        assert!(
            r.is_error && r.content.contains("invalid arguments"),
            "{}",
            r.content
        );
    }
}
