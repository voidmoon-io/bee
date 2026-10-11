//! 019-http-intercept US9 (T089) — HAR export: valid, and nothing in it that should not leave.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use harness::{scope, Session};
use serde_json::json;

#[tokio::test]
async fn the_export_is_har_1_2_without_credentials_and_with_sensitive_headers_flagged() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = Session::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        &[],
        &["http_send"],
    )
    .await;
    let port = http.port();
    // A model-written raw request carrying every header that must not travel unflagged.
    let raw = format!(
        "GET /search?q=x HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Authorization: Basic c2VjcmV0OnRva2Vu\r\n\
         Authorization: Bearer abc\r\nCookie: sid=1\r\nConnection: close\r\n\r\n"
    );
    let (r, _) = s
        .call(
            "http_send",
            json!({ "raw": { "scheme": "http", "host": "127.0.0.1", "port": port, "bytes": raw } }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);
    s.call(
        "http_send",
        json!({ "request": { "url": format!("http://127.0.0.1:{port}/json") } }),
    )
    .await;
    // Also issue a credential, so a live proxy token exists somewhere it could leak from.
    let token = s
        .icpt
        .issue(bee::intercept::control::WireCtx {
            call_id: "c".into(),
            turn: 1,
            origin: "tool".into(),
        })
        .await
        .unwrap();

    let out = s.dir.path().join("x.har");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(["http", "export", "--har"])
        .arg(&out)
        .arg("--project")
        .arg(s.dir.path())
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let text = std::fs::read_to_string(&out).unwrap();
    let har: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(har["log"]["version"], "1.2");
    let entries = har["log"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    for e in entries {
        for k in [
            "startedDateTime",
            "time",
            "request",
            "response",
            "cache",
            "timings",
        ] {
            assert!(e.get(k).is_some(), "missing {k}");
        }
    }
    assert!(!text.contains("PRIVATE KEY"));
    assert!(
        !text.to_ascii_lowercase().contains("proxy-authorization"),
        "the proxy credential header is stripped"
    );
    assert!(!text.contains("c2VjcmV0OnRva2Vu"));
    assert!(!text.contains(&token), "no bee credential");
    let echo = entries
        .iter()
        .find(|e| e["request"]["url"].as_str().unwrap().contains("/search"))
        .unwrap();
    let sensitive = echo["_bee"]["sensitive"].as_array().unwrap();
    assert!(
        sensitive.contains(&json!("authorization")) && sensitive.contains(&json!("cookie")),
        "{sensitive:?}"
    );

    // A filter narrows the export.
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(["http", "export", "--har"])
        .arg(&out)
        .arg("--project")
        .arg(s.dir.path())
        .args(["--filter", r#"{"path_prefix": "/json"}"#])
        .output()
        .unwrap();
    assert!(status.status.success());
    let har: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
}
