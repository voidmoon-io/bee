//! 019-http-intercept US8 (T084) — passive leads stay separate from findings.

#![cfg(feature = "intercept")]

#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use harness::{scope, Session};
use serde_json::json;

#[tokio::test]
async fn a_reflected_parameter_becomes_a_lead_announced_once_and_listed_once() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let mut s = Session::start(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        &[],
        &["http_send", "http_leads"],
    )
    .await;
    let marker = "<zq9marker>";
    let (r, _) = s
        .call(
            "http_send",
            json!({ "request": { "url": format!("http://127.0.0.1:{}/search?q=%3Czq9marker%3E", http.port()) } }),
        )
        .await;
    assert!(!r.is_error, "{}", r.content);

    // The next turn's harness note announces it — once.
    let notes = s.session.sandbox.turn_notes();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("new passive lead"), "{notes:?}");
    assert!(s.session.sandbox.turn_notes().is_empty(), "announced once");

    let (r, _) = s.call("http_leads", json!({ "only_new": true })).await;
    let v = Session::json(&r);
    let leads = v["leads"].as_array().unwrap();
    assert!(
        leads.iter().any(|l| l["kind"] == "reflected_parameter"),
        "{v}"
    );
    // Bee's template, not the target's bytes.
    assert!(
        !r.content.contains(marker) && !r.content.contains("zq9marker"),
        "{}",
        r.content
    );

    let (r, _) = s.call("http_leads", json!({ "only_new": true })).await;
    assert_eq!(Session::json(&r)["leads"], json!([]), "listed once");
    let (r, _) = s.call("http_leads", json!({ "only_new": false })).await;
    assert!(!Session::json(&r)["leads"].as_array().unwrap().is_empty());

    // Never a finding: no ledger was written.
    assert!(!s.dir.path().join(".bee/findings").exists());
}
