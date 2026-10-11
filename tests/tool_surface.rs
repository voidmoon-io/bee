//! 024 PR2 (US4) — every granted tool works the moment it is granted
//! (specs/024-session-core/contracts/tool-surface.md, FR-013–FR-016).
//!
//! One constructor, `ToolRegistry::register`, builds every built-in tool from the registry's
//! `ToolDeps`. A tool registered at start-up, by a skill grant, or by escalation mid-session is built
//! the same way and holds the same dependencies, and `surface()` is the one answer to "which tools,
//! configured how".

use std::sync::Arc;
use std::time::Duration;

use bee::grants::escalate::escalate;
use bee::grants::{ActivePolicy, GrantDelta, GrantOrigin, Ttl};
use bee::provider::ToolCall;
use bee::sandbox::Sandbox;
use bee::skills::AllowWithinCeiling;
use bee::tools::{ToolDeps, ToolRegistry, UnknownTool};
use bee_core::{Access, Mode, Policy};

#[cfg(feature = "intercept")]
#[path = "support/harness.rs"]
mod harness;

fn policy(fs: &[(&str, Access)]) -> Policy {
    let mut p = Policy {
        name: "p".into(),
        description: None,
        mode: Mode::Enforce,
        filesystem: Default::default(),
        exec: Default::default(),
        network: Default::default(),
        exfiltration: Default::default(),
        http: None,
    };
    for (path, a) in fs {
        p.filesystem.insert(path.to_string(), *a);
    }
    p
}

fn call(name: &str, arguments: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: name.into(),
        arguments,
    }
}

/// Grant `tools` mid-session through `escalate`, the way a kernel denial or a skill requirement does.
async fn grant(registry: &mut ToolRegistry, tools: &[&str]) {
    let mut active = ActivePolicy::new(policy(&[]), policy(&[("/tmp", Access::Write)]));
    let mut delta = GrantDelta::default();
    delta
        .filesystem
        .insert("/tmp/granted".to_string(), Access::Write);
    delta.tools = tools.iter().map(|t| t.to_string()).collect();
    let out = escalate(
        &mut active,
        GrantOrigin::Explicit,
        delta,
        Ttl::Turns(5),
        0,
        &AllowWithinCeiling,
        Duration::from_secs(5),
        &mut Sandbox::host(Vec::new()),
        registry,
    )
    .await;
    assert!(out.is_granted(), "{out:?}");
}

/// `surface()` as comparable JSON.
fn surface(registry: &ToolRegistry) -> serde_json::Value {
    serde_json::to_value(registry.surface()).unwrap()
}

#[test]
fn an_unknown_name_is_refused() {
    let mut r = ToolRegistry::new();
    assert_eq!(
        r.register("no_such_tool"),
        Err(UnknownTool("no_such_tool".into()))
    );
}

// (e) `submit_flag` registers only when the deps carry a flag.
#[test]
fn submit_flag_needs_a_flag() {
    let mut r = ToolRegistry::new();
    r.register("submit_flag").unwrap();
    assert!(!r.contains("submit_flag"), "no flag, no tool");
    let mut r = ToolRegistry::with_deps(Arc::new(ToolDeps::with_flag(Some("FLAG{x}"))));
    r.register("submit_flag").unwrap();
    assert!(r.contains("submit_flag"));
    let entry = &r.surface()[0];
    assert_eq!(entry.deps.ctf_flag, Some(true));
}

// (d) A 016 tool compiled out of this build registers its refusing stub, never nothing.
#[cfg(not(feature = "astgrep"))]
#[tokio::test]
async fn a_compiled_out_tool_registers_its_stub() {
    let mut r = ToolRegistry::new();
    r.register("ast_grep").unwrap();
    let res = r
        .execute(
            &call("ast_grep", serde_json::json!({})),
            &Sandbox::host(Vec::new()),
        )
        .await;
    assert!(res.is_error);
    assert!(
        res.content.contains("not_compiled_in") || res.content.contains("astgrep"),
        "{}",
        res.content
    );
}

// (f) A tool granted mid-session is the tool a session that held it from the start has.
#[tokio::test]
async fn a_granted_tool_matches_one_held_from_the_start() {
    let deps = Arc::new(ToolDeps::with_flag(Some("FLAG{x}")));
    let mut from_start = ToolRegistry::with_deps(deps.clone());
    from_start.register("bash").unwrap();
    from_start.register("submit_flag").unwrap();

    let mut granted = ToolRegistry::with_deps(deps);
    granted.register("bash").unwrap();
    grant(&mut granted, &["submit_flag"]).await;

    assert_eq!(surface(&granted), surface(&from_start));
}

// `set_deps` rebuilds every tool `register` built, so a dependency that arrives late (the
// Interceptor, a widened policy's scanner grants) reaches tools already named.
#[test]
fn set_deps_rebuilds_registered_tools() {
    let mut r = ToolRegistry::new();
    r.register("bash").unwrap();
    r.register("submit_flag").unwrap();
    assert!(!r.contains("submit_flag"));
    r.set_deps(Arc::new(ToolDeps::with_flag(Some("FLAG{x}"))));
    // `submit_flag` was not built (no flag), so it is not in the rebuilt set: a late flag does not
    // conjure a tool nobody registered successfully.
    assert!(!r.contains("submit_flag"));
    assert!(r.contains("bash"));
}

// (a) `record_finding` writes to the session's ledger, whether held from the start or granted.
#[cfg(feature = "findings")]
#[tokio::test]
async fn record_finding_writes_to_the_session_ledger_even_when_granted() {
    let dir = tempfile::tempdir().unwrap();
    let security = bee::security::SecurityConfig {
        findings_dir: Some(dir.path().join("ledger")),
        ..Default::default()
    };
    let deps = ToolDeps::default().with_security(&security, None, "run-tool-surface");
    let mut r = ToolRegistry::with_deps(Arc::new(deps));
    r.register("bash").unwrap();
    grant(&mut r, &["record_finding"]).await;

    let entry = r
        .surface()
        .into_iter()
        .find(|e| e.name == "record_finding")
        .expect("granted");
    assert_eq!(entry.deps.ledger, Some(true));

    let res = r
        .execute(
            &call(
                "record_finding",
                serde_json::json!({
                    "path": "src/main.rs",
                    "class": "sql-injection",
                    "title": "query built by concatenation",
                    "evidence": "format!(\"SELECT … {}\", input)"
                }),
            ),
            &Sandbox::host(Vec::new()),
        )
        .await;
    assert!(!res.is_error, "{}", res.content);
    let written = std::fs::read_to_string(dir.path().join("ledger/ledger.jsonl"))
        .expect("the finding went to the session's ledger");
    assert!(written.contains("run-tool-surface"), "{written}");
}

// (c) `scan` holds exactly the grants the deps carry; with none it refuses.
#[cfg(feature = "scanners")]
#[tokio::test]
async fn scan_holds_the_session_grants() {
    let deps = ToolDeps::default().with_security(
        &bee::security::SecurityConfig::default(),
        Some(&policy(&[])),
        "run",
    );
    let mut r = ToolRegistry::with_deps(Arc::new(deps));
    r.register("scan").unwrap();
    assert_eq!(r.surface()[0].deps.scanner_grants, Some(0));
    let res = r
        .execute(
            &call(
                "scan",
                serde_json::json!({ "scanner": "semgrep", "path": "." }),
            ),
            &Sandbox::host(Vec::new()),
        )
        .await;
    assert!(res.is_error, "no grant, no scan: {}", res.content);
}

// (b) An HTTP tool built without an Interceptor refuses; built with one — even when granted
// mid-session — it reaches it.
#[cfg(feature = "intercept")]
mod http {
    use super::*;
    use crate::harness;

    #[tokio::test]
    async fn without_an_interceptor_the_tool_refuses() {
        let mut r = ToolRegistry::new();
        r.register("http_scope").unwrap();
        assert_eq!(r.surface()[0].deps.interceptor, Some(false));
        let res = r
            .execute(
                &call("http_scope", serde_json::json!({})),
                &Sandbox::host(Vec::new()),
            )
            .await;
        assert!(
            res.content.contains("interception proxy is unavailable"),
            "{}",
            res.content
        );
    }

    #[tokio::test]
    async fn a_granted_http_tool_reaches_the_session_interceptor() {
        let mut s = harness::Session::start(
            harness::scope("targets = [\"127.0.0.1:9\"]", &[]),
            &[],
            &["bash"],
        )
        .await;
        assert!(!s.registry.contains("http_scope"));
        grant(&mut s.registry, &["http_scope"]).await;
        let entry = s
            .registry
            .surface()
            .into_iter()
            .find(|e| e.name == "http_scope")
            .expect("granted");
        assert_eq!(
            entry.deps.interceptor,
            Some(true),
            "granted holding the Interceptor"
        );
        let (res, _) = s.call("http_scope", serde_json::json!({})).await;
        assert!(
            !res.content.contains("interception proxy is unavailable"),
            "a granted HTTP tool reaches the running Interceptor: {}",
            res.content
        );
    }
}
