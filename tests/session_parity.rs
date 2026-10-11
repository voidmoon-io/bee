//! Sessions built by different entry points are the same session (024 FR-006–FR-012, SC-001).
//!
//! Every entry point now builds its session through `bee::session::build`; what differs between them
//! is only what they put in the `SessionSpec`. Here one spec is built for each `EntryPoint` and the
//! snapshots must be equal — the tool surface and each tool's dependencies, the escalation floor and
//! ceiling, how grants are decided, and the system prompt. The refusals a concurrent batch makes are
//! checked by name, and so is the one teardown order.
//!
//! The REPL's and `bee run --task`'s mapping from configuration to a spec lives in the binary and
//! joins this comparison when it moves onto the builder (024 PR 5a-2).

#[path = "support/fixtures.rs"]
mod fixtures;

use std::sync::Arc;
use std::time::Duration;

use bee::session::{build, BuildError, Enforcement, EntryPoint, SessionSpec};
use bee::skills::AllowWithinCeiling;
use bee_core::Access;
use fixtures::{http_policy, policy};

const ENTRIES: [EntryPoint; 4] = [
    EntryPoint::Headless,
    EntryPoint::Repl,
    EntryPoint::Tui,
    EntryPoint::Batch { concurrent: false },
];

fn spec(entry: EntryPoint) -> SessionSpec {
    SessionSpec {
        entry,
        label: "parity".into(),
        policy: Some(policy(&[("/tmp/work", Access::Write)])),
        ceiling: Some(policy(&[("/tmp", Access::Write)])),
        enforcement: Enforcement::Host,
        tools: vec!["bash".into(), "read_file".into(), "render".into()],
        ctf_flag: None,
        skill_roots: Vec::new(),
        mcp: Default::default(),
        security: Default::default(),
        workdir: std::env::temp_dir(),
        system_prompt: "You are a test agent.".into(),
        strip_env: Vec::new(),
        http_scope_advisory: false,
        lease_turns: Some(3),
        consent: Arc::new(AllowWithinCeiling),
        consent_timeout: Duration::from_secs(60),
        prebuilt_sandbox: None,
    }
}

async fn snapshot(entry: EntryPoint) -> serde_json::Value {
    let mut session = build(spec(entry), &|_| {}).await.expect("builds");
    let snap = serde_json::to_value(session.snapshot()).unwrap();
    session.shutdown().await.unwrap();
    snap
}

async fn refused(spec: SessionSpec) -> String {
    match build(spec, &|_| {}).await {
        Err(BuildError(m)) => m,
        Ok(_) => panic!("built a session that should have been refused"),
    }
}

// SC-001: one spec, every entry point, one session.
#[tokio::test]
async fn every_entry_point_builds_the_same_session() {
    let headless = snapshot(EntryPoint::Headless).await;
    for entry in &ENTRIES[1..] {
        assert_eq!(snapshot(*entry).await, headless, "{entry:?}");
    }
    // And the snapshot says something: the tools, the floor and ceiling, the lease lifetime.
    let tools: Vec<&str> = headless["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(tools, ["bash", "read_file", "render"]);
    assert_eq!(headless["policy_fs"], serde_json::json!(["/tmp/work"]));
    assert_eq!(headless["ceiling_fs"], serde_json::json!(["/tmp"]));
    assert_eq!(headless["lease_turns"], 3);
}

// FR-007, SC-003: the system prompt carries the notes for the tools the session holds, for every
// entry point — the headless path used to send the scenario's prompt bare.
#[tokio::test]
async fn the_system_prompt_names_the_render_tool_everywhere() {
    for entry in ENTRIES {
        let snap = snapshot(entry).await;
        let prompt = snap["system_prompt"].as_str().unwrap();
        assert!(prompt.starts_with("You are a test agent."), "{entry:?}");
        assert!(prompt.contains("`render` tool"), "{entry:?}: {prompt}");
    }
}

// FR-008: a concurrent batch refuses, by name and before any scope exists, what it cannot provide.
#[tokio::test]
async fn a_concurrent_batch_refuses_what_it_cannot_provide() {
    let batch = EntryPoint::Batch { concurrent: true };

    let mut with_mcp = spec(batch);
    with_mcp.ceiling = None;
    with_mcp.mcp.enabled = true;
    with_mcp.mcp.servers =
        vec![toml::from_str("name = \"fs\"\ntransport = \"stdio\"\ncommand = \"true\"").unwrap()];
    assert!(refused(with_mcp).await.contains("MCP"));

    let mut with_http = spec(batch);
    with_http.ceiling = None;
    with_http.policy = Some(http_policy(&["127.0.0.1:9"]));
    assert!(refused(with_http).await.contains("[policy.http]"));

    assert!(refused(spec(batch)).await.contains("ceiling"));

    let mut with_skills = spec(batch);
    with_skills.ceiling = None;
    with_skills.skill_roots = vec![std::env::temp_dir()];
    assert!(refused(with_skills).await.contains("skills"));

    let mut plain = spec(batch);
    plain.ceiling = None;
    let mut s = build(plain, &|_| {})
        .await
        .expect("a plain batch session builds");
    s.shutdown().await.unwrap();
}

// FR-012: one teardown order — MCP servers, the Interceptor, the scopes — whether the session is
// shut down or dropped.
#[tokio::test]
async fn teardown_has_one_order_shut_down_or_dropped() {
    for entry in ENTRIES {
        let mut s = build(spec(entry), &|_| {}).await.unwrap();
        let log = s.teardown_log.clone();
        s.shutdown().await.unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            ["mcp", "interceptor", "scopes"],
            "{entry:?}"
        );

        let s = build(spec(entry), &|_| {}).await.unwrap();
        let log = s.teardown_log.clone();
        drop(s);
        assert_eq!(
            *log.lock().unwrap(),
            ["mcp", "interceptor", "scopes"],
            "{entry:?} dropped"
        );
    }
}

// FR-011: the `[policy.http]` advisory is decided in one place, the same way for every entry point.
#[test]
fn the_http_advisory_has_one_answer() {
    use bee::session::http_advisory;
    let p = http_policy(&["127.0.0.1:9"]);
    assert_eq!(
        http_advisory(&policy(&[]), Enforcement::Host, false),
        Ok(None)
    );
    if cfg!(feature = "intercept") {
        // Host mode: nothing in the kernel blocks, so the proxy alone enforces — refused unless the
        // operator accepted it.
        let refusal = http_advisory(&p, Enforcement::Host, false).unwrap_err();
        assert!(refusal.0.contains("--http-scope-advisory"), "{refusal}");
        assert!(http_advisory(&p, Enforcement::Host, true)
            .unwrap()
            .is_some());
    } else {
        assert!(
            http_advisory(&p, Enforcement::Host, true).is_err(),
            "no interception compiled in"
        );
    }
}

// FR-008: kernel enforcement asked of a build without it is refused, not quietly downgraded.
#[cfg(not(feature = "enforce"))]
#[tokio::test]
async fn kernel_enforcement_without_the_feature_is_refused() {
    let mut s = spec(EntryPoint::Headless);
    s.enforcement = Enforcement::Kernel;
    let m = refused(s).await;
    assert!(m.contains("--features enforce"), "{m}");
}
