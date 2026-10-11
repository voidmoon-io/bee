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
#[path = "support/scripted.rs"]
mod scripted;

use std::sync::Arc;

use bee::operator::{ChannelConsent, NullOutput, Operator};
use bee::session::{build, BuildError, Enforcement, EntryPoint, SessionSpec};
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
        operator: Operator::autonomous(Arc::new(NullOutput)),
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

// SC-001, SC-005: an autonomous and an interactive session differ only in the operator — who
// decides a grant, and how long they have.
#[tokio::test]
async fn interactive_and_autonomous_differ_only_in_the_operator() {
    let autonomous = snapshot(EntryPoint::Repl).await;
    let (consent, _rx) = ChannelConsent::new();
    let mut interactive_spec = spec(EntryPoint::Repl);
    interactive_spec.operator = Operator::interactive(consent, Arc::new(NullOutput));
    let mut session = build(interactive_spec, &|_| {}).await.expect("builds");
    let interactive = serde_json::to_value(session.snapshot()).unwrap();
    session.shutdown().await.unwrap();

    assert_eq!(autonomous["operator"], "autonomous");
    assert_eq!(interactive["operator"], "interactive");
    assert_eq!(
        (
            autonomous["consent_timeout_secs"].as_u64(),
            interactive["consent_timeout_secs"].as_u64()
        ),
        (Some(60), Some(120))
    );
    let without_operator = |mut v: serde_json::Value| {
        let o = v.as_object_mut().unwrap();
        o.remove("operator");
        o.remove("consent_timeout_secs");
        v
    };
    assert_eq!(without_operator(autonomous), without_operator(interactive));
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

// FR-027 (research R8): a kernel event from an MCP server's own process is that server's, never the
// open tool call's. It lands in the session's per-server record, and a denial there drives no
// escalation for the call. Processes the server spawns are not tracked (documented limitation).
#[tokio::test]
async fn an_mcp_servers_own_events_are_its_not_the_open_calls() {
    use bee::call::{run_call, CallInput, Escalation, TimeoutPolicy};
    use bee::grants::ActivePolicy;
    use bee::provider::ToolCall;
    use bee::sandbox::{CallOrigin, Sandbox, ScriptedAudit};
    use scripted::{ev, Attempt, ScriptedTool, SCRIPTED};

    const SERVER_TGID: u32 = 4242;
    let with_tgid = |mut e: bee_core::AuditEvent, tgid: u32| {
        e.tgid = Some(tgid);
        e
    };
    let server_denial = with_tgid(ev("file_open", "/etc/shadow", "denied", None), SERVER_TGID);
    let tool_event = with_tgid(ev("file_open", "/tmp/work/a", "observed", None), 7);

    // Run one call whose attempt produces both events, with the server registered or not.
    let run = |registered: bool| {
        let (server_denial, tool_event) = (server_denial.clone(), tool_event.clone());
        async move {
            let audit = Arc::new(ScriptedAudit::default());
            let mut s = spec(EntryPoint::Headless);
            s.prebuilt_sandbox = Some(Sandbox::host_scripted(Vec::new(), audit.clone()));
            let mut session = build(s, &|_| {}).await.expect("builds");
            if registered {
                // What the builder does with `McpBridge::server_tgids()` once servers connect.
                session
                    .sandbox
                    .set_mcp_servers([("fs".to_string(), SERVER_TGID)]);
            }
            session.registry.insert(Box::new(ScriptedTool::new(
                audit,
                vec![Attempt::ok("done").with_audit(vec![server_denial, tool_event])],
            )));
            let esc = session.escalation.take().unwrap();
            let mut active = ActivePolicy::new(esc.base.clone(), esc.ceiling.clone());
            let call = ToolCall {
                id: "c1".into(),
                name: SCRIPTED.into(),
                arguments: serde_json::json!({}),
            };
            let out = run_call(
                CallInput {
                    call: &call,
                    turn: 1,
                    origin: CallOrigin::Tool,
                    timeout: TimeoutPolicy::PerCall(std::time::Duration::from_secs(5)),
                },
                &mut session.sandbox,
                &mut session.registry,
                Some(Escalation {
                    config: &esc,
                    active: &mut active,
                    lease_turn: 1,
                }),
            )
            .await;
            let record = session.sandbox.take_mcp_audit();
            session.shutdown().await.unwrap();
            (out, record)
        }
    };

    let (out, record) = run(true).await;
    assert_eq!(
        out.audit,
        std::slice::from_ref(&tool_event),
        "only the tool's own event"
    );
    assert_eq!(out.tool_denials(), 0);
    assert!(out.escalations.is_empty(), "{:?}", out.escalations);
    assert_eq!(record.len(), 1);
    assert_eq!(record["fs"], std::slice::from_ref(&server_denial));

    // Unregistered, the same event is the call's: the routing is attribution, never a filter.
    let (out, record) = run(false).await;
    assert_eq!(out.audit, [server_denial, tool_event]);
    assert!(record.is_empty());
}
