//! Audit probes assert observed defects, not desired behavior. All file effects are in temp dirs.
use std::sync::Arc;
use std::time::Duration;

use bee::grants::escalate::LoopEscalation;
use bee::grants::{GrantDelta, Ttl};
use bee::hooks::{Flow, LoopHook, StepEvent};
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Model, ModelError, ToolCall, ToolSchema, Turn};
use bee::sandbox::Sandbox;
use bee::scenario::Scenario;
use bee::tools::{registry_for, ToolRegistry};
use bee::{run_loop, LoopOptions};

fn scenario() -> Scenario {
    Scenario {
        id: "audit-probe".into(), policy_path: "/dev/null".into(),
        system_prompt: "test".into(), task: "test".into(), turn_limit: 4, timeout_secs: 10,
        tools: vec!["bash".into()], mode: Default::default(), workdir: Default::default(),
        mcp: Default::default(), skills: vec![], ceiling_policy_path: None,
        security: Default::default(),
    }
}

fn call(id: &str) -> ToolCall {
    ToolCall { id: id.into(), name: "bash".into(),
        arguments: serde_json::json!({"command": "printf audit-probe"}) }
}

struct NeverReturns;
#[async_trait::async_trait]
impl Model for NeverReturns {
    fn id(&self) -> &str { "audit/pending" }
    async fn complete(&self, _: &Conversation, _: &[ToolSchema]) -> Result<Turn, ModelError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn probe_provider_outlives_episode_deadline() {
    let mut sc = scenario();
    sc.timeout_secs = 1;
    let result = tokio::time::timeout(Duration::from_millis(1300), run_loop(
        &NeverReturns, &sc, &mut ToolRegistry::new(), &mut Sandbox::host(vec![]),
        &LoopOptions::default(),
    )).await;
    assert!(result.is_err(), "probe: outer watchdog, not the episode deadline, stopped the call");
}

#[tokio::test]
async fn probe_cancelled_child_leaves_descendant_alive() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("survived");
    let ready = tmp.path().join("ready");
    let script = format!(
        "(sleep 1; printf survived > '{}') >/dev/null 2>&1 & touch '{}'; sleep 3",
        marker.display(), ready.display()
    );
    let sandbox = Sandbox::host(vec![]);
    let args = vec!["-c".to_string(), script];
    let result = tokio::time::timeout(Duration::from_millis(300),
        bee::tools::exec::run_child(&sandbox, "sh", &args, None, 4096)).await;
    assert!(ready.exists(), "the shell started before cancellation");
    assert!(result.is_err());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(marker.exists(), "probe: the descendant ran after the tool was cancelled");
    // The final sleep is bounded; allow it to exit before returning.
    tokio::time::sleep(Duration::from_secs(2)).await;
}

struct Hook { grant: bool }
#[async_trait::async_trait]
impl LoopHook for Hook {
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        if let StepEvent::BeforeToolCall(tc) = ev {
            if !self.grant { return Flow::Deny("audit refusal".into()); }
            if tc.id == "1" {
                return Flow::Escalate(GrantDelta {
                    tools: vec!["bash".into()], ..Default::default()
                });
            }
        }
        Flow::Continue
    }
}

fn options(grant: bool) -> LoopOptions {
    let policy = bee_core::Policy::from_toml("[policy]\nname='audit'\n").unwrap();
    LoopOptions {
        escalation: Some(LoopEscalation {
            base: policy.clone(), ceiling: policy, hooks: vec![Box::new(Hook { grant })],
            consent: Arc::new(bee::skills::AllowWithinCeiling),
            timeout: Duration::from_secs(1), default_ttl: Ttl::Turns(1),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn probe_deny_hook_does_not_prevent_execution() {
    let sc = scenario();
    let model = MockModel::scripted(vec![Turn::calls(vec![call("1")]), Turn::text("done")]);
    let transcript = run_loop(&model, &sc, &mut registry_for(&sc.tools, None),
        &mut Sandbox::host(vec![]), &options(false)).await;
    let result = &transcript.turns[0].calls[0].result;
    assert!(!result.is_error);
    assert_eq!(result.content, "audit-probe", "probe: a hook-denied command still executed");
}

#[tokio::test]
async fn probe_one_turn_grant_survives_next_turn() {
    let sc = scenario();
    let model = MockModel::scripted(vec![Turn::calls(vec![call("1")]),
        Turn::calls(vec![call("2")]), Turn::text("done")]);
    let mut registry = ToolRegistry::new();
    let transcript = run_loop(&model, &sc, &mut registry,
        &mut Sandbox::host(vec![]), &options(true)).await;
    assert!(!transcript.turns[0].calls[0].result.is_error);
    assert!(!transcript.turns[1].calls[0].result.is_error,
        "probe: a Turns(1) grant still executes on turn 1 after being granted on turn 0");
    assert!(registry.contains("bash"));
}

#[cfg(feature = "findings")]
#[test]
fn probe_ledger_follows_project_symlink() {
    use bee::findings::{record, Finding, FindingSource, Ledger, Sighting};
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("outside-ledger");
    std::fs::write(&target, "sentinel\n").unwrap();
    let ledger = Ledger::at(tmp.path().join("project/.bee/findings"));
    ledger.ensure_dir().unwrap();
    std::os::unix::fs::symlink(&target, ledger.log_path()).unwrap();
    let finding = Finding::new("a.rs".into(), "test".into(), "test".into(),
        "audit evidence".into(), FindingSource::Tool("audit".into()));
    record(&ledger, finding, Sighting::now("audit")).unwrap();
    let body = std::fs::read_to_string(&target).unwrap();
    assert!(body.starts_with("sentinel\n{"), "probe: ledger append wrote through a symlink");
}

#[test]
fn probe_grant_discards_inherited_executable_pin() {
    use bee::grants::{ActivePolicy, GrantOrigin};
    let base = bee_core::Policy::from_toml(
        "[policy]\nname='audit'\n[policy.exec]\nallow=['!/bin/true']\n"
    ).unwrap();
    let mut ceiling = base.clone();
    ceiling.exec.allow.push("!/bin/sh".into());
    let mut active = ActivePolicy::new(base, ceiling);
    active.try_apply(GrantOrigin::Explicit, GrantDelta {
        exec: vec!["/bin/sh".into()], ..Default::default()
    }, Ttl::Forever, 0).unwrap();
    assert!(active.active().exec.allow.contains(&"/bin/sh".to_string()));
    assert!(!active.active().exec.allow.contains(&"!/bin/sh".to_string()),
        "probe: derive's inherited pin was discarded before installing the grant");
}

#[cfg(all(feature = "tui", debug_assertions))]
#[test]
#[should_panic(expected = "attempt to add with overflow")]
fn probe_chat_height_overflows_u16() {
    use bee::tui::{app::App, chat::{ChatMessage, Role}, view::view};
    let mut app = App::new(80, 24);
    app.chat.push(ChatMessage::text(Role::User, "x\n".repeat(65_536)));
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| view(&mut app, f)).unwrap();
}
