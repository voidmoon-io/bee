//! Behavioral regressions for the practical TigerStyle audit.
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
        id: "audit-probe".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "test".into(),
        task: "test".into(),
        turn_limit: 4,
        timeout_secs: 10,
        tools: vec!["bash".into()],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: vec![],
        ceiling_policy_path: None,
        finish: Default::default(),
        lease_turns: None,
        security: Default::default(),
        context: Default::default(),
        stuck: Default::default(),
    }
}

fn call(id: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: "bash".into(),
        arguments: serde_json::json!({"command": "printf audit-probe"}),
    }
}

struct NeverReturns;
#[async_trait::async_trait]
impl Model for NeverReturns {
    fn id(&self) -> &str {
        "audit/pending"
    }
    async fn complete(&self, _: &Conversation, _: &[ToolSchema]) -> Result<Turn, ModelError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn provider_is_bounded_by_episode_deadline() {
    let mut sc = scenario();
    sc.timeout_secs = 1;
    let result = tokio::time::timeout(
        Duration::from_millis(1300),
        run_loop(
            &NeverReturns,
            &sc,
            &mut ToolRegistry::new(),
            &mut Sandbox::host(vec![]),
            &LoopOptions::default(),
        ),
    )
    .await;
    assert_eq!(result.unwrap().status, bee::EpisodeStatus::Timeout);
}

struct RetryLater(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl Model for RetryLater {
    fn id(&self) -> &str {
        "audit/retry"
    }
    async fn complete(&self, _: &Conversation, _: &[ToolSchema]) -> Result<Turn, ModelError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(ModelError::Transient {
            status: 429,
            retry_after: Some(Duration::from_secs(60)),
        })
    }
}

#[tokio::test]
async fn retry_backoff_uses_the_episode_deadline() {
    let mut sc = scenario();
    sc.timeout_secs = 1;
    let model = RetryLater(Default::default());
    let result = run_loop(
        &model,
        &sc,
        &mut ToolRegistry::new(),
        &mut Sandbox::host(vec![]),
        &LoopOptions::default(),
    )
    .await;
    assert_eq!(result.status, bee::EpisodeStatus::Timeout);
    assert_eq!(model.0.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn cancelled_child_cleans_up_descendants() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("survived");
    let ready = tmp.path().join("ready");
    let script = format!(
        "(sleep 1; printf survived > '{}') >/dev/null 2>&1 & touch '{}'; sleep 3",
        marker.display(),
        ready.display()
    );
    let sandbox = Sandbox::host(vec![]);
    let args = vec!["-c".to_string(), script];
    let result = tokio::time::timeout(
        Duration::from_millis(300),
        bee::tools::exec::run_child(&sandbox, "sh", &args, None, 4096),
    )
    .await;
    assert!(ready.exists(), "the shell started before cancellation");
    assert!(result.is_err());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        !marker.exists(),
        "descendant must not run after cancellation"
    );
    assert!(sandbox.check_cleanup().is_ok());
}

struct Hook {
    grant: bool,
}
#[async_trait::async_trait]
impl LoopHook for Hook {
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        if let StepEvent::BeforeToolCall(tc) = ev {
            if !self.grant {
                return Flow::Deny("audit refusal".into());
            }
            if tc.id == "1" {
                return Flow::Escalate(GrantDelta {
                    tools: vec!["bash".into()],
                    ..Default::default()
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
            base: policy.clone(),
            ceiling: policy,
            hooks: vec![Box::new(Hook { grant })],
            operator: bee::operator::Operator::autonomous(Arc::new(bee::operator::NullOutput))
                .with_timeout(Duration::from_secs(1)),
            default_ttl: Ttl::Turns(1),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn deny_hook_prevents_execution() {
    let sc = scenario();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("must-not-exist");
    let denied = ToolCall {
        arguments: serde_json::json!({"command": format!("touch '{}'", marker.display())}),
        ..call("1")
    };
    let model = MockModel::scripted(vec![Turn::calls(vec![denied]), Turn::text("done")]);
    let transcript = run_loop(
        &model,
        &sc,
        &mut registry_for(&sc.tools, None),
        &mut Sandbox::host(vec![]),
        &options(false),
    )
    .await;
    let result = &transcript.turns[0].calls[0].result;
    assert!(result.is_error);
    assert_eq!(
        transcript.turns[0].calls[0].refused_by_hook.as_deref(),
        Some("audit refusal")
    );
    assert!(result.content.contains("the tool did not run"));
    assert!(!marker.exists());
}

#[tokio::test]
async fn one_turn_grant_expires_before_next_turn() {
    let sc = scenario();
    let model = MockModel::scripted(vec![
        Turn::calls(vec![call("1")]),
        Turn::calls(vec![call("2")]),
        Turn::text("done"),
    ]);
    let mut registry = ToolRegistry::new();
    let transcript = run_loop(
        &model,
        &sc,
        &mut registry,
        &mut Sandbox::host(vec![]),
        &options(true),
    )
    .await;
    assert!(!transcript.turns[0].calls[0].result.is_error);
    assert!(transcript.turns[1].calls[0].result.is_error);
    assert!(!registry.contains("bash"));
}

#[cfg(feature = "findings")]
#[test]
fn ledger_rejects_project_symlink() {
    use bee::findings::{record, Finding, FindingSource, Ledger, Sighting};
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("outside-ledger");
    std::fs::write(&target, "sentinel\n").unwrap();
    let ledger = Ledger::at(tmp.path().join("project/.bee/findings"));
    ledger.ensure_dir().unwrap();
    std::os::unix::fs::symlink(&target, ledger.log_path()).unwrap();
    let finding = Finding::new(
        "a.rs".into(),
        "test".into(),
        "test".into(),
        "audit evidence".into(),
        FindingSource::Tool("audit".into()),
    );
    assert!(record(&ledger, finding, Sighting::now("audit")).is_err());
    let body = std::fs::read_to_string(&target).unwrap();
    assert_eq!(body, "sentinel\n");
}

#[test]
fn grant_preserves_inherited_executable_pin() {
    use bee::grants::{ActivePolicy, GrantOrigin};
    let base = bee_core::Policy::from_toml(
        "[policy]\nname='audit'\n[policy.exec]\nallow=['!/bin/true']\n",
    )
    .unwrap();
    let mut ceiling = base.clone();
    ceiling.exec.allow.push("!/bin/sh".into());
    let mut active = ActivePolicy::new(base, ceiling).unwrap();
    active
        .try_apply(
            GrantOrigin::Explicit,
            GrantDelta {
                exec: vec!["/bin/sh".into()],
                ..Default::default()
            },
            Ttl::Forever,
            0,
        )
        .unwrap();
    assert!(!active.active().exec.allow.contains(&"/bin/sh".to_string()));
    assert!(active.active().exec.allow.contains(&"!/bin/sh".to_string()));
}

#[tokio::test]
async fn noisy_both_pipes_are_drained_and_bounded() {
    let result = bee::tools::exec::run_child(
        &Sandbox::host(vec![]),
        "sh",
        &[
            "-c".into(),
            "head -c 200000 /dev/zero & head -c 200000 /dev/zero >&2; wait".into(),
        ],
        None,
        4096,
    )
    .await;
    assert!(!result.is_error, "{}", result.content);
    assert!(result.truncated);
    assert!(result.content.len() < 4200);
    assert!(result.original_len.unwrap() >= 400000);
}

#[tokio::test]
async fn output_bounds_include_decoding_and_early_stdin_close() {
    let sandbox = Sandbox::host(vec![]);
    for (script, truncated) in [
        ("printf 1234", false),
        ("printf 12345", true),
        (r"printf '\377\377\377\377'", true),
    ] {
        let result = bee::tools::exec::run_child(
            &sandbox,
            "sh",
            &["-c".into(), script.into()],
            Some(vec![0; 65536]),
            4,
        )
        .await;
        assert!(!result.is_error, "{}", result.content);
        assert_eq!(result.truncated, truncated, "{script}");
        assert_eq!(result.content.contains("[truncated:"), truncated);
        assert!(result.content.len() < 100);
    }
    assert!(sandbox.check_cleanup().is_ok());
}

#[cfg(feature = "scanners")]
#[tokio::test]
async fn oversized_scanner_protocol_is_an_error() {
    let result = bee::tools::exec::run_child_timed(
        &Sandbox::host(vec![]),
        "head",
        &["-c".into(), "9000000".into(), "/dev/zero".into()],
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(
        result,
        Err(bee::tools::exec::ChildError::OutputTooLarge)
    ));
}

#[cfg(feature = "findings")]
#[test]
fn ledger_rejects_parent_symlinks_and_hardlinks() {
    use bee::findings::Ledger;
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, tmp.path().join("project")).unwrap();
    assert!(Ledger::at(tmp.path().join("project/findings"))
        .ensure_dir()
        .is_err());
    assert!(!outside.join("findings").exists());
    let ledger = Ledger::at(tmp.path().join("safe"));
    ledger.ensure_dir().unwrap();
    let target = outside.join("sentinel");
    std::fs::write(&target, "sentinel\n").unwrap();
    std::fs::hard_link(&target, ledger.log_path()).unwrap();
    assert!(ledger.events().is_err());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "sentinel\n");
}

#[cfg(feature = "tui")]
#[test]
fn chat_scrolls_past_u16_rows() {
    use bee::tui::{
        app::App,
        chat::{ChatMessage, Role},
        view::view,
    };
    let mut app = App::new(80, 24);
    app.chat
        .push(ChatMessage::text(Role::User, "x\n".repeat(65_536)));
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    app.chat.push(ChatMessage::text(Role::User, "final-marker"));
    terminal.draw(|f| view(&mut app, f)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("final-marker"));
}

#[cfg(feature = "enforce")]
mod kernel {
    use super::*;
    use bee_core::{Access, Policy};
    use bee_userspace::{EnforcementPlan, Engine, ScopeMode, SystemResolver};

    fn sandbox(policy: &Policy) -> Sandbox {
        let plan = EnforcementPlan::prepare(
            &policy.compile(&SystemResolver::current()).unwrap(),
            ScopeMode::Enforce,
        )
        .unwrap();
        let mut engine = Engine::init().expect("BPF-LSM kernel and root required");
        let scope = engine
            .create_scope(
                &format!("hardening-{}", std::process::id()),
                bee_userspace::cgroup::DEFAULT_PARENT,
                &plan,
            )
            .unwrap();
        let reader = engine.take_audit_reader("hardening").unwrap();
        Sandbox::enforced(engine, scope, reader, vec![])
    }

    fn policy() -> Policy {
        Policy::from_toml("[policy]\nname='hardening'\n").unwrap()
    }

    #[tokio::test]
    #[ignore = "requires root and a BPF-LSM kernel; run serially in the VM"]
    async fn attenuated_default_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("project");
        std::fs::create_dir(&allowed).unwrap();
        let mut parent = policy();
        parent
            .filesystem
            .insert(allowed.to_str().unwrap().into(), Access::Write);
        let mut request = parent.clone();
        request
            .filesystem
            .insert(allowed.to_str().unwrap().into(), Access::Read);
        let child = parent.derive(request).unwrap();
        let sandbox = sandbox(&child);
        let outside = dir.path().join("outside");
        let result = bee::tools::exec::run_child(
            &sandbox,
            "sh",
            &[
                "-c".into(),
                format!("printf forbidden > '{}'", outside.display()),
            ],
            None,
            4096,
        )
        .await;
        assert!(result.is_error, "{}", result.content);
        assert_ne!(
            std::fs::read_to_string(outside).unwrap_or_default(),
            "forbidden"
        );
        sandbox.teardown().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires root and a BPF-LSM kernel; run serially in the VM"]
    async fn cancellation_removes_setsid_descendants_and_preserves_services() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("survived");
        let ready = dir.path().join("ready");
        let sandbox = sandbox(&policy());
        let mut service = sandbox
            .tool_command("sleep", &["30".into()])
            .unwrap()
            .spawn()
            .unwrap();
        let args = vec![
            "-c".into(),
            format!(
                "setsid sh -c 'sleep 1; echo survived > {}' >/dev/null 2>&1 & touch {}; sleep 5",
                marker.display(),
                ready.display()
            ),
        ];
        let canceled = tokio::time::timeout(
            Duration::from_millis(300),
            bee::tools::exec::run_child(&sandbox, "sh", &args, None, 4096),
        );
        let sibling_args = vec!["-c".into(), "sleep 0.5; printf sibling".into()];
        let sibling = bee::tools::exec::run_child(&sandbox, "sh", &sibling_args, None, 4096);
        let (canceled, sibling) = tokio::join!(canceled, sibling);
        assert!(ready.exists());
        assert!(canceled.is_err());
        assert_eq!(sibling.content, "sibling");
        assert!(service.try_wait().unwrap().is_none());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!marker.exists());
        assert!(sandbox.check_cleanup().is_ok());
        if let Sandbox::Enforced(scope) = &sandbox {
            assert!(!std::fs::read_dir(&scope.scope.path).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("call-")));
        }
        service.kill().unwrap();
        service.wait().unwrap();
        sandbox.teardown().unwrap();
    }

    struct LeaseHook {
        path: String,
        service_command: std::sync::Mutex<Option<std::process::Command>>,
        service: std::sync::Mutex<Option<std::process::Child>>,
    }
    impl Drop for LeaseHook {
        fn drop(&mut self) {
            if let Some(mut child) = self.service.get_mut().unwrap().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    #[async_trait::async_trait]
    impl LoopHook for LeaseHook {
        async fn on_event(&self, event: &StepEvent<'_>) -> Flow {
            match event {
                StepEvent::BeforeToolCall(call) if call.id == "1" => Flow::Escalate(GrantDelta {
                    filesystem: [(self.path.clone(), Access::Write)].into(),
                    ..Default::default()
                }),
                StepEvent::AfterToolResult { call, .. } if call.id == "1" => {
                    if let Some(mut cmd) = self.service_command.lock().unwrap().take() {
                        *self.service.lock().unwrap() = Some(cmd.spawn().unwrap());
                    }
                    Flow::Continue
                }
                _ => Flow::Continue,
            }
        }
    }

    async fn finite_lease(fail_narrowing: bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let mut base = policy();
        base.filesystem.insert(path.clone(), Access::Read);
        let mut ceiling = base.clone();
        ceiling.filesystem.insert(path.clone(), Access::Write);
        let mut sandbox = sandbox(&base);
        let service_command =
            fail_narrowing.then(|| sandbox.tool_command("sleep", &["30".into()]).unwrap());
        let opts = LoopOptions {
            escalation: Some(LoopEscalation {
                base,
                ceiling,
                hooks: vec![Box::new(LeaseHook {
                    path: path.clone(),
                    service_command: std::sync::Mutex::new(service_command),
                    service: Default::default(),
                })],
                operator: bee::operator::Operator::autonomous(Arc::new(bee::operator::NullOutput))
                    .with_timeout(Duration::from_secs(2)),
                default_ttl: Ttl::Turns(1),
            }),
            ..Default::default()
        };
        let make_call = |id: &str| ToolCall {
            id: id.into(),
            name: "bash".into(),
            arguments: serde_json::json!({"command": format!("printf data > '{path}/{id}'")}),
        };
        let model = MockModel::scripted(vec![
            Turn::calls(vec![make_call("1")]),
            Turn::calls(vec![make_call("2")]),
            Turn::text("done"),
        ]);
        let result = run_loop(
            &model,
            &scenario(),
            &mut registry_for(&["bash".into()], None),
            &mut sandbox,
            &opts,
        )
        .await;
        assert_eq!(
            std::fs::read_to_string(dir.path().join("1")).unwrap(),
            "data"
        );
        assert_ne!(
            std::fs::read_to_string(dir.path().join("2")).unwrap_or_default(),
            "data"
        );
        if fail_narrowing {
            assert!(
                matches!(result.status, bee::EpisodeStatus::Terminated { .. }),
                "{:?}",
                result.status
            );
            assert!(sandbox.check_cleanup().is_err());
        } else {
            assert_eq!(result.status, bee::EpisodeStatus::Completed);
            assert!(result.turns[1].calls[0].result.is_error);
        }
        drop(opts);
        sandbox.teardown().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires root and a BPF-LSM kernel; run serially in the VM"]
    async fn finite_policy_lease_narrows_in_kernel() {
        finite_lease(false).await;
    }

    #[tokio::test]
    #[ignore = "requires root and a BPF-LSM kernel; run serially in the VM"]
    async fn failed_mandatory_narrowing_stops_execution() {
        finite_lease(true).await;
    }

    #[tokio::test]
    #[ignore = "requires root and a BPF-LSM kernel; run serially in the VM"]
    async fn granted_executable_keeps_its_inode_pin() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image");
        std::fs::copy("/usr/bin/true", &image).unwrap();
        let mut base = policy();
        base.exec.allow.push("!/usr/bin/true".into());
        let mut ceiling = base.clone();
        ceiling.exec.allow.push(format!("!{}", image.display()));
        let mut sandbox = sandbox(&base);
        let mut active = bee::grants::ActivePolicy::new(base, ceiling).unwrap();
        let outcome = bee::grants::escalate::escalate(
            &mut active,
            bee::grants::GrantOrigin::Explicit,
            GrantDelta {
                exec: vec![image.to_str().unwrap().into()],
                ..Default::default()
            },
            Ttl::Forever,
            0,
            &bee::operator::Operator::autonomous(Arc::new(bee::operator::NullOutput)),
            &mut sandbox,
            &mut ToolRegistry::new(),
        )
        .await;
        assert!(outcome.is_granted(), "{outcome:?}");
        assert!(
            !bee::tools::exec::run_child(&sandbox, image.to_str().unwrap(), &[], None, 4096)
                .await
                .is_error
        );
        std::fs::rename(&image, dir.path().join("old-image")).unwrap();
        std::fs::copy("/usr/bin/true", &image).unwrap();
        assert!(
            bee::tools::exec::run_child(&sandbox, image.to_str().unwrap(), &[], None, 4096)
                .await
                .is_error
        );
        sandbox.teardown().unwrap();
    }
}

struct QuietOutput;
impl bee::repl::ReplOutput for QuietOutput {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, _: &bee::tools::ToolResult, _: &[bee_core::AuditEvent]) {}
    fn error(&self, _: &str) {}
    fn info(&self, _: &str) {}
}

#[tokio::test]
async fn repl_denial_and_expiry_match_headless_behavior() {
    for grant in [false, true] {
        let config = bee::repl::ReplConfig {
            escalation: Some(
                bee::repl::ReplEscalation::new(options(grant).escalation.unwrap()).unwrap(),
            ),
            ..Default::default()
        };
        let mut registry = if grant {
            ToolRegistry::new()
        } else {
            registry_for(&["bash".into()], None)
        };
        let model = MockModel::scripted(vec![
            Turn::calls(vec![call("1"), call("same-turn")]),
            Turn::calls(vec![call("2")]),
            Turn::text("done"),
        ]);
        let result = bee::repl::run_exchange(
            "run",
            &model,
            &mut Conversation::new("test", "test"),
            &mut registry,
            &mut Sandbox::host(vec![]),
            &config,
            &QuietOutput,
            &Default::default(),
            None,
        )
        .await;
        assert_eq!(result.turns[0].calls[0].result.is_error, !grant);
        assert_eq!(result.turns[0].calls[1].result.is_error, !grant);
        assert!(result.turns[1].calls[0].result.is_error);
        if grant {
            assert!(!registry.contains("bash"));
        }
    }

    let config = bee::repl::ReplConfig {
        agent_turn_budget: 1,
        escalation: Some(
            bee::repl::ReplEscalation::new(options(true).escalation.unwrap()).unwrap(),
        ),
        ..Default::default()
    };
    let mut registry = ToolRegistry::new();
    let mut sandbox = Sandbox::host(vec![]);
    let mut conversation = Conversation::new("test", "test");
    let model = MockModel::scripted(vec![
        Turn::calls(vec![call("1")]),
        Turn::calls(vec![call("2")]),
    ]);
    for expired in [false, true] {
        let result = bee::repl::run_exchange(
            "run",
            &model,
            &mut conversation,
            &mut registry,
            &mut sandbox,
            &config,
            &QuietOutput,
            &Default::default(),
            None,
        )
        .await;
        assert_eq!(result.turns[0].calls[0].result.is_error, expired);
    }
    assert!(
        !registry.contains("bash"),
        "a new exchange must not reset the lease clock"
    );
}

struct Terminate;
#[async_trait::async_trait]
impl LoopHook for Terminate {
    async fn on_event(&self, event: &StepEvent<'_>) -> Flow {
        if matches!(event, StepEvent::BeforeToolCall(_)) {
            Flow::Terminate("stop here".into())
        } else {
            Flow::Continue
        }
    }
}

#[tokio::test]
async fn termination_never_dispatches_the_tool() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("must-not-exist");
    let mut opts = options(false);
    opts.escalation.as_mut().unwrap().hooks = vec![Box::new(Terminate)];
    let model = MockModel::scripted(vec![Turn::calls(vec![ToolCall {
        arguments: serde_json::json!({"command": format!("touch '{}'", marker.display())}),
        ..call("1")
    }])]);
    let result = run_loop(
        &model,
        &scenario(),
        &mut registry_for(&["bash".into()], None),
        &mut Sandbox::host(vec![]),
        &opts,
    )
    .await;
    assert!(matches!(
        result.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert!(!marker.exists());
}

#[cfg(feature = "findings")]
#[test]
fn concurrent_batches_publish_the_complete_ledger() {
    use bee::findings::{fold, record_batch, Finding, FindingSource, Ledger, Sighting, View};
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::at(dir.path());
    std::thread::scope(|scope| {
        for batch in 0..4 {
            let ledger = &ledger;
            scope.spawn(move || {
                let records = (0..50)
                    .map(|n| {
                        (
                            Finding::new(
                                format!("{batch}/{n}.rs"),
                                "test".into(),
                                "finding".into(),
                                "evidence".into(),
                                FindingSource::Tool("fixture".into()),
                            ),
                            Sighting::now("batch"),
                        )
                    })
                    .collect();
                assert!(record_batch(ledger, records)
                    .unwrap()
                    .into_iter()
                    .all(|r| r.is_ok()));
            });
        }
    });
    let view = fold(&ledger).unwrap();
    let cache: View = serde_json::from_slice(&std::fs::read(ledger.view_path()).unwrap()).unwrap();
    assert_eq!(view.findings.len(), 200);
    assert_eq!(cache.findings.len(), view.findings.len());
    assert_eq!(cache.skipped, 0);
}

#[cfg(feature = "findings")]
#[test]
#[ignore = "manual persistence measurement; set BEE_LEDGER_BENCH_BASELINE=1 for repeated single writes"]
fn measure_ledger_batch() {
    use bee::findings::{record, record_batch, Finding, FindingSource, Ledger, Sighting};
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::at(dir.path());
    let record_for = |n: usize| {
        (
            Finding::new(
                format!("src/{n}.rs"),
                "test".into(),
                "observation".into(),
                "evidence".repeat(30),
                FindingSource::Tool("benchmark".into()),
            ),
            Sighting::now("benchmark"),
        )
    };
    for chunk in 0..10 {
        assert!(record_batch(
            &ledger,
            (chunk * 200..(chunk + 1) * 200).map(record_for).collect()
        )
        .unwrap()
        .iter()
        .all(Result::is_ok));
    }
    let start = std::time::Instant::now();
    let baseline = std::env::var_os("BEE_LEDGER_BENCH_BASELINE").is_some();
    if baseline {
        for n in 2000..2200 {
            let (f, s) = record_for(n);
            record(&ledger, f, s).unwrap();
        }
    } else {
        assert!(
            record_batch(&ledger, (2000..2200).map(record_for).collect())
                .unwrap()
                .iter()
                .all(Result::is_ok)
        );
    }
    eprintln!(
        "ledger_measurement existing=2000 added=200 view_refreshes={} elapsed_ms={}",
        if baseline { 200 } else { 1 },
        start.elapsed().as_millis()
    );
    assert_eq!(bee::findings::fold(&ledger).unwrap().findings.len(), 2200);
}

struct NeverConsent;
#[async_trait::async_trait]
impl bee::operator::Consent for NeverConsent {
    async fn decide(&self, _: &bee::operator::ConsentRequest) -> bee::skills::Decision {
        std::future::pending().await
    }
}

#[tokio::test]
async fn episode_deadline_includes_consent() {
    let mut scenario = scenario();
    scenario.timeout_secs = 1;
    let mut opts = options(true);
    let escalation = opts.escalation.as_mut().unwrap();
    escalation.operator = bee::operator::Operator::with_consent(
        bee::operator::OperatorKind::Autonomous,
        Arc::new(NeverConsent),
    )
    .with_timeout(Duration::from_secs(30));
    let model = MockModel::scripted(vec![Turn::calls(vec![call("1")])]);
    let mut registry = ToolRegistry::new();
    let result = tokio::time::timeout(
        Duration::from_millis(1300),
        run_loop(
            &model,
            &scenario,
            &mut registry,
            &mut Sandbox::host(vec![]),
            &opts,
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.status, bee::EpisodeStatus::Timeout);
    assert!(!registry.contains("bash"));
}
