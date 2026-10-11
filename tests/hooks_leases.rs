//! 024 PR4 (US5) — hooks do what they say (FR-028–FR-034, contracts/hooks.md).
//!
//! Through both loops: a hook that refuses a call stops it before it runs; a lease with a lifetime in
//! model turns expires at the turn start where it runs out, however many calls each turn made; a hook
//! that releases a lease narrows the scope; the MCP tool list refreshes at turn start through the hook
//! mechanism. On a host, narrowing is observed as requested — the lease leaves the active policy and
//! lease-only tools are withdrawn. That the kernel then denies is the VM tier's claim (FR-042).

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::episode::{run_loop, LoopOptions};
use bee::grants::escalate::LoopEscalation;
use bee::grants::{GrantDelta, Ttl};
use bee::hooks::{Flow, LoopHook, StepEvent, StepEventKind};
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Message, ToolSchema, Turn};
use bee::repl::{run_exchange, ReplConfig, ReplEscalation, ReplOutput};
use bee::sandbox::Sandbox;
use bee::tools::{Tool, ToolRegistry, ToolResult};
use bee::turn::ToolRefresh;
use bee_core::{Access, AuditEvent};
use fixtures::*;
use scripted::*;

// ── Hooks ───────────────────────────────────────────────────────────────────────────────────────

/// Refuses every call whose id is `id`.
struct DenyCall(&'static str);

#[async_trait::async_trait]
impl LoopHook for DenyCall {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::BeforeToolCall
    }
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        match ev {
            StepEvent::BeforeToolCall(c) if c.id == self.0 => Flow::Deny("not this one".into()),
            _ => Flow::Continue,
        }
    }
}

/// Before the call with id `id`, proposes read access to `/tmp/leased` and the `give_up` tool — a
/// grant whose only trace in the registry is that tool.
struct GrantOn(&'static str);

#[async_trait::async_trait]
impl LoopHook for GrantOn {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::BeforeToolCall
    }
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        match ev {
            StepEvent::BeforeToolCall(c) if c.id == self.0 => {
                let mut d = GrantDelta {
                    tools: vec!["give_up".into()],
                    ..Default::default()
                };
                d.filesystem.insert("/tmp/leased".into(), Access::Read);
                Flow::Escalate(d)
            }
            _ => Flow::Continue,
        }
    }
}

/// At the start of model turn `turn`, releases lease `id`.
struct ReleaseAt(u32, &'static str);

#[async_trait::async_trait]
impl LoopHook for ReleaseAt {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::TurnStart
    }
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        match ev {
            StepEvent::TurnStart { turn } if *turn == self.0 => Flow::Deescalate(self.1.into()),
            _ => Flow::Continue,
        }
    }
}

// ── Setup ───────────────────────────────────────────────────────────────────────────────────────

fn escalation(hooks: Vec<Box<dyn LoopHook>>, ttl: Ttl) -> LoopEscalation {
    LoopEscalation {
        base: policy(&[]),
        ceiling: policy(&[("/tmp", Access::Write)]),
        hooks,
        consent: RecordingConsent::new(true),
        timeout: Duration::from_secs(5),
        default_ttl: ttl,
    }
}

/// A registry with the scripted tool, and its attempt counter.
fn registry() -> (ToolRegistry, Arc<AtomicU32>, Sandbox) {
    let audit = Arc::new(bee::sandbox::ScriptedAudit::default());
    let sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let tool = ScriptedTool::new(audit, Vec::new());
    let counter = tool.counter();
    let mut r = ToolRegistry::new();
    r.insert(Box::new(tool));
    (r, counter, sb)
}

/// Model turns, each calling `scripted` once per id, then a text turn.
fn script(turns: &[&[&str]]) -> MockModel {
    let mut out: Vec<Turn> = turns
        .iter()
        .map(|ids| {
            let calls: Vec<(&str, &str)> = ids.iter().map(|id| (*id, SCRIPTED)).collect();
            tool_turn(None, &calls)
        })
        .collect();
    out.push(text_turn("done"));
    MockModel::scripted(out)
}

/// The episode's progress lines.
async fn episode(
    model: MockModel,
    esc: LoopEscalation,
    registry: &mut ToolRegistry,
    sb: &mut Sandbox,
    refresh: Option<Arc<dyn ToolRefresh>>,
) -> (bee::EpisodeTranscript, Vec<String>) {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let opts = LoopOptions {
        progress: Some(Box::new(move |l: &str| {
            sink.lock().unwrap().push(l.to_string())
        })),
        escalation: Some(esc),
        tool_refresh: refresh,
        ..LoopOptions::default()
    };
    let t = run_loop(
        &model,
        &scenario("hooks", &[SCRIPTED], 10, 30),
        registry,
        sb,
        &opts,
    )
    .await;
    let lines = lines.lock().unwrap().clone();
    (t, lines)
}

/// Everything a REPL exchange showed, in order: `call <id>` and `info: …`.
#[derive(Default)]
struct Log(Mutex<Vec<String>>);

impl ReplOutput for Log {
    fn assistant_delta(&self, _: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _: &str, _: &serde_json::Value) {}
    fn tool_result(&self, r: &ToolResult, _: &[AuditEvent]) {
        self.0
            .lock()
            .unwrap()
            .push(format!("result: {}", r.content));
    }
    fn error(&self, msg: &str) {
        self.0.lock().unwrap().push(format!("error: {msg}"));
    }
    fn info(&self, msg: &str) {
        self.0.lock().unwrap().push(format!("info: {msg}"));
    }
}

async fn repl(
    model: MockModel,
    config: &ReplConfig,
    registry: &mut ToolRegistry,
    sb: &mut Sandbox,
) -> (bee::repl::ExchangeResult, Conversation, Vec<String>) {
    let mut convo = Conversation::new("test", "");
    let out = Log::default();
    let r = run_exchange(
        "go",
        &model,
        &mut convo,
        registry,
        sb,
        config,
        &out,
        &Arc::new(Mutex::new(VecDeque::new())),
        None,
    )
    .await;
    let log = out.0.lock().unwrap().clone();
    (r, convo, log)
}

/// What the model was told for call `id`.
fn told(convo: &Conversation, id: &str) -> String {
    convo
        .messages
        .iter()
        .find_map(|m| match m {
            Message::ToolResult {
                call_id, content, ..
            } if call_id == id => Some(content.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

// ── (a) A hook that refuses a call stops it ────────────────────────────────────────────────────

#[tokio::test]
async fn a_refused_call_never_runs_in_the_episode() {
    let (mut reg, ran, mut sb) = registry();
    let (t, _) = episode(
        script(&[&["c0"]]),
        escalation(vec![Box::new(DenyCall("c0"))], Ttl::Forever),
        &mut reg,
        &mut sb,
        None,
    )
    .await;
    assert_eq!(ran.load(Ordering::SeqCst), 0, "the tool never ran");
    let call = &t.turns[0].calls[0];
    assert_eq!(call.refused_by_hook.as_deref(), Some("not this one"));
    assert!(call.result.is_error);
    assert!(
        call.result.content.starts_with("refused by hook:"),
        "{}",
        call.result.content
    );
}

#[tokio::test]
async fn a_refused_call_never_runs_in_the_repl() {
    let (mut reg, ran, mut sb) = registry();
    let config = ReplConfig {
        escalation: Some(ReplEscalation::new(escalation(
            vec![Box::new(DenyCall("c0"))],
            Ttl::Forever,
        ))),
        ..ReplConfig::default()
    };
    let (r, convo, _) = repl(script(&[&["c0"]]), &config, &mut reg, &mut sb).await;
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(
        r.turns[0].calls[0].refused_by_hook.as_deref(),
        Some("not this one")
    );
    assert!(told(&convo, "c0").starts_with("refused by hook:"));
}

// ── (b) A lease lives for N model turns, however many calls they make ──────────────────────────

/// Turn 0 one call; turn 1 the granting call; turn 2 three calls; turn 3 one call. A
/// `Ttl::Turns(2)` lease granted in turn 1 expires at the start of turn 3.
fn lease_script() -> MockModel {
    script(&[&["c0"], &["c1"], &["c2", "c3", "c4"], &["c5"]])
}

#[tokio::test]
async fn a_lease_expires_after_two_model_turns_in_the_episode() {
    let (mut reg, _, mut sb) = registry();
    let (_, lines) = episode(
        lease_script(),
        escalation(vec![Box::new(GrantOn("c1"))], Ttl::Turns(2)),
        &mut reg,
        &mut sb,
        None,
    )
    .await;
    let at = |needle: &str| {
        lines
            .iter()
            .position(|l| l == needle)
            .unwrap_or_else(|| panic!("no line {needle:?} in {lines:#?}"))
    };
    let expired = at("  lease expired: g0");
    assert!(
        at("turn 2") < expired,
        "still live through turn 2's three calls"
    );
    assert_eq!(expired + 2, at("turn 3"), "expired at the start of turn 3");
    assert_eq!(lines[expired + 1], "  tools withdrawn: give_up");
    assert!(
        !reg.contains("give_up"),
        "the lease-only tool was withdrawn"
    );
}

#[tokio::test]
async fn a_lease_expires_after_two_model_turns_in_the_repl() {
    let (mut reg, _, mut sb) = registry();
    let config = ReplConfig {
        escalation: Some(ReplEscalation::new(escalation(
            vec![Box::new(GrantOn("c1"))],
            Ttl::Turns(2),
        ))),
        ..ReplConfig::default()
    };
    let (_, _, log) = repl(lease_script(), &config, &mut reg, &mut sb).await;
    let expired = log
        .iter()
        .position(|l| l == "info: capability lease g0 expired")
        .unwrap_or_else(|| panic!("{log:#?}"));
    let results: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("result:"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(results.len(), 6);
    assert!(
        results[4] < expired && expired < results[5],
        "between turn 2's last call and turn 3's"
    );
    assert!(!reg.contains("give_up"));
    let esc = config.escalation.as_ref().unwrap();
    assert!(esc.active.lock().await.leases().is_empty());
}

// ── (c) A hook that releases a lease narrows the scope ──────────────────────────────────────────

#[tokio::test]
async fn a_released_lease_narrows_the_scope() {
    let (mut reg, _, mut sb) = registry();
    let (_, lines) = episode(
        script(&[&["c0"], &["c1"]]),
        escalation(
            vec![Box::new(GrantOn("c0")), Box::new(ReleaseAt(1, "g0"))],
            Ttl::Forever,
        ),
        &mut reg,
        &mut sb,
        None,
    )
    .await;
    assert!(
        lines.iter().any(|l| l == "  lease released: g0"),
        "{lines:#?}"
    );
    assert!(!reg.contains("give_up"));

    let (mut reg, _, mut sb) = registry();
    let config = ReplConfig {
        escalation: Some(ReplEscalation::new(escalation(
            vec![Box::new(GrantOn("c0")), Box::new(ReleaseAt(1, "g0"))],
            Ttl::Forever,
        ))),
        ..ReplConfig::default()
    };
    let (_, _, log) = repl(script(&[&["c0"], &["c1"]]), &config, &mut reg, &mut sb).await;
    assert!(
        log.iter()
            .any(|l| l == "info: capability lease g0 released"),
        "{log:#?}"
    );
    let active = config.escalation.as_ref().unwrap().active.lock().await;
    assert!(active.leases().is_empty());
    assert!(!active.active().filesystem.contains_key("/tmp/leased"));
}

// ── (d) MCP refresh happens at turn start, through the hook mechanism ───────────────────────────

/// A changed tool source: dirty once, and re-registering adds the tool `refreshed`.
struct FakeSource {
    dirty: AtomicBool,
    reregistered: AtomicU32,
}

struct Refreshed;

#[async_trait::async_trait]
impl Tool for Refreshed {
    fn name(&self) -> &'static str {
        "refreshed"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "refreshed".into(),
            description: "registered at turn start".into(),
            parameters: serde_json::json!({ "type": "object" }),
        }
    }
    async fn call(&self, _: serde_json::Value, _: &Sandbox) -> ToolResult {
        ToolResult::ok("refreshed")
    }
}

impl ToolRefresh for FakeSource {
    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::SeqCst)
    }
    fn reregister(&self, registry: &mut ToolRegistry) {
        self.reregistered.fetch_add(1, Ordering::SeqCst);
        registry.insert(Box::new(Refreshed));
    }
}

#[tokio::test]
async fn a_changed_tool_source_is_refreshed_at_turn_start() {
    for loop_kind in ["episode", "repl"] {
        let source = Arc::new(FakeSource {
            dirty: AtomicBool::new(true),
            reregistered: AtomicU32::new(0),
        });
        let model = MockModel::scripted(vec![text_turn("done")]);
        let (mut reg, _, mut sb) = registry();
        let refresh: Arc<dyn ToolRefresh> = source.clone();
        if loop_kind == "episode" {
            episode(
                model,
                escalation(Vec::new(), Ttl::Forever),
                &mut reg,
                &mut sb,
                Some(refresh),
            )
            .await;
        } else {
            let config = ReplConfig {
                tool_refresh: Some(refresh),
                ..ReplConfig::default()
            };
            repl(model, &config, &mut reg, &mut sb).await;
        }
        assert_eq!(source.reregistered.load(Ordering::SeqCst), 1, "{loop_kind}");
        assert!(reg.contains("refreshed"), "{loop_kind}");
    }
}
