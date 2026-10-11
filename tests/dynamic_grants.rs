//! Mid-session capability grants through the REPL exchange loop (007-dynamic-grants).
//!
//! These are the tests that only became writable once `run_exchange` dispatched `StepEvent`s (T009).
//! Before that, escalation ran in `run_loop` only — where 006-skills' startup pass has already
//! resolved every discovered skill's `requires` against the same ceiling with the same sink, so the
//! proactive hook could not grant anything the preload had not. An episode is pre-authorized by its
//! ceiling *file*; an interactive session has an operator in front of it, which is the whole reason
//! a capability asked for mid-session is a question rather than a formality.
//!
//! What is covered here is therefore the **proactive** cycle (US2) end to end: a grant that widens,
//! a grant that is refused unpromptably, a grant that is already held and must not nag, and a sink
//! that never answers.
//!
//! **Not covered here:** the reactive cycle (US1). It triggers on a kernel denial, and a plain
//! `Sandbox::Host` has no kernel, so its `drain_audit` returns nothing. Its enforcement coverage is
//! the VM matrix (`reload-widen-allow`, `reload-beyond-ceiling`; tasks T018), plus the unit tests on
//! `escalate()` itself.
//!
//! This file once recorded a decision *not* to give the host sandbox a replay seam, because it
//! would put a test seam in the type that mediates enforcement. 024-session-core revised that
//! (research R1, plan Complexity Tracking): the seam now exists as `Sandbox::host_scripted`, behind
//! the test-only `test-support` feature, which no shipping build enables (guarded by
//! `tests/test_support_absent.rs`). Host coverage of the reactive retry path lives in
//! `tests/call_characterization.rs` and, from PR 3, `tests/call_lifecycle.rs`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::grants::escalate::{DenialEscalationHook, LoopEscalation, SkillEscalationHook};
use bee::grants::Ttl;
use bee::operator::ConsentRequest;
use bee::provider::mock_model::MockModel;
use bee::provider::{Conversation, Model, ToolCall, Turn};
use bee::repl::{run_exchange, ReplConfig, ReplEscalation, ReplOutput};
use bee::skills::SkillRegistry;
use bee::tools::{ToolRegistry, ToolResult};
use bee_core::{Access, AuditEvent, Mode, Policy};

// ── Fixtures ────────────────────────────────────────────────────────────────────────────────────

/// Collects what the user would have seen. Only the lines the assertions read are kept.
#[derive(Default)]
struct Out {
    lines: Mutex<Vec<String>>,
}

impl Out {
    fn dump(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }
    fn contains(&self, needle: &str) -> bool {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains(needle))
    }
}

impl ReplOutput for Out {
    fn assistant_delta(&self, _chunk: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, name: &str, args: &serde_json::Value) {
        self.lines
            .lock()
            .unwrap()
            .push(format!("CALL {name} {args}"));
    }
    fn tool_result(&self, result: &ToolResult, _audit: &[AuditEvent]) {
        self.lines
            .lock()
            .unwrap()
            .push(format!("RESULT err={} {}", result.is_error, result.content));
    }
    fn error(&self, msg: &str) {
        self.lines.lock().unwrap().push(format!("ERROR {msg}"));
    }
    fn info(&self, msg: &str) {
        self.lines.lock().unwrap().push(format!("INFO {msg}"));
    }
}

/// A consent sink that records how many times it was asked. The count is the assertion in every
/// "must not prompt" case — a refusal that still prompted has failed even though its outcome reads
/// correct.
struct SpySink {
    asked: Arc<AtomicU32>,
    answer: bool,
}

#[async_trait::async_trait]
impl bee::operator::Consent for SpySink {
    async fn decide(&self, _r: &ConsentRequest) -> bee::skills::Decision {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.answer {
            bee::skills::Decision::Granted
        } else {
            bee::skills::Decision::Denied
        }
    }
}

/// A sink that never answers — the out-of-band approver who walked away (US3).
struct NeverAnswers;

#[async_trait::async_trait]
impl bee::operator::Consent for NeverAnswers {
    async fn decide(&self, _r: &ConsentRequest) -> bee::skills::Decision {
        // Far longer than any timeout under test; the timeout must fire, not this.
        tokio::time::sleep(Duration::from_secs(3600)).await;
        bee::skills::Decision::Granted
    }
}

fn policy(name: &str, fs: &[(&str, Access)]) -> Policy {
    let mut p = Policy {
        name: name.to_string(),
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

/// Write a skills root holding one `builder` skill with the given `requires:` block.
fn skills_root(tag: &str, requires_yaml: &str) -> SkillRegistry {
    let root = std::env::temp_dir().join(format!("bee-dyn-{}-{tag}", std::process::id()));
    let d = root.join("builder");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("SKILL.md"),
        format!("---\nname: builder\ndescription: builds things\n{requires_yaml}---\nUse bash.\n"),
    )
    .unwrap();
    SkillRegistry::discover(&[root])
}

fn skill_call(id: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: "skill".into(),
        arguments: serde_json::json!({ "name": "builder" }),
    }
}

fn bash_call(id: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: "bash".into(),
        arguments: serde_json::json!({ "command": "echo granted" }),
    }
}

struct Fixture {
    config: ReplConfig,
    /// Tools registered before the exchange begins — deliberately *not* including what the skill
    /// asks for, so a pass proves the grant did it.
    registry: ToolRegistry,
}

/// Build a session whose base is `base`, ceiling `ceiling`, with one capability-requesting skill.
fn fixture(
    base: Policy,
    ceiling: Policy,
    requires_yaml: &str,
    consent: Arc<dyn bee::operator::Consent>,
    timeout: Duration,
    tag: &str,
) -> Fixture {
    let skills = Arc::new(skills_root(tag, requires_yaml));
    let hooks: Vec<Box<dyn bee::hooks::LoopHook>> = vec![
        Box::new(DenialEscalationHook { enabled: true }),
        Box::new(SkillEscalationHook::new(skills.clone())),
    ];
    let escalation = ReplEscalation::new(LoopEscalation {
        base,
        ceiling,
        hooks,
        operator: bee::operator::Operator::with_consent(
            bee::operator::OperatorKind::Interactive,
            consent,
        )
        .with_timeout(timeout),
        default_ttl: Ttl::Forever,
    });

    // Only the `skill` tool starts registered. `bash` must arrive via the grant or not at all.
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(bee::tools::skill::SkillTool::new(skills.clone())));

    Fixture {
        config: ReplConfig {
            skills,
            escalation: Some(escalation),
            ..ReplConfig::default()
        },
        registry,
    }
}

async fn exchange(f: &mut Fixture, model: &dyn Model) -> Out {
    let mut sb = bee::Sandbox::host(Vec::new());
    let mut convo = Conversation {
        system: f.config.system_prompt.clone(),
        messages: Vec::new(),
    };
    let out = Out::default();
    let steering = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    run_exchange(
        "go",
        model,
        &mut convo,
        &mut f.registry,
        &mut sb,
        &f.config,
        &out,
        &steering,
        None,
    )
    .await;
    out
}

/// Load the skill, then use the tool it asked for, then wrap up.
fn skill_then_bash() -> MockModel {
    MockModel::scripted(vec![
        Turn::calls(vec![skill_call("1")]),
        Turn::calls(vec![bash_call("2")]),
        Turn::text("done"),
    ])
}

// ── US2 · a mid-session grant widens the session ────────────────────────────────────────────────

/// The grant a skill asks for mid-session takes effect for the calls that follow it.
///
/// `bash` is not registered when the exchange starts. If it runs, the only thing that can have
/// registered it is the escalation cycle the `skill` call triggered.
#[tokio::test]
async fn a_skill_grant_registers_its_tool_for_later_calls() {
    let asked = Arc::new(AtomicU32::new(0));
    let mut f = fixture(
        policy("base", &[]),
        policy("ceil", &[("/tmp", Access::Write)]),
        "requires:\n  tools: [bash]\n",
        Arc::new(SpySink {
            asked: asked.clone(),
            answer: true,
        }),
        Duration::from_secs(5),
        "grant",
    );

    let out = exchange(&mut f, &skill_then_bash()).await;

    assert!(
        out.contains("granted"),
        "bash should have run under the grant: {}",
        out.dump()
    );
    assert!(
        !out.contains("unknown tool"),
        "bash was never registered: {}",
        out.dump()
    );
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "the operator is asked exactly once for a genuinely new capability"
    );
}

/// A capability already held is not asked for again.
///
/// This is the property that makes an interactive consent sink usable at all: the skill's `requires`
/// block is re-proposed on *every* `skill` call, so without the already-held check the operator is
/// prompted once per call for something they approved the first time. The sink must never be
/// consulted, and — because nothing changed — no "capability granted" line is printed either.
#[tokio::test]
async fn an_already_held_capability_is_never_asked_for_again() {
    let asked = Arc::new(AtomicU32::new(0));
    let mut f = fixture(
        policy("base", &[]),
        policy("ceil", &[("/tmp", Access::Write)]),
        "requires:\n  tools: [bash]\n",
        Arc::new(SpySink {
            asked: asked.clone(),
            answer: true,
        }),
        Duration::from_secs(5),
        "held",
    );
    // Pre-register the tool: this session already has the capability the skill will ask for.
    f.registry.register("bash").unwrap();

    let model = MockModel::scripted(vec![
        Turn::calls(vec![skill_call("1")]),
        Turn::calls(vec![skill_call("2")]),
        Turn::calls(vec![bash_call("3")]),
        Turn::text("done"),
    ]);
    let out = exchange(&mut f, &model).await;

    assert_eq!(
        asked.load(Ordering::SeqCst),
        0,
        "consent must not be consulted for a capability already held: {}",
        out.dump()
    );
    assert!(
        !out.contains("capability granted"),
        "nothing changed, so nothing should be announced: {}",
        out.dump()
    );
    assert!(out.contains("granted"), "bash still runs: {}", out.dump());
}

// ── US2 · the unpromptable bound ────────────────────────────────────────────────────────────────

/// Beyond the ceiling is refused without consulting the operator (SC-002).
///
/// The ceiling is attenuation, not preference — there is no answer the operator could give that
/// would make the grant legal, so asking would be theatre that trains them to approve. Base equals
/// ceiling here, so `/etc: write` is unreachable by construction.
#[tokio::test]
async fn a_beyond_ceiling_grant_is_refused_without_consulting_consent() {
    let asked = Arc::new(AtomicU32::new(0));
    let base = policy("tight", &[]);
    let mut f = fixture(
        base.clone(),
        base,
        "requires:\n  tools: [bash]\n  filesystem:\n    /etc: write\n",
        Arc::new(SpySink {
            asked: asked.clone(),
            answer: true,
        }),
        Duration::from_secs(5),
        "greedy",
    );

    let out = exchange(&mut f, &skill_then_bash()).await;

    assert_eq!(
        asked.load(Ordering::SeqCst),
        0,
        "a beyond-ceiling request must never reach the operator: {}",
        out.dump()
    );
    assert!(
        out.contains("exceeds capability ceiling"),
        "the refusal must say why: {}",
        out.dump()
    );
    // The refusal is total: the tool bundled with the over-reaching request is withheld too.
    assert!(
        out.contains("unknown tool"),
        "bash must not be registered by a refused grant: {}",
        out.dump()
    );
}

/// A refused grant leaves the session exactly as it was — no lease, no half-applied delta.
#[tokio::test]
async fn a_grant_the_operator_denies_withholds_the_tool() {
    let asked = Arc::new(AtomicU32::new(0));
    let mut f = fixture(
        policy("base", &[]),
        policy("ceil", &[("/tmp", Access::Write)]),
        "requires:\n  tools: [bash]\n",
        Arc::new(SpySink {
            asked: asked.clone(),
            answer: false,
        }),
        Duration::from_secs(5),
        "denied",
    );

    let out = exchange(&mut f, &skill_then_bash()).await;

    assert_eq!(asked.load(Ordering::SeqCst), 1, "the operator was asked");
    assert!(
        out.contains("denied by operator"),
        "the refusal is reported: {}",
        out.dump()
    );
    assert!(
        out.contains("unknown tool"),
        "a denied grant registers nothing: {}",
        out.dump()
    );
}

// ── US3 · an approver who never answers ─────────────────────────────────────────────────────────

/// A consent sink that never resolves times out and denies, and the session keeps going (SC-003).
///
/// Fail-closed: the elapse refuses, not grants and not hangs, and says it timed out (024 T055). The assertion that
/// matters as much as the outcome is that the test finishes at all.
#[tokio::test]
async fn a_consent_sink_that_never_answers_times_out_and_denies() {
    let mut f = fixture(
        policy("base", &[]),
        policy("ceil", &[("/tmp", Access::Write)]),
        "requires:\n  tools: [bash]\n",
        Arc::new(NeverAnswers),
        Duration::from_millis(150),
        "timeout",
    );

    let started = std::time::Instant::now();
    let out = exchange(&mut f, &skill_then_bash()).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "the exchange hung waiting on consent ({elapsed:?})"
    );
    assert!(
        out.contains("consent timed out"),
        "an elapsed timeout is a refusal, reported as a timeout and not as the operator's no: {}",
        out.dump()
    );
    assert!(
        out.contains("unknown tool"),
        "nothing is granted on a timeout: {}",
        out.dump()
    );
}

// ── 019-http-intercept P2: what the consent prompt shows, and what a denial asks for ────────────
//
// Two verified 007 defects (research R13). A `GrantDelta.net` or `.exec` entry was approved without
// ever being displayed, because `GrantRequest` carried only tools and filesystem. And reactive
// escalation matched op names the kernel never emits (`socket_connect`, `bprm_check_security`),
// so a network or exec denial produced an empty delta.

use bee::grants::escalate::{delta_from_denial, escalate};
use bee::grants::{ActivePolicy, GrantDelta, GrantOrigin};
use bee::sandbox::Sandbox;

/// A sink that records the console rendering of every request it is asked about, then grants.
#[derive(Default)]
struct RenderingSink {
    seen: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl bee::operator::Consent for RenderingSink {
    async fn decide(&self, r: &ConsentRequest) -> bee::skills::Decision {
        self.seen.lock().unwrap().push(r.render_lines().join("\n"));
        bee::skills::Decision::Granted
    }
}

/// A ceiling wide enough that every delta below is within it, so consent is always consulted.
fn wide_ceiling() -> Policy {
    let mut p = policy("ceil", &[("/tmp", Access::Write)]);
    p.network.allow = vec!["1.2.3.4:443".into(), "10.0.0.5:443".into()];
    p.exec.allow = vec!["/usr/bin/x".into(), "/bin/true".into()];
    p.http = Some(bee_core::HttpPolicy {
        targets: vec![bee_core::HostPort::try_from("app.test:443".to_string()).unwrap()],
        ..Default::default()
    });
    p
}

/// Run `delta` through the real escalation cycle and return what the operator was shown.
async fn shown_for(delta: GrantDelta) -> String {
    let mut ap = ActivePolicy::new(policy("base", &[]), wide_ceiling());
    let mut reg = ToolRegistry::new();
    let mut sb = Sandbox::host(Vec::new());
    let sink = Arc::new(RenderingSink::default());
    let operator = bee::operator::Operator::with_consent(
        bee::operator::OperatorKind::Interactive,
        sink.clone(),
    );
    let out = escalate(
        &mut ap,
        GrantOrigin::Explicit,
        delta,
        Ttl::Turns(1),
        0,
        &operator,
        &mut sb,
        &mut reg,
    )
    .await;
    // What matters here is what the operator was shown. (An `http_targets` grant is then refused
    // in this proxy-less host sandbox — the fail-closed path, covered in tests/intercept_escalation.rs.)
    let _ = out;
    let seen = sink.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "consent consulted exactly once");
    seen[0].clone()
}

// (a)
#[tokio::test]
async fn a_network_grant_is_shown_to_the_operator() {
    let shown = shown_for(GrantDelta {
        net: vec!["1.2.3.4:443".into()],
        ..Default::default()
    })
    .await;
    assert!(shown.contains("1.2.3.4:443"), "{shown}");
}

// (b)
#[tokio::test]
async fn an_exec_grant_is_shown_to_the_operator() {
    let shown = shown_for(GrantDelta {
        exec: vec!["/usr/bin/x".into()],
        ..Default::default()
    })
    .await;
    assert!(shown.contains("/usr/bin/x"), "{shown}");
}

// (c) The struct literal is exhaustive on purpose: a new `GrantDelta` field fails to compile here
// until this test renders it too, which is exactly the review this guard exists to force.
#[tokio::test]
async fn every_field_of_a_grant_is_rendered() {
    let delta = GrantDelta {
        tools: vec!["bash".into()],
        filesystem: [("/tmp/w".to_string(), Access::Write)]
            .into_iter()
            .collect(),
        exec: vec!["/bin/true".into()],
        net: vec!["10.0.0.5:443".into()],
        http_targets: vec!["app.test:443".into()],
    };
    let shown = shown_for(delta).await;
    for needle in [
        "bash",
        "/tmp/w",
        "/bin/true",
        "10.0.0.5:443",
        "http target: app.test:443",
    ] {
        assert!(shown.contains(needle), "missing {needle}: {shown}");
    }
}

// (d)
#[test]
fn a_connect_denial_asks_for_that_destination() {
    let d = delta_from_denial("connect", "1.2.3.4:443");
    assert_eq!(d.net, vec!["1.2.3.4:443".to_string()]);
    assert!(d.exec.is_empty() && d.filesystem.is_empty());
}

// (e)
#[test]
fn an_exec_denial_asks_for_that_binary() {
    let d = delta_from_denial("exec", "/usr/bin/x");
    assert_eq!(d.exec, vec!["/usr/bin/x".to_string()]);
    assert!(d.net.is_empty() && d.filesystem.is_empty());
}

/// Before P5 a kernel connect audit carried no target. An empty target must not become a grant of
/// "" — it asks for nothing.
#[test]
fn a_connect_denial_without_a_destination_asks_for_nothing() {
    assert!(delta_from_denial("connect", "").is_empty());
}

/// P5: a kernel connect denial now carries its destination, formatted by `AuditEvent::from_record`
/// as `ip:port` (`crates/core/src/audit.rs`). That exact string is a grantable net entry.
#[test]
fn a_formatted_kernel_connect_target_is_a_grantable_destination() {
    let d = delta_from_denial("connect", "10.0.0.5:443");
    assert_eq!(d.net, vec!["10.0.0.5:443".to_string()]);
}
