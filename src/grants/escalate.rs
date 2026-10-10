//! The escalation cycle and its trigger hooks (007-dynamic-grants).
//!
//! [`escalate`] is the widen cycle: attenuation pre-check → consent (bounded by a timeout,
//! elapse → deny) → [`ActivePolicy::try_apply`] → [`crate::sandbox::Sandbox::reload`] → register
//! granted tools. It is consumed by the loop driver on a [`Flow::Escalate`] returned by a hook.
//!
//! Two built-in hooks emit that `Flow`: [`DenialEscalationHook`] (reactive — a kernel denial, US1)
//! and [`SkillEscalationHook`] (proactive — a loaded skill's `requires`, US2). Both only *propose*
//! a delta; the driver runs the cycle so the `Sandbox`/`ActivePolicy` mutation stays in one place.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bee_core::Access;

use crate::grants::{ActivePolicy, GrantDelta, GrantId, GrantOrigin, Ttl};
use crate::hooks::{Flow, LoopHook, StepEvent, StepEventKind};
use crate::sandbox::Sandbox;
use crate::skills::grant::{parse_access, Decision};
use crate::skills::{ConsentSink, GrantRequest, SkillRegistry, SkillRequires};
use crate::tools::ToolRegistry;

/// Per-episode escalation configuration, carried on `LoopOptions`/`ReplConfig`. `None` there ⇒ no
/// escalation (the loop behaves exactly as before this feature). The loop builds a mutable
/// [`ActivePolicy`] from `base`/`ceiling` at startup and drives `hooks` each step.
pub struct LoopEscalation {
    /// The episode's floor (the policy the scope was compiled with, incl. any 006 preload grants).
    pub base: bee_core::Policy,
    /// The attenuation ceiling; `= base` disables widening.
    pub ceiling: bee_core::Policy,
    /// Hooks that may return [`Flow::Escalate`]/[`Flow::Deescalate`].
    pub hooks: Vec<Box<dyn LoopHook>>,
    /// The async consent sink (with a timeout applied by the loop).
    pub consent: Arc<dyn ConsentSink>,
    /// Max wait for consent before deny (fail-closed).
    pub timeout: Duration,
    /// TTL applied to a granted lease that carries none.
    pub default_ttl: Ttl,
}

/// The result of an escalation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalateOutcome {
    /// Granted; the scope was reloaded and the lease recorded under this id.
    Granted(GrantId),
    /// Every capability asked for was already held, so nothing was asked of the operator and nothing
    /// was reloaded. Distinct from [`EscalateOutcome::Granted`]: no lease exists to narrow later,
    /// and a caller that retries on a grant must not retry on this — the scope did not change, so
    /// the retry would fail exactly as the first attempt did.
    AlreadyHeld,
    /// Refused (beyond ceiling, denied by consent/timeout, or a reload failure). No state changed.
    Refused(String),
}

impl EscalateOutcome {
    /// True only when this escalation *widened* the scope. `AlreadyHeld` is deliberately false: it
    /// is the answer to "did anything change", and nothing did.
    pub fn is_granted(&self) -> bool {
        matches!(self, EscalateOutcome::Granted(_))
    }
}

/// Run the widen cycle for `delta`. Order (contract `consent.md`): attenuation pre-check (no
/// prompting beyond ceiling) → consent with timeout (elapse → deny) → apply → reload → register
/// tools. Any failure leaves `active`, the scope, and the registry unchanged (fail-closed).
#[allow(clippy::too_many_arguments)]
pub async fn escalate(
    active: &mut ActivePolicy,
    origin: GrantOrigin,
    delta: GrantDelta,
    ttl: Ttl,
    turn: u32,
    consent: &dyn ConsentSink,
    timeout: Duration,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> EscalateOutcome {
    if delta.is_empty() {
        return EscalateOutcome::Refused("empty grant".to_string());
    }

    // 0. Ask only for what is not already held. A skill's `requires` is resolved at startup and
    //    re-proposed on every `skill` call, so without this the operator is prompted again for
    //    capabilities they already approved — once per call. Tools are registry membership rather
    //    than policy, so they are filtered against the live registry instead of the policy.
    let mut delta = active.unmet(&delta);
    delta.tools.retain(|t| !registry.contains(t));
    if delta.is_empty() {
        return EscalateOutcome::AlreadyHeld;
    }

    // 1. Attenuation ceiling — unpromptable. A beyond-ceiling request never reaches consent.
    if let Err(e) = active.check_widen(&delta) {
        return EscalateOutcome::Refused(e);
    }

    // 2. Consent, bounded by a timeout. Elapse or Denied → refuse (fail-closed, Constitution I).
    let fs_display: BTreeMap<String, String> = delta
        .filesystem
        .iter()
        .map(|(p, a)| (p.clone(), access_word(*a).to_string()))
        .collect();
    let request = GrantRequest {
        skill: origin_label(&origin),
        tools: &delta.tools,
        filesystem: &fs_display,
        net: &delta.net,
        exec: &delta.exec,
        http_targets: &delta.http_targets,
    };
    let decision = match tokio::time::timeout(timeout, consent.confirm(&request)).await {
        Ok(d) => d,
        Err(_) => Decision::Denied, // timed out
    };
    if decision == Decision::Denied {
        return EscalateOutcome::Refused("denied by operator".to_string());
    }

    // 3. Apply the lease (re-validates ⊆ ceiling and recomputes `active`).
    let tools = delta.tools.clone();
    let http_targets = delta.http_targets.clone();
    let id = match active.try_apply(origin, delta, ttl, turn) {
        Ok(id) => id,
        Err(e) => return EscalateOutcome::Refused(e),
    };

    // 4. Reload the live scope with the widened policy. On failure, roll the lease back (keep-prior).
    if let Err(e) = sandbox.reload(active.active()) {
        active.release(&id);
        return EscalateOutcome::Refused(format!("reload failed: {e}"));
    }

    // 4b. A target-scope widening (019 US3) also reaches the proxy, atomically across both layers:
    //     the proxy scope's kernel rules, then the worker's own scope. If the worker cannot take it,
    //     the sidecar is rolled back to its previous plan and the lease released — the operator's
    //     "yes" never leaves the two layers disagreeing.
    if !http_targets.is_empty() {
        if let Err(e) = sandbox.apply_http_scope(active.active()).await {
            active.release(&id);
            let _ = sandbox.reload(active.active());
            return EscalateOutcome::Refused(format!("target-scope widening failed: {e}"));
        }
    }

    // 5. Register granted tools (Layer 1 membership).
    for tool in &tools {
        crate::tools::register_named(registry, tool, None);
    }
    EscalateOutcome::Granted(id)
}

/// The proactive escalation step (US2), shared by both loops.
///
/// Dispatches [`StepEvent::BeforeToolCall`] and, if a hook proposes a grant, runs the widen cycle
/// before the call executes. Returns `None` when escalation is off or no hook proposed anything —
/// the overwhelmingly common case, and the one that must cost nothing.
///
/// This exists because `run_loop` and `run_exchange` are not one loop and should not be forced into
/// one: the episode loop is non-streaming, deadline-bounded and builds a transcript; the REPL loop
/// streams, is budget-bounded, and carries a steering queue. What they genuinely share is the
/// escalation *step*, so that is what is extracted (007 T009). The `Sandbox`/`ActivePolicy` mutation
/// stays in one place either way, which is the property that mattered.
pub async fn proactive_step(
    esc: &LoopEscalation,
    active: &mut ActivePolicy,
    call: &crate::provider::ToolCall,
    turn: u32,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Option<EscalateOutcome> {
    let ev = StepEvent::BeforeToolCall(call);
    let Flow::Escalate(delta) = crate::hooks::dispatch(&esc.hooks, &ev).await else {
        return None;
    };
    let skill = call
        .arguments
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("skill")
        .to_string();
    Some(
        escalate(
            active,
            GrantOrigin::SkillRequires { skill },
            delta,
            esc.default_ttl,
            turn,
            esc.consent.as_ref(),
            esc.timeout,
            sandbox,
            registry,
        )
        .await,
    )
}

/// The reactive escalation step (US1), shared by both loops.
///
/// Dispatches [`StepEvent::KernelDenial`] for the first denial in this call's drained audit and, if
/// a hook proposes a grant scoped to the denied resource, runs the widen cycle. The caller decides
/// whether to retry — it owns the deadline and the transcript — but must retry **only** on
/// [`EscalateOutcome::is_granted`], and only once (SC-005).
#[allow(clippy::too_many_arguments)]
pub async fn reactive_step(
    esc: &LoopEscalation,
    active: &mut ActivePolicy,
    op: &str,
    target: &str,
    call: &crate::provider::ToolCall,
    turn: u32,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Option<EscalateOutcome> {
    let ev = StepEvent::KernelDenial { op, target, call };
    let Flow::Escalate(delta) = crate::hooks::dispatch(&esc.hooks, &ev).await else {
        return None;
    };
    Some(
        escalate(
            active,
            GrantOrigin::ReactiveDenial {
                op: op.to_string(),
                target: target.to_string(),
            },
            delta,
            esc.default_ttl,
            turn,
            esc.consent.as_ref(),
            esc.timeout,
            sandbox,
            registry,
        )
        .await,
    )
}

/// The proxy-refusal escalation step (019 US3), shared by both loops.
///
/// Dispatches [`StepEvent::ProxyRefusal`] for the first `refused_out_of_scope` proxy event of this
/// call and, if a hook proposes a grant, runs the widen cycle for exactly that `host:port`. As with
/// [`reactive_step`], the caller retries **only** on [`EscalateOutcome::is_granted`], and only once.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_refusal_step(
    esc: &LoopEscalation,
    active: &mut ActivePolicy,
    events: &[crate::proxy_event::ProxyEvent],
    call: &crate::provider::ToolCall,
    turn: u32,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Option<EscalateOutcome> {
    let ev = events
        .iter()
        .find(|e| e.kind == crate::proxy_event::ProxyEventKind::RefusedOutOfScope)?;
    let step = StepEvent::ProxyRefusal {
        host: &ev.host,
        port: ev.port,
        call,
    };
    let Flow::Escalate(delta) = crate::hooks::dispatch(&esc.hooks, &step).await else {
        return None;
    };
    Some(
        escalate(
            active,
            GrantOrigin::ProxyRefusal {
                host: ev.host.clone(),
                port: ev.port,
                call: call.id.clone(),
            },
            delta,
            esc.default_ttl,
            turn,
            esc.consent.as_ref(),
            esc.timeout,
            sandbox,
            registry,
        )
        .await,
    )
}

/// Proposes exactly the refused `host:port` as a target-scope widening (019 US3). Gated like the
/// kernel-denial hook: on only where a ceiling authorises widening at all.
pub struct ProxyRefusalHook {
    pub enabled: bool,
}

#[async_trait::async_trait]
impl LoopHook for ProxyRefusalHook {
    fn observes(&self, kind: StepEventKind) -> bool {
        self.enabled && kind == StepEventKind::ProxyRefusal
    }

    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        if let StepEvent::ProxyRefusal { host, port, .. } = ev {
            let hp = bee_core::HostPort {
                host: (*host).to_string(),
                port: *port,
            };
            return Flow::Escalate(GrantDelta {
                http_targets: vec![hp.to_string()],
                ..Default::default()
            });
        }
        Flow::Continue
    }
}

/// The first denial in a drained audit batch, as `(op, target)`. Both loops locate the reactive
/// trigger the same way; only one of them should own the spelling of "the first denial".
pub fn first_denial(audit: &[bee_core::AuditEvent]) -> Option<(String, String)> {
    audit
        .iter()
        .find(|e| e.decision == "denied")
        .map(|e| (e.op.clone(), e.target.clone()))
}

fn access_word(a: Access) -> &'static str {
    match a {
        Access::Read => "read",
        Access::Write => "write",
        Access::Deny => "deny",
    }
}

fn origin_label(origin: &GrantOrigin) -> &str {
    match origin {
        GrantOrigin::ReactiveDenial { .. } => "reactive-denial",
        GrantOrigin::SkillRequires { skill } => skill,
        GrantOrigin::Explicit => "explicit",
        GrantOrigin::ProxyRefusal { .. } => "proxy-refusal",
    }
}

/// Build a [`GrantDelta`] from a [`SkillRequires`] block (proactive path). Errors on a malformed
/// access word so a bad skill is refused, not silently narrowed.
pub fn delta_from_requires(req: &SkillRequires) -> Result<GrantDelta, String> {
    let mut delta = GrantDelta {
        tools: req.tools.clone(),
        ..Default::default()
    };
    for (path, word) in &req.filesystem {
        delta.filesystem.insert(path.clone(), parse_access(word)?);
    }
    Ok(delta)
}

/// Build a minimal [`GrantDelta`] for a kernel denial (reactive path). The `op` vocabulary is the
/// kernel audit's own (`op_str` in `crates/core/src/audit.rs`): `file_open` → write access to the
/// target (write implies read, so it covers both a read- and a write-denial); `connect` → a net rule;
/// `exec` → an exec-allow entry. Unknown ops, and an empty target, yield an empty delta.
///
/// Until 019 matched these against the LSM *hook* names (`socket_connect`, `bprm_check_security`),
/// which no audit event ever carries, so network and exec denials never escalated (research R13).
/// A connect target reads `ip:port` only from kernels running the P5 eBPF object; on an older object
/// it is empty, and the delta stays empty rather than granting "".
pub fn delta_from_denial(op: &str, target: &str) -> GrantDelta {
    let mut delta = GrantDelta::default();
    if target.is_empty() {
        return delta;
    }
    match op {
        "file_open" => {
            delta.filesystem.insert(target.to_string(), Access::Write);
        }
        "connect" => {
            delta.net.push(target.to_string());
        }
        "exec" => {
            delta.exec.push(target.to_string());
        }
        _ => {}
    }
    delta
}

/// Reactive escalation (US1): on a [`StepEvent::KernelDenial`], propose a grant scoped to the denied
/// resource. Gated by `enabled` (off by default in batch unless a ceiling authorizes it).
pub struct DenialEscalationHook {
    pub enabled: bool,
}

#[async_trait::async_trait]
impl LoopHook for DenialEscalationHook {
    fn observes(&self, kind: StepEventKind) -> bool {
        self.enabled && kind == StepEventKind::KernelDenial
    }

    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        if let StepEvent::KernelDenial { op, target, .. } = ev {
            let delta = delta_from_denial(op, target);
            if !delta.is_empty() {
                return Flow::Escalate(delta);
            }
        }
        Flow::Continue
    }
}

/// Proactive escalation (US2): on a `skill` tool call, if the loaded skill declares a `requires`
/// block, propose that delta before the instructions take effect. The driver's escalation cycle
/// (attenuation + consent) decides whether it is granted.
pub struct SkillEscalationHook {
    skills: Arc<SkillRegistry>,
}

impl SkillEscalationHook {
    pub fn new(skills: Arc<SkillRegistry>) -> Self {
        SkillEscalationHook { skills }
    }
}

#[async_trait::async_trait]
impl LoopHook for SkillEscalationHook {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::BeforeToolCall
    }

    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        if let StepEvent::BeforeToolCall(call) = ev {
            if call.name != "skill" {
                return Flow::Continue;
            }
            let Some(name) = call.arguments.get("name").and_then(|v| v.as_str()) else {
                return Flow::Continue;
            };
            if let Some(skill) = self.skills.get(name) {
                if let Some(req) = &skill.requires {
                    if let Ok(delta) = delta_from_requires(req) {
                        if !delta.is_empty() {
                            return Flow::Escalate(delta);
                        }
                    }
                }
            }
        }
        Flow::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{DenyAll, GrantOrigin};
    use crate::sandbox::Sandbox;
    use crate::skills::grant::AllowWithinCeiling;
    use bee_core::{Mode, Policy};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn policy(name: &str, fs: &[(&str, Access)]) -> Policy {
        let mut p = Policy {
            name: name.to_string(),
            description: None,
            mode: Mode::Enforce,
            filesystem: BTreeMap::new(),
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

    fn fs_delta(path: &str, a: Access) -> GrantDelta {
        let mut d = GrantDelta::default();
        d.filesystem.insert(path.to_string(), a);
        d
    }

    fn host() -> Sandbox {
        Sandbox::host(Vec::new())
    }

    // T014 / T012 — within-ceiling grant is applied, scope reloaded (host no-op), tools registered.
    #[tokio::test]
    async fn escalate_within_ceiling_grants_and_reloads() {
        let mut ap = ActivePolicy::new(
            policy("base", &[]),
            policy("ceil", &[("/tmp", Access::Write)]),
        );
        let mut reg = ToolRegistry::new();
        let mut sb = host();
        let mut delta = fs_delta("/tmp/w", Access::Write);
        delta.tools = vec!["bash".into()];
        let out = escalate(
            &mut ap,
            GrantOrigin::Explicit,
            delta,
            Ttl::Turns(1),
            0,
            &AllowWithinCeiling,
            Duration::from_secs(5),
            &mut sb,
            &mut reg,
        )
        .await;
        assert!(out.is_granted());
        assert!(ap.active().filesystem.contains_key("/tmp/w"));
        assert!(reg.contains("bash"), "granted tool registered");
    }

    // T013(a) — beyond-ceiling escalation is refused WITHOUT consulting consent.
    #[tokio::test]
    async fn escalate_beyond_ceiling_refuses_without_consent() {
        static ASKED: AtomicBool = AtomicBool::new(false);
        let spy = |_: &GrantRequest<'_>| {
            ASKED.store(true, Ordering::SeqCst);
            true
        };
        let mut ap = ActivePolicy::new(
            policy("base", &[]),
            policy("ceil", &[("/tmp", Access::Write)]),
        );
        let mut reg = ToolRegistry::new();
        let mut sb = host();
        let out = escalate(
            &mut ap,
            GrantOrigin::Explicit,
            fs_delta("/etc", Access::Write),
            Ttl::Forever,
            0,
            &spy,
            Duration::from_secs(5),
            &mut sb,
            &mut reg,
        )
        .await;
        assert!(
            matches!(out, EscalateOutcome::Refused(ref r) if r.contains("exceeds capability ceiling"))
        );
        assert!(
            !ASKED.load(Ordering::SeqCst),
            "consent must not be consulted beyond the ceiling"
        );
        assert!(ap.leases().is_empty());
    }

    // Consent denial (or timeout) refuses and changes nothing.
    #[tokio::test]
    async fn escalate_denied_by_consent_is_refused() {
        let mut ap = ActivePolicy::new(
            policy("base", &[]),
            policy("ceil", &[("/tmp", Access::Write)]),
        );
        let mut reg = ToolRegistry::new();
        let mut sb = host();
        let out = escalate(
            &mut ap,
            GrantOrigin::Explicit,
            fs_delta("/tmp/w", Access::Write),
            Ttl::Forever,
            0,
            &DenyAll,
            Duration::from_secs(5),
            &mut sb,
            &mut reg,
        )
        .await;
        assert!(matches!(out, EscalateOutcome::Refused(_)));
        assert!(!ap.active().filesystem.contains_key("/tmp/w"));
    }

    #[tokio::test]
    async fn denial_hook_builds_a_write_delta_for_file_open() {
        let hook = DenialEscalationHook { enabled: true };
        let call = crate::provider::ToolCall {
            id: "1".into(),
            name: "bash".into(),
            arguments: serde_json::json!({}),
        };
        let ev = StepEvent::KernelDenial {
            op: "file_open",
            target: "/data/x",
            call: &call,
        };
        match hook.on_event(&ev).await {
            Flow::Escalate(d) => assert_eq!(d.filesystem.get("/data/x"), Some(&Access::Write)),
            other => panic!("expected Escalate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disabled_denial_hook_does_not_observe() {
        let hook = DenialEscalationHook { enabled: false };
        assert!(!hook.observes(StepEventKind::KernelDenial));
    }
}
