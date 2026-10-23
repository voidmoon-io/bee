//! The escalation cycle and its trigger hooks (007-dynamic-grants).
//!
//! [`escalate`] is the widen cycle: attenuation pre-check → the session's
//! [`crate::operator::Operator`] (which bounds consent by its timeout and records the decision) →
//! [`ActivePolicy::try_apply`] → [`crate::sandbox::Sandbox::reload`] → register
//! granted tools. It is consumed by the loop driver on a [`Flow::Escalate`] returned by a hook.
//!
//! Two built-in hooks emit that `Flow`: [`DenialEscalationHook`] (reactive — a kernel denial, US1)
//! and [`SkillEscalationHook`] (proactive — a loaded skill's `requires`, US2). Both only *propose*
//! a delta; the driver runs the cycle so the `Sandbox`/`ActivePolicy` mutation stays in one place.

use std::sync::Arc;

use bee_core::Access;

use crate::grants::{ActivePolicy, GrantDelta, GrantId, GrantOrigin, Ttl};
use crate::hooks::{Flow, LoopHook, StepEvent, StepEventKind};
use crate::operator::{ConsentRequest, Operator, Reason};
use crate::sandbox::Sandbox;
use crate::skills::grant::parse_access;
use crate::skills::{SkillRegistry, SkillRequires};
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
    /// Who decides a grant, within what time, and where each decision is recorded (024).
    pub operator: Operator,
    /// TTL applied to a granted lease that carries none.
    pub default_ttl: Ttl,
}

impl LoopEscalation {
    /// The loop must install any restrictions added while validating its starting policy.
    pub fn initialize(&self, active: &ActivePolicy, sandbox: &mut Sandbox) -> Result<(), String> {
        if self.default_ttl == Ttl::Turns(0) {
            return Err("a finite grant must last at least one turn".into());
        }
        if !active.leases().is_empty() {
            return Ok(());
        }
        let mut supplied = self.base.clone();
        supplied.defaults.deny_unmatched_writes = supplied.denies_unmatched_writes();
        if active.active() != &supplied {
            sandbox.reload(active.active())?;
        }
        Ok(())
    }
}

/// The result of an escalation attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", content = "detail", rename_all = "snake_case")]
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
/// prompting beyond ceiling, but recorded) → the operator's consent, bounded by its timeout → apply →
/// reload → register tools. Any failure leaves `active`, the scope, and the registry unchanged
/// (fail-closed). A request whose capabilities are all held is not a decision and is not recorded.
#[allow(clippy::too_many_arguments)]
pub async fn escalate(
    active: &mut ActivePolicy,
    origin: GrantOrigin,
    delta: GrantDelta,
    ttl: Ttl,
    turn: u32,
    operator: &Operator,
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
    let leased_tools = active.granted_tools();
    let has_new_authority = !delta.filesystem.is_empty()
        || !delta.exec.is_empty()
        || !delta.net.is_empty()
        || !delta.http_targets.is_empty()
        || delta.tools.iter().any(|t| !registry.contains(t));
    if !has_new_authority {
        return EscalateOutcome::AlreadyHeld;
    }
    delta
        .tools
        .retain(|t| !registry.contains(t) || leased_tools.contains(t));
    if delta.is_empty() {
        return EscalateOutcome::AlreadyHeld;
    }

    // 1. Attenuation ceiling — unpromptable. A beyond-ceiling request never reaches consent, but the
    //    refusal is recorded like any other decision.
    let request = ConsentRequest::from_delta(origin.clone(), &delta, turn);
    if let Err(e) = active.check_widen(&delta) {
        operator.record_unasked(request, Reason::BeyondCeiling);
        return EscalateOutcome::Refused(e);
    }

    // 2. Consent, bounded by the operator's timeout. Anything but a grant refuses (fail-closed,
    //    Constitution I), and a timeout says so rather than reading as the operator's "no".
    let record = operator.consent(request).await;
    match record.reason {
        Reason::Granted => {}
        Reason::TimedOut => return EscalateOutcome::Refused("consent timed out".to_string()),
        _ => return EscalateOutcome::Refused("denied by operator".to_string()),
    }

    // 3. Apply the lease (re-validates ⊆ ceiling and recomputes `active`).
    let tools = delta.tools.clone();
    let http_targets = delta.http_targets.clone();
    let mut candidate = active.clone();
    let id = match candidate.try_apply(origin, delta, ttl, turn) {
        Ok(id) => id,
        Err(e) => return EscalateOutcome::Refused(e),
    };

    // Prepare both authority layers before committing lease and tool membership.
    if candidate.active() != active.active() {
        if let Err(e) = sandbox.reload(candidate.active()) {
            return EscalateOutcome::Refused(format!("reload failed: {e}"));
        }
    }
    if !http_targets.is_empty() {
        let guard = sandbox.policy_update_guard();
        let updated = sandbox.apply_http_scope(candidate.active()).await;
        guard.finish();
        if let Err(e) = updated {
            if let Err(rollback) = sandbox.reload(active.active()) {
                sandbox.cleanup_failed(format!("grant rollback failed: {rollback}"));
            }
            return EscalateOutcome::Refused(format!("target-scope widening failed: {e}"));
        }
    }
    *active = candidate;
    operator.attach_lease(&record, &id);

    // 5. Register granted tools (Layer 1 membership), built by the one constructor with the
    //    session's dependencies, so a tool granted now is configured exactly as one present from the
    //    start (024 FR-014). The widened policy may grant a scanner, so scanner grants are recomputed
    //    first — rebuilding a `scan` already present, too.
    #[cfg(feature = "scanners")]
    {
        let deps = (**registry.deps()).clone().with_policy(active.active());
        registry.set_deps(std::sync::Arc::new(deps));
    }
    for tool in &tools {
        // An unknown name was refused at validation; nothing to register.
        let _ = registry.register(tool);
    }
    EscalateOutcome::Granted(id)
}

pub(crate) async fn install_narrowing(
    active: &mut ActivePolicy,
    candidate: ActivePolicy,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Result<(), String> {
    if candidate.active() != active.active() {
        let installed = sandbox.reload(candidate.active());
        if let Err(e) = installed {
            let detail = format!("mandatory policy narrowing failed: {e}");
            sandbox.cleanup_failed(detail.clone());
            return Err(detail);
        }
        if candidate.active().http != active.active().http {
            let guard = sandbox.policy_update_guard();
            let updated = sandbox.apply_http_scope(candidate.active()).await;
            guard.finish();
            if let Err(e) = updated {
                let detail = format!("mandatory target-scope narrowing failed: {e}");
                sandbox.cleanup_failed(detail.clone());
                return Err(detail);
            }
        }
    }
    let before = active.granted_tools();
    let after = candidate.granted_tools();
    for name in before.difference(&after) {
        registry.remove(name);
    }
    *active = candidate;
    Ok(())
}

pub(crate) async fn release_leases(
    ids: &[GrantId],
    active: &mut ActivePolicy,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut candidate = active.clone();
    for id in ids {
        if !candidate.release(id)? {
            return Err(format!("unknown grant: {id}"));
        }
    }
    install_narrowing(active, candidate, sandbox, registry).await
}

/// Apply lifecycle decisions shared by model and tool-result boundaries.
pub(crate) async fn lifecycle_step(
    config: &LoopEscalation,
    active: &mut ActivePolicy,
    event: StepEvent<'_>,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
) -> Result<(), String> {
    let decision =
        crate::hooks::dispatch_bounded(&config.hooks, &event, config.operator.timeout()).await;
    if let Some(reason) = decision.terminate {
        return Err(reason);
    }
    if decision.deny.is_some()
        || decision.escalate.is_some()
        || decision.refresh_tools
        || (!decision.deescalate.is_empty() && matches!(event, StepEvent::BeforeModelCall { .. }))
    {
        return Err(format!("unsupported hook action at {:?}", event.kind()));
    }
    release_leases(&decision.deescalate, active, sandbox, registry).await
}

// The escalation *steps* — dispatching `BeforeToolCall`, `KernelDenial` and `ProxyRefusal` to the
// hooks and running the widen cycle on a proposed grant — live in `src/call.rs`, the one copy of the
// call protocol (024 FR-017). What stays here is the widen cycle itself and the hooks that propose
// grants.

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

/// VM-test builds only: release lease `grant` at the top of model turn `turn`, as a real
/// [`Flow::Deescalate`] hook would. Set from outside by `BEE_VM_RELEASE_LEASE=<turn>:<grant>`, so the
/// BPF-LSM matrix can prove that a release narrows the kernel (024 SC-010, `lease-release`).
#[cfg(feature = "vm-test")]
pub struct VmReleaseHook {
    pub turn: u32,
    pub grant: crate::grants::GrantId,
}

#[cfg(feature = "vm-test")]
impl VmReleaseHook {
    /// The hook `BEE_VM_RELEASE_LEASE` asks for, if it is set and well formed.
    pub fn from_env() -> Option<Self> {
        Self::parse(&std::env::var("BEE_VM_RELEASE_LEASE").ok()?)
    }

    fn parse(v: &str) -> Option<Self> {
        let (turn, grant) = v.split_once(':')?;
        Some(VmReleaseHook {
            turn: turn.parse().ok()?,
            grant: grant.to_string(),
        })
    }
}

#[cfg(feature = "vm-test")]
#[async_trait::async_trait]
impl LoopHook for VmReleaseHook {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::TurnStart
    }

    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
        match ev {
            StepEvent::TurnStart { turn } if *turn == self.turn => {
                Flow::Deescalate(self.grant.clone())
            }
            _ => Flow::Continue,
        }
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
    use crate::operator::{AllowWithinCeiling, OperatorKind, Verdict};
    use crate::sandbox::Sandbox;
    use bee_core::{Mode, Policy};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn operator(consent: impl crate::operator::Consent + 'static) -> Operator {
        Operator::with_consent(OperatorKind::Autonomous, Arc::new(consent))
    }

    fn policy(name: &str, fs: &[(&str, Access)]) -> Policy {
        let mut p = Policy {
            defaults: Default::default(),
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
        )
        .unwrap();
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
            &operator(AllowWithinCeiling),
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
        struct Spy;
        #[async_trait::async_trait]
        impl crate::operator::Consent for Spy {
            async fn decide(&self, _r: &ConsentRequest) -> crate::operator::Decision {
                ASKED.store(true, Ordering::SeqCst);
                crate::operator::Decision::Granted
            }
        }
        let spy = operator(Spy);
        let mut ap = ActivePolicy::new(
            policy("base", &[]),
            policy("ceil", &[("/tmp", Access::Write)]),
        )
        .unwrap();
        let mut reg = ToolRegistry::new();
        let mut sb = host();
        let out = escalate(
            &mut ap,
            GrantOrigin::Explicit,
            fs_delta("/etc", Access::Write),
            Ttl::Forever,
            0,
            &spy,
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
        let log = spy.take_log();
        assert_eq!(log.len(), 1, "the refusal is still recorded");
        assert_eq!(
            (log[0].decision, log[0].reason),
            (Verdict::Refused, Reason::BeyondCeiling)
        );
    }

    // Consent denial (or timeout) refuses and changes nothing.
    #[tokio::test]
    async fn escalate_denied_by_consent_is_refused() {
        let mut ap = ActivePolicy::new(
            policy("base", &[]),
            policy("ceil", &[("/tmp", Access::Write)]),
        )
        .unwrap();
        let mut reg = ToolRegistry::new();
        let mut sb = host();
        let out = escalate(
            &mut ap,
            GrantOrigin::Explicit,
            fs_delta("/tmp/w", Access::Write),
            Ttl::Forever,
            0,
            &operator(DenyAll),
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

    #[cfg(feature = "vm-test")]
    #[tokio::test]
    async fn vm_release_hook_releases_its_lease_at_its_turn_only() {
        assert!(VmReleaseHook::parse("1").is_none(), "no grant");
        assert!(VmReleaseHook::parse("x:g0").is_none(), "no turn");
        let hook = VmReleaseHook::parse("1:g0").expect("well formed");
        assert!(hook.observes(StepEventKind::TurnStart));
        assert!(!hook.observes(StepEventKind::KernelDenial));
        assert_eq!(
            hook.on_event(&StepEvent::TurnStart { turn: 0 }).await,
            Flow::Continue
        );
        assert_eq!(
            hook.on_event(&StepEvent::TurnStart { turn: 1 }).await,
            Flow::Deescalate("g0".into())
        );
    }
}
