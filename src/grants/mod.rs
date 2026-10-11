//! Runtime capability-grant state machine (007-dynamic-grants).
//!
//! [`ActivePolicy`] is the loop's mutable current policy, kept within `[base, ceiling]`. A grant is a
//! [`GrantLease`] layered onto `base`; `active` is always `base ∪ (live leases' deltas)`. Widening
//! ([`ActivePolicy::try_apply`]) is validated `⊆ ceiling` via [`bee_core`] attenuation *before* it is
//! accepted — beyond-ceiling grants are refused (the unpromptable bound, Constitution II). Narrowing
//! ([`ActivePolicy::expire`] / [`ActivePolicy::release`]) drops leases and recomputes.
//!
//! This module is pure (`bee_core::Policy` only, no async, no kernel) and fully host-testable. The
//! escalation cycle that consumes it — consent, `Sandbox::reload`, retry — lives in [`escalate`].

use std::collections::{BTreeMap, BTreeSet};

use bee_core::{Access, Policy};

pub mod escalate;

pub use crate::skills::grant::{
    resolve_grants, AllowWithinCeiling, ConsentSink, Decision, DenyAll, GrantOutcome, GrantRequest,
};

/// Stable identifier for a lease, targetable by de-escalation. Deterministic (a per-policy counter),
/// so tests and audits are reproducible.
pub type GrantId = String;

/// A capability change, in bee-core policy vocabulary. Produced by a skill's `requires` block, by a
/// reactive kernel denial, or explicitly. `tools` is harness registry membership (Layer 1); the rest
/// fold into the compiled policy (Layer 2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantDelta {
    pub tools: Vec<String>,
    pub filesystem: BTreeMap<String, Access>,
    pub exec: Vec<String>,
    pub net: Vec<String>,
    /// `host:port` entries to add to the interception **target** scope (019 US3). Folded into
    /// `[policy.http].targets`; the ceiling's `[policy.http]` bounds them like any other grant.
    pub http_targets: Vec<String>,
}

impl GrantDelta {
    /// True when the delta grants nothing (equivalent to no grant).
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
            && self.filesystem.is_empty()
            && self.exec.is_empty()
            && self.net.is_empty()
            && self.http_targets.is_empty()
    }

    /// Fold `other` into this delta: the union of both, a path asked for twice taking the more
    /// permissive access. How grants proposed by several hooks for one event combine (024 FR-034).
    pub fn merge(&mut self, other: GrantDelta) {
        fn union(mine: &mut Vec<String>, theirs: Vec<String>) {
            for x in theirs {
                if !mine.contains(&x) {
                    mine.push(x);
                }
            }
        }
        union(&mut self.tools, other.tools);
        union(&mut self.exec, other.exec);
        union(&mut self.net, other.net);
        union(&mut self.http_targets, other.http_targets);
        for (path, access) in other.filesystem {
            let merged = match self.filesystem.get(&path) {
                Some(&mine) => more_permissive(mine, access),
                None => access,
            };
            self.filesystem.insert(path, merged);
        }
    }
}

/// Why a lease was granted — provenance for the audit trail (Constitution IV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantOrigin {
    /// A tool hit a kernel denial and the grant covers that resource.
    ReactiveDenial { op: String, target: String },
    /// A loaded skill's `requires` block asked for it.
    SkillRequires { skill: String },
    /// Explicitly requested (e.g. a de-escalatable manual grant).
    Explicit,
    /// The interception proxy refused a call's request to `host:port` (019 US3).
    ProxyRefusal {
        host: String,
        port: u16,
        call: String,
    },
}

/// How long a grant lives. Turn counts are deterministic (the default, reproducible in scored runs);
/// `Forever` narrows only on explicit de-escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ttl {
    /// Expires once `granted_at_turn + n` turns have started.
    Turns(u32),
    /// Never auto-expires; dropped only by [`ActivePolicy::release`].
    Forever,
}

/// One approved grant, tracked so it can be narrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLease {
    pub id: GrantId,
    pub origin: GrantOrigin,
    pub delta: GrantDelta,
    pub ttl: Ttl,
    pub granted_at_turn: u32,
}

impl GrantLease {
    /// The turn at which this lease expires, if it has a finite TTL.
    pub fn expires_at_turn(&self) -> Option<u32> {
        match self.ttl {
            Ttl::Turns(n) => Some(self.granted_at_turn.saturating_add(n)),
            Ttl::Forever => None,
        }
    }

    /// True when `turn` has reached the lease's expiry.
    pub fn is_expired(&self, turn: u32) -> bool {
        self.expires_at_turn().is_some_and(|e| turn >= e)
    }
}

/// Fold a delta's Layer-2 rules into a policy (widening). Filesystem grants raise to the more
/// permissive access; exec/net additions are unioned. Tools are *not* policy — the caller registers
/// them separately.
fn fold_delta(policy: &mut Policy, delta: &GrantDelta) {
    for (path, &access) in &delta.filesystem {
        let raised = match policy.filesystem.get(path) {
            Some(&existing) => more_permissive(existing, access),
            None => access,
        };
        policy.filesystem.insert(path.clone(), raised);
    }
    for e in &delta.exec {
        if !policy.exec.allow.contains(e) {
            policy.exec.allow.push(e.clone());
        }
    }
    for n in &delta.net {
        if !policy.network.allow.contains(n) {
            policy.network.allow.push(n.clone());
        }
    }
    // Target-scope additions (019). A malformed entry is dropped here and so cannot widen; with no
    // `[policy.http]` section there is nothing to add to — and the ceiling check then refuses the
    // grant, because a section created from nothing has no parent to be a subset of.
    for t in &delta.http_targets {
        let Ok(hp) = bee_core::HostPort::try_from(t.clone()) else {
            continue;
        };
        let http = policy.http.get_or_insert_with(Default::default);
        if !http.targets.contains(&hp) {
            http.targets.push(hp);
        }
    }
}

/// The more-permissive of two access levels (Write > Read > Deny).
fn more_permissive(a: Access, b: Access) -> Access {
    fn rank(x: Access) -> u8 {
        match x {
            Access::Deny => 0,
            Access::Read => 1,
            Access::Write => 2,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// The loop's mutable current policy: `base` ⊆ `active` ⊆ `ceiling`, with `active = base ∪ live
/// leases`. Widening is attenuation-checked; narrowing drops leases.
#[derive(Debug, Clone)]
pub struct ActivePolicy {
    base: Policy,
    ceiling: Policy,
    active: Policy,
    leases: Vec<GrantLease>,
    next_id: u64,
}

impl ActivePolicy {
    /// Start at `base`, bounded by `ceiling`. Pass `base.clone()` as the ceiling for
    /// instructions-only (nothing can widen).
    pub fn new(base: Policy, ceiling: Policy) -> Self {
        let active = base.clone();
        ActivePolicy {
            base,
            ceiling,
            active,
            leases: Vec::new(),
            next_id: 0,
        }
    }

    /// The currently enforced policy (source of the next reload's plan).
    pub fn active(&self) -> &Policy {
        &self.active
    }

    /// The attenuation ceiling.
    pub fn ceiling(&self) -> &Policy {
        &self.ceiling
    }

    /// Live leases, in grant order.
    pub fn leases(&self) -> &[GrantLease] {
        &self.leases
    }

    /// Tools granted by any live lease (Layer 1 membership).
    pub fn granted_tools(&self) -> BTreeSet<String> {
        self.leases
            .iter()
            .flat_map(|l| l.delta.tools.iter().cloned())
            .collect()
    }

    /// Recompute `active` from `base` plus every live lease's delta.
    fn recompute(&mut self) {
        let mut p = self.base.clone();
        for lease in &self.leases {
            fold_delta(&mut p, &lease.delta);
        }
        self.active = p;
    }

    /// Attenuation pre-check: would widening by `delta` stay `⊆ ceiling`? Does **not** mutate — used
    /// by [`escalate::escalate`] to refuse a beyond-ceiling request *before* consulting consent.
    pub fn check_widen(&self, delta: &GrantDelta) -> Result<(), String> {
        self.check_net_enforceable(delta)?;
        let mut candidate = self.active.clone();
        fold_delta(&mut candidate, delta);
        self.ceiling
            .derive(candidate)
            .map(|_| ())
            .map_err(|e| format!("exceeds capability ceiling: {e}"))
    }

    /// Under an active `[policy.http]` the tool scope's only network rule is the proxy loopback:
    /// every reload re-applies it over `network.allow` (019), and `compile_http` refuses a policy
    /// that names both. A direct `net` grant would therefore be approved, recorded and never
    /// enforced — and break the next recompile. Refused before consent, so nobody is asked.
    fn check_net_enforceable(&self, delta: &GrantDelta) -> Result<(), String> {
        let intercepting = self.active.http.as_ref().is_some_and(|h| h.is_active());
        if intercepting && !delta.net.is_empty() {
            return Err(format!(
                "direct network grant {:?} has no effect under [policy.http]: tool traffic goes \
                 through the proxy; grant an http target instead",
                delta.net
            ));
        }
        Ok(())
    }

    /// The part of `delta` that `active` does not already grant.
    ///
    /// A skill's `requires` block is resolved once at startup (006-skills) and again by
    /// [`escalate::SkillEscalationHook`] every time the model calls `skill` — so without this, the
    /// second pass re-proposes capabilities the first already granted. That is harmless with a
    /// non-interactive sink, which approves silently, and is not harmless at all with a prompting
    /// one: the operator is asked to re-approve what they already approved, once per call. So a
    /// delta is narrowed to what is genuinely new before consent is consulted, and an escalation
    /// with nothing left in it never becomes a prompt.
    ///
    /// Filesystem rules are compared **key for key**, not by prefix containment, even though the
    /// compiler resolves them most-specific-first. That is the conservative direction: a request for
    /// `/srv/x` under a held `/srv` is treated as unmet and escalates redundantly, which costs a
    /// prompt. Reading it the other way would mean suppressing a request the compiler might not
    /// actually have covered, which costs a capability the model was told it had.
    ///
    /// `tools` are registry membership rather than policy, so they pass through untouched — the
    /// caller filters them against the live [`crate::tools::ToolRegistry`].
    pub fn unmet(&self, delta: &GrantDelta) -> GrantDelta {
        let mut out = GrantDelta {
            tools: delta.tools.clone(),
            ..Default::default()
        };
        for (path, &want) in &delta.filesystem {
            let held = self.active.filesystem.get(path).copied();
            // Held at least as permissively as asked ⇒ already granted.
            if held.is_some_and(|h| more_permissive(h, want) == h) {
                continue;
            }
            out.filesystem.insert(path.clone(), want);
        }
        for e in &delta.exec {
            if !self.active.exec.allow.contains(e) {
                out.exec.push(e.clone());
            }
        }
        for n in &delta.net {
            if !self.active.network.allow.contains(n) {
                out.net.push(n.clone());
            }
        }
        for t in &delta.http_targets {
            let held = bee_core::HostPort::try_from(t.clone()).is_ok_and(|hp| {
                self.active
                    .http
                    .as_ref()
                    .is_some_and(|h| h.targets.contains(&hp))
            });
            if !held {
                out.http_targets.push(t.clone());
            }
        }
        out
    }

    fn mint_id(&mut self) -> GrantId {
        let id = format!("g{}", self.next_id);
        self.next_id += 1;
        id
    }

    /// Attempt to widen with `delta` as a new lease. Validates `active ∪ delta ⊆ ceiling` FIRST
    /// (attenuation, not consent) — a beyond-ceiling delta returns `Err(reason)` and changes nothing.
    /// On success returns the new lease id. Consent is the caller's concern (see [`escalate`]).
    pub fn try_apply(
        &mut self,
        origin: GrantOrigin,
        delta: GrantDelta,
        ttl: Ttl,
        turn: u32,
    ) -> Result<GrantId, String> {
        self.check_net_enforceable(&delta)?;
        let mut candidate = self.active.clone();
        fold_delta(&mut candidate, &delta);
        self.ceiling
            .derive(candidate)
            .map_err(|e| format!("exceeds capability ceiling: {e}"))?;
        let id = self.mint_id();
        self.leases.push(GrantLease {
            id: id.clone(),
            origin,
            delta,
            ttl,
            granted_at_turn: turn,
        });
        self.recompute();
        Ok(id)
    }

    /// Drop every lease expired at `turn`; returns the dropped ids (empty ⇒ no narrowing needed).
    pub fn expire(&mut self, turn: u32) -> Vec<GrantId> {
        let mut dropped = Vec::new();
        let mut kept = Vec::with_capacity(self.leases.len());
        for lease in std::mem::take(&mut self.leases) {
            if lease.is_expired(turn) {
                dropped.push(lease.id);
            } else {
                kept.push(lease);
            }
        }
        self.leases = kept;
        if !dropped.is_empty() {
            self.recompute();
        }
        dropped
    }

    /// Drop the lease with `id`; returns true if one was removed (⇒ narrowing needed).
    pub fn release(&mut self, id: &str) -> bool {
        let before = self.leases.len();
        self.leases.retain(|l| l.id != id);
        let dropped = self.leases.len() != before;
        if dropped {
            self.recompute();
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(name: &str, fs: &[(&str, Access)]) -> Policy {
        let mut p = Policy {
            name: name.to_string(),
            description: None,
            mode: bee_core::Mode::Enforce,
            filesystem: BTreeMap::new(),
            exec: Default::default(),
            network: Default::default(),
            exfiltration: Default::default(),
            http: None,
        };
        for (path, access) in fs {
            p.filesystem.insert(path.to_string(), *access);
        }
        p
    }

    fn fs_delta(path: &str, access: Access) -> GrantDelta {
        let mut d = GrantDelta::default();
        d.filesystem.insert(path.to_string(), access);
        d
    }

    #[test]
    fn a_direct_net_grant_is_refused_while_intercepting() {
        // Review of #21: the reload re-applies the proxy loopback over `network.allow`, so the grant
        // would be approved and never enforced.
        let mut base = policy("base", &[]);
        base.http = Some(bee_core::policy::HttpPolicy {
            targets: vec![bee_core::HostPort::try_from("app.test:443".to_string()).unwrap()],
            ..Default::default()
        });
        let mut ceiling = base.clone();
        ceiling.network.allow.push("10.0.0.5:443".into());
        let mut ap = ActivePolicy::new(base, ceiling);
        let d = GrantDelta {
            net: vec!["10.0.0.5:443".into()],
            ..Default::default()
        };
        assert!(ap.check_widen(&d).unwrap_err().contains("[policy.http]"));
        assert!(ap
            .try_apply(GrantOrigin::Explicit, d, Ttl::Forever, 0)
            .is_err());
    }

    // ── `unmet` — what is left of a delta once what is already held is taken out ────────────────

    #[test]
    fn unmet_drops_what_is_already_held_at_the_same_or_greater_access() {
        let base = policy("base", &[("/a", Access::Write), ("/b", Access::Read)]);
        let ap = ActivePolicy::new(base.clone(), base);

        // Held at exactly the asked access, and held more permissively than asked: both satisfied.
        assert!(ap.unmet(&fs_delta("/a", Access::Write)).is_empty());
        assert!(ap.unmet(&fs_delta("/a", Access::Read)).is_empty());
        assert!(ap.unmet(&fs_delta("/b", Access::Read)).is_empty());
    }

    #[test]
    fn unmet_keeps_an_upgrade_and_anything_unheld() {
        let base = policy("base", &[("/b", Access::Read)]);
        let ap = ActivePolicy::new(base.clone(), base);

        // Read held, write asked — an upgrade is a widening, not a re-request.
        assert_eq!(
            ap.unmet(&fs_delta("/b", Access::Write))
                .filesystem
                .get("/b"),
            Some(&Access::Write)
        );
        // Never mentioned at all.
        assert_eq!(
            ap.unmet(&fs_delta("/c", Access::Read)).filesystem.get("/c"),
            Some(&Access::Read)
        );
    }

    #[test]
    fn unmet_compares_paths_key_for_key_rather_than_by_prefix() {
        // `/srv` is held, `/srv/x` is asked. The compiler would resolve the child under the parent,
        // so this *is* a redundant request — but `unmet` keeps it anyway. Erring this way costs a
        // consent prompt; erring the other way would suppress a request whose coverage was only
        // assumed, and hand the model a capability nobody granted.
        let base = policy("base", &[("/srv", Access::Write)]);
        let ap = ActivePolicy::new(base.clone(), base);
        assert_eq!(
            ap.unmet(&fs_delta("/srv/x", Access::Write))
                .filesystem
                .get("/srv/x"),
            Some(&Access::Write)
        );
    }

    #[test]
    fn unmet_filters_exec_and_net_against_what_is_allowed() {
        let mut base = policy("base", &[]);
        base.exec.allow = vec!["/usr/bin/git".to_string()];
        base.network.allow = vec!["example.com:443".to_string()];
        let ap = ActivePolicy::new(base.clone(), base);

        let delta = GrantDelta {
            exec: vec!["/usr/bin/git".into(), "/usr/bin/cargo".into()],
            net: vec!["example.com:443".into(), "crates.io:443".into()],
            ..Default::default()
        };
        let left = ap.unmet(&delta);
        assert_eq!(left.exec, vec!["/usr/bin/cargo".to_string()]);
        assert_eq!(left.net, vec!["crates.io:443".to_string()]);
    }

    #[test]
    fn unmet_leaves_tools_alone_because_they_are_not_policy() {
        // Registry membership is Layer 1; `ActivePolicy` has no view of it, so the caller filters.
        let base = policy("base", &[]);
        let ap = ActivePolicy::new(base.clone(), base);
        let delta = GrantDelta {
            tools: vec!["bash".into()],
            ..Default::default()
        };
        assert_eq!(ap.unmet(&delta).tools, vec!["bash".to_string()]);
    }

    #[test]
    fn starts_at_base_no_leases() {
        let base = policy("base", &[("/a", Access::Read)]);
        let ap = ActivePolicy::new(base.clone(), base.clone());
        assert_eq!(ap.active().filesystem, base.filesystem);
        assert!(ap.leases().is_empty());
    }

    #[test]
    fn apply_within_ceiling_widens() {
        let base = policy("base", &[]);
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let mut ap = ActivePolicy::new(base, ceiling);
        let id = ap
            .try_apply(
                GrantOrigin::Explicit,
                fs_delta("/tmp/w", Access::Write),
                Ttl::Forever,
                0,
            )
            .expect("within ceiling");
        assert_eq!(ap.active().filesystem.get("/tmp/w"), Some(&Access::Write));
        assert_eq!(ap.leases().len(), 1);
        assert_eq!(ap.leases()[0].id, id);
    }

    #[test]
    fn apply_beyond_ceiling_is_refused_and_noop() {
        let base = policy("base", &[]);
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let mut ap = ActivePolicy::new(base, ceiling);
        let err = ap
            .try_apply(
                GrantOrigin::Explicit,
                fs_delta("/etc", Access::Write),
                Ttl::Forever,
                0,
            )
            .unwrap_err();
        assert!(err.contains("exceeds capability ceiling"));
        assert!(!ap.active().filesystem.contains_key("/etc"));
        assert!(ap.leases().is_empty());
    }

    #[test]
    fn expire_narrows_at_ttl() {
        let base = policy("base", &[]);
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let mut ap = ActivePolicy::new(base, ceiling);
        ap.try_apply(
            GrantOrigin::Explicit,
            fs_delta("/tmp/w", Access::Write),
            Ttl::Turns(1),
            0,
        )
        .unwrap();
        // Live on turn 0.
        assert!(ap.active().filesystem.contains_key("/tmp/w"));
        assert!(ap.expire(0).is_empty(), "not yet expired");
        // Expires at turn 1.
        let dropped = ap.expire(1);
        assert_eq!(dropped.len(), 1);
        assert!(!ap.active().filesystem.contains_key("/tmp/w"));
    }

    #[test]
    fn release_drops_a_named_lease() {
        let base = policy("base", &[]);
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let mut ap = ActivePolicy::new(base, ceiling);
        let id = ap
            .try_apply(
                GrantOrigin::Explicit,
                fs_delta("/tmp/w", Access::Write),
                Ttl::Forever,
                0,
            )
            .unwrap();
        assert!(ap.release(&id));
        assert!(!ap.release(&id), "already gone");
        assert!(!ap.active().filesystem.contains_key("/tmp/w"));
    }

    #[test]
    fn granted_tools_union_over_live_leases() {
        let base = policy("base", &[]);
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let mut ap = ActivePolicy::new(base, ceiling);
        let mut d = fs_delta("/tmp/w", Access::Write);
        d.tools = vec!["bash".into(), "read_file".into()];
        ap.try_apply(GrantOrigin::Explicit, d, Ttl::Forever, 0)
            .unwrap();
        let tools = ap.granted_tools();
        assert!(tools.contains("bash") && tools.contains("read_file"));
    }

    // T028 — attenuation property test (Constitution II gate): no sequence of apply/expire/release
    // ever yields an active policy outside [base, ceiling], and active always reconstructs from
    // base + live leases.
    mod property {
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone)]
        enum Op {
            Apply(usize, u32), // ceiling-path index, ttl turns
            Expire(u32),
            Release(usize), // lease index (mod live count)
        }

        fn op_strategy() -> impl Strategy<Value = Op> {
            prop_oneof![
                (0usize..3, 0u32..4).prop_map(|(p, t)| Op::Apply(p, t)),
                (0u32..8).prop_map(Op::Expire),
                (0usize..8).prop_map(Op::Release),
            ]
        }

        proptest! {
            #[test]
            fn active_stays_within_bounds(ops in prop::collection::vec(op_strategy(), 0..40)) {
                // Ceiling permits write under three distinct subtrees; base grants nothing.
                let base = policy("base", &[]);
                let ceiling = policy("ceiling", &[
                    ("/a", Access::Write), ("/b", Access::Write), ("/c", Access::Write),
                ]);
                let paths = ["/a/x", "/b/x", "/c/x"];
                let mut ap = ActivePolicy::new(base.clone(), ceiling.clone());
                let mut turn = 0u32;

                for op in ops {
                    match op {
                        Op::Apply(p, ttl) => {
                            // Always within ceiling by construction; must succeed.
                            let _ = ap.try_apply(
                                GrantOrigin::Explicit,
                                fs_delta(paths[p], Access::Write),
                                Ttl::Turns(ttl),
                                turn,
                            );
                        }
                        Op::Expire(t) => { let _ = ap.expire(t); turn = turn.max(t); }
                        Op::Release(i) => {
                            if let Some(id) = ap.leases().get(i % ap.leases().len().max(1))
                                .map(|l| l.id.clone()) {
                                ap.release(&id);
                            }
                        }
                    }

                    // Invariant 1: active ⊆ ceiling (attenuation holds after every step).
                    prop_assert!(ceiling.derive(ap.active().clone()).is_ok());
                    // Invariant 2: active ⊇ base (never drops below the floor).
                    prop_assert!(ap.active().derive(base.clone()).is_ok());
                    // Invariant 3: active == base ∪ live-lease deltas (no orphaned rules).
                    let mut rebuilt = base.clone();
                    for lease in ap.leases() { fold_delta(&mut rebuilt, &lease.delta); }
                    prop_assert_eq!(&ap.active().filesystem, &rebuilt.filesystem);
                }
            }
        }
    }
}
