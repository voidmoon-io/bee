//! Attenuation: prove a derived policy is a subset of its parent (FR-005, SC-002).
//!
//! The validator is **sound and conservative** (constitution Principle II): when subset containment
//! cannot be proven it rejects (fail-closed), even at the cost of rejecting some children that would
//! in fact be safe. Reasoning is at the authoring level over raw pattern strings — parent and child
//! share the same token vocabulary (`:project_root`, `~`), so string-level subtree reasoning is
//! valid without resolving to the host environment.
//!
//! # Silence inherits, it does not reset
//!
//! Checking the child's *stated* rules against the parent is only half of subset containment. The
//! other half is what the child leaves out. An authoring policy says nothing about a dimension it
//! omits, and every layer below reads "no rules" as "nothing to enforce": an empty
//! `[policy.network]` clears `FLAG_NET_ENFORCED`, an empty `[policy.exec]` installs no `EXEC_ALLOW`
//! entry, and no write rule anywhere leaves `FLAG_FS_WRITE_DEFAULT_DENY` unset. That reading is
//! deliberate for a **root** policy — an operator who writes no network rules is not asking for an
//! egress firewall — but for a *derived* policy it inverts the whole point: the shortest possible
//! child would silently out-rank the parent that bounds it.
//!
//! So [`Policy::derive`] does not hand back the request as written. It returns the **effective**
//! child policy, under one rule applied uniformly:
//!
//! > A dimension the child does not mention is inherited from the parent, and a restriction the
//! > parent placed inside a region the child re-grants is re-added if the child dropped it.
//!
//! Inheriting (rather than rejecting, or defaulting to deny-all) is what keeps the rule usable: a
//! subagent policy that narrows only the filesystem should not have to restate the parent's exec
//! and network lists to avoid being handed either nothing or everything. The result is always ⊆ the
//! parent, because every inherited rule *is* a parent rule.
//!
//! The same reasoning covers two smaller leaks: an inode pin (`!bin`) is part of a parent's
//! restriction, so a child naming the same executable unpinned inherits the pin; and the FR-008
//! protected defaults ([`crate::compiler::PROTECTED_DEFAULTS`]) are injected during *compilation*,
//! after this check runs, so a child grant reaching into `~/.ssh` or `.git` is refused here unless
//! the parent named that region explicitly. Overriding a protected default is the author's
//! prerogative; it is not inherited by an untrusted child.

use std::collections::BTreeMap;

use crate::compiler::{lower_pattern, FsPrimitive, PROTECTED_DEFAULTS};
use crate::error::AttenuationError;
use crate::policy::{Access, Policy};
use bee_common::AccessMode;

/// A pattern's region for containment reasoning.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Region {
    /// A concrete path (exact/subtree).
    Prefix(Vec<u8>),
    /// A glob, identified by a canonical (kind, bytes) key. Two globs are "the same region" iff equal.
    Glob(u8, Vec<u8>),
}

fn region_of(raw: &str) -> Option<Region> {
    match lower_pattern(raw, AccessMode::READ).ok()? {
        FsPrimitive::Prefix { path, .. } => Some(Region::Prefix(path)),
        FsPrimitive::Postfix { suffix, .. } => Some(Region::Glob(0, suffix)),
        FsPrimitive::Segment { name, .. } => Some(Region::Glob(1, name)),
        FsPrimitive::BoundedStar { pattern, .. } => Some(Region::Glob(2, pattern)),
    }
}

/// True if prefix `outer` contains `inner` (inner == outer, or inner lies beneath outer).
fn prefix_contains(outer: &[u8], inner: &[u8]) -> bool {
    if inner == outer {
        return true;
    }
    inner.len() > outer.len() && inner.starts_with(outer) && inner[outer.len()] == b'/'
}

impl Policy {
    /// Derive a validated child policy that is provably ⊆ `self`. Returns the **effective** child —
    /// the request plus every parent restriction it left out (see the module docs) — or the first
    /// [`AttenuationError`] found.
    pub fn derive(&self, request: Policy) -> Result<Policy, AttenuationError> {
        // Mode may only stay the same or become stricter (parent Enforce ⇒ child Enforce).
        if request.mode.strictness() < self.mode.strictness() {
            return Err(AttenuationError::new(
                "mode",
                "child mode is looser than parent (parent enforces; child must enforce)",
            ));
        }

        self.check_filesystem(&request.filesystem)?;
        self.check_exec(&request)?;
        self.check_network(&request)?;
        self.check_http(&request)?;
        // Exfiltration: a child may only *add* sensitive paths / enable detection (narrowing) — no check.

        Ok(self.inherit_restrictions(request))
    }

    /// Close what the request left unsaid. Every rule added here is a parent rule, so the result is
    /// still ⊆ `self`; what changes is that the child can no longer *widen by omission*.
    fn inherit_restrictions(&self, mut child: Policy) -> Policy {
        // Filesystem. A child that states no path rules inherits the parent's map wholesale: the
        // alternative — an empty rule set — is read downstream as "no filesystem enforcement",
        // which is the widening this exists to stop. A child that does state rules keeps them, but
        // re-acquires every parent `deny`: `check_filesystem` only forces a child to replicate the
        // restrictions that fall *inside* a region it re-granted, so a parent deny the child never
        // went near would otherwise simply evaporate.
        if child.filesystem.is_empty() {
            child.filesystem = self.filesystem.clone();
        } else {
            for (raw, &access) in &self.filesystem {
                if access == Access::Deny {
                    // A validated child cannot already hold a *grant* at a denied region —
                    // `check_prefix_grant` rejects that outright — so this never demotes a grant.
                    child.filesystem.entry(raw.clone()).or_insert(Access::Deny);
                }
            }
        }

        // Executables. An empty child list installs no allowlist at all, which the kernel reads as
        // unrestricted execution; inherit the parent's list instead. A child that names executables
        // keeps its (already validated ⊆) selection, but each entry re-acquires the parent's inode
        // pin — dropping the `!` is a widening, since a pinned rule survives a swapped binary.
        if child.exec.allow.is_empty() {
            child.exec.allow = self.exec.allow.clone();
        } else {
            for entry in &mut child.exec.allow {
                if entry.starts_with('!') {
                    continue;
                }
                if self.exec.allow.iter().any(|p| p == &format!("!{entry}")) {
                    entry.insert(0, '!');
                }
            }
        }

        // Network. An empty child list clears `FLAG_NET_ENFORCED` and permits every destination;
        // inherit the parent's allowlist instead.
        if child.network.allow.is_empty() {
            child.network.allow = self.network.allow.clone();
        }

        // Interception scope (019). A child that says nothing about `[policy.http]` is still bound
        // by the parent's: without it the child's tool scope would compile with no proxy loopback
        // rule and reach whatever its own network list says — or, empty, everything.
        if child.http.is_none() {
            child.http = self.http.clone();
        }

        child
    }

    /// `[policy.http]` subset rules (data-model.md §Attenuation rules). An absent child section is
    /// not checked here — it inherits, in [`Policy::inherit_restrictions`].
    fn check_http(&self, request: &Policy) -> Result<(), AttenuationError> {
        let Some(child) = &request.http else {
            return Ok(());
        };
        let empty = crate::policy::HttpPolicy::default();
        let parent = self.http.as_ref().unwrap_or(&empty);

        // A section with no targets is inactive: the child's tool scope would compile with no proxy
        // loopback rule and fall back to its own network list — under an intercepting parent that
        // list is empty, which the kernel reads as "everything". Turning interception off is not a
        // narrowing, so it is refused rather than silently inherited.
        if parent.is_active() && !child.is_active() {
            return Err(AttenuationError::new(
                "http.targets",
                "an empty targets list would drop the parent's interception scope; \
                 name a subset of its targets or omit [policy.http] to inherit it",
            ));
        }

        for t in &child.targets {
            if !parent.targets.contains(t) {
                return Err(AttenuationError::new(
                    format!("http.targets:{t}"),
                    "target not in parent's [policy.http] targets",
                ));
            }
        }
        for e in &child.egress {
            if !parent.egress.contains(e) && !parent.targets.contains(e) {
                return Err(AttenuationError::new(
                    format!("http.egress:{e}"),
                    "egress host not in parent's [policy.http] targets or egress",
                ));
            }
        }
        for (field, child_pats, parent_pats) in [
            ("inspect", &child.inspect, &parent.inspect),
            (
                "insecure_upstream",
                &child.insecure_upstream,
                &parent.insecure_upstream,
            ),
        ] {
            for c in child_pats {
                // `Some(true)` from some parent pattern, or refuse. `None` (undecidable) is a refusal
                // exactly as `Some(false)` is: an unprovable subset is not a subset.
                if !parent_pats.iter().any(|p| p.covers(c) == Some(true)) {
                    return Err(AttenuationError::new(
                        format!("http.{field}:{c}"),
                        "pattern not provably covered by the parent's",
                    ));
                }
            }
        }
        let (c, p) = (&child.limits, &parent.limits);
        for (name, over) in [
            ("rps", c.rps > p.rps),
            ("concurrency", c.concurrency > p.concurrency),
            (
                "max_requests_per_run",
                c.max_requests_per_run > p.max_requests_per_run,
            ),
            ("max_body_bytes", c.max_body_bytes > p.max_body_bytes),
            ("store_cap_bytes", c.store_cap_bytes > p.store_cap_bytes),
        ] {
            // A parent without `[policy.http]` has no limits to exceed, but it also has no targets,
            // so a child that reaches here with a target was already refused above.
            if over && self.http.is_some() {
                return Err(AttenuationError::new(
                    format!("http.limits.{name}"),
                    "limit exceeds the parent's",
                ));
            }
        }
        Ok(())
    }

    fn check_filesystem(&self, child: &BTreeMap<String, Access>) -> Result<(), AttenuationError> {
        for (raw, &access) in child {
            if access == Access::Deny {
                continue; // adding a denial always narrows.
            }
            let cap = format!("filesystem:{raw}");
            let region = region_of(raw)
                .ok_or_else(|| AttenuationError::new(&cap, "child pattern is not a valid rule"))?;

            match region {
                Region::Prefix(pc) => self.check_prefix_grant(&cap, &pc, access, child)?,
                Region::Glob(kind, bytes) => {
                    // Conservative: a glob grant is permitted only if the parent has an identical
                    // glob rule granting at least this access.
                    let ok = self.filesystem.iter().any(|(pr, &pa)| {
                        pa != Access::Deny
                            && access.is_subset_of(pa)
                            && region_of(pr) == Some(Region::Glob(kind, bytes.clone()))
                    });
                    if !ok {
                        return Err(AttenuationError::new(
                            &cap,
                            "glob grant not provably contained in parent (needs an identical parent glob rule)",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Sound check for a concrete-path child grant.
    fn check_prefix_grant(
        &self,
        cap: &str,
        pc: &[u8],
        access: Access,
        child: &BTreeMap<String, Access>,
    ) -> Result<(), AttenuationError> {
        // 1. Parent's effective access AT pc = the most specific parent rule whose region ⊇ pc.
        let mut eff: Option<(Access, usize)> = None;
        for (pr, &pa) in &self.filesystem {
            if let Some(Region::Prefix(pp)) = region_of(pr) {
                if prefix_contains(&pp, pc) && pp.len() >= eff.map_or(0, |(_, l)| l) {
                    eff = Some((pa, pp.len()));
                }
            }
        }
        let parent_access = match eff {
            None => {
                return Err(AttenuationError::new(
                    cap,
                    "no parent rule covers this path",
                ));
            }
            Some((Access::Deny, _)) => {
                return Err(AttenuationError::new(cap, "parent denies this path"));
            }
            Some((a, _)) => a,
        };
        if !access.is_subset_of(parent_access) {
            return Err(AttenuationError::new(
                cap,
                "requested access exceeds the parent's access for this path",
            ));
        }

        // 1b. FR-008 protected regions are injected at compile time, *after* this check, and a
        // more-specific rule out-ranks them at load. A broad parent grant must therefore not let a
        // child reach into `~/.ssh` (or write `.git`) by naming it precisely.
        self.check_protected(cap, pc, access)?;

        // 2. Any parent rule that REDUCES access *inside* pc must be replicated by the child.
        for (pr, &pa) in &self.filesystem {
            let reduces = !access.is_subset_of(pa); // deny, or a lesser grant
            if !reduces {
                continue;
            }
            match region_of(pr) {
                Some(Region::Prefix(pd)) if prefix_contains(pc, &pd) && pd.as_slice() != pc => {
                    if !child_replicates_prefix(child, &pd, pa) {
                        return Err(AttenuationError::new(
                            cap,
                            "parent restricts a path inside this grant; child must replicate that restriction",
                        ));
                    }
                }
                // A parent glob restriction could intersect pc; require the child replicates it.
                Some(Region::Glob(kind, bytes))
                    if !child_replicates_glob(child, kind, &bytes, pa) =>
                {
                    return Err(AttenuationError::new(
                        cap,
                        "parent has a glob restriction that may intersect this grant; child must replicate it",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Refuse a child grant that lands inside an FR-008 protected region, unless the protected
    /// default already permits that access (`.git` is read-only, not denied) or the parent named a
    /// region inside the protected one explicitly — an override the operator authored, which the
    /// child is merely inheriting rather than inventing.
    fn check_protected(
        &self,
        cap: &str,
        pc: &[u8],
        access: Access,
    ) -> Result<(), AttenuationError> {
        for (raw, protected) in PROTECTED_DEFAULTS {
            let Some(Region::Prefix(pp)) = region_of(raw) else {
                continue; // the table holds concrete paths; a glob there would be a bug.
            };
            if !prefix_contains(&pp, pc) {
                continue;
            }
            if protected.grants(access.to_bits()) {
                continue; // e.g. reading `.git`, which the default allows.
            }
            let overridden = self.filesystem.iter().any(|(pr, &pa)| {
                pa != Access::Deny
                    && access.is_subset_of(pa)
                    && matches!(region_of(pr), Some(Region::Prefix(pe))
                        if prefix_contains(&pp, &pe) && prefix_contains(&pe, pc))
            });
            if !overridden {
                return Err(AttenuationError::new(
                    cap,
                    format!(
                        "path lies inside the protected region '{raw}' (FR-008); \
                         the parent must grant it explicitly for a child to receive it"
                    ),
                ));
            }
        }
        Ok(())
    }

    fn check_exec(&self, request: &Policy) -> Result<(), AttenuationError> {
        for entry in &request.exec.allow {
            let name = entry.strip_prefix('!').unwrap_or(entry);
            let ok = self
                .exec
                .allow
                .iter()
                .any(|p| p.strip_prefix('!').unwrap_or(p) == name);
            if !ok {
                return Err(AttenuationError::new(
                    format!("exec:{name}"),
                    "executable not in parent's allowlist",
                ));
            }
        }
        Ok(())
    }

    fn check_network(&self, request: &Policy) -> Result<(), AttenuationError> {
        for entry in &request.network.allow {
            if !self.network.allow.iter().any(|p| p == entry) {
                return Err(AttenuationError::new(
                    format!("network:{entry}"),
                    "destination not in parent's allowlist",
                ));
            }
        }
        Ok(())
    }
}

fn child_replicates_prefix(
    child: &BTreeMap<String, Access>,
    pd: &[u8],
    parent_access: Access,
) -> bool {
    child.iter().any(|(cr, &ca)| {
        ca.is_subset_of(parent_access)
            && matches!(region_of(cr), Some(Region::Prefix(cp)) if prefix_contains(&cp, pd))
    })
}

fn child_replicates_glob(
    child: &BTreeMap<String, Access>,
    kind: u8,
    bytes: &[u8],
    parent_access: Access,
) -> bool {
    child.iter().any(|(cr, &ca)| {
        ca.is_subset_of(parent_access) && region_of(cr) == Some(Region::Glob(kind, bytes.to_vec()))
    })
}
