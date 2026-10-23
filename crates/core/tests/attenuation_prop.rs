//! Property-based attenuation tests (T039 / SC-002): a derived policy can never exceed its parent.
//!
//! We assert both directions:
//! * **Completeness** — a child built as a construction-guaranteed subset is accepted.
//! * **Soundness** — a child that adds any capability the parent lacks is rejected.

use std::collections::BTreeMap;

use bee_core::policy::{Access, ExecPolicy, ExfilPolicy, Mode, NetPolicy};
use bee_core::Policy;
use proptest::prelude::*;

fn mk(mode: Mode, fs: BTreeMap<String, Access>, exec: Vec<String>, net: Vec<String>) -> Policy {
    Policy {
        name: "p".into(),
        description: None,
        mode,
        filesystem: fs,
        exec: ExecPolicy { allow: exec },
        network: NetPolicy { allow: net },
        defaults: Default::default(),
        exfiltration: ExfilPolicy::default(),
        http: None,
    }
}

// (id, is_write, keep_in_child)
fn specs() -> impl Strategy<Value = Vec<(u32, bool, bool)>> {
    prop::collection::vec((0u32..20, any::<bool>(), any::<bool>()), 0..8)
}

proptest! {
    #[test]
    fn subset_by_construction_is_accepted(s in specs()) {
        let mut parent_fs = BTreeMap::new();
        let mut child_fs = BTreeMap::new();
        for (id, is_write, keep) in &s {
            let path = format!("/proj/d{id}");
            parent_fs.insert(path.clone(), if *is_write { Access::Write } else { Access::Read });
            if *keep {
                // Read is a subset of both Read and Write, so this is always within parent.
                child_fs.insert(path, Access::Read);
            }
        }
        let parent = mk(Mode::Enforce, parent_fs, vec!["cargo".into(), "rustc".into()], vec!["crates.io:443".into()]);
        let child = mk(Mode::Enforce, child_fs, vec!["cargo".into()], vec![]);
        prop_assert!(parent.derive(child).is_ok(), "constructed subset must be accepted");
    }

    #[test]
    fn adding_outside_filesystem_grant_is_rejected(s in specs(), outside in 0u32..50) {
        let mut parent_fs = BTreeMap::new();
        for (id, is_write, _) in &s {
            parent_fs.insert(format!("/proj/d{id}"), if *is_write { Access::Write } else { Access::Read });
        }
        // Child = an exact copy of the parent's grants (⊆) PLUS one grant outside any parent region.
        let mut child_fs = parent_fs.clone();
        child_fs.insert(format!("/outside/x{outside}"), Access::Write);
        let parent = mk(Mode::Enforce, parent_fs, vec![], vec![]);
        let child = mk(Mode::Enforce, child_fs, vec![], vec![]);
        prop_assert!(parent.derive(child).is_err(), "a grant outside every parent region must be rejected");
    }

    #[test]
    fn adding_exec_not_in_parent_is_rejected(s in specs()) {
        let mut parent_fs = BTreeMap::new();
        for (id, is_write, _) in &s {
            parent_fs.insert(format!("/proj/d{id}"), if *is_write { Access::Write } else { Access::Read });
        }
        let parent = mk(Mode::Enforce, parent_fs.clone(), vec!["cargo".into()], vec![]);
        // "curl" is never in the parent's allowlist.
        let child = mk(Mode::Enforce, parent_fs, vec!["cargo".into(), "curl".into()], vec![]);
        prop_assert!(parent.derive(child).is_err());
    }
}

// ── Scanner grants (016-native-tools, Constitution II gate / T064) ───────────────────────────────
//
// The external scanner tier gave `ExecPolicy.allow` a new class of occupant: an inode-pinned
// third-party analysis binary, granted so an episode can run it over the code bee is meant to be
// securing. That is a capability like any other, and the whole point of routing it through the
// ordinary derive path is that no sequence of grants can widen past the ceiling.
//
// Phrased in core's own terms — a pinned exec entry — because `bee-core` does not know what a
// "scanner" is, and should not. What it knows is that an executable a parent never allowed cannot
// appear in a child, at any depth, however many derivations it took to get there.

/// Candidate scanner binaries, and which of them the ceiling admits.
fn scanner_sets() -> impl Strategy<Value = (Vec<usize>, Vec<usize>)> {
    (
        prop::collection::vec(0usize..6, 1..5),
        prop::collection::vec(0usize..6, 0..5),
    )
}

fn scanner_path(id: usize) -> String {
    format!("/opt/scanners/s{id}")
}

proptest! {
    /// **Soundness.** However long the chain of derivations, the surviving exec allowlist never
    /// names a binary the ceiling did not.
    #[test]
    fn no_sequence_of_scanner_grants_escapes_the_ceiling((ceiling_ids, requested) in scanner_sets()) {
        let ceiling_allow: Vec<String> =
            ceiling_ids.iter().map(|id| format!("!{}", scanner_path(*id))).collect();
        let ceiling = mk(Mode::Enforce, BTreeMap::new(), ceiling_allow, vec![]);

        // Each requested scanner is asked for in its own derivation, so this tests the *sequence*
        // rather than one big request — an escalation path that widened a step at a time would slip
        // past a single-shot check.
        let mut active = ceiling.clone();
        for id in &requested {
            let step = mk(
                Mode::Enforce,
                BTreeMap::new(),
                vec![format!("!{}", scanner_path(*id))],
                vec![],
            );
            match active.clone().derive(step) {
                Ok(next) => active = next,
                // A refusal is a correct outcome; what must never happen is acceptance of something
                // outside the ceiling, which the assertion below checks for whatever survived.
                Err(_) => continue,
            }
        }

        for entry in &active.exec.allow {
            let name = entry.strip_prefix('!').unwrap_or(entry);
            prop_assert!(
                ceiling_ids.iter().any(|id| scanner_path(*id) == name),
                "`{name}` survived a derivation chain but is not in the ceiling"
            );
        }
    }

    /// A scanner the ceiling never named is refused, no matter how much legitimate company it keeps.
    #[test]
    fn a_scanner_outside_the_ceiling_is_refused(ceiling_ids in prop::collection::vec(0usize..6, 1..5)) {
        let ceiling_allow: Vec<String> =
            ceiling_ids.iter().map(|id| format!("!{}", scanner_path(*id))).collect();
        let ceiling = mk(Mode::Enforce, BTreeMap::new(), ceiling_allow.clone(), vec![]);

        // Every granted scanner, plus one that was never granted.
        let mut child_allow = ceiling_allow;
        child_allow.push("!/opt/scanners/never-granted".to_string());
        let child = mk(Mode::Enforce, BTreeMap::new(), child_allow, vec![]);

        prop_assert!(
            ceiling.derive(child).is_err(),
            "an ungranted scanner must be refused even alongside granted ones"
        );
    }

    /// Dropping the `!` cannot launder a pinned grant into an unpinned one.
    ///
    /// This matters more for a scanner than for anything else in the allowlist: an unpinned entry
    /// authorises the *path*, so a binary swapped at that path still runs — the exact substitution
    /// SC-010 exists to forbid. A child that asks for the same scanner without the pin must inherit
    /// the pin rather than shed it.
    #[test]
    fn a_child_cannot_unpin_a_scanner_it_inherited(ids in prop::collection::vec(0usize..6, 1..4)) {
        let ceiling_allow: Vec<String> =
            ids.iter().map(|id| format!("!{}", scanner_path(*id))).collect();
        let ceiling = mk(Mode::Enforce, BTreeMap::new(), ceiling_allow, vec![]);

        let unpinned: Vec<String> = ids.iter().map(|id| scanner_path(*id)).collect();
        let child = mk(Mode::Enforce, BTreeMap::new(), unpinned, vec![]);

        let derived = ceiling.derive(child).expect("naming the same binaries is a subset");
        for entry in &derived.exec.allow {
            prop_assert!(
                entry.starts_with('!'),
                "`{entry}` lost its inode pin through derivation"
            );
        }
    }
}
