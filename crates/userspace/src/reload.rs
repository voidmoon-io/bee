//! Transactional re-population of a live scope's rule maps (007-dynamic-grants).
//!
//! A reload touches four maps in sequence. Applied naively, a failure partway leaves some of them
//! holding the new policy and some the old — and since the caller is told the reload failed, it goes
//! on believing the old policy is in force while the kernel enforces a mixture. For `NET_ALLOW` that
//! mixture can be *wider* than either policy: an inserted destination nobody tracks, which no later
//! narrowing removes (VULN-FINDINGS-current F-001).
//!
//! Two rules close that:
//!
//! 1. **Diff against the kernel, not a memory of it.** The scope's installed `NET_ALLOW` keys are
//!    read back from the map on every reload. There is no userspace ledger to fall out of step, so a
//!    key orphaned by any earlier failure is removed by the next successful reload.
//! 2. **All or nothing.** Every write is recorded beside its inverse. Any failure replays the inverses
//!    newest-first and returns [`ReloadError::Refused`] with the maps as they were. If an inverse
//!    itself fails, the scope's state is unknown and the error is [`ReloadError::Inconsistent`] — the
//!    caller must stop running anything in that scope.
//!
//! The logic is written against [`ScopeMaps`] rather than aya so the rollback paths — which need a map
//! write to fail on demand — are testable on a host with no kernel.

use bee_common::layout::{DenyList, NetKey, ScopeMeta};
use thiserror::Error;

use crate::EnforcementPlan;

/// The per-scope rule maps, as a reload sees them. Errors are strings because the only thing a
/// caller does with one is report it.
pub trait ScopeMaps {
    fn meta(&self, cgroup_id: u64) -> Result<Option<ScopeMeta>, String>;
    fn set_meta(&mut self, cgroup_id: u64, meta: ScopeMeta) -> Result<(), String>;

    fn fs(&self, cgroup_id: u64) -> Result<Option<DenyList>, String>;
    fn set_fs(&mut self, cgroup_id: u64, rules: DenyList) -> Result<(), String>;
    fn remove_fs(&mut self, cgroup_id: u64) -> Result<(), String>;

    fn exec(&self, cgroup_id: u64) -> Result<Option<DenyList>, String>;
    fn set_exec(&mut self, cgroup_id: u64, rules: DenyList) -> Result<(), String>;
    fn remove_exec(&mut self, cgroup_id: u64) -> Result<(), String>;

    /// Every `NET_ALLOW` key currently installed for `cgroup_id`.
    fn net_keys(&self, cgroup_id: u64) -> Result<Vec<NetKey>, String>;
    fn insert_net(&mut self, key: NetKey) -> Result<(), String>;
    fn remove_net(&mut self, key: &NetKey) -> Result<(), String>;
}

/// Why a reload did not take effect.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReloadError {
    /// Nothing changed: the reload was refused before any write, or every write was rolled back.
    #[error("reload refused, prior rules left in force: {0}")]
    Refused(String),
    /// A write failed and so did undoing it. The scope's rules are a mixture of the two policies and
    /// may be wider than either. Nothing further may run in this scope.
    #[error("reload failed and could not be rolled back; scope state unknown: {0}")]
    Inconsistent(String),
}

/// One applied write, held as what it takes to reverse it.
enum Undo {
    Meta(ScopeMeta),
    Fs(Option<DenyList>),
    Exec(Option<DenyList>),
    NetInserted(NetKey),
    NetRemoved(NetKey),
}

/// Make `cgroup_id`'s rules exactly `plan`, or leave them exactly as they were.
///
/// Caller preconditions are those of `Engine::reload_scope`: nothing is executing in the scope, and
/// `plan` was compiled from a policy already validated `⊆ ceiling`.
pub fn apply<M: ScopeMaps>(
    maps: &mut M,
    cgroup_id: u64,
    plan: &EnforcementPlan,
) -> Result<(), ReloadError> {
    // Read everything before writing anything, so a read failure refuses with nothing to undo.
    let read = |e: String| ReloadError::Refused(e);
    let prev_meta = maps
        .meta(cgroup_id)
        .map_err(read)?
        .ok_or_else(|| ReloadError::Refused(format!("cgroup {cgroup_id} is not a live scope")))?;
    let prev_fs = maps.fs(cgroup_id).map_err(read)?;
    let prev_exec = maps.exec(cgroup_id).map_err(read)?;
    let installed = maps.net_keys(cgroup_id).map_err(read)?;

    let wanted: Vec<NetKey> = plan
        .net_rules
        .iter()
        .map(|t| NetKey { cgroup_id, ..*t })
        .collect();

    let mut undo: Vec<Undo> = Vec::new();
    match write_all(
        maps, cgroup_id, plan, &wanted, &installed, prev_meta, prev_fs, prev_exec, &mut undo,
    ) {
        Ok(()) => Ok(()),
        Err(cause) => match roll_back(maps, cgroup_id, undo) {
            Ok(()) => Err(ReloadError::Refused(cause)),
            Err(undo_err) => Err(ReloadError::Inconsistent(format!(
                "{cause}; rollback: {undo_err}"
            ))),
        },
    }
}

/// The forward writes. Additions go in before anything is narrowed and removals come last, so the
/// only failure most likely in practice — a full `NET_ALLOW` — is hit while there is the least to
/// undo.
#[allow(clippy::too_many_arguments)]
fn write_all<M: ScopeMaps>(
    maps: &mut M,
    cgroup_id: u64,
    plan: &EnforcementPlan,
    wanted: &[NetKey],
    installed: &[NetKey],
    prev_meta: ScopeMeta,
    prev_fs: Option<DenyList>,
    prev_exec: Option<DenyList>,
    undo: &mut Vec<Undo>,
) -> Result<(), String> {
    for key in wanted.iter().filter(|k| !installed.contains(k)) {
        maps.insert_net(*key)?;
        undo.push(Undo::NetInserted(*key));
    }

    maps.set_meta(cgroup_id, plan.meta)?;
    undo.push(Undo::Meta(prev_meta));

    if plan.has_fs_rules {
        maps.set_fs(cgroup_id, plan.fs_rules)?;
    } else if prev_fs.is_some() {
        maps.remove_fs(cgroup_id)?;
    }
    undo.push(Undo::Fs(prev_fs));

    if plan.has_exec_rules {
        maps.set_exec(cgroup_id, plan.exec_rules)?;
    } else if prev_exec.is_some() {
        maps.remove_exec(cgroup_id)?;
    }
    undo.push(Undo::Exec(prev_exec));

    for key in installed.iter().filter(|k| !wanted.contains(k)) {
        maps.remove_net(key)?;
        undo.push(Undo::NetRemoved(*key));
    }
    Ok(())
}

/// Replay `undo` newest-first. Keeps going past a failure so as much as possible is restored, and
/// reports the first failure.
fn roll_back<M: ScopeMaps>(maps: &mut M, cgroup_id: u64, undo: Vec<Undo>) -> Result<(), String> {
    let mut first_err = None;
    for step in undo.into_iter().rev() {
        let r = match step {
            Undo::Meta(m) => maps.set_meta(cgroup_id, m),
            Undo::Fs(Some(d)) => maps.set_fs(cgroup_id, d),
            Undo::Fs(None) => maps.remove_fs(cgroup_id),
            Undo::Exec(Some(d)) => maps.set_exec(cgroup_id, d),
            Undo::Exec(None) => maps.remove_exec(cgroup_id),
            Undo::NetInserted(k) => maps.remove_net(&k),
            Undo::NetRemoved(k) => maps.insert_net(k),
        };
        if let Err(e) = r {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const CG: u64 = 7;
    const OTHER: u64 = 9;

    fn net(cgroup_id: u64, port: u16) -> NetKey {
        NetKey {
            cgroup_id,
            family: 2,
            port,
            _pad: [0; 4],
            addr: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn meta(flags: u8) -> ScopeMeta {
        ScopeMeta {
            mode: 0,
            flags,
            _pad: [0; 6],
        }
    }

    fn deny(count: u32) -> DenyList {
        DenyList {
            count,
            ..DenyList::EMPTY
        }
    }

    fn plan(
        flags: u8,
        fs: Option<DenyList>,
        exec: Option<DenyList>,
        ports: &[u16],
    ) -> EnforcementPlan {
        EnforcementPlan {
            meta: meta(flags),
            fs_rules: fs.unwrap_or(DenyList::EMPTY),
            has_fs_rules: fs.is_some(),
            exec_rules: exec.unwrap_or(DenyList::EMPTY),
            has_exec_rules: exec.is_some(),
            net_rules: ports.iter().map(|p| net(0, *p)).collect(),
        }
    }

    /// In-memory maps whose `fail_at`-th mutation (0-based, counting every mutation including
    /// rollback writes) fails, and every mutation after `fail_from` too.
    #[derive(Clone, Default, PartialEq, Debug)]
    struct Fake {
        meta: BTreeMap<u64, ScopeMeta>,
        fs: BTreeMap<u64, DenyList>,
        exec: BTreeMap<u64, DenyList>,
        net: BTreeSet<(u64, u16)>,
        #[allow(clippy::struct_field_names)]
        writes: usize,
        fail_at: Option<usize>,
        fail_from: Option<usize>,
    }

    impl Fake {
        fn tick(&mut self) -> Result<(), String> {
            let n = self.writes;
            self.writes += 1;
            if self.fail_at == Some(n) || self.fail_from.is_some_and(|f| n >= f) {
                return Err(format!("injected failure at write {n}"));
            }
            Ok(())
        }
        /// The enforced state, without the bookkeeping.
        fn state(&self) -> Fake {
            Fake {
                meta: self.meta.clone(),
                fs: self.fs.clone(),
                exec: self.exec.clone(),
                net: self.net.clone(),
                ..Fake::default()
            }
        }
    }

    impl ScopeMaps for Fake {
        fn meta(&self, c: u64) -> Result<Option<ScopeMeta>, String> {
            Ok(self.meta.get(&c).copied())
        }
        fn set_meta(&mut self, c: u64, m: ScopeMeta) -> Result<(), String> {
            self.tick()?;
            self.meta.insert(c, m);
            Ok(())
        }
        fn fs(&self, c: u64) -> Result<Option<DenyList>, String> {
            Ok(self.fs.get(&c).copied())
        }
        fn set_fs(&mut self, c: u64, d: DenyList) -> Result<(), String> {
            self.tick()?;
            self.fs.insert(c, d);
            Ok(())
        }
        fn remove_fs(&mut self, c: u64) -> Result<(), String> {
            self.tick()?;
            self.fs.remove(&c);
            Ok(())
        }
        fn exec(&self, c: u64) -> Result<Option<DenyList>, String> {
            Ok(self.exec.get(&c).copied())
        }
        fn set_exec(&mut self, c: u64, d: DenyList) -> Result<(), String> {
            self.tick()?;
            self.exec.insert(c, d);
            Ok(())
        }
        fn remove_exec(&mut self, c: u64) -> Result<(), String> {
            self.tick()?;
            self.exec.remove(&c);
            Ok(())
        }
        fn net_keys(&self, c: u64) -> Result<Vec<NetKey>, String> {
            Ok(self
                .net
                .iter()
                .filter(|(cg, _)| *cg == c)
                .map(|(cg, p)| net(*cg, *p))
                .collect())
        }
        fn insert_net(&mut self, k: NetKey) -> Result<(), String> {
            self.tick()?;
            self.net.insert((k.cgroup_id, k.port));
            Ok(())
        }
        fn remove_net(&mut self, k: &NetKey) -> Result<(), String> {
            self.tick()?;
            self.net.remove(&(k.cgroup_id, k.port));
            Ok(())
        }
    }

    /// A live scope holding fs + exec rules and egress to ports 1 and 2, beside an unrelated scope.
    fn live() -> Fake {
        let mut f = Fake::default();
        f.meta.insert(CG, meta(1));
        f.fs.insert(CG, deny(1));
        f.exec.insert(CG, deny(1));
        f.net.extend([(CG, 1), (CG, 2), (OTHER, 1), (OTHER, 3)]);
        f.meta.insert(OTHER, meta(1));
        f
    }

    /// Narrow fs away, change exec, and move egress from {1,2} to {2,3,4}: every kind of write.
    fn target() -> EnforcementPlan {
        plan(2, None, Some(deny(2)), &[2, 3, 4])
    }

    fn expected_after_target() -> Fake {
        let mut f = live();
        f.meta.insert(CG, meta(2));
        f.fs.remove(&CG);
        f.exec.insert(CG, deny(2));
        f.net.remove(&(CG, 1));
        f.net.extend([(CG, 3), (CG, 4)]);
        f
    }

    #[test]
    fn a_clean_reload_installs_exactly_the_plan() {
        let mut f = live();
        apply(&mut f, CG, &target()).unwrap();
        assert_eq!(f.state(), expected_after_target().state());
    }

    #[test]
    fn a_failure_at_any_write_leaves_every_map_as_it_was() {
        // `target()` removes fs and sets exec; the second plan sets fs and removes exec. Between them
        // every kind of write is a failure point.
        for (name, p) in [
            ("target", target()),
            ("inverse", plan(1, Some(deny(3)), None, &[1])),
        ] {
            let mut probe = live();
            apply(&mut probe, CG, &p).unwrap();
            let total = probe.writes;
            assert!(total > 0, "{name}: plan made no writes");

            for k in 0..total {
                let mut f = Fake {
                    fail_at: Some(k),
                    ..live()
                };
                let err = apply(&mut f, CG, &p).unwrap_err();
                assert!(
                    matches!(err, ReloadError::Refused(_)),
                    "{name} write {k}: {err}"
                );
                assert_eq!(f.state(), live().state(), "{name} write {k} left a mixture");
            }
        }
    }

    #[test]
    fn a_key_no_ledger_knows_about_is_still_removed() {
        // F-001: an earlier failed reload left port 9 installed with nothing in userspace tracking
        // it. Reading the installed set from the map is what lets a later narrowing see it.
        let mut f = live();
        f.net.insert((CG, 9));
        apply(&mut f, CG, &target()).unwrap();
        assert!(
            !f.net.contains(&(CG, 9)),
            "orphaned egress key survived the reload"
        );
        assert_eq!(f.state(), expected_after_target().state());
    }

    #[test]
    fn other_scopes_are_never_touched() {
        let mut f = live();
        apply(&mut f, CG, &plan(1, None, None, &[])).unwrap();
        assert!(f.net.contains(&(OTHER, 1)) && f.net.contains(&(OTHER, 3)));
        assert_eq!(f.meta.get(&OTHER), Some(&meta(1)));
    }

    #[test]
    fn an_unregistered_cgroup_is_refused_before_any_write() {
        let mut f = live();
        let err = apply(&mut f, 42, &target()).unwrap_err();
        assert!(matches!(err, ReloadError::Refused(_)));
        assert_eq!(f.writes, 0);
    }

    #[test]
    fn a_failed_rollback_is_reported_as_inconsistent() {
        // Fail the last forward write, then everything after it — i.e. every undo.
        let mut probe = live();
        apply(&mut probe, CG, &target()).unwrap();
        let last = probe.writes - 1;
        let mut f = Fake {
            fail_from: Some(last),
            ..live()
        };
        let err = apply(&mut f, CG, &target()).unwrap_err();
        assert!(matches!(err, ReloadError::Inconsistent(_)), "{err}");
    }
}
