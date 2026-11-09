//! The Supervisor (018-subagent-scopes): the one owner of a session's enforcement engine and its
//! audit ring. Every kernel scope the session uses — the tool scope, the interception proxy's scope,
//! a concurrent batch's episodes, and later its subagents — is created, reloaded, drained and torn
//! down through it.
//!
//! # Why one owner
//!
//! The kernel has one `AUDIT_RB` ring for every scope, and the engine's loaded object must outlive
//! every scope it enforces: dropping it detaches the LSM programs, and anything still running is
//! then unenforced. So scopes cannot each own an engine, and two readers cannot share the ring
//! without racing for its records. The supervisor holds both, behind locks; a [`ScopeHandle`] is
//! what a sandbox holds instead.
//!
//! # Audit is routed when a scope drains, not in the background
//!
//! A scope's drain reads everything the ring holds *now*, files each event under the scope it
//! belongs to, and returns its own. Any event the kernel wrote before the drain is therefore in it,
//! which reactive escalation depends on: a denial must be visible in the call that caused it. An
//! asynchronous demultiplexer cannot promise that without waiting, so the supervisor does not use
//! one. Events for a cgroup no scope has registered are dropped, as they always were.
//!
//! # Scopes are flat
//!
//! Every cgroup is created directly under [`cgroup::DEFAULT_PARENT`], whatever the userspace
//! parent. **Do not nest a child scope inside its parent's cgroup.** The kernel resolves a process
//! to a scope by trying its own cgroup, then walking ancestors from the root down and taking the
//! *shallowest* registered one. A subagent nested in its parent that creates a sub-cgroup and moves
//! into it would resolve to the **parent** — broader rules, enforced and audited as if correct.
//! Flat, the child scope is the only scope ancestor, so the same move still lands on the child
//! (specs/018-subagent-scopes/research.md R5). The parent relation lives here, in userspace, and
//! orders teardown: children first, because no cgroup kill reaps a sibling.

use std::collections::BTreeMap;

/// The order to tear `id`'s subtree down in: every descendant before its parent, `id` last. Ids not
/// in `parents` are ignored; a cycle cannot form because a record's parent must exist when it is
/// created.
#[cfg_attr(not(feature = "enforce"), allow(dead_code))]
fn teardown_order(parents: &BTreeMap<String, Option<String>>, id: &str) -> Vec<String> {
    fn visit(parents: &BTreeMap<String, Option<String>>, id: &str, out: &mut Vec<String>) {
        for (child, parent) in parents {
            if parent.as_deref() == Some(id) {
                visit(parents, child, out);
            }
        }
        out.push(id.to_string());
    }
    let mut out = Vec::new();
    if parents.contains_key(id) {
        visit(parents, id, &mut out);
    }
    out
}

#[cfg(feature = "enforce")]
pub use enforce::{Drained, ScopeHandle, Supervisor};

#[cfg(feature = "enforce")]
mod enforce {
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use bee_core::AuditEvent;
    use bee_userspace::events::AuditReader;
    use bee_userspace::{cgroup, EnforcementPlan, Engine, ReloadError};

    /// Events held for one scope between its drains. Past this, later events are counted as dropped.
    const PENDING_MAX: usize = 16_384;
    /// Ring reads per drain (each reads up to 4096 records). A ring still not empty after them is
    /// reported as a limited drain rather than read without bound.
    const DRAIN_ROUNDS: usize = 4;

    /// The session's enforcement owner. Cheap to clone; every clone is the same supervisor.
    #[derive(Clone)]
    pub struct Supervisor {
        inner: Arc<Inner>,
    }

    struct Inner {
        // Fields drop in declaration order. The engine is last: by the time it drops nothing else
        // refers to a scope, and its own `Drop` kills every scope cgroup it created before it
        // detaches — or keeps the programs attached if one will not empty.
        scopes: Mutex<BTreeMap<String, Record>>,
        audit: Mutex<Router>,
        engine: Mutex<Engine>,
    }

    struct Record {
        cgroup_id: u64,
        path: PathBuf,
        parent: Option<String>,
    }

    struct Router {
        reader: AuditReader,
        pending: HashMap<u64, Pending>,
    }

    struct Pending {
        /// Stamped as each event's `scope_id`.
        label: String,
        events: Vec<AuditEvent>,
        dropped: u64,
    }

    /// What one drain returned.
    #[derive(Debug, Default)]
    pub struct Drained {
        pub events: Vec<AuditEvent>,
        /// Events this scope lost since its last drain because its pending buffer was full.
        pub dropped: u64,
        /// The ring still held records when the drain stopped reading.
        pub limited: bool,
    }

    /// One live scope: its cgroup, and the supervisor that owns it. This is what a sandbox holds.
    pub struct ScopeHandle {
        supervisor: Supervisor,
        pub id: String,
        pub cgroup_id: u64,
        pub path: PathBuf,
    }

    impl Supervisor {
        /// Attach the engine and take the audit ring. Fails closed on a kernel that cannot enforce.
        pub fn start() -> Result<Supervisor, String> {
            let mut engine = Engine::init().map_err(|e| format!("engine init: {e}"))?;
            // The reader's own scope id is never seen: every event is restamped with the label of
            // the scope it is routed to.
            let reader = engine
                .take_audit_reader("bee")
                .map_err(|e| format!("audit reader: {e}"))?;
            Ok(Supervisor {
                inner: Arc::new(Inner {
                    scopes: Mutex::new(BTreeMap::new()),
                    audit: Mutex::new(Router {
                        reader,
                        pending: HashMap::new(),
                    }),
                    engine: Mutex::new(engine),
                }),
            })
        }

        /// Create a scope from an already compiled and validated `plan`. A plan is the only input:
        /// there is no way to get a scope without having compiled a policy, and for a subagent that
        /// policy can only have come from attenuation.
        ///
        /// `label` is what this scope's audit events carry as `scope_id`. `parent` is bookkeeping
        /// only — teardown order and attribution; the cgroup is always flat (module docs). On error
        /// nothing is left behind.
        pub fn create_scope(
            &self,
            id: &str,
            label: &str,
            parent: Option<&ScopeHandle>,
            plan: &EnforcementPlan,
        ) -> Result<ScopeHandle, String> {
            let parent = parent.map(|p| p.id.clone());
            let mut scopes = self.inner.scopes.lock().expect("supervisor scopes");
            if scopes.contains_key(id) {
                return Err(format!("create scope: '{id}' already exists"));
            }
            if let Some(p) = &parent {
                if !scopes.contains_key(p) {
                    return Err(format!("create scope: parent '{p}' is not live"));
                }
            }
            let created = self
                .inner
                .engine
                .lock()
                .expect("supervisor engine")
                .create_scope(id, cgroup::DEFAULT_PARENT, plan);
            let scope = match created {
                Ok(s) => s,
                Err(e) => {
                    // The cgroup may exist even though registering it failed.
                    let path = PathBuf::from(cgroup::DEFAULT_PARENT).join(id);
                    if path.exists() {
                        let _ = cgroup::kill_scope_cgroup(&path);
                        let _ = cgroup::teardown_scope_cgroup(&path);
                    }
                    return Err(format!("create scope: {e}"));
                }
            };
            // Registered before any process can join, so the scope's first event is kept.
            self.inner
                .audit
                .lock()
                .expect("supervisor audit")
                .pending
                .insert(
                    scope.cgroup_id,
                    Pending {
                        label: label.to_string(),
                        events: Vec::new(),
                        dropped: 0,
                    },
                );
            scopes.insert(
                id.to_string(),
                Record {
                    cgroup_id: scope.cgroup_id,
                    path: scope.path.clone(),
                    parent,
                },
            );
            Ok(ScopeHandle {
                supervisor: self.clone(),
                id: id.to_string(),
                cgroup_id: scope.cgroup_id,
                path: scope.path,
            })
        }

        fn reload(&self, cgroup_id: u64, plan: &EnforcementPlan) -> Result<(), ReloadError> {
            self.inner
                .engine
                .lock()
                .expect("supervisor engine")
                .reload_scope(cgroup_id, plan)
        }

        /// Read the ring, file every event under its scope, and return `cgroup_id`'s.
        fn drain(&self, cgroup_id: u64) -> Drained {
            let mut router = self.inner.audit.lock().expect("supervisor audit");
            let Router { reader, pending } = &mut *router;
            let mut exhausted = false;
            for _ in 0..DRAIN_ROUNDS {
                exhausted = reader.drain(&mut |mut ev| {
                    let Some(p) = pending.get_mut(&ev.cgroup_id) else {
                        return;
                    };
                    if p.events.len() >= PENDING_MAX {
                        p.dropped += 1;
                        return;
                    }
                    ev.scope_id = Some(p.label.clone());
                    p.events.push(ev);
                });
                if exhausted {
                    break;
                }
            }
            match pending.get_mut(&cgroup_id) {
                Some(p) => Drained {
                    events: std::mem::take(&mut p.events),
                    dropped: std::mem::take(&mut p.dropped),
                    limited: !exhausted,
                },
                None => Drained {
                    limited: !exhausted,
                    ..Drained::default()
                },
            }
        }

        /// Tear `id` and its userspace descendants down, children first: kill, stop routing its
        /// events, remove the cgroup. A scope that will not empty is reported and stays registered —
        /// the engine's own drop retries it, and keeps enforcing if it still cannot. Tearing down a
        /// scope that is already gone is not an error.
        fn teardown(&self, id: &str) -> Result<(), String> {
            let mut scopes = self.inner.scopes.lock().expect("supervisor scopes");
            let parents: BTreeMap<String, Option<String>> = scopes
                .iter()
                .map(|(k, r)| (k.clone(), r.parent.clone()))
                .collect();
            let mut errors = Vec::new();
            for victim in super::teardown_order(&parents, id) {
                let record = &scopes[&victim];
                let result = cgroup::kill_scope_cgroup(&record.path)
                    .and_then(|()| cgroup::teardown_scope_cgroup(&record.path));
                match result {
                    Ok(()) => {
                        let cg = record.cgroup_id;
                        scopes.remove(&victim);
                        self.inner
                            .audit
                            .lock()
                            .expect("supervisor audit")
                            .pending
                            .remove(&cg);
                    }
                    Err(e) => errors.push(format!("{victim}: {e}")),
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl ScopeHandle {
        /// The supervisor this scope belongs to.
        pub fn supervisor(&self) -> &Supervisor {
            &self.supervisor
        }

        /// A fork-safe `pre_exec` closure that joins the calling process to this scope's cgroup.
        pub fn join_closure(
            &self,
        ) -> std::io::Result<impl Fn() -> std::io::Result<()> + Send + Sync + 'static> {
            let procs = cgroup::procs_path_c(&self.path)?;
            Ok(move || cgroup::raw_join_self(&procs))
        }

        /// Replace this scope's rule maps with `plan` (007). See `Engine::reload_scope` for the
        /// all-or-nothing contract.
        pub fn reload(&self, plan: &EnforcementPlan) -> Result<(), ReloadError> {
            self.supervisor.reload(self.cgroup_id, plan)
        }

        /// This scope's kernel events since its last drain, each stamped with its label.
        pub fn drain(&self) -> Drained {
            self.supervisor.drain(self.cgroup_id)
        }

        /// Kill everything left in this scope and its descendants, then remove their cgroups.
        pub fn teardown(&self) -> Result<(), String> {
            self.supervisor.teardown(&self.id)
        }
    }

    /// Scopes cross into spawned tasks (the concurrent runner, and subagents).
    #[allow(dead_code)]
    fn _assert_send_sync(s: Supervisor, h: ScopeHandle) {
        fn both<T: Send + Sync>(_: T) {}
        both(s);
        both(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forest(edges: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<String>> {
        edges
            .iter()
            .map(|(k, p)| (k.to_string(), p.map(str::to_string)))
            .collect()
    }

    #[test]
    fn a_scope_is_torn_down_after_all_its_descendants() {
        let f = forest(&[
            ("root", None),
            ("proxy", Some("root")),
            ("sub-a", Some("root")),
            ("sub-a-1", Some("sub-a")),
            ("other", None),
        ]);
        let order = teardown_order(&f, "root");
        let pos = |s: &str| order.iter().position(|x| x == s).unwrap();
        assert_eq!(order.len(), 4, "only root's subtree: {order:?}");
        assert!(pos("sub-a-1") < pos("sub-a"));
        assert!(pos("sub-a") < pos("root"));
        assert!(pos("proxy") < pos("root"));
        assert_eq!(order.last().map(String::as_str), Some("root"));
    }

    #[test]
    fn tearing_down_a_leaf_touches_nothing_else() {
        let f = forest(&[("root", None), ("sub", Some("root"))]);
        assert_eq!(teardown_order(&f, "sub"), vec!["sub".to_string()]);
    }

    #[test]
    fn an_unknown_scope_has_nothing_to_tear_down() {
        let f = forest(&[("root", None)]);
        assert!(teardown_order(&f, "gone").is_empty());
    }
}
