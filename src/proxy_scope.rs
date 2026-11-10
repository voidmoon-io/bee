//! A proxy scope: the kernel scope the interception worker runs in (019 P4), one per sandbox that
//! intercepts — a session's tool scope, and each subagent whose derived policy has an active
//! `[policy.http]` (026, 019 T092).
//!
//! # Resolve-and-admit (026 research R9)
//!
//! The kernel matches addresses, never names, so `[policy.http]` hosts used to be pinned to the
//! addresses they resolved to when the policy compiled. A CDN-backed host that moved mid-session
//! was then refused (`refused_address_drift`), or reached nothing.
//!
//! Now the worker resolves nothing itself; it asks bee (`FromWorker::Resolve`). For a proxy scope,
//! bee:
//!
//! 1. refuses a name that is not one of the scope's declared targets or egress hosts;
//! 2. resolves it;
//! 3. when an address is not yet in the scope's kernel rules, **reloads the proxy scope** with it
//!    added — at most [`MAX_ADMITTED_PER_HOST`] per name, the oldest evicted beyond that — and
//!    records the reload;
//! 4. answers only once the reload has taken effect.
//!
//! The worker connects only to addresses in an answer, so every upstream connection is to an
//! address the kernel admitted for a declared name. [`Admissions`] is that bookkeeping, pure so a
//! host test can drive it; [`ProxyScope`] applies it to a live kernel scope.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;

use bee_core::compiler::{CompiledNet, HttpScope};

/// Addresses a proxy scope holds for one name. Past this, the oldest is evicted at the next admit.
pub const MAX_ADMITTED_PER_HOST: usize = 16;

/// Which names a proxy scope declares, on which ports, and which addresses its kernel rules hold
/// for each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admissions {
    ports: BTreeMap<String, BTreeSet<u16>>,
    /// Oldest first. Seeded with the compile-time addresses.
    held: BTreeMap<String, VecDeque<IpAddr>>,
}

/// What admitting one lookup changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admitted {
    /// The answer for the worker: the looked-up addresses the kernel holds for the name, in the
    /// resolver's order.
    pub answer: Vec<IpAddr>,
    /// Addresses this lookup added. Non-empty means the scope must be reloaded.
    pub added: Vec<IpAddr>,
    /// Addresses dropped to stay within [`MAX_ADMITTED_PER_HOST`].
    pub evicted: Vec<IpAddr>,
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

impl Admissions {
    /// The names `scope` declares, holding the addresses they compiled to.
    pub fn new(scope: &HttpScope) -> Admissions {
        let mut a = Admissions::default();
        a.redeclare(scope);
        a
    }

    /// Replace the declared names with `scope`'s (a consented widening, 019 US3). A name still
    /// declared keeps what was admitted for it, and gains its compile-time addresses; a name no
    /// longer declared is dropped with everything held for it.
    pub fn redeclare(&mut self, scope: &HttpScope) {
        let mut ports: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
        let mut held: BTreeMap<String, VecDeque<IpAddr>> = BTreeMap::new();
        for e in scope.targets.iter().chain(&scope.egress) {
            let host = normalize(&e.host);
            ports.entry(host.clone()).or_default().insert(e.port);
            let q = held
                .entry(host.clone())
                .or_insert_with(|| self.held.get(&host).cloned().unwrap_or_default());
            for a in &e.resolved {
                if !q.contains(a) {
                    q.push_back(*a);
                }
            }
        }
        self.ports = ports;
        self.held = held;
    }

    /// Whether `host` is declared.
    pub fn declares(&self, host: &str) -> bool {
        self.ports.contains_key(&normalize(host))
    }

    /// What admitting `addrs` for `host` would hold, without changing `self`. `Err` for a name the
    /// scope does not declare: nothing is resolved into a scope for a name nobody approved.
    pub fn propose(&self, host: &str, addrs: &[IpAddr]) -> Result<(Admissions, Admitted), String> {
        let key = normalize(host);
        let Some(current) = self.held.get(&key) else {
            return Err(format!(
                "{host} is not one of this proxy scope's targets or egress hosts"
            ));
        };
        let mut q = current.clone();
        let mut added = Vec::new();
        for a in addrs.iter().take(MAX_ADMITTED_PER_HOST) {
            if !q.contains(a) && !added.contains(a) {
                q.push_back(*a);
                added.push(*a);
            }
        }
        let mut evicted = Vec::new();
        while q.len() > MAX_ADMITTED_PER_HOST {
            if let Some(old) = q.pop_front() {
                evicted.push(old);
            }
        }
        let answer = addrs.iter().filter(|a| q.contains(a)).copied().collect();
        let mut next = self.clone();
        next.held.insert(key, q);
        Ok((
            next,
            Admitted {
                answer,
                added,
                evicted,
            },
        ))
    }

    /// The scope's kernel network rules: every held address on every declared port of its name.
    pub fn net(&self) -> Vec<CompiledNet> {
        let mut net: Vec<CompiledNet> = Vec::new();
        for (host, ports) in &self.ports {
            for addr in self.held.get(host).into_iter().flatten() {
                for port in ports {
                    let n = CompiledNet {
                        addr: *addr,
                        port: *port,
                    };
                    if !net.contains(&n) {
                        net.push(n);
                    }
                }
            }
        }
        net
    }

    /// What is held for `host`, oldest first.
    pub fn held(&self, host: &str) -> Vec<IpAddr> {
        self.held
            .get(&normalize(host))
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default()
    }
}

#[cfg(feature = "enforce")]
pub use live::{ProxyScope, ProxySnapshot};

#[cfg(feature = "enforce")]
mod live {
    use std::net::IpAddr;
    use std::sync::Mutex;

    use bee_core::compiler::{CompiledHttp, HttpScope};
    use bee_core::{CompiledPolicy, Mode};
    use bee_userspace::{EnforcementPlan, ReloadError, ScopeMode};

    use super::{Admissions, Admitted};
    use crate::supervisor::ScopeHandle;

    /// A live proxy scope on the session's supervisor, created as the userspace child of the tool
    /// scope it serves so it is torn down first (018). Shared: the sandbox owns it, and the
    /// worker's resolver reaches it through a `Weak` to admit addresses while tools run.
    pub struct ProxyScope {
        /// Tags this scope's audit events (`"proxy"`); the supervisor stamps it as their `scope_id`.
        pub label: String,
        scope: ScopeHandle,
        /// Every change to the scope's rules — an admit, a widening, a rollback — holds this lock
        /// across its reload, so they apply one at a time and `state` is always what is installed.
        state: Mutex<State>,
    }

    /// Everything needed to put a proxy scope back as it was (a failed widening's rollback).
    #[derive(Clone)]
    pub struct ProxySnapshot {
        base: CompiledPolicy,
        plan: EnforcementPlan,
        admissions: Admissions,
    }

    struct State {
        /// The compiled proxy scope; its `net` is replaced by `admissions.net()` on every install.
        base: CompiledPolicy,
        plan: EnforcementPlan,
        admissions: Admissions,
        /// Set when a reload could not be rolled back: the rules are then unknown, and the tool
        /// scope this proxy serves refuses every further child.
        poisoned: Option<String>,
    }

    fn plan_for(base: &CompiledPolicy, admissions: &Admissions) -> Result<EnforcementPlan, String> {
        let mut c = base.clone();
        c.net = admissions.net();
        let mode = match c.mode {
            Mode::Enforce => ScopeMode::Enforce,
            Mode::Observe => ScopeMode::Observe,
        };
        EnforcementPlan::prepare(&c, mode).map_err(|e| format!("proxy scope plan: {e}"))
    }

    impl ProxyScope {
        /// Create the proxy scope for `compiled` beside `tool_scope`, on its supervisor.
        pub fn create(
            tool_scope: &ScopeHandle,
            compiled: &CompiledHttp,
        ) -> Result<ProxyScope, String> {
            let admissions = Admissions::new(&compiled.http_scope);
            let plan = plan_for(&compiled.proxy_scope, &admissions)?;
            let scope = tool_scope
                .supervisor()
                .create_scope(
                    &format!("{}-proxy", tool_scope.id),
                    "proxy",
                    Some(tool_scope),
                    &plan,
                )
                .map_err(|e| format!("create proxy scope: {e}"))?;
            Ok(ProxyScope {
                label: "proxy".into(),
                scope,
                state: Mutex::new(State {
                    base: compiled.proxy_scope.clone(),
                    plan,
                    admissions,
                    poisoned: None,
                }),
            })
        }

        pub fn handle(&self) -> &ScopeHandle {
            &self.scope
        }

        /// Why the scope's rules are unknown, if a reload left them so.
        pub fn poisoned(&self) -> Option<String> {
            self.lock().poisoned.clone()
        }

        pub fn snapshot(&self) -> ProxySnapshot {
            let s = self.lock();
            ProxySnapshot {
                base: s.base.clone(),
                plan: s.plan.clone(),
                admissions: s.admissions.clone(),
            }
        }

        /// What is held for `host` now (tests and diagnostics).
        pub fn held(&self, host: &str) -> Vec<IpAddr> {
            self.lock().admissions.held(host)
        }

        /// Recompile for a widened `[policy.http]` (019 US3): `proxy` is its compiled proxy scope,
        /// `http` the worker's scope. Admitted addresses of names still declared are kept.
        pub fn rescope(&self, proxy: &CompiledPolicy, http: &HttpScope) -> Result<(), String> {
            let mut s = self.lock();
            let mut admissions = s.admissions.clone();
            admissions.redeclare(http);
            let plan = plan_for(proxy, &admissions)?;
            self.install(&mut s, plan, proxy.clone(), admissions)
        }

        /// Put back exactly what `snap` recorded.
        pub fn restore(&self, snap: &ProxySnapshot) -> Result<(), String> {
            let mut s = self.lock();
            self.install(
                &mut s,
                snap.plan.clone(),
                snap.base.clone(),
                snap.admissions.clone(),
            )
        }

        /// Resolve-and-admit (module docs): hold `addrs` for `host`, reloading the scope first when
        /// any is new. Returns once the kernel holds the answer.
        pub fn admit(&self, host: &str, addrs: &[IpAddr]) -> Result<Admitted, String> {
            let mut s = self.lock();
            let (next, admitted) = s.admissions.propose(host, addrs)?;
            if admitted.added.is_empty() && admitted.evicted.is_empty() {
                return Ok(admitted);
            }
            let plan = plan_for(&s.base, &next)?;
            let base = s.base.clone();
            self.install(&mut s, plan, base, next)?;
            Ok(admitted)
        }

        fn install(
            &self,
            s: &mut State,
            plan: EnforcementPlan,
            base: CompiledPolicy,
            admissions: Admissions,
        ) -> Result<(), String> {
            if let Some(why) = &s.poisoned {
                return Err(format!(
                    "proxy scope reload: already in an unknown state: {why}"
                ));
            }
            if let Err(e) = self.scope.reload(&plan) {
                if let ReloadError::Inconsistent(_) = e {
                    // The proxy scope is every tool child's egress path: unknown rules there are
                    // as unsafe as unknown rules on the tool scope itself.
                    s.poisoned = Some(format!("proxy scope: {e}"));
                }
                return Err(format!("proxy scope reload: {e}"));
            }
            s.plan = plan;
            s.base = base;
            s.admissions = admissions;
            Ok(())
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee_core::compiler::{EnforcedBy, Role, ScopeEntry};
    use bee_core::policy::HttpLimits;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn entry(host: &str, port: u16, ips: &[&str], role: Role) -> ScopeEntry {
        ScopeEntry {
            host: host.into(),
            port,
            resolved: ips.iter().map(|s| ip(s)).collect(),
            role,
            enforced_by: vec![EnforcedBy::Proxy { host: host.into() }],
        }
    }

    fn scope() -> HttpScope {
        HttpScope {
            targets: vec![entry("app.test", 443, &["127.0.0.2"], Role::Target)],
            egress: vec![entry("prov.test", 8443, &["127.0.0.5"], Role::Egress)],
            inspect: vec![],
            insecure_upstream: vec![],
            limits: HttpLimits::default(),
        }
    }

    fn has(net: &[CompiledNet], addr: &str, port: u16) -> bool {
        net.contains(&CompiledNet {
            addr: ip(addr),
            port,
        })
    }

    #[test]
    fn the_compiled_addresses_are_held_from_the_start() {
        let a = Admissions::new(&scope());
        let net = a.net();
        assert_eq!(net.len(), 2);
        assert!(has(&net, "127.0.0.2", 443));
        assert!(has(&net, "127.0.0.5", 8443));
    }

    #[test]
    fn an_undeclared_name_is_refused() {
        let a = Admissions::new(&scope());
        let err = a.propose("other.test", &[ip("127.0.0.9")]).unwrap_err();
        assert!(err.contains("other.test"), "{err}");
    }

    #[test]
    fn a_new_address_is_added_on_the_names_ports_only() {
        let a = Admissions::new(&scope());
        let (next, admitted) = a.propose("PROV.test.", &[ip("127.0.0.6")]).unwrap();
        assert_eq!(admitted.added, vec![ip("127.0.0.6")]);
        assert_eq!(admitted.answer, vec![ip("127.0.0.6")]);
        let net = next.net();
        assert!(has(&net, "127.0.0.6", 8443));
        assert!(!has(&net, "127.0.0.6", 443), "not on another name's port");
        assert!(has(&net, "127.0.0.5", 8443), "the old address stays");
    }

    #[test]
    fn a_held_address_adds_nothing() {
        let a = Admissions::new(&scope());
        let (next, admitted) = a.propose("prov.test", &[ip("127.0.0.5")]).unwrap();
        assert!(admitted.added.is_empty() && admitted.evicted.is_empty());
        assert_eq!(admitted.answer, vec![ip("127.0.0.5")]);
        assert_eq!(next, a);
    }

    #[test]
    fn past_the_bound_the_oldest_is_evicted() {
        let mut a = Admissions::new(&scope());
        for i in 0..MAX_ADMITTED_PER_HOST {
            let (next, _) = a
                .propose("prov.test", &[ip(&format!("10.0.0.{}", i + 1))])
                .unwrap();
            a = next;
        }
        let held = a.held("prov.test");
        assert_eq!(held.len(), MAX_ADMITTED_PER_HOST);
        assert!(
            !held.contains(&ip("127.0.0.5")),
            "the compile-time address was the oldest"
        );
        let (next, admitted) = a.propose("prov.test", &[ip("10.0.1.1")]).unwrap();
        assert_eq!(admitted.evicted, vec![ip("10.0.0.1")]);
        assert_eq!(next.held("prov.test").len(), MAX_ADMITTED_PER_HOST);
        assert!(!has(&next.net(), "10.0.0.1", 8443));
    }

    #[test]
    fn a_widening_keeps_what_was_admitted_for_names_still_declared() {
        let a = Admissions::new(&scope());
        let (mut a, _) = a.propose("prov.test", &[ip("127.0.0.6")]).unwrap();
        let mut wider = scope();
        wider
            .targets
            .push(entry("new.test", 443, &["127.0.0.7"], Role::Target));
        a.redeclare(&wider);
        assert!(a.held("prov.test").contains(&ip("127.0.0.6")));
        assert!(a.declares("new.test"));

        let mut narrower = scope();
        narrower.egress.clear();
        a.redeclare(&narrower);
        assert!(!a.declares("prov.test"));
        assert!(!has(&a.net(), "127.0.0.6", 8443));
    }
}
