//! 019-http-intercept T022 — `[policy.http]` attenuation (Constitution II, data-model.md
//! §Attenuation rules).
//!
//! Soundness: no derived child is ever outside its parent on targets, egress, inspect,
//! insecure_upstream or limits. Completeness: a child built as a subset by construction is accepted.
//! Silence inherits: a child that omits `[policy.http]` gets the parent's, never "no limits".

use bee_core::policy::{HostPattern, HostPort, HttpLimits, HttpPolicy};
use bee_core::Policy;
use proptest::prelude::*;

fn hp(host: &str, port: u16) -> HostPort {
    HostPort {
        host: host.into(),
        port,
    }
}

fn pat(s: &str) -> HostPattern {
    HostPattern::try_from(s.to_string()).unwrap()
}

fn policy(http: Option<HttpPolicy>) -> Policy {
    let mut p = Policy::from_toml("[policy]\nname = \"p\"\n").unwrap();
    p.http = http;
    p
}

fn parent_http() -> HttpPolicy {
    HttpPolicy {
        targets: vec![
            hp("a.test", 443),
            hp("b.app.test", 443),
            hp("10.0.0.5", 8080),
        ],
        egress: vec![hp("crates.io", 443)],
        inspect: vec![pat("*.app.test"), pat("a.test")],
        insecure_upstream: vec![pat("*.app.test")],
        limits: HttpLimits {
            rps: 10,
            concurrency: 4,
            max_requests_per_run: 2000,
            max_body_bytes: 1 << 24,
            store_cap_bytes: 1 << 31,
        },
    }
}

#[test]
fn an_absent_child_section_inherits_the_parents() {
    let parent = policy(Some(parent_http()));
    let derived = parent.derive(policy(None)).expect("silence is a subset");
    assert_eq!(derived.http, Some(parent_http()));
}

#[test]
fn a_child_cannot_add_http_under_a_parent_without_it() {
    let parent = policy(None);
    let child = policy(Some(HttpPolicy {
        targets: vec![hp("a.test", 443)],
        ..HttpPolicy::default()
    }));
    assert!(parent.derive(child).is_err());
}

#[test]
fn a_wildcard_child_under_an_exact_parent_is_rejected() {
    let parent = policy(Some(parent_http()));
    let mut h = parent_http();
    h.inspect = vec![pat("*.a.test")];
    assert!(parent.derive(policy(Some(h))).is_err());
}

#[test]
fn a_narrower_wildcard_is_covered() {
    let parent = policy(Some(parent_http()));
    let mut h = parent_http();
    h.inspect = vec![pat("*.x.app.test"), pat("x.app.test")];
    h.insecure_upstream = vec![pat("*.x.app.test")];
    assert!(parent.derive(policy(Some(h))).is_ok());
}

#[test]
fn a_target_may_not_be_downgraded_from_egress_into_target() {
    // Egress hosts are reachable but never testable; a child may not promote one.
    let parent = policy(Some(parent_http()));
    let mut h = parent_http();
    h.targets.push(hp("crates.io", 443));
    assert!(parent.derive(policy(Some(h))).is_err());
}

#[test]
fn a_child_may_move_a_target_into_egress() {
    // Reaching without testing is strictly less than testing.
    let parent = policy(Some(parent_http()));
    let mut h = parent_http();
    h.targets.retain(|t| t.host != "a.test");
    h.inspect.retain(|p| p.to_string() != "a.test");
    h.egress.push(hp("a.test", 443));
    assert!(parent.derive(policy(Some(h))).is_ok());
}

#[test]
fn higher_limits_are_rejected() {
    let parent = policy(Some(parent_http()));
    for bump in 0..5 {
        let mut h = parent_http();
        match bump {
            0 => h.limits.rps += 1,
            1 => h.limits.concurrency += 1,
            2 => h.limits.max_requests_per_run += 1,
            3 => h.limits.max_body_bytes += 1,
            _ => h.limits.store_cap_bytes += 1,
        }
        assert!(parent.derive(policy(Some(h))).is_err(), "bump {bump}");
    }
}

#[test]
fn undecidable_containment_is_rejected() {
    // A child pattern the parent can neither be shown to cover nor not to cover is refused. An
    // exact parent name never covers a wildcard, and wildcards over unrelated suffixes are disjoint.
    let parent = policy(Some(parent_http()));
    let mut h = parent_http();
    h.inspect = vec![pat("*.test")];
    assert!(parent.derive(policy(Some(h))).is_err());
}

// ── properties ──────────────────────────────────────────────────────────────────────────────────

const HOSTS: &[&str] = &[
    "a.test",
    "b.test",
    "c.app.test",
    "d.app.test",
    "10.0.0.1",
    "10.0.0.2",
];

fn pool() -> Vec<HostPort> {
    let mut v = Vec::new();
    for h in HOSTS {
        for port in [80u16, 443] {
            v.push(hp(h, port));
        }
    }
    v
}

fn subset_of(v: &[HostPort]) -> impl Strategy<Value = Vec<HostPort>> {
    let v = v.to_vec();
    prop::collection::vec(any::<bool>(), v.len()).prop_map(move |keep| {
        v.iter()
            .zip(keep)
            .filter(|(_, k)| *k)
            .map(|(h, _)| h.clone())
            .collect()
    })
}

fn limits_le(p: HttpLimits) -> impl Strategy<Value = HttpLimits> {
    (
        1..=p.rps,
        1..=p.concurrency,
        1..=p.max_requests_per_run,
        1..=p.max_body_bytes,
        1..=p.store_cap_bytes,
    )
        .prop_map(
            |(rps, concurrency, max_requests_per_run, max_body_bytes, store_cap_bytes)| {
                HttpLimits {
                    rps,
                    concurrency,
                    max_requests_per_run,
                    max_body_bytes,
                    store_cap_bytes,
                }
            },
        )
}

fn parent_of(targets: Vec<HostPort>, egress: Vec<HostPort>) -> HttpPolicy {
    HttpPolicy {
        targets,
        egress,
        inspect: vec![],
        insecure_upstream: vec![],
        limits: HttpLimits::default(),
    }
}

proptest! {
    #[test]
    fn a_subset_by_construction_is_accepted(
        (parent_t, child_t, limits) in subset_of(&pool()).prop_flat_map(|pt| {
            let pt2 = pt.clone();
            (Just(pt), subset_of(&pt2), limits_le(HttpLimits::default()))
        })
    ) {
        let parent = policy(Some(parent_of(parent_t, vec![])));
        let child = policy(Some(HttpPolicy { targets: child_t, limits, ..HttpPolicy::default() }));
        prop_assert!(parent.derive(child).is_ok());
    }

    #[test]
    fn a_target_outside_the_parent_is_rejected(
        parent_t in subset_of(&pool()),
        extra in 0usize..12,
    ) {
        let all = pool();
        let outside = all[extra].clone();
        prop_assume!(!parent_t.contains(&outside));
        let parent = policy(Some(parent_of(parent_t.clone(), vec![])));
        let mut child_t = parent_t;
        child_t.push(outside);
        let child = policy(Some(HttpPolicy { targets: child_t, ..HttpPolicy::default() }));
        prop_assert!(parent.derive(child).is_err());
    }

    /// Whatever a child asks for, the effective policy `derive` hands back is inside the parent on
    /// every `[policy.http]` dimension — the property the ceiling check in US3 relies on (SC-010).
    #[test]
    fn no_derived_policy_is_outside_its_parent(
        parent_t in subset_of(&pool()),
        parent_e in subset_of(&pool()),
        child_t in subset_of(&pool()),
        child_e in subset_of(&pool()),
        child_limits in limits_le(HttpLimits { rps: 20, concurrency: 8, max_requests_per_run: 4000, max_body_bytes: 1 << 25, store_cap_bytes: 1 << 32 }),
        child_absent in any::<bool>(),
    ) {
        let parent_e: Vec<HostPort> = parent_e.into_iter().filter(|e| !parent_t.iter().any(|t| t.host == e.host)).collect();
        let parent_h = parent_of(parent_t, parent_e);
        let parent = policy(Some(parent_h.clone()));
        let child = if child_absent {
            policy(None)
        } else {
            policy(Some(HttpPolicy { targets: child_t, egress: child_e, limits: child_limits, ..HttpPolicy::default() }))
        };
        if let Ok(d) = parent.derive(child) {
            let h = d.http.expect("a derived child under an http parent always has http");
            for t in &h.targets {
                prop_assert!(parent_h.targets.contains(t));
            }
            for e in &h.egress {
                prop_assert!(parent_h.egress.contains(e) || parent_h.targets.contains(e));
            }
            let (c, p) = (&h.limits, &parent_h.limits);
            prop_assert!(c.rps <= p.rps && c.concurrency <= p.concurrency);
            prop_assert!(c.max_requests_per_run <= p.max_requests_per_run);
            prop_assert!(c.max_body_bytes <= p.max_body_bytes && c.store_cap_bytes <= p.store_cap_bytes);
        }
    }
}
