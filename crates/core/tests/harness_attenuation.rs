//! 026 T043/T044 — a harness subagent's derived policy (research R8, R10).
//!
//! Provider hosts are held by **name**: each `requires.net` entry must be one the parent names
//! (its `network.allow`, or — when it intercepts — its `[policy.http]` targets and egress). They
//! become the harness's proxy egress, never kernel address rules: its `network.allow` is always
//! empty. The harness credential stores are denied unless agent and parent both name them.

use std::collections::BTreeMap;

use bee_core::compiler::HARNESS_STORES;
use bee_core::policy::{HostPort, HttpPolicy};
use bee_core::{Access, Policy};
use proptest::prelude::*;

fn hp(host: &str, port: u16) -> HostPort {
    HostPort {
        host: host.into(),
        port,
    }
}

fn policy(net: &[&str], http: Option<HttpPolicy>, fs: &[(&str, Access)]) -> Policy {
    let mut p = Policy::from_toml("[policy]\nname = \"p\"\n").unwrap();
    p.network.allow = net.iter().map(|s| s.to_string()).collect();
    p.http = http;
    p.filesystem = fs
        .iter()
        .map(|(k, a)| (k.to_string(), *a))
        .collect::<BTreeMap<_, _>>();
    p
}

fn request(net: &[&str], fs: &[(&str, Access)]) -> Policy {
    policy(net, None, fs)
}

const HOSTS: &[&str] = &[
    "api.anthropic.com:443",
    "platform.claude.com:443",
    "evil.test:443",
    "10.0.0.5:8080",
];

proptest! {
    // T043: for any parent (intercepting or not) and any requested provider list, derivation either
    // refuses or yields a child whose every provider host the parent held by exact name, whose
    // kernel network rules are empty, and whose proxy egress is exactly what it asked for.
    #[test]
    fn provider_hosts_are_held_by_name_and_never_kernel_rules(
        parent_net in proptest::sample::subsequence(HOSTS.to_vec(), 0..=HOSTS.len()),
        asked in proptest::sample::subsequence(HOSTS.to_vec(), 1..=HOSTS.len()),
        intercepting in any::<bool>(),
    ) {
        let parent = if intercepting {
            let names: Vec<HostPort> = parent_net
                .iter()
                .map(|s| HostPort::try_from(s.to_string()).unwrap())
                .collect();
            policy(&[], Some(HttpPolicy {
                targets: vec![hp("app.test", 443)],
                egress: names,
                ..HttpPolicy::default()
            }), &[])
        } else {
            policy(&parent_net, None, &[])
        };
        let held = |s: &&str| parent_net.contains(s);
        match parent.derive_harness(request(&asked, &[]), HARNESS_STORES) {
            Ok(child) => {
                prop_assert!(asked.iter().all(held), "accepted {asked:?} under {parent_net:?}");
                prop_assert!(child.network.allow.is_empty(), "kernel rules: {:?}", child.network.allow);
                let http = child.http.expect("a harness always has a proxy section");
                let mut egress: Vec<String> = http.egress.iter().map(|h| h.to_string()).collect();
                egress.sort();
                let mut want: Vec<String> = asked.iter().map(|s| s.to_string()).collect();
                want.sort();
                prop_assert_eq!(egress, want);
                if intercepting {
                    prop_assert_eq!(http.targets, vec![hp("app.test", 443)]);
                } else {
                    prop_assert!(http.targets.is_empty());
                }
            }
            Err(_) => prop_assert!(!asked.iter().all(held), "refused {asked:?} under {parent_net:?}"),
        }
    }
}

#[test]
fn a_provider_host_the_parent_does_not_name_is_refused_naming_it() {
    let parent = policy(&["api.anthropic.com:443"], None, &[]);
    let err = parent
        .derive_harness(request(&["evil.test:443"], &[]), HARNESS_STORES)
        .unwrap_err();
    assert!(err.to_string().contains("evil.test:443"), "{err}");
}

#[test]
fn an_address_rule_does_not_hold_a_name() {
    // The parent allows an address; the harness asks for a name resolving to it. Names are matched
    // as names: the kernel never sees one, so an address cannot vouch for it.
    let parent = policy(&["160.79.104.10:443"], None, &[]);
    assert!(parent
        .derive_harness(request(&["api.anthropic.com:443"], &[]), HARNESS_STORES)
        .is_err());
}

// T044: every harness credential store is denied, unless the agent and the parent both name it.
#[test]
fn harness_stores_are_denied_unless_both_name_them() {
    let parent = policy(
        &["api.anthropic.com:443"],
        None,
        &[("~", Access::Write), ("~/.claude", Access::Write)],
    );
    let child = parent
        .derive_harness(
            request(
                &["api.anthropic.com:443"],
                &[("~/.claude", Access::Write), ("~/.codex", Access::Write)],
            ),
            HARNESS_STORES,
        )
        .unwrap();
    assert_eq!(child.filesystem.get("~/.claude"), Some(&Access::Write));
    // The agent named ~/.codex, but the parent holds it only through `~`: denied.
    for store in HARNESS_STORES.iter().filter(|s| **s != "~/.claude") {
        assert_eq!(
            child.filesystem.get(*store),
            Some(&Access::Deny),
            "{store} must be denied"
        );
    }
}

#[test]
fn the_global_protected_defaults_are_unchanged_for_ordinary_children() {
    let parent = policy(&["api.anthropic.com:443"], None, &[("~", Access::Write)]);
    let child = parent.derive(request(&[], &[])).unwrap();
    for store in HARNESS_STORES {
        assert_eq!(child.filesystem.get(*store), None, "{store}");
    }
}

// Only the stores passed are denied: the caller passes those present, to keep within the eBPF
// backend's rule budget.
#[test]
fn only_the_stores_passed_are_denied() {
    let parent = policy(&["api.anthropic.com:443"], None, &[("~", Access::Write)]);
    let child = parent
        .derive_harness(request(&["api.anthropic.com:443"], &[]), &["~/.codex"])
        .unwrap();
    assert_eq!(child.filesystem.get("~/.codex"), Some(&Access::Deny));
    assert_eq!(child.filesystem.get("~/.claude"), None);
}
