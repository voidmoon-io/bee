//! Pure preparation of a backend-neutral compiled Policy for the current eBPF backend.
//!
//! An [`EnforcementPlan`] is the only policy representation in `bee-userspace` that means
//! “structurally installable.” Planning performs no kernel I/O and must complete before a cgroup or
//! BPF map is touched.

use bee_common::layout::{DenyList, NetKey, ScopeMeta};
use bee_common::{
    AccessMode, ScopeMode, DENY_MAX_RULES, DENY_PREFIX_MAX, FLAG_FS_WRITE_DEFAULT_DENY,
    FLAG_NET_ENFORCED, FS_KIND_POSTFIX, FS_KIND_SUBTREE,
};
use bee_core::{CompiledPolicy, FsPrimitive};
use thiserror::Error;

/// Maximum entries in the current backend's global network allow map.
const NET_MAX_ENTRIES: usize = 4096;

/// A complete, immutable plan for installing one compiled Policy into the eBPF backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementPlan {
    pub(crate) meta: ScopeMeta,
    pub(crate) fs_rules: DenyList,
    pub(crate) has_fs_rules: bool,
    pub(crate) exec_rules: DenyList,
    pub(crate) has_exec_rules: bool,
    /// Map-ready templates. Scope installation fills in the runtime cgroup id.
    pub(crate) net_rules: Vec<NetKey>,
}

impl EnforcementPlan {
    /// Validate and encode backend-neutral policy intent for the current eBPF implementation.
    pub fn prepare(
        compiled: &CompiledPolicy,
        effective_mode: ScopeMode,
    ) -> Result<Self, PlanError> {
        let fs_rules = plan_filesystem(&compiled.fs)?;
        let exec_rules = plan_exec(&compiled.exec)?;
        let net_rules = plan_network(&compiled.net)?;

        if compiled.exfiltration_enabled {
            return Err(PlanError::UnsupportedExfiltration);
        }
        // 019: a tool policy with `[policy.http]` whose proxy loopback rule was never applied would
        // install with no network rule — which this backend reads as unrestricted egress.
        if compiled.proxy_loopback_required {
            return Err(PlanError::ProxyLoopbackMissing);
        }

        let mut flags = 0;
        if !net_rules.is_empty() {
            flags |= FLAG_NET_ENFORCED;
        }
        if compiled.fs_write_default_deny
            || fs_rules.rules[..fs_rules.count as usize]
                .iter()
                .any(|rule| AccessMode(rule.mode).contains(AccessMode::WRITE))
        {
            flags |= FLAG_FS_WRITE_DEFAULT_DENY;
        }

        Ok(Self {
            meta: ScopeMeta {
                mode: effective_mode as u8,
                flags,
                _pad: [0; 6],
            },
            has_fs_rules: fs_rules.count > 0,
            fs_rules,
            has_exec_rules: exec_rules.count > 0,
            exec_rules,
            net_rules,
        })
    }

    /// Effective Scope mode encoded by this plan.
    pub fn mode(&self) -> ScopeMode {
        if self.meta.mode == ScopeMode::Observe as u8 {
            ScopeMode::Observe
        } else {
            ScopeMode::Enforce
        }
    }

    /// Number of filesystem rules that will be installed.
    pub fn filesystem_rule_count(&self) -> usize {
        self.fs_rules.count as usize
    }

    /// Number of executable rules that will be installed.
    pub fn executable_rule_count(&self) -> usize {
        self.exec_rules.count as usize
    }

    /// Number of network destinations that will be installed.
    pub fn network_rule_count(&self) -> usize {
        self.net_rules.len()
    }
}

/// A backend capability or structural limit prevents a compiled Policy from being installed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("eBPF backend cannot enforce filesystem {kind} rule '{target}'")]
    UnsupportedFilesystem { kind: &'static str, target: String },
    /// A pinned executable rule with no resolved identity (017). Formerly this variant said the
    /// backend could not enforce a pin *at all*, which made every scanner grant uninstallable and
    /// left 016's external tier reachable only under `--host`. The kernel matches identity now; what
    /// remains unenforceable is a pin whose file could not be identified.
    #[error("inode-pinned executable '{target}' has no resolved identity")]
    UnidentifiedPin { target: String },
    #[error("eBPF backend cannot enforce enabled exfiltration detection")]
    UnsupportedExfiltration,
    /// A tool policy with `[policy.http]` targets reached the backend without its proxy loopback
    /// rule (019). Installing it would leave the scope with no network rule at all.
    #[error(
        "policy has [policy.http] targets but no proxy loopback rule; tool children would have \
         unrestricted egress (this policy runs only in a session that starts the interception proxy)"
    )]
    ProxyLoopbackMissing,
    #[error(
        "{capability} rule '{target}' is too long for the eBPF backend ({actual} > {max} bytes)"
    )]
    RuleTooLong {
        capability: &'static str,
        target: String,
        actual: usize,
        max: usize,
    },
    #[error("too many {capability} rules for the eBPF backend ({actual} > {max})")]
    TooManyRules {
        capability: &'static str,
        actual: usize,
        max: usize,
    },
}

fn display_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn plan_filesystem(rules: &[FsPrimitive]) -> Result<DenyList, PlanError> {
    let mut encoded: Vec<(u8, u8, &[u8])> = Vec::with_capacity(rules.len());
    for rule in rules {
        let (kind, mode, bytes) = match rule {
            FsPrimitive::Prefix { path, mode, .. } => (FS_KIND_SUBTREE, mode.0, path.as_slice()),
            FsPrimitive::Postfix { suffix, mode } => (FS_KIND_POSTFIX, mode.0, suffix.as_slice()),
            FsPrimitive::Segment { name, .. } => {
                return Err(PlanError::UnsupportedFilesystem {
                    kind: "segment",
                    target: display_bytes(name),
                })
            }
            FsPrimitive::BoundedStar { pattern, .. } => {
                return Err(PlanError::UnsupportedFilesystem {
                    kind: "bounded-star",
                    target: display_bytes(pattern),
                })
            }
        };
        if bytes.len() > DENY_PREFIX_MAX {
            return Err(PlanError::RuleTooLong {
                capability: "filesystem",
                target: display_bytes(bytes),
                actual: bytes.len(),
                max: DENY_PREFIX_MAX,
            });
        }
        // Later author rules override an injected protected default for the exact same region.
        if let Some(index) = encoded
            .iter()
            .position(|(k, _, b)| *k == kind && *b == bytes)
        {
            encoded.remove(index);
        }
        encoded.push((kind, mode, bytes));
    }

    if encoded.len() > DENY_MAX_RULES {
        return Err(PlanError::TooManyRules {
            capability: "filesystem",
            actual: encoded.len(),
            max: DENY_MAX_RULES,
        });
    }

    encoded.sort_by(|a, b| {
        let ka = bee_common::matcher::rule_sort_key(a.0, a.1, a.2.len());
        let kb = bee_common::matcher::rule_sort_key(b.0, b.1, b.2.len());
        kb.cmp(&ka)
    });

    let mut list = DenyList::EMPTY;
    for (i, (kind, mode, bytes)) in encoded.iter().enumerate() {
        list.rules[i].kind = *kind;
        list.rules[i].mode = *mode;
        list.rules[i].len = bytes.len() as u16;
        list.rules[i].bytes[..bytes.len()].copy_from_slice(bytes);
    }
    list.count = encoded.len() as u32;
    Ok(list)
}

fn plan_exec(rules: &[bee_core::CompiledExec]) -> Result<DenyList, PlanError> {
    if rules.len() > DENY_MAX_RULES {
        return Err(PlanError::TooManyRules {
            capability: "executable",
            actual: rules.len(),
            max: DENY_MAX_RULES,
        });
    }

    let mut list = DenyList::EMPTY;
    for (i, rule) in rules.iter().enumerate() {
        // A pinned rule is decided in the kernel by identity, so it carries one; the path rides
        // along for the audit line only. The compiler establishes `pin_inode ⇒ identity`, and a pin
        // that arrives without one is refused rather than installed as a path rule — degrading a pin
        // to its own path is exactly the widening a pin exists to prevent (017 FR-004).
        match (rule.pin_inode, rule.identity) {
            (true, Some(id)) => {
                list.rules[i].ino = id.ino;
                list.rules[i].dev = id.dev;
            }
            (true, None) => {
                return Err(PlanError::UnidentifiedPin {
                    target: display_bytes(&rule.path),
                })
            }
            (false, _) => {}
        }
        if rule.path.len() > DENY_PREFIX_MAX {
            return Err(PlanError::RuleTooLong {
                capability: "executable",
                target: display_bytes(&rule.path),
                actual: rule.path.len(),
                max: DENY_PREFIX_MAX,
            });
        }
        list.rules[i].kind = FS_KIND_SUBTREE;
        list.rules[i].len = rule.path.len() as u16;
        list.rules[i].bytes[..rule.path.len()].copy_from_slice(&rule.path);
    }
    list.count = rules.len() as u32;
    Ok(list)
}

fn plan_network(rules: &[bee_core::CompiledNet]) -> Result<Vec<NetKey>, PlanError> {
    if rules.len() > NET_MAX_ENTRIES {
        return Err(PlanError::TooManyRules {
            capability: "network",
            actual: rules.len(),
            max: NET_MAX_ENTRIES,
        });
    }

    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut key = NetKey {
            cgroup_id: 0,
            family: 0,
            port: rule.port,
            _pad: [0; 4],
            addr: [0; 16],
        };
        match rule.addr {
            std::net::IpAddr::V4(v4) => {
                key.family = 2;
                key.addr[..4].copy_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                key.family = 10;
                key.addr = v6.octets();
            }
        }
        out.push(key);
    }
    out.sort_by_key(|key| (key.family, key.addr, key.port));
    out.dedup_by_key(|key| (key.family, key.addr, key.port));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bee_common::{AccessMode, FLAG_FS_WRITE_DEFAULT_DENY, FLAG_NET_ENFORCED};
    use bee_core::{CompiledExec, CompiledNet, CompiledPolicy, FsPrimitive};

    use super::*;

    fn prefix(path: &[u8], mode: AccessMode) -> FsPrimitive {
        FsPrimitive::Prefix {
            path: path.to_vec(),
            subtree: true,
            mode,
        }
    }

    /// 019 research R2, mirrored against the host reference matcher: the proxy scope's worker
    /// binary stays readable under every prefix deny, its siblings do not, and writes are refused.
    #[test]
    fn the_proxy_scope_reads_its_worker_binary_and_nothing_near_it() {
        use bee_common::matcher::fs_open_blocked;
        use std::path::{Path, PathBuf};

        struct R;
        impl bee_core::Resolver for R {
            fn project_root(&self) -> &str {
                "/home/u/proj"
            }
            fn home(&self) -> &str {
                "/home/u"
            }
            fn resolve_exec(&self, n: &str) -> Result<PathBuf, bee_core::CompileError> {
                Ok(PathBuf::from(n))
            }
            fn resolve_exec_identity(
                &self,
                _: &Path,
            ) -> Result<bee_core::ExecIdentity, bee_core::CompileError> {
                unreachable!()
            }
            fn resolve_host(&self, _: &str) -> Result<Vec<IpAddr>, bee_core::CompileError> {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))])
            }
        }
        let policy = bee_core::Policy::from_toml(
            "[policy]\nname = \"p\"\n[policy.http]\ntargets = [\"app.test:443\"]\n",
        )
        .unwrap();
        for exe in [
            "/home/u/proj/target/debug/bee",
            "/home/ubuntu/bee",
            "/usr/bin/bee",
        ] {
            let c = policy
                .compile_http(&R, Path::new(exe))
                .unwrap()
                .unwrap()
                .proxy_scope;
            let plan = EnforcementPlan::prepare(&c, ScopeMode::Enforce).unwrap();
            assert_ne!(plan.meta.flags & FLAG_FS_WRITE_DEFAULT_DENY, 0);
            assert_ne!(plan.meta.flags & FLAG_NET_ENFORCED, 0);
            let read = |p: &str| !fs_open_blocked(p.as_bytes(), &plan.fs_rules, false, true);
            let write = |p: &str| !fs_open_blocked(p.as_bytes(), &plan.fs_rules, true, true);
            assert!(read(exe), "{exe} unreadable");
            assert!(!write(exe), "{exe} writable");
            // Under a denied prefix the exact rule must not widen to its neighbours. (`/usr/bin` is
            // not denied at all, so a sibling there is readable, as any system file is.)
            if exe.starts_with("/home") {
                assert!(!read(&format!("{exe}-sibling")), "{exe}: sibling readable");
            }
            assert!(!read("/home/u/proj/src/main.rs"));
            assert!(!read("/home/u/proj/.bee/http/index.sqlite"));
            assert!(!read("/home/u/.ssh/id_ed25519"));
            assert!(!read("/root/.aws/credentials"));
            assert!(!read("/home/other/notes"));
            assert!(read("/etc/resolv.conf"));
            assert!(read("/etc/ssl/certs/ca-certificates.crt"));
            assert!(read("/lib/x86_64-linux-gnu/libc.so.6"));
            assert!(!write("/tmp/x"));
        }
    }

    #[test]
    fn a_tool_policy_missing_its_proxy_loopback_is_refused() {
        let compiled = CompiledPolicy {
            proxy_loopback_required: true,
            ..CompiledPolicy::default()
        };
        assert_eq!(
            EnforcementPlan::prepare(&compiled, ScopeMode::Enforce),
            Err(PlanError::ProxyLoopbackMissing)
        );
        let fixed = bee_core::compiler::with_proxy_loopback(compiled, 4000);
        let plan = EnforcementPlan::prepare(&fixed, ScopeMode::Enforce).unwrap();
        assert_eq!(plan.network_rule_count(), 1);
        assert_ne!(plan.meta.flags & FLAG_NET_ENFORCED, 0);
    }

    #[test]
    fn empty_plan_is_installable_and_carries_mode() {
        let plan =
            EnforcementPlan::prepare(&CompiledPolicy::default(), ScopeMode::Observe).unwrap();
        assert_eq!(plan.mode(), ScopeMode::Observe);
        assert_eq!(plan.filesystem_rule_count(), 0);
        assert_eq!(plan.executable_rule_count(), 0);
        assert_eq!(plan.network_rule_count(), 0);
        assert_eq!(plan.meta.flags, 0);
    }

    #[test]
    fn filesystem_rules_are_ordered_and_write_intent_sets_default_deny() {
        let compiled = CompiledPolicy {
            fs: vec![
                prefix(b"/project", AccessMode::READ.union(AccessMode::WRITE)),
                prefix(b"/project/.git", AccessMode::READ),
                FsPrimitive::Postfix {
                    suffix: b".pem".to_vec(),
                    mode: AccessMode::DENY,
                },
            ],
            ..CompiledPolicy::default()
        };
        let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap();
        assert_eq!(plan.fs_rules.rules[0].kind, FS_KIND_POSTFIX);
        assert_eq!(&plan.fs_rules.rules[0].bytes[..4], b".pem");
        assert_eq!(&plan.fs_rules.rules[1].bytes[..13], b"/project/.git");
        assert_ne!(plan.meta.flags & FLAG_FS_WRITE_DEFAULT_DENY, 0);
    }

    #[test]
    fn deny_breaks_equal_specificity_tie() {
        let compiled = CompiledPolicy {
            fs: vec![
                prefix(b"/project", AccessMode::READ),
                prefix(b"/project", AccessMode::DENY),
            ],
            ..CompiledPolicy::default()
        };
        let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap();
        assert!(AccessMode(plan.fs_rules.rules[0].mode).is_deny());
    }

    #[test]
    fn later_rule_overrides_same_region() {
        let compiled = CompiledPolicy {
            fs: vec![
                prefix(b"/project/.git", AccessMode::READ),
                prefix(b"/project/.git", AccessMode::READ.union(AccessMode::WRITE)),
            ],
            ..CompiledPolicy::default()
        };
        let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap();
        assert_eq!(plan.filesystem_rule_count(), 1);
        assert!(AccessMode(plan.fs_rules.rules[0].mode).contains(AccessMode::WRITE));
        assert_ne!(plan.meta.flags & FLAG_FS_WRITE_DEFAULT_DENY, 0);
    }

    #[test]
    fn unsupported_filesystem_kinds_fail_closed() {
        let segment = CompiledPolicy {
            fs: vec![FsPrimitive::Segment {
                name: b"target".to_vec(),
                mode: AccessMode::READ,
            }],
            ..CompiledPolicy::default()
        };
        assert!(matches!(
            EnforcementPlan::prepare(&segment, ScopeMode::Enforce),
            Err(PlanError::UnsupportedFilesystem {
                kind: "segment",
                ..
            })
        ));

        let star = CompiledPolicy {
            fs: vec![FsPrimitive::BoundedStar {
                pattern: b"foo*bar".to_vec(),
                mode: AccessMode::READ,
            }],
            ..CompiledPolicy::default()
        };
        assert!(matches!(
            EnforcementPlan::prepare(&star, ScopeMode::Enforce),
            Err(PlanError::UnsupportedFilesystem {
                kind: "bounded-star",
                ..
            })
        ));
    }

    #[test]
    fn filesystem_capacity_and_encoded_length_fail_closed() {
        let at_limit = CompiledPolicy {
            fs: (0..DENY_MAX_RULES)
                .map(|i| prefix(format!("/p/{i}").as_bytes(), AccessMode::READ))
                .collect(),
            ..CompiledPolicy::default()
        };
        assert_eq!(
            EnforcementPlan::prepare(&at_limit, ScopeMode::Enforce)
                .unwrap()
                .filesystem_rule_count(),
            DENY_MAX_RULES
        );

        let too_many = CompiledPolicy {
            fs: (0..=DENY_MAX_RULES)
                .map(|i| prefix(format!("/p/{i}").as_bytes(), AccessMode::READ))
                .collect(),
            ..CompiledPolicy::default()
        };
        assert_eq!(
            EnforcementPlan::prepare(&too_many, ScopeMode::Enforce).unwrap_err(),
            PlanError::TooManyRules {
                capability: "filesystem",
                actual: DENY_MAX_RULES + 1,
                max: DENY_MAX_RULES,
            }
        );

        let long = CompiledPolicy {
            fs: vec![prefix(&[b'x'; DENY_PREFIX_MAX + 1], AccessMode::READ)],
            ..CompiledPolicy::default()
        };
        assert!(matches!(
            EnforcementPlan::prepare(&long, ScopeMode::Enforce),
            Err(PlanError::RuleTooLong {
                capability: "filesystem",
                ..
            })
        ));
    }

    #[test]
    fn a_pin_installs_carrying_the_identity_it_was_given() {
        // 017: this is the case that used to be refused outright, which made every 016 scanner
        // grant uninstallable. The rule now carries identity; the path is along for the audit line.
        let pinned = CompiledPolicy {
            exec: vec![CompiledExec {
                path: b"/usr/bin/opengrep".to_vec(),
                pin_inode: true,
                identity: Some(bee_core::ExecIdentity {
                    ino: 4242,
                    dev: 66_306,
                }),
            }],
            ..CompiledPolicy::default()
        };
        let plan = EnforcementPlan::prepare(&pinned, ScopeMode::Enforce).expect("a pin installs");
        assert_eq!(plan.exec_rules.count, 1);
        assert_eq!(plan.exec_rules.rules[0].ino, 4242);
        assert_eq!(plan.exec_rules.rules[0].dev, 66_306);
        assert!(plan.exec_rules.rules[0].is_pinned());
    }

    #[test]
    fn an_unpinned_rule_carries_no_identity() {
        let unpinned = CompiledPolicy {
            exec: vec![CompiledExec {
                path: b"/usr/bin/cargo".to_vec(),
                pin_inode: false,
                identity: None,
            }],
            ..CompiledPolicy::default()
        };
        let plan = EnforcementPlan::prepare(&unpinned, ScopeMode::Enforce).unwrap();
        assert!(!plan.exec_rules.rules[0].is_pinned(), "ino must stay 0");
    }

    #[test]
    fn a_pin_with_no_identity_is_refused_rather_than_loosened() {
        // The compiler cannot produce this, which is the point: if it ever did, the backend must not
        // quietly install a path rule that matches whatever now sits at that path (FR-004).
        let orphan = CompiledPolicy {
            exec: vec![CompiledExec {
                path: b"/usr/bin/opengrep".to_vec(),
                pin_inode: true,
                identity: None,
            }],
            ..CompiledPolicy::default()
        };
        assert!(matches!(
            EnforcementPlan::prepare(&orphan, ScopeMode::Enforce),
            Err(PlanError::UnidentifiedPin { .. })
        ));
    }

    #[test]
    fn executable_length_and_count_fail_closed() {
        let long = CompiledPolicy {
            exec: vec![CompiledExec {
                path: vec![b'x'; DENY_PREFIX_MAX + 1],
                pin_inode: false,
                identity: None,
            }],
            ..CompiledPolicy::default()
        };
        assert!(matches!(
            EnforcementPlan::prepare(&long, ScopeMode::Enforce),
            Err(PlanError::RuleTooLong {
                capability: "executable",
                ..
            })
        ));

        let too_many = CompiledPolicy {
            exec: (0..=DENY_MAX_RULES)
                .map(|i| CompiledExec {
                    path: format!("/bin/tool-{i}").into_bytes(),
                    pin_inode: false,
                    identity: None,
                })
                .collect(),
            ..CompiledPolicy::default()
        };
        assert!(matches!(
            EnforcementPlan::prepare(&too_many, ScopeMode::Enforce),
            Err(PlanError::TooManyRules {
                capability: "executable",
                ..
            })
        ));
    }

    #[test]
    fn network_rules_are_deterministic_deduplicated_and_flagged() {
        let v4 = CompiledNet {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 443,
        };
        let v6 = CompiledNet {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        let compiled = CompiledPolicy {
            net: vec![v6, v4.clone(), v4],
            ..CompiledPolicy::default()
        };
        let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap();
        assert_eq!(plan.network_rule_count(), 2);
        assert_eq!(plan.net_rules[0].family, 2);
        assert_eq!(plan.net_rules[1].family, 10);
        assert_ne!(plan.meta.flags & FLAG_NET_ENFORCED, 0);
    }

    #[test]
    fn enabled_exfiltration_fails_closed() {
        let compiled = CompiledPolicy {
            exfiltration_enabled: true,
            ..CompiledPolicy::default()
        };
        assert_eq!(
            EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap_err(),
            PlanError::UnsupportedExfiltration
        );

        let disabled_metadata = CompiledPolicy {
            exfiltration_enabled: false,
            sensitive: vec![prefix(b"/secret", AccessMode::READ)],
            ..CompiledPolicy::default()
        };
        assert!(EnforcementPlan::prepare(&disabled_metadata, ScopeMode::Enforce).is_ok());
    }

    #[test]
    fn network_capacity_fails_closed() {
        let compiled = CompiledPolicy {
            net: (0..=NET_MAX_ENTRIES)
                .map(|i| CompiledNet {
                    addr: IpAddr::V6(Ipv6Addr::from(i as u128)),
                    port: 443,
                })
                .collect(),
            ..CompiledPolicy::default()
        };
        assert_eq!(
            EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap_err(),
            PlanError::TooManyRules {
                capability: "network",
                actual: NET_MAX_ENTRIES + 1,
                max: NET_MAX_ENTRIES,
            }
        );
    }
}
