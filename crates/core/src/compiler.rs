//! Policy compiler: authoring [`Policy`] → backend-neutral [`CompiledPolicy`].
//!
//! Two responsibilities that the constitution keeps out of the kernel:
//! 1. **Glob lowering** — reduce each path pattern to a verifier-safe primitive
//!    (exact/subtree/postfix/segment/bounded-star), or fail closed on an irreducible pattern (R6).
//! 2. **Name resolution** — resolve `:project_root`/`~` tokens, executable names → paths, and
//!    domains → IPs, via an injected [`Resolver`] (no ambient I/O in the core logic — NFR-005).

use std::net::IpAddr;
use std::path::PathBuf;

use bee_common::AccessMode;

use crate::error::CompileError;
use crate::policy::{Mode, Policy};

/// Host-environment resolution injected into the compiler so it stays pure and testable.
pub trait Resolver {
    /// Absolute project root (replaces the `:project_root` token).
    fn project_root(&self) -> &str;
    /// Absolute home directory (replaces a leading `~`).
    fn home(&self) -> &str;
    /// Resolve an executable name or path to an absolute path (PATH search + existence check).
    fn resolve_exec(&self, name: &str) -> Result<PathBuf, CompileError>;
    /// Identity of an already-resolved executable, for a `!`-pinned entry only (017 FR-001).
    ///
    /// Separate from [`Resolver::resolve_exec`] because most entries never need it, and because
    /// failure here means something different: the path resolved, but the file it names could not be
    /// identified — which must be a refusal, never a rule that matches the path loosely (FR-004).
    fn resolve_exec_identity(&self, path: &std::path::Path) -> Result<ExecIdentity, CompileError>;
    /// Resolve a network host (domain/IP/CIDR) to concrete IP addresses.
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, CompileError>;
}

/// A lowered filesystem rule region + access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsPrimitive {
    /// Exact or subtree match on a resolved absolute path (both go to the LPM prefix map;
    /// `subtree=true` means "and everything beneath").
    Prefix {
        path: Vec<u8>,
        subtree: bool,
        mode: AccessMode,
    },
    /// Literal suffix, e.g. `.log` from `*.log`.
    Postfix { suffix: Vec<u8>, mode: AccessMode },
    /// A path component equals a literal, e.g. `target` from `**/target`.
    Segment { name: Vec<u8>, mode: AccessMode },
    /// Single-segment `*` glob matched against the basename.
    BoundedStar { pattern: Vec<u8>, mode: AccessMode },
}

/// The identity of a file: what a pin actually names (017).
///
/// A path is a way of *reaching* a file, not the file itself, and the two can come apart between the
/// moment a policy is written and the moment an image is loaded. `dev` is the **kernel's** `s_dev`
/// encoding rather than the libc `st_dev` the host reports — the resolver converts, because the
/// comparison happens in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecIdentity {
    pub ino: u64,
    pub dev: u32,
}

/// A compiled executable rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledExec {
    pub path: Vec<u8>,
    /// Pin the resolved inode (TOCTOU-hard) rather than match by path.
    pub pin_inode: bool,
    /// The identity the pin resolved to, `Some` **iff** `pin_inode` — the compiler establishes that
    /// invariant, and a backend is entitled to treat a pin with no identity as a bug rather than as
    /// a rule to install loosely.
    pub identity: Option<ExecIdentity>,
}

/// A compiled network egress rule (one per resolved IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledNet {
    pub addr: IpAddr,
    pub port: u16,
}

/// Normalized, host-resolved policy intent.
///
/// This representation is backend-neutral: it may contain capabilities that a particular
/// enforcement backend cannot install. Backends must prepare and validate their own runnable plan
/// before touching enforcement state.
#[derive(Debug, Clone, Default)]
pub struct CompiledPolicy {
    pub mode: Mode,
    pub fs: Vec<FsPrimitive>,
    pub exec: Vec<CompiledExec>,
    pub net: Vec<CompiledNet>,
    /// Whether the author requested exfiltration detection.
    pub exfiltration_enabled: bool,
    /// Resolved sensitive paths for an exfiltration-capable backend.
    pub sensitive: Vec<FsPrimitive>,
    /// Deny every write-open no rule grants, even when no rule grants a write (019, research R2).
    /// The backend otherwise latches write-default-deny only on the presence of a `write` rule.
    pub fs_write_default_deny: bool,
    /// Set by [`Policy::compile`] when `[policy.http]` is active: the tool scope's only network rule
    /// must be the session proxy's loopback port, which only the session builder knows. A plan
    /// refuses to install a policy still carrying this flag, so no path — a session, a reload after
    /// a grant, `bee exec` — can install the tool scope with *no* network rule, which the kernel
    /// would read as unrestricted egress. [`with_proxy_loopback`] clears it.
    pub proxy_loopback_required: bool,
}

impl Policy {
    /// Normalize and resolve this policy without choosing an enforcement backend. Fails closed on
    /// irreducible authoring patterns or unresolvable names. Target: < 50ms for ≤100 path + ≤50 net
    /// rules (SC-006).
    pub fn compile(&self, r: &dyn Resolver) -> Result<CompiledPolicy, CompileError> {
        let fs = self.compile_filesystem(r)?;

        let mut exec = Vec::new();
        for entry in &self.exec.allow {
            let (name, pin) = match entry.strip_prefix('!') {
                Some(rest) => (rest, true),
                None => (entry.as_str(), false),
            };
            let path = r.resolve_exec(name)?;
            // Resolved here rather than at install time so a pin that names nothing identifiable is
            // a compile-time refusal — the operator learns it when they write the policy, not when
            // the kernel silently has one fewer rule than they think.
            let identity = if pin {
                Some(r.resolve_exec_identity(&path)?)
            } else {
                None
            };
            exec.push(CompiledExec {
                path: path.into_os_string().into_encoded_bytes(),
                pin_inode: pin,
                identity,
            });
        }

        let mut net = Vec::new();
        for entry in &self.network.allow {
            let (host, port) = split_host_port(entry)?;
            for addr in r.resolve_host(host)? {
                net.push(CompiledNet { addr, port });
            }
        }

        let mut sensitive = Vec::new();
        for raw in &self.exfiltration.sensitive_paths {
            let resolved = resolve_tokens(raw, r);
            sensitive.push(lower_pattern(&resolved, AccessMode::READ)?);
        }

        Ok(CompiledPolicy {
            mode: self.mode,
            fs,
            exec,
            net,
            exfiltration_enabled: self.exfiltration.enabled,
            sensitive,
            fs_write_default_deny: self.denies_unmatched_writes(),
            proxy_loopback_required: self.http.as_ref().is_some_and(|h| h.is_active()),
        })
    }

    /// The filesystem rules alone, in the order [`Policy::compile`] emits them. Needs only path
    /// tokens from `r` — no executable or DNS resolution — so a caller can ask what the kernel would
    /// allow at a path without compiling the rest of the policy.
    pub fn compile_filesystem(&self, r: &dyn Resolver) -> Result<Vec<FsPrimitive>, CompileError> {
        let mut fs = Vec::new();
        // Inject FR-008 protected defaults first, then explicit rules; explicit rules that name the
        // same resolved path override (a later duplicate prefix with the same length wins at load).
        // That override is the *author's* prerogative: for a derived policy, attenuation has already
        // refused any child grant reaching into a protected region that the parent did not name
        // explicitly, so nothing untrusted gets here (see [`crate::attenuation`]).
        for (raw, access) in PROTECTED_DEFAULTS {
            fs.push(FsPrimitive::Prefix {
                path: resolve_tokens(raw, r).into_bytes(),
                subtree: true,
                mode: *access,
            });
        }

        for (raw, access) in &self.filesystem {
            let resolved = resolve_tokens(raw, r);
            let prim = lower_pattern(&resolved, access.to_bits())?;
            fs.push(prim);
        }
        Ok(fs)
    }

    /// Compile `[policy.http]` into the proxy scope (kernel) and the HTTP scope (worker) — 019,
    /// contracts/policy-http.md. `Ok(None)` when the section is absent or has no targets.
    ///
    /// `worker_exe` is the resolved, canonical path of the binary the proxy worker execs — the caller
    /// passes `std::env::current_exe()` canonicalised — so the core stays free of ambient I/O.
    pub fn compile_http(
        &self,
        r: &dyn Resolver,
        worker_exe: &std::path::Path,
    ) -> Result<Option<CompiledHttp>, CompileError> {
        let Some(http) = self.http.as_ref().filter(|h| h.is_active()) else {
            return Ok(None);
        };

        if !self.network.allow.is_empty() {
            return Err(CompileError::HttpWithDirectNetwork(
                self.network.allow.join(", "),
            ));
        }
        for e in &http.egress {
            if http.targets.iter().any(|t| t.host == e.host) {
                return Err(CompileError::HostRoleConflict(e.host.clone()));
            }
        }
        for p in &http.inspect {
            if !http.targets.iter().any(|t| p.matches(&t.host)) {
                return Err(CompileError::InspectOutsideTargets(p.to_string()));
            }
        }
        for p in &http.insecure_upstream {
            if !http.inspect.iter().any(|i| i.covers(p) == Some(true)) {
                return Err(CompileError::InsecureOutsideInspect(p.to_string()));
            }
        }
        let l = &http.limits;
        for (name, zero) in [
            ("rps", l.rps == 0),
            ("concurrency", l.concurrency == 0),
            ("max_requests_per_run", l.max_requests_per_run == 0),
            ("max_body_bytes", l.max_body_bytes == 0),
            ("store_cap_bytes", l.store_cap_bytes == 0),
        ] {
            if zero {
                return Err(CompileError::ZeroLimit(name.into()));
            }
        }

        let entry =
            |hp: &crate::policy::HostPort, role: Role| -> Result<ScopeEntry, CompileError> {
                let mut resolved = r.resolve_host(&hp.host)?;
                resolved.sort();
                resolved.dedup();
                let mut enforced_by: Vec<EnforcedBy> = resolved
                    .iter()
                    .map(|a| EnforcedBy::Kernel {
                        addr: *a,
                        port: hp.port,
                    })
                    .collect();
                enforced_by.push(EnforcedBy::Proxy {
                    host: hp.host.clone(),
                });
                Ok(ScopeEntry {
                    host: hp.host.clone(),
                    port: hp.port,
                    resolved,
                    role,
                    enforced_by,
                })
            };
        let targets = http
            .targets
            .iter()
            .map(|t| entry(t, Role::Target))
            .collect::<Result<Vec<_>, _>>()?;
        let egress = http
            .egress
            .iter()
            .map(|t| entry(t, Role::Egress))
            .collect::<Result<Vec<_>, _>>()?;

        let mut net: Vec<CompiledNet> = Vec::new();
        for e in targets.iter().chain(&egress) {
            for addr in &e.resolved {
                let n = CompiledNet {
                    addr: *addr,
                    port: e.port,
                };
                if !net.contains(&n) {
                    net.push(n);
                }
            }
        }

        let proxy_scope = CompiledPolicy {
            mode: self.mode,
            fs: proxy_scope_fs(r, worker_exe),
            exec: vec![CompiledExec {
                path: worker_exe.as_os_str().as_encoded_bytes().to_vec(),
                pin_inode: false,
                identity: None,
            }],
            net,
            exfiltration_enabled: false,
            sensitive: Vec::new(),
            fs_write_default_deny: true,
            proxy_loopback_required: false,
        };
        Ok(Some(CompiledHttp {
            proxy_scope,
            http_scope: HttpScope {
                targets,
                egress,
                inspect: http.inspect.clone(),
                insecure_upstream: http.insecure_upstream.clone(),
                limits: http.limits,
            },
        }))
    }
}

/// The proxy scope's filesystem rules (research R2).
///
/// The kernel file model is a **deny list** — reads with no matching rule are allowed — so this is a
/// *reduced* read surface, not an empty one. It denies reads of the project, the operator's home,
/// `/home`, `/root`, and every protected credential directory not already beneath one of those;
/// leaves the loader, libc, `/etc/ssl`, `/etc/resolv.conf`, `/etc/hosts` and `/etc/nsswitch.conf`
/// readable; and (with [`CompiledPolicy::fs_write_default_deny`]) refuses every write.
///
/// The one grant is an **exact read rule for the worker binary**. `file_open` fires on exec, the
/// worker is exec'd after it joins the scope, and both a dev build (`target/debug/bee` under the
/// project) and the VM matrix binary (`/home/ubuntu/bee`) sit under denied prefixes. Rules are
/// installed most-specific-first and the first match decides, so the longer binary path outranks
/// every prefix deny above it.
///
/// Bounded by the kernel's per-scope rule budget (`DENY_MAX_RULES` = 8): at most 1 + 4 + 2 rules.
fn proxy_scope_fs(r: &dyn Resolver, worker_exe: &std::path::Path) -> Vec<FsPrimitive> {
    let mut denies: Vec<Vec<u8>> = Vec::new();
    let push_deny = |path: String, denies: &mut Vec<Vec<u8>>| {
        let p = path.trim_end_matches('/').as_bytes().to_vec();
        if p.is_empty() {
            return;
        }
        // Skip a region a deny already covers: it adds a rule, not a restriction.
        let covered = denies
            .iter()
            .any(|d| p == *d || (p.len() > d.len() && p.starts_with(d) && p[d.len()] == b'/'));
        if !covered {
            denies.retain(|d| !(d.len() > p.len() && d.starts_with(&p) && d[p.len()] == b'/'));
            denies.push(p);
        }
    };
    for p in [
        r.project_root().to_string(),
        r.home().to_string(),
        "/home".to_string(),
        "/root".to_string(),
    ] {
        push_deny(p, &mut denies);
    }
    for (raw, mode) in PROTECTED_DEFAULTS {
        if mode.is_deny() {
            push_deny(resolve_tokens(raw, r), &mut denies);
        }
    }

    let mut fs = vec![FsPrimitive::Prefix {
        path: worker_exe.as_os_str().as_encoded_bytes().to_vec(),
        subtree: false,
        mode: AccessMode::READ,
    }];
    fs.extend(denies.into_iter().map(|path| FsPrimitive::Prefix {
        path,
        subtree: true,
        mode: AccessMode::DENY,
    }));
    fs
}

impl FsPrimitive {
    /// A read grant for exactly `path` (and anything beneath it). Used for the one file a scope must
    /// be able to read even when the policy denies its parent — the session CA bundle (019 US4).
    pub fn read_grant(path: &std::path::Path) -> FsPrimitive {
        FsPrimitive::Prefix {
            path: path.as_os_str().as_encoded_bytes().to_vec(),
            subtree: false,
            mode: AccessMode::READ,
        }
    }
}

/// Replace a tool policy's network with exactly `127.0.0.1:<port>` — the session proxy (019,
/// research R4). With `[policy.http]` present this is the tool scope's **only** network rule, so
/// `FLAG_NET_ENFORCED` is always set and a child that ignores `HTTP_PROXY` reaches nothing.
pub fn with_proxy_loopback(mut tool: CompiledPolicy, port: u16) -> CompiledPolicy {
    tool.net = vec![CompiledNet {
        addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port,
    }];
    tool.proxy_loopback_required = false;
    tool
}

/// Output of [`Policy::compile_http`]: what the kernel installs for the proxy, and what the proxy
/// worker enforces in user space.
#[derive(Debug, Clone)]
pub struct CompiledHttp {
    /// Network = resolved `targets ∪ egress`; filesystem per [`proxy_scope_fs`]; exec = the worker.
    pub proxy_scope: CompiledPolicy,
    pub http_scope: HttpScope,
}

/// The scope the proxy worker enforces: host names, roles, inspection and limits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpScope {
    pub targets: Vec<ScopeEntry>,
    pub egress: Vec<ScopeEntry>,
    pub inspect: Vec<crate::pattern::HostPattern>,
    pub insecure_upstream: Vec<crate::pattern::HostPattern>,
    pub limits: crate::policy::HttpLimits,
}

/// One scope host, its compiled addresses, and the layers that enforce it (FR-011).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopeEntry {
    pub host: String,
    pub port: u16,
    /// The addresses the kernel permits for this entry, resolved at compile time.
    pub resolved: Vec<IpAddr>,
    pub role: Role,
    /// One `Kernel` rule per resolved address, plus the `Proxy` host-name check.
    pub enforced_by: Vec<EnforcedBy>,
}

/// What a scope host may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Testable: model-originated requests and inspection allowed.
    Target,
    /// Reachable as a tunnel only; refused by model-originated tools.
    Egress,
}

/// The layer that enforces a scope rule — shown with every rule so a user-space check is never
/// presented as a kernel guarantee (Constitution III).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum EnforcedBy {
    /// The kernel permits the proxy scope to connect to this address and port.
    Kernel { addr: IpAddr, port: u16 },
    /// The proxy checks the host name (and CONNECT host = SNI, and the role).
    Proxy { host: String },
}

/// FR-008: within any writable root, protect VCS/config/credential dirs unless explicitly overridden.
///
/// Held in **authoring tokens**, not resolved paths, because two callers need it at two different
/// stages: [`Policy::compile`] resolves and injects it, while [`crate::attenuation`] reasons over it
/// at the authoring level (where it, too, compares raw patterns). One table, one truth.
pub const PROTECTED_DEFAULTS: &[(&str, AccessMode)] = &[
    (":project_root/.git", AccessMode::READ),
    (":project_root/.bee", AccessMode::DENY),
    ("~/.ssh", AccessMode::DENY),
    ("~/.aws", AccessMode::DENY),
];

/// Resolve `:project_root` and a leading `~` to absolute paths. Other characters pass through.
pub fn resolve_tokens(raw: &str, r: &dyn Resolver) -> String {
    if let Some(rest) = raw.strip_prefix(":project_root") {
        return format!("{}{}", r.project_root(), rest);
    }
    if let Some(rest) = raw.strip_prefix('~') {
        return format!("{}{}", r.home(), rest);
    }
    raw.to_string()
}

/// Classify a resolved pattern into a verifier-safe primitive, or fail closed.
///
/// Lowering rules (research R6):
/// * no `*`                      → Prefix{subtree} (covers exact and subtree)
/// * `**/<name>` (name no `/`,`*`) → Segment(name)
/// * `*<suffix>` (suffix no `/`,`*`) → Postfix(suffix)   (e.g. `*.log`)
/// * single segment with `*` (no `/`) → BoundedStar
/// * anything else (mid-path `**`, dir-anchored glob) → UnsupportedGlob
pub fn lower_pattern(resolved: &str, mode: AccessMode) -> Result<FsPrimitive, CompileError> {
    let b = resolved.as_bytes();

    if !resolved.contains('*') {
        return Ok(FsPrimitive::Prefix {
            path: b.to_vec(),
            subtree: true,
            mode,
        });
    }

    // `**/<name>`
    if let Some(name) = resolved.strip_prefix("**/") {
        if !name.is_empty() && !name.contains('/') && !name.contains('*') {
            return Ok(FsPrimitive::Segment {
                name: name.as_bytes().to_vec(),
                mode,
            });
        }
    }

    // `*<suffix>` — leading star, single segment, no further star.
    if let Some(suffix) = resolved.strip_prefix('*') {
        if !suffix.is_empty() && !suffix.contains('/') && !suffix.contains('*') {
            return Ok(FsPrimitive::Postfix {
                suffix: suffix.as_bytes().to_vec(),
                mode,
            });
        }
    }

    // Single-segment glob (no `/`), any number of `*`.
    if !resolved.contains('/') {
        return Ok(FsPrimitive::BoundedStar {
            pattern: b.to_vec(),
            mode,
        });
    }

    Err(CompileError::UnsupportedGlob(
        resolved.to_string(),
        "dir-anchored or mid-path '**' globs are not verifier-safe; use a bare '*.ext'/'**/name' \
         pattern or a subtree rule"
            .into(),
    ))
}

/// Split `host:port`, handling bracketed IPv6 (`[::1]:443`).
fn split_host_port(entry: &str) -> Result<(&str, u16), CompileError> {
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| CompileError::BadNetRule(entry.to_string(), "expected host:port".into()))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port: u16 = port
        .parse()
        .map_err(|_| CompileError::BadNetRule(entry.to_string(), "invalid port".into()))?;
    if host.is_empty() {
        return Err(CompileError::BadNetRule(
            entry.to_string(),
            "empty host".into(),
        ));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> AccessMode {
        AccessMode::READ
    }

    #[test]
    fn lower_plain_path_is_subtree() {
        let p = lower_pattern("/home/u/project", m()).unwrap();
        assert_eq!(
            p,
            FsPrimitive::Prefix {
                path: b"/home/u/project".to_vec(),
                subtree: true,
                mode: m()
            }
        );
    }

    #[test]
    fn lower_postfix() {
        assert_eq!(
            lower_pattern("*.log", m()).unwrap(),
            FsPrimitive::Postfix {
                suffix: b".log".to_vec(),
                mode: m()
            }
        );
    }

    #[test]
    fn lower_segment() {
        assert_eq!(
            lower_pattern("**/target", m()).unwrap(),
            FsPrimitive::Segment {
                name: b"target".to_vec(),
                mode: m()
            }
        );
    }

    #[test]
    fn lower_bounded_star() {
        assert_eq!(
            lower_pattern("foo*bar", m()).unwrap(),
            FsPrimitive::BoundedStar {
                pattern: b"foo*bar".to_vec(),
                mode: m()
            }
        );
    }

    #[test]
    fn lower_irreducible_is_error() {
        // mid-path glob
        assert!(matches!(
            lower_pattern("/var/*/secret", m()),
            Err(CompileError::UnsupportedGlob(..))
        ));
        // dir-anchored postfix
        assert!(matches!(
            lower_pattern("/proj/*.log", m()),
            Err(CompileError::UnsupportedGlob(..))
        ));
        // bare mid-path **
        assert!(matches!(
            lower_pattern("/var/**/x", m()),
            Err(CompileError::UnsupportedGlob(..))
        ));
    }

    #[test]
    fn host_port_split() {
        assert_eq!(
            split_host_port("crates.io:443").unwrap(),
            ("crates.io", 443)
        );
        assert_eq!(split_host_port("[::1]:8080").unwrap(), ("::1", 8080));
        assert!(split_host_port("noport").is_err());
        assert!(split_host_port("host:notaport").is_err());
    }
}
