//! Authoring policy types and TOML deserialization (the source of truth — Principle IV).
//!
//! These types mirror the TOML in `contracts/policy.schema.md` verbatim. They hold *raw* pattern
//! strings (tokens like `:project_root` and `~` unresolved); resolution and glob lowering happen in
//! [`crate::compiler`]. Keeping authoring separate from the compiled form keeps policy reviewable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Enforcement mode for a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block denied operations.
    #[default]
    Enforce,
    /// Allow but emit an "observed" audit record (dry-run, FR-016).
    Observe,
}

impl Mode {
    /// Strictness ordering: `Enforce` (blocks) is stricter than `Observe` (allows).
    /// Used by attenuation — a child may not be looser than its parent.
    pub fn strictness(self) -> u8 {
        match self {
            Mode::Enforce => 1,
            Mode::Observe => 0,
        }
    }
}

impl From<Mode> for bee_common::ScopeMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Enforce => bee_common::ScopeMode::Enforce,
            Mode::Observe => bee_common::ScopeMode::Observe,
        }
    }
}

/// Authoring-level file access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
    Deny,
}

impl Access {
    /// Convert to the kernel bitflag representation.
    pub fn to_bits(self) -> bee_common::AccessMode {
        use bee_common::AccessMode as M;
        match self {
            // Write implies read.
            Access::Write => M::WRITE.union(M::READ),
            Access::Read => M::READ,
            Access::Deny => M::DENY,
        }
    }

    /// Is `self` an access level less-than-or-equal to `other` (for attenuation)?
    /// Deny is the most restrictive and is `<=` everything.
    pub fn is_subset_of(self, other: Access) -> bool {
        match (self, other) {
            (Access::Deny, _) => true, // adding a deny always narrows
            (Access::Read, Access::Read) => true,
            (Access::Read, Access::Write) => true, // read ⊆ write
            (Access::Write, Access::Write) => true,
            _ => false,
        }
    }
}

/// Executable allowlist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecPolicy {
    /// Names (resolved via PATH) or absolute paths. A leading `!` pins the binary inode (TOCTOU-hard).
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Network egress allowlist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetPolicy {
    /// `host:port` entries; host is a domain, IP, or CIDR. Deny-all is implicit when non-empty.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Exfiltration-detection config (parsed now; enforcement deferred to P3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExfilPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
}

/// A declarative sandbox policy for one scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub mode: Mode,
    /// Path → access. Most-specific match wins at enforcement time; `deny` beats a grant at a tie.
    #[serde(default)]
    pub filesystem: BTreeMap<String, Access>,
    #[serde(default)]
    pub exec: ExecPolicy,
    #[serde(default)]
    pub network: NetPolicy,
    #[serde(default)]
    pub exfiltration: ExfilPolicy,
    /// HTTP(S) interception target scope (019-http-intercept). Present with non-empty `targets` ⇒
    /// tool children reach only the session's interception proxy, and the proxy reaches only these
    /// hosts (contracts/policy-http.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpPolicy>,
}

pub use crate::pattern::HostPattern;

/// `host:port` — a DNS name or IP literal and one port, the same shape as a `network.allow` entry.
/// The host is normalised (lowercase, no trailing dot, no IPv6 brackets) so equality is semantic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl TryFrom<String> for HostPort {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let t = s.trim();
        let (host, port) = t
            .rsplit_once(':')
            .ok_or_else(|| format!("'{s}' must be host:port"))?;
        let bracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
        // An unbracketed IPv6 literal (`fe80::1`) would otherwise split on its own last colon and
        // parse silently as a different host and port.
        if bracketed.is_none() && host.contains(':') {
            return Err(format!(
                "'{s}': an IPv6 address must be bracketed, as [addr]:port"
            ));
        }
        let host = crate::pattern::normalize_host(bracketed.unwrap_or(host));
        if host.is_empty() || host.contains('*') || host.contains('/') {
            return Err(format!("'{s}': invalid host"));
        }
        let port: u16 = port.parse().map_err(|_| format!("'{s}': invalid port"))?;
        if port == 0 {
            return Err(format!("'{s}': port 0"));
        }
        Ok(HostPort { host, port })
    }
}

impl From<HostPort> for String {
    fn from(h: HostPort) -> String {
        h.to_string()
    }
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// `[policy.http]` — the interception target scope (data-model.md §HttpPolicy). Unknown keys are a
/// parse error naming the key (fail closed: a typo'd `inspect` must not silently inspect nothing).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicy {
    /// Hosts that may be **tested**. Non-empty ⇔ interception is active.
    #[serde(default)]
    pub targets: Vec<HostPort>,
    /// Hosts that may be **reached** through the proxy as tunnels only; never testable.
    #[serde(default)]
    pub egress: Vec<HostPort>,
    /// Hosts (⊆ `targets`) whose TLS the proxy decrypts.
    #[serde(default)]
    pub inspect: Vec<HostPattern>,
    /// Hosts (⊆ `inspect`) whose upstream certificate is not verified.
    #[serde(default)]
    pub insecure_upstream: Vec<HostPattern>,
    #[serde(default)]
    pub limits: HttpLimits,
}

impl HttpPolicy {
    /// Whether interception is active: there is something to test.
    pub fn is_active(&self) -> bool {
        !self.targets.is_empty()
    }
}

/// Pacing and volume limits for `[policy.http]`. Every limit attenuates downward (child ≤ parent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpLimits {
    pub rps: u32,
    pub concurrency: u32,
    pub max_requests_per_run: u32,
    pub max_body_bytes: u64,
    pub store_cap_bytes: u64,
}

impl Default for HttpLimits {
    fn default() -> Self {
        HttpLimits {
            rps: 10,
            concurrency: 4,
            max_requests_per_run: 2000,
            max_body_bytes: 16 * 1024 * 1024,
            store_cap_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Deserialize)]
struct Doc {
    policy: Policy,
}

impl Policy {
    /// Parse and structurally validate a policy from a TOML string.
    pub fn from_toml(s: &str) -> Result<Policy, PolicyError> {
        let doc: Doc = toml::from_str(s).map_err(|e| PolicyError::Toml(e.to_string()))?;
        let policy = doc.policy;
        policy.validate()?;
        Ok(policy)
    }

    /// Read and parse a policy from a file path.
    pub fn from_path(p: &std::path::Path) -> Result<Policy, PolicyError> {
        let s = std::fs::read_to_string(p)
            .map_err(|e| PolicyError::Io(format!("{}: {e}", p.display())))?;
        Policy::from_toml(&s)
    }

    /// Structural validation independent of the host environment.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.name.trim().is_empty() {
            return Err(PolicyError::Invalid("policy.name must not be empty".into()));
        }
        for entry in &self.network.allow {
            if !entry.contains(':') {
                return Err(PolicyError::Invalid(format!(
                    "network rule '{entry}' must be host:port"
                )));
            }
        }
        Ok(())
    }
}
