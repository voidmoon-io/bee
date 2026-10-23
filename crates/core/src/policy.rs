//! Authoring policy types and TOML deserialization (the source of truth — Principle IV).
//!
//! These types hold authoring TOML plus effective restrictions inherited during derivation. Pattern
//! strings remain raw (tokens like `:project_root` and `~` unresolved); resolution and glob lowering
//! happen in [`crate::compiler`]. The compiled form remains separate from this reviewable policy.

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPolicy {
    /// Names (resolved via PATH) or absolute paths. A leading `!` pins the binary inode (TOCTOU-hard).
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Network egress allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPolicy {
    /// `host:port` entries; host is a domain, IP, or CIDR. Deny-all is implicit when non-empty.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Exfiltration-detection config (parsed now; enforcement deferred to P3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExfilPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
}

/// Restrictions carried across derivation independently of explicit grants.
/// Serialized as well as cloned so a policy round-trip cannot lose inherited restrictions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveDefaults {
    #[serde(default)]
    pub deny_unmatched_writes: bool,
}

/// A declarative sandbox policy for one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub defaults: EffectiveDefaults,
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
}

#[derive(Deserialize)]
struct Doc {
    policy: Policy,
}

impl Policy {
    /// A write grant opts a root into write allowlisting. Derived policies also retain that
    /// decision independently of whether any of their remaining rules grant writes.
    pub fn denies_unmatched_writes(&self) -> bool {
        self.defaults.deny_unmatched_writes || self.filesystem.values().any(|a| *a == Access::Write)
    }

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
