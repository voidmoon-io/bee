//! Error types for policy parsing, compilation, and attenuation.

use thiserror::Error;

/// Errors from parsing/validating a [`crate::Policy`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("TOML parse error: {0}")]
    Toml(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Errors from compiling a policy into a [`crate::CompiledPolicy`]. All are fail-closed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompileError {
    /// A glob pattern cannot be lowered to a verifier-safe primitive (research R6).
    #[error("unsupported glob pattern '{0}': {1}")]
    UnsupportedGlob(String, String),
    #[error("cannot resolve executable '{0}': {1}")]
    UnresolvableExec(String, String),
    #[error("cannot resolve network host '{0}': {1}")]
    UnresolvableHost(String, String),
    #[error("malformed network rule '{0}': {1}")]
    BadNetRule(String, String),
    /// `[policy.http].targets` alongside `[policy.network].allow` (019, research R4): with
    /// interception active the tool scope's only network rule is the proxy, so a direct allowlist
    /// would be silently replaced — refused rather than ignored.
    #[error(
        "[policy.http] targets and [policy.network] allow are both set ({0}); with interception, \
         tool children reach only the proxy — list these hosts under [policy.http] targets or \
         egress instead"
    )]
    HttpWithDirectNetwork(String),
    #[error(
        "[policy.http] inspect pattern '{0}' matches no target host (inspect must be ⊆ targets)"
    )]
    InspectOutsideTargets(String),
    #[error(
        "[policy.http] insecure_upstream pattern '{0}' is not covered by inspect \
         (insecure_upstream must be ⊆ inspect)"
    )]
    InsecureOutsideInspect(String),
    #[error("[policy.http] host '{0}' is in both targets and egress; a host has exactly one role")]
    HostRoleConflict(String),
    #[error("[policy.http.limits] {0} must be greater than zero")]
    ZeroLimit(String),
}

/// A specific reason a derived policy exceeded its parent (FR-005 / SC-002).
#[derive(Debug, Error, PartialEq, Eq)]
#[error("attenuation violation on {capability}: {reason}")]
pub struct AttenuationError {
    /// Which capability over-reached, e.g. `filesystem:/etc/passwd`, `exec:curl`, `network:host:443`.
    pub capability: String,
    /// Human-readable explanation.
    pub reason: String,
}

impl AttenuationError {
    pub fn new(capability: impl Into<String>, reason: impl Into<String>) -> Self {
        AttenuationError {
            capability: capability.into(),
            reason: reason.into(),
        }
    }
}
