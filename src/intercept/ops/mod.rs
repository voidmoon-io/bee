//! The Interceptor's typed operations (024 US6, FR-035–FR-038, contracts/intercept-ops.md).
//!
//! Send with redirect following, replay with edits and a measured diff, fuzz from a template, the
//! sitemap and bounded exchange reads — usable without going through a tool. The `http_*` tools are
//! thin adapters over these: they parse JSON arguments into a spec, make one op call, and shape the
//! result. Ops never see a `Sandbox`; the caller passes the call's attribution as a [`CallCtx`].

pub mod bound;
pub mod fuzz_run;
pub mod read;
pub mod replay;
pub mod send;
pub mod sitemap;

pub use fuzz_run::{fuzz, template_from, FuzzResult, FuzzSpec};
pub use read::{read_exchange, scope_view, Part};
pub use replay::{replay, side_of, stored_request, ReplayResult, ReplaySpec};
pub use send::{build_request, send, Hop, Preview, SendResult, SendSpec, StructuredRequest};
pub use sitemap::{sitemap, SitemapQuery};

use crate::intercept::control::{ProxyEventKind, RawTarget};
use crate::intercept::sidecar::InterceptError;

/// Which call an op's traffic is attributed to: call id, turn and origin, as they travel to the
/// worker with the call's credential.
pub type CallCtx = crate::intercept::control::WireCtx;

/// Why an operation did not produce its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// The proxy is not running; nothing was sent directly instead.
    Unavailable(String),
    /// The request cannot be made as given (bad argument, unknown exchange, …).
    Invalid(String),
    /// The scope or the policy's limits refused it. `note` adds what happened before the refusal.
    Refused {
        reason: Refusal,
        note: Option<String>,
    },
    /// Anything else: the store, the worker.
    Failed(String),
}

impl From<InterceptError> for OpError {
    fn from(e: InterceptError) -> OpError {
        match e {
            InterceptError::Unavailable(d) => OpError::Unavailable(d),
            other => OpError::Failed(other.to_string()),
        }
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::Unavailable(d) | OpError::Invalid(d) | OpError::Failed(d) => f.write_str(d),
            OpError::Refused { reason, .. } => write!(f, "refused: {reason:?}"),
        }
    }
}

/// A refusal by the Target scope or the policy's limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `layer` names who refused, e.g. `proxy (refused_scope)`.
    OutOfScope {
        host: String,
        port: u16,
        layer: String,
    },
    /// The host is reachable only as a tunnel.
    EgressOnly {
        host: String,
    },
    LimitExceeded {
        limit: String,
        value: u64,
    },
}

impl Refusal {
    /// The refusal a proxy event of `kind` on `target` stands for.
    pub fn from_proxy(kind: &ProxyEventKind, target: &RawTarget) -> Refusal {
        match kind {
            ProxyEventKind::RefusedEgressOnly => Refusal::EgressOnly {
                host: target.host.clone(),
            },
            ProxyEventKind::RefusedLimit => Refusal::LimitExceeded {
                limit: "rps/concurrency".into(),
                value: 0,
            },
            _ => Refusal::OutOfScope {
                host: target.host.clone(),
                port: target.port,
                layer: format!("proxy ({})", kind.as_str()),
            },
        }
    }
}
