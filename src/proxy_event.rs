//! Proxy-layer events (019-http-intercept, research R14): what the interception proxy refused, and
//! the rule and hold notices it raised.
//!
//! Deliberately a **different type** from the kernel's `AuditEvent`: the two layers must stay
//! distinguishable everywhere they are shown (FR-009, FR-011), so a proxy decision is never rendered
//! or counted as a kernel one. Ungated plain data, so transcripts carry it in every build.

use serde::{Deserialize, Serialize};

/// Kinds of proxy-layer event (research R14). Never merged with kernel `AuditEvent`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyEventKind {
    RefusedOutOfScope,
    RefusedSniMismatch,
    RefusedBadCredential,
    RefusedEgressOnly,
    RefusedLimit,
    RefusedAddressDrift,
    RuleFired,
    Held,
    AutoForwarded,
}

impl ProxyEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyEventKind::RefusedOutOfScope => "refused_out_of_scope",
            ProxyEventKind::RefusedSniMismatch => "refused_sni_mismatch",
            ProxyEventKind::RefusedBadCredential => "refused_bad_credential",
            ProxyEventKind::RefusedEgressOnly => "refused_egress_only",
            ProxyEventKind::RefusedLimit => "refused_limit",
            ProxyEventKind::RefusedAddressDrift => "refused_address_drift",
            ProxyEventKind::RuleFired => "rule_fired",
            ProxyEventKind::Held => "held",
            ProxyEventKind::AutoForwarded => "auto_forwarded",
        }
    }

    /// A refusal, as opposed to a rule or hold notice.
    pub fn is_refusal(self) -> bool {
        self.as_str().starts_with("refused_")
    }
}

/// A proxy-layer event (data-model.md §ProxyEvent). `layer` is always `"proxy"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEvent {
    pub ts: String,
    pub session_id: String,
    #[serde(default)]
    pub call_id: Option<String>,
    pub layer: String,
    pub kind: ProxyEventKind,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub detail: serde_json::Value,
}
