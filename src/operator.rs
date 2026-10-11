//! The Operator: the one seam where an autonomous bee and an interactive bee differ (024 FR-001–FR-005,
//! contracts/operator.md).
//!
//! A session has exactly one [`Operator`]. It decides every capability request through one [`Consent`]
//! adapter, bounded by one timeout, and records every decision — granted, refused by the operator,
//! timed out, or beyond the ceiling and so never offered — in one [`ConsentLog`] that ends up in the
//! session record. Nothing else calls a consent adapter.
//!
//! - **Autonomous** (`bee run`, batches): [`AllowWithinCeiling`]. The ceiling policy file is the
//!   operator's reviewable pre-authorization, so a request already proven within it is granted
//!   without waiting on anyone. Decisions are reported through [`ProgressOutput`].
//! - **Interactive** (the REPL and TUI): [`ChannelConsent`]. The request crosses a channel to the
//!   front-end, which owns the only terminal reader and sends the answer back. A front-end that has
//!   gone away is a refusal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bee_core::Access;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::grants::{GrantDelta, GrantId, GrantOrigin};

/// Which kind of operator a session has. Recorded on every [`ConsentRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorKind {
    /// A person answers each request.
    Interactive,
    /// The ceiling policy decides; nobody is asked.
    Autonomous,
}

/// An adapter's answer to one request. When in doubt, refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Granted,
    Denied,
}

/// A capability request, owned so it can cross a channel to a front-end. It carries every kind of
/// capability, so no field can be approved unseen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRequest {
    /// Why the grant is asked for.
    pub origin: GrantOrigin,
    /// Harness tools to register.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// Filesystem grants.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filesystem: BTreeMap<String, Access>,
    /// Binaries to execute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<String>,
    /// Network destinations (`host:port`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net: Vec<String>,
    /// Interception targets to add to the session's target scope (019 US3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_targets: Vec<String>,
    /// The model turn the request was made on; 0 at start-up.
    pub turn: u32,
}

impl ConsentRequest {
    /// The request for `delta`, every capability kind included.
    pub fn from_delta(origin: GrantOrigin, delta: &GrantDelta, turn: u32) -> Self {
        ConsentRequest {
            origin,
            tools: delta.tools.clone(),
            filesystem: delta.filesystem.clone(),
            exec: delta.exec.clone(),
            net: delta.net.clone(),
            http_targets: delta.http_targets.clone(),
            turn,
        }
    }

    /// Who is asking, as the prompt names it: the skill, or the kind of trigger.
    pub fn requester(&self) -> &str {
        match &self.origin {
            GrantOrigin::SkillRequires { skill } | GrantOrigin::Startup { skill } => skill,
            GrantOrigin::ReactiveDenial { .. } => "reactive-denial",
            GrantOrigin::Explicit => "explicit",
            GrantOrigin::ProxyRefusal { .. } => "proxy-refusal",
        }
    }

    /// The request as an operator reads it: a header naming the requester, then one line per granted
    /// item. Every interactive front-end renders through this, so none can forget a field — a grant
    /// field that is not rendered here is approved unseen.
    ///
    /// Every value is passed through [`crate::safe_text::safe_line`]: the fields can be skill-
    /// authored or derived from a kernel audit, and this text *is* the consent boundary, so a value
    /// must not be able to forge a second line or hide behind terminal escapes.
    pub fn render_lines(&self) -> Vec<String> {
        let safe = crate::safe_text::safe_line;
        let mut lines = vec![format!(
            "'{}' requests extra capabilities:",
            safe(self.requester())
        )];
        if !self.tools.is_empty() {
            let tools: Vec<_> = self.tools.iter().map(|t| safe(t)).collect();
            lines.push(format!("  tools: {}", tools.join(", ")));
        }
        for (path, access) in &self.filesystem {
            lines.push(format!(
                "  filesystem: {} = {}",
                safe(path),
                access_word(*access)
            ));
        }
        for dest in &self.net {
            lines.push(format!("  network: connect {}", safe(dest)));
        }
        for bin in &self.exec {
            lines.push(format!("  exec: {}", safe(bin)));
        }
        for target in &self.http_targets {
            lines.push(format!(
                "  http target: {} (testable through the proxy)",
                safe(target)
            ));
        }
        lines
    }
}

/// The word an operator reads for an access mode.
pub fn access_word(a: Access) -> &'static str {
    match a {
        Access::Read => "read",
        Access::Write => "write",
        Access::Deny => "deny",
    }
}

/// Whether a recorded request was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Granted,
    Refused,
}

/// Why a request ended as it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The operator granted it.
    Granted,
    /// The operator refused it, or the front-end that would have asked is gone.
    DeniedByOperator,
    /// Nobody answered within the timeout.
    TimedOut,
    /// Beyond the ceiling: refused without being offered to anyone.
    BeyondCeiling,
}

impl Reason {
    fn label(self) -> &'static str {
        match self {
            Reason::Granted => "granted",
            Reason::DeniedByOperator => "denied by operator",
            Reason::TimedOut => "timed out",
            Reason::BeyondCeiling => "beyond ceiling",
        }
    }
}

/// One decision, as the session record keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// The decision's position in the session, from 0.
    pub seq: u32,
    pub request: ConsentRequest,
    pub decision: Verdict,
    pub reason: Reason,
    pub operator: OperatorKind,
    /// The lease a granted request became, once applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<GrantId>,
    /// When the decision was made, RFC 3339.
    pub ts: String,
}

impl ConsentRecord {
    /// The record as one progress line: `consent: granted (granted) — skill 'x'`.
    pub fn line(&self) -> String {
        let decision = match self.decision {
            Verdict::Granted => "granted",
            Verdict::Refused => "refused",
        };
        format!(
            "consent: {decision} ({}) — {}",
            self.reason.label(),
            origin_text(&self.request.origin)
        )
    }
}

fn origin_text(origin: &GrantOrigin) -> String {
    let safe = crate::safe_text::safe_line;
    match origin {
        GrantOrigin::Startup { skill } => format!("start-up grant for skill '{}'", safe(skill)),
        GrantOrigin::SkillRequires { skill } => format!("skill '{}'", safe(skill)),
        GrantOrigin::ReactiveDenial { op, target } => {
            format!("kernel denial {} {}", safe(op), safe(target))
        }
        GrantOrigin::ProxyRefusal { host, port, .. } => {
            format!("proxy refusal {}:{port}", safe(host))
        }
        GrantOrigin::Explicit => "explicit request".to_string(),
    }
}

/// Every decision a session made, in order.
pub type ConsentLog = Arc<Mutex<Vec<ConsentRecord>>>;

/// Decides one request. May await a person; must not block the executor. The [`Operator`] applies
/// the timeout, so an adapter never needs its own.
#[async_trait::async_trait]
pub trait Consent: Send + Sync {
    async fn decide(&self, request: &ConsentRequest) -> Decision;
}

/// Where the Operator reports what it decided.
pub trait SessionOutput: Send + Sync {
    /// One line of session information.
    fn info(&self, line: &str);
    /// A decision was made and recorded.
    fn consent_decided(&self, record: &ConsentRecord) {
        self.info(&record.line());
    }
}

impl<T: crate::repl::ReplOutput + ?Sized> SessionOutput for T {
    fn info(&self, line: &str) {
        crate::repl::ReplOutput::info(self, line);
    }
}

/// Reports nothing.
pub struct NullOutput;

impl SessionOutput for NullOutput {
    fn info(&self, _line: &str) {}
}

/// The Autonomous operator's output: the episode's progress lines, with one additive line per
/// decision, `  consent: …` (contracts/operator.md).
pub struct ProgressOutput(pub Arc<crate::episode::ProgressSink>);

impl SessionOutput for ProgressOutput {
    fn info(&self, line: &str) {
        (self.0)(line);
    }
    fn consent_decided(&self, record: &ConsentRecord) {
        (self.0)(&format!("  {}", record.line()));
    }
}

/// Grant every request — used when the **ceiling policy file** *is* the authorization (batch and CTF
/// episodes, Constitution IV). Safe because the Operator is only asked about a request already proven
/// within the ceiling; with no distinct ceiling, base is the ceiling and nothing reaches here.
pub struct AllowWithinCeiling;

#[async_trait::async_trait]
impl Consent for AllowWithinCeiling {
    async fn decide(&self, _request: &ConsentRequest) -> Decision {
        Decision::Granted
    }
}

/// Refuse every request.
pub struct DenyAll;

#[async_trait::async_trait]
impl Consent for DenyAll {
    async fn decide(&self, _request: &ConsentRequest) -> Decision {
        Decision::Denied
    }
}

/// A request waiting on a front-end, and where its answer goes. Dropping `reply` unanswered refuses.
pub struct ConsentAsk {
    pub request: ConsentRequest,
    pub reply: oneshot::Sender<Decision>,
}

/// The front-end's end of a [`ChannelConsent`].
pub type ConsentReceiver = mpsc::UnboundedReceiver<ConsentAsk>;

/// Interactive consent: each request goes to the front-end over a channel, and the answer comes back
/// on a oneshot. A front-end that has gone away, or drops the reply, refuses.
pub struct ChannelConsent {
    tx: mpsc::UnboundedSender<ConsentAsk>,
}

impl ChannelConsent {
    pub fn new() -> (Self, ConsentReceiver) {
        let (tx, rx) = mpsc::unbounded_channel();
        (ChannelConsent { tx }, rx)
    }
}

#[async_trait::async_trait]
impl Consent for ChannelConsent {
    async fn decide(&self, request: &ConsentRequest) -> Decision {
        let (reply, answer) = oneshot::channel();
        let ask = ConsentAsk {
            request: request.clone(),
            reply,
        };
        if self.tx.send(ask).is_err() {
            return Decision::Denied;
        }
        answer.await.unwrap_or(Decision::Denied)
    }
}

/// The session's operator: one consent adapter, one output, one timeout, one log. Cloning shares
/// all four.
#[derive(Clone)]
pub struct Operator {
    kind: OperatorKind,
    consent: Arc<dyn Consent>,
    output: Arc<RwLock<Arc<dyn SessionOutput>>>,
    timeout: Duration,
    log: ConsentLog,
}

impl Operator {
    /// A person answers through the front-end at the other end of `consent`. Default timeout 120 s.
    pub fn interactive(consent: ChannelConsent, output: Arc<dyn SessionOutput>) -> Self {
        Self::new(
            OperatorKind::Interactive,
            Arc::new(consent),
            output,
            Duration::from_secs(120),
        )
    }

    /// The ceiling decides ([`AllowWithinCeiling`]). Default timeout 60 s.
    pub fn autonomous(output: Arc<dyn SessionOutput>) -> Self {
        Self::new(
            OperatorKind::Autonomous,
            Arc::new(AllowWithinCeiling),
            output,
            Duration::from_secs(60),
        )
    }

    /// An operator over any adapter — a test's scripted consent, or a custom approver.
    pub fn with_consent(kind: OperatorKind, consent: Arc<dyn Consent>) -> Self {
        Self::new(kind, consent, Arc::new(NullOutput), Duration::from_secs(60))
    }

    fn new(
        kind: OperatorKind,
        consent: Arc<dyn Consent>,
        output: Arc<dyn SessionOutput>,
        timeout: Duration,
    ) -> Self {
        Operator {
            kind,
            consent,
            output: Arc::new(RwLock::new(output)),
            timeout,
            log: ConsentLog::default(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn kind(&self) -> OperatorKind {
        self.kind
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Decide `request`: ask the adapter, bounded by the timeout; record the decision; tell the
    /// output. The only way bee asks for consent.
    pub async fn consent(&self, request: ConsentRequest) -> ConsentRecord {
        let reason = match tokio::time::timeout(self.timeout, self.consent.decide(&request)).await {
            Ok(Decision::Granted) => Reason::Granted,
            Ok(Decision::Denied) => Reason::DeniedByOperator,
            Err(_) => Reason::TimedOut,
        };
        self.record(request, reason)
    }

    /// Record a refusal made without asking. Only [`Reason::BeyondCeiling`] is decided this way.
    pub fn record_unasked(&self, request: ConsentRequest, reason: Reason) -> ConsentRecord {
        debug_assert_eq!(reason, Reason::BeyondCeiling);
        self.record(request, reason)
    }

    /// Note the lease a granted decision became.
    pub fn attach_lease(&self, record: &ConsentRecord, lease: &GrantId) {
        let mut log = self.log.lock().expect("consent log");
        if let Some(r) = log.iter_mut().find(|r| r.seq == record.seq) {
            r.lease = Some(lease.clone());
        }
    }

    fn record(&self, request: ConsentRequest, reason: Reason) -> ConsentRecord {
        let record = {
            let mut log = self.log.lock().expect("consent log");
            let record = ConsentRecord {
                seq: log.len() as u32,
                request,
                decision: if reason == Reason::Granted {
                    Verdict::Granted
                } else {
                    Verdict::Refused
                },
                reason,
                operator: self.kind,
                lease: None,
                ts: now_rfc3339(),
            };
            log.push(record.clone());
            record
        };
        self.output().consent_decided(&record);
        record
    }

    /// Where session information goes.
    pub fn output(&self) -> Arc<dyn SessionOutput> {
        self.output.read().expect("operator output").clone()
    }

    /// Point session information at a front-end that exists only once the session is running: the
    /// inline REPL's printer, the TUI's event sink.
    pub fn set_output(&self, output: Arc<dyn SessionOutput>) {
        *self.output.write().expect("operator output") = output;
    }

    /// Every decision so far, without draining them.
    pub fn log(&self) -> Vec<ConsentRecord> {
        self.log.lock().expect("consent log").clone()
    }

    /// Every decision so far; the log is left empty.
    pub fn take_log(&self) -> Vec<ConsentRecord> {
        std::mem::take(&mut *self.log.lock().expect("consent log"))
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ConsentRequest {
        ConsentRequest {
            origin: GrantOrigin::SkillRequires {
                skill: "probe".into(),
            },
            tools: vec!["bash".into()],
            filesystem: BTreeMap::from([("/tmp/w".to_string(), Access::Write)]),
            exec: vec!["/bin/true".into()],
            net: vec!["10.0.0.1:443".into()],
            http_targets: vec!["app.test:443".into()],
            turn: 3,
        }
    }

    #[test]
    fn every_capability_kind_is_rendered() {
        let lines = request().render_lines().join("\n");
        for needle in [
            "'probe' requests",
            "tools: bash",
            "filesystem: /tmp/w = write",
            "network: connect 10.0.0.1:443",
            "exec: /bin/true",
            "http target: app.test:443",
        ] {
            assert!(lines.contains(needle), "{needle} missing from:\n{lines}");
        }
    }

    #[tokio::test]
    async fn a_dropped_front_end_refuses() {
        let (consent, rx) = ChannelConsent::new();
        drop(rx);
        let op = Operator::interactive(consent, Arc::new(NullOutput));
        let rec = op.consent(request()).await;
        assert_eq!(
            (rec.decision, rec.reason),
            (Verdict::Refused, Reason::DeniedByOperator)
        );
    }

    #[tokio::test]
    async fn a_dropped_reply_refuses() {
        let (consent, mut rx) = ChannelConsent::new();
        let op = Operator::interactive(consent, Arc::new(NullOutput));
        let front_end = tokio::spawn(async move {
            let ask = rx.recv().await.unwrap();
            drop(ask.reply);
        });
        let rec = op.consent(request()).await;
        front_end.await.unwrap();
        assert_eq!(rec.reason, Reason::DeniedByOperator);
    }

    #[tokio::test]
    async fn records_are_numbered_and_kept_in_order() {
        let op = Operator::autonomous(Arc::new(NullOutput));
        let a = op.consent(request()).await;
        let b = op.record_unasked(request(), Reason::BeyondCeiling);
        op.attach_lease(&a, &"g1".to_string());
        let log = op.take_log();
        assert_eq!(log.len(), 2);
        assert_eq!((log[0].seq, log[1].seq), (0, 1));
        assert_eq!(log[0].lease.as_deref(), Some("g1"));
        assert_eq!(b.decision, Verdict::Refused);
        assert!(op.log().is_empty());
    }

    #[test]
    fn the_progress_line_names_the_decision_and_its_origin() {
        let rec = ConsentRecord {
            seq: 0,
            request: request(),
            decision: Verdict::Refused,
            reason: Reason::BeyondCeiling,
            operator: OperatorKind::Autonomous,
            lease: None,
            ts: String::new(),
        };
        assert_eq!(
            rec.line(),
            "consent: refused (beyond ceiling) — skill 'probe'"
        );
    }
}
