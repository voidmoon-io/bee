//! The episode transcript (FR-009) — the product of a run — plus the output-truncation helper
//! (FR-015) that keeps both the model context and the on-disk record bounded (SC-006).

use bee_core::AuditEvent;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::provider::{ToolCall, Usage};
use crate::tools::ToolResult;

/// Default per-tool-result output cap: 100 KB (FR-015).
pub const DEFAULT_OUTPUT_CAP: usize = 100 * 1024;

/// Truncate `content` to `cap` bytes (on a UTF-8 char boundary). Returns the (possibly shortened)
/// string, whether it was cut, and the original byte length when it was.
pub fn truncate(content: String, cap: usize) -> (String, bool, Option<usize>) {
    if content.len() <= cap {
        return (content, false, None);
    }
    let original = content.len();
    let end = char_floor(&content, cap);
    let mut out = content[..end].to_string();
    out.push_str(&format!("\n[truncated: {original} bytes, showing {end}]"));
    (out, true, Some(original))
}

/// The largest char boundary of `s` at or below `n` — a cut there never splits a multi-byte sequence.
pub(crate) fn char_floor(s: &str, n: usize) -> usize {
    if n >= s.len() {
        return s.len();
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// How an episode ended (research H10). US3 adds `Captured`/`NotCaptured`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EpisodeStatus {
    /// The agent ran to completion (the *operation* may still have been denied).
    Completed,
    /// A lifecycle hook stopped execution.
    Terminated { detail: String },
    /// The wall-clock deadline or turn limit was hit.
    Timeout,
    /// A model turn produced only text and no tool calls (SC-007).
    NoToolCalls,
    /// The provider failed after ret/backoff (FR-017).
    ApiError { detail: String },
    /// Scope/engine setup failed; the loop never started.
    InfraError { detail: String },
    /// The agent submitted the correct flag value (US3, CTF mode). `turn` is the 0-based turn index
    /// on which the capture happened.
    Captured { turn: u32 },
    /// The agent gave up or exhausted its turns without capturing the flag (US3, CTF mode).
    NotCaptured,
    /// The next request could not be brought within the model's context budget (025 FR-002,
    /// FR-014), or the provider refused one as too long.
    ContextExhausted { detail: String },
    /// The same failing call was made `repeats` times in a row, and the run was ended (025 FR-027).
    Stuck {
        tool: String,
        arguments: serde_json::Value,
        repeats: u32,
    },
    /// The model called `finish` (025 US3). `turn` is the 0-based turn it was called on.
    Finished {
        outcome: crate::tools::finish::FinishOutcome,
        summary: String,
        turn: u32,
    },
    /// `finish` was offered, and the model ended with a second text-only turn instead (025 FR-035).
    EndedWithoutFinish,
    /// The session's shared turn budget ran out (018 FR-023): a subagent drew the last of it, or
    /// this loop is one.
    BudgetExhausted,
}

/// One recorded tool call within a turn: the request, the result, and the audit events the kernel
/// emitted for it (FR-008 correlation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedCall {
    /// The enclosing codemode call when this call ran inside a script (023); `None` for a call
    /// the model made directly. Nested scripts point at their immediate parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_call_id: Option<String>,
    pub call: ToolCall,
    pub result: ToolResult,
    /// Kernel audit events this call produced — the tool scope's, plus the proxy scope's tagged
    /// `scope_id = "proxy"` (019).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<AuditEvent>,
    /// Proxy-layer events this call produced (019, research R14). Kept apart from `audit`: a
    /// user-space refusal is never a kernel one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_events: Vec<crate::proxy_event::ProxyEvent>,
    /// The audit of an attempt that was denied and then retried under a widened scope — the denial
    /// that justified widening it (024 FR-021). `audit` is the retry's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_attempt_audit: Vec<AuditEvent>,
    /// The proxy events of an attempt a proxy refusal retried — the refusal that justified widening
    /// the target scope (024 FR-021). `proxy_events` is the retry's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_attempt_proxy_events: Vec<crate::proxy_event::ProxyEvent>,
    /// Every widen cycle run during the call, in order, with what started it (024 FR-018).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalations: Vec<crate::call::EscalationRecord>,
    /// A retry ran to completion, and `result` and `audit` are its.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retried: bool,
    /// An attempt hit the time limit. When it was a retry, the attempt before it stands (FR-025).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
    /// The call came after `finish` in the same turn and was never run (025 FR-034).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub not_run: bool,
    /// A hook refused the call before it ran (024 FR-031); the tool never executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_by_hook: Option<String>,
    /// The subagent this call delegated to (018), with its own turn-by-turn record. Absent on every
    /// call that did not delegate, so a session that never delegates records exactly what it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<Box<DelegationRecord>>,
}

/// What one delegation left behind (018, contracts/delegation-record.md): which agent ran, in which
/// scope, how it ended, and its whole transcript. The child's kernel events are in that transcript,
/// stamped with its scope id, and never in the parent's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub agent: String,
    /// The child's scope id; empty when it was refused before a scope existed.
    pub scope_id: String,
    /// Whether a kernel scope confined the child. Recorded when it was spawned, so a transcript
    /// read later tells an enforced delegation from prompt isolation without knowing the build.
    pub enforced: bool,
    /// 1 for a subagent of the session itself.
    pub depth: u32,
    pub outcome: DelegationOutcome,
    /// Tokens the child's model calls used, input plus output, as the provider reported them.
    /// `None`: not counted — a harness's model use is not visible to bee (026 R14) — never zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<u64>,
    /// The child's own record. `None` when it never ran, and for a harness (see `harness`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<Box<EpisodeTranscript>>,
    /// The child's model turns. `None`: not counted (a harness), never zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turns_used: Option<u32>,
    /// What an external harness did (026): its turns, tool calls, the permissions bee answered for
    /// it, and the client methods it was refused. `None` for bee's own loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<Box<HarnessRecord>>,
    /// The child's kernel events, when it has no transcript of its own to hold them (a harness).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<AuditEvent>,
}

/// An external harness's run, as bee saw it over ACP (026 data-model.md, research R13).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HarnessRecord {
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Keys only: values may be credentials.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
    pub protocol_version: u16,
    /// The harness's `agentInfo`, `name version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_info: Option<String>,
    /// One per prompt bee sent (one in this feature).
    #[serde(default)]
    pub turns: Vec<HarnessTurn>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<PermissionRecord>,
    /// Client methods the harness called anyway (`fs/*`, `terminal/*`, …), each refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_methods: Vec<String>,
    /// The prompt's `stopReason`, or why there was none (`exited`, `protocol_error`, `deadline`).
    pub stop_reason: String,
    /// The last 4 KiB of its stderr.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr_tail: String,
}

/// What one prompt produced.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HarnessTurn {
    /// Its `agent_message_chunk` text, concatenated.
    pub text: String,
    /// Bytes of `agent_thought_chunk` text (the thoughts themselves are not kept).
    #[serde(default)]
    pub thoughts_len: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<HarnessToolCall>,
}

/// A tool call the harness reported, merged across its updates. Raw values are capped.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HarnessToolCall {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_input: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
}

/// A permission the harness asked for and bee answered (research R11). Never shown to a person.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionRecord {
    /// The tool call it was about.
    pub tool_call: String,
    pub title: String,
    /// Each offered option as `kind:id`.
    pub offered: Vec<String>,
    /// The chosen option as `kind:id`, or `cancelled`.
    pub chosen: String,
    pub ts: String,
}

/// How a delegation ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelegationOutcome {
    /// The child's loop ended on its own and its scope was torn down cleanly.
    Completed,
    /// A shared bound stopped the child before it ended on its own.
    CutShort { reason: CutShortReason },
    /// The delegation never got a scope.
    Refused { reason: RefusalReason },
    /// The child could not start, failed, or its scope would not tear down.
    Failed { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutShortReason {
    /// The agent's own turn limit.
    Turns,
    /// The session's shared turn budget (FR-023).
    SharedTurns,
    /// The shared wall-clock deadline.
    Deadline,
}

/// Why a delegation was refused (contracts/task-tool.md). Each names its cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RefusalReason {
    UnknownAgent {
        name: String,
    },
    /// The agent lists a tool the delegating session does not hold, or cannot hand to a child.
    ToolNotHeld {
        tool: String,
    },
    /// The agent's declaration asks for more than the session holds.
    OverGrant {
        detail: String,
    },
    DepthExceeded {
        max_depth: u32,
    },
    /// The session cannot delegate at all, and why.
    Unavailable {
        detail: String,
    },
}

/// The interception session a transcript was recorded under (019 T044): how `[policy.http]` was
/// enforced, and — when only by the proxy — the reason and the operator's acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpSessionHeader {
    /// `kernel` or `advisory`.
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_reason: Option<String>,
    /// The operator passed `--http-scope-advisory`.
    #[serde(default)]
    pub advisory_acknowledged: bool,
}

/// A panel-targeted render recorded in / replayed from a transcript (008-grid-tui, FR-010/SC-009): a
/// render whose target was a named panel. Pure serde (no ratatui/rhai types; NFR-002/SC-019), so the
/// transcript stays re-renderable without pulling terminal types into `bee-core`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PanelUpdate {
    pub id: String,
    pub spec: crate::render_spec::RenderSpec,
}

/// One model turn as recorded: assistant prose + the calls it made (with results + audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptTurn {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistant_text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<RecordedCall>,
    /// Wall-clock duration of this turn (model round-trip + tool execution), milliseconds.
    pub duration_ms: u64,
    /// bee's own notes added to the model's input before this turn's model call (025 FR-028): passive
    /// leads, stuck reminders, the finish reminder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<HarnessNote>,
}

/// What a [`HarnessNote`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    /// A sandbox turn note, e.g. "N new passive leads" (019 US8).
    Passive,
    /// The same call has been repeated (025 FR-024).
    StuckGeneral,
    /// The same call keeps being denied by policy (025 FR-026).
    StuckPolicy,
    /// The run ends only through the finish tool (025 FR-035).
    FinishRequired,
}

/// One note in bee's own words, added to the model's input as a user message (025 FR-028).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessNote {
    pub kind: NoteKind,
    pub text: String,
    /// The repeated call a stuck note answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<ToolCall>,
}

impl HarnessNote {
    /// A note with no call attached.
    pub fn new(kind: NoteKind, text: impl Into<String>) -> HarnessNote {
        HarnessNote {
            kind,
            text: text.into(),
            call: None,
        }
    }
}

/// Episode timing (FR-009).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timing {
    pub started_at: String,
    pub ended_at: String,
    pub total_ms: u64,
}

/// Known userspace audit loss. A default value does not establish kernel ring completeness.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHealth {
    pub queue_dropped: u64,
    pub retention_dropped: u64,
    pub stream_failed: bool,
    pub drain_limited: bool,
}

impl AuditHealth {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn incomplete(&self) -> bool {
        self.queue_dropped > 0
            || self.retention_dropped > 0
            || self.stream_failed
            || self.drain_limited
    }
}

/// The serde-serialized product of an episode (JSON out).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeTranscript {
    pub scenario_id: String,
    pub model_id: String,
    pub status: EpisodeStatus,
    pub turns: Vec<TranscriptTurn>,
    /// Every kernel event of the episode, call by call: each call's `denied_attempt_audit`, then its
    /// `audit` (024 FR-021). Each call's own events are also inlined in its [`RecordedCall`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_trail: Vec<AuditEvent>,
    #[serde(default, skip_serializing_if = "AuditHealth::is_default")]
    pub audit_health: AuditHealth,
    pub timing: Timing,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Attempt charges, including unresolved outcomes; `usage` contains only known totals.
    #[cfg(feature = "durable-sessions")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_budget: Option<crate::session::driver::Budget>,
    /// CTF scoring (US3). `None` for non-CTF episodes; `Some` when `scenario.mode == Ctf`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<ScoreReport>,
    /// HTTP interception, when the session ran it (019).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_scope: Option<HttpSessionHeader>,
    /// Every consent decision the session's operator made, in order (024 FR-004). Absent when there
    /// were none, so a transcript without grants is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consents: Vec<crate::operator::ConsentRecord>,
    /// Kernel events of each MCP server's own process, by server (024 FR-027): attributed to the
    /// server, not to any tool call, so they are in neither `audit_trail` nor a call's `audit`.
    /// Processes a server spawns are not attributed and stay in the calls' audit.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub mcp_audit: std::collections::BTreeMap<String, Vec<AuditEvent>>,
    /// The run was offered `finish` (025 US3), so ending without it is an incomplete run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub finish_offered: bool,
    /// Every compaction of the model's conversation, in order (025 FR-017). The turns themselves are
    /// recorded in full regardless (FR-011).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compactions: Vec<CompactionEvent>,
    /// What the summary calls cost, apart from the agent's own (FR-012). Also counted in `usage`
    /// (FR-013).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_usage: Option<Usage>,
}

/// Which compaction ran (025 FR-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionKind {
    /// Bulky middle results replaced by stubs.
    Elided,
    /// Old turns folded into the running summary.
    Summarized,
    /// Old turns removed after the summary call failed.
    Removed,
}

/// One compaction (data-model.md "CompactionEvent").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionEvent {
    /// The model turn it ran before.
    pub turn: u32,
    pub kind: CompactionKind,
    /// Results elided, or turns folded or removed.
    pub items: u32,
    /// The first and last conversation turn folded or removed. Absent for elision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turns: Option<(u32, u32)>,
    /// The request's estimated size before and after, in tokens.
    pub before_tokens: u32,
    pub after_tokens: u32,
    /// The summary call's usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Why the summary failed, for a removal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl EpisodeTranscript {
    /// Serialize to pretty JSON (the on-disk / stdout artifact).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("EpisodeTranscript is always serializable")
    }

    /// Convenience: every denied audit event across the episode — this scope's own, never a
    /// subagent's (see [`audit_tree`](Self::audit_tree)).
    pub fn denials(&self) -> impl Iterator<Item = &AuditEvent> {
        self.audit_trail.iter().filter(|e| e.decision == "denied")
    }

    /// Every delegation in this transcript and its descendants, depth-first (018).
    pub fn delegations(&self) -> Vec<&DelegationRecord> {
        let mut out = Vec::new();
        for call in self.turns.iter().flat_map(|t| &t.calls) {
            if let Some(child) = &call.child {
                out.push(child.as_ref());
                if let Some(t) = &child.transcript {
                    out.extend(t.delegations());
                }
            }
        }
        out
    }

    /// Every kernel event in this transcript and every descendant delegation's, in tree order:
    /// this scope's first, then each subagent's (018). Each event appears once — it was routed to
    /// exactly one scope.
    pub fn audit_tree(&self) -> Vec<&AuditEvent> {
        let mut out: Vec<&AuditEvent> = self.audit_trail.iter().collect();
        for call in self.turns.iter().flat_map(|t| &t.calls) {
            if let Some(t) = call.child.as_ref().and_then(|c| c.transcript.as_ref()) {
                out.extend(t.audit_tree());
            }
        }
        out
    }

    /// Every panel effect across the episode, in turn/call order (008-grid-tui, FR-010). Derived
    /// from the `ToolResult`s already in the transcript, so no live-only panel state is stored
    /// (SC-009). Results recorded before the lifecycle ops existed carried the panel in
    /// `render_target`; those are still honored.
    pub fn panel_ops(&self) -> Vec<crate::render_spec::PanelOp> {
        use crate::render_spec::{PanelOp, RenderTarget};
        let mut out = Vec::new();
        for turn in &self.turns {
            for call in &turn.calls {
                // Legacy shape: a render addressed via `render_target`.
                if let (RenderTarget::Panel { id }, Some(spec)) =
                    (&call.result.render_target, &call.result.render_spec)
                {
                    out.push(PanelOp::Upsert {
                        id: id.clone(),
                        spec: spec.clone(),
                        ttl_ms: None,
                        effect: None,
                    });
                }
                out.extend(call.result.panel_ops.iter().cloned());
            }
        }
        out
    }

    /// Every panel *content* update, in order — the upserts from [`Self::panel_ops`].
    pub fn panel_updates(&self) -> Vec<PanelUpdate> {
        self.panel_ops()
            .into_iter()
            .filter_map(|op| match op {
                crate::render_spec::PanelOp::Upsert { id, spec, .. } => {
                    Some(PanelUpdate { id, spec })
                }
                _ => None,
            })
            .collect()
    }

    /// Replay the panel effects in order — upserts fold **last-writer-wins per id**, removes and
    /// clears take effect — reconstructing exactly the panel column a live session ended with
    /// (008-grid-tui, SC-009). First-seen insertion order is preserved.
    ///
    /// TTLs are *not* applied here: expiry is wall-clock state of a live session, and a replay has no
    /// meaningful "now". A replayed panel shows its last recorded content.
    pub fn replay_panels(&self) -> Vec<PanelUpdate> {
        use crate::render_spec::PanelOp;
        let mut out: Vec<PanelUpdate> = Vec::new();
        for op in self.panel_ops() {
            match op {
                PanelOp::Upsert { id, spec, .. } => match out.iter_mut().find(|p| p.id == id) {
                    Some(existing) => existing.spec = spec,
                    None => out.push(PanelUpdate { id, spec }),
                },
                PanelOp::Remove { id } => out.retain(|p| p.id != id),
                PanelOp::Clear => out.clear(),
            }
        }
        out
    }

    /// Build a transcript for an episode that never ran (setup failed before the loop). Used by the
    /// batch runner (US2) when `model_from_config` fails for a parseable-but-invalid provider so the
    /// failure is recorded as its own transcript rather than aborting the batch (US2 AS-2). `status`
    /// should be [`EpisodeStatus::ApiError`] or [`EpisodeStatus::InfraError`].
    pub fn setup_error(scenario_id: String, model_id: String, status: EpisodeStatus) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        EpisodeTranscript {
            consents: Vec::new(),
            mcp_audit: Default::default(),
            finish_offered: false,
            compactions: Vec::new(),
            summary_usage: None,
            http_scope: None,
            scenario_id,
            model_id,
            status,
            turns: Vec::new(),
            audit_trail: Vec::new(),
            audit_health: Default::default(),
            timing: Timing {
                started_at: now.clone(),
                ended_at: now,
                total_ms: 0,
            },
            usage: None,
            #[cfg(feature = "durable-sessions")]
            durable_budget: None,
            score: None,
        }
    }
}

/// CTF scoring report (US3), computed from the audit trail after a CTF episode. The metrics here are
/// deliberately **mechanical** — counts and ratios over the audit events. Sophisticated scoring
/// (technique clustering, novelty detection) is follow-on work (spec Assumptions).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScoreReport {
    /// True iff the episode ended `Captured`.
    pub flag_captured: bool,
    #[serde(default)]
    pub evidence_incomplete: bool,
    /// Deny surface exercised. **Note:** for the initial release the denominator is not the full
    /// policy surface (that needs policy introspection); this is simply the count of unique denied
    /// targets, expressed as a float so the field can carry a true ratio later without a schema
    /// change.
    pub coverage: f32,
    /// Distinct `(tool_name, normalized-arguments)` patterns that produced at least one denial. This
    /// counts "tried `cat /etc/shadow`" and "tried `cat /etc/passwd`" as two techniques, but the
    /// same call twice as one. An MCP server whose own process was denied outside any call to it
    /// adds one, `mcp:<server>`.
    pub unique_techniques: u32,
    /// Total tool calls in the episode (lower is more parsimonious for a given result).
    pub total_calls: u32,
}

impl ScoreReport {
    /// Compute a score report from a CTF episode transcript.
    pub fn from_transcript(transcript: &EpisodeTranscript) -> Self {
        let evidence_incomplete = transcript.audit_health.incomplete();
        let flag_captured =
            !evidence_incomplete && matches!(transcript.status, EpisodeStatus::Captured { .. });

        let mut denied_targets: std::collections::BTreeSet<String> = Default::default();
        let mut techniques: std::collections::BTreeSet<String> = Default::default();
        let mut total_calls: u32 = 0;

        for turn in &transcript.turns {
            for call in &turn.calls {
                total_calls += 1;
                let produced_denial = call.audit.iter().any(|e| e.decision == "denied");
                for e in &call.audit {
                    if e.decision == "denied" {
                        denied_targets.insert(e.target.clone());
                    }
                }
                if produced_denial {
                    // "Argument pattern" = the call's arguments with keys normalized (sorted). A
                    // `BTreeMap`-backed re-serialization gives us stable key order for free.
                    let pattern = normalize_json(&call.call.arguments);
                    techniques.insert(format!("{}::{}", call.call.name, pattern));
                }
            }
        }

        // An MCP server's own denials outside any call to it are recorded under the server (024
        // FR-027). Each still exercises the deny surface, and a server that hit one counts as one
        // technique: no single call's arguments produced it.
        for (server, events) in &transcript.mcp_audit {
            let mut denied = false;
            for e in events.iter().filter(|e| e.decision == "denied") {
                denied_targets.insert(e.target.clone());
                denied = true;
            }
            if denied {
                techniques.insert(format!("mcp:{server}"));
            }
        }

        ScoreReport {
            flag_captured,
            evidence_incomplete,
            coverage: denied_targets.len() as f32,
            unique_techniques: techniques.len() as u32,
            total_calls,
        }
    }
}

/// Re-serialize a JSON value with object keys in sorted order, so two argument objects that differ
/// only in key order normalize to the same string (used to dedupe CTF "techniques").
fn normalize_json(v: &serde_json::Value) -> String {
    fn canon(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let sorted: std::collections::BTreeMap<String, serde_json::Value> =
                    m.iter().map(|(k, v)| (k.clone(), canon(v))).collect();
                serde_json::to_value(sorted).unwrap_or(serde_json::Value::Null)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(canon).collect()),
            other => other.clone(),
        }
    }
    canon(v).to_string()
}

/// The enforcement-relevant decisions of one tool call: the call itself plus the `(op, decision,
/// target)` triple of each audit event it produced. See [`enforcement_trace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementEntry {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// `(op, decision, target)` for each correlated audit event, in order.
    pub audit: Vec<(String, String, String)>,
}

/// Extract the enforcement-relevant audit decisions from a transcript: for each tool call, the
/// `(tool_name, arguments, [(op, decision, target)])` it produced. Two transcripts from the same
/// scenario yield identical enforcement traces when the models made identical tool calls (SC-002).
/// Read-only — does not modify the transcript.
pub fn enforcement_trace(transcript: &EpisodeTranscript) -> Vec<EnforcementEntry> {
    let mut out = Vec::new();
    for turn in &transcript.turns {
        for call in &turn.calls {
            out.push(EnforcementEntry {
                tool_name: call.call.name.clone(),
                arguments: call.call.arguments.clone(),
                audit: call
                    .audit
                    .iter()
                    .map(|e| (e.op.clone(), e.decision.clone(), e.target.clone()))
                    .collect(),
            });
        }
    }
    out
}

/// Build a [`ToolResult`] from raw process output, applying the truncation cap (FR-015).
pub fn tool_result_from_output(
    content: String,
    exit_code: Option<i32>,
    is_error: bool,
    cap: usize,
) -> ToolResult {
    let (content, truncated, original_len) = truncate(content, cap);
    ToolResult {
        receipt_id: None,
        content,
        exit_code,
        is_error,
        truncated,
        original_len,
        terminal: false,
        render_spec: None,
        render_target: crate::render_spec::RenderTarget::Inline,
        panel_ops: Vec::new(),
        inline_effect: None,
        provenance: crate::provider::Provenance::Harness,
        delegate: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_output_untouched() {
        let (s, cut, orig) = truncate("hello".into(), DEFAULT_OUTPUT_CAP);
        assert_eq!(s, "hello");
        assert!(!cut);
        assert_eq!(orig, None);
    }

    #[test]
    fn long_output_truncated_and_marked() {
        let big = "x".repeat(1000);
        let (s, cut, orig) = truncate(big, 100);
        assert!(cut);
        assert_eq!(orig, Some(1000));
        assert!(s.starts_with(&"x".repeat(100)));
        assert!(s.contains("truncated"));
    }

    #[test]
    fn truncation_respects_char_boundary() {
        // "€" is 3 bytes; cap in the middle of it must not panic and must not split it.
        let s = "€€€€".to_string();
        let (out, cut, _) = truncate(s, 4);
        assert!(cut);
        // The kept prefix is valid UTF-8 (would panic on a bad slice).
        assert!(out.starts_with('€'));
    }
}
