//! [`SessionEvent`] (008-grid-tui, T004 / data-model.md): what the shared session core says as a turn
//! progresses.
//!
//! The turn loop ([`crate::repl::run_exchange`]) already writes everything through the
//! [`crate::repl::ReplOutput`] trait — that trait *is* the engine's output seam. `SessionEvent` is a
//! faithful 1:1 mirror of those callbacks, so a front-end (the TUI) can reconstruct exactly what the
//! inline REPL renders. Renderer-agnostic — no ratatui/rustyline types leak in.

use bee_core::AuditEvent;
use serde_json::Value;

use crate::render_spec::{EffectSpec, RenderSpec};
use crate::tools::ToolResult;

/// One thing the session core emitted, mirroring one [`crate::repl::ReplOutput`] callback.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A streamed assistant-token delta (`assistant_delta`).
    AssistantDelta(String),
    /// End of an assistant prose block (`assistant_end`).
    AssistantEnd,
    /// A tool call the agent requested, before it runs (`tool_call`).
    ToolCall { name: String, arguments: Value },
    /// A grouped tool call presentation with a stable identity (`tool_event`, 023).
    ToolPresentation(crate::repl::presentation::CallEvent),
    /// A tool result plus its kernel audit events (`tool_result`).
    ToolResult {
        result: ToolResult,
        audit: Vec<AuditEvent>,
    },
    /// A visualization to draw inline in the chat flow (`render_widget`).
    RenderWidget {
        spec: RenderSpec,
        effect: Option<EffectSpec>,
    },
    /// A render addressed to a named, persistent panel (`panel_update`, 008-grid-tui US2). The TUI
    /// upserts `spec` into panel `id` beside chat — same id replaces in place (FR-008/009).
    PanelUpdate { id: String, spec: RenderSpec },
    /// A full-screen takeover (`overlay`, 009-tachyonfx-effects US3). Emitted only when the visual
    /// gate admitted `RenderTarget::Overlay`, so the TUI never has to re-check the level. `ttl_ms`
    /// is what the script asked for; the granted lifetime is resolved against the operator's
    /// configuration when the overlay is constructed.
    Overlay {
        spec: RenderSpec,
        ttl_ms: Option<u32>,
    },
    /// A panel-lifecycle effect (`panel_op`, 008-grid-tui US2): create/replace with an optional TTL,
    /// remove one panel, or clear them all. The TUI applies it to its panel registry.
    PanelOp(crate::render_spec::PanelOp),
    /// An error line the user should see (`error`).
    Error(String),
    /// An informational line — banners, meta-command output (`info`).
    Info(String),
    /// A proxy-layer event (`proxy_event`, 019) — rendered apart from kernel denials.
    Proxy(crate::proxy_event::ProxyEvent),
    /// A dim per-exchange summary footer (`footer`).
    Footer(String),
    /// A steering acknowledgement (`steering`).
    Steering(String),
    /// A block the sender declared to be markdown (`markdown`) — a skill's instructions, say. The
    /// TUI renders it styled; declared, never inferred (010).
    Markdown(String),
    /// The conversation history was dropped (`clear_history`, `/clear`). The model's message log is
    /// already empty when this arrives; a front-end that keeps its own copy of the transcript — the
    /// TUI's chat pane — has to be told, or it goes on showing a conversation the model has
    /// forgotten (010).
    Cleared,
    /// The "working" indicator began (`busy_start`) — the assistant turn is in flight.
    TurnStarted,
    /// The "working" indicator ended (`busy_stop`).
    TurnDone,
}
