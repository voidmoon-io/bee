//! Interactive REPL (US5): a human chats with a sandboxed coding agent in real time.
//!
//! Where [`crate::episode`] drives a *scripted* task to completion and stops, the REPL replaces that
//! outer driver with an interactive loop — the user types a message, the agent responds (making any
//! number of tool calls along the way), everything is shown, and control returns to the user for the
//! next message. The conversation persists for the whole session.
//!
//! The *inner* agent-turn loop is structurally similar to the episode loop but has different
//! semantics — text-only means "back to the user", not "episode ends"; there is no wall-clock
//! deadline; the conversation outlives a single exchange — so it is its own code here. It reuses the
//! same low-level building blocks: [`Model::stream`], [`ToolRegistry::execute`],
//! [`Sandbox::drain_audit`]. `episode.rs` is deliberately left untouched.
//!
//! ## Live IO model
//!
//! The session keeps exactly one `readline` outstanding at all times, on a blocking thread. When the
//! user is idle its result is the next message/command; while an exchange is running the same
//! outstanding line becomes a *steering* message — queued and injected before the agent's next model
//! call, so the user can redirect the agent mid-task without interrupting and cold-starting. All
//! agent output flows through a rustyline [`ExternalPrinter`](rustyline::ExternalPrinter) so it
//! scrolls above the live input line rather than corrupting it, and assistant prose streams in a
//! line at a time as the model generates it.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bee_core::AuditEvent;
use futures_util::StreamExt;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use time::OffsetDateTime;

use crate::provider::{
    Conversation, Message, Model, ModelError, StreamEvent, ToolSchema, Turn, Usage,
};
use crate::render_spec::{EffectSpec, RenderSpec};
use crate::sandbox::Sandbox;
use crate::tools::{ToolRegistry, ToolResult};
use crate::transcript::{EpisodeStatus, EpisodeTranscript, RecordedCall, Timing, TranscriptTurn};

pub mod terminal;

pub use terminal::TerminalOutput;

/// A shared queue of user "steering" messages typed while an exchange is running. The main loop
/// pushes to it; [`run_exchange`] drains it before each model call and injects the lines as user
/// turns, so the agent catches them on its next turn.
pub type SteeringQueue = Arc<Mutex<VecDeque<String>>>;

/// Configuration for an interactive REPL session.
pub struct ReplConfig {
    /// System prompt for the session.
    pub system_prompt: String,
    /// Max model calls per user message before forcing a pause (safety cap).
    /// Prevents a runaway agent from making 200 API calls off one message.
    pub agent_turn_budget: u32,
    /// Per-tool-call timeout (seconds). Individual tool calls that hang are killed.
    pub tool_timeout_secs: u64,
    /// Max retries on transient provider errors (429/5xx).
    pub max_retries: u32,
    /// Human-readable label for the active policy/enforcement mode, shown by `/policy`.
    pub policy_label: String,
    /// Play the bee mascot animation once at startup (003-visual-render, Slice 2, FR-032). On by
    /// default; suppress with `--no-bee` / `BEE_MASCOT=0`.
    pub mascot: bool,
    /// Pre-rendered `/mcp` output: configured MCP servers, their status, and the domain policy
    /// (004-mcp-client, US10). `None` when MCP is not configured / the `mcp` feature is off.
    pub mcp_summary: Option<String>,
    /// Optional per-turn tool-refresh hook (004-mcp-client, FR-043): re-registers MCP tools when a
    /// server sent `tools/list_changed`. rmcp-agnostic (a plain closure); `None` is a no-op.
    #[allow(clippy::type_complexity)]
    pub refresh_tools: Option<Box<dyn Fn(&mut ToolRegistry) + Send + Sync>>,
    /// Discovered skills (006-skills), shared with the `skill` tool. Backs the `/skill` command and
    /// the system-prompt nudge. Defaults to an empty registry (no skills, no `/skill`).
    pub skills: Arc<crate::skills::SkillRegistry>,
    /// The three presentation axes (009): how much screen the agent may claim, whether anything
    /// animates, and how long a takeover may live. Resolved once at startup from CLI > env >
    /// scenario > default.
    pub visual: crate::config::VisualConfig,
    /// Dynamic capability grants (007-dynamic-grants). `None` ⇒ escalation is off and the exchange
    /// behaves exactly as before. An interactive session is where this earns its keep: unlike an
    /// episode, the operator is present, so consent can be a prompt rather than a pre-authorizing
    /// ceiling file.
    pub escalation: Option<ReplEscalation>,
}

/// Session-lifetime escalation state for the REPL.
///
/// A grant outlives the exchange that requested it — the point of a capability is that the next
/// message can use it — but [`run_exchange`] takes `&ReplConfig`, so the mutable half lives behind a
/// lock rather than in the signature. The turn counter is monotonic across exchanges for the same
/// reason: a `Ttl::Turns` lease measured per-exchange would silently reset every time the user
/// pressed enter.
pub struct ReplEscalation {
    /// The static half: base, ceiling, hooks, consent sink, timeout, default TTL.
    pub config: crate::grants::escalate::LoopEscalation,
    /// The mutable half. `tokio::sync::Mutex` because it is held across the consent `await`.
    pub active: tokio::sync::Mutex<crate::grants::ActivePolicy>,
    /// Turns elapsed since the session began, for lease TTL accounting.
    turn: std::sync::atomic::AtomicU32,
}

impl ReplEscalation {
    /// Build session state from an escalation config, starting the active policy at its `base`.
    pub fn new(config: crate::grants::escalate::LoopEscalation) -> Result<Self, String> {
        let active = crate::grants::ActivePolicy::new(config.base.clone(), config.ceiling.clone())?;
        Ok(ReplEscalation {
            config,
            active: tokio::sync::Mutex::new(active),
            turn: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// The current session turn, incrementing it for the next caller.
    fn next_turn(&self) -> Result<u32, String> {
        self.turn
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .map_err(|_| "session turn counter exhausted".into())
    }
}

impl Default for ReplConfig {
    fn default() -> Self {
        ReplConfig {
            system_prompt: "You are a coding agent operating in a sandbox. You have access to \
                            bash, read_file, write_file, and list_directory tools. Use them to \
                            help the user with their tasks."
                .to_string(),
            agent_turn_budget: 25,
            tool_timeout_secs: 30,
            max_retries: 3,
            policy_label: "none".to_string(),
            mascot: true,
            mcp_summary: None,
            refresh_tools: None,
            skills: Arc::new(crate::skills::SkillRegistry::default()),
            visual: crate::config::VisualConfig::default(),
            escalation: None,
        }
    }
}

/// How the REPL renders to the user. The default impl ([`TerminalOutput`]) writes through a
/// rustyline external printer with ANSI color; a `Vec<String>` collector makes the agent-turn loop
/// testable without a terminal.
pub trait ReplOutput: Send + Sync {
    /// A chunk of streaming assistant prose (no trailing newline implied).
    fn assistant_delta(&self, chunk: &str);
    /// The end of an assistant prose block — flush any buffered partial line.
    fn assistant_end(&self);
    /// A tool call the agent requested (before it runs).
    fn tool_call(&self, name: &str, arguments: &serde_json::Value);
    /// A tool call's result, plus any kernel audit events it produced.
    fn tool_result(&self, result: &ToolResult, audit: &[AuditEvent]);
    /// An error the user should see (provider failure, bad meta-command).
    fn error(&self, msg: &str);
    /// An informational line (banners, warnings, meta-command output).
    fn info(&self, msg: &str);
    /// A block the sender declares to be **markdown** — a skill's instructions, say (010). Defaults
    /// to [`ReplOutput::info`], which prints the source verbatim: that is the honest rendering for a
    /// scrolling terminal, and markdown source is meant to be readable as-is. The full-screen TUI
    /// overrides it to style the block. Never inferred from content — a tool result containing `**`
    /// is data, not emphasis — so only a caller that *knows* it holds markdown calls this.
    fn markdown(&self, md: &str) {
        self.info(md);
    }
    /// The conversation history was dropped (`/clear`). Defaults to a no-op: the inline REPL's
    /// history *is* the terminal's scrollback, which belongs to the user and which we do not erase.
    /// A front-end holding its own copy of the transcript (the TUI's chat pane) overrides this —
    /// otherwise it keeps displaying a conversation the model has already forgotten (010).
    fn clear_history(&self) {}
    /// A dim per-exchange summary footer. Defaults to [`ReplOutput::info`].
    fn footer(&self, msg: &str) {
        self.info(msg);
    }
    /// Acknowledgement that a steering message was queued/injected. Defaults to
    /// [`ReplOutput::info`].
    fn steering(&self, msg: &str) {
        self.info(msg);
    }
    /// Begin a "working" indicator — called the instant a model call is dispatched, so the wait for
    /// the first token never looks dead. Defaults to a no-op (tests need no spinner).
    fn busy_start(&self) {}
    /// End the "working" indicator — called when the first token/tool arrives or the call fails.
    /// Defaults to a no-op.
    fn busy_stop(&self) {}
    /// Render a visualization produced by the `render` tool (003-visual-render, FR-024). The default
    /// emits a plain-text ASCII fallback through [`ReplOutput::info`] — a text table, never a blank
    /// (US6 AS-5). `TerminalOutput` overrides this to draw the widget as ANSI art.
    fn render_widget(&self, spec: &RenderSpec, _effect: Option<&EffectSpec>) {
        for line in spec.to_ascii().lines() {
            self.info(line);
        }
    }
    /// A full-screen takeover (009-tachyonfx-effects, FR-013a). Defaults to drawing inline: the
    /// inline REPL scrolls and has no surface to take over, so a takeover there is just a widget in
    /// the flow (009 spec, Edge Cases). The full-screen TUI's `SessionSink` overrides this.
    fn overlay(&self, spec: &RenderSpec, _ttl_ms: Option<u32>, effect: Option<&EffectSpec>) {
        self.render_widget(spec, effect);
    }
    /// A render addressed to a named, persistent panel (008-grid-tui, FR-008). Defaults to drawing
    /// inline via [`ReplOutput::render_widget`] — the inline REPL has no panel column, so targeted
    /// renders still appear in the chat flow (back-compat, FR-008 scenario 3). The full-screen TUI's
    /// `SessionSink` overrides this to upsert the panel beside chat.
    fn panel_update(&self, _id: &str, spec: &RenderSpec) {
        self.render_widget(spec, None);
    }
    /// One panel-lifecycle effect (008-grid-tui, US2): create/replace (optionally with a TTL),
    /// remove, or clear. The default routes upserts to [`ReplOutput::panel_update`] and ignores
    /// remove/clear, since a front-end with no panel column has nothing to reclaim.
    fn panel_op(&self, op: &crate::render_spec::PanelOp) {
        if let crate::render_spec::PanelOp::Upsert { id, spec, .. } = op {
            self.panel_update(id, spec);
        }
    }
}

/// Why one user→agent exchange ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// The agent produced a text-only turn and yielded control back to the user.
    Responded,
    /// The agent hit `agent_turn_budget` model calls without stopping; control was returned anyway.
    BudgetExhausted,
    /// A provider error (after retries) ended the exchange.
    ApiError(String),
    Terminated(String),
}

/// The result of running one user→agent exchange (used by [`run_repl`] and by tests).
pub struct ExchangeResult {
    /// Why the exchange ended.
    pub outcome: ExchangeOutcome,
    /// Model round-trips made during this exchange.
    pub model_calls: u32,
    /// Tool calls executed during this exchange.
    pub tool_calls: u32,
    /// Denials observed during this exchange.
    pub denials: u32,
    /// The turns recorded, for optional transcript building. Indices are exchange-local (0-based).
    pub turns: Vec<TranscriptTurn>,
    /// Audit events observed during this exchange, in order.
    pub audit: Vec<AuditEvent>,
    /// Token usage summed across this exchange's model calls, when the provider reports it.
    pub usage: Option<Usage>,
}

/// The session record produced when the REPL exits.
pub struct ReplSession {
    /// The full conversation (system prompt + every user/assistant/tool message).
    pub conversation: Conversation,
    /// Number of user messages sent (meta-commands excluded).
    pub exchanges: u32,
    pub total_tool_calls: u32,
    pub total_denials: u32,
    /// The session as an [`EpisodeTranscript`] (always `Some` once the session ends).
    pub transcript: Option<EpisodeTranscript>,
}

/// A parsed meta-command (a line beginning with `/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaCommand {
    /// `/quit` or `/exit` — end the session.
    Quit,
    /// `/save [path]` — write the session transcript to a JSON file.
    Save(Option<String>),
    /// `/audit` — show a summary of all audit events so far.
    Audit,
    /// `/clear` — clear the conversation history (keep the system prompt).
    Clear,
    /// `/tools` — list the tools the agent has.
    Tools,
    /// `/policy` — show the active policy / enforcement mode.
    Policy,
    /// `/mcp` — show configured MCP servers, their status, and the domain policy (004-mcp-client).
    Mcp,
    /// `/skill [name]` — list discovered skills, or load one's instructions as the next turn
    /// (006-skills).
    Skill(Option<String>),
    /// `/system [text]` — show the system prompt, or replace it when text is given.
    System(Option<String>),
    /// `/history` — show recent user messages this session.
    History,
    /// `/retry` — re-send the last user message.
    Retry,
    /// `/help` — list available commands.
    Help,
    /// An unrecognized `/command`.
    Unknown(String),
}

/// Parse a line as a meta-command. Returns `None` for a line that is not a meta-command (i.e. a
/// normal user message to send to the model). Only lines beginning with `/` are meta-commands.
pub fn parse_meta_command(line: &str) -> Option<MetaCommand> {
    let line = line.trim();
    if !line.starts_with('/') {
        return None;
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let arg = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(match cmd {
        "/quit" | "/exit" => MetaCommand::Quit,
        "/save" => MetaCommand::Save(arg),
        "/audit" => MetaCommand::Audit,
        "/clear" => MetaCommand::Clear,
        "/tools" => MetaCommand::Tools,
        "/policy" => MetaCommand::Policy,
        "/mcp" => MetaCommand::Mcp,
        "/skill" | "/skills" => MetaCommand::Skill(arg),
        "/system" => MetaCommand::System(arg),
        "/history" => MetaCommand::History,
        "/retry" => MetaCommand::Retry,
        "/help" => MetaCommand::Help,
        other => MetaCommand::Unknown(other.to_string()),
    })
}

const HELP_TEXT: &str = "commands:\n  \
    /help           show this help\n  \
    /tools          list the tools the agent has\n  \
    /policy         show the active policy / enforcement mode\n  \
    /mcp            show configured MCP servers and the domain policy\n  \
    /skill [name]   list skills, or load one's instructions into the conversation\n  \
    /system [text]  show the system prompt, or replace it\n  \
    /history        show recent messages this session\n  \
    /retry          re-send your last message\n  \
    /save [path]    write the session transcript to a JSON file (default: bee-repl-session.json)\n  \
    /audit          summarize the audit events seen so far\n  \
    /clear          clear the conversation history (keeps the system prompt)\n  \
    /quit, /exit    end the session\n\
    anything else is sent to the agent. while the agent is working, what you type is queued as a \
    steering message and reaches it on its next turn.";

/// Open one provider stream with bounded exponential backoff on transient (429/5xx) errors. Only the
/// stream-open call is retried; once tokens have been rendered a mid-stream failure is surfaced, not
/// retried. There is no wall-clock deadline — the user is waiting and can always re-send — so this
/// simply caps the number of attempts.
async fn stream_with_retry(
    model: &dyn Model,
    convo: &Conversation,
    schemas: &[ToolSchema],
    max_retries: u32,
) -> Result<crate::provider::EventStream, String> {
    let mut attempt: u32 = 0;
    loop {
        match model.stream(convo, schemas).await {
            Ok(stream) => return Ok(stream),
            Err(ModelError::Transient {
                status,
                retry_after,
            }) => {
                if attempt >= max_retries {
                    return Err(format!(
                        "transient provider error (status {status}) after {attempt} retries"
                    ));
                }
                let backoff = retry_after
                    .unwrap_or_else(|| Duration::from_millis(200 * 2u64.pow(attempt.min(6))));
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
            Err(ModelError::Auth) => return Err("provider authentication failed".to_string()),
            Err(ModelError::Request(m)) => return Err(format!("provider rejected request: {m}")),
            Err(ModelError::Decode(m)) => return Err(format!("could not decode response: {m}")),
        }
    }
}

/// Drain the steering queue into the conversation as user turns, echoing each so the user sees their
/// nudge land. Returns the number injected.
fn drain_steering(queue: &SteeringQueue, convo: &mut Conversation, output: &dyn ReplOutput) -> u32 {
    let mut drained = 0;
    loop {
        let next = queue.lock().expect("steering queue").pop_front();
        match next {
            Some(text) => {
                output.steering(&format!("↳ steering: {text}"));
                convo.push(Message::User { text });
                drained += 1;
            }
            None => break,
        }
    }
    drained
}

/// Consume one model stream: render text deltas live and return the assembled [`Turn`] plus the
/// time-to-first-token (ms since `call_start`, the dispatch instant), for metrics. The "working"
/// indicator (started by the caller when the call was dispatched) is stopped the instant the first
/// event arrives. `saw_text` reports whether any prose was rendered (so the caller can close the
/// assistant block).
async fn consume_stream(
    mut stream: crate::provider::EventStream,
    output: &dyn ReplOutput,
    call_start: Instant,
) -> Result<(Turn, Option<u64>), String> {
    // Wait for the first event, then drop the "working" indicator — from here on the stream itself
    // (tokens, tool calls) shows liveness.
    let first = stream.next().await;
    output.busy_stop();
    let ttft = first
        .is_some()
        .then(|| call_start.elapsed().as_millis() as u64);

    let mut saw_text = false;
    let mut ev = first;
    loop {
        match ev {
            Some(Ok(StreamEvent::TextDelta(delta))) => {
                output.assistant_delta(&delta);
                saw_text = true;
            }
            // Tool calls are rendered by the caller as they execute; the Done turn carries them.
            Some(Ok(StreamEvent::ToolCall(_))) => {}
            Some(Ok(StreamEvent::Done(turn))) => {
                if saw_text {
                    output.assistant_end();
                }
                return Ok((turn, ttft));
            }
            Some(Err(e)) => {
                if saw_text {
                    output.assistant_end();
                }
                return Err(e.to_string());
            }
            None => {
                // Stream ended without a Done event — treat as an empty text turn.
                if saw_text {
                    output.assistant_end();
                }
                return Ok((Turn::text(String::new()), ttft));
            }
        }
        ev = stream.next().await;
    }
}

/// Tell the user what an escalation did. Only a grant or a refusal is worth a line: `AlreadyHeld` is
/// the ordinary case — a skill re-stating capabilities it was given at startup — and narrating it on
/// every call would be noise that trains the user to ignore the ones that matter.
fn report_escalation(
    output: &dyn ReplOutput,
    subject: &str,
    outcome: &crate::grants::escalate::EscalateOutcome,
) {
    use crate::grants::escalate::EscalateOutcome;
    match outcome {
        EscalateOutcome::Granted(id) => {
            output.info(&format!("capability granted for {subject} (lease {id})"))
        }
        EscalateOutcome::Refused(reason) => {
            output.info(&format!("capability refused for {subject} — {reason}"))
        }
        EscalateOutcome::Denied(reason) | EscalateOutcome::Terminated(reason) => {
            output.error(reason)
        }
        EscalateOutcome::AlreadyHeld => {}
    }
}

/// Run one user→agent exchange: inject `user_message`, then run the agent turn loop until the agent
/// responds with text only (control back to the user), the model-call budget is exhausted, or the
/// provider errors. Before each model call the steering queue is drained into the conversation, so a
/// message the user typed mid-exchange reaches the agent on its next turn. The conversation is
/// mutated in place and persists across exchanges.
///
/// This is the testable core of the REPL — [`run_repl`] wraps it with readline and meta-commands.
#[allow(clippy::too_many_arguments)]
pub async fn run_exchange(
    user_message: &str,
    model: &dyn Model,
    conversation: &mut Conversation,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    config: &ReplConfig,
    output: &dyn ReplOutput,
    steering: &SteeringQueue,
    recorder: Option<&crate::metrics::Recorder>,
) -> ExchangeResult {
    conversation.push(Message::User {
        text: user_message.to_string(),
    });

    let mut turns: Vec<TranscriptTurn> = Vec::new();
    let mut audit_all: Vec<AuditEvent> = Vec::new();
    let mut model_calls = 0u32;
    let mut tool_calls = 0u32;
    let mut denials = 0u32;
    let mut usage_total: Option<Usage> = None;

    macro_rules! stop_exchange {
        ($detail:expr) => {{
            let detail = $detail;
            output.error(&detail);
            return ExchangeResult {
                outcome: ExchangeOutcome::Terminated(detail),
                model_calls,
                tool_calls,
                denials,
                turns,
                audit: audit_all,
                usage: usage_total,
            };
        }};
    }
    for _step in 0..config.agent_turn_budget {
        if let Err(detail) = sandbox.check_cleanup() {
            stop_exchange!(detail);
        }
        let turn_no = match config
            .escalation
            .as_ref()
            .map(|e| e.next_turn())
            .transpose()
        {
            Ok(turn) => turn,
            Err(detail) => {
                stop_exchange!(detail);
            }
        };
        if let (Some(esc), Some(turn_no)) = (config.escalation.as_ref(), turn_no) {
            let mut active = esc.active.lock().await;
            if turn_no == 0 {
                if let Err(detail) = esc.config.initialize(&active, sandbox) {
                    stop_exchange!(detail);
                }
            }

            if let Some(crate::grants::escalate::EscalateOutcome::Terminated(detail)) =
                crate::grants::escalate::turn_start(
                    &esc.config,
                    &mut active,
                    turn_no,
                    sandbox,
                    registry,
                )
                .await
            {
                stop_exchange!(detail);
            }
        }

        // Fold in any steering the user typed since the last model call — the agent catches it now.
        drain_steering(steering, conversation, output);

        // Refresh MCP tools if a server sent `tools/list_changed` (FR-043), then snapshot schemas.
        if let Some(refresh) = &config.refresh_tools {
            refresh(&mut *registry);
        }
        let schemas = registry.schemas();
        if let (Some(esc), Some(turn_no)) = (config.escalation.as_ref(), turn_no) {
            let mut active = esc.active.lock().await;
            if let Some(crate::grants::escalate::EscalateOutcome::Terminated(detail)) =
                crate::grants::escalate::event_step(
                    &esc.config,
                    &mut active,
                    crate::hooks::StepEvent::BeforeModelCall {
                        convo: conversation,
                        schemas: &schemas,
                    },
                    turn_no,
                    sandbox,
                    registry,
                )
                .await
            {
                stop_exchange!(detail);
            }
        }

        let turn_start = Instant::now();
        // Show a "working" indicator from the instant the call is dispatched — this covers the
        // stream-open latency and the wait for the first token, which is the gap that otherwise
        // feels dead. `consume_stream` stops it on the first event.
        output.busy_start();
        let stream =
            match stream_with_retry(model, conversation, &schemas, config.max_retries).await {
                Ok(s) => s,
                Err(detail) => {
                    output.busy_stop();
                    output.error(&detail);
                    if let Some(rec) = recorder {
                        rec.record(
                            model.id(),
                            Usage::default(),
                            turn_start.elapsed().as_millis() as u64,
                            None,
                            "error",
                            "error",
                        );
                    }
                    return ExchangeResult {
                        outcome: ExchangeOutcome::ApiError(detail),
                        model_calls,
                        tool_calls,
                        denials,
                        turns,
                        audit: audit_all,
                        usage: usage_total,
                    };
                }
            };
        let (turn, ttft_ms) = match consume_stream(stream, output, turn_start).await {
            Ok(t) => t,
            Err(detail) => {
                output.error(&detail);
                if let Some(rec) = recorder {
                    rec.record(
                        model.id(),
                        Usage::default(),
                        turn_start.elapsed().as_millis() as u64,
                        None,
                        "error",
                        "error",
                    );
                }
                return ExchangeResult {
                    outcome: ExchangeOutcome::ApiError(detail),
                    model_calls,
                    tool_calls,
                    denials,
                    turns,
                    audit: audit_all,
                    usage: usage_total,
                };
            }
        };
        model_calls += 1;
        if let Some(rec) = recorder {
            rec.record(
                model.id(),
                turn.usage.unwrap_or_default(),
                turn_start.elapsed().as_millis() as u64,
                ttft_ms,
                crate::metrics::stop_label(&turn.stop),
                "ok",
            );
        }
        if let Some(u) = turn.usage {
            usage_total = Some(usage_total.map_or(u, |acc| acc + u));
        }

        let assistant_text = turn.text.clone();

        // A turn with no tool calls means the agent is done responding. But if the user queued a
        // steering message while it was finishing, don't hand control back yet — record this turn
        // and loop so the agent responds to the nudge instead of forcing a cold re-send.
        if turn.tool_calls.is_empty() {
            conversation.push(Message::Assistant {
                text: turn.text,
                tool_calls: Vec::new(),
            });
            turns.push(TranscriptTurn {
                index: turns.len() as u32,
                assistant_text,
                calls: Vec::new(),
                duration_ms: turn_start.elapsed().as_millis() as u64,
            });
            if steering.lock().expect("steering queue").is_empty() {
                return ExchangeResult {
                    outcome: ExchangeOutcome::Responded,
                    model_calls,
                    tool_calls,
                    denials,
                    turns,
                    audit: audit_all,
                    usage: usage_total,
                };
            }
            continue;
        }

        conversation.push(Message::Assistant {
            text: turn.text.clone(),
            tool_calls: turn.tool_calls.clone(),
        });

        let mut recorded: Vec<RecordedCall> = Vec::new();
        for tc in &turn.tool_calls {
            tool_calls += 1;
            output.tool_call(&tc.name, &tc.arguments);

            // Proactive escalation (007, US2): a hook may request a grant before this call runs —
            // a loaded skill's `requires`, above all. In an interactive session the consent sink is
            // a prompt, which is why the cycle only ever asks for what is not already held.
            let mut refusal = None;
            if let (Some(esc), Some(turn_no)) = (config.escalation.as_ref(), turn_no) {
                let mut active = esc.active.lock().await;
                if let Some(out) = crate::grants::escalate::proactive_step(
                    &esc.config,
                    &mut active,
                    tc,
                    turn_no,
                    sandbox,
                    registry,
                )
                .await
                {
                    report_escalation(output, "capability", &out);
                    match out {
                        crate::grants::escalate::EscalateOutcome::Denied(reason) => {
                            refusal = Some(ToolResult::error(reason))
                        }
                        crate::grants::escalate::EscalateOutcome::Terminated(reason) => {
                            turns.push(TranscriptTurn {
                                index: turns.len() as u32,
                                assistant_text,
                                calls: recorded,
                                duration_ms: turn_start.elapsed().as_millis() as u64,
                            });
                            stop_exchange!(reason);
                        }
                        _ => (),
                    }
                }
            }

            let mut result = if let Some(refusal) = refusal {
                refusal
            } else {
                match tokio::time::timeout(
                    Duration::from_secs(config.tool_timeout_secs),
                    registry.execute(tc, sandbox),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => ToolResult::error(format!(
                        "tool timed out after {}s",
                        config.tool_timeout_secs
                    )),
                }
            };

            // Correlate the kernel audit events this call produced (FR-008). `settle` lets the async
            // demux path deliver this call's events; it is a no-op for the sync sandboxes.
            sandbox.settle().await;
            let mut audit = sandbox.drain_audit();
            sandbox.retain_audit(&mut audit);
            audit_all.extend(audit.iter().cloned());

            // Reactive escalation (007, US1): a kernel denial may be escalated and the call retried
            // exactly once under the widened scope, so the user sees one result rather than a
            // denial followed by a mysterious success.
            if let (Some(esc), Some(turn_no)) = (config.escalation.as_ref(), turn_no) {
                if let Some((op, target)) = crate::grants::escalate::first_denial(&audit) {
                    let mut active = esc.active.lock().await;
                    if let Some(out) = crate::grants::escalate::reactive_step(
                        &esc.config,
                        &mut active,
                        &op,
                        &target,
                        tc,
                        turn_no,
                        sandbox,
                        registry,
                    )
                    .await
                    {
                        report_escalation(output, &format!("{op} {target}"), &out);
                        match &out {
                            crate::grants::escalate::EscalateOutcome::Denied(reason) => {
                                result = ToolResult::error(reason.clone())
                            }
                            crate::grants::escalate::EscalateOutcome::Terminated(reason) => {
                                let detail = reason.clone();
                                recorded.push(RecordedCall {
                                    call: tc.clone(),
                                    result,
                                    audit,
                                });
                                turns.push(TranscriptTurn {
                                    index: turns.len() as u32,
                                    assistant_text,
                                    calls: recorded,
                                    duration_ms: turn_start.elapsed().as_millis() as u64,
                                });
                                stop_exchange!(detail);
                            }
                            _ => (),
                        }
                        if out.is_granted() {
                            result = tokio::time::timeout(
                                Duration::from_secs(config.tool_timeout_secs),
                                registry.execute(tc, sandbox),
                            )
                            .await
                            .unwrap_or_else(|_| ToolResult::error("tool retry timed out"));
                            sandbox.settle().await;
                            let mut retry_audit = sandbox.drain_audit();
                            sandbox.retain_audit(&mut retry_audit);
                            audit_all.extend(retry_audit.iter().cloned());
                            audit = retry_audit;
                        }
                    }
                }
            }

            if let (Some(esc), Some(turn_no)) = (config.escalation.as_ref(), turn_no) {
                let mut active = esc.active.lock().await;
                if let Some(crate::grants::escalate::EscalateOutcome::Terminated(detail)) =
                    crate::grants::escalate::event_step(
                        &esc.config,
                        &mut active,
                        crate::hooks::StepEvent::AfterToolResult {
                            call: tc,
                            result: &result,
                            audit: &audit,
                        },
                        turn_no,
                        sandbox,
                        registry,
                    )
                    .await
                {
                    recorded.push(RecordedCall {
                        call: tc.clone(),
                        result,
                        audit,
                    });
                    turns.push(TranscriptTurn {
                        index: turns.len() as u32,
                        assistant_text,
                        calls: recorded,
                        duration_ms: turn_start.elapsed().as_millis() as u64,
                    });
                    stop_exchange!(detail);
                }
            }
            denials += audit.iter().filter(|e| e.decision == "denied").count() as u32;
            output.tool_result(&result, &audit);
            // If the tool produced a visualization (the `render` tool), surface it — routed by its
            // target: inline into chat, or upserted into a named panel (008-grid-tui, FR-008). The
            // model still receives only `result.content` (the text summary), never the art (FR-023).
            if let Some(spec) = &result.render_spec {
                let fx = result.inline_effect.as_ref();
                match &result.render_target {
                    // Legacy results routed panels via `render_target`; honor them for back-compat.
                    crate::render_spec::RenderTarget::Panel { id } => output.panel_update(id, spec),
                    // A takeover the gate admitted. `ReplOutput::overlay` defaults to drawing it
                    // inline, which is the inline REPL's honest degrade — it scrolls, so it has no
                    // surface to take over. The full-screen front-end overrides it.
                    crate::render_spec::RenderTarget::Overlay { ttl_ms } => {
                        output.overlay(spec, *ttl_ms, fx)
                    }
                    crate::render_spec::RenderTarget::Inline => output.render_widget(spec, fx),
                }
            }
            // Then each panel-lifecycle effect, in order (008-grid-tui, US2).
            for op in &result.panel_ops {
                output.panel_op(op);
            }

            conversation.push(Message::ToolResult {
                call_id: tc.id.clone(),
                name: tc.name.clone(),
                content: result.content.clone(),
                is_error: result.is_error,
            });
            if let Some(warning) = sandbox.audit_warning() {
                output.error(&warning);
            }
            recorded.push(RecordedCall {
                call: tc.clone(),
                result,
                audit,
            });
        }

        turns.push(TranscriptTurn {
            index: turns.len() as u32,
            assistant_text,
            calls: recorded,
            duration_ms: turn_start.elapsed().as_millis() as u64,
        });
        // Loop back — feed the tool results to the model for another turn.
    }

    // Budget exhausted: the agent never produced a text-only turn. The conversation is intact; the
    // user can send another message and the agent can continue.
    output.info("[agent reached tool-call limit for this exchange — returning control to you]");
    ExchangeResult {
        outcome: ExchangeOutcome::BudgetExhausted,
        model_calls,
        tool_calls,
        denials,
        turns,
        audit: audit_all,
        usage: usage_total,
    }
}

/// A count formatted with its noun, pluralized: `1 exchange`, `3 exchanges`.
fn plural(n: u32, noun: &str) -> String {
    if n == 1 {
        format!("{n} {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// A compact token count: `840`, `1.2k`.
fn human_tokens(n: u32) -> String {
    if n >= 1000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

/// The dim one-line summary printed after each exchange, including derived cost for priced models.
fn exchange_footer(result: &ExchangeResult, elapsed: Duration, model_id: &str) -> String {
    let mut parts = vec![
        plural(result.model_calls, "turn"),
        plural(result.tool_calls, "tool call"),
        plural(result.denials, "denial"),
    ];
    match &result.usage {
        Some(u) => {
            let mut tok = format!(
                "{}→{} tok",
                human_tokens(u.input_tokens),
                human_tokens(u.output_tokens)
            );
            // Surface prompt-cache activity so caching is observable live: writes populate the
            // cache (first turn / after a prefix change), reads are the hits that follow (~0.1×
            // cost). Only shown when non-zero, so non-caching providers stay quiet.
            if u.cache_read_tokens > 0 || u.cache_write_tokens > 0 {
                let mut bits = Vec::new();
                if u.cache_read_tokens > 0 {
                    bits.push(format!("{} cached", human_tokens(u.cache_read_tokens)));
                }
                if u.cache_write_tokens > 0 {
                    bits.push(format!("{} written", human_tokens(u.cache_write_tokens)));
                }
                tok.push_str(&format!(" ({})", bits.join(", ")));
            }
            parts.push(tok);
            if let Some(cost) = crate::metrics::pricing::cost(model_id, u) {
                parts.push(format!("${cost:.4}"));
            }
        }
        None => parts.push("usage n/a".to_string()),
    }
    parts.push(format!("{:.1}s", elapsed.as_secs_f64()));
    format!("— {}", parts.join(" · "))
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Build a session transcript from the accumulated turns. A REPL session always ends `Completed`
/// (there is no turn limit or deadline that could time it out).
fn build_transcript(
    model_id: &str,
    started_at: OffsetDateTime,
    start: Instant,
    turns: &[TranscriptTurn],
    audit_trail: &[AuditEvent],
    audit_health: crate::transcript::AuditHealth,
    usage: Option<Usage>,
) -> EpisodeTranscript {
    EpisodeTranscript {
        scenario_id: "repl".to_string(),
        model_id: model_id.to_string(),
        status: EpisodeStatus::Completed,
        turns: turns.to_vec(),
        audit_trail: audit_trail.to_vec(),
        audit_health,
        timing: Timing {
            started_at: rfc3339(started_at),
            ended_at: rfc3339(OffsetDateTime::now_utc()),
            total_ms: start.elapsed().as_millis() as u64,
        },
        usage,
        score: None,
    }
}

/// Summarize the audit events seen so far: total denials and a per-op breakdown.
fn audit_summary(audit: &[AuditEvent]) -> String {
    if audit.is_empty() {
        return "no audit events recorded yet.".to_string();
    }
    let denials = audit.iter().filter(|e| e.decision == "denied").count();
    let mut by_op: std::collections::BTreeMap<(&str, &str), u32> = Default::default();
    for e in audit {
        *by_op
            .entry((e.op.as_str(), e.decision.as_str()))
            .or_default() += 1;
    }
    let mut out = format!(
        "{} total, {}:",
        plural(audit.len() as u32, "audit event"),
        plural(denials as u32, "denial")
    );
    for ((op, decision), n) in by_op {
        out.push_str(&format!("\n  {op} {decision}: {n}"));
    }
    out
}

/// List discovered skills and their (first-line) descriptions, marking user/model visibility.
fn skills_summary(skills: &crate::skills::SkillRegistry) -> String {
    if skills.is_empty() {
        return "no skills discovered.".to_string();
    }
    let mut out = format!("{} discovered:", plural(skills.len() as u32, "skill"));
    for s in skills.iter() {
        let desc = s.description.lines().next().unwrap_or("");
        // Flag anything not loadable both ways, so the layering is visible at a glance.
        let vis = match (s.model_invocable, s.user_invocable) {
            (true, _) => "",
            (false, true) => " [user-only]",
            (false, false) => " [hidden]",
        };
        out.push_str(&format!("\n  {}{vis} — {desc}", s.name));
    }
    out.push_str("\n\nuse /skill <name> to load one's instructions into the conversation.");
    out
}

/// List the enabled tools and their (first-line) descriptions.
fn tools_summary(registry: &ToolRegistry) -> String {
    let schemas = registry.schemas();
    if schemas.is_empty() {
        return "no tools enabled.".to_string();
    }
    let mut out = format!("{} available:", plural(schemas.len() as u32, "tool"));
    for s in &schemas {
        let desc = s.description.lines().next().unwrap_or("");
        out.push_str(&format!("\n  {} — {desc}", s.name));
    }
    out
}

/// Show the most recent user messages this session (capped).
fn history_summary(log: &[String]) -> String {
    if log.is_empty() {
        return "no messages sent yet.".to_string();
    }
    let start = log.len().saturating_sub(20);
    let mut out = String::from("recent messages:");
    for (i, m) in log.iter().enumerate().skip(start) {
        out.push_str(&format!("\n  {}: {m}", i + 1));
    }
    out
}

/// The path the input history is persisted to: `$XDG_STATE_HOME/bee/repl_history`, falling back to
/// `~/.local/state/bee/repl_history`. Creates the parent directory. `None` if neither var is set.
fn history_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    let dir = base.join("bee");
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join("repl_history"))
}

/// The type of the outstanding readline: an editor moved onto a blocking thread that returns it (so
/// its history survives) alongside the line it read.
type ReadHandle = tokio::task::JoinHandle<(DefaultEditor, Result<String, ReadlineError>)>;

/// Issue one `readline` on a blocking thread so the tokio runtime is never blocked. The editor is
/// moved in and returned so its history persists across reads.
fn issue_read(mut editor: DefaultEditor, prompt: String) -> ReadHandle {
    tokio::task::spawn_blocking(move || {
        let line = editor.readline(&prompt);
        (editor, line)
    })
}

/// Record a line in the editor's history and persist it, so history survives across sessions and
/// even an abrupt exit. Errors are swallowed — history is a convenience, never load-bearing.
fn remember(editor: &mut DefaultEditor, path: &Option<PathBuf>, line: &str) {
    let _ = editor.add_history_entry(line);
    if let Some(p) = path {
        let _ = editor.save_history(p);
    }
}

/// The system prompt actually sent to the model: the configured base, plus a short primer on the
/// `render` tool's Rhai drawing API **only when that tool is registered** (005-themes follow-up). The
/// full API surface already lives in the tool's schema, so this stays brief — it just makes the agent
/// aware visuals exist and nudges it to use them when a chart/table/status grid reads better than
/// prose. When `render` is not among the enabled tools, the base prompt is returned unchanged so the
/// agent is never told about a tool it doesn't have.
pub(crate) fn effective_system_prompt(base: &str, registry: &ToolRegistry) -> String {
    let mut prompt = base.to_string();
    if registry.contains("render") {
        prompt.push_str(
            "\n\n\
             You can also draw visualizations with the `render` tool: write a short Rhai script \
             ending in `render(widget)` to produce bar/line charts, sparklines, tables, gauges, \
             pass/fail dot grids, styled text, or sprites — the tool's schema lists the full \
             drawing API. Reach for it when a chart, table, or status grid communicates results \
             (comparisons, trends, distributions, progress, pass/fail) more clearly than plain \
             text; keep using prose to explain. Chart and text colors resolve against the user's \
             active color theme, so prefer semantic color names (accent, success, error, info) or \
             the theme's palette names over raw hex. The user sees the rendered visual; you \
             receive only a short text summary of what was drawn.",
        );
    }
    if registry.contains("skill") {
        // The per-skill catalog lives in the `skill` tool's schema (re-derived each turn), so the
        // nudge here stays short and never duplicates the trigger text.
        prompt.push_str(
            "\n\n\
             You have a `skill` tool that loads reusable, task-specific instructions. Its schema \
             lists the available skills and what each is for; when a task matches one, call `skill` \
             to load it *before* starting, then follow the returned instructions. Loading a skill \
             only adds guidance — it grants no new capabilities.",
        );
    }
    prompt
}

/// Drive an interactive REPL session over a ready sandbox: read a user message, run the agent turn
/// loop (streaming every assistant message, tool call, tool result, and audit denial), then return
/// to the prompt. While the agent works, whatever the user types is queued as a steering message and
/// injected on the agent's next turn. Meta-commands (`/help`, `/tools`, `/policy`, `/system`,
/// `/history`, `/retry`, `/save`, `/audit`, `/clear`, `/quit`) are handled inline. Returns the
/// [`ReplSession`] record when the user quits or EOF is reached.
pub async fn run_repl(
    model: &dyn Model,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    config: &ReplConfig,
) -> ReplSession {
    let started_at = OffsetDateTime::now_utc();
    let start = Instant::now();

    let mut conversation = Conversation {
        system: effective_system_prompt(&config.system_prompt, registry),
        messages: Vec::new(),
    };
    let mut turns: Vec<TranscriptTurn> = Vec::new();
    let mut audit_trail: Vec<AuditEvent> = Vec::new();
    let mut usage_total: Option<Usage> = None;
    let mut exchanges = 0u32;
    let mut total_tool_calls = 0u32;
    let mut total_denials = 0u32;
    let mut message_log: Vec<String> = Vec::new();
    let mut last_user_message: Option<String> = None;

    // Build the editor and take an external printer from it *before* moving it onto the read thread;
    // the printer keeps working across every subsequent readline.
    let mut editor = match DefaultEditor::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("bee-repl: could not initialize readline: {e}");
            let transcript = build_transcript(
                model.id(),
                started_at,
                start,
                &turns,
                &audit_trail,
                sandbox.audit_health(),
                usage_total,
            );
            return ReplSession {
                conversation,
                exchanges,
                total_tool_calls,
                total_denials,
                transcript: Some(transcript),
            };
        }
    };
    let hist_path = history_path();
    if let Some(p) = &hist_path {
        let _ = editor.load_history(p);
    }
    let printer = match editor.create_external_printer() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bee-repl: could not initialize terminal output: {e}");
            let transcript = build_transcript(
                model.id(),
                started_at,
                start,
                &turns,
                &audit_trail,
                sandbox.audit_health(),
                usage_total,
            );
            return ReplSession {
                conversation,
                exchanges,
                total_tool_calls,
                total_denials,
                transcript: Some(transcript),
            };
        }
    };
    let output = TerminalOutput::new(Box::new(printer));

    // Publish the drawable width so the render tool can reject widgets this terminal can't show
    // (008-grid-tui). Height is unbounded here — the inline REPL scrolls — and off a tty (piped
    // output) nothing is known, so the viewport stays unconstrained and no fit check fires.
    {
        let (cols, is_tty) = crate::viz::terminal_dims();
        crate::viz::viewport::set(crate::viz::viewport::Viewport {
            cols,
            inline_cols: cols,
            full_screen: false,
            constrained: is_tty,
            ..crate::viz::viewport::Viewport::unconstrained()
        });
    }

    // Bee mascot (on by default; `--no-bee` / `BEE_MASCOT=0` to suppress): a static sprite banner in
    // the resting pose. (It was a fire-and-forget wing-flap, but the animation's deferred row-reclaim
    // fought the info line + prompt printed immediately below it, leaving two stray black antenna rows
    // after the first message. A static block has no reclaim, so no artifact. The flap belongs in the
    // upcoming full-screen TUI, where a tick-driven redraw needs no cursor-reclaim hack — see
    // docs/grid-tui-plan.md §5.)
    if config.mascot {
        output.render_widget(
            &RenderSpec::Sprite {
                spec: crate::viz::bee::sprite(),
            },
            None,
        );
    }

    output.info(&format!(
        "interactive session — {} — type /help for commands",
        model.id()
    ));

    // One metrics recorder for the whole session (None if no metrics path is resolvable).
    let recorder = crate::metrics::Recorder::new("repl", format!("repl:{}", std::process::id()));

    let steering: SteeringQueue = Arc::new(Mutex::new(VecDeque::new()));
    let prompt = "bee> ".to_string();
    // Exactly one readline is outstanding at all times.
    let mut pending = issue_read(editor, prompt.clone());

    loop {
        // Idle: wait for the next full line.
        let (mut editor, line_res) = pending.await.expect("readline task panicked");
        let line = match line_res {
            Ok(l) => l,
            // Ctrl-D (EOF) ends the session; Ctrl-C cancels the current line and re-prompts.
            Err(ReadlineError::Eof) => break,
            Err(ReadlineError::Interrupted) => {
                pending = issue_read(editor, prompt.clone());
                continue;
            }
            Err(e) => {
                output.error(&format!("input error: {e}"));
                break;
            }
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            pending = issue_read(editor, prompt.clone());
            continue;
        }
        remember(&mut editor, &hist_path, &line);

        // Decide what (if anything) to send to the agent this iteration.
        let mut to_run: Option<String> = None;
        let mut quit = false;
        if let Some(cmd) = parse_meta_command(&line) {
            match cmd {
                MetaCommand::Quit => quit = true,
                MetaCommand::Help => output.info(HELP_TEXT),
                MetaCommand::Audit => output.info(&audit_summary(&audit_trail)),
                MetaCommand::Tools => output.info(&tools_summary(registry)),
                MetaCommand::Policy => output.info(&format!("policy: {}", config.policy_label)),
                MetaCommand::Mcp => output.info(
                    config
                        .mcp_summary
                        .as_deref()
                        .unwrap_or("MCP: not configured"),
                ),
                MetaCommand::Skill(None) => output.info(&skills_summary(&config.skills)),
                MetaCommand::Skill(Some(name)) => match config.skills.get(&name) {
                    Some(skill) => match skill.body() {
                        Ok(body) => {
                            output.info(&format!("loaded skill '{name}' into the conversation."));
                            // Show the operator the instructions the agent was just handed. A
                            // SKILL.md body is markdown by definition (006-skills), so it is
                            // declared as such rather than guessed at (010).
                            output.markdown(&body);
                            to_run = Some(crate::tools::skill::load_message(
                                &skill.name,
                                &body,
                                &serde_json::Value::Null,
                            ));
                        }
                        Err(e) => output.error(&format!("skill '{name}': {e}")),
                    },
                    None => {
                        output.error(&format!("unknown skill '{name}'. try /skill to list them."))
                    }
                },
                MetaCommand::System(None) => {
                    output.info(&format!("system prompt:\n{}", conversation.system));
                }
                MetaCommand::System(Some(text)) => {
                    conversation.system = text;
                    output.info("system prompt updated.");
                }
                MetaCommand::History => output.info(&history_summary(&message_log)),
                MetaCommand::Retry => match &last_user_message {
                    Some(m) => to_run = Some(m.clone()),
                    None => output.error("nothing to retry yet."),
                },
                MetaCommand::Clear => {
                    conversation.messages.clear();
                    // Before the info line, so a front-end that wipes its transcript still shows the
                    // acknowledgement afterwards rather than clearing it away again (010).
                    output.clear_history();
                    output.info("conversation history cleared (system prompt kept).");
                }
                MetaCommand::Save(path) => {
                    let path = path.unwrap_or_else(|| "bee-repl-session.json".to_string());
                    let transcript = build_transcript(
                        model.id(),
                        started_at,
                        start,
                        &turns,
                        &audit_trail,
                        sandbox.audit_health(),
                        usage_total,
                    );
                    match std::fs::write(&path, transcript.to_json()) {
                        Ok(()) => output.info(&format!("saved transcript to {path}")),
                        Err(e) => output.error(&format!("could not write {path}: {e}")),
                    }
                }
                MetaCommand::Unknown(c) => {
                    output.error(&format!("unknown command: {c} (try /help)"));
                }
            }
        } else {
            last_user_message = Some(line.clone());
            message_log.push(line.clone());
            to_run = Some(line);
        }

        if quit {
            break;
        }

        // Re-issue exactly one outstanding read now. While the exchange runs it feeds steering; when
        // idle it is the next prompt.
        pending = issue_read(editor, prompt.clone());

        let Some(msg) = to_run else {
            continue;
        };

        // Run the exchange, folding in any line the user submits mid-flight as a steering message.
        let ex_start = Instant::now();
        let mut quit_after = false;
        let result = {
            let fut = run_exchange(
                &msg,
                model,
                &mut conversation,
                registry,
                sandbox,
                config,
                &output,
                &steering,
                recorder.as_ref(),
            );
            tokio::pin!(fut);
            loop {
                tokio::select! {
                    r = &mut fut => break r,
                    joined = &mut pending => {
                        let (mut editor, line_res) = joined.expect("readline task panicked");
                        match line_res {
                            Ok(l) => {
                                let l = l.trim().to_string();
                                if !l.is_empty() {
                                    remember(&mut editor, &hist_path, &l);
                                    output.steering(&format!("↳ queued: {l}"));
                                    steering.lock().expect("steering queue").push_back(l);
                                }
                            }
                            // Ctrl-D mid-exchange: quit once this exchange finishes.
                            Err(ReadlineError::Eof) => quit_after = true,
                            // Ctrl-C mid-exchange: drop the partial line, keep going.
                            Err(ReadlineError::Interrupted) => {}
                            Err(e) => output.error(&format!("input error: {e}")),
                        }
                        pending = issue_read(editor, prompt.clone());
                    }
                }
            }
        };

        exchanges += 1;
        total_tool_calls += result.tool_calls;
        total_denials += result.denials;
        if let Some(u) = result.usage {
            usage_total = Some(usage_total.map_or(u, |acc| acc + u));
        }
        output.footer(&exchange_footer(&result, ex_start.elapsed(), model.id()));
        // Re-index the exchange's turns into the session-wide sequence before accumulating.
        for mut t in result.turns {
            t.index = turns.len() as u32;
            turns.push(t);
        }
        audit_trail.extend(result.audit);

        if quit_after {
            break;
        }
    }

    output.info(&format!(
        "session ended ({}, {}, {})",
        plural(exchanges, "exchange"),
        plural(total_tool_calls, "tool call"),
        plural(total_denials, "denial")
    ));

    let transcript = build_transcript(
        model.id(),
        started_at,
        start,
        &turns,
        &audit_trail,
        sandbox.audit_health(),
        usage_total,
    );
    ReplSession {
        conversation,
        exchanges,
        total_tool_calls,
        total_denials,
        transcript: Some(transcript),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::mock_model::MockModel;
    use crate::provider::ToolCall;
    use crate::sandbox;
    use crate::tools::registry_for;
    use std::sync::Mutex;

    /// A [`ReplOutput`] that captures every rendered line into a shared buffer. Streaming deltas are
    /// accumulated and flushed as one `TEXT ...` line on [`ReplOutput::assistant_end`].
    #[derive(Default)]
    struct Collector {
        lines: Mutex<Vec<String>>,
        partial: Mutex<String>,
        /// Widgets captured via `render_widget` (003-visual-render, US6 Independent Test).
        widgets: Mutex<Vec<RenderSpec>>,
    }

    impl Collector {
        fn contains(&self, needle: &str) -> bool {
            self.lines
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains(needle))
        }
        fn dump(&self) -> String {
            self.lines.lock().unwrap().join("\n")
        }
    }

    impl ReplOutput for Collector {
        fn assistant_delta(&self, chunk: &str) {
            self.partial.lock().unwrap().push_str(chunk);
        }
        fn assistant_end(&self) {
            let text = std::mem::take(&mut *self.partial.lock().unwrap());
            self.lines.lock().unwrap().push(format!("TEXT {text}"));
        }
        fn tool_call(&self, name: &str, arguments: &serde_json::Value) {
            self.lines
                .lock()
                .unwrap()
                .push(format!("CALL {name} {arguments}"));
        }
        fn tool_result(&self, result: &ToolResult, audit: &[AuditEvent]) {
            let mut buf = self.lines.lock().unwrap();
            buf.push(format!("RESULT err={} {}", result.is_error, result.content));
            for e in audit {
                buf.push(format!("AUDIT {} {} {}", e.decision, e.op, e.target));
            }
        }
        fn error(&self, msg: &str) {
            self.lines.lock().unwrap().push(format!("ERROR {msg}"));
        }
        fn info(&self, msg: &str) {
            self.lines.lock().unwrap().push(format!("INFO {msg}"));
        }
        fn render_widget(&self, spec: &RenderSpec, _effect: Option<&EffectSpec>) {
            self.widgets.lock().unwrap().push(spec.clone());
        }
    }

    fn host_sandbox() -> Sandbox {
        Sandbox::host(sandbox::key_vars(None))
    }

    fn empty_steering() -> SteeringQueue {
        Arc::new(Mutex::new(VecDeque::new()))
    }

    fn bash_call(id: &str, command: &str) -> ToolCall {
        ToolCall {
            id: id.into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": command }),
        }
    }

    async fn exchange(model: &dyn Model, config: &ReplConfig) -> (ExchangeResult, Collector) {
        let mut registry = registry_for(&["bash".to_string(), "read_file".to_string()], None);
        let mut sb = host_sandbox();
        let mut convo = Conversation {
            system: config.system_prompt.clone(),
            messages: Vec::new(),
        };
        let out = Collector::default();
        let steering = empty_steering();
        let res = run_exchange(
            "hello",
            model,
            &mut convo,
            &mut registry,
            &mut sb,
            config,
            &out,
            &steering,
            None,
        )
        .await;
        (res, out)
    }

    #[tokio::test]
    async fn agent_responds_with_text() {
        let model = MockModel::scripted(vec![Turn::text("Hi there, how can I help?")]);
        let (res, out) = exchange(&model, &ReplConfig::default()).await;
        assert_eq!(res.outcome, ExchangeOutcome::Responded);
        assert_eq!(res.tool_calls, 0);
        assert!(out.contains("Hi there"), "output: {}", out.dump());
    }

    #[tokio::test]
    async fn agent_calls_tool_then_responds() {
        let model = MockModel::scripted(vec![
            Turn::calls(vec![bash_call("1", "echo hello-from-tool")]),
            Turn::text("Done — the tool printed a greeting."),
        ]);
        let (res, out) = exchange(&model, &ReplConfig::default()).await;
        assert_eq!(res.outcome, ExchangeOutcome::Responded);
        assert_eq!(res.tool_calls, 1);
        assert!(out.contains("CALL bash"), "output: {}", out.dump());
        assert!(out.contains("hello-from-tool"), "output: {}", out.dump());
        assert!(out.contains("Done —"), "output: {}", out.dump());
    }

    #[tokio::test]
    async fn agent_budget_exhausted() {
        // The model always wants another tool call, never text-only.
        let mut script = Vec::new();
        for i in 0..10 {
            script.push(Turn::calls(vec![bash_call(&i.to_string(), "echo loop")]));
        }
        let model = MockModel::scripted(script);
        let config = ReplConfig {
            agent_turn_budget: 3,
            ..ReplConfig::default()
        };
        let (res, out) = exchange(&model, &config).await;
        assert_eq!(res.outcome, ExchangeOutcome::BudgetExhausted);
        assert_eq!(res.model_calls, 3);
        assert_eq!(res.tool_calls, 3);
        assert!(out.contains("tool-call limit"), "output: {}", out.dump());
    }

    #[test]
    fn system_prompt_mentions_visuals_only_when_render_enabled() {
        let base = "You are a coding agent.";
        // render enabled ⇒ the visuals primer is appended.
        let with_render = registry_for(&["bash".into(), "render".into()], None);
        let prompt = effective_system_prompt(base, &with_render);
        assert!(prompt.starts_with(base), "base prompt preserved");
        assert!(
            prompt.contains("render(widget)"),
            "should mention the render API"
        );
        assert!(
            prompt.contains("active color theme"),
            "should tie colors to the theme"
        );
        // render absent ⇒ base is returned verbatim (don't advertise a missing tool).
        let no_render = registry_for(&["bash".into(), "read_file".into()], None);
        assert_eq!(effective_system_prompt(base, &no_render), base);
    }

    #[tokio::test]
    async fn denial_surfaces_in_output() {
        // In host mode this produces no real kernel denials, but it exercises the drain path: the
        // tool runs, audit is drained (empty on host), and the result is rendered. The enforcement
        // assertion is the VM's job.
        let model = MockModel::scripted(vec![
            Turn::calls(vec![ToolCall {
                id: "1".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({ "path": "/etc/shadow" }),
            }]),
            Turn::text("I attempted to read the file."),
        ]);
        let (res, out) = exchange(&model, &ReplConfig::default()).await;
        assert_eq!(res.tool_calls, 1);
        // The drain path ran and a result was rendered (denial count is 0 on the host).
        assert_eq!(res.denials, 0);
        assert!(out.contains("RESULT"), "output: {}", out.dump());
    }

    #[tokio::test]
    async fn preloaded_steering_is_injected_before_first_call() {
        // A steering message queued before the exchange starts must be injected as a user turn ahead
        // of the model call, and echoed to the user.
        let model = MockModel::scripted(vec![Turn::text("ack")]);
        let mut registry = registry_for(&["bash".to_string()], None);
        let mut sb = host_sandbox();
        let mut convo = Conversation {
            system: "sys".into(),
            messages: Vec::new(),
        };
        let out = Collector::default();
        let steering = empty_steering();
        steering
            .lock()
            .unwrap()
            .push_back("actually, focus on tests".to_string());

        let res = run_exchange(
            "start",
            &model,
            &mut convo,
            &mut registry,
            &mut sb,
            &ReplConfig::default(),
            &out,
            &steering,
            None,
        )
        .await;

        assert_eq!(res.outcome, ExchangeOutcome::Responded);
        // Both the original message and the steering message are in the conversation, in order.
        let user_texts: Vec<&str> = convo
            .messages
            .iter()
            .filter_map(|m| match m {
                Message::User { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(user_texts, vec!["start", "actually, focus on tests"]);
        assert!(
            out.contains("↳ steering: actually, focus on tests"),
            "output: {}",
            out.dump()
        );
        assert!(
            steering.lock().unwrap().is_empty(),
            "steering queue should be drained"
        );
    }

    #[tokio::test]
    async fn pending_steering_keeps_agent_going_instead_of_ending() {
        // The agent would end after "first" (text-only), but a steering message arrives *during*
        // the first turn (simulated by the model pushing it as a side effect), so the exchange must
        // loop and consume the nudge rather than returning control after one turn.
        use std::sync::atomic::{AtomicU32, Ordering};
        let steering = empty_steering();
        let steer_clone = steering.clone();
        let calls = Arc::new(AtomicU32::new(0));
        let model = MockModel::from_fn(move |_convo| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                // The user types a steering message while the agent is mid-turn.
                steer_clone
                    .lock()
                    .unwrap()
                    .push_back("keep going".to_string());
                Turn::text("first")
            } else {
                Turn::text("second")
            }
        });
        let mut registry = registry_for(&["bash".to_string()], None);
        let mut sb = host_sandbox();
        let mut convo = Conversation {
            system: "sys".into(),
            messages: Vec::new(),
        };
        let out = Collector::default();

        let res = run_exchange(
            "go",
            &model,
            &mut convo,
            &mut registry,
            &mut sb,
            &ReplConfig::default(),
            &out,
            &steering,
            None,
        )
        .await;

        assert_eq!(res.outcome, ExchangeOutcome::Responded);
        assert_eq!(
            res.model_calls, 2,
            "should have taken a second turn for the steering message"
        );
        assert!(out.contains("first"), "output: {}", out.dump());
        assert!(out.contains("second"), "output: {}", out.dump());
    }

    #[test]
    fn meta_command_quit() {
        assert_eq!(parse_meta_command("/quit"), Some(MetaCommand::Quit));
        assert_eq!(parse_meta_command("/exit"), Some(MetaCommand::Quit));
        assert_eq!(parse_meta_command("  /quit  "), Some(MetaCommand::Quit));
    }

    #[test]
    fn meta_command_parsing() {
        assert_eq!(parse_meta_command("hello world"), None);
        assert_eq!(parse_meta_command("/help"), Some(MetaCommand::Help));
        assert_eq!(parse_meta_command("/audit"), Some(MetaCommand::Audit));
        assert_eq!(parse_meta_command("/clear"), Some(MetaCommand::Clear));
        assert_eq!(parse_meta_command("/tools"), Some(MetaCommand::Tools));
        assert_eq!(parse_meta_command("/policy"), Some(MetaCommand::Policy));
        assert_eq!(parse_meta_command("/mcp"), Some(MetaCommand::Mcp));
        assert_eq!(parse_meta_command("/skill"), Some(MetaCommand::Skill(None)));
        assert_eq!(
            parse_meta_command("/skills"),
            Some(MetaCommand::Skill(None))
        );
        assert_eq!(
            parse_meta_command("/skill tui-design"),
            Some(MetaCommand::Skill(Some("tui-design".to_string())))
        );
        assert_eq!(parse_meta_command("/history"), Some(MetaCommand::History));
        assert_eq!(parse_meta_command("/retry"), Some(MetaCommand::Retry));
        assert_eq!(
            parse_meta_command("/system"),
            Some(MetaCommand::System(None))
        );
        assert_eq!(
            parse_meta_command("/system be terse"),
            Some(MetaCommand::System(Some("be terse".to_string())))
        );
        assert_eq!(parse_meta_command("/save"), Some(MetaCommand::Save(None)));
        assert_eq!(
            parse_meta_command("/save out.json"),
            Some(MetaCommand::Save(Some("out.json".to_string())))
        );
        assert_eq!(
            parse_meta_command("/bogus"),
            Some(MetaCommand::Unknown("/bogus".to_string()))
        );
    }

    #[test]
    fn audit_summary_is_readable() {
        assert!(audit_summary(&[]).contains("no audit events"));
    }

    #[test]
    fn footer_reads_cleanly() {
        let result = ExchangeResult {
            outcome: ExchangeOutcome::Responded,
            model_calls: 2,
            tool_calls: 1,
            denials: 0,
            turns: Vec::new(),
            audit: Vec::new(),
            usage: Some(Usage {
                input_tokens: 1234,
                output_tokens: 340,
                ..Default::default()
            }),
        };
        let footer = exchange_footer(
            &result,
            Duration::from_millis(4100),
            "anthropic/claude-opus-4-8",
        );
        assert!(footer.contains("2 turns"), "{footer}");
        assert!(footer.contains("1 tool call"), "{footer}");
        assert!(footer.contains("1.2k→340 tok"), "{footer}");
        assert!(footer.contains("4.1s"), "{footer}");
        // priced model → cost appears; 1234·$5/M + 340·$25/M = $0.0147
        assert!(footer.contains("$0.01"), "{footer}");
        // no cache activity in this exchange → no cache annotation
        assert!(!footer.contains("cached"), "{footer}");
        assert!(!footer.contains("written"), "{footer}");
    }

    #[test]
    fn footer_shows_cache_reads_and_writes() {
        // First turn: cache written but not yet read.
        let write_only = ExchangeResult {
            outcome: ExchangeOutcome::Responded,
            model_calls: 1,
            tool_calls: 0,
            denials: 0,
            turns: Vec::new(),
            audit: Vec::new(),
            usage: Some(Usage {
                input_tokens: 200,
                output_tokens: 50,
                cache_write_tokens: 3400,
                ..Default::default()
            }),
        };
        let footer = exchange_footer(&write_only, Duration::from_millis(500), "mock/scripted");
        assert!(footer.contains("3.4k written"), "{footer}");
        assert!(!footer.contains("cached"), "{footer}");

        // A later turn: the prefix is re-read from cache, and the new tail is written.
        let read_and_write = ExchangeResult {
            usage: Some(Usage {
                input_tokens: 80,
                output_tokens: 60,
                cache_read_tokens: 3400,
                cache_write_tokens: 900,
                ..Default::default()
            }),
            ..write_only
        };
        let footer = exchange_footer(&read_and_write, Duration::from_millis(500), "mock/scripted");
        assert!(footer.contains("(3.4k cached, 900 written)"), "{footer}");
    }

    #[test]
    fn footer_omits_cost_for_unpriced_model() {
        let result = ExchangeResult {
            outcome: ExchangeOutcome::Responded,
            model_calls: 1,
            tool_calls: 0,
            denials: 0,
            turns: Vec::new(),
            audit: Vec::new(),
            usage: Some(Usage {
                input_tokens: 100,
                output_tokens: 50,
                ..Default::default()
            }),
        };
        let footer = exchange_footer(&result, Duration::from_millis(500), "mock/scripted");
        assert!(!footer.contains('$'), "{footer}");
    }

    #[test]
    fn plural_agrees() {
        assert_eq!(plural(1, "denial"), "1 denial");
        assert_eq!(plural(0, "denial"), "0 denials");
        assert_eq!(plural(2, "exchange"), "2 exchanges");
    }
}
