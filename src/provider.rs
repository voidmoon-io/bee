//! The provider seam (research H3): value types every backend speaks, plus the [`Model`] trait.
//!
//! All Rig types stay behind this seam — harness code and tests depend on these plain types, never
//! on `rig-core`. Two impls ship in slice 1: [`mock_model::MockModel`] (offline, scripted) and
//! `rig_model::RigModel` (T013, Anthropic + openai-compat).

use std::time::Duration;

use futures_util::stream::{self, BoxStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod framing;
pub mod limits;
pub mod mock_model;
pub mod rig_model;

/// Where a tool result's content came from — which decides how it is framed for the model
/// (019-http-intercept P1, contracts/model-framing.md).
///
/// Content bee composed itself is passed through as-is. Content a scoped child printed, or a network
/// peer sent, is *data the model must not take instructions from*, and is wrapped in a nonced
/// `<untrusted-data>` envelope by [`framing::frame_tool_result`] — the single place results are
/// rendered for a provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// Composed entirely by bee: refusal messages, `cvss`, `http_scope`.
    #[default]
    Harness,
    /// stdout/stderr of a scoped child: `bash`, `search`, file reads, scanner output.
    Child,
    /// Bytes from a network peer, named by `source` (`http:<exchange-id>`, `mcp:<server>`).
    Remote { source: String },
}

impl Provenance {
    /// For `skip_serializing_if`: transcripts written before 019 stay byte-identical for harness results.
    pub fn is_harness(&self) -> bool {
        matches!(self, Provenance::Harness)
    }
}

/// The ordered message log the loop maintains and re-sends each turn.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conversation {
    /// Scenario system prompt (maps to Rig `preamble`).
    pub system: String,
    /// User / assistant / tool-result turns in order.
    pub messages: Vec<Message>,
}

impl Conversation {
    /// Start a conversation from a system prompt and the first user task.
    pub fn new(system: impl Into<String>, task: impl Into<String>) -> Self {
        Conversation {
            system: system.into(),
            messages: vec![Message::User { text: task.into() }],
        }
    }

    pub fn push(&mut self, m: Message) {
        self.messages.push(m);
    }
}

/// One entry in a [`Conversation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Message {
    /// The initial task and any plain user text.
    User { text: String },
    /// A model turn as recorded (prose and/or tool calls).
    Assistant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    /// A tool result fed back to the model.
    ToolResult {
        call_id: String,
        name: String,
        content: String,
        is_error: bool,
        /// How the content is framed for the model (019 P1). Defaults to `Harness` so conversations
        /// serialised before it deserialise unchanged.
        #[serde(default, skip_serializing_if = "Provenance::is_harness")]
        provenance: Provenance,
    },
}

/// The return of [`Model::complete`] — a single model response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Turn {
    /// Assistant prose, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Requested tool calls; empty ⇒ a candidate `no_tool_calls` terminal state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// Why the model stopped.
    pub stop: StopReason,
    /// Token usage when the provider reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

impl Turn {
    /// A text-only turn that ends the conversation (used by scripts and as a graceful fallback).
    pub fn text(msg: impl Into<String>) -> Self {
        Turn {
            text: Some(msg.into()),
            tool_calls: Vec::new(),
            stop: StopReason::EndTurn,
            usage: None,
        }
    }

    /// A turn that requests one or more tool calls.
    pub fn calls(calls: Vec<ToolCall>) -> Self {
        Turn {
            text: None,
            tool_calls: calls,
            stop: StopReason::ToolUse,
            usage: None,
        }
    }
}

/// A single tool-call request from the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Provider-assigned id; correlates the [`Message::ToolResult`] back to this call.
    pub id: String,
    /// Tool name; must match a registered tool.
    pub name: String,
    /// Raw arguments; validated per-tool (may be malformed → FR-016).
    pub arguments: serde_json::Value,
}

/// Why a model turn stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    Other(String),
}

/// Token usage as reported by the provider. Beyond the plain input/output counts, this captures the
/// tokens that dominate cost on cache-aware providers: `cache_read_tokens` bill at ~0.1× input,
/// `cache_write_tokens` at 1.25×–2× input, and `reasoning_tokens` (extended thinking) bill as output.
/// The extra fields default to 0 for providers (or older transcripts) that don't report them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    /// Input tokens served from the provider's prompt cache (billed at a large discount).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_read_tokens: u32,
    /// Input tokens written to the provider's prompt cache (billed at a premium).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_write_tokens: u32,
    /// Reasoning / extended-thinking tokens (billed as output).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reasoning_tokens: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl std::ops::Add for Usage {
    type Output = Usage;
    /// Component-wise sum (for totalling per-episode usage).
    fn add(self, other: Usage) -> Usage {
        Usage {
            input_tokens: self.input_tokens + other.input_tokens,
            output_tokens: self.output_tokens + other.output_tokens,
            cache_read_tokens: self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens: self.cache_write_tokens + other.cache_write_tokens,
            reasoning_tokens: self.reasoning_tokens + other.reasoning_tokens,
        }
    }
}

/// One incremental event from [`Model::stream`]. Text arrives in [`StreamEvent::TextDelta`]
/// chunks as the model generates; each requested tool call arrives complete as a
/// [`StreamEvent::ToolCall`]; the stream always ends with exactly one [`StreamEvent::Done`]
/// carrying the fully-assembled [`Turn`] (its `text` is the concatenation of every delta, and its
/// `usage` the provider's final count). A consumer that ignores the deltas and reads only `Done`
/// sees exactly what [`Model::complete`] would have returned.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A chunk of assistant prose to render incrementally.
    TextDelta(String),
    /// A fully-formed tool call the model requested.
    ToolCall(ToolCall),
    /// The turn finished; carries the complete [`Turn`] (text, tool calls, stop reason, usage).
    Done(Turn),
}

/// A boxed stream of [`StreamEvent`]s — the return of [`Model::stream`].
pub type EventStream = BoxStream<'static, Result<StreamEvent, ModelError>>;

/// A tool schema advertised to the model (becomes a Rig `ToolDefinition`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's arguments.
    pub parameters: serde_json::Value,
}

/// Errors a [`Model`] may return. The loop — not the model — owns retry/backoff (FR-017), so a
/// transient failure is *reported*, never slept on.
#[derive(Debug, Error)]
pub enum ModelError {
    /// 429 / 5xx — the loop backs off and retries, then records `api_error`.
    #[error("transient provider error (status {status})")]
    Transient {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// Authentication failed (bad/missing key).
    #[error("provider authentication failed")]
    Auth,
    /// Malformed request / non-retryable 4xx.
    #[error("provider rejected the request: {0}")]
    Request(String),
    /// The provider response could not be parsed into a [`Turn`].
    #[error("could not decode provider response: {0}")]
    Decode(String),
}

/// Build a boxed [`Model`] from a provider config (research H3/H4). `api_key` is the resolved key
/// (may be empty for local OpenAI-compatible endpoints); it is ignored for `mock`.
pub fn model_from_config(
    cfg: &crate::config::ProviderConfig,
    api_key: &str,
) -> Result<Box<dyn Model>, ModelError> {
    use crate::config::ProviderType;
    // Semantic validation happens here, not only at load, because the batch runner deliberately
    // loads provider files with `parse_unchecked` so one bad file becomes a single `infra_error`
    // transcript instead of aborting the batch (US2 AS-2). Validating at construction keeps that
    // isolation property while making sure the batch path cannot skip the checks a directly-loaded
    // provider gets — notably the `api_key_env` namespace rule, which is what stops an unreviewed
    // provider TOML from naming an arbitrary host secret.
    cfg.validate_for_use()
        .map_err(|e| ModelError::Request(e.to_string()))?;
    match cfg.provider {
        ProviderType::Anthropic | ProviderType::OpenAiCompat => {
            Ok(Box::new(rig_model::RigModel::from_config(cfg, api_key)?))
        }
        ProviderType::Mock => {
            let turns: Vec<Turn> = cfg
                .script
                .iter()
                .enumerate()
                .map(|(i, step)| match &step.tool {
                    Some(name) => Turn::calls(vec![ToolCall {
                        id: format!("call-{i}"),
                        name: name.clone(),
                        arguments: step.args.clone().unwrap_or(serde_json::Value::Null),
                    }]),
                    None => Turn::text(step.text.clone().unwrap_or_default()),
                })
                .collect();
            Ok(Box::new(
                mock_model::MockModel::scripted(turns).with_id(cfg.model_id()),
            ))
        }
    }
}

/// The stable interface every LLM backend implements (contracts/model-trait.md).
#[async_trait::async_trait]
pub trait Model: Send + Sync {
    /// Stable `"<provider>/<model>"` id recorded in the transcript, e.g. `anthropic/claude-opus-4-8`.
    fn id(&self) -> &str;

    /// One model turn: send the conversation + available tool schemas, get back text and/or tool
    /// calls. MUST perform exactly one provider round-trip and MUST NOT retry internally.
    async fn complete(
        &self,
        convo: &Conversation,
        tools: &[ToolSchema],
    ) -> Result<Turn, ModelError>;

    /// Like [`Model::complete`], but yields the turn incrementally as a stream of [`StreamEvent`]s
    /// ending in exactly one [`StreamEvent::Done`]. The default implementation is a *buffered*
    /// fallback: it performs the same single round-trip as `complete` and then replays the result as
    /// one text delta, the tool calls, and `Done` — so a backend that cannot stream (e.g. the mock,
    /// or a future provider) needs no extra code, and callers can always drive the streaming path.
    /// Real backends override this to emit provider deltas live.
    async fn stream(
        &self,
        convo: &Conversation,
        tools: &[ToolSchema],
    ) -> Result<EventStream, ModelError> {
        let turn = self.complete(convo, tools).await?;
        let mut events: Vec<Result<StreamEvent, ModelError>> = Vec::new();
        if let Some(text) = &turn.text {
            if !text.is_empty() {
                events.push(Ok(StreamEvent::TextDelta(text.clone())));
            }
        }
        for tc in &turn.tool_calls {
            events.push(Ok(StreamEvent::ToolCall(tc.clone())));
        }
        events.push(Ok(StreamEvent::Done(turn)));
        Ok(Box::pin(stream::iter(events)))
    }
}
