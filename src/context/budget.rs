//! The context budget and the request-size estimator (025 research R2, R3).
//!
//! bee has no tokenizer. A request's size is estimated from its bytes divided by a bytes-per-token
//! ratio that starts conservative (3.0, which over-counts English and code) and is recalibrated from
//! the size the provider reports for each request it was sent.

use crate::provider::framing::UNTRUSTED_DATA_CLAUSE;
use crate::provider::{limits, Conversation, Message, ToolSchema, Usage};

/// The window assumed when nothing names one (R3): the smallest in the study the defaults come from,
/// and the likeliest size of an unknown local model. Too low only compacts early.
pub const DEFAULT_WINDOW: u32 = 32_000;
/// The reply reserve when the provider config sets no `max_tokens` — the adapter's own default.
pub const DEFAULT_MAX_TOKENS: u32 = 4_096;
/// The starting bytes-per-token ratio.
pub const INITIAL_RATIO: f32 = 3.0;
const MIN_RATIO: f32 = 2.0;
const MAX_RATIO: f32 = 6.0;
/// Bytes of framing a tool result gains on the wire beyond its content (error prefix, envelope).
const RESULT_OVERHEAD: usize = 120;

/// Where a session's window came from, in precedence order (contracts/config.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowSource {
    /// `[context] window_tokens` (scenario, project or user config).
    Config,
    /// `[provider] context_window`.
    ProviderFile,
    /// bee's table of known models.
    Table,
    /// Nothing named one: [`DEFAULT_WINDOW`].
    Default,
}

/// How many input tokens one request may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudget {
    /// The model's context window, in tokens.
    pub window: u32,
    /// Room kept for the reply: `max_tokens` plus a 2% margin for estimation error.
    pub reply_reserve: u32,
    pub source: WindowSource,
}

impl ContextBudget {
    /// The window, from the first source that names one.
    pub fn new(
        model_id: &str,
        config_window: Option<u32>,
        provider_window: Option<u32>,
        max_tokens: u32,
    ) -> ContextBudget {
        let (window, source) = if let Some(w) = config_window {
            (w, WindowSource::Config)
        } else if let Some(w) = provider_window {
            (w, WindowSource::ProviderFile)
        } else if let Some(w) = limits::context_window(model_id) {
            (w, WindowSource::Table)
        } else {
            (DEFAULT_WINDOW, WindowSource::Default)
        };
        ContextBudget {
            window,
            reply_reserve: max_tokens.saturating_add(window / 50),
            source,
        }
    }

    /// The input tokens one request may carry.
    pub fn tokens(&self) -> u32 {
        self.window.saturating_sub(self.reply_reserve)
    }
}

/// The bytes a request built from `convo` and `tools` carries, approximately: what the provider
/// adapter sends, minus its fixed JSON structure. Calibration absorbs the difference.
pub fn estimate_bytes(convo: &Conversation, tools: &[ToolSchema]) -> usize {
    let tools_bytes = serde_json::to_vec(tools).map_or(0, |v| v.len());
    let messages: usize = convo.messages.iter().map(message_bytes).sum();
    convo.system.len() + UNTRUSTED_DATA_CLAUSE.len() + tools_bytes + messages
}

/// The bytes one message adds to a request, as [`estimate_bytes`] counts them.
pub fn message_bytes(m: &Message) -> usize {
    match m {
        Message::User { text } => text.len(),
        Message::Assistant { text, tool_calls } => {
            text.as_ref().map_or(0, String::len)
                + tool_calls
                    .iter()
                    .map(|c| c.id.len() + c.name.len() + c.arguments.to_string().len())
                    .sum::<usize>()
        }
        Message::ToolResult {
            call_id, content, ..
        } => call_id.len() + content.len() + RESULT_OVERHEAD,
    }
}

/// Bytes to estimated tokens at `ratio` bytes per token, rounded up.
pub fn tokens(bytes: usize, ratio: f32) -> u32 {
    (bytes as f64 / f64::from(ratio)).ceil() as u32
}

/// The ratio after observing that `sent_bytes` were billed as the request size in `usage`: the
/// running ratio moved halfway toward the observed one, kept within [2, 6]. A provider that reports
/// no input size leaves it as it was.
pub fn recalibrate(ratio: f32, sent_bytes: usize, usage: &Usage) -> f32 {
    let observed = u64::from(usage.input_tokens)
        + u64::from(usage.cache_read_tokens)
        + u64::from(usage.cache_write_tokens);
    if observed == 0 || sent_bytes == 0 {
        return ratio;
    }
    let seen = (sent_bytes as f64 / observed as f64) as f32;
    (0.5 * ratio + 0.5 * seen).clamp(MIN_RATIO, MAX_RATIO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_comes_from_the_first_source_that_names_one() {
        let b = ContextBudget::new(
            "anthropic/claude-sonnet-4-6",
            Some(50_000),
            Some(80_000),
            4096,
        );
        assert_eq!((b.window, b.source), (50_000, WindowSource::Config));
        let b = ContextBudget::new("anthropic/claude-sonnet-4-6", None, Some(80_000), 4096);
        assert_eq!((b.window, b.source), (80_000, WindowSource::ProviderFile));
        let b = ContextBudget::new("anthropic/claude-sonnet-4-6", None, None, 4096);
        assert_eq!((b.window, b.source), (200_000, WindowSource::Table));
        let b = ContextBudget::new("openai-compat/local", None, None, 4096);
        assert_eq!(
            (b.window, b.source),
            (DEFAULT_WINDOW, WindowSource::Default)
        );
    }

    #[test]
    fn the_reply_reserve_is_max_tokens_plus_two_percent() {
        let b = ContextBudget::new("x", Some(100_000), None, 4096);
        assert_eq!(b.reply_reserve, 4096 + 2000);
        assert_eq!(b.tokens(), 100_000 - 6096);
    }

    #[test]
    fn recalibration_moves_toward_the_observed_ratio_and_stays_clamped() {
        let usage = Usage {
            input_tokens: 1000,
            ..Default::default()
        };
        // 4000 bytes billed as 1000 tokens: 4 bytes/token observed; halfway from 3 is 3.5.
        assert_eq!(recalibrate(3.0, 4000, &usage), 3.5);
        // Absurd observations are clamped.
        assert_eq!(recalibrate(3.0, 100_000, &usage), 6.0);
        assert_eq!(recalibrate(3.0, 10, &usage), 2.0);
        // No reported size: unchanged.
        assert_eq!(recalibrate(3.0, 4000, &Usage::default()), 3.0);
    }

    #[test]
    fn cache_tokens_count_toward_the_observed_size() {
        let usage = Usage {
            input_tokens: 200,
            cache_read_tokens: 600,
            cache_write_tokens: 200,
            ..Default::default()
        };
        assert_eq!(recalibrate(3.0, 4000, &usage), 3.5);
    }
}
