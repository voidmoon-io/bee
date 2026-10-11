//! How much conversation a model can be sent, and keeping a long session inside it
//! (025-long-run-resilience, specs/025-long-run-resilience/contracts/context.md).
//!
//! A session has a **context budget**: the model's window less room for its reply (research R3).
//! Before every model request bee estimates the request's size from its bytes, calibrated by the
//! token counts the provider reports (R2), and never sends a request it measures as over budget.
//! Each tool result reaches the model capped at the smaller of a byte limit and a share of the budget
//! (R8); the session record keeps the tool's full output.
//!
//! Compaction (R1, R5–R7) edits the conversation in place. The record is built from call results, not
//! from the conversation, so it never sees compaction (FR-011).

pub mod budget;
pub mod config;

use crate::provider::{Conversation, ToolSchema, Usage};

pub use budget::{ContextBudget, WindowSource};
pub use config::{ConfigError, ContextConfig, ResolvedContext};

/// What a session knows about its context before it starts: the `[context]` layers below the scenario
/// (user and project config), and the provider file's `context_window` and `max_tokens`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContextInputs {
    /// `[context]` from user and project config, already merged. A scenario's own `[context]` is merged
    /// over it by the loop.
    pub config: ContextConfig,
    /// `[provider] context_window`.
    pub provider_window: Option<u32>,
    /// `[provider] max_tokens`; `None` is the adapter's default.
    pub max_tokens: Option<u32>,
}

/// The size of the request about to be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prepared {
    pub estimate_tokens: u32,
    pub sent_bytes: usize,
}

/// The request cannot be brought within the context budget (FR-002, FR-014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextExhausted {
    pub detail: String,
}

/// One session's context budget and the state that keeps it (data-model.md). Both loops hold one and
/// call it at the same points: [`prepare`](Self::prepare) before each model request,
/// [`observe`](Self::observe) after it, and [`cap`](Self::cap) on each tool result they push.
#[derive(Debug, Clone)]
pub struct ContextManager {
    cfg: ResolvedContext,
    budget: ContextBudget,
    /// Bytes per token (R2).
    ratio: f32,
}

impl ContextManager {
    /// Build the manager for a session on `model_id`. `scenario` is the scenario's own `[context]`,
    /// which wins over `inputs.config`. The `String` is the one-time notice to show when the window is
    /// a guess (FR-001).
    pub fn for_session(
        inputs: &ContextInputs,
        scenario: Option<&ContextConfig>,
        model_id: &str,
    ) -> Result<(ContextManager, Option<String>), ConfigError> {
        let cfg = match scenario {
            Some(s) => inputs.config.merge(*s),
            None => inputs.config,
        };
        let max_tokens = inputs.max_tokens.unwrap_or(budget::DEFAULT_MAX_TOKENS);
        let budget = ContextBudget::new(
            model_id,
            cfg.window_tokens,
            inputs.provider_window,
            max_tokens,
        );
        let resolved = cfg.resolve(budget.window, max_tokens)?;
        let notice = (budget.source == WindowSource::Default).then(|| {
            format!(
                "context: window unknown for {model_id}; assuming {} tokens (set [context] window_tokens)",
                budget.window
            )
        });
        Ok((
            ContextManager {
                cfg: resolved,
                budget,
                ratio: budget::INITIAL_RATIO,
            },
            notice,
        ))
    }

    pub fn budget(&self) -> &ContextBudget {
        &self.budget
    }

    pub fn config(&self) -> &ResolvedContext {
        &self.cfg
    }

    /// The bytes of one tool result the model may receive: the smaller of the configured byte cap and
    /// a share of the budget (FR-020).
    pub fn result_cap(&self) -> usize {
        let share = f64::from(self.budget.tokens())
            * f64::from(self.cfg.result_cap_share)
            * f64::from(self.ratio);
        (self.cfg.result_cap_bytes as usize).min(share as usize)
    }

    /// `content` as the model should see it (FR-020, FR-021). A result within the cap is returned
    /// unchanged; a longer one is cut on a char boundary and marked with its original size —
    /// `original_len` when the tool had already cut it. The record keeps the tool's result (FR-022).
    pub fn cap(&self, content: &str, original_len: Option<usize>) -> String {
        let cap = self.result_cap();
        if content.len() <= cap {
            return content.to_string();
        }
        let end = crate::transcript::char_floor(content, cap);
        let original = original_len.unwrap_or(content.len()).max(content.len());
        format!(
            "{}\n[bee: showing {end} of {original} bytes — request a narrower range (line offset, \
             filter, smaller search) to see more]",
            &content[..end]
        )
    }

    /// Measure the request `convo` and `tools` make, and refuse it if it is over budget (FR-002).
    pub fn prepare(
        &mut self,
        convo: &Conversation,
        tools: &[ToolSchema],
    ) -> Result<Prepared, ContextExhausted> {
        let sent_bytes = budget::estimate_bytes(convo, tools);
        let estimate_tokens = budget::tokens(sent_bytes, self.ratio);
        if estimate_tokens > self.budget.tokens() {
            return Err(ContextExhausted {
                detail: format!(
                    "the next request is about {estimate_tokens} tokens; the context budget is {} \
                     ({}-token window less {} for the reply)",
                    self.budget.tokens(),
                    self.budget.window,
                    self.budget.reply_reserve
                ),
            });
        }
        Ok(Prepared {
            estimate_tokens,
            sent_bytes,
        })
    }

    /// Recalibrate the estimator from what the provider reported for the request just sent (R2).
    pub fn observe(&mut self, sent_bytes: usize, usage: Option<&Usage>) {
        if let Some(u) = usage {
            self.ratio = budget::recalibrate(self.ratio, sent_bytes, u);
        }
    }

    /// The current bytes-per-token ratio.
    pub fn ratio(&self) -> f32 {
        self.ratio
    }

    /// Forget per-conversation state (`/clear`, FR-019). The calibrated ratio is kept: it describes the
    /// model, not the conversation.
    pub fn reset(&mut self) {}
}

/// Whether a provider error (as the loops report it) is a refusal for exceeding the context window —
/// the second line of defence when the estimate was low (plan risk 2).
pub fn is_context_overflow(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    [
        "prompt is too long",
        "context_length_exceeded",
        "maximum context length",
        "context window",
        "too many tokens",
    ]
    .iter()
    .any(|p| d.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(window: u32) -> ContextManager {
        let inputs = ContextInputs {
            config: ContextConfig {
                window_tokens: Some(window),
                ..Default::default()
            },
            provider_window: None,
            max_tokens: Some(1024),
        };
        ContextManager::for_session(&inputs, None, "mock/scripted")
            .unwrap()
            .0
    }

    #[test]
    fn a_result_within_the_cap_is_unchanged() {
        assert_eq!(manager(200_000).cap("hello", None), "hello");
    }

    #[test]
    fn the_cap_is_the_smaller_of_bytes_and_budget_share() {
        // 200k window: 10% of the budget is far above 24,000 bytes, so the byte cap applies.
        assert_eq!(manager(200_000).result_cap(), 24_000);
        // 16k window: budget 16000 - 1024 - 320 = 14656 tokens; 10% × 3 bytes/token = 4396 bytes.
        assert_eq!(manager(16_000).result_cap(), 4_396);
    }

    #[test]
    fn a_cut_never_splits_a_character_and_states_the_original_size() {
        let m = manager(200_000);
        let s = "é".repeat(20_000); // 40,000 bytes
        let out = m.cap(&s, None);
        assert!(
            out.contains("of 40000 bytes"),
            "{}",
            &out[out.len() - 120..]
        );
        assert!(out.starts_with('é'));
        let out = m.cap(&s, Some(100_000));
        assert!(
            out.contains("of 100000 bytes"),
            "the tool's own original size wins"
        );
    }

    #[test]
    fn context_overflow_errors_are_recognised() {
        assert!(is_context_overflow(
            "provider rejected request: prompt is too long: 210000 tokens > 200000 maximum"
        ));
        assert!(!is_context_overflow("provider authentication failed"));
    }
}
