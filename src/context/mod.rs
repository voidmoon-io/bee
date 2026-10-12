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
pub mod compact;
pub mod config;
pub mod summary;

use std::collections::HashMap;
use std::time::Instant;

use crate::provider::{Conversation, Message, Model, ToolSchema, Usage};
use crate::transcript::{CompactionEvent, CompactionKind};

use compact::{CallNote, TurnSpan};
use summary::SummaryState;

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
    /// What a summary call made while preparing cost (FR-013): the loop adds it to the session's
    /// usage. The events themselves come from [`ContextManager::take_events`].
    pub summary_usage: Option<Usage>,
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
    /// What each pushed result's stub would say, by call id (R5).
    notes: HashMap<String, CallNote>,
    summary: Option<SummaryState>,
    /// Whether the head (the bee-inserted messages after the preamble) holds a summary, then a removal
    /// marker. Known by position, never by text (analysis U2).
    head_summary: bool,
    head_marker: bool,
    /// Turns folded or removed so far: the number the oldest remaining turn would have had.
    turns_gone: u32,
    /// Turns removed so far, as the marker states.
    removed: u32,
    events: Vec<CompactionEvent>,
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
                notes: HashMap::new(),
                summary: None,
                head_summary: false,
                head_marker: false,
                turns_gone: 0,
                removed: 0,
                events: Vec::new(),
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

    /// Record what `call_id`'s stub would say, when its result is pushed (R5).
    pub fn note_call(&mut self, call_id: &str, note: CallNote) {
        self.notes.insert(call_id.to_string(), note);
    }

    /// The compactions since the last call, for the record (FR-017).
    pub fn take_events(&mut self) -> Vec<CompactionEvent> {
        std::mem::take(&mut self.events)
    }

    fn tokens(&self, bytes: usize) -> u32 {
        budget::tokens(bytes, self.ratio)
    }

    /// `share` of the budget, in bytes at the current ratio.
    fn share_bytes(&self, share: f32) -> usize {
        (f64::from(self.budget.tokens()) * f64::from(share) * f64::from(self.ratio)) as usize
    }

    fn head_len(&self) -> usize {
        usize::from(self.head_summary) + usize::from(self.head_marker)
    }

    /// Bring the request `convo` and `tools` make within budget, then measure it (contracts/context.md
    /// "Per-turn sequence"). With compaction on: over `soft` of the budget, bulky middle results are
    /// elided; still over `hard`, the oldest middle turns are folded into the summary, or removed if
    /// that fails. Either way, a request still over the whole budget is refused (FR-002, FR-014).
    /// `turn` stamps the events. The future is `Send` and holds no lock across its one await.
    pub async fn prepare(
        &mut self,
        convo: &mut Conversation,
        tools: &[ToolSchema],
        model: &dyn Model,
        deadline: Instant,
        turn: u32,
    ) -> Result<Prepared, ContextExhausted> {
        let mut summary_usage = None;
        if self.cfg.compaction {
            summary_usage = self.compact(convo, tools, model, deadline, turn).await;
        }
        let sent_bytes = budget::estimate_bytes(convo, tools);
        let estimate_tokens = self.tokens(sent_bytes);
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
            summary_usage,
        })
    }

    /// Elide, then summarize or remove, as the thresholds call for. Returns the summary call's usage.
    async fn compact(
        &mut self,
        convo: &mut Conversation,
        tools: &[ToolSchema],
        model: &dyn Model,
        deadline: Instant,
        turn: u32,
    ) -> Option<Usage> {
        let b = f64::from(self.budget.tokens());
        let soft = (b * f64::from(self.cfg.soft)) as u32;
        let hard = (b * f64::from(self.cfg.hard)) as u32;
        let target_bytes = self.share_bytes(self.cfg.soft - self.cfg.target_gap);

        let mut bytes = budget::estimate_bytes(convo, tools);
        if self.tokens(bytes) < soft {
            return None;
        }
        let preamble = convo.messages.len().min(1);
        let head_end = (preamble + self.head_len()).min(convo.messages.len());
        let spans = compact::segment(convo, head_end);
        let recent = compact::recent_start(
            convo,
            &spans,
            self.ratio,
            self.budget.tokens(),
            self.cfg.recent_share,
        );
        if recent == 0 {
            return None;
        }
        let middle_end = spans[recent].start;

        // 1. Elision (R5).
        let before = self.tokens(bytes);
        let bulky_bytes = (self.cfg.bulky_tokens as f32 * self.ratio) as usize;
        let elided = compact::elide(
            convo,
            &self.notes,
            head_end,
            middle_end,
            bulky_bytes,
            &mut bytes,
            target_bytes,
        );
        if elided > 0 {
            self.events.push(CompactionEvent {
                turn,
                kind: CompactionKind::Elided,
                items: elided,
                turns: None,
                before_tokens: before,
                after_tokens: self.tokens(bytes),
                usage: None,
                error: None,
            });
        }
        if self.tokens(bytes) < hard {
            return None;
        }

        // 2. Summarize the oldest middle turns, enough to reach the target (R6).
        let middle = &spans[..recent];
        let mut fold = 0;
        let mut freed = 0usize;
        for span in middle {
            fold += 1;
            freed += compact::span_bytes(convo, *span);
            if bytes.saturating_sub(freed) <= target_bytes {
                break;
            }
        }
        let folded: Vec<TurnSpan> = middle[..fold].to_vec();
        let fold_end = folded[fold - 1].end;
        let (first, last) = (self.turns_gone, self.turns_gone + fold as u32 - 1);
        let before = self.tokens(bytes);

        let mut prev = self.summary.as_ref().map(|s| s.text.clone());
        if self.head_marker {
            let marker = compact::removal_marker(self.removed);
            prev = Some(match prev {
                Some(p) => format!("{p}\n{marker}"),
                None => marker,
            });
        }
        let words = (b * f64::from(self.cfg.summary_share) * 0.75) as u32;
        let request = summary::render_request(prev.as_deref(), convo, &folded, first, &self.notes);
        let max_bytes = self.share_bytes(self.cfg.summary_share);
        let outcome = summary::summarize(
            model,
            summary::system_prompt(words),
            request,
            max_bytes,
            deadline,
        )
        .await;
        self.turns_gone += fold as u32;

        match outcome {
            Ok((text, usage)) => {
                // The new summary replaces the whole head, folding any marker into itself.
                let state = SummaryState::next(self.summary.as_ref(), text, first, last);
                convo.messages.drain(preamble..fold_end);
                convo.messages.insert(
                    preamble,
                    Message::User {
                        text: state.message_text(),
                    },
                );
                self.summary = Some(state);
                self.head_summary = true;
                self.head_marker = false;
                self.events.push(CompactionEvent {
                    turn,
                    kind: CompactionKind::Summarized,
                    items: fold as u32,
                    turns: Some((first, last)),
                    before_tokens: before,
                    after_tokens: self.tokens(budget::estimate_bytes(convo, tools)),
                    usage,
                    error: None,
                });
                usage
            }
            Err(error) => {
                // 3. Remove instead, keeping the summary and leaving one marker (R7).
                convo.messages.drain(head_end..fold_end);
                self.removed += fold as u32;
                let marker = Message::User {
                    text: compact::removal_marker(self.removed),
                };
                let at = preamble + usize::from(self.head_summary);
                if self.head_marker {
                    convo.messages[at] = marker;
                } else {
                    convo.messages.insert(at, marker);
                    self.head_marker = true;
                }
                self.events.push(CompactionEvent {
                    turn,
                    kind: CompactionKind::Removed,
                    items: fold as u32,
                    turns: Some((first, last)),
                    before_tokens: before,
                    after_tokens: self.tokens(budget::estimate_bytes(convo, tools)),
                    usage: None,
                    error: Some(error),
                });
                None
            }
        }
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
    pub fn reset(&mut self) {
        self.notes.clear();
        self.summary = None;
        self.head_summary = false;
        self.head_marker = false;
        self.turns_gone = 0;
        self.removed = 0;
        self.events.clear();
    }
}

/// The progress or info line for a compaction (contracts/context.md "Progress and info lines"), without
/// the headless indent.
pub fn describe(e: &CompactionEvent, budget_tokens: u32) -> String {
    let k = |t: u32| format!("{:.1}k", f64::from(t) / 1000.0);
    let sizes = format!(
        "({} → {} tokens of {})",
        k(e.before_tokens),
        k(e.after_tokens),
        k(budget_tokens)
    );
    let (a, b) = e.turns.unwrap_or((0, 0));
    match e.kind {
        CompactionKind::Elided => format!("context: elided {} results {sizes}", e.items),
        CompactionKind::Summarized => format!("context: summarized turns {a}–{b} {sizes}"),
        CompactionKind::Removed => format!(
            "context: removed {} turns after summary failure: {}",
            e.items,
            e.error.as_deref().unwrap_or("")
        ),
    }
}

/// `prepare`'s future must be `Send`: the concurrent runner spawns the episode loop.
#[allow(dead_code)]
fn _assert_send(m: &mut ContextManager, c: &mut Conversation, model: &dyn Model) {
    fn send<T: Send>(_: T) {}
    send(m.prepare(c, &[], model, Instant::now(), 0));
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
