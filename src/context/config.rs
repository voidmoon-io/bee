//! The `[context]` table (025 contracts/config.md, data-model.md).
//!
//! Every key is optional, so the same type serves each layer — user config, project config, a
//! scenario — and [`ContextConfig::merge`] folds them. [`ContextConfig::resolve`] applies defaults and
//! rejects a nonsensical combination outright: a bad threshold is a start-up error, never a silent
//! clamp (Constitution I).

use serde::{Deserialize, Serialize};

/// Default share of the budget above which bulky results are elided.
pub const DEFAULT_SOFT: f32 = 0.60;
/// Default share of the budget above which old turns are summarized.
pub const DEFAULT_HARD: f32 = 0.85;
/// Default gap below `soft` that compaction aims for (FR-015).
pub const DEFAULT_TARGET_GAP: f32 = 0.10;
/// Default share of the budget kept verbatim at the end of the conversation.
pub const DEFAULT_RECENT_SHARE: f32 = 0.30;
/// Default size, in estimated tokens, above which a result may be elided.
pub const DEFAULT_BULKY_TOKENS: u32 = 300;
/// Default maximum summary size, as a share of the budget.
pub const DEFAULT_SUMMARY_SHARE: f32 = 0.10;
/// Default model-facing cap on one tool result, in bytes (research R8).
pub const DEFAULT_RESULT_CAP_BYTES: u32 = 24_000;
/// Default model-facing cap on one tool result, as a share of the budget.
pub const DEFAULT_RESULT_CAP_SHARE: f32 = 0.10;
/// The smallest request bee accepts room for, beyond the reply reserve.
const MIN_INPUT_TOKENS: u32 = 4_096;

/// One layer of `[context]` settings. `None` means "not set here".
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_gap: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_share: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bulky_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_share: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_cap_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_cap_share: Option<f32>,
}

impl ContextConfig {
    /// `self` with every key `over` sets replaced by `over`'s value.
    pub fn merge(self, over: ContextConfig) -> ContextConfig {
        ContextConfig {
            window_tokens: over.window_tokens.or(self.window_tokens),
            compaction: over.compaction.or(self.compaction),
            soft: over.soft.or(self.soft),
            hard: over.hard.or(self.hard),
            target_gap: over.target_gap.or(self.target_gap),
            recent_share: over.recent_share.or(self.recent_share),
            bulky_tokens: over.bulky_tokens.or(self.bulky_tokens),
            summary_share: over.summary_share.or(self.summary_share),
            result_cap_bytes: over.result_cap_bytes.or(self.result_cap_bytes),
            result_cap_share: over.result_cap_share.or(self.result_cap_share),
        }
    }

    /// Apply defaults and validate. `window` is the window that will be used (whatever its source)
    /// and `max_tokens` the reply limit, so a window too small to hold a reply is caught here.
    pub fn resolve(&self, window: u32, max_tokens: u32) -> Result<ResolvedContext, ConfigError> {
        let r = ResolvedContext {
            compaction: self.compaction.unwrap_or(false),
            soft: self.soft.unwrap_or(DEFAULT_SOFT),
            hard: self.hard.unwrap_or(DEFAULT_HARD),
            target_gap: self.target_gap.unwrap_or(DEFAULT_TARGET_GAP),
            recent_share: self.recent_share.unwrap_or(DEFAULT_RECENT_SHARE),
            bulky_tokens: self.bulky_tokens.unwrap_or(DEFAULT_BULKY_TOKENS),
            summary_share: self.summary_share.unwrap_or(DEFAULT_SUMMARY_SHARE),
            result_cap_bytes: self.result_cap_bytes.unwrap_or(DEFAULT_RESULT_CAP_BYTES),
            result_cap_share: self.result_cap_share.unwrap_or(DEFAULT_RESULT_CAP_SHARE),
        };
        if !(0.0 < r.soft && r.soft < r.hard && r.hard < 1.0) {
            return Err(ConfigError(format!(
                "[context] needs 0 < soft < hard < 1 (soft = {}, hard = {})",
                r.soft, r.hard
            )));
        }
        if !(0.0 < r.target_gap && r.target_gap < r.soft) {
            return Err(ConfigError(format!(
                "[context] target_gap must be above 0 and below soft (target_gap = {}, soft = {})",
                r.target_gap, r.soft
            )));
        }
        for (name, v) in [
            ("recent_share", r.recent_share),
            ("summary_share", r.summary_share),
            ("result_cap_share", r.result_cap_share),
        ] {
            if !(0.0 < v && v <= 0.5) {
                return Err(ConfigError(format!(
                    "[context] {name} must be above 0 and at most 0.5 (got {v})"
                )));
            }
        }
        if r.bulky_tokens == 0 || r.result_cap_bytes == 0 {
            return Err(ConfigError(
                "[context] bulky_tokens and result_cap_bytes must be above 0".into(),
            ));
        }
        if window < MIN_INPUT_TOKENS.saturating_add(max_tokens) {
            return Err(ConfigError(format!(
                "a context window of {window} tokens cannot hold a {max_tokens}-token reply and a \
                 {MIN_INPUT_TOKENS}-token request; raise [context] window_tokens or lower max_tokens"
            )));
        }
        Ok(r)
    }
}

/// `[context]` with every default applied, validated.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedContext {
    pub compaction: bool,
    pub soft: f32,
    pub hard: f32,
    pub target_gap: f32,
    pub recent_share: f32,
    pub bulky_tokens: u32,
    pub summary_share: f32,
    pub result_cap_bytes: u32,
    pub result_cap_share: f32,
}

/// An invalid `[context]` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(c: ContextConfig) -> Result<ResolvedContext, ConfigError> {
        c.resolve(200_000, 4_096)
    }

    #[test]
    fn defaults_follow_the_data_model() {
        let r = resolve(ContextConfig::default()).unwrap();
        assert!(
            !r.compaction,
            "compaction ships off until SC-010 (research R12)"
        );
        assert_eq!((r.soft, r.hard, r.target_gap), (0.60, 0.85, 0.10));
        assert_eq!(r.result_cap_bytes, 24_000);
    }

    #[test]
    fn soft_at_or_above_hard_is_rejected() {
        let c = ContextConfig {
            soft: Some(0.9),
            hard: Some(0.85),
            ..Default::default()
        };
        assert!(resolve(c).unwrap_err().0.contains("soft < hard"));
    }

    #[test]
    fn a_zero_share_is_rejected() {
        let c = ContextConfig {
            result_cap_share: Some(0.0),
            ..Default::default()
        };
        assert!(resolve(c).unwrap_err().0.contains("result_cap_share"));
    }

    #[test]
    fn a_window_too_small_for_the_reply_is_rejected() {
        let err = ContextConfig::default().resolve(6_000, 4_096).unwrap_err();
        assert!(err.0.contains("cannot hold"), "{err}");
    }

    #[test]
    fn merge_takes_the_upper_layer_where_it_is_set() {
        let user = ContextConfig {
            window_tokens: Some(100_000),
            soft: Some(0.5),
            ..Default::default()
        };
        let scenario = ContextConfig {
            window_tokens: Some(32_000),
            ..Default::default()
        };
        let m = user.merge(scenario);
        assert_eq!(m.window_tokens, Some(32_000));
        assert_eq!(m.soft, Some(0.5));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(toml::from_str::<ContextConfig>("soft = 0.5\nsofft = 0.6").is_err());
    }
}
