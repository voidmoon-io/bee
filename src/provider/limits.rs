//! Context windows of the models bee knows (025 research R3), in tokens. Kept in step with
//! `metrics::pricing`, which matches the same ids.
//!
//! The table is deliberately coarse. Every Claude model is listed at 200,000 tokens, its standard
//! window: a model with a larger optional window (1M) is only that large when the account and request
//! opt in, so bee assumes the smaller one and lets `[context] window_tokens` raise it. Guessing low only
//! makes compaction start earlier; guessing high would send requests the provider refuses.

/// The standard window of every Claude model.
const CLAUDE_WINDOW: u32 = 200_000;

/// The window the `mock` provider reports. The mock is not a real model, but giving it a window keeps
/// the unknown-window notice out of every offline run.
const MOCK_WINDOW: u32 = 200_000;

/// The context window of `model_id` (`"<provider>/<model>"` or a bare model name), or `None` when bee
/// does not know it.
pub fn context_window(model_id: &str) -> Option<u32> {
    if model_id.starts_with("mock/") {
        return Some(MOCK_WINDOW);
    }
    let model = model_id.rsplit('/').next().unwrap_or(model_id);
    if model.starts_with("claude-") {
        return Some(CLAUDE_WINDOW);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_models_are_known_with_or_without_a_provider_prefix() {
        assert_eq!(context_window("anthropic/claude-sonnet-4-6"), Some(200_000));
        assert_eq!(context_window("claude-opus-4-8"), Some(200_000));
        assert_eq!(
            context_window("openai-compat/claude-haiku-4-5"),
            Some(200_000)
        );
    }

    #[test]
    fn the_mock_provider_has_a_window() {
        assert_eq!(context_window("mock/scripted"), Some(200_000));
    }

    #[test]
    fn an_unknown_model_is_none() {
        assert_eq!(context_window("openai-compat/llama-3.1-8b"), None);
        assert_eq!(context_window("gpt-oss"), None);
    }
}
