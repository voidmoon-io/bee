//! Opt-in live-provider smoke tests (T024). These actually talk to a provider, so they **skip
//! cleanly** when the endpoint/key is absent: no Ollama on `localhost:11434` → skip; no
//! `ANTHROPIC_API_KEY` → skip. They prove `RigModel` really speaks both provider shapes (FR-002).
//!
//! Run with output: `cargo test --test live_smoke -- --nocapture`.

use std::net::TcpStream;
use std::time::Duration;

use bee::config::{ProviderConfig, ProviderType};
use bee::provider::rig_model::RigModel;
use bee::{Conversation, Model};

fn probe_convo() -> Conversation {
    Conversation::new(
        "You are a terse assistant.",
        "Reply with the single word: pong",
    )
}

#[tokio::test]
async fn ollama_openai_compat_smoke() {
    // Skip unless a local Ollama is listening.
    let base = "http://localhost:11434/v1";
    if TcpStream::connect_timeout(
        &"127.0.0.1:11434".parse().unwrap(),
        Duration::from_millis(300),
    )
    .is_err()
    {
        eprintln!("[skip] ollama_openai_compat_smoke: nothing listening on localhost:11434");
        return;
    }

    let cfg = ProviderConfig {
        context_window: None,
        provider: ProviderType::OpenAiCompat,
        base_url: Some(base.to_string()),
        model: std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "qwen2.5-coder".to_string()),
        api_key_env: "OPENAI_API_KEY".to_string(),
        max_tokens: Some(64),
        temperature: None,
        thinking: None,
        effort: None,
        prompt_caching: true,
        script: Vec::new(),
    };
    let model = RigModel::from_config(&cfg, "").expect("build openai-compat model");
    let turn = model
        .complete(&probe_convo(), &[])
        .await
        .expect("ollama completion");
    assert!(
        turn.text.is_some() || !turn.tool_calls.is_empty(),
        "expected some assistant content from ollama"
    );
    eprintln!("[ok] ollama replied: {:?}", turn.text);
}

#[tokio::test]
async fn anthropic_smoke() {
    let key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("[skip] anthropic_smoke: ANTHROPIC_API_KEY not set");
            return;
        }
    };
    let cfg = ProviderConfig {
        context_window: None,
        provider: ProviderType::Anthropic,
        base_url: None,
        // A cheap current model for the smoke; overridable.
        model: std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-haiku-4-5".to_string()),
        api_key_env: "ANTHROPIC_API_KEY".to_string(),
        max_tokens: Some(64),
        temperature: None,
        thinking: None,
        effort: None,
        prompt_caching: true,
        script: Vec::new(),
    };
    let model = RigModel::from_config(&cfg, &key).expect("build anthropic model");
    let turn = model
        .complete(&probe_convo(), &[])
        .await
        .expect("anthropic completion");
    assert!(
        turn.text.is_some(),
        "expected assistant text from anthropic"
    );
    eprintln!("[ok] anthropic replied: {:?}", turn.text);
}
