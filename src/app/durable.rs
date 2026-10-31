//! Explicit operator opt-in. No project file can silently enable transcript retention.
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug, Default)]
pub struct DurableArgs {
    /// Persist the session in this absolute, private directory (requires durable-sessions).
    #[arg(long, requires = "session_id")]
    pub session_dir: Option<PathBuf>,
    /// Stable session identity; must match the directory on reopen.
    #[arg(long, requires = "session_dir")]
    pub session_id: Option<String>,
    /// Idempotency key for a headless submission; repeating it resumes or replays that request.
    #[arg(long, requires = "session_dir", conflicts_with = "resume")]
    pub request_id: Option<String>,
    /// Resume/replay this previously admitted request without submitting new input.
    #[arg(long, requires = "session_dir")]
    pub resume: Option<String>,
    /// Maximum charged tool attempts per durable submission, including unresolved attempts.
    #[arg(long, requires = "session_dir")]
    pub tool_call_limit: Option<u32>,
}
impl DurableArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.session_dir.is_some() && !cfg!(feature = "durable-sessions") {
            return Err(
                "durable sessions require building with --features durable-sessions".into(),
            );
        }
        if self.session_dir.as_ref().is_some_and(|p| !p.is_absolute()) {
            return Err("--session-dir must be an absolute path".into());
        }
        Ok(())
    }
    #[cfg(feature = "durable-sessions")]
    pub async fn open(
        &self,
        cfg: &super::config::EffectiveConfig,
        tools: &[String],
        security: &bee::security::SecurityConfig,
    ) -> Result<Option<std::sync::Arc<bee::session::driver::Session>>, String> {
        let Some(path) = &self.session_dir else {
            return Ok(None);
        };
        if cfg.context != Default::default() || cfg.stuck != Default::default() {
            return Err(
                "durable sessions do not yet support explicit context or stuck-detection settings"
                    .into(),
            );
        }
        if cfg.policy.as_ref().is_some_and(|p| p.http.is_some())
            || tools.iter().any(|t| t == "finish")
        {
            return Err("durable sessions do not yet support HTTP interception or finish".into());
        }
        let compatibility = bee::session::driver::fingerprint(&serde_json::json!({
            "provider": cfg.provider, "tools": tools, "security": security,
            "cwd": std::env::current_dir().map_err(|e| e.to_string())?,
            "visual": (cfg.visual.level, cfg.visual.animations, cfg.visual.takeover_ttl_secs),
        }))
        .map_err(|e| e.to_string())?;
        bee::session::driver::Session::open(
            path.clone(),
            bee::session::durable::SessionId(
                self.session_id.clone().ok_or("--session-id required")?,
            ),
            compatibility,
            self.resume.clone(),
        )
        .await
        .map(Some)
        .map_err(|e| e.to_string())
    }
}
