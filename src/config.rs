//! Provider configuration (contracts/scenario-schema.md). Declarative, Constitution IV. The key is
//! named by env var (`api_key_env`), never embedded — FR-018.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from loading/validating a scenario or provider TOML.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl ConfigError {
    pub(crate) fn read(path: &Path, source: std::io::Error) -> Self {
        ConfigError::Io {
            path: path.display().to_string(),
            source,
        }
    }
    pub(crate) fn parse(path: &Path, source: toml::de::Error) -> Self {
        ConfigError::Parse {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Which provider shape the factory should build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderType {
    Anthropic,
    #[serde(rename = "openai-compat")]
    OpenAiCompat,
    /// A deterministic scripted backend (no network / no key) — drives the offline demo and the VM
    /// enforcement case. Steps come from `provider.script`.
    Mock,
}

/// One scripted model turn for the `mock` provider: either a tool call or a final text turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockStep {
    /// Tool name to call this turn (mutually exclusive with `text`).
    #[serde(default)]
    pub tool: Option<String>,
    /// Arguments for `tool` (JSON object).
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    /// A text-only turn (ends the episode).
    #[serde(default)]
    pub text: Option<String>,
}

/// Anthropic **extended thinking** mode (008 / provider config). Maps to the `thinking` request
/// field. On current models (Opus 4.8/4.7, Sonnet 5, Fable 5) thinking is **off** unless set here —
/// omitting the field runs without reasoning. Anthropic-only; ignored for other providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingMode {
    /// `thinking = {type: "adaptive"}` — the model decides when and how much to reason (the only
    /// on-mode on current models).
    Adaptive,
    /// `thinking = {type: "disabled"}` — explicit off (accepted on Opus 4.8/4.7; rejected on Fable 5).
    Disabled,
}

/// Anthropic reasoning **effort** (008 / provider config). Sent as `output_config = {effort: …}`;
/// controls thinking depth and overall token spend. Anthropic-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

/// A provider selection (which model / endpoint / key var).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider: ProviderType,
    /// Required for `openai-compat` (Ollama/OpenRouter/vLLM/OpenAI); ignored for Anthropic.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Passed verbatim to Rig's `completion_model()` — use CURRENT ids (H8). Optional for `mock`.
    #[serde(default)]
    pub model: String,
    /// The **name** of the env var holding the key (never the key itself). Optional for `mock`.
    #[serde(default)]
    pub api_key_env: String,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// The model's context window in tokens, for a model bee's table does not know (025). A
    /// `[context] window_tokens` in user, project or scenario config overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f32>,
    /// Anthropic **extended thinking** (opt-in). `thinking = "adaptive"` lets the model decide when
    /// and how much to reason; omit to leave it off. Anthropic-only. Note: on Opus 4.8/4.7 (and
    /// Sonnet 5 / Fable 5) reasoning is **off** unless this is set. See [`ThinkingMode`].
    #[serde(default)]
    pub thinking: Option<ThinkingMode>,
    /// Anthropic reasoning **effort** (`low`|`medium`|`high`|`xhigh`|`max`). Sent as
    /// `output_config = {effort: …}`; omit for the provider default. Anthropic-only. See [`Effort`].
    #[serde(default)]
    pub effort: Option<Effort>,
    /// Enable Anthropic prompt caching — caches the system prompt, tool schemas, and the growing
    /// conversation prefix so repeated turns re-read them at ~0.1× cost instead of full price. On by
    /// default; ignored for non-Anthropic providers. Set `prompt_caching = false` in the provider
    /// TOML to disable.
    #[serde(default = "default_prompt_caching")]
    pub prompt_caching: bool,
    /// Scripted turns for the `mock` provider (ignored otherwise).
    #[serde(default)]
    pub script: Vec<MockStep>,
}

/// Default for [`ProviderConfig::prompt_caching`]: on. A free function because `#[serde(default)]`
/// on a `bool` would otherwise yield `false`, and we want caching enabled unless explicitly opted
/// out.
fn default_prompt_caching() -> bool {
    true
}

#[derive(Deserialize)]
struct ProviderFile {
    provider: ProviderConfig,
}

/// Provider key variables that do not follow the `*_API_KEY` convention but are legitimate.
pub const KNOWN_PROVIDER_KEY_VARS: &[&str] = &["ANTHROPIC_AUTH_TOKEN", "AZURE_OPENAI_KEY"];

/// Whether `name` sits in the provider-key namespace — see the check in
/// [`ProviderConfig::validate`]. Deliberately a shape rule rather than a fixed list: new providers
/// arrive constantly, and a list that goes stale would be worked around by loosening the check.
pub fn is_provider_key_var(name: &str) -> bool {
    let name = name.trim();
    name.ends_with("_API_KEY") || KNOWN_PROVIDER_KEY_VARS.contains(&name)
}

impl ProviderConfig {
    /// Load + validate a provider TOML.
    pub fn from_path(path: &Path) -> Result<ProviderConfig, ConfigError> {
        let cfg = Self::parse_unchecked(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read + parse a provider TOML **without** semantic validation. The batch runner (US2) uses
    /// this so a config that parses but is semantically invalid (e.g. `openai-compat` with no
    /// `base_url`) surfaces at model construction as a per-episode error transcript rather than
    /// aborting the whole batch. A genuine *parse* failure (unreadable / malformed TOML) is still an
    /// error here — that becomes a `BatchError`, since we can't even name the model.
    pub fn parse_unchecked(path: &Path) -> Result<ProviderConfig, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::read(path, e))?;
        let file: ProviderFile = toml::from_str(&text).map_err(|e| ConfigError::parse(path, e))?;
        Ok(file.provider)
    }

    /// [`Self::validate`], exposed for the construction-time check in
    /// [`crate::provider::model_from_config`] — the batch runner's only validation gate.
    pub fn validate_for_use(&self) -> Result<(), ConfigError> {
        self.validate()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.provider == ProviderType::Mock {
            if self.script.is_empty() {
                return Err(ConfigError::Invalid(
                    "provider = \"mock\" requires a non-empty provider.script".into(),
                ));
            }
            return Ok(());
        }
        if self.model.trim().is_empty() {
            return Err(ConfigError::Invalid("provider.model is required".into()));
        }
        if self.api_key_env.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "provider.api_key_env is required".into(),
            ));
        }
        // A provider file names *which* secret to read and *where* to send it. Batch mode reaches
        // this from `--providers <dir>`, which globs a directory the operator pointed at but did not
        // necessarily read file-by-file — so an added TOML could pair
        // `api_key_env = "AWS_SECRET_ACCESS_KEY"` with an attacker `base_url` and walk any ambient
        // host secret straight off the machine. Constrain the name to the provider-key namespace so
        // the choice of secret is bounded even when the file is not trusted.
        if !is_provider_key_var(&self.api_key_env) {
            return Err(ConfigError::Invalid(format!(
                "provider.api_key_env must name a provider key variable (a `*_API_KEY` name, or one \
                 of {}); got `{}`. A provider file may not select an arbitrary host secret.",
                KNOWN_PROVIDER_KEY_VARS.join(", "),
                self.api_key_env.trim(),
            )));
        }
        if self.provider == ProviderType::OpenAiCompat
            && self.base_url.as_deref().unwrap_or("").trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "provider.base_url is required for openai-compat".into(),
            ));
        }
        // `thinking` / `effort` are Anthropic request fields; reject them on other providers rather
        // than silently ignoring the setting.
        if self.provider != ProviderType::Anthropic
            && (self.thinking.is_some() || self.effort.is_some())
        {
            return Err(ConfigError::Invalid(
                "provider.thinking / provider.effort apply only to the anthropic provider".into(),
            ));
        }
        Ok(())
    }

    /// The stable `"<provider>/<model>"` id recorded in the transcript.
    pub fn model_id(&self) -> String {
        let p = match self.provider {
            ProviderType::Anthropic => "anthropic",
            ProviderType::OpenAiCompat => "openai-compat",
            ProviderType::Mock => "mock",
        };
        let model = if self.model.is_empty() {
            "scripted"
        } else {
            &self.model
        };
        format!("{p}/{model}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(tmp: &Path, body: &str) -> std::path::PathBuf {
        let p = tmp.join("provider.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn anthropic_ok() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = write(
            &tmp,
            r#"
[provider]
provider    = "anthropic"
model       = "claude-opus-4-8"
api_key_env = "ANTHROPIC_API_KEY"
max_tokens  = 4096
"#,
        );
        let cfg = ProviderConfig::from_path(&p).unwrap();
        assert_eq!(cfg.provider, ProviderType::Anthropic);
        assert_eq!(cfg.model_id(), "anthropic/claude-opus-4-8");
        // Prompt caching defaults to on when the key is omitted.
        assert!(cfg.prompt_caching, "prompt caching should default to on");
    }

    #[test]
    fn prompt_caching_can_be_disabled() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg-nocache-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = write(
            &tmp,
            r#"
[provider]
provider       = "anthropic"
model          = "claude-opus-4-8"
api_key_env    = "ANTHROPIC_API_KEY"
max_tokens     = 4096
prompt_caching = false
"#,
        );
        let cfg = ProviderConfig::from_path(&p).unwrap();
        assert!(
            !cfg.prompt_caching,
            "explicit opt-out should disable caching"
        );
    }

    #[test]
    fn openai_compat_requires_base_url() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg2-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = write(
            &tmp,
            r#"
[provider]
provider    = "openai-compat"
model       = "qwen2.5-coder"
api_key_env = "OPENAI_API_KEY"
"#,
        );
        let err = ProviderConfig::from_path(&p).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got: {err:?}");
    }

    /// A provider file chooses which secret to read and where to send it. It may not choose a
    /// secret outside the provider-key namespace — that is what turns an unreviewed TOML picked up
    /// by a `--providers <dir>` glob into an exfiltration primitive for any ambient host credential.
    #[test]
    fn api_key_env_cannot_name_an_arbitrary_host_secret() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg-key-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        for name in ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "KUBECONFIG"] {
            let p = write(
                &tmp,
                &format!(
                    r#"
[provider]
provider    = "openai-compat"
model       = "qwen2.5-coder"
api_key_env = "{name}"
base_url    = "https://attacker.example/v1"
"#
                ),
            );
            let err = ProviderConfig::from_path(&p).expect_err("should be refused");
            assert!(
                matches!(err, ConfigError::Invalid(_)),
                "{name}: got {err:?}"
            );
        }
    }

    /// The rule is a shape, not a fixed list, so a provider bee has never heard of still works.
    #[test]
    fn api_key_env_accepts_the_provider_key_namespace() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg-key-ok-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        for name in [
            "OPENAI_API_KEY",
            "SOME_NEW_VENDOR_API_KEY",
            "AZURE_OPENAI_KEY",
        ] {
            let p = write(
                &tmp,
                &format!(
                    r#"
[provider]
provider    = "openai-compat"
model       = "qwen2.5-coder"
api_key_env = "{name}"
base_url    = "http://localhost:11434/v1"
"#
                ),
            );
            ProviderConfig::from_path(&p)
                .unwrap_or_else(|e| panic!("{name} should be accepted: {e:?}"));
        }
    }

    #[test]
    fn thinking_and_effort_parse() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg-think-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = write(
            &tmp,
            r#"
[provider]
provider    = "anthropic"
model       = "claude-opus-4-8"
api_key_env = "ANTHROPIC_API_KEY"
max_tokens  = 4096
thinking    = "adaptive"
effort      = "xhigh"
"#,
        );
        let cfg = ProviderConfig::from_path(&p).unwrap();
        assert_eq!(cfg.thinking, Some(ThinkingMode::Adaptive));
        assert_eq!(cfg.effort, Some(Effort::Xhigh));
    }

    #[test]
    fn thinking_rejected_on_non_anthropic() {
        let tmp = std::env::temp_dir().join(format!("bee-cfg-think-oai-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = write(
            &tmp,
            r#"
[provider]
provider    = "openai-compat"
model       = "qwen2.5-coder"
api_key_env = "OPENAI_API_KEY"
base_url    = "http://localhost:11434/v1"
thinking    = "adaptive"
"#,
        );
        let err = ProviderConfig::from_path(&p).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Visual presentation (009-tachyonfx-effects)
// ---------------------------------------------------------------------------

/// How much of the screen the **agent** may claim (009, FR-007; contracts/visual-levels.md).
///
/// The variant order *is* the permission order, and `Ord` is derived from it, so gate checks are
/// comparisons (`level >= VisualLevel::Takeover`) rather than match arms that must each be got
/// right. Deny-by-default falls out of `Default` being the restricted-but-useful middle
/// (Constitution I).
///
/// This axis is independent of color (`NO_COLOR`) and of motion ([`VisualConfig::animations`]).
/// In particular it governs the *agent*, never bee's own chrome: at [`VisualLevel::None`] the
/// harness still animates its own UI (FR-006d).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VisualLevel {
    /// No panels, no overlays. `render` output flows inline in chat only.
    None,
    /// Side panels, capped at a third of the width. The default.
    #[default]
    Panels,
    /// Panels may grow to half the width.
    PanelsWide,
    /// Full-screen overlays are permitted, in addition to panels.
    Takeover,
}

impl VisualLevel {
    /// Parse a configured value. Unknown input is a **hard error**, never a fallback to the default:
    /// a policy that cannot be compiled is refused rather than silently weakened (Constitution I).
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "none" => Ok(Self::None),
            "panels" => Ok(Self::Panels),
            "panels-wide" => Ok(Self::PanelsWide),
            "takeover" => Ok(Self::Takeover),
            other => Err(ConfigError::Invalid(format!(
                "unknown visual_level {other:?} (want one of: none, panels, panels-wide, takeover)"
            ))),
        }
    }

    /// The canonical configured spelling — the inverse of [`Self::parse`], for banners and notes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Panels => "panels",
            Self::PanelsWide => "panels-wide",
            Self::Takeover => "takeover",
        }
    }

    /// Whether a full-screen overlay is permitted at this level (FR-013).
    pub fn allows_takeover(self) -> bool {
        self >= VisualLevel::Takeover
    }

    /// Whether named panels are permitted at this level.
    pub fn allows_panels(self) -> bool {
        self >= VisualLevel::Panels
    }

    /// The panel width cap as a fraction of the terminal width, as `(numerator, denominator)`
    /// (FR-011, FR-012). `None` at [`VisualLevel::None`], where no panel is drawn at all.
    pub fn panel_width_fraction(self) -> Option<(u16, u16)> {
        match self {
            Self::None => None,
            Self::Panels => Some((1, 3)),
            Self::PanelsWide | Self::Takeover => Some((1, 2)),
        }
    }
}

/// Default takeover lifetime in seconds (FR-017): long enough to read a visualization, short enough
/// not to be annoying. The operator can always dismiss earlier.
pub const DEFAULT_TAKEOVER_TTL_SECS: u32 = 30;
/// Hard ceiling on the configured takeover lifetime (FR-017). Above this a config is a mistake worth
/// surfacing rather than clamping — unlike an *agent* request, which clamps silently (FR-021).
pub const MAX_TAKEOVER_TTL_SECS: u32 = 120;

/// The `[harness]` table of a scenario file — the declarative half of the visual configuration
/// (Constitution IV: policy-as-data, reviewable in a diff).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HarnessSection {
    #[serde(default)]
    pub visual_level: Option<String>,
    /// `false` disables all motion — agent effects *and* harness chrome (FR-006a).
    #[serde(default)]
    pub animations: Option<bool>,
    #[serde(default)]
    pub takeover_ttl_secs: Option<u32>,
}

/// The three resolved presentation axes (009). They are independent and compose freely: a session
/// may have full color, full takeover rights, and zero motion (contracts/motion-control.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisualConfig {
    /// How much screen the agent may claim.
    pub level: VisualLevel,
    /// Whether anything animates at all. `false` makes every effect an instant no-op and keeps the
    /// render loop out of its 60fps state entirely (FR-006b/c).
    pub animations: bool,
    /// Resolved takeover lifetime; a hard cap on what a script may request (FR-021).
    pub takeover_ttl_secs: u32,
}

impl Default for VisualConfig {
    fn default() -> Self {
        VisualConfig {
            level: VisualLevel::default(),
            animations: true,
            takeover_ttl_secs: DEFAULT_TAKEOVER_TTL_SECS,
        }
    }
}

impl VisualConfig {
    /// Resolve all three axes with **CLI > env > scenario > default** precedence (FR-008, FR-006a).
    ///
    /// `cli_level` is `--visual-level`; `cli_no_animation` is the `--no-animation` flag (a flag, so
    /// it can only turn motion *off*, never back on). Env reads `BEE_VISUAL_LEVEL` and
    /// `BEE_NO_ANIMATION`; the latter is presence-is-truth like `NO_COLOR`
    /// (`viz::palette::is_color_enabled`), so `BEE_NO_ANIMATION=0` still disables. Surprising in
    /// isolation, but consistent with the convention bee already implements.
    pub fn resolve(
        cli_level: Option<&str>,
        cli_no_animation: bool,
        scenario: Option<&HarnessSection>,
    ) -> Result<Self, ConfigError> {
        let env_level = std::env::var("BEE_VISUAL_LEVEL").ok();
        Self::resolve_with(
            cli_level,
            cli_no_animation,
            env_level.as_deref(),
            std::env::var_os("BEE_NO_ANIMATION").is_some(),
            scenario,
        )
    }

    /// The pure core of [`Self::resolve`], with the environment passed in rather than read.
    ///
    /// Precedence and fail-closed behavior are the parts worth testing, and testing them through
    /// the real environment would mean mutating process-global state from parallel test threads.
    /// Injecting it keeps those tests deterministic and keeps `set_var` (unsafe in recent editions)
    /// out of the crate entirely.
    pub fn resolve_with(
        cli_level: Option<&str>,
        cli_no_animation: bool,
        env_level: Option<&str>,
        env_no_animation: bool,
        scenario: Option<&HarnessSection>,
    ) -> Result<Self, ConfigError> {
        let level = match (
            cli_level,
            env_level,
            scenario.and_then(|h| h.visual_level.as_deref()),
        ) {
            (Some(s), _, _) | (None, Some(s), _) | (None, None, Some(s)) => VisualLevel::parse(s)?,
            (None, None, None) => VisualLevel::default(),
        };

        // Motion is off if *any* source says so: the CLI flag, the env var's presence, or an
        // explicit `animations = false`. Accessibility settings should be sticky — a scenario must
        // not be able to switch motion back on for an operator who asked for a still screen.
        let animations = !cli_no_animation
            && !env_no_animation
            && scenario.and_then(|h| h.animations).unwrap_or(true);

        let takeover_ttl_secs = scenario
            .and_then(|h| h.takeover_ttl_secs)
            .unwrap_or(DEFAULT_TAKEOVER_TTL_SECS);
        if takeover_ttl_secs == 0 || takeover_ttl_secs > MAX_TAKEOVER_TTL_SECS {
            return Err(ConfigError::Invalid(format!(
                "takeover_ttl_secs must be 1..={MAX_TAKEOVER_TTL_SECS} (got {takeover_ttl_secs})"
            )));
        }

        Ok(VisualConfig {
            level,
            animations,
            takeover_ttl_secs,
        })
    }

    /// Clamp a script-requested takeover lifetime to the configured maximum (FR-021). A shorter
    /// request is honored as given; a longer one is clamped down rather than refused.
    pub fn clamp_takeover_ttl(&self, requested_ms: Option<u64>) -> std::time::Duration {
        let max_ms = u64::from(self.takeover_ttl_secs) * 1000;
        std::time::Duration::from_millis(requested_ms.map_or(max_ms, |ms| ms.min(max_ms)))
    }
}

#[cfg(test)]
mod visual_tests {
    use super::*;

    fn section(level: Option<&str>, animations: Option<bool>, ttl: Option<u32>) -> HarnessSection {
        HarnessSection {
            visual_level: level.map(str::to_string),
            animations,
            takeover_ttl_secs: ttl,
        }
    }

    fn resolve(
        cli: Option<&str>,
        cli_no_anim: bool,
        env: Option<&str>,
        env_no_anim: bool,
        s: Option<&HarnessSection>,
    ) -> Result<VisualConfig, ConfigError> {
        VisualConfig::resolve_with(cli, cli_no_anim, env, env_no_anim, s)
    }

    #[test]
    fn defaults_are_panels_animated_and_thirty_seconds() {
        let c = resolve(None, false, None, false, None).expect("defaults resolve");
        assert_eq!(
            c.level,
            VisualLevel::Panels,
            "default is the restricted tier"
        );
        assert!(c.animations);
        assert_eq!(c.takeover_ttl_secs, DEFAULT_TAKEOVER_TTL_SECS);
    }

    #[test]
    fn level_precedence_is_cli_then_env_then_scenario() {
        let s = section(Some("none"), None, None);
        // Scenario alone.
        assert_eq!(
            resolve(None, false, None, false, Some(&s)).unwrap().level,
            VisualLevel::None
        );
        // Env beats scenario.
        assert_eq!(
            resolve(None, false, Some("panels-wide"), false, Some(&s))
                .unwrap()
                .level,
            VisualLevel::PanelsWide
        );
        // CLI beats both.
        assert_eq!(
            resolve(
                Some("takeover"),
                false,
                Some("panels-wide"),
                false,
                Some(&s)
            )
            .unwrap()
            .level,
            VisualLevel::Takeover
        );
    }

    #[test]
    fn an_unknown_level_is_a_hard_error_not_a_fallback() {
        // Constitution I: a policy that cannot be compiled is refused, never silently weakened to
        // the default — and never silently falls through to the next source.
        for src in [
            resolve(Some("bogus"), false, None, false, None),
            resolve(None, false, Some("bogus"), false, None),
            resolve(
                None,
                false,
                None,
                false,
                Some(&section(Some("bogus"), None, None)),
            ),
        ] {
            let err = src.expect_err("unknown level must error");
            assert!(
                err.to_string().contains("unknown visual_level"),
                "unhelpful error: {err}"
            );
        }
    }

    #[test]
    fn motion_is_off_if_any_source_says_so_and_a_scenario_cannot_switch_it_back_on() {
        assert!(
            !resolve(None, true, None, false, None).unwrap().animations,
            "CLI flag"
        );
        assert!(
            !resolve(None, false, None, true, None).unwrap().animations,
            "env var"
        );
        assert!(
            !resolve(
                None,
                false,
                None,
                false,
                Some(&section(None, Some(false), None))
            )
            .unwrap()
            .animations,
            "scenario"
        );
        // An operator who asked for a still screen keeps it, whatever the scenario wants.
        let loud = section(None, Some(true), None);
        assert!(
            !resolve(None, true, None, false, Some(&loud))
                .unwrap()
                .animations
        );
        assert!(
            !resolve(None, false, None, true, Some(&loud))
                .unwrap()
                .animations
        );
    }

    #[test]
    fn motion_is_independent_of_level() {
        // FR-006d: visual_level = "none" restricts the *agent*; it does not silence motion, which
        // is the only switch that reaches harness chrome.
        let c = resolve(
            None,
            false,
            None,
            false,
            Some(&section(Some("none"), None, None)),
        )
        .unwrap();
        assert_eq!(c.level, VisualLevel::None);
        assert!(c.animations, "level none must not imply motion off");
        // And the converse: motion off leaves takeover rights intact.
        let c = resolve(Some("takeover"), true, None, false, None).unwrap();
        assert!(c.level.allows_takeover());
        assert!(!c.animations);
    }

    #[test]
    fn an_out_of_range_configured_ttl_is_a_hard_error() {
        // A config asking for 600s is a mistake worth surfacing (unlike an agent request, which
        // clamps silently — see `clamp_takeover_ttl`).
        let err = resolve(
            None,
            false,
            None,
            false,
            Some(&section(None, None, Some(600))),
        )
        .expect_err("600s must error");
        assert!(err.to_string().contains("takeover_ttl_secs"), "got {err}");
        assert!(resolve(
            None,
            false,
            None,
            false,
            Some(&section(None, None, Some(0)))
        )
        .is_err());
        assert_eq!(
            resolve(
                None,
                false,
                None,
                false,
                Some(&section(None, None, Some(120)))
            )
            .unwrap()
            .takeover_ttl_secs,
            MAX_TAKEOVER_TTL_SECS,
            "the maximum itself is allowed"
        );
    }

    #[test]
    fn agent_requested_ttl_clamps_down_but_honors_shorter() {
        let c = resolve(
            None,
            false,
            None,
            false,
            Some(&section(None, None, Some(20))),
        )
        .unwrap();
        assert_eq!(
            c.clamp_takeover_ttl(Some(90_000)).as_secs(),
            20,
            "clamped down"
        );
        assert_eq!(
            c.clamp_takeover_ttl(Some(5_000)).as_millis(),
            5_000,
            "shorter honored"
        );
        assert_eq!(
            c.clamp_takeover_ttl(None).as_secs(),
            20,
            "default is the cap"
        );
    }

    #[test]
    fn the_tiers_are_ordered_so_gate_checks_are_comparisons() {
        assert!(VisualLevel::None < VisualLevel::Panels);
        assert!(VisualLevel::Panels < VisualLevel::PanelsWide);
        assert!(VisualLevel::PanelsWide < VisualLevel::Takeover);
        // Levels are a ceiling, not a mode: takeover still allows panels.
        assert!(VisualLevel::Takeover.allows_panels());
        assert!(VisualLevel::Takeover.allows_takeover());
        assert!(VisualLevel::PanelsWide.allows_panels());
        assert!(!VisualLevel::PanelsWide.allows_takeover());
        assert!(!VisualLevel::None.allows_panels());
    }

    #[test]
    fn width_fractions_match_the_tier_table() {
        assert_eq!(VisualLevel::None.panel_width_fraction(), None);
        assert_eq!(VisualLevel::Panels.panel_width_fraction(), Some((1, 3)));
        assert_eq!(VisualLevel::PanelsWide.panel_width_fraction(), Some((1, 2)));
        assert_eq!(VisualLevel::Takeover.panel_width_fraction(), Some((1, 2)));
    }

    #[test]
    fn the_harness_section_parses_from_scenario_toml() {
        // Policy-as-data (Constitution IV): the axes are declarative and diff-reviewable.
        let s: HarnessSection = toml::from_str(
            r#"
            visual_level = "takeover"
            animations = false
            takeover_ttl_secs = 15
            "#,
        )
        .expect("parse [harness]");
        let c = resolve(None, false, None, false, Some(&s)).unwrap();
        assert_eq!(c.level, VisualLevel::Takeover);
        assert!(!c.animations);
        assert_eq!(c.takeover_ttl_secs, 15);
    }
}
