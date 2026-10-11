//! Effective configuration: one resolution, shared by every session command (ADR-0001).
//!
//! Bee resolves four sources, highest precedence first — explicit flags, an explicitly supplied
//! `--config` file, project configuration, user configuration — into one [`EffectiveConfig`], or
//! into a list of what is missing and where it could be supplied. Precedence is applied **per
//! field**, not per file, so a project file that sets only the tool list does not discard the user
//! file's theme.
//!
//! Two properties matter more than the mechanics:
//!
//! * **Project configuration is untrusted.** Fields that name a credential-bearing variable or set
//!   the bound everything else is checked against are operator-only, rejected outright in a project
//!   file rather than quietly dropped ([`file::FileConfig::user_only_sections`]).
//! * **A requested policy is attenuated, not trusted.** It is derived against the ceiling with
//!   `bee_core::Policy::derive` — the same validator behind subagent policies and skill capability
//!   grants — so an over-grant produces that validator's error rather than a second, differently
//!   worded refusal.
//!
//! [`resolve_from_layers`] is the pure core, with the discovered files passed in. That split is the
//! same one `VisualConfig::resolve_with` makes in the harness, and for the same reason: it keeps
//! the precedence tests off process-global state.

// Nothing calls the resolver yet: `bee run` and `bee repl` are wired onto it in consolidation
// issues 03 and 04, and the completeness rules it feeds land in issue 05. Until then every entry
// point here is dead to the compiler. The allow is temporary and comes off with issue 05 — if it is
// still here after that, something never got wired up.
#![allow(dead_code)]

pub mod file;

use std::path::{Path, PathBuf};

use bee::config::{HarnessSection, VisualConfig};
use bee::viz::theme::Theme;
use bee::ProviderConfig;
use bee_core::Policy;

use file::{Layer, LoadError, Origin};

/// Tools an agent gets when nothing configures otherwise. Matches what `bee-repl` has shipped:
/// `render` is included so the agent can draw in the terminal, `search` for ripgrep over the scope.
pub const DEFAULT_TOOLS: &[&str] = &[
    "bash",
    "read_file",
    "write_file",
    "list_directory",
    "search",
    "render",
];
/// Max model calls per user message — a safety cap against a runaway agent.
pub const DEFAULT_BUDGET: u32 = 25;
/// Max tool-call rounds for a headless episode.
pub const DEFAULT_TURN_LIMIT: u32 = 8;
/// Wall-clock cap for a headless episode.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// What the operator typed. Every field is the highest-precedence source for its axis.
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub config: Option<PathBuf>,
    pub provider: Option<PathBuf>,
    pub policy: Option<PathBuf>,
    pub ceiling_policy: Option<PathBuf>,
    pub mcp_config: Option<PathBuf>,
    /// Comma-separated, as the flag has always been.
    pub tools: Option<String>,
    pub system: Option<String>,
    pub budget: Option<u32>,
    pub turn_limit: Option<u32>,
    pub timeout_secs: Option<u64>,
    pub theme: Option<String>,
    pub visual_level: Option<String>,
    /// A flag, so it can only turn motion off, never back on.
    pub no_animation: bool,
}

/// The validated, complete result of resolving operator intent, user configuration, and project
/// configuration. Never grants authority beyond the user configuration: `policy` is already
/// attenuated against `ceiling`.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub provider: ProviderConfig,
    pub provider_path: PathBuf,
    /// The session's policy, already derived against the ceiling.
    pub policy: Option<Policy>,
    pub policy_path: Option<PathBuf>,
    pub ceiling: Option<Policy>,
    pub ceiling_path: Option<PathBuf>,
    pub mcp_config: Option<PathBuf>,
    pub tools: Vec<String>,
    pub system: Option<String>,
    pub budget: u32,
    pub turn_limit: u32,
    pub timeout_secs: u64,
    pub theme: Theme,
    /// An unknown theme name warns and falls back rather than failing — theming is decoration
    /// (FR-052). Contrast `visual`, where an unknown value is a hard error because the level is a
    /// ceiling and falling back could widen it.
    pub theme_warning: Option<String>,
    pub visual: VisualConfig,
    /// Security tooling configuration (016-native-tools): the ledger location and per-scanner
    /// settings. Paths are already resolved against the file that declared them.
    pub security: file::SecuritySection,
    /// `[context]` from every layer, merged key by key (025). Validated when a session starts, against
    /// the model's window.
    pub context: file::ContextSection,
}

/// One thing bee needs and does not have, with the places it could come from.
#[derive(Debug, Clone)]
pub struct MissingRequirement {
    pub what: &'static str,
    pub supply: Vec<String>,
}

impl std::fmt::Display for MissingRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.what)?;
        for place in &self.supply {
            write!(f, "\n      {place}")?;
        }
        Ok(())
    }
}

/// Why resolution failed. Every variant is a refusal *before* a provider is contacted or a tool
/// runs — that ordering is the point of ADR-0001.
#[derive(Debug)]
pub enum ResolveError {
    Load(LoadError),
    Provider { path: PathBuf, detail: String },
    Policy { path: PathBuf, detail: String },
    Attenuation(String),
    Visual(String),
    Incomplete(Vec<MissingRequirement>),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Load(e) => write!(f, "{e}"),
            ResolveError::Provider { path, detail } => {
                write!(f, "provider {}: {detail}", path.display())
            }
            ResolveError::Policy { path, detail } => {
                write!(f, "policy {}: {detail}", path.display())
            }
            ResolveError::Attenuation(detail) => write!(
                f,
                "refusing to run: the requested policy exceeds the ceiling: {detail}"
            ),
            ResolveError::Visual(detail) => write!(f, "{detail}"),
            ResolveError::Incomplete(missing) => {
                write!(f, "incomplete configuration:")?;
                for m in missing {
                    write!(f, "\n  - {m}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ResolveError {}

impl From<LoadError> for ResolveError {
    fn from(e: LoadError) -> Self {
        ResolveError::Load(e)
    }
}

/// A path plus the layer it was written in, so it can be resolved relative to that file.
type Sourced = (PathBuf, Origin);

/// The merged-but-not-yet-validated view of every layer plus the flags.
#[derive(Debug, Default)]
struct Merged {
    provider: Option<Sourced>,
    policy: Option<Sourced>,
    ceiling: Option<Sourced>,
    mcp_config: Option<Sourced>,
    tools: Option<Vec<String>>,
    system: Option<String>,
    budget: Option<u32>,
    turn_limit: Option<u32>,
    timeout_secs: Option<u64>,
    theme: Option<file::ThemeConfig>,
    visual_level: Option<String>,
    animations: Option<bool>,
    security: Option<file::SecuritySection>,
    context: file::ContextSection,
}

impl Merged {
    /// Fold the layers in ascending precedence, then the flags on top. Each `Some` overwrites; each
    /// `None` leaves the lower layer's value standing, which is what makes precedence per-field.
    fn build(layers: &[Layer], flags: &Flags) -> Self {
        let mut m = Merged::default();
        for layer in layers {
            let c = &layer.config;
            if let Some(p) = &c.provider {
                m.provider = Some((layer.resolve_path(&p.path), layer.origin));
            }
            if let Some(p) = &c.policy {
                if let Some(path) = &p.path {
                    m.policy = Some((layer.resolve_path(path), layer.origin));
                }
                if let Some(path) = &p.ceiling {
                    m.ceiling = Some((layer.resolve_path(path), layer.origin));
                }
            }
            if let Some(s) = &c.session {
                if let Some(v) = &s.tools {
                    m.tools = Some(v.clone());
                }
                if let Some(v) = &s.system {
                    m.system = Some(v.clone());
                }
                if let Some(v) = s.budget {
                    m.budget = Some(v);
                }
                if let Some(v) = s.turn_limit {
                    m.turn_limit = Some(v);
                }
                if let Some(v) = s.timeout_secs {
                    m.timeout_secs = Some(v);
                }
            }
            if let Some(v) = &c.visual {
                if let Some(l) = &v.level {
                    m.visual_level = Some(l.clone());
                }
                if let Some(a) = v.animations {
                    m.animations = Some(a);
                }
            }
            if let Some(mcp) = &c.mcp {
                m.mcp_config = Some((layer.resolve_path(&mcp.config), layer.origin));
            }
            if let Some(t) = &c.theme {
                m.theme = Some(t.clone());
            }
            if let Some(s) = &c.security {
                // Resolve every path against the file that wrote it, as the other sections do: a
                // ruleset written in the user config means the same thing regardless of which
                // directory bee was invoked from.
                let mut s = s.clone();
                s.findings_dir = s.findings_dir.as_ref().map(|p| layer.resolve_path(p));
                for scanner in s.scanners.values_mut() {
                    scanner.rules = scanner.rules.as_ref().map(|p| layer.resolve_path(p));
                    scanner.bundle = scanner.bundle.as_ref().map(|p| layer.resolve_path(p));
                }
                m.security = Some(s);
            }
            if let Some(c) = c.context {
                m.context = m.context.merge(c);
            }
        }

        // Flags win over every file. Their paths are relative to the working directory, which is
        // where the operator typed them, so they are taken as written.
        if let Some(p) = &flags.provider {
            m.provider = Some((p.clone(), Origin::Explicit));
        }
        if let Some(p) = &flags.policy {
            m.policy = Some((p.clone(), Origin::Explicit));
        }
        if let Some(p) = &flags.ceiling_policy {
            m.ceiling = Some((p.clone(), Origin::Explicit));
        }
        if let Some(p) = &flags.mcp_config {
            m.mcp_config = Some((p.clone(), Origin::Explicit));
        }
        if let Some(t) = &flags.tools {
            m.tools = Some(split_list(t));
        }
        if let Some(s) = &flags.system {
            m.system = Some(s.clone());
        }
        if let Some(v) = flags.budget {
            m.budget = Some(v);
        }
        if let Some(v) = flags.turn_limit {
            m.turn_limit = Some(v);
        }
        if let Some(v) = flags.timeout_secs {
            m.timeout_secs = Some(v);
        }
        m
    }
}

/// Split a comma-separated flag value, dropping empties — the shape every tool list flag has used.
fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Discover the configuration files and resolve them with the flags.
pub fn resolve(cwd: &Path, flags: &Flags) -> Result<EffectiveConfig, ResolveError> {
    let layers = file::discover(cwd, flags.config.as_deref())?;
    resolve_from_layers(&layers, flags)
}

/// Resolve only the presentation axes — theme and visual level — without requiring a provider.
///
/// For commands that have no single session to configure but still have to install the theme and
/// the visual gate: a batch, which carries its own provider per pair, and the reporting commands.
/// Splitting it out means those commands do not have to invent a provider they will never use.
pub fn resolve_presentation(
    cwd: &Path,
    flags: &Flags,
) -> Result<(Theme, Option<String>, VisualConfig), ResolveError> {
    let layers = file::discover(cwd, flags.config.as_deref())?;
    let m = Merged::build(&layers, flags);
    let (theme, warning) = resolve_theme(flags, &m);
    let visual = resolve_visual(flags, &m)?;
    Ok((theme, warning, visual))
}

/// Theme: flag > `BEE_THEME` > file. An unknown name warns and falls back — theming is decoration
/// (FR-052).
fn resolve_theme(flags: &Flags, m: &Merged) -> (Theme, Option<String>) {
    bee::viz::theme::resolve(
        flags.theme.as_deref(),
        std::env::var("BEE_THEME").ok().as_deref(),
        m.theme.as_ref(),
    )
}

/// Visual: flag > `BEE_VISUAL_LEVEL` > file, through the harness's own resolver so the
/// motion-stickiness rule — any source may turn motion off, none may turn it back on — is the one
/// already tested there. An unknown level is a hard error: this is a ceiling, and falling back
/// could widen it.
fn resolve_visual(flags: &Flags, m: &Merged) -> Result<VisualConfig, ResolveError> {
    let section = HarnessSection {
        visual_level: m.visual_level.clone(),
        animations: m.animations,
        takeover_ttl_secs: None,
    };
    VisualConfig::resolve(
        flags.visual_level.as_deref(),
        flags.no_animation,
        Some(&section),
    )
    .map_err(|e| ResolveError::Visual(e.to_string()))
}

/// The pure core: resolve already-discovered layers against the flags.
pub fn resolve_from_layers(
    layers: &[Layer],
    flags: &Flags,
) -> Result<EffectiveConfig, ResolveError> {
    let m = Merged::build(layers, flags);

    // Completeness first. Reporting "no provider" beats reporting a parse error in a policy the
    // session was never going to reach.
    let Some((provider_path, _)) = m.provider.clone() else {
        return Err(ResolveError::Incomplete(vec![MissingRequirement {
            what: "a provider — which model or endpoint the session talks to",
            supply: vec![
                "supply it with --provider <FILE>".to_string(),
                format!("or `[provider] path` in {}", Origin::User.describe()),
                format!("or `[provider] path` in {}", Origin::Explicit.describe()),
            ],
        }]));
    };

    let provider =
        ProviderConfig::from_path(&provider_path).map_err(|e| ResolveError::Provider {
            path: provider_path.clone(),
            detail: e.to_string(),
        })?;

    let ceiling = load_policy(m.ceiling.as_ref())?;
    let requested = load_policy(m.policy.as_ref())?;

    // Attenuate: a requested policy is a *request*, bounded by the ceiling. With no ceiling
    // configured there is nothing to bound it against and it stands as written.
    let policy = match (ceiling.clone(), requested) {
        (Some(ceiling), Some(requested)) => Some(
            ceiling
                .derive(requested)
                .map_err(|e| ResolveError::Attenuation(e.to_string()))?,
        ),
        (None, Some(requested)) => Some(requested),
        (Some(_), None) => None,
        (None, None) => None,
    };

    let (theme, theme_warning) = resolve_theme(flags, &m);
    let visual = resolve_visual(flags, &m)?;

    Ok(EffectiveConfig {
        provider,
        provider_path,
        policy,
        policy_path: m.policy.map(|(p, _)| p),
        ceiling,
        ceiling_path: m.ceiling.map(|(p, _)| p),
        mcp_config: m.mcp_config.map(|(p, _)| p),
        tools: m
            .tools
            .unwrap_or_else(|| DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect()),
        system: m.system,
        budget: m.budget.unwrap_or(DEFAULT_BUDGET).max(1),
        turn_limit: m.turn_limit.unwrap_or(DEFAULT_TURN_LIMIT).max(1),
        timeout_secs: m.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1),
        theme,
        theme_warning,
        visual,
        security: m.security.unwrap_or_default(),
        context: m.context,
    })
}

fn load_policy(sourced: Option<&Sourced>) -> Result<Option<Policy>, ResolveError> {
    let Some((path, _)) = sourced else {
        return Ok(None);
    };
    Policy::from_path(path)
        .map(Some)
        .map_err(|e| ResolveError::Policy {
            path: path.clone(),
            detail: e.to_string(),
        })
}

#[cfg(test)]
mod tests;
