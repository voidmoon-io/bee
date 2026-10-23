//! The configuration file schema and its discovery (ADR-0001, consolidation issue 02).
//!
//! One schema, read from up to three places: user configuration at `~/.config/bee/config.toml`,
//! project configuration at `.bee/config.toml`, and whatever `--config` names. Every field is
//! optional, because a file that supplies one thing must not be obliged to supply the rest — that
//! is what makes configuration files *inputs* rather than requirements.
//!
//! Paths inside a file resolve relative to **that file's** directory, not the working directory. A
//! project config saying `path = "policies/dev.toml"` means the one in the project, wherever bee
//! was invoked from.

use std::path::{Path, PathBuf};

use serde::Deserialize;

pub use bee::viz::theme::ThemeConfig;

/// Which layer a value came from. Carried on every loaded file so precedence, trust, and
/// missing-requirement reporting can all name a real place rather than "somewhere".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `~/.config/bee/config.toml` — operator-owned, trusted, establishes the ceiling.
    User,
    /// `.bee/config.toml` — repository-local, untrusted when the repository is.
    Project,
    /// An explicitly supplied `--config` file. Trusted: the operator named it on the command line.
    Explicit,
}

impl Origin {
    /// How to describe this layer in an error the operator has to act on.
    pub fn describe(self) -> &'static str {
        match self {
            Origin::User => "user configuration (~/.config/bee/config.toml)",
            Origin::Project => "project configuration (.bee/config.toml)",
            Origin::Explicit => "the --config file",
        }
    }

    /// Whether this layer may set fields reserved to the operator. Project configuration may not:
    /// it is untrusted input when the repository is untrusted.
    pub fn is_trusted(self) -> bool {
        !matches!(self, Origin::Project)
    }
}

/// The root of a bee configuration file.
///
/// `deny_unknown_fields` on purpose: a mistyped section that silently does nothing is the worst
/// outcome for a file that governs what an agent is allowed to do.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Which model the session talks to. **Operator-only** — see [`FileConfig::user_only_sections`].
    #[serde(default)]
    pub provider: Option<ProviderSection>,
    #[serde(default)]
    pub policy: Option<PolicySection>,
    #[serde(default)]
    pub session: Option<SessionSection>,
    #[serde(default)]
    pub visual: Option<VisualSection>,
    /// MCP servers. **Operator-only** — see [`FileConfig::user_only_sections`].
    #[serde(default)]
    pub mcp: Option<McpSection>,
    /// The `[theme]` section bee has read from the user config since 005-themes. Unchanged, and
    /// deliberately still parsed by the same type, so an existing config file keeps working.
    #[serde(default)]
    pub theme: Option<ThemeConfig>,
    /// Security tooling (016-native-tools). **Operator-only** — see
    /// [`FileConfig::user_only_sections`].
    #[serde(default)]
    pub security: Option<SecuritySection>,
    /// The context budget and compaction (025). Not operator-only: a project may tune its own budget,
    /// and nothing here widens what the agent may do.
    #[serde(default)]
    pub context: Option<ContextSection>,
    /// Stuck detection (025 US2). Not operator-only, for the reason `[context]` is not: it can only
    /// end a run sooner or remind the model, never widen what it may do.
    #[serde(default)]
    pub stuck: Option<StuckSection>,
}

/// The `[context]` table (025 contracts/config.md). The shape lives in the library, which also reads
/// it from a scenario file; every key is optional, and layers merge key by key.
pub use bee::context::ContextConfig as ContextSection;

/// The `[stuck]` table (025 contracts/config.md), shared with scenario files like `[context]`.
pub use bee::stuck::StuckConfig as StuckSection;

/// The `[security]` table — where findings are recorded and how a granted scanner is configured.
///
/// The shape lives in the library ([`bee::security`]) because the episode path needs it too, and
/// duplicating it here would let the two drift. What this layer adds is *trust*: the section is
/// **operator-only**, for the same reason `[policy] ceiling` is. A scanner's ruleset decides what a
/// granted third-party binary does with the access it was given, and its timeout decides how long it
/// holds that access. A repository that could set either would be configuring a capability the
/// operator granted it — the wrong actor answering the question.
pub use bee::security::SecurityConfig as SecuritySection;

/// Where the provider TOML lives (the file naming the model, endpoint, and key variable).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSection {
    pub path: PathBuf,
}

/// The session's policy, and the ceiling any request is bounded by.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    /// The policy for the session's scope. Requestable: a project may propose one, and it is
    /// resolved against the ceiling rather than taken at face value.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// The capability ceiling. **Operator-only** — a repository that could raise its own ceiling
    /// would not have one.
    #[serde(default)]
    pub ceiling: Option<PathBuf>,
}

/// Session shape: what the agent gets and how long it may run.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSection {
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    #[serde(default)]
    pub system: Option<String>,
    /// Max model calls per user message (interactive sessions).
    #[serde(default)]
    pub budget: Option<u32>,
    /// Max tool-call rounds (headless sessions).
    #[serde(default)]
    pub turn_limit: Option<u32>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// How much screen the agent may claim, and whether anything moves.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisualSection {
    /// `none` | `panels` | `panels-wide` | `takeover`. Kept as a string here and parsed during
    /// resolution so an unknown value is one hard error in one place, never a silent default —
    /// this is a ceiling, and falling back could widen it.
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub animations: Option<bool>,
}

/// Where the MCP configuration TOML lives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSection {
    pub config: PathBuf,
}

impl FileConfig {
    /// The sections only a trusted layer may set, with the reason each is reserved. Every one of
    /// them either names a credential-bearing environment variable or sets the bound that the rest
    /// of the configuration is checked against — neither is a thing an untrusted repository gets a
    /// say in.
    pub fn user_only_sections(&self) -> Vec<(&'static str, &'static str)> {
        let mut found = Vec::new();
        if self.provider.is_some() {
            found.push((
                "[provider]",
                "it names the model, endpoint, and key variable the session talks to",
            ));
        }
        if self.policy.as_ref().is_some_and(|p| p.ceiling.is_some()) {
            found.push((
                "[policy] ceiling",
                "a repository that could raise its own ceiling would not have one",
            ));
        }
        if self.mcp.is_some() {
            found.push((
                "[mcp]",
                "MCP servers are launched with named credential variables",
            ));
        }
        if self.security.is_some() {
            found.push((
                "[security]",
                "it configures what a granted scanner does with the access the operator gave it",
            ));
        }
        found
    }
}

/// One discovered, parsed configuration file.
#[derive(Debug, Clone)]
pub struct Layer {
    pub origin: Origin,
    /// The file this came from — the base for resolving relative paths inside it.
    pub path: PathBuf,
    pub config: FileConfig,
}

impl Layer {
    /// Resolve a path written in this file against the file's own directory.
    pub fn resolve_path(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            return p.to_path_buf();
        }
        match self.path.parent() {
            Some(dir) => dir.join(p),
            None => p.to_path_buf(),
        }
    }
}

/// Failures from reading configuration. A missing file is not one of them — absence is the normal
/// case, and [`load`] reports it as `Ok(None)`.
#[derive(Debug)]
pub enum LoadError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// A layer set a field reserved to the operator.
    Untrusted {
        path: PathBuf,
        origin: Origin,
        field: &'static str,
        why: &'static str,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            LoadError::Parse { path, source } => {
                write!(f, "cannot parse {}: {source}", path.display())
            }
            LoadError::Untrusted {
                path,
                origin,
                field,
                why,
            } => write!(
                f,
                "{} may not set {field}: {why}\n  found in {}\n  set it in user configuration \
                 (~/.config/bee/config.toml) or on the command line instead",
                origin.describe(),
                path.display()
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Read and validate one configuration file. `Ok(None)` when the file is simply not there.
pub fn load(path: &Path, origin: Origin) -> Result<Option<Layer>, LoadError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(LoadError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let config: FileConfig = toml::from_str(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    if !origin.is_trusted() {
        if let Some((field, why)) = config.user_only_sections().first() {
            return Err(LoadError::Untrusted {
                path: path.to_path_buf(),
                origin,
                field,
                why,
            });
        }
    }

    Ok(Some(Layer {
        origin,
        path: path.to_path_buf(),
        config,
    }))
}

/// Where project configuration lives, relative to a working directory.
pub fn project_config_path(cwd: &Path) -> PathBuf {
    cwd.join(".bee").join("config.toml")
}

/// Discover the layers, lowest precedence first: user, then project, then any `--config` file.
///
/// The user path comes from `bee::viz::theme::config_path` — the same function that has
/// located this file since 005-themes, so there is exactly one definition of where user
/// configuration lives.
pub fn discover(cwd: &Path, explicit: Option<&Path>) -> Result<Vec<Layer>, LoadError> {
    let mut layers = Vec::new();

    if let Some(user) = bee::viz::theme::config_path() {
        if let Some(layer) = load(&user, Origin::User)? {
            layers.push(layer);
        }
    }
    if let Some(layer) = load(&project_config_path(cwd), Origin::Project)? {
        layers.push(layer);
    }
    if let Some(explicit) = explicit {
        // An explicitly named file that is not there is an error, unlike the discovered ones: the
        // operator asked for it by name.
        match load(explicit, Origin::Explicit)? {
            Some(layer) => layers.push(layer),
            None => {
                return Err(LoadError::Read {
                    path: explicit.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no such configuration file",
                    ),
                })
            }
        }
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_theme_only_config_still_parses() {
        // The compatibility case that matters: this is the only bee config file anyone has today.
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "config.toml",
            "[theme]\nname = \"dracula\"\naccent = \"#ff79c6\"\n",
        );
        let layer = load(&path, Origin::User).unwrap().unwrap();
        let theme = layer.config.theme.unwrap();
        assert_eq!(theme.name.as_deref(), Some("dracula"));
        assert_eq!(theme.accent.as_deref(), Some("#ff79c6"));
    }

    #[test]
    fn an_absent_file_is_absence_not_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(load(&missing, Origin::User).unwrap().is_none());
    }

    #[test]
    fn a_malformed_file_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", "[session\ntools = [");
        let err = load(&path, Origin::Project).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("cannot parse"), "{text}");
        assert!(text.contains("config.toml"), "{text}");
    }

    #[test]
    fn an_unknown_section_is_rejected_rather_than_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", "[sesion]\nbudget = 3\n");
        let err = load(&path, Origin::User).unwrap_err();
        assert!(err.to_string().contains("cannot parse"), "{err}");
    }

    #[test]
    fn project_configuration_may_not_set_operator_only_sections() {
        let dir = tempfile::tempdir().unwrap();
        for (body, field) in [
            ("[provider]\npath = \"p.toml\"\n", "[provider]"),
            ("[policy]\nceiling = \"c.toml\"\n", "[policy] ceiling"),
            ("[mcp]\nconfig = \"m.toml\"\n", "[mcp]"),
        ] {
            let path = write(dir.path(), "config.toml", body);
            let err = load(&path, Origin::Project).unwrap_err();
            let text = err.to_string();
            assert!(text.contains(field), "expected {field} named in: {text}");
            assert!(text.contains("project configuration"), "{text}");

            // The same field in a trusted layer is fine.
            assert!(load(&path, Origin::User).unwrap().is_some());
            assert!(load(&path, Origin::Explicit).unwrap().is_some());
        }
    }

    #[test]
    fn project_configuration_may_request_a_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", "[policy]\npath = \"dev.toml\"\n");
        let layer = load(&path, Origin::Project).unwrap().unwrap();
        assert_eq!(
            layer.config.policy.unwrap().path.unwrap(),
            PathBuf::from("dev.toml")
        );
    }

    #[test]
    fn paths_resolve_against_the_files_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "sub/config.toml",
            "[policy]\npath = \"p.toml\"\n",
        );
        let layer = load(&path, Origin::Explicit).unwrap().unwrap();
        assert_eq!(
            layer.resolve_path(Path::new("p.toml")),
            dir.path().join("sub").join("p.toml")
        );
        // Absolute paths are left alone.
        assert_eq!(
            layer.resolve_path(Path::new("/etc/bee.toml")),
            PathBuf::from("/etc/bee.toml")
        );
    }

    #[test]
    fn an_explicitly_named_missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover(dir.path(), Some(&dir.path().join("nope.toml"))).unwrap_err();
        assert!(err.to_string().contains("nope.toml"), "{err}");
    }
}
