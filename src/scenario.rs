//! Scenario definition (contracts/scenario-schema.md): the environment + task an episode runs. A
//! bee policy (feature 001 TOML) confines it; the workdir is materialized before the run.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::tools::{is_known_tool, DEFAULT_TOOLS};

/// Scoring mode. `Ctf` (US3) plants a flag and enables the terminal `submit_flag`/`give_up` tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScoringMode {
    #[default]
    Standard,
    Ctf,
}

/// A file to create in the workdir before the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSpec {
    pub path: PathBuf,
    #[serde(default)]
    pub content: String,
}

/// A planted CTF flag (US3): a sentinel `value` written to `path` before the run. The agent's goal
/// is to read it and `submit_flag` the value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagSpec {
    pub path: PathBuf,
    pub value: String,
}

/// Files/dirs to materialize before the episode, plus an optional planted flag (US3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkdirSetup {
    #[serde(default)]
    pub create_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub create_files: Vec<FileSpec>,
    #[serde(default)]
    pub flag: Option<FlagSpec>,
    /// The directory every materialized path must resolve under.
    ///
    /// **`serde(skip)` is the security property, not a convenience.** These writes happen on the
    /// trusted host, as the launcher (root, under `--features enforce`), *before* any sandbox
    /// exists — so a scenario that could name its own containment root could name `/` and overwrite
    /// anything the launcher can reach. The scenario proposes paths; only the operator says where
    /// they may land, via `--workdir-root`. `None` means a fresh per-episode temp directory.
    #[serde(skip)]
    pub root: Option<PathBuf>,
}

/// A scenario: policy + task + limits + enabled tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    /// bee security policy (feature 001 TOML) compiled for the scope.
    pub policy_path: PathBuf,
    pub system_prompt: String,
    pub task: String,
    /// Max tool-call rounds (FR-007).
    pub turn_limit: u32,
    /// Wall-clock cap in seconds (FR-007).
    pub timeout_secs: u64,
    #[serde(default = "default_tools")]
    pub tools: Vec<String>,
    #[serde(default)]
    pub mode: ScoringMode,
    #[serde(default)]
    pub workdir: WorkdirSetup,
    /// MCP client policy (004-mcp-client). Sourced from the **top-level** `[mcp]` table (a sibling of
    /// `[scenario]`), not `[scenario.mcp]` — see [`Scenario::from_path`]. Defaults to disabled.
    #[serde(default)]
    pub mcp: crate::mcp::McpPolicy,
    /// Skill discovery roots (006-skills), scanned in precedence order (earlier wins). Explicit —
    /// not implicit cwd — so an episode stays reproducible. Empty ⇒ no skills, no `skill` tool.
    /// Relative roots resolve against the scenario file's directory (see [`Scenario::from_path`]).
    #[serde(default)]
    pub skills: Vec<PathBuf>,
    /// Capability ceiling for skill grants (006-skills, step 3). A skill's `requires` block may
    /// widen the base `policy_path` only up to this ceiling; anything beyond it is refused
    /// unpromptably (attenuation, Constitution II/III). This file *is* the operator's reviewable
    /// pre-authorization for a non-interactive run. `None` ⇒ base is the ceiling ⇒ skills grant
    /// nothing (instructions-only). Relative paths resolve against the scenario file's directory.
    #[serde(default)]
    pub ceiling_policy_path: Option<PathBuf>,
    /// Security tooling configuration (016-native-tools). Sourced from the **top-level**
    /// `[security]` table, a sibling of `[scenario]` — the same treatment `[mcp]` gets, and for the
    /// same reason: it configures a subsystem rather than describing the episode. Governs where
    /// findings are recorded and how a granted scanner runs; the grant itself stays in the policy
    /// file, where capabilities live.
    #[serde(default)]
    pub security: crate::security::SecurityConfig,
    /// Context budget and compaction settings (025). Sourced from the **top-level** `[context]` table,
    /// like `[mcp]` and `[security]`, and merged over the user's and project's `[context]`.
    #[serde(default, skip_serializing_if = "is_default_context")]
    pub context: crate::context::ContextConfig,
    /// How many model turns a capability granted mid-episode lasts before it expires and the scope
    /// narrows again (007 US4, 024 FR-029). Absent: a grant lasts for the rest of the episode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_turns: Option<u32>,
}

fn is_default_context(c: &crate::context::ContextConfig) -> bool {
    *c == crate::context::ContextConfig::default()
}

fn default_tools() -> Vec<String> {
    DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect()
}

#[derive(Deserialize)]
struct ScenarioFile {
    scenario: Scenario,
    /// The top-level `[mcp]` table, a sibling of `[scenario]` (research R10). Folded onto
    /// `Scenario::mcp` in [`Scenario::from_path`] so callers see a single `Scenario`.
    #[serde(default)]
    mcp: Option<crate::mcp::McpPolicy>,
    /// The top-level `[security]` table, folded the same way (016-native-tools).
    #[serde(default)]
    security: Option<crate::security::SecurityConfig>,
    /// The top-level `[context]` table (025), folded the same way.
    #[serde(default)]
    context: Option<crate::context::ContextConfig>,
}

impl Scenario {
    /// The wall-clock deadline as a `Duration`.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Load + validate a scenario TOML.
    pub fn from_path(path: &std::path::Path) -> Result<Scenario, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::read(path, e))?;
        let file: ScenarioFile = toml::from_str(&text).map_err(|e| ConfigError::parse(path, e))?;
        let mut s = file.scenario;
        // Fold the top-level `[mcp]` table (sibling of `[scenario]`) onto the scenario (research R10).
        if let Some(mcp) = file.mcp {
            s.mcp = mcp;
        }
        if let Some(security) = file.security {
            s.security = security;
        }
        if let Some(context) = file.context {
            s.context = context;
        }
        // Resolve a relative policy_path against the scenario file's directory for portability.
        if s.policy_path.is_relative() {
            if let Some(dir) = path.parent() {
                let joined = dir.join(&s.policy_path);
                if joined.exists() {
                    s.policy_path = joined;
                }
            }
        }
        // Same portability treatment for relative skill roots and the ceiling policy (006-skills).
        if let Some(dir) = path.parent() {
            for root in &mut s.skills {
                if root.is_relative() {
                    let joined = dir.join(&*root);
                    if joined.exists() {
                        *root = joined;
                    }
                }
            }
            if let Some(ceiling) = &mut s.ceiling_policy_path {
                if ceiling.is_relative() {
                    let joined = dir.join(&*ceiling);
                    if joined.exists() {
                        *ceiling = joined;
                    }
                }
            }
        }
        s.validate()?;
        Ok(s)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.lease_turns == Some(0) {
            return Err(ConfigError::Invalid(
                "scenario.lease_turns must be at least 1 (omit it for grants that do not expire)"
                    .into(),
            ));
        }
        for (field, val) in [
            ("id", &self.id),
            ("system_prompt", &self.system_prompt),
            ("task", &self.task),
        ] {
            if val.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "scenario.{field} is required"
                )));
            }
        }
        if self.policy_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "scenario.policy_path is required".into(),
            ));
        }
        if self.turn_limit < 1 {
            return Err(ConfigError::Invalid(
                "scenario.turn_limit must be >= 1".into(),
            ));
        }
        if self.timeout_secs < 1 {
            return Err(ConfigError::Invalid(
                "scenario.timeout_secs must be >= 1".into(),
            ));
        }
        // CTF mode (US3): a flag must be planted, and the terminal `submit_flag` tool must be
        // enabled (a CTF with no way to submit is unwinnable).
        match self.mode {
            ScoringMode::Ctf => {
                match &self.workdir.flag {
                    Some(f) if !f.path.as_os_str().is_empty() && !f.value.is_empty() => {}
                    _ => {
                        return Err(ConfigError::Invalid(
                            "mode = \"ctf\" requires [scenario.workdir.flag] with path and value"
                                .into(),
                        ))
                    }
                }
                if !self.tools.iter().any(|t| t == "submit_flag") {
                    return Err(ConfigError::Invalid(
                        "mode = \"ctf\" requires \"submit_flag\" in the tools list".into(),
                    ));
                }
            }
            // A flag on a non-CTF scenario is ignored (a warning would go here if we had a logger).
            ScoringMode::Standard => {}
        }
        // Reject tool names we don't ship, before the run.
        for t in &self.tools {
            if !is_known_tool(t) {
                return Err(ConfigError::Invalid(format!("unknown tool: {t}")));
            }
        }
        // MCP policy semantics (004-mcp-client): unique server names, transport-appropriate fields.
        self.mcp.validate().map_err(ConfigError::Invalid)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, body: &str) -> PathBuf {
        let tmp = std::env::temp_dir().join(format!("bee-scn-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("scenario.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    const OK: &str = r#"
[scenario]
id            = "hello"
policy_path   = "/etc/bee/policy.toml"
system_prompt = "You are a coding agent."
task          = "List the working dir."
turn_limit    = 5
timeout_secs  = 60
"#;

    #[test]
    fn loads_defaults() {
        let p = write("ok", OK);
        let s = Scenario::from_path(&p).unwrap();
        assert_eq!(s.tools, default_tools());
        assert_eq!(s.mode, ScoringMode::Standard);
        assert_eq!(s.timeout(), Duration::from_secs(60));
    }

    const CTF_FLAG: &str = r#"
[scenario.workdir.flag]
path  = "/secrets/flag.txt"
value = "FLAG{abc}"
"#;

    #[test]
    fn skills_defaults_empty() {
        let p = write("noskills", OK);
        let s = Scenario::from_path(&p).unwrap();
        assert!(s.skills.is_empty());
    }

    #[test]
    fn relative_skill_roots_resolve_against_scenario_dir() {
        // A relative root that exists next to the scenario file is rewritten to an absolute path;
        // one that doesn't exist is left as-authored (portability, matching policy_path).
        let p = write(
            "skills",
            &format!("{OK}skills = [\"skills\", \"missing\"]\n"),
        );
        let dir = p.parent().unwrap();
        std::fs::create_dir_all(dir.join("skills")).unwrap();
        let s = Scenario::from_path(&p).unwrap();
        assert_eq!(s.skills[0], dir.join("skills"));
        assert_eq!(s.skills[1], PathBuf::from("missing"));
    }

    #[test]
    fn lease_turns_is_optional_and_at_least_one() {
        let s = Scenario::from_path(&write("lease-none", OK)).unwrap();
        assert_eq!(s.lease_turns, None, "grants do not expire unless asked");
        let s =
            Scenario::from_path(&write("lease-two", &format!("{OK}lease_turns = 2\n"))).unwrap();
        assert_eq!(s.lease_turns, Some(2));
        assert!(matches!(
            Scenario::from_path(&write("lease-zero", &format!("{OK}lease_turns = 0\n"))),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn ctf_requires_flag() {
        // mode = "ctf" with submit_flag but no planted flag → rejected.
        let body = format!("{OK}mode = \"ctf\"\ntools = [\"bash\", \"submit_flag\"]\n");
        let p = write("ctf-noflag", &body);
        assert!(matches!(
            Scenario::from_path(&p),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn ctf_requires_submit_flag_tool() {
        // mode = "ctf" with a flag but no submit_flag tool → rejected.
        let body = format!("{OK}mode = \"ctf\"\ntools = [\"bash\"]\n{CTF_FLAG}");
        let p = write("ctf-notool", &body);
        assert!(matches!(
            Scenario::from_path(&p),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn ctf_mode_now_accepted() {
        // A valid CTF scenario parses (the slice-1 rejection is gone).
        let body = format!(
            "{OK}mode = \"ctf\"\ntools = [\"bash\", \"submit_flag\", \"give_up\"]\n{CTF_FLAG}"
        );
        let p = write("ctf-ok", &body);
        let s = Scenario::from_path(&p).expect("valid CTF scenario");
        assert_eq!(s.mode, ScoringMode::Ctf);
        assert_eq!(s.workdir.flag.as_ref().unwrap().value, "FLAG{abc}");
    }

    #[test]
    fn rejects_unknown_tool() {
        let p = write("badtool", &format!("{OK}tools = [\"bash\", \"nmap\"]\n"));
        assert!(matches!(
            Scenario::from_path(&p),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_zero_turn_limit() {
        let body = OK.replace("turn_limit    = 5", "turn_limit    = 0");
        let p = write("zero", &body);
        assert!(matches!(
            Scenario::from_path(&p),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn no_mcp_section_is_disabled() {
        // SC-027: a scenario with no `[mcp]` table has MCP off — behaves like the pre-feature harness.
        let s = Scenario::from_path(&write("no-mcp", OK)).unwrap();
        assert!(!s.mcp.enabled);
        assert!(s.mcp.servers.is_empty());
    }

    #[test]
    fn top_level_mcp_section_parses() {
        // `[mcp]` is a sibling of `[scenario]` (research R10), folded onto the scenario.
        let body = format!(
            "{OK}\n[mcp]\nenabled = true\nallowed_domains = [\"*.company.com\"]\n\n\
             [[mcp.servers]]\nname = \"fs\"\ntransport = \"stdio\"\ncommand = \"srv\"\n"
        );
        let s = Scenario::from_path(&write("with-mcp", &body)).unwrap();
        assert!(s.mcp.enabled);
        assert_eq!(s.mcp.servers.len(), 1);
        assert_eq!(s.mcp.servers[0].name, "fs");
    }
}
