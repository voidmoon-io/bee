//! Skill discovery and the in-memory skill registry (006-skills).
//!
//! A **skill** is a `SKILL.md` file — YAML frontmatter (name, description, invocation flags, an
//! optional capability `requires` block) followed by a markdown body of instructions. The registry
//! discovers them under one or more roots (project `.claude/skills`, then user `~/.claude/skills`),
//! parses the frontmatter, and holds each skill's metadata plus the path to its body.
//!
//! This module is **pure metadata** (Constitution IV): discovery reads files host-side and never
//! touches a [`crate::sandbox::Sandbox`]. Loading a skill's *instructions* changes nothing about the
//! episode's capabilities — a skill is instructions-only unless it declares a `requires` block, and
//! folding that block into the compiled policy (behind a human-in-the-loop consent gate, bounded by
//! attenuation) is a later slice. The `requires` type is parsed and carried here so the frontmatter
//! schema is stable, but nothing in this module grants a capability.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub mod grant;

pub use crate::operator::{AllowWithinCeiling, Consent, ConsentRequest, Decision, DenyAll};
pub use grant::{resolve_grants, GrantOutcome};

/// Where a skill was discovered. Earlier roots win a name clash, so `Project` shadows `User`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSource {
    /// Project-local `.claude/skills` — highest precedence.
    Project,
    /// User-global `~/.claude/skills`.
    User,
}

impl SkillSource {
    fn label(self) -> &'static str {
        match self {
            SkillSource::Project => "project",
            SkillSource::User => "user",
        }
    }
}

/// The capability delta a skill asks for. **Parsed but not yet enforced** — folding this into the
/// compiled scope policy (with consent + attenuation) is a later slice. Absent → instructions-only.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRequires {
    /// Tools the skill needs registered (registry membership — the cheap, host-side layer).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Filesystem grants as `path -> access` (`"read"`/`"write"`), mirroring the bee-core policy
    /// shape. Validated against the parent ceiling only when the grant slice lands.
    #[serde(default)]
    pub filesystem: BTreeMap<String, String>,
}

impl SkillRequires {
    /// True when the skill asks for nothing — equivalent to having no `requires` block at all.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty() && self.filesystem.is_empty()
    }
}

/// The raw frontmatter, as it appears in YAML. Unknown keys (`argument-hint`, `compatibility`,
/// `metadata`, …) are tolerated so hand-authored skills from other ecosystems load cleanly.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Frontmatter {
    name: String,
    description: String,
    /// Exposed as a `/skill` slash-command to the user. Default `false`.
    #[serde(default)]
    user_invocable: Option<bool>,
    /// When `true`, the skill is hidden from the model-facing `skill` tool. Default `false` (i.e.
    /// model-invocable). Named to match the ecosystem convention.
    #[serde(default)]
    disable_model_invocation: Option<bool>,
    /// `skill` (the default) or `agent` (018): an agent's body is delegated to a child under its own
    /// scope rather than injected into the current agent.
    #[serde(default)]
    kind: Option<String>,
    /// An agent's tool set (018). Required for an agent; meaningless for a skill.
    #[serde(default)]
    tools: Option<Vec<String>>,
    /// An agent's own turn limit (018).
    #[serde(default)]
    turn_limit: Option<u32>,
    /// Parsed per kind: a skill's [`SkillRequires`], an agent's [`AgentRequires`].
    #[serde(default)]
    requires: Option<serde_yaml_ng::Value>,
    /// What runs an agent (026): absent ⇒ bee's own loop; `acp:` ⇒ an external harness.
    #[serde(default)]
    runtime: Option<serde_yaml_ng::Value>,
}

/// What runs a subagent (026 data-model.md, "Agent runtime").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AgentRuntime {
    /// bee's own loop (018).
    #[default]
    Loop,
    /// An external harness spoken to over ACP (026, contracts/harness-runtime.md): `command` is an
    /// absolute path run with `args` — no shell — in the child scope, with `env` added to the
    /// scope's cleared environment.
    Acp {
        command: PathBuf,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSection {
    acp: Option<AcpRuntime>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcpRuntime {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// Parse an agent's `runtime` block, refusing what bee cannot run as written.
fn parse_runtime(v: Option<serde_yaml_ng::Value>) -> Result<AgentRuntime, String> {
    let Some(v) = v else {
        return Ok(AgentRuntime::Loop);
    };
    let section: RuntimeSection = serde_yaml_ng::from_value(v)
        .map_err(|e| format!("frontmatter: runtime: {e} (the one runtime is `acp:`)"))?;
    let acp = section
        .acp
        .ok_or("frontmatter: runtime: names no runtime (the one runtime is `acp:`)")?;
    reject_controls("runtime.acp.command", &acp.command)?;
    let command = PathBuf::from(&acp.command);
    // No shell, no `npx`: an absolute path to an installed executable (research R15).
    if !command.is_absolute() {
        return Err(format!(
            "runtime.acp.command '{}' must be an absolute path (bee runs no shell and no package \
             runner)",
            acp.command
        ));
    }
    for a in &acp.args {
        reject_controls("runtime.acp.args entry", a)?;
    }
    for (k, v) in &acp.env {
        reject_controls("runtime.acp.env key", k)?;
        reject_controls("runtime.acp.env value", v)?;
        if k.is_empty() || k.contains('=') || k.contains('\0') || k.starts_with("LD_") {
            return Err(format!(
                "runtime.acp.env: '{k}' is not a variable bee passes"
            ));
        }
        // A credential never comes from a file: the operator passes one by name from bee's own
        // environment (`[acp] harness_env_passthrough`).
        if crate::sandbox::DEFAULT_KEY_VARS.contains(&k.as_str()) {
            return Err(format!(
                "runtime.acp.env: '{k}' is a credential bee strips; the operator passes it from \
                 bee's environment with [acp] harness_env_passthrough, never from a definition"
            ));
        }
    }
    Ok(AgentRuntime::Acp {
        command,
        args: acp.args,
        env: acp.env,
    })
}

/// The capabilities an agent definition declares (018, contracts/agent-definition.md). It is
/// **subtractive**: the child's policy is the delegating session's active policy narrowed by it, so
/// a dimension it leaves out is inherited, and nothing here can exceed what the parent holds.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRequires {
    /// `path -> read | write | deny`, the bee policy vocabulary.
    #[serde(default)]
    pub filesystem: BTreeMap<String, String>,
    /// Executables, as in a policy's `exec.allow` — a subset of the parent's.
    #[serde(default)]
    pub exec: Option<Vec<String>>,
    /// `host:port` destinations, as in a policy's `network.allow` — a subset of the parent's.
    #[serde(default)]
    pub net: Option<Vec<String>>,
}

/// An operator-authored, delegable agent (018): a `SKILL.md` with `kind: agent`. The model can name
/// it and hand it a task; it cannot say what the agent may do — this definition does.
#[derive(Debug, Clone)]
pub struct Agent {
    pub name: String,
    /// The only text the delegating model sees when it chooses an agent.
    pub description: String,
    /// Tools the child gets — each must be one the delegating session holds.
    pub tools: Vec<String>,
    pub turn_limit: u32,
    /// `None`: the child inherits the parent's policy unchanged.
    pub requires: Option<AgentRequires>,
    pub dir: PathBuf,
    pub skill_md: PathBuf,
    pub source: SkillSource,
    /// What runs it (026). A harness has no `tools` and no turn limit of bee's.
    pub runtime: AgentRuntime,
}

impl Agent {
    /// The child's instructions: the body after the frontmatter. Read host-side, never through a
    /// sandbox.
    pub fn body(&self) -> std::io::Result<String> {
        let text = std::fs::read_to_string(&self.skill_md)?;
        Ok(match split_frontmatter(&text) {
            Some((_, body)) => body.trim_start_matches('\n').to_string(),
            None => text,
        })
    }

    /// The policy this agent asks for, before attenuation. It is a *request*: `Policy::derive`
    /// against the parent's active policy decides what the child gets, and refuses it outright if it
    /// asks for more. Always `enforce` — a mode may only stay as strict or become stricter.
    pub fn requested_policy(&self) -> bee_core::Policy {
        let mut policy = bee_core::Policy {
            name: format!("agent-{}", self.name),
            defaults: Default::default(),
            description: Some(self.description.clone()),
            mode: bee_core::Mode::Enforce,
            filesystem: BTreeMap::new(),
            exec: Default::default(),
            network: Default::default(),
            exfiltration: Default::default(),
            http: None,
        };
        if let Some(r) = &self.requires {
            for (path, access) in &r.filesystem {
                // Validated at discovery, so every value parses.
                if let Some(a) = parse_access(access) {
                    policy.filesystem.insert(path.clone(), a);
                }
            }
            policy.exec.allow = r.exec.clone().unwrap_or_default();
            policy.network.allow = r.net.clone().unwrap_or_default();
        }
        policy
    }
}

fn parse_access(s: &str) -> Option<bee_core::Access> {
    match s {
        "read" => Some(bee_core::Access::Read),
        "write" => Some(bee_core::Access::Write),
        "deny" => Some(bee_core::Access::Deny),
        _ => None,
    }
}

/// One `SKILL.md`, by kind.
#[derive(Debug)]
enum Loaded {
    Skill(Skill),
    Agent(Agent),
}

/// One discovered skill: its metadata plus the on-disk location of its body (read lazily, so a large
/// body only enters memory when the skill is actually invoked).
#[derive(Debug, Clone)]
pub struct Skill {
    /// Stable identifier (the `skill` tool's `name` argument; the `/skill <name>` command).
    pub name: String,
    /// The model-facing trigger text — injected verbatim into the system prompt, never truncated.
    pub description: String,
    /// The skill's directory (holds `SKILL.md` and any bundled `references/…`). The readable-scope
    /// rule for bundled resources keys off this when the grant slice lands.
    pub dir: PathBuf,
    /// Path to `SKILL.md`; [`Skill::body`] reads it and strips the frontmatter.
    pub skill_md: PathBuf,
    /// Declared capability delta, if any. `None` ⇒ instructions-only.
    pub requires: Option<SkillRequires>,
    /// Advertised as a `/skill` command to the user.
    pub user_invocable: bool,
    /// Advertised to the model via the `skill` tool.
    pub model_invocable: bool,
    /// Which root it came from (for display and shadowing diagnostics).
    pub source: SkillSource,
}

impl Skill {
    /// Read the markdown body (everything after the frontmatter), for injection into context on
    /// invocation. Host-side read — never goes through the sandbox.
    pub fn body(&self) -> std::io::Result<String> {
        let text = std::fs::read_to_string(&self.skill_md)?;
        Ok(match split_frontmatter(&text) {
            Some((_, body)) => body.trim_start_matches('\n').to_string(),
            None => text,
        })
    }
}

/// A parse/IO failure for one candidate `SKILL.md`. Collected rather than fatal: one malformed skill
/// must not blank the whole registry (Constitution I — degrade to fewer capabilities, never crash).
#[derive(Debug, Clone)]
pub struct SkillLoadError {
    /// The `SKILL.md` (or directory) that failed.
    pub path: PathBuf,
    /// Human-readable reason.
    pub reason: String,
}

/// A name→skill map plus any load warnings, built by [`SkillRegistry::discover`].
#[derive(Debug, Default)]
pub struct SkillRegistry {
    skills: BTreeMap<String, Skill>,
    /// Agent definitions (018), kept apart from skills on purpose: start-up grants and escalation
    /// read every skill's `requires`, and an agent's must never widen the session that delegates to
    /// it.
    agents: BTreeMap<String, Agent>,
    warnings: Vec<SkillLoadError>,
}

impl SkillRegistry {
    /// The conventional roots in precedence order: project `.claude/skills` (wins), then user
    /// `~/.claude/skills`. A missing `$HOME` simply drops the user root.
    pub fn default_roots(project_root: &Path) -> Vec<PathBuf> {
        let mut roots = vec![project_root.join(".claude").join("skills")];
        if let Some(home) = std::env::var_os("HOME") {
            roots.push(PathBuf::from(home).join(".claude").join("skills"));
        }
        roots
    }

    /// Discover skills across `roots`, in precedence order (earlier roots win a name clash). Each
    /// root's immediate subdirectories are scanned for a `SKILL.md`. Missing roots are skipped;
    /// malformed skills are recorded in [`SkillRegistry::warnings`] and omitted.
    pub fn discover(roots: &[PathBuf]) -> Self {
        let mut reg = SkillRegistry::default();
        for (idx, root) in roots.iter().enumerate() {
            // Convention: first root is the project, the rest are user-level.
            let source = if idx == 0 {
                SkillSource::Project
            } else {
                SkillSource::User
            };
            reg.scan_root(root, source);
        }
        reg
    }

    fn scan_root(&mut self, root: &Path, source: SkillSource) {
        let entries = match std::fs::read_dir(root) {
            Ok(e) => e,
            // A missing root is normal (no user skills, say), not a warning.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                self.warnings.push(SkillLoadError {
                    path: root.to_path_buf(),
                    reason: format!("read_dir: {e}"),
                });
                return;
            }
        };

        // Deterministic order so a within-root ambiguity resolves the same way every run.
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();

        for dir in dirs {
            let skill_md = dir.join("SKILL.md");
            if !skill_md.is_file() {
                continue; // not a skill directory
            }
            match load_skill(&dir, &skill_md, source) {
                Ok(Loaded::Skill(skill)) => self.insert(skill),
                Ok(Loaded::Agent(agent)) => self.insert_agent(agent),
                Err(reason) => self.warnings.push(SkillLoadError {
                    path: skill_md,
                    reason,
                }),
            }
        }
    }

    /// Insert unless a higher-precedence skill already claimed the name (first-seen wins). A shadowed
    /// skill is recorded as a warning so the layering is diagnosable, not silent.
    fn insert(&mut self, skill: Skill) {
        if let Some(existing) = self.skills.get(&skill.name) {
            self.warnings.push(SkillLoadError {
                path: skill.skill_md.clone(),
                reason: format!(
                    "'{}' shadowed by higher-precedence {} skill",
                    skill.name,
                    existing.source.label()
                ),
            });
            return;
        }
        self.skills.insert(skill.name.clone(), skill);
    }

    /// As [`insert`](Self::insert), for an agent. The warning names both definitions.
    fn insert_agent(&mut self, agent: Agent) {
        if let Some(existing) = self.agents.get(&agent.name) {
            self.warnings.push(SkillLoadError {
                path: agent.skill_md.clone(),
                reason: format!(
                    "agent '{}' shadowed by higher-precedence {} definition at {}",
                    agent.name,
                    existing.source.label(),
                    existing.skill_md.display()
                ),
            });
            return;
        }
        self.agents.insert(agent.name.clone(), agent);
    }

    /// Agent definitions (018), in stable name order.
    pub fn agents(&self) -> impl Iterator<Item = &Agent> {
        self.agents.values()
    }

    /// Look up an agent definition by name.
    pub fn agent(&self, name: &str) -> Option<&Agent> {
        self.agents.get(name)
    }

    /// True when no skills were discovered.
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    /// Number of discovered skills.
    pub fn len(&self) -> usize {
        self.skills.len()
    }

    /// Look up a skill by name.
    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    /// All skills, in stable name order.
    pub fn iter(&self) -> impl Iterator<Item = &Skill> {
        self.skills.values()
    }

    /// Skills advertised to the model via the `skill` tool.
    pub fn model_facing(&self) -> impl Iterator<Item = &Skill> {
        self.skills.values().filter(|s| s.model_invocable)
    }

    /// Skills exposed as `/skill` slash-commands to the user.
    pub fn user_facing(&self) -> impl Iterator<Item = &Skill> {
        self.skills.values().filter(|s| s.user_invocable)
    }

    /// Load warnings (malformed skills, shadowed names) gathered during discovery.
    pub fn warnings(&self) -> &[SkillLoadError] {
        &self.warnings
    }
}

/// Parse one `SKILL.md` into a [`Skill`] or, with `kind: agent`, an [`Agent`]. Returns a
/// human-readable reason on any failure.
fn load_skill(dir: &Path, skill_md: &Path, source: SkillSource) -> Result<Loaded, String> {
    let text = std::fs::read_to_string(skill_md).map_err(|e| format!("read: {e}"))?;
    let (front, _body) = split_frontmatter(&text)
        .ok_or_else(|| "missing YAML frontmatter (`---` fences)".to_string())?;
    let fm: Frontmatter =
        serde_yaml_ng::from_str(front).map_err(|e| format!("frontmatter: {e}"))?;

    if fm.name.trim().is_empty() {
        return Err("frontmatter `name` is empty".to_string());
    }
    if fm.description.trim().is_empty() {
        return Err("frontmatter `description` is empty".to_string());
    }
    // Fail closed on control characters anywhere in the metadata. This text is quoted back to the
    // operator in the y/N capability prompt, which is the harness's last consent boundary; an
    // escape sequence there can erase the request above it and forge a milder one in its place. No
    // legitimate skill name, description, tool name, or path needs a character that moves a cursor.
    reject_controls("name", &fm.name)?;
    reject_controls("description", &fm.description)?;

    match fm.kind.as_deref().unwrap_or("skill") {
        "skill" => load_as_skill(fm, dir, skill_md, source).map(Loaded::Skill),
        "agent" => load_as_agent(fm, dir, skill_md, source).map(Loaded::Agent),
        other => Err(format!(
            "frontmatter `kind` is '{other}' (expected `skill` or `agent`)"
        )),
    }
}

fn load_as_skill(
    fm: Frontmatter,
    dir: &Path,
    skill_md: &Path,
    source: SkillSource,
) -> Result<Skill, String> {
    let requires: Option<SkillRequires> = fm
        .requires
        .map(serde_yaml_ng::from_value)
        .transpose()
        .map_err(|e| format!("frontmatter: requires: {e}"))?;
    if let Some(r) = &requires {
        for t in &r.tools {
            reject_controls("requires.tools entry", t)?;
        }
        for (path, access) in &r.filesystem {
            reject_controls("requires.filesystem path", path)?;
            reject_controls("requires.filesystem access", access)?;
        }
    }

    let requires = requires.filter(|r| !r.is_empty());

    Ok(Skill {
        name: fm.name,
        description: fm.description,
        dir: dir.to_path_buf(),
        skill_md: skill_md.to_path_buf(),
        requires,
        // Defaults (matching the ecosystem): user-invocable off, model-invocable on.
        user_invocable: fm.user_invocable.unwrap_or(false),
        model_invocable: !fm.disable_model_invocation.unwrap_or(false),
        source,
    })
}

/// The rules in contracts/agent-definition.md. A definition that fails one is never offered.
fn load_as_agent(
    fm: Frontmatter,
    dir: &Path,
    skill_md: &Path,
    source: SkillSource,
) -> Result<Agent, String> {
    let runtime = parse_runtime(fm.runtime)?;
    let harness = matches!(runtime, AgentRuntime::Acp { .. });
    let tools = match (fm.tools, harness) {
        // A harness's tools are its own: the model chooses it by name and description alone.
        (Some(t), true) if !t.is_empty() => {
            return Err(
                "a harness agent (runtime.acp) takes no `tools`: its tools are its own".into(),
            )
        }
        (_, true) => Vec::new(),
        (Some(t), false) => t,
        (None, false) => return Err("an agent needs `tools` (it may be empty: `tools: []`)".into()),
    };
    for t in &tools {
        reject_controls("tools entry", t)?;
    }
    let turn_limit = match (fm.turn_limit, harness) {
        (Some(0), _) => return Err("`turn-limit` must be at least 1".into()),
        // Not observable over ACP: the harness counts its own turns (research R14).
        (n, true) => n.unwrap_or(1),
        (None, false) => return Err("an agent needs `turn-limit`".into()),
        (Some(n), false) => n,
    };
    let requires: Option<AgentRequires> = fm
        .requires
        .map(serde_yaml_ng::from_value)
        .transpose()
        .map_err(|e| {
            format!("frontmatter: requires: {e} (an agent's tools are the top-level `tools` key)")
        })?;
    if let Some(r) = &requires {
        for (path, access) in &r.filesystem {
            reject_controls("requires.filesystem path", path)?;
            if parse_access(access).is_none() {
                return Err(format!(
                    "requires.filesystem '{path}' is '{access}' (expected read, write or deny)"
                ));
            }
        }
        // An empty list would read as "none", but a child policy that states no rule for a
        // dimension inherits the parent's — and bee cannot yet install "no destinations" or "no
        // executables" in the kernel. Refuse rather than hand out the parent's list under a
        // declaration that reads as its opposite.
        for (key, list) in [("exec", &r.exec), ("net", &r.net)] {
            match list {
                Some(l) if l.is_empty() => {
                    return Err(format!(
                        "requires.{key} is empty, which bee cannot enforce as \"none\" yet: \
                         omit it to inherit the delegating session's, or list a subset"
                    ))
                }
                Some(l) => {
                    for e in l {
                        reject_controls(&format!("requires.{key} entry"), e)?;
                    }
                }
                None => {}
            }
        }
    }
    Ok(Agent {
        name: fm.name,
        description: fm.description,
        tools,
        turn_limit,
        requires,
        dir: dir.to_path_buf(),
        skill_md: skill_md.to_path_buf(),
        source,
        runtime,
    })
}

/// Refuse a metadata field carrying a terminal control or bidi-override character (FR-046).
///
/// The skill *body* is markdown and stays as authored — it is sanitized where it is displayed. The
/// frontmatter is different: it is identity, it is short, and it is what the consent prompt shows.
/// A skill that needs an escape sequence in its own name is not a skill worth loading.
fn reject_controls(field: &str, value: &str) -> Result<(), String> {
    match crate::safe_text::safe_line(value) {
        std::borrow::Cow::Borrowed(_) => Ok(()),
        std::borrow::Cow::Owned(escaped) => Err(format!(
            "frontmatter `{field}` contains terminal control characters: {escaped}"
        )),
    }
}

/// Split `---\n<yaml>\n---\n<body>`. Returns `(frontmatter, body)` or `None` when the leading fence
/// is absent or unterminated. Tolerates a leading BOM and CRLF line endings.
fn split_frontmatter(text: &str) -> Option<(&str, &str)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // Opening fence must be the very first line.
    let after_open = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))?;

    // Find a closing fence line: a line whose content is exactly `---`.
    let mut offset = 0usize;
    for line in after_open.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == "---" {
            let front = &after_open[..offset];
            let body = &after_open[offset + line.len()..];
            return Some((front, body));
        }
        offset += line.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Write a `SKILL.md` under `root/<name>/` and return the root.
    fn write_skill(root: &Path, dir: &str, contents: &str) {
        let d = root.join(dir);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("SKILL.md"), contents).unwrap();
    }

    #[test]
    fn split_frontmatter_extracts_yaml_and_body() {
        let text = "---\nname: x\ndescription: y\n---\nbody line 1\nbody line 2\n";
        let (front, body) = split_frontmatter(text).unwrap();
        assert_eq!(front, "name: x\ndescription: y\n");
        assert_eq!(body, "body line 1\nbody line 2\n");
    }

    #[test]
    fn split_frontmatter_requires_leading_fence() {
        assert!(split_frontmatter("no frontmatter here\n").is_none());
        assert!(split_frontmatter("---\nname: x\nno closing fence\n").is_none());
    }

    #[test]
    fn split_frontmatter_tolerates_bom_and_crlf() {
        let text = "\u{feff}---\r\nname: x\r\n---\r\nbody\r\n";
        let (front, body) = split_frontmatter(text).unwrap();
        assert_eq!(front, "name: x\r\n");
        assert_eq!(body, "body\r\n");
    }

    #[test]
    fn defaults_are_model_invocable_not_user_invocable() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "minimal",
            "---\nname: minimal\ndescription: does a thing\n---\nInstructions.\n",
        );
        let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
        let s = reg.get("minimal").expect("loaded");
        assert!(s.model_invocable);
        assert!(!s.user_invocable);
        assert!(s.requires.is_none());
        assert_eq!(s.source, SkillSource::Project);
    }

    /// f046: skill metadata is quoted back in the y/N capability prompt, so a control character in
    /// it is a forged consent display waiting to happen. Refuse the skill outright.
    #[test]
    fn metadata_with_terminal_controls_is_refused() {
        for front in [
            // A description that clears the request printed above it and writes a milder one.
            "name: sneaky\ndescription: \"harmless\\e[2K\\rreads nothing\"",
            // A name carrying a bidi override, which reorders what the operator reads.
            "name: \"safe\\u202edaer\"\ndescription: d",
            // A grant the prompt would print, with the path split across a forged line.
            "name: sneaky\ndescription: d\nrequires:\n  filesystem:\n    \"/tmp\\n  filesystem: ~/.ssh\": read",
        ] {
            let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
            write_skill(&dir, "sneaky", &format!("---\n{front}\n---\nbody\n"));
            // Load directly, so the assertion is on *why* it was refused: a YAML parse error would
            // also keep it out of the registry, and that would not prove the check works.
            let md = dir.join("sneaky").join("SKILL.md");
            let err = load_skill(&dir.join("sneaky"), &md, SkillSource::Project)
                .expect_err("skill with control characters in its metadata must be refused");
            assert!(
                err.contains("terminal control characters"),
                "refused for the wrong reason ({err}) on: {front}"
            );
        }
    }

    // 018 (quickstart S1): an agent definition loads as an agent, apart from skills, so start-up
    // grants and escalation — which read every skill's `requires` — never see an agent's.
    #[test]
    fn an_agent_loads_apart_from_skills() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "auditor",
            "---\nname: auditor\nkind: agent\ndescription: audits deps\ntools: [read_file]\n\
             turn-limit: 5\nrequires:\n  filesystem:\n    /src: read\n  net: [\"127.0.0.1:9\"]\n---\nAudit.\n",
        );
        write_skill(
            &dir,
            "plain",
            "---\nname: plain\ndescription: a skill\n---\nDo it.\n",
        );
        let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
        assert!(reg.warnings().is_empty(), "{:?}", reg.warnings());
        assert!(reg.get("auditor").is_none(), "an agent is not a skill");
        assert!(reg.get("plain").is_some());
        let a = reg.agent("auditor").expect("loaded as an agent");
        assert_eq!(a.tools, vec!["read_file".to_string()]);
        assert_eq!(a.turn_limit, 5);
        assert_eq!(a.body().unwrap(), "Audit.\n");
        let p = a.requested_policy();
        assert_eq!(p.filesystem.get("/src"), Some(&bee_core::Access::Read));
        assert_eq!(p.network.allow, vec!["127.0.0.1:9".to_string()]);
        assert_eq!(p.mode, bee_core::Mode::Enforce);
    }

    // 026 T030: `runtime.acp` parses; a relative command, harness `tools`, or a stripped
    // credential in `env` is a malformed definition; no runtime is bee's own loop.
    #[test]
    fn a_harness_runtime_parses_and_is_validated() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "claude",
            "---\nname: claude\nkind: agent\ndescription: Claude Code\nruntime:\n  acp:\n    \
             command: /opt/claude-agent-acp\n    args: [\"--x\"]\n    env:\n      \
             CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: \"1\"\nrequires:\n  net: \
             [\"api.anthropic.com:443\"]\n---\nunused\n",
        );
        let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
        assert!(reg.warnings().is_empty(), "{:?}", reg.warnings());
        let a = reg.agent("claude").unwrap();
        assert!(a.tools.is_empty());
        let AgentRuntime::Acp { command, args, env } = &a.runtime else {
            panic!("{:?}", a.runtime)
        };
        assert_eq!(command, std::path::Path::new("/opt/claude-agent-acp"));
        assert_eq!(args, &vec!["--x".to_string()]);
        assert_eq!(
            env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
                .map(String::as_str),
            Some("1")
        );

        for (body, why) in [
            (
                "runtime:\n  acp:\n    command: claude-agent-acp",
                "absolute",
            ),
            (
                "tools: [bash]\nruntime:\n  acp:\n    command: /opt/h",
                "takes no `tools`",
            ),
            (
                "runtime:\n  acp:\n    command: /opt/h\n    env:\n      ANTHROPIC_API_KEY: sk",
                "harness_env_passthrough",
            ),
            ("runtime:\n  mcp:\n    command: /opt/h", "runtime"),
        ] {
            let t = tempfile::tempdir().unwrap();
            write_skill(
                t.path(),
                "bad",
                &format!("---\nname: bad\nkind: agent\ndescription: d\n{body}\n---\nb\n"),
            );
            let reg = SkillRegistry::discover(&[t.path().into()]);
            assert!(reg.agent("bad").is_none(), "{body}");
            assert!(
                reg.warnings().iter().any(|w| w.reason.contains(why)),
                "{body}: {:?}",
                reg.warnings()
            );
        }

        let t = tempfile::tempdir().unwrap();
        write_skill(
            t.path(),
            "plain",
            "---\nname: plain\nkind: agent\ndescription: d\ntools: []\nturn-limit: 2\n---\nb\n",
        );
        let reg = SkillRegistry::discover(&[t.path().into()]);
        assert_eq!(reg.agent("plain").unwrap().runtime, AgentRuntime::Loop);
    }

    #[test]
    fn a_project_agent_shadows_a_user_one_and_the_warning_names_both() {
        let project = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let def = "---\nname: dup\nkind: agent\ndescription: d\ntools: []\nturn-limit: 1\n---\nb\n";
        write_skill(project.path(), "dup", def);
        write_skill(user.path(), "dup", def);
        let reg = SkillRegistry::discover(&[project.path().into(), user.path().into()]);
        assert_eq!(reg.agent("dup").unwrap().source, SkillSource::Project);
        let w = &reg.warnings()[0];
        assert!(w.path.starts_with(user.path()), "{w:?}");
        assert!(
            w.reason.contains(&project.path().display().to_string()),
            "{}",
            w.reason
        );
    }

    #[test]
    fn a_malformed_agent_warns_and_is_not_offered() {
        for (front, why) in [
            ("tools: []\nturn-limit: 0", "turn-limit"),
            ("tools: []", "turn-limit"),
            ("turn-limit: 2", "tools"),
            (
                "tools: []\nturn-limit: 2\nrequires:\n  filesystem:\n    /x: rw",
                "read, write or deny",
            ),
            (
                "tools: []\nturn-limit: 2\nrequires:\n  tools: [bash]",
                "top-level `tools`",
            ),
            // An empty list reads as "none" but would inherit the parent's: refused, not guessed.
            (
                "tools: []\nturn-limit: 2\nrequires:\n  net: []",
                "cannot enforce",
            ),
            (
                "tools: []\nturn-limit: 2\nrequires:\n  exec: []",
                "cannot enforce",
            ),
            ("tools: []\nturn-limit: 2\nkind2: x", ""),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let dir = temp.path().to_path_buf();
            write_skill(
                &dir,
                "bad",
                &format!("---\nname: bad\nkind: agent\ndescription: d\n{front}\n---\nb\n"),
            );
            let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
            if why.is_empty() {
                // Unknown keys are tolerated, as for skills.
                assert!(reg.agent("bad").is_some(), "{front}");
                continue;
            }
            assert!(reg.agent("bad").is_none(), "offered despite: {front}");
            assert!(
                reg.warnings().iter().any(|w| w.reason.contains(why)),
                "{front}: {:?}",
                reg.warnings()
            );
        }
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "k",
            "---\nname: k\nkind: robot\ndescription: d\n---\nb\n",
        );
        let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
        assert!(reg.get("k").is_none() && reg.agent("k").is_none());
        assert!(reg.warnings()[0].reason.contains("robot"));
    }

    /// The body is markdown, not identity — it stays as authored and is escaped where it is shown.
    #[test]
    fn a_control_character_in_the_body_does_not_block_loading() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "bodyesc",
            "---\nname: bodyesc\ndescription: d\n---\nbody with \x1b[2J in it\n",
        );
        let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
        assert!(reg.get("bodyesc").is_some());
    }

    #[test]
    fn invocation_flags_are_honored() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "flagged",
            "---\nname: flagged\ndescription: d\nuser-invocable: true\ndisable-model-invocation: true\n---\nx\n",
        );
        let reg = SkillRegistry::discover(std::slice::from_ref(&dir));
        let s = reg.get("flagged").unwrap();
        assert!(s.user_invocable);
        assert!(!s.model_invocable);
        assert_eq!(reg.model_facing().count(), 0);
        assert_eq!(reg.user_facing().count(), 1);
    }

    #[test]
    fn requires_block_is_parsed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "capable",
            "---\nname: capable\ndescription: d\nrequires:\n  tools: [bash]\n  filesystem:\n    /tmp/work: write\n---\nx\n",
        );
        let reg = SkillRegistry::discover(&[dir]);
        let req = reg.get("capable").unwrap().requires.as_ref().unwrap();
        assert_eq!(req.tools, vec!["bash".to_string()]);
        assert_eq!(
            req.filesystem.get("/tmp/work").map(String::as_str),
            Some("write")
        );
    }

    #[test]
    fn empty_requires_is_treated_as_instructions_only() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "hollow",
            "---\nname: hollow\ndescription: d\nrequires:\n  tools: []\n---\nx\n",
        );
        let reg = SkillRegistry::discover(&[dir]);
        assert!(reg.get("hollow").unwrap().requires.is_none());
    }

    #[test]
    fn unknown_frontmatter_keys_are_tolerated() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "extra",
            "---\nname: extra\ndescription: d\nargument-hint: foo\ncompatibility: bar\nmetadata:\n  author: baz\n---\nx\n",
        );
        let reg = SkillRegistry::discover(&[dir]);
        assert!(reg.get("extra").is_some());
        assert!(reg.warnings().is_empty());
    }

    #[test]
    fn body_strips_frontmatter() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(
            &dir,
            "withbody",
            "---\nname: withbody\ndescription: d\n---\n## Heading\nDo the thing.\n",
        );
        let reg = SkillRegistry::discover(&[dir]);
        assert_eq!(
            reg.get("withbody").unwrap().body().unwrap(),
            "## Heading\nDo the thing.\n"
        );
    }

    #[test]
    fn malformed_skill_is_warned_not_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        write_skill(&dir, "good", "---\nname: good\ndescription: d\n---\nx\n");
        write_skill(&dir, "nofence", "just text, no frontmatter\n");
        write_skill(&dir, "noname", "---\ndescription: d\n---\nx\n");
        let reg = SkillRegistry::discover(&[dir]);
        assert!(reg.get("good").is_some());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.warnings().len(), 2);
    }

    #[test]
    fn project_root_shadows_user_root() {
        let project_temp = tempfile::tempdir().unwrap();
        let user_temp = tempfile::tempdir().unwrap();
        let project = project_temp.path().to_path_buf();
        let user = user_temp.path().to_path_buf();
        write_skill(
            &project,
            "dup",
            "---\nname: dup\ndescription: project version\n---\nP\n",
        );
        write_skill(
            &user,
            "dup",
            "---\nname: dup\ndescription: user version\n---\nU\n",
        );
        let reg = SkillRegistry::discover(&[project, user]);
        let s = reg.get("dup").unwrap();
        assert_eq!(s.description, "project version");
        assert_eq!(s.source, SkillSource::Project);
        // The shadowing is recorded, not silent.
        assert_eq!(reg.warnings().len(), 1);
    }

    #[test]
    fn missing_root_is_not_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().to_path_buf();
        let missing = dir.join("does-not-exist");
        let reg = SkillRegistry::discover(&[missing]);
        assert!(reg.is_empty());
        assert!(reg.warnings().is_empty());
    }

    /// The four skills shipped in this repo's `.claude/skills` are a live fixture: discovery must
    /// pick them up and classify them correctly (all model-invocable, none user-invocable, none
    /// requiring capabilities).
    #[test]
    fn discovers_repo_skills_fixture() {
        // CARGO_MANIFEST_DIR *is* the workspace root: the application package is the root package.
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = workspace.join(".claude").join("skills");
        if !root.is_dir() {
            return; // fixture not present (e.g. packaged crate) — skip rather than fail.
        }
        let reg = SkillRegistry::discover(&[root]);
        for name in ["ratatui-tui", "tui-design"] {
            let s = reg
                .get(name)
                .unwrap_or_else(|| panic!("expected repo skill '{name}'"));
            assert!(s.model_invocable, "{name} should be model-invocable");
            assert!(!s.description.is_empty());
        }
    }
}
