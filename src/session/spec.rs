//! What an entry point knows before a session starts (024 data-model `SessionSpec`).
//!
//! Every entry point — the headless episode, the REPL and TUI, the batch runners, the test harness —
//! fills one of these in and hands it to [`super::build`]. Nothing about *how* a session is assembled
//! lives in an entry point any more; what differs between them is only what they put here.

use std::path::PathBuf;

use bee_core::Policy;

use crate::operator::Operator;

/// Which entry point a session serves. It selects refusals and labels, never behaviour (FR-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPoint {
    /// `bee run`: one headless episode.
    Headless,
    /// The inline REPL.
    Repl,
    /// The full-screen TUI.
    Tui,
    /// `bee run --batch`. `concurrent` batches share one engine and cannot run every part (FR-008).
    Batch { concurrent: bool },
}

/// What the session's tools run under, decided once, before the builder runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// A kernel-enforced scope (BPF-LSM).
    Kernel,
    /// Hardened, credential-stripped host processes, with no kernel scope.
    Host,
}

/// Everything [`super::build`] needs.
pub struct SessionSpec {
    pub entry: EntryPoint,
    /// A short name for the session — a scenario id, `repl` — used in scope and session ids.
    pub label: String,
    /// The policy the scope is compiled from, before skill grants widen it. `None`: no policy, so no
    /// grants and no escalation base beyond an empty policy.
    pub policy: Option<Policy>,
    /// The ceiling grants are bounded by. `None`: the policy is its own ceiling, which also turns off
    /// widening on a kernel denial or proxy refusal.
    pub ceiling: Option<Policy>,
    pub enforcement: Enforcement,
    /// The tools asked for, by name.
    pub tools: Vec<String>,
    /// The planted CTF flag, which `submit_flag` checks against.
    pub ctf_flag: Option<String>,
    /// Where skills are discovered, in precedence order.
    pub skill_roots: Vec<PathBuf>,
    /// MCP servers to connect.
    pub mcp: crate::mcp::McpPolicy,
    /// Where findings are recorded and how a granted scanner runs.
    pub security: crate::security::SecurityConfig,
    /// The project root: where the interception store lives.
    pub workdir: PathBuf,
    /// The base system prompt. The builder adds the notes for the tools the session holds.
    pub system_prompt: String,
    /// Environment variables tool children must not inherit.
    pub strip_env: Vec<String>,
    /// `--http-scope-advisory`: accept interception the kernel does not back.
    pub http_scope_advisory: bool,
    /// The lifetime of grants made mid-session, in model turns. `None`: the rest of the session.
    pub lease_turns: Option<u32>,
    /// Who decides a grant request, and where every decision is recorded (FR-001). The only thing
    /// an autonomous and an interactive session differ by.
    pub operator: Operator,
    /// A sandbox the entry point built itself — the concurrent runner's scopes share one engine and one
    /// audit ring, which the builder cannot create per session. `None`: the builder builds it.
    pub prebuilt_sandbox: Option<crate::sandbox::Sandbox>,
}

/// Why a session could not be built. Every refusal happens before a scope exists or a child runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError(pub String);

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BuildError {}

/// Refuse a combination this entry point cannot provide, naming it (FR-008, contracts/session-builder.md).
/// A configured part is never silently left out.
pub fn refuse_unsupported(spec: &SessionSpec) -> Result<(), BuildError> {
    if let EntryPoint::Batch { concurrent: true } = spec.entry {
        let unsupported = "not supported in concurrent batches (see 018-subagent-scopes)";
        if spec.mcp.enabled && !spec.mcp.servers.is_empty() {
            return Err(BuildError(format!("MCP servers are {unsupported}")));
        }
        if spec
            .policy
            .as_ref()
            .and_then(|p| p.http.as_ref())
            .is_some_and(|h| h.is_active())
        {
            return Err(BuildError(format!(
                "[policy.http] interception is {unsupported}"
            )));
        }
        if spec.ceiling.is_some() {
            return Err(BuildError(format!(
                "widening escalation (a ceiling policy) is {unsupported}"
            )));
        }
        // Skill directories widen the policy, and a concurrent batch compiles each scope before the
        // session is built.
        if !spec.skill_roots.is_empty() {
            return Err(BuildError(format!("skills are {unsupported}")));
        }
    }
    if spec.mcp.enabled && !cfg!(feature = "mcp") {
        return Err(BuildError(
            "MCP servers are configured, but bee was built without --features mcp".into(),
        ));
    }
    if spec.enforcement == Enforcement::Kernel && !cfg!(feature = "enforce") {
        return Err(BuildError(
            "kernel enforcement was asked for, but this bee was built without --features enforce"
                .into(),
        ));
    }
    Ok(())
}
