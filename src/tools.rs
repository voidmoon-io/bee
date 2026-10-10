//! The tool trait, its result type, and the name→tool registry (contracts/tool-contracts.md).
//!
//! Every tool executes as a **sandboxed child inside the episode's bee scope** (via [`Sandbox`]) and
//! returns a [`ToolResult`]. A tool MUST NOT panic on bad arguments — it returns an error result
//! (FR-016). Concrete tools (`bash`, `read_file`, `write_file`, `list_directory`) land in T014/T015.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::provider::{ToolCall, ToolSchema};
use crate::sandbox::Sandbox;

pub mod bash;
pub mod ctf;
pub mod exec;
pub mod files;
pub mod outcome;
pub mod render;
pub mod search;
pub mod skill;

// Security analysis tools (016-native-tools). Each is gated by its family's feature so a build that
// selects none of them compiles none of them; `outcome` above is NOT gated, because the fail-closed
// result type is what the compiled-out stubs return.
#[cfg(feature = "astgrep")]
pub mod astgrep;
#[cfg(feature = "cvss")]
pub mod cvss;
#[cfg(feature = "findings")]
pub mod finding;
#[cfg(feature = "gitlog")]
pub mod gitlog;
#[cfg(feature = "intercept")]
pub mod http;
#[cfg(feature = "scanners")]
pub mod scanner;

pub use outcome::{ToolOutcome, UnavailableReason};

use crate::render_spec::{EffectSpec, PanelOp, RenderSpec, RenderTarget};

/// The default tool set advertised to the model (contracts/scenario-schema.md). The CTF terminal
/// tools (`submit_flag`, `give_up`) are **not** here — a scenario opts into them via its `tools`
/// list when `mode = "ctf"`.
pub const DEFAULT_TOOLS: &[&str] = &[
    "bash",
    "read_file",
    "write_file",
    "list_directory",
    "search",
];

/// The CTF terminal tools (US3), enabled only when a scenario lists them.
pub const CTF_TOOLS: &[&str] = &["submit_flag", "give_up"];

/// The visualization tools (003-visual-render, US6). **Not** in `DEFAULT_TOOLS` (NFR-003): a
/// scenario or the REPL config opts in by listing `"render"`.
pub const RENDER_TOOLS: &[&str] = &["render"];

/// The skills tool (006-skills). **Not** in `DEFAULT_TOOLS`: it needs a discovered
/// [`crate::skills::SkillRegistry`], so — unlike the other names — [`registry_for`] cannot build it
/// from a name alone. The caller inserts [`skill::SkillTool`] with the registry (auto-enabled when
/// discovery finds ≥1 model-facing skill).
pub const SKILL_TOOLS: &[&str] = &["skill"];

/// The native security-analysis tools (016-native-tools). **Not** in `DEFAULT_TOOLS`: a scenario or
/// the REPL config opts in by listing them, exactly as it does for `render`.
///
/// This list holds only tools that are **built**. A tool named here but compiled out registers as a
/// refusing stub (`NotCompiledIn`); a tool absent from it is rejected at validation as unknown. Both
/// are honest answers, and neither is "it ran and found nothing".
pub const SEC_TOOLS: &[&str] = &[
    "ast_grep",
    "cvss",
    "record_finding",
    "list_findings",
    "git_log",
];

/// The external scanner tier (016-native-tools). Listing `scan` is necessary but **not sufficient**
/// to run a scanner: the episode's policy must also carry an inode-pinned `ExecPolicy.allow` grant
/// for the specific binary, or the tool refuses with `NotGranted` (FR-008).
pub const SCANNER_TOOLS: &[&str] = &["scan"];

/// Every tool name the harness knows how to build. A scenario may only list names from this set
/// (scenario validation rejects the rest before a run).
///
/// A 016 tool whose Cargo feature is compiled out is still *known*. That is deliberate: it registers
/// a stub that refuses with `NotCompiledIn`, so a scenario referencing it fails loudly at the call
/// with an actionable message instead of being silently dropped at validation — and, critically, it
/// never looks like a tool that ran and found nothing (spec Edge Case "the build was slimmed down").
pub fn is_known_tool(name: &str) -> bool {
    DEFAULT_TOOLS.contains(&name)
        || CTF_TOOLS.contains(&name)
        || RENDER_TOOLS.contains(&name)
        || SKILL_TOOLS.contains(&name)
        || SEC_TOOLS.contains(&name)
        || SCANNER_TOOLS.contains(&name)
}

/// The Cargo feature each 016 tool needs, for the `NotCompiledIn` message. Covers only the tools
/// currently in [`SEC_TOOLS`]/[`SCANNER_TOOLS`]; entries for the unbuilt tools land with their
/// phases, alongside the tools themselves.
pub fn sec_tool_family(name: &str) -> Option<&'static str> {
    match name {
        "ast_grep" => Some("astgrep"),
        "git_log" => Some("gitlog"),
        "cvss" => Some("cvss"),
        "record_finding" | "list_findings" => Some("findings"),
        "scan" => Some("scanners"),
        _ => None,
    }
}

/// The outcome of one tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// stdout (+ formatted stderr/exit for `bash`), or the file/dir payload, or an error message.
    pub content: String,
    /// Process exit code, for process-backed tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// True for a kernel denial (`EACCES`), a non-zero exit, or a malformed-arg error.
    pub is_error: bool,
    /// True if `content` was capped (FR-015).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Pre-truncation byte length, when `truncated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_len: Option<usize>,
    /// When true, this tool call ends the episode (the CTF terminal tools `submit_flag`/`give_up`,
    /// US3). The loop is otherwise tool-name-agnostic — it reads this flag, not the name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminal: bool,
    /// The visualization to render, when this result came from the `render` tool (003-visual-render,
    /// FR-023). **Never sent to the model** — `content` carries the human-readable summary instead;
    /// recorded in the transcript for later re-rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_spec: Option<RenderSpec>,
    /// Where the `render_spec` is addressed (008-grid-tui, FR-008). **Legacy**: panel effects now
    /// travel in `panel_ops`; this remains so transcripts recorded before the lifecycle ops still
    /// replay. New results always leave it `Inline`.
    #[serde(default, skip_serializing_if = "RenderTarget::is_inline")]
    pub render_target: RenderTarget,
    /// Panel effects this call requested — create/replace (optionally with a TTL), remove, or clear
    /// (008-grid-tui, US2 lifecycle). Ordered; the front-end applies them in sequence. The model
    /// never sees these, only the text summary in `content`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub panel_ops: Vec<PanelOp>,
    /// The effect the agent attached to the inline widget via `.effect()` (009 FR-022).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_effect: Option<EffectSpec>,
}

impl ToolResult {
    /// A successful, non-truncated text result.
    pub fn ok(content: impl Into<String>) -> Self {
        ToolResult {
            content: content.into(),
            exit_code: None,
            is_error: false,
            truncated: false,
            original_len: None,
            terminal: false,
            render_spec: None,
            render_target: RenderTarget::Inline,
            panel_ops: Vec::new(),
            inline_effect: None,
        }
    }

    /// An error result (bad args, denial, missing file, …). `is_error = true`.
    pub fn error(content: impl Into<String>) -> Self {
        ToolResult {
            content: content.into(),
            exit_code: None,
            is_error: true,
            truncated: false,
            original_len: None,
            terminal: false,
            render_spec: None,
            render_target: RenderTarget::Inline,
            panel_ops: Vec::new(),
            inline_effect: None,
        }
    }

    /// A successful `render`-tool result committed to the **inline** target: `content` is the text
    /// summary, `render_spec` the widget (003-visual-render, FR-023).
    pub fn rendered(summary: impl Into<String>, spec: RenderSpec) -> Self {
        ToolResult::rendered_to(summary, spec, RenderTarget::Inline)
    }

    /// A successful `render`-tool result committed to `target` — inline (chat) or a named panel
    /// (008-grid-tui, FR-008). The model still receives only the text `summary`.
    pub fn rendered_to(summary: impl Into<String>, spec: RenderSpec, target: RenderTarget) -> Self {
        ToolResult {
            render_spec: Some(spec),
            render_target: target,
            ..ToolResult::ok(summary)
        }
    }

    /// A successful `render`-tool result carrying an optional inline widget plus the panel effects
    /// the script requested (008-grid-tui, US2 lifecycle). The model still receives only `summary`.
    pub fn rendered_with_ops(
        summary: impl Into<String>,
        inline: Option<RenderSpec>,
        panel_ops: Vec<PanelOp>,
        inline_effect: Option<EffectSpec>,
    ) -> Self {
        ToolResult {
            render_spec: inline,
            panel_ops,
            inline_effect,
            ..ToolResult::ok(summary)
        }
    }

    /// A successful **terminal** result (a CTF tool that ends the episode, US3). `terminal = true`,
    /// `is_error = false`.
    pub fn terminal_ok(content: impl Into<String>) -> Self {
        ToolResult {
            terminal: true,
            ..ToolResult::ok(content)
        }
    }

    /// The FR-016 malformed-arguments result: `"<tool>: invalid arguments: <detail>"`.
    pub fn invalid_args(tool: &str, detail: impl std::fmt::Display) -> Self {
        ToolResult::error(format!("{tool}: invalid arguments: {detail}"))
    }
}

/// A tool the agent may call. Object-safe so tools live in a `Box<dyn Tool>` registry.
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    /// The tool's stable name (matches [`ToolCall::name`]).
    fn name(&self) -> &'static str;

    /// The JSON-Schema-bearing schema advertised to the model.
    fn schema(&self) -> ToolSchema;

    /// Execute inside `sandbox`. MUST NOT panic on bad `arguments` — return an error result.
    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult;
}

/// A name→tool map plus the schema list handed to the model each turn.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        ToolRegistry::default()
    }

    /// Register a tool (last registration under a name wins).
    pub fn insert(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name(), tool);
    }

    /// Register a tool, chaining.
    pub fn with(mut self, tool: Box<dyn Tool>) -> Self {
        self.insert(tool);
        self
    }

    /// True if a tool with `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// The schemas for all registered tools, in stable name order.
    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools.values().map(|t| t.schema()).collect()
    }

    /// Drop every `mcp__…` tool. Used to rebuild the MCP set after a `tools/list_changed`
    /// notification (004-mcp-client, FR-043) — the bridge then re-registers the current tools.
    pub fn remove_mcp_tools(&mut self) {
        self.tools.retain(|name, _| !name.starts_with("mcp__"));
    }

    /// Execute a model-requested call. An unknown tool name yields an error result (fed back to the
    /// model), never a panic (FR-016).
    pub async fn execute(&self, call: &ToolCall, sandbox: &Sandbox) -> ToolResult {
        match self.tools.get(call.name.as_str()) {
            Some(tool) => tool.call(call.arguments.clone(), sandbox).await,
            None => ToolResult::error(format!("unknown tool: {}", call.name)),
        }
    }
}

/// Build a registry holding just the `enabled` tools (validated names; unknown names are dropped —
/// [`crate::scenario::Scenario`] validation already rejects them before a run). `flag` is the CTF
/// sentinel value (US3): `submit_flag` needs it at construction to check submissions, so it is only
/// registered when `flag` is `Some`.
pub fn registry_for(enabled: &[String], flag: Option<&str>) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    for name in enabled {
        register_named(&mut r, name, flag);
    }
    r
}

/// Register a single built-in tool by name into an existing registry (idempotent — last wins). Used
/// both by [`registry_for`] and to add skill-granted tools (006-skills) after grant resolution. An
/// unknown name (or `skill`, which needs an external registry) is a silent no-op.
pub fn register_named(r: &mut ToolRegistry, name: &str, flag: Option<&str>) {
    match name {
        "bash" => r.insert(Box::new(bash::Bash)),
        "read_file" => r.insert(Box::new(files::ReadFile)),
        "write_file" => r.insert(Box::new(files::WriteFile)),
        "list_directory" => r.insert(Box::new(files::ListDirectory)),
        "submit_flag" => {
            if let Some(value) = flag {
                r.insert(Box::new(ctf::SubmitFlag::new(value.to_string())));
            }
        }
        "give_up" => r.insert(Box::new(ctf::GiveUp)),
        "render" => r.insert(Box::new(render::RenderTool::new())),
        "search" => r.insert(Box::new(search::Search)),
        // `skill` needs a discovered SkillRegistry, so the caller inserts it separately (see
        // `skill::SkillTool`). Recognized as known so it isn't an unknown name.
        "skill" => {}

        // ── 016-native-tools ───────────────────────────────────────────────────────────────────
        // Each arm registers the real tool when its family is compiled in, and a refusing stub when
        // it is not. The stub is the point: a compiled-out security tool must announce its absence,
        // never answer as though it ran (Constitution I).
        #[cfg(feature = "astgrep")]
        "ast_grep" => r.insert(Box::new(astgrep::AstGrepTool)),
        #[cfg(feature = "gitlog")]
        "git_log" => r.insert(Box::new(gitlog::GitLogTool)),
        #[cfg(feature = "cvss")]
        "cvss" => r.insert(Box::<cvss::CvssTool>::default()),
        // The ledger tools default to `.bee/findings` under the working directory and a
        // pid-derived run id. A caller that knows the episode id re-inserts them configured —
        // registration is last-wins — so the default is a working tool, not a placeholder.
        #[cfg(feature = "findings")]
        "record_finding" => r.insert(Box::<finding::RecordFinding>::default()),
        #[cfg(feature = "findings")]
        "list_findings" => r.insert(Box::<finding::ListFindings>::default()),
        // `scan` defaults to holding NO grants, which means it refuses with `NotGranted` until a
        // caller inserts it with the episode's resolved grants. That is the right default for a
        // tool that runs a third-party binary: forgetting to wire it up fails closed.
        #[cfg(feature = "scanners")]
        "scan" => r.insert(Box::<scanner::ScanTool>::default()),

        other => {
            if let Some(family) = sec_tool_family(other) {
                // Known 016 name whose feature is off in this build (the `#[cfg]` arms above did not
                // match). Register the refusing stub rather than dropping it.
                r.insert(Box::new(NotCompiledIn::new(other, family)));
            }
        }
    }
}

/// The stub registered for a 016 tool whose Cargo feature is compiled out.
///
/// It exists so that "this build cannot do that" and "there was nothing to find" can never be
/// confused. Without it, a scenario listing `scan` against a binary built without `--features
/// scanners` would silently register nothing, the model would see no such tool, and the run would
/// complete looking clean.
pub struct NotCompiledIn {
    name: String,
    family: &'static str,
}

impl NotCompiledIn {
    pub fn new(name: &str, family: &'static str) -> Self {
        NotCompiledIn {
            name: name.to_string(),
            family,
        }
    }
}

#[async_trait::async_trait]
impl Tool for NotCompiledIn {
    fn name(&self) -> &'static str {
        // The registry keys on the &'static str returned here, so leak the owned name once at
        // registration. There is exactly one stub per compiled-out tool per process.
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name.clone(),
            description: format!(
                "UNAVAILABLE in this build: requires the `{}` feature. Calling this reports its \
                 absence; it does not scan.",
                self.family
            ),
            parameters: serde_json::json!({ "type": "object", "properties": {} }),
        }
    }

    async fn call(&self, _arguments: serde_json::Value, _sandbox: &Sandbox) -> ToolResult {
        let reason = outcome::UnavailableReason::NotCompiledIn {
            family: self.family.to_string(),
        };
        outcome::audit_refusal(&self.name, &reason);
        ToolOutcome::<()>::unavailable(reason).into_tool_result(|_| String::new())
    }
}

/// Re-register the security tools with the session's ledger and scanner grants
/// (016-native-tools US2/US3).
///
/// [`registry_for`] can build these from a name alone, but only with defaults: the ledger under the
/// working directory, a pid-derived run id, and — for `scan` — **no grants at all**. This replaces
/// them with instances that know the session's configuration. Registration is last-wins, so calling
/// this after the registry is built is the whole mechanism.
///
/// The `scan` default is the one to understand: an unconfigured scan tool holds an empty grant list
/// and refuses every call with `NotGranted`. Forgetting to call this therefore fails closed
/// (Constitution I) — the failure mode is "bee would not run the scanner", never "bee ran a scanner
/// nobody authorised".
///
/// Both front-ends call this at the same point in their sequence: after grant resolution, so a
/// scanner a skill widened the policy to include is visible, and before the policy is moved into the
/// scope, which is the last moment it can be read.
// `policy` is read only to resolve scanner grants, so a build without `scanners` does not use it.
#[cfg_attr(not(feature = "scanners"), allow(unused_variables))]
pub fn configure_security_tools(
    registry: &mut ToolRegistry,
    security: &crate::security::SecurityConfig,
    policy: Option<&bee_core::Policy>,
    run_id: &str,
) {
    #[cfg(feature = "findings")]
    {
        use crate::findings::Ledger;
        let ledger = Ledger::resolve(security.findings_dir.as_deref());

        if registry.contains("record_finding") {
            registry.insert(Box::new(finding::RecordFinding::new(
                ledger.clone(),
                run_id,
            )));
        }
        if registry.contains("list_findings") {
            registry.insert(Box::new(finding::ListFindings::new(ledger.clone())));
        }
        #[cfg(feature = "cvss")]
        if registry.contains("cvss") {
            // The scoring tool writes `Scored` events, so it needs the same ledger the recorder
            // uses — otherwise a score would land in a different file from the finding it scores.
            registry.insert(Box::new(cvss::CvssTool::new(ledger.clone())));
        }
        #[cfg(feature = "scanners")]
        if registry.contains("scan") {
            let grants = crate::scanners::grants_from_policy(policy, security);
            registry.insert(Box::new(scanner::ScanTool::new(grants, ledger, run_id)));
        }
    }
}
