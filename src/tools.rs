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
pub mod finish;
#[cfg(feature = "source")]
pub mod hunt;
pub mod outcome;
pub mod render;
#[cfg(feature = "repro")]
pub mod repro;
pub mod search;
pub mod skill;
#[cfg(feature = "source")]
pub mod source;

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
#[cfg(feature = "intercept")]
pub mod http_fuzz;
#[cfg(feature = "intercept")]
pub mod http_get;
#[cfg(feature = "intercept")]
pub mod http_history;
#[cfg(feature = "intercept")]
pub mod http_intercept;
#[cfg(feature = "intercept")]
pub mod http_leads;
#[cfg(feature = "intercept")]
pub mod http_replay;
#[cfg(feature = "intercept")]
pub mod http_send;
#[cfg(feature = "intercept")]
pub mod http_sitemap;
#[cfg(feature = "findings")]
pub mod receipt;
#[cfg(feature = "scanners")]
pub mod scanner;

pub use crate::provider::Provenance;
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

/// How a headless run ends (025 US3). **Not** in `DEFAULT_TOOLS`: the episode adds it to a standard
/// run's surface itself, unless the scenario says `finish = false`.
pub const RUN_TOOLS: &[&str] = &["finish"];

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
    "receipt_get",
    "source_pin",
    "source_read",
    "hunt_checkpoint",
    "hunt_resume",
    "repro_run",
];

/// The external scanner tier (016-native-tools). Listing `scan` is necessary but **not sufficient**
/// to run a scanner: the episode's policy must also carry an inode-pinned `ExecPolicy.allow` grant
/// for the specific binary, or the tool refuses with `NotGranted` (FR-008).
pub const SCANNER_TOOLS: &[&str] = &["scan"];

/// The HTTP(S) interception tools (019-http-intercept). Opt-in like the security tools; they answer
/// only in a session whose policy declares `[policy.http]`, and refuse with `interceptor_unavailable`
/// anywhere else. Compiled out (no `intercept` feature) they register as `NotCompiledIn` stubs.
pub const HTTP_TOOLS: &[&str] = &[
    "http_scope",
    "http_send",
    "http_get",
    "http_history",
    "http_replay",
    "http_sitemap",
    "http_fuzz",
    "http_intercept",
    "http_leads",
];

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
        || RUN_TOOLS.contains(&name)
        || RENDER_TOOLS.contains(&name)
        || SKILL_TOOLS.contains(&name)
        || SEC_TOOLS.contains(&name)
        || SCANNER_TOOLS.contains(&name)
        || HTTP_TOOLS.contains(&name)
        || (cfg!(feature = "vm-test") && name == "http_debug")
}

/// The Cargo feature each 016 tool needs, for the `NotCompiledIn` message. Covers only the tools
/// currently in [`SEC_TOOLS`]/[`SCANNER_TOOLS`]; entries for the unbuilt tools land with their
/// phases, alongside the tools themselves.
pub fn sec_tool_family(name: &str) -> Option<&'static str> {
    match name {
        "ast_grep" => Some("astgrep"),
        "git_log" => Some("gitlog"),
        "cvss" => Some("cvss"),
        "record_finding" | "list_findings" | "receipt_get" => Some("findings"),
        "scan" => Some("scanners"),
        n if HTTP_TOOLS.contains(&n) => Some("intercept"),
        "repro_run" => Some("repro"),
        "source_pin" | "source_read" | "hunt_checkpoint" | "hunt_resume" => Some("source"),
        _ => None,
    }
}

/// The outcome of one tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Durable harness-issued receipt, when evidence capture is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
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
    /// Where `content` came from, which decides whether it reaches the model inside an
    /// `<untrusted-data>` envelope (019 P1). Defaults to `Harness`: a tool must opt its output *in* to
    /// being treated as data, and every path that relays child or remote bytes does.
    #[serde(default, skip_serializing_if = "Provenance::is_harness")]
    pub provenance: Provenance,
}

impl ToolResult {
    /// A successful, non-truncated text result.
    pub fn ok(content: impl Into<String>) -> Self {
        ToolResult {
            receipt_id: None,
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
            provenance: Provenance::Harness,
        }
    }

    /// An error result (bad args, denial, missing file, …). `is_error = true`.
    pub fn error(content: impl Into<String>) -> Self {
        ToolResult {
            receipt_id: None,
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
            provenance: Provenance::Harness,
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

    /// A call a hook refused before it ran (024 FR-031): `is_error`, and phrased so the model can tell
    /// it from a failure of the tool — the tool never ran.
    pub fn refused_by_hook(reason: &str) -> Self {
        ToolResult::error(format!("refused by hook: {reason} (the tool did not run)"))
    }

    /// The FR-016 malformed-arguments result: `"<tool>: invalid arguments: <detail>"`.
    pub fn invalid_args(tool: &str, detail: impl std::fmt::Display) -> Self {
        ToolResult::error(format!("{tool}: invalid arguments: {detail}"))
    }

    /// This result, with its content marked as coming from `provenance` (019 P1).
    pub fn with_provenance(self, provenance: Provenance) -> Self {
        ToolResult { provenance, ..self }
    }
}

/// A tool the agent may call. Object-safe so tools live in a `Box<dyn Tool>` registry.
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    /// The tool's stable name (matches [`ToolCall::name`]).
    fn name(&self) -> &'static str;

    /// The JSON-Schema-bearing schema advertised to the model.
    fn schema(&self) -> ToolSchema;

    /// The MCP server this tool forwards to, if it is one. A call to it owns the kernel events of
    /// that server's own process (024 FR-027).
    fn mcp_server(&self) -> Option<&str> {
        None
    }
    /// Trusted implementation contract. Mutations and unknown tools never replay by default.
    fn durable_contract(&self) -> ToolContract {
        ToolContract {
            version: 1,
            recovery: crate::session::durable::RecoveryPolicy::NeverReplay,
        }
    }

    /// Execute inside `sandbox`. MUST NOT panic on bad `arguments` — return an error result.
    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult;
    #[cfg(feature = "durable-sessions")]
    fn supports_journal(&self) -> bool {
        false
    }
    #[cfg(feature = "durable-sessions")]
    async fn call_journaled(
        &self,
        _arguments: serde_json::Value,
        _sandbox: &mut Sandbox,
        _journal: &mut crate::session::driver::journal::Journal,
    ) -> Result<ToolResult, crate::session::driver::DriverError> {
        Err(crate::session::driver::DriverError::Refused(
            "tool has no checkpoint executor".into(),
        ))
    }
}

/// The session dependencies a tool is built with (024 FR-013, research R4).
///
/// The registry holds one, and [`ToolRegistry::register`] — the only constructor of a built-in tool —
/// builds every tool from it. A dependency that is absent is not an error: the tool registers and
/// fails closed when called (an HTTP tool without an Interceptor refuses `interceptor_unavailable`, a
/// `scan` without grants refuses `NotGranted`), exactly as it would have at start-up.
#[derive(Clone, Default)]
pub struct ToolDeps {
    /// The planted CTF flag (US3). `submit_flag` is registered only when it is set.
    pub ctf_flag: Option<String>,
    #[cfg(feature = "findings")]
    pub evidence: Option<crate::evidence::EvidenceStore>,
    #[cfg(feature = "repro")]
    pub reproductions: std::collections::BTreeMap<String, crate::security::ReproductionProfile>,
    /// Discovered skills (006). `skill` is registered only when they are set.
    pub skills: Option<std::sync::Arc<crate::skills::SkillRegistry>>,
    /// The finding ledger the security tools write to (016). `None` is each tool's own default: the
    /// ledger under the working directory.
    #[cfg(feature = "findings")]
    pub ledger: Option<crate::findings::Ledger>,
    /// The run id findings are recorded under. `None` is each tool's own default.
    #[cfg(feature = "findings")]
    pub run_id: Option<String>,
    /// The security configuration scanner grants are derived from, kept so the grants can be
    /// recomputed when the policy widens ([`ToolDeps::with_policy`]).
    #[cfg(feature = "scanners")]
    pub security: crate::security::SecurityConfig,
    /// The scanners the active policy grants. Empty means `scan` refuses every call.
    #[cfg(feature = "scanners")]
    pub scanner_grants: Vec<crate::scanners::ScannerGrant>,
    /// The session's HTTP interception proxy (019). `None` means the HTTP tools refuse.
    #[cfg(feature = "intercept")]
    pub interceptor: Option<crate::intercept::sidecar::Interceptor>,
}

impl ToolDeps {
    /// Dependencies holding only a CTF flag — what a registry built from a name list needs.
    pub fn with_flag(flag: Option<&str>) -> ToolDeps {
        ToolDeps {
            ctf_flag: flag.map(str::to_string),
            ..ToolDeps::default()
        }
    }

    /// These dependencies configured for a session's security tooling (016): its ledger, its run id
    /// and the scanners `policy` grants. Replaces the former `configure_security_tools` pass.
    // Each field is behind its own feature, so a slim build reads none of the arguments.
    #[cfg_attr(
        not(feature = "findings"),
        allow(unused_variables, unused_mut, clippy::needless_pass_by_value)
    )]
    pub fn with_security(
        mut self,
        security: &crate::security::SecurityConfig,
        #[allow(unused_variables)] policy: Option<&bee_core::Policy>,
        run_id: &str,
    ) -> ToolDeps {
        #[cfg(feature = "findings")]
        {
            self.ledger = Some(crate::findings::Ledger::resolve(
                security.findings_dir.as_deref(),
            ));
            self.run_id = Some(run_id.to_string());
            if self.evidence.is_none() {
                let root = security
                    .findings_dir
                    .as_ref()
                    .map(|p| p.join("evidence"))
                    .unwrap_or_else(|| ".bee/evidence".into());
                self.evidence = Some(crate::evidence::EvidenceStore::new(root, run_id));
            }
        }
        #[cfg(feature = "scanners")]
        {
            self.security = security.clone();
            self.scanner_grants = crate::scanners::grants_from_policy(policy, security);
        }
        #[cfg(feature = "repro")]
        {
            self.reproductions = security.reproductions.clone();
        }
        self
    }

    /// These dependencies after the active policy became `policy`: scanner grants are recomputed, so a
    /// scanner a grant just allowed is usable by `scan` (024 US4). Nothing else depends on the policy.
    #[cfg_attr(not(feature = "scanners"), allow(unused_variables, unused_mut))]
    pub fn with_policy(mut self, policy: &bee_core::Policy) -> ToolDeps {
        #[cfg(feature = "scanners")]
        {
            self.scanner_grants = crate::scanners::grants_from_policy(Some(policy), &self.security);
        }
        self
    }

    /// These dependencies with the session's Interceptor (019).
    #[cfg(feature = "intercept")]
    pub fn with_interceptor(mut self, icpt: crate::intercept::sidecar::Interceptor) -> ToolDeps {
        self.interceptor = Some(icpt);
        self
    }
}

/// A name [`ToolRegistry::register`] does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTool(pub String);

impl std::fmt::Display for UnknownTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown tool: {}", self.0)
    }
}

impl std::error::Error for UnknownTool {}

/// Which session dependencies one tool was built with — booleans and counts, never their contents
/// (024 FR-015). `None` means the tool does not use that dependency.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DepsSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctf_flag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_grants: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interceptor: Option<bool>,
}

/// One tool the model can call, as [`ToolRegistry::surface`] reports it.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceEntry {
    pub name: String,
    pub schema: ToolSchema,
    pub deps: DepsSummary,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolContract {
    pub version: u32,
    pub recovery: crate::session::durable::RecoveryPolicy,
}

#[cfg(feature = "findings")]
pub mod durable;

/// A name→tool map plus the schema list handed to the model each turn.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn Tool>>,
    deps: std::sync::Arc<ToolDeps>,
    /// The tools built by [`register`](Self::register), which [`set_deps`](Self::set_deps) rebuilds.
    /// A tool placed with [`insert`](Self::insert) (an MCP proxy, a test double) is not in it.
    built: std::collections::BTreeSet<&'static str>,
}

impl ToolRegistry {
    /// Enable receipts for calls through this registry, including subsequently added tools.
    #[cfg(feature = "findings")]
    pub fn enable_evidence(&mut self, store: crate::evidence::EvidenceStore) {
        let mut deps = (*self.deps).clone();
        deps.evidence = Some(store);
        self.set_deps(std::sync::Arc::new(deps));
        self.register("receipt_get").expect("known receipt tool");
    }
    pub fn new() -> Self {
        ToolRegistry::default()
    }

    /// An empty registry whose tools will be built from `deps`.
    pub fn with_deps(deps: std::sync::Arc<ToolDeps>) -> Self {
        ToolRegistry {
            deps,
            ..ToolRegistry::default()
        }
    }

    /// The dependencies tools are built from.
    pub fn deps(&self) -> &std::sync::Arc<ToolDeps> {
        &self.deps
    }

    /// Replace the dependencies, and rebuild every tool [`register`](Self::register) built so each
    /// holds the new ones (a widened policy's scanner grants, an Interceptor that started after the
    /// tools were named). There is no second configuration pass to forget (024 research R4).
    pub fn set_deps(&mut self, deps: std::sync::Arc<ToolDeps>) {
        self.deps = deps;
        let names: Vec<&'static str> = self.built.iter().copied().collect();
        for name in names {
            // Every name in `built` was registered successfully, so it is known.
            let _ = self.register(name);
        }
    }

    /// Place a tool built elsewhere — an MCP proxy, a test double (last registration under a name
    /// wins). Built-in tools are constructed by [`register`](Self::register) instead.
    pub fn insert(&mut self, tool: Box<dyn Tool>) {
        self.built.remove(tool.name());
        self.tools.insert(tool.name(), tool);
    }

    /// Place a tool, chaining.
    pub fn with(mut self, tool: Box<dyn Tool>) -> Self {
        self.insert(tool);
        self
    }

    /// Build the built-in tool `name` from this registry's dependencies and register it (last wins).
    /// The only constructor of a non-MCP tool (024 FR-013): a tool registered at start-up, by a skill
    /// grant, or by escalation mid-session is built the same way and holds the same dependencies
    /// (FR-014). A 016 tool compiled out of this build registers its `NotCompiledIn` stub. `submit_flag`
    /// and `skill` register only when their dependency is set, and are otherwise a no-op.
    pub fn register(&mut self, name: &str) -> Result<(), UnknownTool> {
        let Some(tool) = build(name, &self.deps)? else {
            return Ok(());
        };
        let key = tool.name();
        self.tools.insert(key, tool);
        self.built.insert(key);
        #[cfg(feature = "findings")]
        if self.deps.evidence.is_some()
            && matches!(
                key,
                "source_pin" | "source_read" | "hunt_checkpoint" | "hunt_resume" | "repro_run"
            )
        {
            self.register("receipt_get")?;
        }
        Ok(())
    }

    /// True if a tool with `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// The MCP server tool `name` forwards to, if it is an MCP tool (024 FR-027).
    pub fn mcp_server(&self, name: &str) -> Option<&str> {
        self.tools.get(name).and_then(|t| t.mcp_server())
    }

    /// The schemas for all registered tools, in stable name order.
    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools.values().map(|t| t.schema()).collect()
    }

    /// Every tool the model can call now, with the dependencies each was built with (024 FR-015) —
    /// the one answer to "which tools, configured how". In the order [`schemas`](Self::schemas) offers
    /// them, so what is reported is what the model is shown.
    pub fn surface(&self) -> Vec<SurfaceEntry> {
        self.tools
            .iter()
            .map(|(name, tool)| SurfaceEntry {
                name: name.to_string(),
                schema: tool.schema(),
                deps: if self.built.contains(name) {
                    deps_summary(name, &self.deps)
                } else {
                    DepsSummary::default()
                },
            })
            .collect()
    }

    /// Unregister the tool `name` — a tool only an expired or released lease granted (024 FR-029).
    /// Returns whether one was registered.
    pub fn remove(&mut self, name: &str) -> bool {
        self.built.remove(name);
        self.tools.remove(name).is_some()
    }

    /// Drop every `mcp__…` tool. Used to rebuild the MCP set after a `tools/list_changed`
    /// notification (004-mcp-client, FR-043) — the bridge then re-registers the current tools.
    pub fn remove_mcp_tools(&mut self) {
        self.tools.retain(|name, _| !name.starts_with("mcp__"));
    }

    /// Execute a model-requested call. An unknown tool name yields an error result (fed back to the
    /// model), never a panic (FR-016).
    pub async fn execute(&self, call: &ToolCall, sandbox: &Sandbox) -> ToolResult {
        let result = self.execute_unrecorded(call, sandbox).await;
        #[cfg(feature = "findings")]
        if let Some(store) = self.deps.evidence.as_ref().filter(|_| {
            [
                "receipt_get",
                "source_pin",
                "source_read",
                "hunt_checkpoint",
                "hunt_resume",
                "repro_run",
            ]
            .iter()
            .any(|name| self.contains(name))
        }) {
            let store = store.clone();
            let call = call.clone();
            let observed = result.clone();
            let saved = tokio::task::spawn_blocking(move || store.record(&call, &observed)).await;
            let mut result = result;
            match saved {
                Ok(Ok(id)) => return result.with_receipt(id),
                error => {
                    // The effect may already have happened. Never imply it is safe to replay.
                    result.is_error = true;
                    result.content = format!("Evidence persistence failed after tool execution; do not automatically retry the effect: {error:?}\n{}", result.content);
                }
            }
            return result;
        }
        result
    }

    async fn execute_unrecorded(&self, call: &ToolCall, sandbox: &Sandbox) -> ToolResult {
        if let Err(error) = sandbox.check_cleanup() {
            return ToolResult::error(error);
        }
        match self.tools.get(call.name.as_str()) {
            Some(tool) => tool.call(call.arguments.clone(), sandbox).await,
            None => ToolResult::error(format!("unknown tool: {}", call.name)),
        }
    }
}

#[cfg(feature = "findings")]
impl ToolResult {
    pub(crate) fn with_receipt(mut self, id: String) -> Self {
        self.content = format!(
            "[Bee receipt: {id}; records tool output, not verification]\n{}",
            self.content
        );
        self.receipt_id = Some(id);
        self
    }
}

/// Build a registry holding just the `enabled` tools (validated names; unknown names are dropped —
/// [`crate::scenario::Scenario`] validation already rejects them before a run). `flag` is the CTF
/// sentinel value (US3): `submit_flag` needs it to check submissions, so it is only registered when
/// `flag` is `Some`. A caller with more dependencies builds [`ToolRegistry::with_deps`] and registers
/// through it.
pub fn registry_for(enabled: &[String], flag: Option<&str>) -> ToolRegistry {
    let mut r = ToolRegistry::with_deps(std::sync::Arc::new(ToolDeps::with_flag(flag)));
    for name in enabled {
        let _ = r.register(name);
    }
    r
}

/// Construct the built-in tool `name` from `deps`. `Ok(None)` is a known tool whose dependency is
/// absent and which therefore registers nothing (`submit_flag` without a flag, `skill` without
/// skills).
// Most arms are behind a family feature, so a slim build leaves `deps` unread in several of them.
#[cfg_attr(
    not(all(feature = "findings", feature = "intercept")),
    allow(unused_variables)
)]
fn build(name: &str, deps: &ToolDeps) -> Result<Option<Box<dyn Tool>>, UnknownTool> {
    let tool: Box<dyn Tool> = match name {
        "bash" => Box::new(bash::Bash),
        "read_file" => Box::new(files::ReadFile),
        "write_file" => Box::new(files::WriteFile),
        "list_directory" => Box::new(files::ListDirectory),
        "submit_flag" => match &deps.ctf_flag {
            Some(value) => Box::new(ctf::SubmitFlag::new(value.clone())),
            None => return Ok(None),
        },
        "give_up" => Box::new(ctf::GiveUp),
        "finish" => Box::new(finish::Finish),
        "render" => Box::new(render::RenderTool::new()),
        "search" => Box::new(search::Search),
        "skill" => match &deps.skills {
            Some(skills) => Box::new(skill::SkillTool::new(skills.clone())),
            None => return Ok(None),
        },

        // ── 016-native-tools ───────────────────────────────────────────────────────────────────
        // Each arm builds the real tool when its family is compiled in, and the arm below the match
        // builds a refusing stub when it is not. The stub is the point: a compiled-out security tool
        // must announce its absence, never answer as though it ran (Constitution I).
        #[cfg(feature = "astgrep")]
        "ast_grep" => Box::new(astgrep::AstGrepTool),
        #[cfg(feature = "gitlog")]
        "git_log" => Box::new(gitlog::GitLogTool),
        // The scoring tool writes `Scored` events, so it needs the same ledger the recorder uses —
        // otherwise a score would land in a different file from the finding it scores.
        #[cfg(all(feature = "cvss", feature = "findings"))]
        "cvss" => match &deps.ledger {
            Some(ledger) => Box::new(cvss::CvssTool::new(ledger.clone())),
            None => Box::<cvss::CvssTool>::default(),
        },
        #[cfg(all(feature = "cvss", not(feature = "findings")))]
        "cvss" => Box::<cvss::CvssTool>::default(),
        // Without a session ledger the ledger tools use `.bee/findings` under the working directory
        // and a pid-derived run id: a working tool, not a placeholder.
        #[cfg(feature = "findings")]
        "record_finding" => match (&deps.ledger, &deps.run_id) {
            (Some(ledger), Some(run_id)) => Box::new(
                finding::RecordFinding::new(ledger.clone(), run_id.clone())
                    .with_evidence(deps.evidence.clone()),
            ),
            _ => Box::new(finding::RecordFinding::default().with_evidence(deps.evidence.clone())),
        },
        #[cfg(feature = "findings")]
        "receipt_get" => Box::new(match &deps.evidence {
            Some(store) => receipt::ReceiptGet::new(store.clone()),
            None => receipt::ReceiptGet::unconfigured(),
        }),
        #[cfg(feature = "source")]
        "source_pin" => Box::new(source::SourceTool::new("source_pin", deps.evidence.clone())),
        #[cfg(feature = "source")]
        "source_read" => Box::new(source::SourceTool::new(
            "source_read",
            deps.evidence.clone(),
        )),
        #[cfg(feature = "source")]
        "hunt_checkpoint" => Box::new(hunt::HuntTool::new(
            "hunt_checkpoint",
            deps.evidence.clone(),
        )),
        #[cfg(feature = "source")]
        "hunt_resume" => Box::new(hunt::HuntTool::new("hunt_resume", deps.evidence.clone())),
        #[cfg(feature = "repro")]
        "repro_run" => Box::new(repro::ReproRun {
            profiles: deps.reproductions.clone(),
            evidence: deps.evidence.clone(),
            source_worker: None,
        }),
        #[cfg(feature = "findings")]
        "list_findings" => match &deps.ledger {
            Some(ledger) => Box::new(finding::ListFindings::new(ledger.clone())),
            None => Box::<finding::ListFindings>::default(),
        },
        // `scan` holds exactly the grants the active policy gives. With none it refuses with
        // `NotGranted`: forgetting to supply them fails closed — the failure mode is "bee would not
        // run the scanner", never "bee ran a scanner nobody authorised".
        #[cfg(feature = "scanners")]
        "scan" => match (&deps.ledger, &deps.run_id) {
            (Some(ledger), Some(run_id)) => Box::new(scanner::ScanTool::new(
                deps.scanner_grants.clone(),
                ledger.clone(),
                run_id.clone(),
            )),
            _ => Box::<scanner::ScanTool>::default(),
        },
        // 019: built with the session's Interceptor; without one — a session with no
        // `[policy.http]` — they refuse `interceptor_unavailable`.
        #[cfg(feature = "vm-test")]
        "http_debug" => match http::tool("http_debug", deps.interceptor.clone()) {
            Some(t) => t,
            None => return Err(UnknownTool(name.to_string())),
        },
        #[cfg(feature = "intercept")]
        n if HTTP_TOOLS.contains(&n) => match http::tool(n, deps.interceptor.clone()) {
            Some(t) => t,
            None => return Err(UnknownTool(name.to_string())),
        },

        other => match sec_tool_family(other) {
            // Known 016 name whose feature is off in this build (the `#[cfg]` arms above did not
            // match). Register the refusing stub rather than dropping it.
            Some(family) => Box::new(NotCompiledIn::new(other, family)),
            None => return Err(UnknownTool(other.to_string())),
        },
    };
    Ok(Some(tool))
}

/// The dependencies the built-in tool `name` uses, and whether `deps` supplies them.
fn deps_summary(name: &str, deps: &ToolDeps) -> DepsSummary {
    let mut s = DepsSummary::default();
    match name {
        "submit_flag" => s.ctf_flag = Some(deps.ctf_flag.is_some()),
        "skill" => s.skills = Some(deps.skills.as_ref().map_or(0, |k| k.iter().count())),
        #[cfg(feature = "findings")]
        "record_finding" | "list_findings" | "cvss" => s.ledger = Some(deps.ledger.is_some()),
        #[cfg(feature = "scanners")]
        "scan" => {
            s.ledger = Some(deps.ledger.is_some());
            s.scanner_grants = Some(deps.scanner_grants.len());
        }
        #[cfg(feature = "intercept")]
        n if HTTP_TOOLS.contains(&n) || n == "http_debug" => {
            s.interceptor = Some(deps.interceptor.is_some());
        }
        _ => {}
    }
    s
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
