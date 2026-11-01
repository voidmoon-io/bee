//! The bee harness library — drives an LLM agent through a multi-turn tool loop whose tools execute
//! inside a bee scope, producing an auditable [`transcript::EpisodeTranscript`].
//!
//! This is the library half of the application package. The commands that drive it — `bee run`,
//! `bee repl`, `bee metrics` — are in `src/app/`, reached only from `src/main.rs`. One package,
//! because the library has exactly one consumer (ADR-0002).
//!
//! ## Build modes
//!
//! * **default** — tools run as hardened, credential-stripped **host** processes with no kernel
//!   scope (`Sandbox::Host`). Enough for the offline [`provider::MockModel`] tests and the live
//!   provider smoke; keeps the workspace default build free of the bpf toolchain (Constitution V,
//!   SC-005).
//! * **`--features enforce`** — additionally builds `bee-userspace`'s eBPF-LSM path so each tool
//!   call runs inside a real bee scope and kernel denials are drained into the transcript
//!   (`Sandbox::Enforced`). This is the mode the VM enforcement case exercises.
//!
//! The multi-turn loop, tool execution, retry/backoff, truncation, and audit correlation all live
//! here — not in Rig, which is confined behind the [`provider::Model`] seam (research H2/H3).

#![warn(rust_2018_idioms)]

// Structural code search (016-native-tools US1). Gated: the grammars are compiled C, so a build that
// wants none of them compiles none of them.
#[cfg(feature = "astgrep")]
pub mod astgrep;
pub mod batch;
// One tool call, start to finish — the only copy of the call protocol (024 FR-017).
pub mod call;
#[cfg(feature = "concurrent")]
pub mod concurrent;
pub mod config;
// Context budget and compaction for long runs (025-long-run-resilience).
pub mod context;
pub mod episode;
#[cfg(feature = "findings")]
pub mod evidence;
// The finding ledger (016-native-tools US2). Gated: it is the substrate the security tools write
// into, and a build that selects none of them has nothing to record.
#[cfg(feature = "findings")]
pub mod findings;
// Repository history (016-native-tools US5). Gated: `gix` is a large dependency tree, and a build
// that does not ask a repository anything should not carry a git implementation.
#[cfg(feature = "gitlog")]
pub mod gitlog;
pub mod grants;
pub mod hooks;
// HTTP(S) interception (019-http-intercept). Gated: the proxy worker, its TLS stack and the exchange
// store exist only in a build that asked for them (SC-009).
#[cfg(feature = "source")]
pub mod hunt;
#[cfg(feature = "intercept")]
pub mod intercept;
pub mod mcp;
pub mod metrics;
pub mod operator;
pub mod provider;
// Proxy-layer events (019). Ungated: transcripts carry them in every build.
pub mod proxy_event;
pub mod render_api;
pub mod render_spec;
pub mod repl;
#[cfg(feature = "repro")]
pub mod reproduction;
// Terminal-safety for untrusted text. Ungated: every front-end and the consent prompt need it.
pub mod safe_text;
pub mod sandbox;
// SARIF ingestion for the external scanner tier (016-native-tools US3).
#[cfg(feature = "scanners")]
pub mod sarif;
// External scanner adapters (016-native-tools US3).
#[cfg(feature = "scanners")]
pub mod scanners;
pub mod scenario;
pub mod search;
#[cfg(feature = "source")]
pub mod source;
// Operator configuration for the security tooling (016-native-tools). Ungated: plain data, so a
// configuration file keeps parsing on a build that compiled none of the tools.
pub mod security;
// The Session builder: one assembly of a session for every entry point (024 FR-006).
pub mod session;
pub mod skills;
pub mod stuck;
pub mod tools;
pub mod transcript;
// The top of a model turn: lease expiry, release, MCP refresh (024 FR-028–FR-030).
pub mod turn;
// Full-screen TUI front-end (008-grid-tui, M3–M4). Only compiled with `--features tui`.
#[cfg(feature = "tui")]
pub mod tui;
// The visual permission gate (009). Ungated: the render tool, which is where the gate runs, exists
// in every build.
pub mod visual_gate;
pub mod viz;

pub use batch::{run_batch, BatchConfig, BatchError, BatchResult};
#[cfg(feature = "concurrent")]
pub use concurrent::run_concurrent;
pub use config::{ProviderConfig, ProviderType};
pub use episode::{
    run_episode, run_episode_with, run_loop, EpisodeOptions, LoopOptions, ProgressSink,
};
pub use mcp::{McpPolicy, McpServerConfig, McpTransport};
pub use metrics::{CallRecord, Recorder};
pub use provider::{
    model_from_config, Conversation, Message, Model, ModelError, ToolCall, ToolSchema, Turn,
};
pub use render_spec::RenderSpec;
pub use repl::{run_repl, ReplConfig, ReplOutput, ReplSession};

/// Mark the current process **non-dumpable** (FR-018, research H7): `/proc/<pid>/environ`, `mem`,
/// and `maps` become root-only, so a **same-uid** sandboxed tool child cannot read the still-in-
/// memory provider key from the harness. Call once at startup. Env-stripping (the primary defense)
/// happens per-child in [`sandbox`]; this closes the `/proc/self` read path.
pub fn set_non_dumpable() -> std::io::Result<()> {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` is a simple, side-effect-free process attribute set.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
pub use sandbox::Sandbox;
pub use scenario::Scenario;
pub use skills::{Skill, SkillRegistry, SkillRequires, SkillSource};
pub use tools::{Tool, ToolRegistry, ToolResult};
pub use transcript::{
    enforcement_trace, EnforcementEntry, EpisodeStatus, EpisodeTranscript, ScoreReport,
};

pub mod python;
