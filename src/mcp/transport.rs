//! Sandboxed stdio transport for MCP servers (004-mcp-client, T017).
//!
//! The child is built with [`Sandbox::tool_command`] — the same path as `bash` and the file tools —
//! so it joins the episode's scope cgroup, is env-stripped, and is hardened. The resulting
//! `std::process::Command` (which carries the cgroup-join `pre_exec` closure) is converted to a
//! `tokio::process::Command` and handed to rmcp's [`TokioChildProcess`].
//!
//! The R3 spike (`episode::mcp_cgroup_spike`) proves the cgroup-join survives rmcp's `process-wrap`
//! wrapper (Constitution III); source analysis shows a wrapper-less `CommandWrap` preserves the
//! inner command's `pre_exec` (research R3/§3.2).

use std::process::Stdio;

use rmcp::transport::TokioChildProcess;

use crate::sandbox::Sandbox;

use super::config::McpServerConfig;

/// The call context an MCP stdio server runs under: `mcp:<name>` for its lifetime.
pub fn mcp_call(name: &str) -> crate::sandbox::CallContext {
    crate::sandbox::CallContext {
        call_id: format!("mcp:{name}"),
        turn: 0,
        origin: crate::sandbox::CallOrigin::Mcp(name.to_string()),
    }
}

/// Spawn a stdio MCP server as a sandboxed child and wrap it as an rmcp child-process transport.
///
/// `stderr` is discarded (stdout is the JSON-RPC framing channel); the child is killed on drop.
/// Returns the transport ready to hand to `().serve(...)`, and the child's `tgid`: the server's own
/// kernel events are attributed to it by that (024 FR-027, research R8).
pub fn spawn_stdio(
    sandbox: &Sandbox,
    config: &McpServerConfig,
) -> Result<(TokioChildProcess, Option<u32>), String> {
    let command = config
        .command
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            format!(
                "mcp server '{}': stdio transport requires `command`",
                config.name
            )
        })?;

    // Same spawn path as built-in tools: cgroup join (under enforce) + env strip + hardening. The
    // server is its own long-lived caller, `mcp:<name>`, so under interception its traffic carries
    // that attribution rather than whichever tool call happened to be running (019 T042).
    let std_cmd = sandbox
        .tool_command_as(&mcp_call(&config.name), command, &config.args)
        .map_err(|e| format!("mcp server '{}': {e}", config.name))?;

    let mut cmd = tokio::process::Command::from(std_cmd);
    for (k, v) in &config.env {
        cmd.env(k, v);
    }
    cmd.kill_on_drop(true);

    // Use the builder so stderr can be silenced without disturbing the piped stdin/stdout framing.
    TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn()
        .map(|(proc, _stderr)| {
            let tgid = proc.id();
            (proc, tgid)
        })
        .map_err(|e| format!("mcp server '{}': spawn {command}: {e}", config.name))
}
