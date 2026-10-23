//! `McpBridge` — owns the connected MCP servers for one episode/REPL session and registers their
//! tools into the shared [`ToolRegistry`] (004-mcp-client).
//!
//! The bridge holds each server's `rmcp` [`RunningService`] (which owns the stdio child + background
//! task); dropping the bridge kills the children (kill-on-drop). `McpToolProxy`s in the registry
//! hold only a cheap [`Peer`] clone, so a late call after teardown returns a disconnected error
//! (FR-042).
//!
//! ## `tools/list_changed` (FR-043)
//! Each connected server is served with a [`NotifyHandler`] whose `on_tool_list_changed` re-fetches
//! the tool list and updates a shared cache, then sets the bridge-wide **dirty** flag. The agent
//! loop calls [`McpBridge::take_dirty`] each turn and, when set, re-registers the current tools so
//! the change reaches the model on its next turn.
//!
//! ## Attribution (024 FR-027)
//! A stdio server runs in the session's tool scope for its whole lifetime. Its own process's kernel
//! events are told apart by `tgid`, recorded at spawn and exposed by [`McpBridge::server_tgids`]. A
//! call made to the server keeps them in its audit, so its denials are fed back and can escalate;
//! otherwise the session records them under the server, never in an unrelated open call's audit.
//! Limits, until MCP servers run in their own scope (018-subagent-scopes):
//! - **processes a server spawns are not attributed**: their events stay in the tool scope's stream,
//!   and land in whichever call is open;
//! - the `tgid` is the pid in bee's own PID namespace. Inside a separate one (bee in a container) it
//!   does not match the kernel's, and server events fall back to the open call;
//! - a server that exits keeps its `tgid` entry, so a process that later reuses the pid is filed
//!   under the server.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::client::ClientHandler;
use rmcp::model::Tool as RmcpTool;
use rmcp::service::{NotificationContext, Peer, RoleClient, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::ServiceExt;

use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::ToolRegistry;

use super::config::{McpServerConfig, McpTransport};
use super::policy::McpPolicy;
use super::proxy::{tool_schema, McpToolProxy};
use super::transport::spawn_stdio;

/// Stdio spawn + `initialize` handshake budget (NFR-005).
const STDIO_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Remote TCP + TLS + `initialize` handshake budget (NFR-005).
const REMOTE_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

/// A server's current tools: `(bare_name, namespaced_schema)`. Shared between the server's
/// [`NotifyHandler`] (which refreshes it on `tools/list_changed`) and the bridge (which reads it to
/// (re-)register proxies).
type SharedTools = Arc<Mutex<Vec<(String, ToolSchema)>>>;

/// Apply `allowed_tools`/`denied_tools` (FR-039) and namespace the surviving schemas (FR-036).
fn filter_tools(cfg: &McpServerConfig, tools: &[RmcpTool]) -> Vec<(String, ToolSchema)> {
    tools
        .iter()
        .filter(|t| cfg.tool_allowed(&t.name))
        .map(|t| (t.name.to_string(), tool_schema(&cfg.name, t)))
        .collect()
}

/// The `rmcp` client handler for one server. On a `tools/list_changed` notification it re-fetches the
/// tool list, re-filters/namespaces it into the shared cache, and flags the bridge dirty (FR-043).
struct NotifyHandler {
    cfg: McpServerConfig,
    tools: SharedTools,
    dirty: Arc<AtomicBool>,
    refreshing: tokio::sync::Mutex<()>,
}

impl ClientHandler for NotifyHandler {
    async fn on_tool_list_changed(&self, context: NotificationContext<RoleClient>) {
        let Ok(_refresh) = self.refreshing.try_lock() else {
            return;
        };
        let deadline = tokio::time::Instant::now() + STDIO_STARTUP_TIMEOUT;
        match discover_tools(&context.peer, deadline).await {
            Ok(tools) => {
                *self.tools.lock().expect("mcp tools lock") = filter_tools(&self.cfg, &tools)
            }
            Err(error) => {
                self.tools.lock().expect("mcp tools lock").clear();
                eprintln!("MCP tool refresh failed for {}: {error}", self.cfg.name);
            }
        }
        self.dirty.store(true, Ordering::SeqCst);
    }
}

// Bounds apply to discovery after transport decoding; rmcp's HTTP response decoder has its own
// allocation behavior and this does not claim a wire-level memory limit.
const DISCOVERY_PAGES: usize = 32;
const DISCOVERY_TOOLS: usize = 1024;
const DISCOVERY_BYTES: usize = 4 * 1024 * 1024;

struct DiscoveryBudget(usize);

impl std::io::Write for DiscoveryBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("MCP discovery byte budget exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn discover_tools(
    peer: &Peer<RoleClient>,
    deadline: tokio::time::Instant,
) -> Result<Vec<RmcpTool>, String> {
    let mut cursor = None;
    let mut cursors = std::collections::BTreeSet::new();
    let mut tools = Vec::new();
    let mut budget = DiscoveryBudget(DISCOVERY_BYTES);
    for _ in 0..DISCOVERY_PAGES {
        let params = cursor
            .take()
            .map(|cursor| rmcp::model::PaginatedRequestParams::default().with_cursor(Some(cursor)));
        let page = tokio::time::timeout_at(deadline, peer.list_tools(params))
            .await
            .map_err(|_| "MCP discovery deadline exceeded".to_string())?
            .map_err(|e| e.to_string())?;
        if tools.len().saturating_add(page.tools.len()) > DISCOVERY_TOOLS {
            return Err("MCP discovery tool count exceeded".into());
        }
        for tool in &page.tools {
            serde_json::to_writer(&mut budget, tool).map_err(|e| e.to_string())?;
        }
        tools.extend(page.tools);
        match page.next_cursor {
            None => return Ok(tools),
            Some(next) => {
                if next.len() > 4096 {
                    return Err("MCP discovery cursor exceeds byte budget".into());
                }
                if !cursors.insert(next.clone()) {
                    return Err("MCP discovery repeated a cursor".into());
                }
                cursor = Some(next);
            }
        }
    }
    Err("MCP discovery page count exceeded".into())
}

/// Lifecycle state of a configured MCP server.
#[derive(Debug, Clone)]
pub enum ServerStatus {
    /// Connected and its (filtered) tools registered.
    Connected,
    /// Was connected; the child crashed or the peer died (FR-042).
    Disconnected,
    /// Never became usable (spawn/initialize failed or timed out); carries the reason.
    Failed(String),
}

impl ServerStatus {
    pub fn label(&self) -> String {
        match self {
            ServerStatus::Connected => "connected".into(),
            ServerStatus::Disconnected => "disconnected".into(),
            ServerStatus::Failed(why) => format!("failed: {why}"),
        }
    }
}

/// The live `rmcp` handle for a connected server. Held for its RAII kill-on-drop; the `peer` is
/// cloned into each tool proxy.
struct ServerHandle {
    /// Owns the child + background task (+ the [`NotifyHandler`]). Held, not read — dropping it tears
    /// the connection down.
    #[allow(dead_code)]
    service: RunningService<RoleClient, NotifyHandler>,
    peer: Peer<RoleClient>,
}

/// One configured server and whatever we learned when connecting.
pub struct ConnectedServer {
    config: McpServerConfig,
    /// The server's current (filtered, namespaced) tools — refreshed on `tools/list_changed`.
    tools: SharedTools,
    status: ServerStatus,
    handle: Option<ServerHandle>,
    /// The stdio child's `tgid`, for attributing its kernel events (FR-027). `None` for a remote
    /// server or one that never connected.
    tgid: Option<u32>,
}

impl ConnectedServer {
    pub fn config(&self) -> &McpServerConfig {
        &self.config
    }
    pub fn status(&self) -> &ServerStatus {
        &self.status
    }
    pub fn tool_count(&self) -> usize {
        self.tools.lock().expect("mcp tools lock").len()
    }
}

/// Manages the connected MCP servers for an episode/REPL session.
pub struct McpBridge {
    policy: McpPolicy,
    servers: BTreeMap<String, ConnectedServer>,
    /// Set by any server's [`NotifyHandler`] on `tools/list_changed`; the loop consumes it via
    /// [`McpBridge::take_dirty`] to re-register tools for the next turn (FR-043).
    dirty: Arc<AtomicBool>,
}

impl McpBridge {
    /// A disabled bridge (no servers). Used when `[mcp]` is absent or `enabled = false`.
    pub fn disabled() -> Self {
        McpBridge {
            policy: McpPolicy::default(),
            servers: BTreeMap::new(),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Connect the configured servers under `policy`, spawning stdio children in `sandbox`.
    ///
    /// Never fails the episode: a server that cannot connect is recorded as [`ServerStatus::Failed`]
    /// and simply contributes no tools (Constitution I, fail-closed capability absence).
    pub async fn connect(policy: McpPolicy, sandbox: &Sandbox) -> Self {
        let dirty = Arc::new(AtomicBool::new(false));
        let mut servers = BTreeMap::new();
        if policy.enabled {
            let max = policy.max_servers as usize;
            for cfg in policy.servers.iter().take(max) {
                let server = match cfg.transport {
                    McpTransport::Stdio => connect_stdio(cfg, sandbox, dirty.clone()).await,
                    McpTransport::Sse | McpTransport::StreamableHttp => {
                        connect_remote(cfg, &policy, dirty.clone()).await
                    }
                };
                servers.insert(cfg.name.clone(), server);
            }
        }
        McpBridge {
            policy,
            servers,
            dirty,
        }
    }

    /// Consume the dirty flag: returns `true` (and resets it) if a `tools/list_changed` notification
    /// arrived since the last call. The loop uses this to decide whether to re-register tools.
    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::SeqCst)
    }

    /// Register one [`McpToolProxy`] per surviving tool of each connected server into `registry`
    /// (FR-036/FR-039). Reads each server's current (possibly refreshed) tool cache.
    pub fn register_into(&self, registry: &mut ToolRegistry) {
        let timeout = self.policy.tool_timeout();
        for (name, srv) in &self.servers {
            if !matches!(srv.status, ServerStatus::Connected) {
                continue;
            }
            let Some(handle) = &srv.handle else { continue };
            let tools = srv.tools.lock().expect("mcp tools lock").clone();
            for (bare, schema) in tools {
                let proxy = McpToolProxy::new(name, bare, schema, handle.peer.clone(), timeout);
                registry.insert(Box::new(proxy));
            }
        }
    }

    /// The connected servers, for the `/mcp` REPL command and status reporting (US10).
    pub fn servers(&self) -> impl Iterator<Item = (&str, &ConnectedServer)> {
        self.servers.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Each connected stdio server's own process, as `(name, tgid)` (FR-027). The session hands these
    /// to its sandbox so the server's kernel events are recorded under it.
    pub fn server_tgids(&self) -> Vec<(String, u32)> {
        self.servers
            .iter()
            .filter(|(_, s)| matches!(s.status, ServerStatus::Connected))
            .filter_map(|(name, s)| Some((name.clone(), s.tgid?)))
            .collect()
    }

    /// The policy this bridge was built from (exposes the domain allowlist for `/mcp`).
    pub fn policy(&self) -> &McpPolicy {
        &self.policy
    }

    /// A human-readable multi-line summary for the REPL `/mcp` command (US10): each server's
    /// transport, status, and tool count, plus the domain allow/deny lists.
    pub fn summary(&self) -> String {
        if !self.policy.enabled {
            return "MCP: disabled".to_string();
        }
        let mut out = format!("MCP: {} server(s)", self.servers.len());
        for (name, srv) in &self.servers {
            let transport = match srv.config.transport {
                McpTransport::Stdio => "stdio",
                McpTransport::Sse => "sse",
                McpTransport::StreamableHttp => "streamable_http",
            };
            out.push_str(&format!(
                "\n  {name} [{transport}] — {} ({} tools)",
                srv.status.label(),
                srv.tool_count()
            ));
        }
        let join = |ps: &[super::policy::DomainPattern]| {
            ps.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "\n  allowed_domains: [{}]",
            join(&self.policy.allowed_domains)
        ));
        out.push_str(&format!(
            "\n  denied_domains: [{}]",
            join(&self.policy.denied_domains)
        ));
        out
    }

    /// Tear down: drop every server handle, killing stdio children. Consumes the bridge.
    pub fn teardown(self) {
        // Dropping `self.servers` drops each `RunningService`, whose kill-on-drop reaps the child.
    }
}

fn failed_server(cfg: &McpServerConfig, why: String) -> ConnectedServer {
    ConnectedServer {
        config: cfg.clone(),
        tools: Arc::new(Mutex::new(Vec::new())),
        status: ServerStatus::Failed(why),
        handle: None,
        tgid: None,
    }
}

/// After the `initialize` handshake, fetch + filter the server's tools into `shared` and build the
/// connected record. Shared by the stdio and remote paths.
async fn finalize_connection(
    cfg: &McpServerConfig,
    running: RunningService<RoleClient, NotifyHandler>,
    shared: SharedTools,
    deadline: tokio::time::Instant,
) -> ConnectedServer {
    let tools = match discover_tools(running.peer(), deadline).await {
        Ok(t) => t,
        Err(e) => return failed_server(cfg, format!("list_tools failed: {e}")),
    };
    *shared.lock().expect("mcp tools lock") = filter_tools(cfg, &tools);
    let peer = running.peer().clone();
    ConnectedServer {
        config: cfg.clone(),
        tools: shared,
        status: ServerStatus::Connected,
        handle: Some(ServerHandle {
            service: running,
            peer,
        }),
        tgid: None,
    }
}

/// Build the `NotifyHandler` + shared cache for a server about to connect.
fn handler_for(cfg: &McpServerConfig, dirty: Arc<AtomicBool>) -> (NotifyHandler, SharedTools) {
    let shared: SharedTools = Arc::new(Mutex::new(Vec::new()));
    let handler = NotifyHandler {
        cfg: cfg.clone(),
        tools: shared.clone(),
        dirty,
        refreshing: tokio::sync::Mutex::new(()),
    };
    (handler, shared)
}

/// Connect one stdio MCP server: spawn it sandboxed, run the `initialize` handshake under the
/// startup budget, then finalize. Never panics — any failure yields a [`ServerStatus::Failed`]
/// server with no tools (fail-closed, Constitution I).
async fn connect_stdio(
    cfg: &McpServerConfig,
    sandbox: &Sandbox,
    dirty: Arc<AtomicBool>,
) -> ConnectedServer {
    let deadline = tokio::time::Instant::now() + STDIO_STARTUP_TIMEOUT;
    // Under interception the server gets its own proxy credential for its lifetime, issued (and
    // acknowledged) before it can make a request (019 T042). A no-op without `[policy.http]`.
    if tokio::time::timeout_at(
        deadline,
        sandbox.begin_side_call(&super::transport::mcp_call(&cfg.name)),
    )
    .await
    .is_err()
    {
        return failed_server(cfg, "MCP credential setup deadline exceeded".into());
    }
    let (transport, tgid) = match spawn_stdio(sandbox, cfg) {
        Ok(t) => t,
        Err(e) => return failed_server(cfg, e),
    };
    let (handler, shared) = handler_for(cfg, dirty);
    let running = match tokio::time::timeout_at(deadline, handler.serve(transport)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return failed_server(cfg, format!("initialize failed: {e}")),
        Err(_) => {
            return failed_server(
                cfg,
                format!(
                    "initialize timed out (>{}s)",
                    STDIO_STARTUP_TIMEOUT.as_secs()
                ),
            )
        }
    };
    ConnectedServer {
        tgid,
        ..finalize_connection(cfg, running, shared, deadline).await
    }
}

/// Connect one remote MCP server over Streamable HTTP. The domain gate is checked **first** — a
/// refused domain yields a `Failed` server with **no transport opened** (SC-021). The `token_env`
/// value (if any) becomes the `Authorization: Bearer` header (FR-041); it is never logged.
async fn connect_remote(
    cfg: &McpServerConfig,
    policy: &McpPolicy,
    dirty: Arc<AtomicBool>,
) -> ConnectedServer {
    let url = match cfg.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => u,
        None => return failed_server(cfg, "remote transport requires `url`".into()),
    };

    // Deny-by-default domain gate, BEFORE any socket is opened (Constitution I, SC-021).
    if let Err(reason) = policy.allow_url(url) {
        return failed_server(cfg, reason);
    }

    // `transport = "sse"` is a deprecated alias for the Streamable-HTTP client (research R2); both
    // land here. (No logger to warn through; the deprecation is documented in the config contract.)
    let mut config = StreamableHttpClientTransportConfig::with_uri(url.to_string());
    if let Some(name) = &cfg.token_env {
        // rmcp applies this via `bearer_auth`, i.e. it prepends "Bearer " — pass the raw token.
        if let Ok(token) = std::env::var(name) {
            if !token.is_empty() {
                config = config.auth_header(token);
            }
        }
    }

    let deadline = tokio::time::Instant::now() + REMOTE_STARTUP_TIMEOUT;
    let transport = StreamableHttpClientTransport::from_config(config);
    let (handler, shared) = handler_for(cfg, dirty);
    let running = match tokio::time::timeout_at(deadline, handler.serve(transport)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return failed_server(cfg, format!("initialize failed: {e}")),
        Err(_) => {
            return failed_server(
                cfg,
                format!(
                    "initialize timed out (>{}s)",
                    REMOTE_STARTUP_TIMEOUT.as_secs()
                ),
            )
        }
    };
    finalize_connection(cfg, running, shared, deadline).await
}

/// The bridge's tools change when a server sends `tools/list_changed`; turn start refreshes them
/// through [`crate::turn::RefreshHook`] (004 FR-043, 024 FR-030).
impl crate::turn::ToolRefresh for McpBridge {
    fn take_dirty(&self) -> bool {
        McpBridge::take_dirty(self)
    }

    fn reregister(&self, registry: &mut ToolRegistry) {
        registry.remove_mcp_tools();
        self.register_into(registry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn discovery_fixture(mode: &'static str) -> RunningService<RoleClient, ()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut lines = BufReader::new(read).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                let Some(id) = request.get("id") else {
                    continue;
                };
                let result = if request["method"] == "initialize" {
                    serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture", "version": "1"}})
                } else if mode == "stall" {
                    continue;
                } else if mode == "repeat" {
                    serde_json::json!({"tools": [], "nextCursor": "same"})
                } else if mode == "oversize" {
                    let tool =
                        serde_json::json!({"name": "tool", "inputSchema": {"type": "object"}});
                    serde_json::json!({"tools": vec![tool; DISCOVERY_TOOLS + 1]})
                } else {
                    serde_json::json!({"tools": []})
                };
                let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
                if write
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        ().serve(client).await.unwrap()
    }

    #[tokio::test]
    async fn discovery_limits_apply_after_a_successful_handshake() {
        for (mode, expected) in [
            ("stall", "deadline"),
            ("repeat", "cursor"),
            ("oversize", "count"),
        ] {
            let service = discovery_fixture(mode).await;
            let error = discover_tools(
                service.peer(),
                tokio::time::Instant::now() + Duration::from_millis(100),
            )
            .await
            .unwrap_err();
            assert!(error.contains(expected), "{mode}: {error}");
            service.cancel().await.unwrap();
        }
        let service = discovery_fixture("empty").await;
        assert!(discover_tools(
            service.peer(),
            tokio::time::Instant::now() + Duration::from_secs(1)
        )
        .await
        .unwrap()
        .is_empty());
        service.cancel().await.unwrap();
    }

    #[test]
    fn disabled_bridge_registers_nothing() {
        let bridge = McpBridge::disabled();
        let mut registry = ToolRegistry::new();
        bridge.register_into(&mut registry);
        assert!(registry.schemas().is_empty());
        assert!(!bridge.take_dirty());
    }

    #[tokio::test]
    async fn connect_disabled_policy_is_empty() {
        let bridge = McpBridge::connect(McpPolicy::default(), &Sandbox::host(vec![])).await;
        assert_eq!(bridge.servers().count(), 0);
    }
}
