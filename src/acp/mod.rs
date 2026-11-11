//! The Agent Client Protocol (026-acp).
//!
//! **Inward** ([`agent`]): `bee acp` is an ACP agent. A client such as t3code launches it, and each
//! client session is a bee session — built the way `bee repl` builds one, in the client's working
//! directory, enforced by its own kernel scope. Prompts stream back as `session/update`s
//! ([`output`]); a capability the session asks for becomes a `session/request_permission` the client
//! answers. bee never uses the client's file-system or terminal methods: they would run outside the
//! scope.
//!
//! **Outward** ([`harness`]): bee is the ACP *client* of an external harness — Claude Code, Codex,
//! OpenCode — run as a subagent inside its own kernel scope, its permission requests answered by
//! bee and its web traffic through a proxy scope of its own.
//!
//! The protocol is ACP version 1, through the `agent-client-protocol` crate with no features: bee
//! supplies its own byte streams, and its own tokio runtime drives the connection.

pub mod agent;
#[cfg(any(feature = "test-support", feature = "vm-test"))]
pub mod fake_harness;
pub mod harness;
pub mod output;

use std::path::PathBuf;

use crate::operator::Operator;
use crate::provider::Model;
use crate::repl::ReplConfig;
use crate::session::Session;

/// The only protocol version bee speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// A stdio MCP server an ACP client asked a session to start. Whether it starts is the operator's
/// decision ([`SessionFactory`]); HTTP and SSE servers never get this far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMcpServer {
    pub name: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// What a session needs from the process that serves it.
pub struct OpenSession {
    /// The session id bee issued (`acp-…`), which names its scope.
    pub id: String,
    /// The client's working directory: absolute, an existing directory (checked before this).
    pub cwd: PathBuf,
    /// Interactive: its questions go to the client.
    pub operator: Operator,
    pub client_mcp: Vec<ClientMcpServer>,
}

/// A session ready for prompts.
pub struct OpenedSession {
    pub session: Session,
    pub model: Box<dyn Model>,
    pub config: ReplConfig,
    /// Lines the client should see once the session exists (dropped MCP servers, advisories).
    pub notices: Vec<String>,
}

/// Builds sessions. `bee acp` resolves configuration in the session's directory the way `bee repl`
/// does; a test builds one around a scripted model.
#[async_trait::async_trait]
pub trait SessionFactory: Send + Sync {
    async fn open(&self, request: OpenSession) -> Result<OpenedSession, String>;
}
