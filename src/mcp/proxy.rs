//! `McpToolProxy` — a [`crate::tools::Tool`] that forwards a call to a connected MCP server via its
//! `rmcp` peer (004-mcp-client, T009/T010). Like `RenderTool` (003) it ignores the `&Sandbox`: the
//! MCP *server* is what the kernel sandboxes (for stdio) or the domain gate controls (for remote) —
//! this in-process proxy does no I/O of its own (research R6).

use std::time::Duration;

use async_trait::async_trait;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, Tool as RmcpTool};
use rmcp::service::{Peer, RoleClient};
use serde_json::Value;

use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::{Tool, ToolResult};

/// Build the model-facing [`ToolSchema`] for an MCP tool, namespacing its name to
/// `mcp__{server}__{tool}` (FR-036) and passing the server's JSON-Schema through verbatim.
pub fn tool_schema(server: &str, tool: &RmcpTool) -> ToolSchema {
    ToolSchema {
        name: format!("mcp__{server}__{}", tool.name),
        description: tool
            .description
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_default(),
        parameters: Value::Object((*tool.input_schema).clone()),
    }
}

/// A short label for a non-text content block, so the model sees *something* meaningful.
fn content_kind(b: &ContentBlock) -> &'static str {
    match b {
        ContentBlock::Text(_) => "text",
        ContentBlock::Image(_) => "image",
        ContentBlock::Audio(_) => "audio",
        ContentBlock::Resource(_) => "resource",
        ContentBlock::ResourceLink(_) => "resource_link",
        _ => "unknown",
    }
}

/// Map an rmcp [`CallToolResult`] into bee's [`ToolResult`] (T009): flatten text blocks into
/// `content`, mark non-text blocks, fall back to `structured_content`, carry `is_error`, and apply
/// the same output cap as built-in tools (FR-038/SC-024).
pub fn call_tool_result_to_tool_result(res: CallToolResult, cap: usize) -> ToolResult {
    let is_error = res.is_error.unwrap_or(false);
    let mut parts: Vec<String> = Vec::with_capacity(res.content.len());
    for block in &res.content {
        match block.as_text() {
            Some(t) => parts.push(t.text.clone()),
            None => parts.push(format!("[non-text content: {}]", content_kind(block))),
        }
    }
    let mut text = parts.join("\n");
    if text.is_empty() {
        if let Some(sc) = &res.structured_content {
            text = sc.to_string();
        }
    }
    // Reuse the built-in truncation path so MCP results cap identically (FR-015/FR-038).
    crate::transcript::tool_result_from_output(text, None, is_error, cap)
}

/// A single MCP tool exposed to the model, routing through the owning server's `rmcp` peer.
pub struct McpToolProxy {
    /// The leaked, `'static`, namespaced name (`mcp__{server}__{tool}`). Required because both the
    /// `Tool` trait and the registry `BTreeMap` key on `&'static str`; leaked once per tool at
    /// connect time, so the leak is bounded by tool count, not call volume (research R6).
    name: &'static str,
    /// The server name, for a clean "disconnected" message.
    server: String,
    /// The tool name as the server knows it (un-namespaced), sent in `call_tool`.
    bare_tool: String,
    schema: ToolSchema,
    peer: Peer<RoleClient>,
    timeout: Duration,
}

impl McpToolProxy {
    /// Build a proxy for `bare_tool` on `server`. `schema` must already carry the namespaced name
    /// (see [`tool_schema`]). `peer` is a cheap clone of the server's `rmcp` peer.
    pub fn new(
        server: &str,
        bare_tool: String,
        schema: ToolSchema,
        peer: Peer<RoleClient>,
        timeout: Duration,
    ) -> Self {
        let name: &'static str = Box::leak(format!("mcp__{server}__{bare_tool}").into_boxed_str());
        McpToolProxy {
            name,
            server: server.to_string(),
            bare_tool,
            schema,
            peer,
            timeout,
        }
    }
}

#[async_trait]
impl Tool for McpToolProxy {
    fn name(&self) -> &'static str {
        self.name
    }

    fn mcp_server(&self) -> Option<&str> {
        Some(&self.server)
    }

    fn schema(&self) -> ToolSchema {
        self.schema.clone()
    }

    async fn call(&self, arguments: Value, _sandbox: &Sandbox) -> ToolResult {
        // MCP arguments must be a JSON object (or absent). A non-object is a malformed call (FR-016).
        let args = match arguments {
            Value::Object(map) => Some(map),
            Value::Null => None,
            other => {
                let kind = match other {
                    Value::Array(_) => "array",
                    Value::String(_) => "string",
                    Value::Number(_) => "number",
                    Value::Bool(_) => "bool",
                    _ => "value",
                };
                return ToolResult::invalid_args(
                    self.name,
                    format!("expected a JSON object, got {kind}"),
                );
            }
        };

        let mut params = CallToolRequestParams::new(self.bare_tool.clone());
        params.arguments = args;

        match tokio::time::timeout(self.timeout, self.peer.call_tool(params)).await {
            // The server's reply is a remote peer's bytes: framed as untrusted data (019 P1).
            Ok(Ok(res)) => {
                call_tool_result_to_tool_result(res, crate::transcript::DEFAULT_OUTPUT_CAP)
                    .with_provenance(crate::provider::Provenance::Remote {
                        source: format!("mcp:{}", self.server),
                    })
            }
            Ok(Err(e)) => {
                use rmcp::service::ServiceError;
                let msg = match &e {
                    ServiceError::TransportClosed | ServiceError::TransportSend(_) => {
                        format!("MCP server '{}' disconnected", self.server)
                    }
                    _ => format!("MCP tool '{}': {e}", self.name),
                };
                ToolResult::error(msg)
            }
            Err(_) => ToolResult::error(format!(
                "MCP tool '{}': timed out after {}s",
                self.name,
                self.timeout.as_secs()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::CallToolResult;

    #[test]
    fn maps_text_success() {
        let res = CallToolResult::success(vec![
            ContentBlock::text("hello"),
            ContentBlock::text("world"),
        ]);
        let tr = call_tool_result_to_tool_result(res, 1024);
        assert_eq!(tr.content, "hello\nworld");
        assert!(!tr.is_error);
    }

    #[test]
    fn maps_error_flag() {
        let res = CallToolResult::error(vec![ContentBlock::text("boom")]);
        let tr = call_tool_result_to_tool_result(res, 1024);
        assert!(tr.is_error);
        assert_eq!(tr.content, "boom");
    }

    #[test]
    fn falls_back_to_structured_content() {
        let res = CallToolResult::structured(serde_json::json!({"rows": 3}));
        let tr = call_tool_result_to_tool_result(res, 1024);
        assert!(tr.content.contains("rows"));
    }

    #[test]
    fn truncates_large_content() {
        let big = "x".repeat(200);
        let res = CallToolResult::success(vec![ContentBlock::text(big)]);
        let tr = call_tool_result_to_tool_result(res, 50);
        assert!(tr.truncated);
        assert_eq!(tr.original_len, Some(200));
    }
}
