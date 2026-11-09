//! The `task` tool (018-subagent-scopes, contracts/task-tool.md) — delegate a piece of work to an
//! operator-authored agent.
//!
//! The tool does not run anything. It checks the request names a known agent and carries a task,
//! and returns a [`DelegationRequest`] on its result; the call lifecycle (`crate::call`) runs the
//! subagent in its own scope and replaces the result with the subagent's report. Like `render`, the
//! model never sees the request — only what replaces it.
//!
//! The schema offers agent names and descriptions and nothing else: **there is no capability, tool or
//! policy parameter** (FR-003). The model chooses what to delegate and to whom; the operator chose
//! what each agent may do, by writing its definition.

use std::sync::Arc;

use serde_json::json;

use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::skills::SkillRegistry;
use crate::tools::{DelegationRequest, Tool, ToolResult};

/// The model-facing `task` tool, over the session's discovered agent definitions.
pub struct TaskTool {
    agents: Arc<SkillRegistry>,
}

impl TaskTool {
    /// Register it only when `agents` holds at least one agent definition.
    pub fn new(agents: Arc<SkillRegistry>) -> Self {
        TaskTool { agents }
    }

    fn names(&self) -> Vec<String> {
        self.agents.agents().map(|a| a.name.clone()).collect()
    }
}

fn description(agents: &SkillRegistry) -> String {
    let mut d = String::from(
        "Delegate a self-contained piece of work to a subagent. The subagent runs with its own, \
         narrower capabilities and returns a written report. It does not see this conversation: \
         put everything it needs in the prompt.\n\nAvailable agents:\n",
    );
    for a in agents.agents() {
        // The description is the only thing the model chooses by: verbatim, never truncated.
        d.push_str("- ");
        d.push_str(&a.name);
        d.push_str(": ");
        d.push_str(&a.description);
        d.push('\n');
    }
    d
}

#[async_trait::async_trait]
impl Tool for TaskTool {
    fn name(&self) -> &'static str {
        "task"
    }

    fn schema(&self) -> ToolSchema {
        let mut agent = json!({
            "type": "string",
            "description": "Which agent to delegate to."
        });
        let names = self.names();
        if !names.is_empty() {
            agent["enum"] = json!(names);
        }
        ToolSchema {
            name: "task".to_string(),
            description: description(&self.agents),
            parameters: json!({
                "type": "object",
                "properties": {
                    "agent": agent,
                    "prompt": {
                        "type": "string",
                        "description": "The task, self-contained. The subagent does not see this conversation."
                    }
                },
                "required": ["agent", "prompt"]
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, _sandbox: &Sandbox) -> ToolResult {
        let Some(agent) = arguments.get("agent").and_then(|v| v.as_str()) else {
            return ToolResult::invalid_args("task", "missing string field 'agent'");
        };
        let Some(prompt) = arguments.get("prompt").and_then(|v| v.as_str()) else {
            return ToolResult::invalid_args("task", "missing string field 'prompt'");
        };
        if prompt.trim().is_empty() {
            return ToolResult::invalid_args("task", "'prompt' is empty");
        }
        // The enum makes this rare, not impossible: a model can emit anything (FR-004).
        if self.agents.agent(agent).is_none() {
            return ToolResult::error(format!(
                "task: unknown agent '{agent}'. Available agents: {}",
                self.names().join(", ")
            ));
        }
        ToolResult {
            delegate: Some(Box::new(DelegationRequest {
                agent: agent.to_string(),
                prompt: prompt.to_string(),
            })),
            ..ToolResult::ok(String::new())
        }
    }
}
