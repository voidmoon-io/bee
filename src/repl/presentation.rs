//! Presentation identities are scoped independently of model messages and recovery tokens.
use crate::provider::ToolCall;
use crate::tools::ToolResult;
use bee_core::AuditEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationId {
    pub submission: String,
    pub turn: u32,
    pub call: String,
}

#[derive(Debug, Clone)]
pub struct CallContext {
    pub invocation: InvocationId,
    pub parent: Option<InvocationId>,
    pub replay: bool,
    pub depth: usize,
}

impl CallContext {
    pub fn new(
        submission: &str,
        turn: u32,
        call: &str,
        parent: Option<&str>,
        replay: bool,
        depth: usize,
    ) -> Self {
        let identity = |call: &str| InvocationId {
            submission: submission.into(),
            turn,
            call: call.into(),
        };
        Self {
            invocation: identity(call),
            parent: parent.map(identity),
            replay,
            depth,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CallOutcome {
    Running,
    Completed {
        result: Box<ToolResult>,
        audit: Vec<AuditEvent>,
    },
    Unresolved {
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub struct CallEvent {
    pub context: CallContext,
    pub call: ToolCall,
    pub outcome: CallOutcome,
}

impl CallEvent {
    /// Full details remain available in ordinary scrollback, including receipts and denials.
    pub fn text(&self) -> String {
        let status = match &self.outcome {
            CallOutcome::Running => "running",
            CallOutcome::Completed { result, .. } if result.is_error => "error",
            CallOutcome::Completed { .. } => "completed",
            CallOutcome::Unresolved { .. } => "UNRESOLVED",
        };
        let replay = if self.context.replay { " [replay]" } else { "" };
        let mut text = format!(
            "{} {} [{}]{replay}\narguments: {}",
            self.call.name, self.context.invocation.call, status, self.call.arguments
        );
        if self.call.name == "codemode" {
            if let Some(source) = self.call.arguments.get("source").and_then(|v| v.as_str()) {
                text.push_str(&format!("\nPython:\n{source}"));
            }
        }
        match &self.outcome {
            CallOutcome::Running => {}
            CallOutcome::Unresolved { detail } => text.push_str(&format!("\n{detail}")),
            CallOutcome::Completed { result, audit } => {
                text.push_str(&format!("\n{}", result.content));
                if let Some(receipt) = &result.receipt_id {
                    text.push_str(&format!("\nreceipt: {receipt}"));
                }
                for event in audit {
                    text.push_str(&format!(
                        "\naudit: {}",
                        serde_json::to_string(event).expect("audit serializes")
                    ));
                }
            }
        }
        if self.context.depth > 0 {
            let indent = "    ".repeat(self.context.depth);
            text.lines()
                .map(|line| format!("{indent}{line}"))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            text
        }
    }
}
