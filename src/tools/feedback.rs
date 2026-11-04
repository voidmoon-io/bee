//! Agent feedback is recorded by the normal call lifecycle in the run transcript.
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{provider::ToolSchema, sandbox::Sandbox};

use super::{Tool, ToolContract, ToolResult};

const MAX_MESSAGE_CHARS: usize = 4000;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Category {
    Bug,
    Confusion,
    Suggestion,
    Positive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedbackArgs {
    category: Category,
    message: String,
}

pub struct Feedback;

#[async_trait::async_trait]
impl Tool for Feedback {
    fn name(&self) -> &'static str {
        "feedback"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "Leave feedback about the harness or its tools in this run's transcript/log. Report bugs, confusing behavior, suggestions, or what worked well. Include concrete observations; do not include secrets. This does not end the run or contact anyone.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": ["bug", "confusion", "suggestion", "positive"]},
                    "message": {"type": "string", "minLength": 1, "maxLength": MAX_MESSAGE_CHARS}
                },
                "required": ["category", "message"],
                "additionalProperties": false
            }),
        }
    }

    fn durable_contract(&self) -> ToolContract {
        ToolContract {
            version: 1,
            recovery: crate::session::durable::RecoveryPolicy::RetrySafe { max_attempts: 2 },
        }
    }

    async fn call(&self, arguments: Value, _: &Sandbox) -> ToolResult {
        let args = match serde_json::from_value::<FeedbackArgs>(arguments) {
            Ok(args) => args,
            Err(_) => return ToolResult::invalid_args("feedback", "expected category (bug, confusion, suggestion, positive) and message; no extra fields"),
        };
        if args.message.trim().is_empty() || args.message.chars().count() > MAX_MESSAGE_CHARS {
            return ToolResult::invalid_args(
                "feedback",
                "message must contain 1 to 4000 characters and must not be blank",
            );
        }
        let _ = args.category;
        // The call arguments carry the feedback; the driver owns persistence and replay.
        ToolResult::ok("Feedback accepted for this run's transcript.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_feedback_without_ending_the_run_and_rejects_invalid_input() {
        let sandbox = Sandbox::host(vec![]);
        for category in ["bug", "confusion", "suggestion", "positive"] {
            let result = Feedback
                .call(
                    json!({"category":category,"message":"Concrete observation"}),
                    &sandbox,
                )
                .await;
            assert!(!result.is_error);
            assert!(!result.terminal);
        }
        for arguments in [
            json!({}),
            json!({"category":"unknown","message":"test"}),
            json!({"category":"bug","message":"  "}),
            json!({"category":"bug","message":"x".repeat(4001)}),
            json!({"category":"bug","message":"test","path":"/tmp/log"}),
        ] {
            assert!(Feedback.call(arguments, &sandbox).await.is_error);
        }
    }
}
