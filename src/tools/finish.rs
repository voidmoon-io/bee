//! `finish` — how an autonomous run ends (025 US3, contracts/finish.md).
//!
//! Offered only to a headless standard-mode run; never to the REPL or a CTF (FR-037). A valid call
//! is terminal: the loop records `Finished { outcome, summary, turn }` and runs nothing after it.
//! An invalid one is an ordinary error result, and the run goes on (FR-032).

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;

use super::{Tool, ToolResult};

/// The longest summary `finish` accepts, in characters.
pub const MAX_SUMMARY_CHARS: usize = 4000;

/// How the model says the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinishOutcome {
    /// The task is done.
    Completed,
    /// Something outside the model's control prevents it.
    Blocked,
    /// The model stopped for another reason.
    Abandoned,
}

impl fmt::Display for FinishOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FinishOutcome::Completed => "completed",
            FinishOutcome::Blocked => "blocked",
            FinishOutcome::Abandoned => "abandoned",
        })
    }
}

/// The accepted arguments of a `finish` call, or why they are not acceptable.
fn check(arguments: &Value) -> Result<(FinishOutcome, String), String> {
    let outcome = arguments
        .get("outcome")
        .ok_or("outcome is required")?
        .clone();
    let outcome: FinishOutcome = serde_json::from_value(outcome)
        .map_err(|_| "outcome must be one of completed, blocked, abandoned".to_string())?;
    let summary = arguments
        .get("summary")
        .and_then(Value::as_str)
        .ok_or("summary is required and must be a string")?;
    if summary.trim().is_empty() {
        return Err("summary must not be empty".into());
    }
    if summary.chars().count() > MAX_SUMMARY_CHARS {
        return Err(format!(
            "summary must be at most {MAX_SUMMARY_CHARS} characters"
        ));
    }
    Ok((outcome, summary.to_string()))
}

/// The outcome and summary of a `finish` call the tool accepted. `None` for one it refused.
pub fn parse(arguments: &Value) -> Option<(FinishOutcome, String)> {
    check(arguments).ok()
}

/// The `finish` tool.
pub struct Finish;

#[async_trait::async_trait]
impl Tool for Finish {
    fn name(&self) -> &'static str {
        "finish"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "finish".to_string(),
            description:
                "End this run. Call it once, when the task is complete, or when you cannot \
                          make further progress. outcome: \"completed\" if the task is done; \
                          \"blocked\" if something outside your control (access, missing \
                          information, a broken environment) prevents it; \"abandoned\" if you \
                          stopped for another reason. summary: what you did, what the result is, \
                          and anything the operator must know. Tool calls after finish in the same \
                          turn are not run."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "outcome": { "type": "string", "enum": ["completed", "blocked", "abandoned"] },
                    "summary": { "type": "string", "minLength": 1, "maxLength": MAX_SUMMARY_CHARS }
                },
                "required": ["outcome", "summary"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, arguments: Value, _sandbox: &Sandbox) -> ToolResult {
        match check(&arguments) {
            Ok((outcome, _)) => ToolResult::terminal_ok(format!("run finished: {outcome}")),
            Err(why) => ToolResult::invalid_args("finish", why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_outcome_with_a_summary() {
        for (word, outcome) in [
            ("completed", FinishOutcome::Completed),
            ("blocked", FinishOutcome::Blocked),
            ("abandoned", FinishOutcome::Abandoned),
        ] {
            let args = json!({"outcome": word, "summary": "did it"});
            assert_eq!(parse(&args), Some((outcome, "did it".into())));
            assert_eq!(outcome.to_string(), word);
        }
    }

    #[test]
    fn refuses_what_the_schema_refuses() {
        let long = "x".repeat(MAX_SUMMARY_CHARS + 1);
        for args in [
            json!({"summary": "s"}),
            json!({"outcome": "done", "summary": "s"}),
            json!({"outcome": "completed"}),
            json!({"outcome": "completed", "summary": "   "}),
            json!({"outcome": "completed", "summary": 3}),
            json!({"outcome": "completed", "summary": long}),
        ] {
            assert!(parse(&args).is_none(), "{args} accepted");
        }
        let at_limit = "é".repeat(MAX_SUMMARY_CHARS);
        assert!(
            parse(&json!({"outcome": "completed", "summary": at_limit})).is_some(),
            "the limit counts characters, not bytes"
        );
    }

    #[tokio::test]
    async fn a_valid_call_is_terminal_and_an_invalid_one_is_not() {
        let sb = Sandbox::host(Vec::new());
        let ok = Finish
            .call(json!({"outcome": "blocked", "summary": "no access"}), &sb)
            .await;
        assert!(ok.terminal && !ok.is_error);
        assert_eq!(ok.content, "run finished: blocked");

        let bad = Finish.call(json!({"outcome": "blocked"}), &sb).await;
        assert!(!bad.terminal && bad.is_error);
        assert!(
            bad.content.starts_with("finish: invalid arguments:"),
            "{}",
            bad.content
        );
    }
}
