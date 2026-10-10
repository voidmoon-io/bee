//! The `git_log` tool (016-native-tools US5): what the repository remembers about a path.
//!
//! Like [`crate::tools::search`] and [`crate::tools::astgrep`], this tool's "binary" is bee itself:
//! it execs `bee gitlog-worker …` through the sandbox, so the object files and packs `gix` opens in
//! [`crate::gitlog`] pass the scope's `file_open` policy. Reading history in the harness would read
//! around the sandbox — `.git` is just a directory of files, and a policy that denies it means it.
//!
//! **Why this wrapper reads an exit code rather than a message.** Three outcomes look identical from
//! outside a child that printed nothing: a history with no matching commits, a path that is not in a
//! repository at all, and a request the repository could not answer. The worker separates them by
//! exit code and this wrapper maps them to `Completed` / `Unavailable { NotARepository }` / `Failed`
//! (contract `tool-outcome.md`). Grepping prose would tie the distinction to wording.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::gitlog::{worker_argv, GitLogArgs, Mode, EXIT_NOT_A_REPOSITORY};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::exec::{run_child_timed, ChildError};
use crate::tools::outcome::{audit_refusal, ToolOutcome, UnavailableReason};
use crate::tools::{Tool, ToolResult};

/// The cap on commits a single call returns.
const COMMIT_LIMIT: usize = 50;

/// Wall-clock budget for one history query.
///
/// Generous, because blame on a long-lived file is genuinely slow work and a partial answer is not
/// on offer here — but bounded, because a repository with a pathological history must not hold a
/// turn open indefinitely. A query that exceeds it reports `Failed`, never a short history.
const BUDGET: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct Args {
    #[serde(default = "default_path")]
    path: String,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    line: Option<u32>,
}

fn default_path() -> String {
    ".".to_string()
}

fn default_mode() -> String {
    "log".to_string()
}

/// `{ "path"?: string, "mode"?: "log"|"blame", "line"?: number }` → repository history.
pub struct GitLogTool;

#[async_trait::async_trait]
impl Tool for GitLogTool {
    fn name(&self) -> &'static str {
        "git_log"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "git_log".to_string(),
            description: format!(
                "Read the repository's history for a path. `log` lists the commits that changed it, \
                 newest first, as `<sha> <date> <author> <summary>` (capped at {COMMIT_LIMIT}). \
                 `blame` names the commit that introduced one line — use it to find out when a piece \
                 of code appeared and what change it came in with. Read-only: this never writes to \
                 the repository."
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File or directory to ask about. Defaults to the current directory."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["log", "blame"],
                        "description": "`log` for the commits touching the path, `blame` for the origin of one line."
                    },
                    "line": {
                        "type": "integer",
                        "description": "1-indexed line to attribute. Required for `blame`, ignored for `log`."
                    }
                },
                "required": []
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let args: Args = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("git_log", e),
        };

        let mode: Mode = match args.mode.parse() {
            Ok(m) => m,
            Err(e) => return failed(e),
        };
        // Caught here rather than in the child: it costs a process, and the diagnostic is about the
        // call the model made, not about anything the repository said.
        if mode == Mode::Blame && args.line.is_none() {
            return failed("blame needs a `line` (the 1-indexed line to attribute)".to_string());
        }

        let exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return ToolResult::error(format!("git_log: cannot locate bee executable: {e}"))
            }
        };

        let req = GitLogArgs {
            path: args.path.into(),
            mode,
            line: args.line,
            limit: COMMIT_LIMIT,
        };

        let run = match run_child_timed(sandbox, &exe, &worker_argv(&req), BUDGET).await {
            Ok(r) => r,
            Err(ChildError::TimedOut(d)) => {
                return failed(format!(
                    "history query exceeded its {}s budget",
                    d.as_secs()
                ))
            }
            Err(ChildError::Spawn(e)) => return failed(e),
        };

        match run.code {
            Some(0) => {
                let commits: Vec<String> = run
                    .stdout
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string)
                    .collect();
                let truncated = commits.len() >= COMMIT_LIMIT;
                // Commit messages and authors are repository content: child output, framed as
                // untrusted data (019 P1).
                ToolOutcome::Completed {
                    value: commits,
                    truncated,
                }
                .into_tool_result(render)
                .with_provenance(crate::tools::Provenance::Child)
            }
            Some(EXIT_NOT_A_REPOSITORY) => {
                let reason = UnavailableReason::NotARepository {
                    path: req.path.clone(),
                };
                audit_refusal("git_log", &reason);
                ToolOutcome::<Vec<String>>::unavailable(reason).into_tool_result(render)
            }
            // Any other non-zero code: the worker said why on stderr, and its diagnostic is more
            // specific than anything this side could reconstruct from the code alone.
            _ => failed(first_line(&run.stderr).unwrap_or_else(|| {
                format!(
                    "the history worker exited {}",
                    run.code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "on a signal".to_string())
                )
            })),
        }
    }
}

/// A clean run with no commits renders as exactly that, in words — the sentence a reader can tell
/// apart from "did not run" at a glance (FR-012).
fn render(commits: Vec<String>) -> String {
    if commits.is_empty() {
        return "no commits in this repository touch that path".to_string();
    }
    commits.join("\n")
}

fn failed(detail: String) -> ToolResult {
    ToolOutcome::<Vec<String>>::Failed { reason: detail }.into_tool_result(render)
}

fn first_line(s: &str) -> Option<String> {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.trim_start_matches("git_log: ").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_history_reads_as_an_answer_not_a_silence() {
        let rendered = render(Vec::new());
        assert!(rendered.contains("no commits"), "{rendered}");
        // And it must not be sayable as a refusal — the two are what the exit codes keep apart.
        assert!(!rendered.contains("did not run"), "{rendered}");
    }

    #[test]
    fn the_schema_offers_both_modes_and_requires_neither_argument() {
        let schema = GitLogTool.schema();
        let modes = schema.parameters["properties"]["mode"]["enum"]
            .as_array()
            .expect("mode enumerates its options");
        assert_eq!(modes.len(), 2);
        assert!(schema.parameters["required"].as_array().unwrap().is_empty());
    }

    #[test]
    fn the_description_says_it_cannot_write() {
        assert!(GitLogTool.schema().description.contains("Read-only"));
    }
}
