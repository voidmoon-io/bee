//! The `search` tool: regex search over file contents (ripgrep), run inside the scope.
//!
//! Unlike `bash`/`read_file`, whose "binary" is a system program, this tool's binary is **bee
//! itself**: it execs `bee search-worker …` through [`run_child`], so the ripgrep-library search in
//! [`crate::search`] runs in a process that has joined the scope cgroup and is subject to the LSM.
//! The model never touches the harness's own view of the filesystem — every file the search opens
//! goes through the scope's `file_open` policy, same as any other tool child.

use serde::Deserialize;
use serde_json::json;

use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::search::{worker_argv, SearchArgs};
use crate::tools::exec::run_child;
use crate::tools::{Tool, ToolResult};
use crate::transcript::DEFAULT_OUTPUT_CAP;

/// The cap on matching lines a single call returns. Also bounds walk time on a large tree.
pub(crate) const MATCH_LIMIT: usize = 200;

#[derive(Deserialize)]
struct Args {
    pattern: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    glob: String,
    #[serde(default)]
    ignore_case: bool,
}

fn default_path() -> String {
    ".".to_string()
}

/// `{ "pattern": string, "path"?: string, "glob"?: string, "ignore_case"?: bool }` → ripgrep search.
pub struct Search;

#[async_trait::async_trait]
impl Tool for Search {
    fn name(&self) -> &'static str {
        "search"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "search".to_string(),
            description: "Search file contents with a regular expression (ripgrep). Returns matching \
                          lines as `path:line:text`, honoring .gitignore and skipping binary files. \
                          Results are capped; narrow with `glob` or a more specific `pattern` if you \
                          hit the cap."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "The regular expression to search for."
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory or file to search under. Defaults to the current directory."
                    },
                    "glob": {
                        "type": "string",
                        "description": "Optional glob to restrict which files are searched, e.g. \"**/*.rs\"."
                    },
                    "ignore_case": {
                        "type": "boolean",
                        "description": "Case-insensitive match. Default is smart-case."
                    }
                },
                "required": ["pattern"]
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let args: Args = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("search", e),
        };

        // The worker is this very executable, exec'd through the sandbox so it joins the scope. If we
        // cannot name our own binary there is no safe fallback (running the library here would search
        // outside the sandbox), so fail the call rather than escape the scope.
        let exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return ToolResult::error(format!("search: cannot locate bee executable: {e}"))
            }
        };

        let req = SearchArgs {
            path: args.path.into(),
            glob: args.glob,
            ignore_case: args.ignore_case,
            limit: MATCH_LIMIT,
            pattern: args.pattern,
        };
        run_child(sandbox, &exe, &worker_argv(&req), None, DEFAULT_OUTPUT_CAP).await
    }
}
