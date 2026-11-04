//! The `edit_file` tool: replace an exact string in a file, inside the scope.
//!
//! Like `search`, its binary is bee itself: it execs `bee edit-worker` through [`run_child`], so the
//! read and the write both happen in a scope-joined child and the LSM mediates each open (see
//! [`crate::edit`]). The request goes to the worker on stdin as JSON — never on argv.

use serde_json::json;

use crate::edit::EditRequest;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::exec::run_child;
use crate::tools::{Tool, ToolResult};
use crate::transcript::DEFAULT_OUTPUT_CAP;

/// `{ path, old_string, new_string, replace_all? }` → `bee edit-worker` with the request on stdin.
pub struct EditFile;

#[async_trait::async_trait]
impl Tool for EditFile {
    fn name(&self) -> &'static str {
        "edit_file"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "edit_file".to_string(),
            description:
                "Replace an exact string in an existing file. `old_string` must match the \
                          file exactly (including whitespace and indentation) and, unless \
                          `replace_all` is set, exactly once — include enough surrounding lines to \
                          make it unique. Prefer this to write_file for changing part of a file."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File to edit." },
                    "old_string": { "type": "string", "description": "Exact text to replace." },
                    "new_string": { "type": "string", "description": "Replacement text." },
                    "replace_all": {
                        "type": "boolean",
                        "description": "Replace every occurrence instead of requiring exactly one."
                    }
                },
                "required": ["path", "old_string", "new_string"]
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let req: EditRequest = match serde_json::from_value(arguments) {
            Ok(r) => r,
            Err(e) => return ToolResult::invalid_args("edit_file", e),
        };
        // No safe fallback without our own binary: editing here would open the file outside the scope.
        let exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return ToolResult::error(format!("edit_file: cannot locate bee executable: {e}"))
            }
        };
        let body = match serde_json::to_vec(&req) {
            Ok(b) => b,
            Err(e) => return ToolResult::error(format!("edit_file: encoding request: {e}")),
        };
        run_child(
            sandbox,
            &exe,
            &["edit-worker".to_string()],
            Some(body),
            DEFAULT_OUTPUT_CAP,
        )
        .await
    }
}
