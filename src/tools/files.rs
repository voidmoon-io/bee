//! Structured file tools (FR-004): `read_file`, `edit_file`, `ensure_line`, `write_file`,
//! `list_directory`. Each
//! takes typed arguments but still executes as a sandboxed child so the LSM enforces the operation
//! (contracts/tool-contracts.md — tools never pre-check paths in user space). Each execs
//! `bee file-worker` ([`crate::fileops`]) with the request on stdin as JSON — never on argv — so the
//! only exec a scope needs for them is bee itself, which every tool scope allows
//! ([`crate::tools::exec::tool_scope`]).

use serde::Deserialize;
use serde_json::json;

use crate::fileops::{
    EditRequest, EnsureLineRequest, FileRequest, ListRequest, ReadRequest, WriteRequest,
};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::exec::run_child;
use crate::tools::{Tool, ToolResult};
use crate::transcript::DEFAULT_OUTPUT_CAP;

fn string_prop(name: &str, desc: &str, required: &[&str]) -> serde_json::Value {
    json!({
        "type": "object",
        "properties": { name: { "type": "string", "description": desc } },
        "required": required
    })
}

#[derive(Deserialize)]
struct PathArgs {
    path: String,
}

/// The durable contract of a tool with no effect: after a crash, once the old child is confirmed
/// gone, recovery may simply run the read again. Version 2: version 1 (before the worker) never
/// replayed, so a session suspended under it does not silently resume under different recovery.
fn read_only_contract() -> crate::tools::ToolContract {
    crate::tools::ToolContract {
        version: 2,
        recovery: crate::session::durable::RecoveryPolicy::RetrySafe { max_attempts: 2 },
    }
}

/// Room left under [`DEFAULT_OUTPUT_CAP`] for the worker's closing note and any stderr, so the worker
/// cuts on a line boundary before the harness's byte cap could cut mid-line.
const READ_HEADROOM: usize = 1024;

/// Exec `bee file-worker` in the scope with `req` on stdin. There is no fallback without our own
/// binary: doing the file I/O here would open the file outside the scope.
async fn run_file_worker(tool: &str, req: &FileRequest, sandbox: &Sandbox) -> ToolResult {
    let exe = match crate::tools::exec::bee_executable() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => return ToolResult::error(format!("{tool}: cannot locate bee executable: {e}")),
    };
    let body = match serde_json::to_vec(req) {
        Ok(b) => b,
        Err(e) => return ToolResult::error(format!("{tool}: encoding request: {e}")),
    };
    run_child(
        sandbox,
        &exe,
        &["file-worker".to_string()],
        Some(body),
        DEFAULT_OUTPUT_CAP,
    )
    .await
}

#[derive(Deserialize)]
struct ReadArgs {
    path: String,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `{ path, offset?, limit? }` → `bee file-worker` with a read request on stdin.
pub struct ReadFile;

#[async_trait::async_trait]
impl Tool for ReadFile {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn durable_contract(&self) -> crate::tools::ToolContract {
        read_only_contract()
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "read_file".to_string(),
            description: "Read a text file, exactly as stored (invalid UTF-8 is shown lossily). For \
                          a large file pass `offset` (1-based first line) and `limit` (line count). \
                          When less than the whole file is shown, a final `[lines a-b of N; continue \
                          with offset=…]` note says where to resume. Binary files are refused. Errors \
                          if the file is missing or access is denied."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file to read." },
                    "offset": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "First line to show, 1-based. Defaults to 1."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Most lines to show. Defaults to all that fit."
                    }
                },
                "required": ["path"]
            }),
        }
    }
    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let args: ReadArgs = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("read_file", e),
        };
        let req = FileRequest::Read(ReadRequest {
            path: args.path,
            offset: args.offset,
            limit: args.limit,
            max_bytes: Some(DEFAULT_OUTPUT_CAP - READ_HEADROOM),
        });
        run_file_worker("read_file", &req, sandbox).await
    }
}

/// `{ path, old_string, new_string, replace_all? }` → `bee file-worker` with an edit request on stdin.
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
                          make it unique. Idempotent: repeating an edit that already landed changes \
                          nothing and reports `unchanged`. Prefer this to write_file for changing \
                          part of a file."
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
        run_file_worker("edit_file", &FileRequest::Edit(req), sandbox).await
    }
}

/// `{ path, line?, regexp?, search_string?, state?, insert_after?, insert_before?, create? }` →
/// `bee file-worker` with an ensure-line request on stdin.
pub struct EnsureLine;

#[async_trait::async_trait]
impl Tool for EnsureLine {
    fn name(&self) -> &'static str {
        "ensure_line"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ensure_line".to_string(),
            description: "Make sure one line is present in, or absent from, a file. Idempotent \
                          (like Ansible's lineinfile): running it again reports `unchanged`. \
                          state=present: with `regexp` or `search_string`, the last matching line \
                          becomes `line`; otherwise, unless an identical line exists, `line` is \
                          inserted after the last `insert_after` match, before the last \
                          `insert_before` match, or at the end. state=absent: removes every \
                          matching line (or every line equal to `line`). Use edit_file for \
                          multi-line changes."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File to change." },
                    "line": {
                        "type": "string",
                        "description": "The line (no line breaks). Required for state=present."
                    },
                    "regexp": {
                        "type": "string",
                        "description": "Regex selecting the line(s) to replace or remove."
                    },
                    "search_string": {
                        "type": "string",
                        "description": "Substring selecting the line(s) to replace or remove. \
                                        Use instead of regexp for literal text."
                    },
                    "state": {
                        "type": "string",
                        "enum": ["present", "absent"],
                        "description": "Defaults to present."
                    },
                    "insert_after": {
                        "type": "string",
                        "description": "Regex, or EOF (default): insert after the last matching line."
                    },
                    "insert_before": {
                        "type": "string",
                        "description": "Regex, or BOF: insert before the last matching line."
                    },
                    "create": {
                        "type": "boolean",
                        "description": "Create the file if it is missing (state=present)."
                    }
                },
                "required": ["path"]
            }),
        }
    }
    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let req: EnsureLineRequest = match serde_json::from_value(arguments) {
            Ok(r) => r,
            Err(e) => return ToolResult::invalid_args("ensure_line", e),
        };
        run_file_worker("ensure_line", &FileRequest::EnsureLine(req), sandbox).await
    }
}

/// `{ "path": string, "content": string }` → `bee file-worker` with a write request on stdin.
pub struct WriteFile;

#[async_trait::async_trait]
impl Tool for WriteFile {
    fn name(&self) -> &'static str {
        "write_file"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "write_file".to_string(),
            description: "Write text to a file (truncating it). Errors if the write is denied by \
                          policy or fails."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Destination file path." },
                    "content": { "type": "string", "description": "Text to write." }
                },
                "required": ["path", "content"]
            }),
        }
    }
    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let req: WriteRequest = match serde_json::from_value(arguments) {
            Ok(r) => r,
            Err(e) => return ToolResult::invalid_args("write_file", e),
        };
        run_file_worker("write_file", &FileRequest::Write(req), sandbox).await
    }
}

/// `{ "path": string }` → `bee file-worker` with a list request on stdin.
pub struct ListDirectory;

#[async_trait::async_trait]
impl Tool for ListDirectory {
    fn name(&self) -> &'static str {
        "list_directory"
    }
    fn durable_contract(&self) -> crate::tools::ToolContract {
        read_only_contract()
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "list_directory".to_string(),
            description: "List a directory's entries (one per line; trailing '/' marks subdirs). \
                          Errors if the directory is missing or access is denied."
                .to_string(),
            parameters: string_prop("path", "Directory path to list.", &["path"]),
        }
    }
    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let args: PathArgs = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("list_directory", e),
        };
        let req = FileRequest::List(ListRequest { path: args.path });
        run_file_worker("list_directory", &req, sandbox).await
    }
}
