//! The `edit_file` tool's worker: an exact-string replacement that runs inside the scope.
//!
//! Same seam as [`crate::search`]: the harness never opens a file itself (contracts/tool-contracts.md).
//! [`crate::tools::edit`] execs `bee edit-worker` through [`crate::tools::exec::run_child`], so the
//! read and the write-back both happen in a process that has joined the scope cgroup, and the LSM
//! mediates each open. The request travels on **stdin as JSON**, not argv: the strings are arbitrary
//! model text, possibly large, and argv is neither size-safe nor the place for file contents.
//!
//! The edit itself is [`apply`], a pure function, so its rules are unit-tested without a process:
//! `old_string` must be non-empty, differ from `new_string`, and — unless `replace_all` — match
//! **exactly once**. Zero or several matches is refused with a message saying which, so the model can
//! widen its context and retry instead of silently editing the wrong place.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// One `edit_file` request, shared by the tool (which serializes it onto the worker's stdin) and the
/// worker (which parses it back).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRequest {
    pub path: String,
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: bool,
}

/// Why an edit was refused. Each variant renders as one actionable sentence for the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    EmptyOld,
    NoChange,
    NotFound,
    Ambiguous { count: usize },
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOld => f.write_str("old_string is empty; use write_file to create a file"),
            Self::NoChange => f.write_str("old_string and new_string are identical; nothing to do"),
            Self::NotFound => f.write_str(
                "old_string not found; it must match the file exactly, including whitespace",
            ),
            Self::Ambiguous { count } => write!(
                f,
                "old_string matches {count} times; add surrounding context to make it unique, \
                 or set replace_all"
            ),
        }
    }
}

/// Apply the edit to `content`, returning the new text and how many replacements were made.
pub fn apply(content: &str, req: &EditRequest) -> Result<(String, usize), EditError> {
    if req.old_string.is_empty() {
        return Err(EditError::EmptyOld);
    }
    if req.old_string == req.new_string {
        return Err(EditError::NoChange);
    }
    let count = content.matches(req.old_string.as_str()).count();
    match (count, req.replace_all) {
        (0, _) => Err(EditError::NotFound),
        (1, _) | (_, true) => Ok((
            content.replace(req.old_string.as_str(), &req.new_string),
            count,
        )),
        (n, false) => Err(EditError::Ambiguous { count: n }),
    }
}

/// The worker body: read the JSON request from `input`, edit the file, report on `out`.
///
/// Exit codes: 0 edited, 1 refused (the rule in [`EditError`]), 2 bad request or I/O (including a
/// kernel denial, which surfaces as `EACCES` from the open). A non-UTF-8 file is refused rather than
/// rewritten lossily — an edit must never corrupt bytes it was not asked to touch.
pub fn run(input: &mut impl Read, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let mut raw = String::new();
    if let Err(e) = input.read_to_string(&mut raw) {
        let _ = writeln!(err, "edit_file: reading request: {e}");
        return 2;
    }
    let req: EditRequest = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "edit_file: invalid request: {e}");
            return 2;
        }
    };
    let content = match std::fs::read(&req.path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                let _ = writeln!(err, "edit_file: {} is not valid UTF-8; refusing", req.path);
                return 2;
            }
        },
        Err(e) => {
            let _ = writeln!(err, "edit_file: {}: {e}", req.path);
            return 2;
        }
    };
    let (updated, count) = match apply(&content, &req) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(err, "edit_file: {e}");
            return 1;
        }
    };
    if let Err(e) = write_in_place(&req.path, updated.as_bytes()) {
        let _ = writeln!(err, "edit_file: writing {}: {e}", req.path);
        return 2;
    }
    let noun = if count == 1 {
        "replacement"
    } else {
        "replacements"
    };
    let _ = writeln!(out, "edited {}: {count} {noun}", req.path);
    0
}

/// Truncate-and-write the existing file, like `write_file`'s `tee`. Deliberately not temp+rename: that
/// needs create rights in the directory, which a scope granting only this file's write would deny.
fn write_in_place(path: &str, bytes: &[u8]) -> io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(old: &str, new: &str, all: bool) -> EditRequest {
        EditRequest {
            path: "f".into(),
            old_string: old.into(),
            new_string: new.into(),
            replace_all: all,
        }
    }

    #[test]
    fn a_unique_match_is_replaced() {
        let (s, n) = apply("let a = 1;\nlet b = 2;\n", &req("b = 2", "b = 3", false)).unwrap();
        assert_eq!((s.as_str(), n), ("let a = 1;\nlet b = 3;\n", 1));
    }

    #[test]
    fn no_match_is_refused() {
        assert_eq!(
            apply("abc", &req("xyz", "q", false)),
            Err(EditError::NotFound)
        );
    }

    #[test]
    fn several_matches_are_refused_without_replace_all() {
        assert_eq!(
            apply("x x x", &req("x", "y", false)),
            Err(EditError::Ambiguous { count: 3 })
        );
    }

    #[test]
    fn replace_all_replaces_every_match() {
        assert_eq!(
            apply("x x x", &req("x", "y", true)),
            Ok(("y y y".into(), 3))
        );
    }

    #[test]
    fn empty_and_identical_strings_are_refused() {
        assert_eq!(apply("abc", &req("", "q", false)), Err(EditError::EmptyOld));
        assert_eq!(
            apply("abc", &req("a", "a", false)),
            Err(EditError::NoChange)
        );
    }

    #[test]
    fn whitespace_is_significant() {
        assert_eq!(
            apply("    indented", &req("  indented\n", "x", false)),
            Err(EditError::NotFound)
        );
    }
}
