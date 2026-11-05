//! One-line summaries of tool calls, for display only.
//!
//! A call is shown as `▸ <name> <target>` and its result as `✓ <outcome>`, where the target says
//! what the call is about (`src/repl.rs`, `"terminate!" in src`, `cargo build`) and the outcome what
//! came of it (`41 lines`, `7 hits in 3 files`, `exit 0 · 12 passed`). The raw JSON arguments and
//! the first line of output said neither.
//!
//! This is a table keyed by tool name rather than a method on `Tool`, so tools stay free of display
//! concerns. Summaries are built only from the call's arguments and the result the model already
//! receives — nothing here changes what the model sees. Every string is passed through
//! [`safe_line`]: arguments and output are untrusted, and these lines go straight to the terminal.
//!
//! A tool without an entry, or a call whose arguments do not parse, returns `None`, and the caller
//! falls back to its generic rendering.

use serde_json::Value;

use crate::safe_text::safe_line;
use crate::tools::ToolResult;

/// The longest target shown, in characters.
const MAX_TARGET_CHARS: usize = 80;
/// The most preview lines shown under a failed call.
const MAX_PREVIEW_LINES: usize = 3;

/// What a call is about, for the call line: `None` for a tool with no summary (or arguments that do
/// not parse), in which case the caller shows its generic form.
pub fn target(name: &str, args: &Value) -> Option<String> {
    let s = |key: &str| args.get(key).and_then(Value::as_str);
    let t = match name {
        "read_file" | "write_file" => s("path")?.to_string(),
        "list_directory" => s("path").unwrap_or(".").to_string(),
        "search" => {
            let mut t = format!("\"{}\"", s("pattern")?);
            if let Some(path) = s("path").filter(|p| !p.is_empty() && *p != ".") {
                t.push_str(&format!(" in {path}"));
            }
            if let Some(glob) = s("glob").filter(|g| !g.is_empty()) {
                t.push_str(&format!(" ({glob})"));
            }
            t
        }
        "bash" => {
            let command = s("command")?.trim();
            let first = command.lines().next().unwrap_or("");
            if command.lines().nth(1).is_some() {
                format!("{first} …")
            } else {
                first.to_string()
            }
        }
        "codemode" => codemode_target(s("source")?),
        _ => return None,
    };
    Some(clip(&safe_line(&t), MAX_TARGET_CHARS))
}

/// What came of a completed call, for the result line: `None` when the tool has no summary, and the
/// caller shows the first line of output instead.
pub fn outcome(name: &str, args: &Value, result: &ToolResult) -> Option<String> {
    if name == "bash" {
        return Some(bash_outcome(result));
    }
    if result.is_error {
        // A refused or failed call: its own first line says why better than any count would.
        return None;
    }
    let o = match name {
        "read_file" => count(lines(&result.content), "line", result.truncated),
        "write_file" => {
            let written = args.get("content").and_then(Value::as_str).unwrap_or("");
            format!("{} written", count(lines(written), "line", false))
        }
        "list_directory" => count(lines(&result.content), "entry", result.truncated),
        "search" => search_outcome(&result.content),
        _ => return None,
    };
    Some(o)
}

/// Lines worth showing under the result line even when the output is otherwise hidden: the tail of
/// a failed command (where compilers and test runners put the error), or the rest of another tool's
/// error message. Empty for a call that succeeded.
pub fn preview(name: &str, result: &ToolResult) -> Vec<String> {
    if !result.is_error {
        return Vec::new();
    }
    let meaningful: Vec<&str> = result
        .content
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty() && *l != "[stderr]")
        .collect();
    let picked: Vec<&str> = if name == "bash" {
        let from = meaningful.len().saturating_sub(MAX_PREVIEW_LINES);
        meaningful[from..].to_vec()
    } else {
        // The first line is already the outcome line.
        meaningful
            .iter()
            .skip(1)
            .take(MAX_PREVIEW_LINES)
            .copied()
            .collect()
    };
    picked
        .into_iter()
        .map(|l| clip(&safe_line(l), MAX_TARGET_CHARS * 2))
        .collect()
}

/// The script's first comment or docstring line, else its size.
fn codemode_target(source: &str) -> String {
    let described = source.lines().map(str::trim).find_map(|l| {
        let text = l
            .strip_prefix('#')
            .or_else(|| l.strip_prefix("\"\"\""))
            .or_else(|| l.strip_prefix("'''"))?;
        let text = text
            .trim_end_matches("\"\"\"")
            .trim_end_matches("'''")
            .trim();
        (!text.is_empty()).then(|| text.to_string())
    });
    described.unwrap_or_else(|| format!("{}-line script", lines(source)))
}

/// `exit N`, plus a test tally when the output looks like cargo or pytest.
fn bash_outcome(result: &ToolResult) -> String {
    let exit = match result.exit_code {
        Some(code) => format!("exit {code}"),
        None if result.is_error => "failed".to_string(),
        None => "done".to_string(),
    };
    match test_tally(&result.content) {
        Some(tally) => format!("{exit} · {tally}"),
        None => exit,
    }
}

/// `N passed, M failed` summed over every cargo `test result:` line, or read from a pytest summary
/// line. Best effort: `None` when the output has neither.
fn test_tally(output: &str) -> Option<String> {
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut seen = false;
    for line in output.lines().map(str::trim) {
        let cargo = line.strip_prefix("test result: ");
        let pytest = line.starts_with('=') && line.ends_with('=') && line.contains(" in ");
        if cargo.is_none() && !pytest {
            continue;
        }
        let body = cargo.unwrap_or(line);
        for part in body.split([';', ',', '=']) {
            let mut words = part.split_whitespace();
            let (Some(n), Some(word)) = (words.next(), words.next()) else {
                continue;
            };
            // cargo says "ok. 5 passed", so skip a leading verdict word.
            let (n, word) = match n.parse::<u64>() {
                Ok(n) => (n, word),
                Err(_) => match (word.parse::<u64>(), words.next()) {
                    (Ok(n), Some(w)) => (n, w),
                    _ => continue,
                },
            };
            match word {
                "passed" => passed += n,
                "failed" => failed += n,
                _ => continue,
            }
            seen = true;
        }
    }
    seen.then(|| {
        if failed > 0 {
            format!("{passed} passed, {failed} failed")
        } else {
            format!("{passed} passed")
        }
    })
}

/// `N hits in M files` for `path:line:text` output; the worker caps results, so a capped count says
/// so.
fn search_outcome(output: &str) -> String {
    let mut hits = 0usize;
    let mut files = std::collections::BTreeSet::new();
    for line in output.lines() {
        let mut parts = line.splitn(3, ':');
        if let (Some(path), Some(n), Some(_)) = (parts.next(), parts.next(), parts.next()) {
            if n.parse::<u64>().is_ok() {
                hits += 1;
                files.insert(path);
            }
        }
    }
    if hits == 0 {
        return "no matches".to_string();
    }
    let capped = if hits >= crate::tools::search::MATCH_LIMIT {
        " (capped)"
    } else {
        ""
    };
    format!(
        "{} in {}{capped}",
        count(hits, "hit", false),
        count(files.len(), "file", false)
    )
}

fn lines(text: &str) -> usize {
    text.lines().count()
}

/// `1 line`, `3 lines`, `40+ lines` when the output was truncated.
fn count(n: usize, noun: &str, truncated: bool) -> String {
    let plus = if truncated { "+" } else { "" };
    let noun = match (n, noun) {
        (1, _) => noun.to_string(),
        (_, "entry") => "entries".to_string(),
        _ => format!("{noun}s"),
    };
    format!("{n}{plus} {noun}")
}

/// At most `max` characters, with `…` marking a cut.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(content: &str) -> ToolResult {
        ToolResult::ok(content.to_string())
    }

    fn exited(code: i32, content: &str) -> ToolResult {
        ToolResult {
            exit_code: Some(code),
            is_error: code != 0,
            ..ok(content)
        }
    }

    #[test]
    fn read_file_shows_the_path_and_a_line_count() {
        let args = json!({ "path": "src/repl.rs" });
        assert_eq!(target("read_file", &args).as_deref(), Some("src/repl.rs"));
        assert_eq!(
            outcome("read_file", &args, &ok("a\nb\nc\n")).as_deref(),
            Some("3 lines")
        );
        let cut = ToolResult {
            truncated: true,
            ..ok("a\nb\n")
        };
        assert_eq!(
            outcome("read_file", &args, &cut).as_deref(),
            Some("2+ lines")
        );
    }

    #[test]
    fn write_file_counts_what_was_written() {
        let args = json!({ "path": "out.txt", "content": "one\ntwo\n" });
        assert_eq!(target("write_file", &args).as_deref(), Some("out.txt"));
        assert_eq!(
            outcome("write_file", &args, &ok("wrote 8 bytes to out.txt")).as_deref(),
            Some("2 lines written")
        );
    }

    #[test]
    fn list_directory_counts_entries() {
        let args = json!({});
        assert_eq!(target("list_directory", &args).as_deref(), Some("."));
        assert_eq!(
            outcome("list_directory", &args, &ok("a/\nb\n")).as_deref(),
            Some("2 entries")
        );
    }

    #[test]
    fn search_shows_the_pattern_and_counts_hits_and_files() {
        let args = json!({ "pattern": "terminate!", "path": "src", "glob": "*.rs" });
        assert_eq!(
            target("search", &args).as_deref(),
            Some("\"terminate!\" in src (*.rs)")
        );
        let out = "src/a.rs:1:x\nsrc/a.rs:9:y\nsrc/b.rs:3:z\n";
        assert_eq!(
            outcome("search", &args, &ok(out)).as_deref(),
            Some("3 hits in 2 files")
        );
        assert_eq!(
            outcome("search", &args, &ok("")).as_deref(),
            Some("no matches")
        );
        let capped: String = (0..crate::tools::search::MATCH_LIMIT)
            .map(|i| format!("f.rs:{i}:x\n"))
            .collect();
        assert!(outcome("search", &args, &ok(&capped))
            .unwrap()
            .ends_with("(capped)"));
    }

    #[test]
    fn bash_shows_the_first_command_line_and_the_exit_code() {
        let args = json!({ "command": "cargo build\ncargo test" });
        assert_eq!(target("bash", &args).as_deref(), Some("cargo build …"));
        assert_eq!(
            outcome("bash", &args, &exited(0, "done")).as_deref(),
            Some("exit 0")
        );
    }

    #[test]
    fn bash_tallies_cargo_and_pytest_results() {
        let cargo = "running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored\n\
                     test result: FAILED. 5 passed; 2 failed; 1 ignored\n";
        assert_eq!(
            outcome("bash", &json!({}), &exited(101, cargo)).as_deref(),
            Some("exit 101 · 8 passed, 2 failed")
        );
        let pytest = "....F\n===== 1 failed, 4 passed in 0.12s =====\n";
        assert_eq!(
            outcome("bash", &json!({}), &exited(1, pytest)).as_deref(),
            Some("exit 1 · 4 passed, 1 failed")
        );
    }

    #[test]
    fn a_failed_command_previews_its_last_lines() {
        let out = "Compiling x\nwarning: unused\n[stderr]\nerror[E0425]: not found\n  --> a.rs:3\n";
        assert_eq!(
            preview("bash", &exited(101, out)),
            ["warning: unused", "error[E0425]: not found", "  --> a.rs:3"]
        );
        assert!(preview("bash", &exited(0, out)).is_empty());
    }

    #[test]
    fn another_tools_error_keeps_its_own_first_line() {
        let args = json!({ "path": "/etc/shadow" });
        let denied = ToolResult::error("cat: /etc/shadow: Permission denied\nhint".to_string());
        assert_eq!(outcome("read_file", &args, &denied), None);
        assert_eq!(preview("read_file", &denied), ["hint"]);
    }

    #[test]
    fn codemode_uses_its_first_comment_else_its_size() {
        let commented = json!({ "source": "# count the tests\nx = 1\n" });
        assert_eq!(
            target("codemode", &commented).as_deref(),
            Some("count the tests")
        );
        let docstring = json!({ "source": "\"\"\"Find callers.\"\"\"\n" });
        assert_eq!(
            target("codemode", &docstring).as_deref(),
            Some("Find callers.")
        );
        let bare = json!({ "source": "a = 1\nb = 2\n" });
        assert_eq!(target("codemode", &bare).as_deref(), Some("2-line script"));
    }

    #[test]
    fn malformed_args_and_unknown_tools_fall_back() {
        assert_eq!(target("read_file", &json!({ "path": 7 })), None);
        assert_eq!(target("bash", &json!("not an object")), None);
        assert_eq!(target("http_get", &json!({ "url": "x" })), None);
        assert_eq!(outcome("http_get", &json!({}), &ok("x")), None);
    }

    #[test]
    fn summaries_are_sanitized_and_clipped() {
        let args = json!({ "command": format!("echo \u{1b}[2Jpwned {}", "x".repeat(200)) });
        let t = target("bash", &args).unwrap();
        assert!(!t.contains('\u{1b}'), "{t:?}");
        assert!(t.chars().count() <= MAX_TARGET_CHARS && t.ends_with('…'));
    }
}
