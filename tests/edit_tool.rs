//! End-to-end for the `edit_file` tool's payload: the hidden `bee edit-worker` subcommand the tool
//! execs through the sandbox. Runs the real built binary over a temp file so the stdin-JSON contract,
//! exit codes and the in-place write are exercised exactly as the tool invokes them. (Under
//! `cargo test`, `current_exe()` is the test harness, so the Tool wrapper itself is covered by the
//! schema and registry assertions here, as `search` does.)

use std::io::Write;
use std::process::{Command, Stdio};

fn temp_file(tag: &str, content: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bee-edit-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("f.txt");
    std::fs::write(&path, content).unwrap();
    path
}

fn edit(req: serde_json::Value) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bee"))
        .arg("edit-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bee edit-worker");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(req.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_unique_match_is_edited_in_place() {
    let p = temp_file("unique", b"fn a() {}\nfn b() {}\n");
    let (code, out, err) = edit(serde_json::json!({
        "path": p, "old_string": "fn b() {}", "new_string": "fn b() { todo!() }"
    }));
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("1 replacement"), "{out}");
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "fn a() {}\nfn b() { todo!() }\n"
    );
}

#[test]
fn an_ambiguous_match_is_refused_and_the_file_is_untouched() {
    let p = temp_file("ambiguous", b"x\nx\n");
    let (code, _, err) = edit(serde_json::json!({"path": p, "old_string": "x", "new_string": "y"}));
    assert_eq!(code, 1);
    assert!(err.contains("matches 2 times"), "{err}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "x\nx\n");
}

#[test]
fn replace_all_edits_every_match() {
    let p = temp_file("all", b"x\nx\n");
    let (code, out, _) = edit(serde_json::json!({
        "path": p, "old_string": "x", "new_string": "y", "replace_all": true
    }));
    assert_eq!(code, 0);
    assert!(out.contains("2 replacements"), "{out}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "y\ny\n");
}

#[test]
fn a_missing_file_is_an_error_not_a_creation() {
    let p = std::env::temp_dir().join(format!("bee-edit-{}-missing/none", std::process::id()));
    let (code, _, err) = edit(serde_json::json!({"path": p, "old_string": "a", "new_string": "b"}));
    assert_eq!(code, 2, "{err}");
    assert!(!p.exists());
}

#[test]
fn a_non_utf8_file_is_refused_unchanged() {
    let bytes = b"ok \xff\xfe bytes";
    let p = temp_file("binary", bytes);
    let (code, _, err) =
        edit(serde_json::json!({"path": p, "old_string": "ok", "new_string": "no"}));
    assert_eq!(code, 2);
    assert!(err.contains("UTF-8"), "{err}");
    assert_eq!(std::fs::read(&p).unwrap(), bytes);
}

#[test]
fn malformed_request_is_rejected() {
    let (code, _, err) = edit(serde_json::json!({"path": "x"}));
    assert_eq!(code, 2);
    assert!(err.contains("invalid request"), "{err}");
}

#[test]
fn edit_file_is_a_default_registered_tool() {
    assert!(bee::tools::DEFAULT_TOOLS.contains(&"edit_file"));
    assert!(bee::tools::is_known_tool("edit_file"));
    let registry = bee::tools::registry_for(&["edit_file".to_string()], None);
    assert!(registry.contains("edit_file"));
}
