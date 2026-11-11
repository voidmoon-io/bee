//! End-to-end for the file tools (`read_file`, `edit_file`, `ensure_line`, `write_file`,
//! `list_directory`): the hidden `bee file-worker` subcommand run directly,
//! so the stdin-JSON contract, exit codes and the in-place write are exercised exactly as the tools
//! invoke them; then the tools themselves through a host sandbox and through codemode.

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

fn edit(mut req: serde_json::Value) -> (i32, String, String) {
    req["op"] = "edit".into();
    worker(req)
}

fn worker(req: serde_json::Value) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bee"))
        .arg("file-worker")
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
    for req in [
        serde_json::json!({"op": "edit", "path": "x"}),
        serde_json::json!({"path": "x"}),
        serde_json::json!({"op": "delete", "path": "x"}),
    ] {
        let (code, _, err) = worker(req);
        assert_eq!(code, 2);
        assert!(err.contains("invalid request"), "{err}");
    }
}

#[test]
fn the_worker_reads_a_line_range() {
    let p = temp_file("read", b"one\ntwo\nthree\n");
    let (code, out, err) =
        worker(serde_json::json!({"op": "read", "path": p, "offset": 2, "limit": 1}));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "two\n[lines 2-2 of 3; continue with offset=3]\n");
    let (code, _, err) = worker(serde_json::json!({"op": "read", "path": p, "offset": 9}));
    assert_eq!(code, 1);
    assert!(err.contains("past the end"), "{err}");
    let (code, _, err) =
        worker(serde_json::json!({"op": "read", "path": p.with_file_name("none")}));
    assert_eq!(code, 2);
    assert!(err.contains("No such file"), "{err}");
}

#[test]
fn a_repeated_edit_reports_unchanged() {
    let p = temp_file("repeat", b"call(foo);\n");
    let req = serde_json::json!({"path": p, "old_string": "foo", "new_string": "foo(bar)"});
    let (code, out, err) = edit(req.clone());
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("edited "), "{out}");
    let (code, out, err) = edit(req);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("unchanged "), "{out}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "call(foo(bar));\n");
}

#[test]
fn ensure_line_converges_through_the_worker() {
    let p = temp_file("ensure", b"Port 22\n");
    let dir = p.parent().unwrap();
    let req = serde_json::json!({"op": "ensure_line", "path": p, "line": "Port 2222", "regexp": "^Port "});
    let (code, out, err) = worker(req.clone());
    assert_eq!(code, 0, "{err}");
    assert!(
        out.starts_with("changed ") && out.contains("replaced line 1"),
        "{out}"
    );
    let (code, out, _) = worker(req);
    assert_eq!(code, 0);
    assert!(out.starts_with("unchanged "), "{out}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "Port 2222\n");

    let fresh = dir.join("fresh.conf");
    let create =
        serde_json::json!({"op": "ensure_line", "path": fresh, "line": "on", "create": true});
    let (code, out, err) = worker(create);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("created the file"), "{out}");
    assert_eq!(std::fs::read_to_string(&fresh).unwrap(), "on\n");

    let missing = dir.join("missing.conf");
    let (code, _, err) =
        worker(serde_json::json!({"op": "ensure_line", "path": missing, "line": "on"}));
    assert_eq!(code, 2, "no create: a missing file is an error");
    assert!(err.contains("No such file"), "{err}");
    let (code, out, _) = worker(
        serde_json::json!({"op": "ensure_line", "path": missing, "line": "on", "state": "absent"}),
    );
    assert_eq!(code, 0);
    assert!(out.starts_with("unchanged "), "{out}");
    assert!(!missing.exists());

    let (code, _, err) =
        worker(serde_json::json!({"op": "ensure_line", "path": p, "line": "x", "regexp": "("}));
    assert_eq!(code, 1);
    assert!(err.contains("not a valid regex"), "{err}");
}

#[test]
fn the_worker_writes_and_lists() {
    let p = temp_file("write", b"old contents that are longer\n");
    let (code, out, err) =
        worker(serde_json::json!({"op": "write", "path": p, "content": "new\n"}));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("wrote 4 bytes"), "{out}");
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "new\n",
        "truncated, not overlaid"
    );
    let dir = p.parent().unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join(".hidden"), "").unwrap();
    let created = dir.join("created.txt");
    let (code, _, err) = worker(serde_json::json!({"op": "write", "path": created, "content": ""}));
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = worker(serde_json::json!({"op": "list", "path": dir}));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, ".hidden\ncreated.txt\nf.txt\nsub/\n");
    let (code, _, err) = worker(serde_json::json!({"op": "list", "path": dir.join("absent")}));
    assert_eq!(code, 2);
    assert!(err.contains("No such file"), "{err}");
}

fn host() -> bee::Sandbox {
    bee::Sandbox::host(vec![])
}

#[tokio::test]
async fn the_tools_run_the_worker_through_the_sandbox() {
    let p = temp_file("tools", b"alpha\nbeta\ngamma\n");
    let registry = bee::tools::registry_for(&["read_file".into(), "edit_file".into()], None);
    let sb = host();
    let edit = registry
        .execute(
            &bee::provider::ToolCall {
                id: "e".into(),
                name: "edit_file".into(),
                arguments: serde_json::json!({"path": p, "old_string": "beta", "new_string": "BETA"}),
            },
            &sb,
        )
        .await;
    assert!(!edit.is_error, "{}", edit.content);
    let read = registry
        .execute(
            &bee::provider::ToolCall {
                id: "r".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({"path": p, "offset": 2, "limit": 1}),
            },
            &sb,
        )
        .await;
    assert!(!read.is_error, "{}", read.content);
    assert!(
        read.content.starts_with("BETA\n[lines 2-2 of 3"),
        "{}",
        read.content
    );
    let refused = registry
        .execute(
            &bee::provider::ToolCall {
                id: "x".into(),
                name: "edit_file".into(),
                arguments: serde_json::json!({"path": p, "old_string": "nope", "new_string": "x"}),
            },
            &sb,
        )
        .await;
    assert!(
        refused.is_error && refused.content.contains("not found"),
        "{}",
        refused.content
    );
}

#[tokio::test]
async fn write_and_list_run_the_worker_too() {
    let p = temp_file("tools-wl", b"");
    let dir = p.parent().unwrap().to_path_buf();
    let registry = bee::tools::registry_for(&["write_file".into(), "list_directory".into()], None);
    let sb = host();
    let call = |name: &str, arguments: serde_json::Value| bee::provider::ToolCall {
        id: name.into(),
        name: name.into(),
        arguments,
    };
    let wrote = registry
        .execute(
            &call(
                "write_file",
                serde_json::json!({"path": dir.join("n.txt"), "content": "hi"}),
            ),
            &sb,
        )
        .await;
    assert!(!wrote.is_error, "{}", wrote.content);
    assert!(
        wrote.content.starts_with("wrote 2 bytes to "),
        "{}",
        wrote.content
    );
    let listed = registry
        .execute(
            &call("list_directory", serde_json::json!({"path": dir})),
            &sb,
        )
        .await;
    assert!(!listed.is_error, "{}", listed.content);
    assert!(
        listed.content.starts_with("f.txt\nn.txt\n"),
        "{}",
        listed.content
    );
}

#[test]
fn the_file_tools_are_default_and_registered() {
    for name in [
        "read_file",
        "edit_file",
        "ensure_line",
        "write_file",
        "list_directory",
    ] {
        assert!(bee::tools::DEFAULT_TOOLS.contains(&name));
        assert!(bee::tools::is_known_tool(name));
        assert!(bee::tools::registry_for(&[name.to_string()], None).contains(name));
    }
}

/// Codemode reaches every file tool through the guest catalog: a Python script edits, reads a range,
/// writes and lists, with each inner call dispatched by the driver under the outer codemode call.
#[cfg(feature = "durable-sessions")]
mod codemode {
    use bee::provider::{mock_model::MockModel, Message, ToolCall, Turn};
    use bee::session::driver::{Limits, Session};
    use bee::session::durable::SessionId;
    use serde_json::json;

    struct Quiet;
    impl bee::repl::ReplOutput for Quiet {
        fn assistant_delta(&self, _: &str) {}
        fn assistant_end(&self) {}
        fn tool_call(&self, _: &str, _: &serde_json::Value) {}
        fn tool_result(&self, _: &bee::ToolResult, _: &[bee_core::AuditEvent]) {}
        fn error(&self, _: &str) {}
        fn info(&self, _: &str) {}
    }

    fn model(source: String) -> MockModel {
        MockModel::from_fn(move |c| {
            if c.messages
                .iter()
                .any(|m| matches!(m, Message::ToolResult { .. }))
            {
                Turn::text("done")
            } else {
                Turn::calls(vec![ToolCall {
                    id: "outer".into(),
                    name: "codemode".into(),
                    arguments: json!({ "source": source }),
                }])
            }
        })
        .with_id("file-tools-codemode")
    }

    #[tokio::test]
    async fn a_script_uses_every_file_tool() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("f.txt");
        std::fs::write(&path, "alpha\nbeta\ngamma\n").unwrap();
        let p = json!(path);
        let n = json!(root.path().join("n.txt"));
        let d = json!(root.path());
        let source = format!(
            "e = call_tool('edit_file', {{'path': {p}, 'old_string': 'beta', 'new_string': 'BETA'}})\n\
             r = call_tool('read_file', {{'path': {p}, 'offset': 2, 'limit': 1}})\n\
             m = call_tool('edit_file', {{'path': {p}, 'old_string': 'nope', 'new_string': 'x'}})\n\
             w = call_tool('write_file', {{'path': {n}, 'content': 'new'}})\n\
             l = call_tool('list_directory', {{'path': {d}}})\n\
             s1 = call_tool('ensure_line', {{'path': {n}, 'line': 'tail', 'insert_after': 'EOF'}})\n\
             s2 = call_tool('ensure_line', {{'path': {n}, 'line': 'tail', 'insert_after': 'EOF'}})\n\
             [e['is_error'], r['is_error'], 'BETA' in r['content'], 'alpha' in r['content'], \
             '[lines 2-2 of 3; continue with offset=3]' in r['content'], m['is_error'], \
             w['is_error'], 'n.txt' in l['content'], \
             'changed' in s1['content'], 'unchanged' in s2['content']]"
        );
        let session = Session::open_observed(
            root.path().join("session"),
            SessionId("file-tools".into()),
            "config".into(),
            None,
            None,
        )
        .await
        .unwrap();
        let mut registry = bee::tools::registry_for(
            &bee::tools::DEFAULT_TOOLS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            None,
        );
        registry.enable_evidence(session.evidence());
        let limits = Limits {
            turns: 4,
            tool_calls: 10,
            timeout_ms: 30_000,
            tool_timeout_ms: 10_000,
            model_attempts: 2,
        };
        let (report, _) = session
            .run(
                "request",
                Some("go"),
                "system",
                limits,
                &model(source),
                &mut registry,
                &mut bee::Sandbox::host(vec![]),
                &Quiet,
                None,
            )
            .await
            .unwrap();
        let calls = &report.turns[0].calls;
        let names: Vec<_> = calls.iter().map(|c| c.call.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "edit_file",
                "read_file",
                "edit_file",
                "write_file",
                "list_directory",
                "ensure_line",
                "ensure_line",
                "codemode"
            ]
        );
        assert!(calls[..7]
            .iter()
            .all(|c| c.parent_call_id.as_deref() == Some("outer")));
        let value: serde_json::Value = serde_json::from_str(&calls[7].result.content).unwrap();
        assert_eq!(
            value["value"],
            json!([false, false, true, false, true, true, false, true, true, true]),
            "{value}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "alpha\nBETA\ngamma\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("n.txt")).unwrap(),
            "new\ntail\n"
        );
    }
}
