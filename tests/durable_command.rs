#![cfg(feature = "durable-sessions")]
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn sigint_persists_cancellation_and_cleans_up_the_native_child() {
    if cfg!(feature = "enforce") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let provider = root.path().join("provider.toml");
    let config = serde_json::json!({"provider": {"provider":"mock", "script":[
        {"tool":"bash", "args":{"command":"printf '%s' \"$$\" > child-pid; sleep 30"}}
    ]}});
    std::fs::write(&provider, toml::to_string(&config).unwrap()).unwrap();
    let state = root.path().join("session");
    let mut child = Command::new(env!("CARGO_BIN_EXE_bee"))
        .args([
            "run",
            "--host",
            "--task",
            "wait",
            "--tools",
            "bash",
            "--provider",
        ])
        .arg(&provider)
        .arg("--session-dir")
        .arg(&state)
        .args(["--session-id", "cancel", "--request-id", "request"])
        .current_dir(root.path())
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(root.path().join("child-pid")) {
            if let Ok(pid) = text.parse::<u32>() {
                break pid;
            }
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "tool did not start: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CLI did not finish cancellation");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let report: bee::EpisodeTranscript = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&output.stderr)));
    assert!(matches!(
        report.status,
        bee::EpisodeStatus::Terminated { .. }
    ));
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    let mut store = bee::session::durable::store::Store::open(
        &state,
        bee::session::durable::SessionId("cancel".into()),
    )
    .unwrap();
    let inputs = store.submissions(0, 100).unwrap();
    assert!(inputs.iter().any(|input| input.input["kind"] == "Cancel"));
}

fn run(root: &Path, args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(args)
        .current_dir(root)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root)
        .env("XDG_STATE_HOME", root.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn headless_request_replays_in_inline_repl_and_keeps_the_same_receipt() {
    if cfg!(feature = "enforce") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let provider = root.path().join("provider.toml");
    let provider_config = serde_json::json!({"provider": {"provider":"mock", "script":[
        {"tool":"bash", "args":{"command":"printf effect >> count"}},
        {"text":"finished"}
    ]}});
    std::fs::write(&provider, toml::to_string(&provider_config).unwrap()).unwrap();
    let state = root.path().join("session");
    let provider = provider.to_str().unwrap();
    let state = state.to_str().unwrap();
    let args = [
        "run",
        "--host",
        "--task",
        "investigate",
        "--system",
        "system",
        "--tools",
        "bash",
        "--provider",
        provider,
        "--session-dir",
        state,
        "--session-id",
        "fixture",
        "--request-id",
        "request",
    ];
    let first = run(root.path(), &args, "");
    assert!(
        first.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&first.stdout)
    );
    let transcript: bee::EpisodeTranscript = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(transcript.status, bee::EpisodeStatus::Completed);
    let second = run(root.path(), &args, "");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let repeated: bee::EpisodeTranscript = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(
        serde_json::to_value(&transcript.turns).unwrap(),
        serde_json::to_value(repeated.turns).unwrap()
    );
    let saved = root.path().join("repl.json");
    let repl = run(
        root.path(),
        &[
            "repl",
            "--host",
            "--no-bee",
            "--no-tui",
            "--system",
            "system",
            "--tools",
            "bash",
            "--provider",
            provider,
            "--session-dir",
            state,
            "--session-id",
            "fixture",
            "--resume",
            "request",
            "--save",
            saved.to_str().unwrap(),
        ],
        "",
    );
    assert!(
        repl.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&repl.stderr),
        String::from_utf8_lossy(&repl.stdout)
    );
    let resumed: bee::EpisodeTranscript =
        serde_json::from_slice(&std::fs::read(saved).unwrap()).unwrap();
    assert_eq!(resumed.durable_budget, transcript.durable_budget);
    assert_eq!(
        serde_json::to_value(transcript.turns).unwrap(),
        serde_json::to_value(resumed.turns).unwrap(),
        "{}\n{}",
        String::from_utf8_lossy(&repl.stdout),
        String::from_utf8_lossy(&repl.stderr)
    );
    assert_eq!(std::fs::read(root.path().join("count")).unwrap(), b"effect");
}

#[test]
fn explicit_tool_budget_is_reported_and_cannot_be_increased_by_replay() {
    if cfg!(feature = "enforce") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let provider = root.path().join("provider.toml");
    let config = serde_json::json!({"provider": {"provider":"mock", "script":[
        {"tool":"bash", "args":{"command":"printf effect > count"}}
    ]}});
    std::fs::write(&provider, toml::to_string(&config).unwrap()).unwrap();
    let state = root.path().join("session");
    let mut args = vec![
        "run",
        "--host",
        "--task",
        "task",
        "--tools",
        "bash",
        "--provider",
        provider.to_str().unwrap(),
        "--session-dir",
        state.to_str().unwrap(),
        "--session-id",
        "budget",
        "--request-id",
        "request",
        "--tool-call-limit",
        "0",
    ];
    for limit in ["0", "50"] {
        *args.last_mut().unwrap() = limit;
        let output = run(root.path(), &args, "");
        let report: bee::EpisodeTranscript = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
        assert_eq!(report.status, bee::EpisodeStatus::Timeout);
        let budget = report.durable_budget.unwrap();
        assert_eq!(budget.charged(bee::session::durable::WorkKind::Model), 1);
        assert_eq!(budget.charged(bee::session::durable::WorkKind::Tool), 0);
        assert!(!root.path().join("count").exists());
    }
}
