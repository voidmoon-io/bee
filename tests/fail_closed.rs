//! The enforcement invariant (consolidation issue 05).
//!
//! Bee's first design principle is deny-by-default and fail-closed: refuse rather than degrade
//! silently. These assert the *error text*, not merely the exit code — the text is the feature. An
//! exit code alone leaves the operator exactly where the old banner line did, knowing something
//! went wrong and not what to do about it.
//!
//! Three of these behave differently depending on whether the binary was built with `enforce`,
//! which is the point: the two builds genuinely differ now, and each says so.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, body).unwrap();
    path
}

fn mock_provider(dir: &Path) -> PathBuf {
    write(
        dir,
        "p.toml",
        // An ad-hoc `--task` run ends through `finish` (025 US3).
        "[provider]\nprovider = \"mock\"\n\n[[provider.script]]\ntool = \"finish\"\n\
         args = { outcome = \"completed\", summary = \"hi\" }\n",
    )
}

fn policy(dir: &Path, name: &str) -> PathBuf {
    write(
        dir,
        name,
        &format!("[policy]\nname = \"{name}\"\n[policy.filesystem]\n\"/tmp\" = \"read\"\n"),
    )
}

fn bee(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_session_with_no_policy_and_no_host_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path());

    for cmd in [
        vec![
            "run",
            "--provider",
            provider.to_str().unwrap(),
            "--task",
            "x",
        ],
        vec!["repl", "--provider", provider.to_str().unwrap(), "--no-bee"],
    ] {
        let out = bee(&cmd);
        assert!(
            !out.status.success(),
            "{:?} started without a policy and without --host",
            cmd[0]
        );
        let err = stderr(&out);
        // Whichever build this is, the message must name --host as the way to proceed.
        assert!(err.contains("--host"), "{err}");
        if cfg!(feature = "enforce") {
            assert!(err.contains("incomplete configuration"), "{err}");
            assert!(err.contains("--policy"), "{err}");
        } else {
            assert!(err.contains("built without enforcement"), "{err}");
        }
    }
}

#[test]
fn host_makes_an_unenforced_session_start_and_say_so() {
    // Headless host mode needs a build without `enforce` — see the next test for why.
    if cfg!(feature = "enforce") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path());

    let out = bee(&[
        "run",
        "--provider",
        provider.to_str().unwrap(),
        "--task",
        "x",
        "--quiet",
        "--host",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    // Loud, on stderr, and legible in a piped log — not a banner line that scrolls past.
    assert!(err.contains("HOST MODE"), "{err}");
    assert!(err.contains("no kernel scope"), "{err}");
}

#[test]
fn headless_host_mode_on_an_enforcement_build_is_refused_not_faked() {
    // A known limitation, made explicit. `run_episode` builds its own sandbox, and under
    // `--features enforce` that path is unconditional. Announcing an unenforced session and then
    // running an enforced one would be exactly the silent divergence this issue exists to stop, so
    // the request is refused with the reason.
    if !cfg!(feature = "enforce") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path());

    let out = bee(&[
        "run",
        "--provider",
        provider.to_str().unwrap(),
        "--task",
        "x",
        "--quiet",
        "--host",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("not available in an enforcement build"),
        "{err}"
    );
    assert!(
        !err.contains("HOST MODE"),
        "must not announce what it will not do: {err}"
    );
}

#[test]
fn host_and_a_policy_together_are_a_contradiction() {
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path());
    let policy = policy(dir.path(), "p");

    // clap catches the flag pair directly.
    let out = bee(&[
        "repl",
        "--provider",
        provider.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--host",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("cannot be used with") || err.contains("contradictory"),
        "{err}"
    );
}

#[test]
fn a_policy_on_a_host_build_is_refused_rather_than_ignored() {
    // The behaviour this replaces: the policy was parsed, accepted, and ignored, with a
    // parenthetical in the banner as the only sign.
    if cfg!(feature = "enforce") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path());
    let policy = policy(dir.path(), "p");

    let out = bee(&[
        "repl",
        "--provider",
        provider.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--no-bee",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("built without enforcement"), "{err}");
    // Both remedies, named.
    assert!(err.contains("--features enforce"), "{err}");
    assert!(err.contains("--host"), "{err}");
    assert!(
        !err.contains("IGNORED"),
        "a policy is never silently ignored: {err}"
    );
}

#[test]
fn host_cannot_be_set_from_a_configuration_file() {
    // Running an agent unenforced belongs to the invocation, not to a file that might have been
    // written months ago or by a repository. The schema rejects the key outright.
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path());
    let config = write(dir.path(), "bee.toml", "[session]\nhost = true\n");

    let out = bee(&[
        "run",
        "--provider",
        provider.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--task",
        "x",
        "--quiet",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("cannot parse"), "{err}");
    assert!(err.contains("host"), "{err}");
}
