//! `bee run` — the headless session's observable contract (consolidation issues 03 and 06).
//!
//! These began as parity tests against `bee-episode`, driving identical inputs through both and
//! comparing transcript JSON and exit codes. Issue 06 retired that binary, so what survives is what
//! the parity was protecting: the transcript on stdout, progress on stderr where a pipe cannot see
//! it, and the exit code for each failure. The `mock` provider keeps every case deterministic and
//! offline.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, body).unwrap();
    path
}

/// A scripted provider: one text turn, no network, no key.
fn mock_provider(dir: &Path, name: &str, reply: &str) -> PathBuf {
    write(
        dir,
        name,
        &format!("[provider]\nprovider = \"mock\"\n\n[[provider.script]]\ntext = \"{reply}\"\n"),
    )
}

/// A scripted provider that ends its run with `finish` — how an ad-hoc `--task` run ends (025 US3).
fn finishing_provider(dir: &Path, name: &str) -> PathBuf {
    write(
        dir,
        name,
        "[provider]\nprovider = \"mock\"\n\n[[provider.script]]\ntool = \"finish\"\n\
         args = { outcome = \"completed\", summary = \"said hello\" }\n",
    )
}

/// A scenario whose run ends at its first text turn: `finish = false` characterizes the pre-finish
/// ending these transport tests were written against (025 T034).
fn scenario(dir: &Path, name: &str, id: &str, task: &str) -> PathBuf {
    write(
        dir,
        name,
        &format!(
            "[scenario]\n\
             id = \"{id}\"\n\
             policy_path = \"/dev/null\"\n\
             system_prompt = \"You are a test agent.\"\n\
             task = \"{task}\"\n\
             turn_limit = 2\n\
             timeout_secs = 10\n\
             tools = []\n\
             finish = false\n"
        ),
    )
}

/// Every test here drives an unenforced episode, which needs `--host`. On an enforcement build
/// that is refused (issue 05: the harness has no unenforced path when compiled with `enforce`), and
/// an enforced episode needs a BPF-LSM kernel this machine does not have. The enforce path is
/// covered where it can actually run — the live VM matrix in `test/vm/`.
fn skip_on_enforcement_build() -> bool {
    if cfg!(feature = "enforce") {
        eprintln!(
            "[skip] host-mode episode: this build enforces, and headless --host is refused.              Covered by test/vm/matrix.sh."
        );
        return true;
    }
    false
}

fn bee_run(args: &[&str]) -> Output {
    let mut a = vec!["run"];
    a.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(&a)
        .output()
        .unwrap()
}

#[test]
fn a_single_episode_writes_its_transcript() {
    if skip_on_enforcement_build() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path(), "p.toml", "Done.");
    let scenario = scenario(dir.path(), "s.toml", "parity", "do the thing");

    let out = bee_run(&[
        "--scenario",
        scenario.to_str().unwrap(),
        "--provider",
        provider.to_str().unwrap(),
        "--quiet",
        "--host",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"scenario_id\": \"parity\""), "{stdout}");
}

#[test]
fn an_ad_hoc_task_runs_without_a_scenario_file() {
    if skip_on_enforcement_build() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let provider = finishing_provider(dir.path(), "p.toml");

    let out = bee_run(&[
        "--task",
        "say hello",
        "--provider",
        provider.to_str().unwrap(),
        "--quiet",
        "--host",
    ]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"scenario_id\": \"adhoc\""));
}

#[test]
fn a_batch_crosses_scenarios_with_providers() {
    if skip_on_enforcement_build() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let s1 = scenario(dir.path(), "scenarios/a.toml", "a", "first");
    let s2 = scenario(dir.path(), "scenarios/b.toml", "b", "second");
    let p1 = mock_provider(dir.path(), "providers/one.toml", "One.");
    let p2 = mock_provider(dir.path(), "providers/two.toml", "Two.");

    let scenarios = format!("{},{}", s1.to_str().unwrap(), s2.to_str().unwrap());
    let providers = format!("{},{}", p1.to_str().unwrap(), p2.to_str().unwrap());

    let out = bee_run(&[
        "--batch",
        "--scenarios",
        &scenarios,
        "--providers",
        &providers,
        "--quiet",
        "--host",
    ]);
    assert!(out.status.success());
    // Two scenarios × two providers.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("\"scenario_id\"").count(), 4, "{stdout}");
}

#[test]
fn a_missing_provider_file_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let scenario = scenario(dir.path(), "s.toml", "x", "task");
    let missing = dir.path().join("nope.toml");

    let out = bee_run(&[
        "--scenario",
        scenario.to_str().unwrap(),
        "--provider",
        missing.to_str().unwrap(),
        "--quiet",
        "--host",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nope.toml"), "{stderr}");
}

#[test]
fn an_unparseable_scenario_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path(), "p.toml", "hi");
    let broken = write(
        dir.path(),
        "broken.toml",
        "id = \"x\"\nthis is not toml [[[\n",
    );

    let out = bee_run(&[
        "--scenario",
        broken.to_str().unwrap(),
        "--provider",
        provider.to_str().unwrap(),
        "--quiet",
        "--host",
    ]);
    assert_eq!(out.status.code(), Some(64), "usage error");
    assert!(String::from_utf8_lossy(&out.stderr).contains("scenario"));
}

#[test]
fn the_transcript_stays_out_of_the_progress_stream() {
    if skip_on_enforcement_build() {
        return;
    }
    // The artifact contract: stdout is parseable JSON even with progress on, because progress goes
    // to stderr. This is what makes `bee run ... > out.json` work.
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path(), "p.toml", "Done.");
    let scenario = scenario(dir.path(), "s.toml", "piped", "task");

    let out = bee_run(&[
        "--scenario",
        scenario.to_str().unwrap(),
        "--provider",
        provider.to_str().unwrap(),
        "--host",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\n{stdout}"));
}

#[test]
fn out_writes_the_transcript_to_a_file() {
    if skip_on_enforcement_build() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let provider = mock_provider(dir.path(), "p.toml", "Done.");
    let scenario = scenario(dir.path(), "s.toml", "tofile", "task");
    let out_path = dir.path().join("transcript.json");

    let out = bee_run(&[
        "--scenario",
        scenario.to_str().unwrap(),
        "--provider",
        provider.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--quiet",
        "--host",
    ]);
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "nothing goes to stdout with --out");
    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains("\"scenario_id\": \"tofile\""), "{written}");
}

#[test]
fn concurrent_without_the_feature_is_an_explicit_refusal() {
    // Never a silent fall back to sequential: the operator asked for concurrency and would
    // otherwise believe they got it.
    if cfg!(feature = "concurrent") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let s = scenario(dir.path(), "s.toml", "x", "task");
    let p = mock_provider(dir.path(), "p.toml", "hi");

    let out = bee_run(&[
        "--batch",
        "--concurrent",
        "--scenarios",
        s.to_str().unwrap(),
        "--providers",
        p.to_str().unwrap(),
        "--quiet",
        "--host",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--features concurrent"), "{stderr}");
}
