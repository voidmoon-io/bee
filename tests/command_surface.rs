//! The top-level `bee` command tree (ADR-0002, consolidation issue 01).
//!
//! These assert the *shape* of the interface rather than what any command does: that bare `bee`
//! explains itself, that the raw process runner has vacated `run` so the headless session can claim
//! it, and that the commands which exist are the ones the ADR says should. The consolidation adds
//! `run`, `repl`, and `metrics` in later issues; until then their absence is the thing worth
//! pinning, because reintroducing `run` as the raw runner is exactly the regression that would
//! quietly undo issue 01.

use std::process::{Command, Output};

fn bee(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn bare_bee_prints_help_and_runs_nothing() {
    let output = bee(&[]);
    assert!(!output.status.success(), "bare `bee` must not run anything");
    // clap writes the help for a missing-subcommand invocation to stderr.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("Usage:"), "{text}");
    for expected in ["check", "validate", "exec"] {
        assert!(text.contains(expected), "help omits `{expected}`:\n{text}");
    }
}

#[test]
fn run_is_not_the_raw_process_runner() {
    // `run` belongs to the headless harness session (ADR-0002). Until that lands it must not
    // resolve to anything — least of all to the diagnostic runner it used to name.
    let output = bee(&["run", "--policy", "/dev/null", "--", "true"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand") || stderr.contains("unexpected argument"),
        "`bee run` should not be a recognised command yet:\n{stderr}"
    );
}

#[test]
fn exec_requires_a_policy_and_a_command() {
    // Both are required arguments, so each omission is a usage error rather than a run with an
    // implied default — there is no implied default for what to enforce or what to enforce it on.
    let no_command = bee(&["exec", "--policy", "/dev/null"]);
    assert!(!no_command.status.success());
    assert!(String::from_utf8_lossy(&no_command.stderr).contains("Usage:"));

    let no_policy = bee(&["exec", "--", "true"]);
    assert!(!no_policy.status.success());
    assert!(String::from_utf8_lossy(&no_policy.stderr).contains("Usage:"));
}

#[test]
fn exec_help_describes_a_diagnostic() {
    let output = bee(&["exec", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("diagnostic"),
        "`bee exec --help` should mark it as secondary to `run`/`repl`:\n{stdout}"
    );
}

#[test]
fn http_scope_advisory_is_an_operator_flag_on_both_sessions() {
    // 019 T044: accepting proxy-only enforcement of `[policy.http]` is an act at the command line,
    // made per session. It is a flag on `run` and `repl` — and nothing in configuration can set it
    // (`config::Flags` has no such field, so no layer can carry it into a session).
    for cmd in ["run", "repl"] {
        let out = bee(&[cmd, "--help"]);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("--http-scope-advisory"),
            "`bee {cmd}`:\n{text}"
        );
    }
}
