//! 019-http-intercept T034 — constructing a session with `[policy.http]`.
//!
//! Driven through the real `bee run` binary with the offline `mock` provider: the refusals are
//! usage errors before anything is contacted, the advisory acknowledgement is recorded in the
//! transcript header, and a tool child's environment carries its per-call proxy credential.

#![cfg(feature = "intercept")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

fn bee(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bee"))
        .current_dir(dir)
        .args(args)
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .unwrap()
}

const HTTP_POLICY: &str =
    "[policy]\nname = \"http\"\nmode = \"enforce\"\n[policy.http]\ntargets = [\"127.0.0.1:9\"]\n";

fn scenario(dir: &Path, policy: &str, tools: &str) -> PathBuf {
    write(dir, "policy.toml", policy);
    write(
        dir,
        "s.toml",
        &format!(
            "[scenario]\nid = \"http-session\"\npolicy_path = \"policy.toml\"\n\
             system_prompt = \"test\"\ntask = \"t\"\nturn_limit = 4\ntimeout_secs = 60\n\
             tools = [{tools}]\n\
             finish = false\n"
        ),
    )
}

fn provider(dir: &Path, script: &str) -> PathBuf {
    write(
        dir,
        "p.toml",
        &format!("[provider]\nprovider = \"mock\"\nmodel = \"m\"\n{script}"),
    )
}

const DONE: &str = "[[provider.script]]\ntext = \"done\"\n";

/// Host mode exists only on a build without `enforce` (`bee run --host` refuses on an enforce
/// build for a separate, older reason).
#[cfg(not(feature = "enforce"))]
mod host_mode {
    use super::*;

    #[test]
    fn host_mode_without_the_flag_refuses_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let s = scenario(dir.path(), HTTP_POLICY, "\"bash\"");
        let p = provider(dir.path(), DONE);
        let out = bee(
            dir.path(),
            &[
                "run",
                "--scenario",
                s.to_str().unwrap(),
                "--provider",
                p.to_str().unwrap(),
                "--host",
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(64),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--http-scope-advisory"), "{stderr}");
        assert!(out.stdout.is_empty(), "no transcript: nothing ran");
    }

    #[test]
    fn with_the_flag_the_banner_prints_and_the_transcript_records_it() {
        let dir = tempfile::tempdir().unwrap();
        let s = scenario(dir.path(), HTTP_POLICY, "\"bash\", \"http_scope\"");
        let p = provider(
            dir.path(),
            &format!("[[provider.script]]\ntool = \"http_scope\"\nargs = {{}}\n{DONE}"),
        );
        let out = bee(
            dir.path(),
            &[
                "run",
                "--scenario",
                s.to_str().unwrap(),
                "--provider",
                p.to_str().unwrap(),
                "--host",
                "--http-scope-advisory",
            ],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        assert!(stderr.contains("HTTP SCOPE ADVISORY"), "{stderr}");
        let t: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(t["http_scope"]["enforcement"], "advisory", "{t}");
        assert_eq!(t["http_scope"]["advisory_acknowledged"], true);
        // `http_scope` itself says advisory, and that no kernel rule is installed.
        let scope = t["turns"][0]["calls"][0]["result"]["content"]
            .as_str()
            .unwrap();
        assert!(scope.contains("\"enforcement\":\"advisory\""), "{scope}");
        assert!(scope.contains("\"installed\":false"), "{scope}");
    }

    #[test]
    fn a_tool_child_gets_its_per_call_proxy_credential() {
        let dir = tempfile::tempdir().unwrap();
        let s = scenario(dir.path(), HTTP_POLICY, "\"bash\"");
        let p = provider(
            dir.path(),
            &format!(
                "[[provider.script]]\ntool = \"bash\"\nargs = {{ command = \"env | grep -i _proxy | sort\" }}\n{DONE}"
            ),
        );
        let out = bee(
            dir.path(),
            &[
                "run",
                "--scenario",
                s.to_str().unwrap(),
                "--provider",
                p.to_str().unwrap(),
                "--host",
                "--http-scope-advisory",
            ],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let t: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let call = &t["turns"][0]["calls"][0];
        let call_id = call["call"]["id"].as_str().unwrap();
        let env = call["result"]["content"].as_str().unwrap();
        let line = env
            .lines()
            .find(|l| l.starts_with("HTTP_PROXY="))
            .unwrap_or_else(|| panic!("no HTTP_PROXY in:\n{env}"));
        let url = line.trim_start_matches("HTTP_PROXY=");
        // http://<call_id>:<32 hex>@127.0.0.1:<port>
        let rest = url.strip_prefix("http://").unwrap();
        let (userinfo, hostport) = rest.split_once('@').unwrap();
        let (user, token) = userinfo.split_once(':').unwrap();
        assert_eq!(user, call_id);
        assert_eq!(token.len(), 32);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(hostport.starts_with("127.0.0.1:"), "{hostport}");
        for var in ["HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"] {
            assert!(
                env.lines().any(|l| l == format!("{var}={url}")),
                "{var} missing:\n{env}"
            );
        }
        assert!(env.lines().any(|l| l == "NO_PROXY="), "{env}");
        assert!(env.lines().any(|l| l == "no_proxy="), "{env}");
        // The token appears only where the child itself printed it — once per proxy variable — and
        // nowhere the harness wrote (the store and transcript reference call ids, never tokens).
        let printed = env.matches(token).count();
        assert_eq!(printed, 6, "{env}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).matches(token).count(),
            printed
        );
    }
}

/// An enforce build with an observe-mode policy refuses exactly as host mode does: the kernel would
/// audit and then allow, so `[policy.http]` would be enforced by the proxy alone.
#[cfg(feature = "enforce")]
#[test]
fn observe_mode_without_the_flag_refuses_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let policy = HTTP_POLICY.replace("mode = \"enforce\"", "mode = \"observe\"");
    let s = scenario(dir.path(), &policy, "\"bash\"");
    let p = provider(dir.path(), DONE);
    let out = bee(
        dir.path(),
        &[
            "run",
            "--scenario",
            s.to_str().unwrap(),
            "--provider",
            p.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // On a host without BPF-LSM the kernel gate refuses first; either way the session does not run,
    // and where the gate passes (the VM) the refusal must name the flag.
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("--http-scope-advisory") || stderr.contains("kernel cannot enforce"),
        "{stderr}"
    );
}

/// The concurrent runner cannot host the proxy's sidecar scope (until 018), so it refuses by name.
#[cfg(feature = "concurrent")]
#[test]
fn the_concurrent_runner_refuses_http_scope() {
    let dir = tempfile::tempdir().unwrap();
    let s = scenario(dir.path(), HTTP_POLICY, "\"bash\"");
    let p = provider(dir.path(), DONE);
    let out = bee(
        dir.path(),
        &[
            "run",
            "--batch",
            "--concurrent",
            "--scenarios",
            s.to_str().unwrap(),
            "--providers",
            p.to_str().unwrap(),
        ],
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        all.contains("specs/018") || all.contains("kernel cannot enforce"),
        "{all}"
    );
}

#[test]
fn the_advisory_flag_is_not_a_configuration_key() {
    // T044: accepting proxy-only enforcement is an operator act at the command line. A config file
    // that tries to set it is rejected as unknown, never honoured.
    let dir = tempfile::tempdir().unwrap();
    let cfg = write(dir.path(), "c.toml", "http_scope_advisory = true\n");
    let s = scenario(dir.path(), HTTP_POLICY, "\"bash\"");
    let p = provider(dir.path(), DONE);
    let out = bee(
        dir.path(),
        &[
            "run",
            "--config",
            cfg.to_str().unwrap(),
            "--scenario",
            s.to_str().unwrap(),
            "--provider",
            p.to_str().unwrap(),
            "--host",
        ],
    );
    assert!(!out.status.success());
}
