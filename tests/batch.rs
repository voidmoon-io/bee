//! Batch runner tests (US2) — deterministic, offline. Two `mock` providers cross one scenario; a
//! bad provider is isolated to its own error transcript; and the enforcement-trace helper extracts
//! the audit decisions of each tool call.

use std::path::{Path, PathBuf};

use bee::batch::{run_batch, BatchConfig};
use bee::provider::{ToolCall, Usage};
use bee::tools::ToolResult;
use bee::transcript::{
    enforcement_trace, EpisodeStatus, EpisodeTranscript, RecordedCall, Timing, TranscriptTurn,
};
use bee_core::AuditEvent;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bee-batch-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

const SCENARIO: &str = r#"
[scenario]
id            = "batch-scn"
policy_path   = "/dev/null"
system_prompt = "You are a test agent."
task          = "run the thing"
turn_limit    = 5
timeout_secs  = 30
tools         = ["bash"]
"#;

/// A `mock` provider that calls `bash` once then wraps up, with a distinct model id.
fn mock_provider(model: &str, command: &str) -> String {
    format!(
        r#"
[provider]
provider = "mock"
model    = "{model}"

[[provider.script]]
tool = "bash"
args = {{ command = "{command}" }}

[[provider.script]]
text = "done"
"#
    )
}

// The batch tests below drive real episodes through `run_episode`, which under `--features enforce`
// brings up a live kernel scope (`Engine::init`) — unavailable in a plain host test run. They are
// the host build's job; ignore them under `enforce` (they still compile, guarding against drift).
#[tokio::test]
#[cfg_attr(
    feature = "enforce",
    ignore = "run_episode needs a live kernel scope; host build only"
)]
async fn batch_two_mocks_same_scenario() {
    let dir = tmpdir("two-mocks");
    let scn = write(&dir, "scn.toml", SCENARIO);
    let a = write(&dir, "alpha.toml", &mock_provider("alpha", "echo aaa"));
    let b = write(&dir, "beta.toml", &mock_provider("beta", "echo bbb"));

    let cfg = BatchConfig {
        scenarios: vec![scn],
        providers: vec![a, b],
        workdir_root: None,
    };
    let result = run_batch(&cfg, None).await;

    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
    assert_eq!(result.transcripts.len(), 2);
    let ids: Vec<&str> = result
        .transcripts
        .iter()
        .map(|t| t.model_id.as_str())
        .collect();
    assert!(ids.contains(&"mock/alpha"), "ids: {ids:?}");
    assert!(ids.contains(&"mock/beta"), "ids: {ids:?}");
    for t in &result.transcripts {
        assert_eq!(t.scenario_id, "batch-scn");
    }
}

#[tokio::test]
#[cfg_attr(
    feature = "enforce",
    ignore = "run_episode needs a live kernel scope; host build only"
)]
async fn batch_bad_provider_isolated() {
    // US2 AS-2: one valid mock + one un-buildable provider (openai-compat with no base_url). The
    // valid one runs; the invalid one becomes an infra_error transcript without affecting it.
    let dir = tmpdir("bad-isolated");
    let scn = write(&dir, "scn.toml", SCENARIO);
    let good = write(&dir, "good.toml", &mock_provider("good", "echo ok"));
    let bad = write(
        &dir,
        "bad.toml",
        r#"
[provider]
provider    = "openai-compat"
model       = "gpt-4o"
api_key_env = "OPENAI_API_KEY"
"#,
    );

    let cfg = BatchConfig {
        scenarios: vec![scn],
        providers: vec![good, bad],
        workdir_root: None,
    };
    let result = run_batch(&cfg, None).await;

    // The bad provider parses fine, so it is NOT a load error — it is an error transcript.
    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
    assert_eq!(result.transcripts.len(), 2);

    let good_t = result
        .transcripts
        .iter()
        .find(|t| t.model_id == "mock/good")
        .unwrap();
    assert!(
        !matches!(
            good_t.status,
            EpisodeStatus::ApiError { .. } | EpisodeStatus::InfraError { .. }
        ),
        "good provider should not error: {:?}",
        good_t.status
    );

    let bad_t = result
        .transcripts
        .iter()
        .find(|t| t.model_id == "openai-compat/gpt-4o")
        .unwrap();
    assert!(
        matches!(
            bad_t.status,
            EpisodeStatus::ApiError { .. } | EpisodeStatus::InfraError { .. }
        ),
        "bad provider should error: {:?}",
        bad_t.status
    );
}

#[tokio::test]
#[cfg_attr(
    feature = "enforce",
    ignore = "run_episode needs a live kernel scope; host build only"
)]
async fn parse_failure_is_a_batch_error() {
    // A provider TOML that cannot even be parsed is a BatchError (we can't name the model), and it
    // does not abort the batch: the good pair still produces its transcript.
    let dir = tmpdir("parse-fail");
    let scn = write(&dir, "scn.toml", SCENARIO);
    let good = write(&dir, "good.toml", &mock_provider("good", "echo ok"));
    let broken = write(&dir, "broken.toml", "this is : not valid = toml [[[");

    let cfg = BatchConfig {
        scenarios: vec![scn],
        providers: vec![good, broken.clone()],
        workdir_root: None,
    };
    let result = run_batch(&cfg, None).await;

    assert_eq!(result.transcripts.len(), 1);
    assert_eq!(result.transcripts[0].model_id, "mock/good");
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].provider_path, broken);
}

#[test]
fn enforcement_trace_extracts_audit() {
    // Build a transcript with a known tool call + audit events; assert the trace mirrors them.
    let denied = AuditEvent {
        ts: "1970-01-01T00:00:00Z".into(),
        scope_id: Some("s".into()),
        cgroup_id: 42,
        pid: Some(1),
        tgid: Some(1),
        op: "file_open".into(),
        decision: "denied".into(),
        errno: 13,
        target: "/etc/shadow".into(),
    };
    let call = RecordedCall {
        denied_attempt_audit: Vec::new(),
        denied_attempt_proxy_events: Vec::new(),
        escalations: Vec::new(),
        retried: false,
        timed_out: false,
        refused_by_hook: None,
        proxy_events: Vec::new(),
        call: ToolCall {
            id: "c1".into(),
            name: "read_file".into(),
            arguments: serde_json::json!({ "path": "/etc/shadow" }),
        },
        result: ToolResult::error("denied"),
        audit: vec![denied.clone()],
    };
    let transcript = EpisodeTranscript {
        consents: Vec::new(),
        http_scope: None,
        scenario_id: "s".into(),
        model_id: "mock/x".into(),
        status: EpisodeStatus::Completed,
        turns: vec![TranscriptTurn {
            notes: Vec::new(),
            index: 0,
            assistant_text: None,
            calls: vec![call],
            duration_ms: 1,
        }],
        audit_trail: vec![denied],
        timing: Timing::default(),
        usage: None::<Usage>,
        score: None,
    };

    let trace = enforcement_trace(&transcript);
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].tool_name, "read_file");
    assert_eq!(
        trace[0].arguments,
        serde_json::json!({ "path": "/etc/shadow" })
    );
    assert_eq!(
        trace[0].audit,
        vec![(
            "file_open".to_string(),
            "denied".to_string(),
            "/etc/shadow".to_string()
        )]
    );
}
