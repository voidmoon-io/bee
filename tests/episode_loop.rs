//! Host loop tests (T010) — deterministic, offline, `MockModel`-driven. No kernel scope: tools run
//! as hardened host children (`Sandbox::host`), which is enough to exercise loop control, truncation,
//! and malformed-arg handling. Real enforcement is the VM case (T012).

use bee::provider::mock_model::MockModel;
use bee::provider::{ToolCall, Turn};
use bee::sandbox::{self, Sandbox};
use bee::scenario::Scenario;
use bee::tools::registry_for;
use bee::transcript::{EpisodeStatus, DEFAULT_OUTPUT_CAP};
use bee::{run_loop, LoopOptions};

fn scenario(turn_limit: u32) -> Scenario {
    Scenario {
        context: Default::default(),
        id: "loop-test".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "You are a test agent.".into(),
        task: "do the thing".into(),
        turn_limit,
        timeout_secs: 30,
        tools: vec!["bash".into()],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: Vec::new(),
        ceiling_policy_path: None,
        security: Default::default(),
    }
}

fn bash_call(id: &str, command: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: "bash".into(),
        arguments: serde_json::json!({ "command": command }),
    }
}

async fn run(turns: Vec<Turn>, turn_limit: u32) -> bee::EpisodeTranscript {
    let model = MockModel::scripted(turns);
    let scn = scenario(turn_limit);
    let mut registry = registry_for(&scn.tools, None);
    let mut sb = Sandbox::host(sandbox::key_vars(None));
    run_loop(
        &model,
        &scn,
        &mut registry,
        &mut sb,
        &LoopOptions::default(),
    )
    .await
}

#[tokio::test]
async fn turn_limit_reached_is_timeout() {
    // The model always wants another tool call, so the loop exhausts the 2-turn budget.
    let t = run(
        vec![
            Turn::calls(vec![bash_call("1", "echo hi")]),
            Turn::calls(vec![bash_call("2", "echo hi")]),
            Turn::calls(vec![bash_call("3", "echo hi")]),
        ],
        2,
    )
    .await;
    assert_eq!(t.status, EpisodeStatus::Timeout);
    assert_eq!(t.turns.len(), 2);
}

#[tokio::test]
async fn text_only_first_turn_is_no_tool_calls() {
    // SC-007: a model that only ever emits text must not hang; it terminates as no_tool_calls.
    let t = run(vec![Turn::text("I have nothing to do.")], 5).await;
    assert_eq!(t.status, EpisodeStatus::NoToolCalls);
    assert_eq!(t.turns.len(), 1);
}

#[tokio::test]
async fn agent_finishing_after_a_tool_call_is_completed() {
    let t = run(
        vec![
            Turn::calls(vec![bash_call("1", "echo done")]),
            Turn::text("All finished."),
        ],
        5,
    )
    .await;
    assert_eq!(t.status, EpisodeStatus::Completed);
    // First turn ran the tool; output captured.
    assert!(t.turns[0].calls[0].result.content.contains("done"));
    assert!(!t.turns[0].calls[0].result.is_error);
}

#[tokio::test]
async fn malformed_tool_args_error_and_loop_continues() {
    // FR-016: bad args → an error ToolResult fed back to the model; the loop keeps going.
    let bad = ToolCall {
        id: "1".into(),
        name: "bash".into(),
        arguments: serde_json::json!({ "not_command": "oops" }),
    };
    let t = run(vec![Turn::calls(vec![bad]), Turn::text("recovered")], 5).await;
    assert_eq!(t.status, EpisodeStatus::Completed);
    let result = &t.turns[0].calls[0].result;
    assert!(result.is_error);
    assert!(
        result.content.contains("invalid arguments"),
        "got: {}",
        result.content
    );
}

#[tokio::test]
async fn oversized_output_is_truncated_and_marked() {
    // FR-015: > 100 KB of output is capped and flagged.
    let t = run(
        vec![
            Turn::calls(vec![bash_call(
                "1",
                "head -c 200000 /dev/zero | tr '\\0' 'a'",
            )]),
            Turn::text("done"),
        ],
        5,
    )
    .await;
    let result = &t.turns[0].calls[0].result;
    assert!(
        result.truncated,
        "expected truncation; len={}",
        result.content.len()
    );
    assert_eq!(result.original_len, Some(200000));
    assert!(result.content.len() <= DEFAULT_OUTPUT_CAP + 128);
}

#[tokio::test]
async fn transcript_shape_is_recorded() {
    // FR-009: model id, turns, timing, and JSON serialization.
    let t = run(
        vec![
            Turn::calls(vec![bash_call("1", "echo hi")]),
            Turn::text("bye"),
        ],
        5,
    )
    .await;
    assert_eq!(t.model_id, "mock/scripted");
    assert_eq!(t.scenario_id, "loop-test");
    assert!(!t.turns.is_empty());
    assert!(!t.timing.started_at.is_empty());
    assert!(t.to_json().contains("\"status\""));
}

#[tokio::test]
async fn unknown_tool_name_is_error_not_panic() {
    let call = ToolCall {
        id: "1".into(),
        name: "nope".into(),
        arguments: serde_json::json!({}),
    };
    let t = run(vec![Turn::calls(vec![call]), Turn::text("done")], 5).await;
    assert_eq!(t.status, EpisodeStatus::Completed);
    assert!(t.turns[0].calls[0].result.is_error);
    assert!(t.turns[0].calls[0].result.content.contains("unknown tool"));
}
