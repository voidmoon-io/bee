//! Concurrent orchestration test (US4) — host-only, no kernel. Four `MockModel` episodes run via
//! `tokio::spawn` sharing one `ToolRegistry`, each in its own `Sandbox::Host`. This validates the
//! concurrent orchestration (all episodes complete, no panics, wall-clock well under 4× a single
//! episode); audit isolation under real enforcement is the VM case (`test/vm/remote-matrix.sh`).

use std::sync::Arc;
use std::time::Instant;

use bee::provider::mock_model::MockModel;
use bee::provider::{ToolCall, Turn};
use bee::sandbox::{self, Sandbox};
use bee::scenario::Scenario;
use bee::tools::registry_for;
use bee::{run_loop, EpisodeStatus, EpisodeTranscript, LoopOptions};

fn scenario() -> Scenario {
    Scenario {
        lease_turns: None,
        context: Default::default(),
        id: "conc".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "test agent".into(),
        task: "sleep then finish".into(),
        turn_limit: 5,
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

/// A model that runs one `sleep <secs>` then wraps up — so the episode takes real wall-clock time we
/// can overlap.
fn sleeper(secs: &str) -> Vec<Turn> {
    vec![
        Turn::calls(vec![ToolCall {
            id: "1".into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": format!("sleep {secs}") }),
        }]),
        Turn::text("done"),
    ]
}

async fn one_episode(scn: Arc<Scenario>) -> EpisodeTranscript {
    // Each episode builds its own registry (run_loop takes `&mut` since 004-mcp-client's per-turn
    // tool refresh; the registries are cheap and independent).
    let mut registry = registry_for(&["bash".to_string()], None);
    let model = MockModel::scripted(sleeper("0.4"));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_concurrent_mock_episodes() {
    let scn = Arc::new(scenario());

    // Baseline: one episode on its own.
    let t0 = Instant::now();
    let _ = one_episode(scn.clone()).await;
    let single = t0.elapsed();

    // Four episodes concurrently.
    let t1 = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let s = scn.clone();
        set.spawn(async move { one_episode(s).await });
    }
    let mut transcripts = Vec::new();
    while let Some(res) = set.join_next().await {
        transcripts.push(res.expect("episode task did not panic"));
    }
    let concurrent = t1.elapsed();

    // All four produced a transcript and completed.
    assert_eq!(transcripts.len(), 4);
    for t in &transcripts {
        assert_eq!(t.status, EpisodeStatus::Completed);
        assert!(t.turns[0].calls[0].result.exit_code == Some(0));
    }
    // Concurrency: four overlapping 0.4s episodes finish well under 4× a single one.
    assert!(
        concurrent < single * 4,
        "concurrent {concurrent:?} not < 4× single {single:?}"
    );
}
