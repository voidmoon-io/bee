//! Sessions built by different entry points must be the same session (024-session-core, FR-006,
//! FR-040). PR 1 writes this test against today's construction paths and ignores it, because they
//! are known to differ. PR 5a rewrites it against `bee::session::build` and removes the `#[ignore]`.
//!
//! Today only two entry points can build a session on a host:
//!
//! * the episode (`bee::episode::run_episode_with`), observed through a model that records what it
//!   is handed on its first call and then ends the episode;
//! * the intercept test harness (`tests/support/harness.rs::Session::start`), which hand-copies the
//!   Interceptor start-up.
//!
//! The concurrent runner needs `enforce` and a BPF-LSM kernel, and the REPL's setup lives in the
//! binary (`src/app/`), so their parity is added in T047 and T061, once both go through the library
//! builder.
//!
//! The effective policy and the escalation timeout are part of the snapshot, but neither path
//! exposes them today: the episode keeps both local to `run_episode_with`, and the harness has no
//! escalation. They are `None` until `Session::snapshot()` exists (T043).

use std::sync::Mutex;
use std::time::Duration;

use bee::provider::{Conversation, Model, ModelError, StopReason, ToolSchema, Turn};
use bee::scenario::Scenario;

/// What two sessions must agree on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Snapshot {
    /// Registered tool names, sorted.
    tools: Vec<String>,
    /// The system prompt the model is given; `None` where the path builds no conversation.
    system_prompt: Option<String>,
    /// Filesystem keys of the effective policy; `None` where the path does not expose it.
    policy_fs: Option<Vec<String>>,
    /// The consent timeout; `None` where the path does not expose it or has no escalation.
    escalation_timeout: Option<Duration>,
}

/// A model that records the tools and system prompt of its first call, then ends the episode.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Option<(Vec<String>, String)>>,
}

#[async_trait::async_trait]
impl Model for Recorder {
    fn id(&self) -> &str {
        "mock/recorder"
    }

    async fn complete(
        &self,
        convo: &Conversation,
        tools: &[ToolSchema],
    ) -> Result<Turn, ModelError> {
        let mut seen = self.seen.lock().unwrap();
        if seen.is_none() {
            let mut names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
            names.sort();
            *seen = Some((names, convo.system.clone()));
        }
        Ok(Turn {
            text: Some("done".into()),
            tool_calls: Vec::new(),
            stop: StopReason::EndTurn,
            usage: None,
        })
    }
}

fn scenario(tools: &[&str]) -> Scenario {
    Scenario {
        id: "parity".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "You are a test agent.".into(),
        task: "go".into(),
        turn_limit: 1,
        timeout_secs: 30,
        tools: tools.iter().map(|t| t.to_string()).collect(),
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: Vec::new(),
        ceiling_policy_path: None,
        security: Default::default(),
    }
}

/// The session `bee run --scenario` builds, as far as it is observable from outside.
async fn episode_snapshot(tools: &[&str]) -> Snapshot {
    let model = Recorder::default();
    bee::episode::run_episode_with(
        &model,
        &scenario(tools),
        None,
        None,
        bee::episode::EpisodeOptions::default(),
    )
    .await;
    let (tools, system) = model.seen.lock().unwrap().take().expect("model was called");
    Snapshot {
        tools,
        system_prompt: Some(system),
        policy_fs: None,
        escalation_timeout: None,
    }
}

/// The capture works: the episode hands the model its declared tools and its own system prompt.
#[tokio::test]
async fn the_episode_snapshot_is_observable() {
    let s = episode_snapshot(&["bash", "read_file"]).await;
    assert_eq!(s.tools, vec!["bash".to_string(), "read_file".to_string()]);
    assert_eq!(s.system_prompt.as_deref(), Some("You are a test agent."));
}

#[cfg(feature = "intercept")]
#[path = "support/harness.rs"]
mod harness;

/// The session the intercept test harness builds.
#[cfg(feature = "intercept")]
async fn harness_snapshot(tools: &[&str]) -> Snapshot {
    let s = harness::Session::start(
        harness::scope("targets = [\"127.0.0.1:9\"]", &[]),
        &[],
        tools,
    )
    .await;
    let mut names: Vec<String> = s.registry.schemas().into_iter().map(|t| t.name).collect();
    names.sort();
    s.icpt.shutdown().await;
    Snapshot {
        tools: names,
        system_prompt: None,
        policy_fs: None,
        escalation_timeout: None,
    }
}

/// Known differences, each closed by PR 5a (T042–T048) or PR 5b (T061):
///
/// * scanner report dir — the episode widens the policy for scanner reports
///   (`widen_for_scanner_reports`); the REPL and harness do not (FR-010);
/// * `--task` MCP/skills — `bee run --task` drops user/project MCP servers and skills (FR-009);
/// * concurrent drops — the concurrent runner silently drops `scenario.mcp` and special-cases
///   `[policy.http]` instead of refusing (FR-008);
/// * system prompt — the episode passes the scenario's prompt verbatim; the REPL appends the
///   render/skill notes (`effective_system_prompt`); the harness builds no conversation (FR-007);
/// * teardown order — each path tears down MCP, the Interceptor and the scopes in its own order, and
///   the harness leaves the Interceptor to its caller (FR-012).
#[cfg(feature = "intercept")]
#[tokio::test]
#[ignore = "known drift until phase 5: scanner dir, --task MCP/skills, concurrent drops, system prompt, teardown order"]
async fn every_entry_point_builds_the_same_session() {
    let tools = ["http_send", "bash"];
    let episode = episode_snapshot(&tools).await;
    let harness = harness_snapshot(&tools).await;
    assert_eq!(episode, harness);
}
