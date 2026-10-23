//! Concurrent episode runner (US4, `concurrent` feature). One shared [`Engine`] owns the attached
//! eBPF programs and the single `AUDIT_RB` ring; an [`AuditDemux`] fans that ring out to per-scope
//! subscribers by `cgroup_id`. Scopes are created **sequentially** on this task (BPF map writes are
//! not concurrent); each episode's loop then runs in its own [`tokio::spawn`] task with a
//! [`Sandbox::Concurrent`] whose audit comes from a demux subscription (no audit cross-contamination
//! — US4 AS-1 / SC-004).
//!
//! The engine is not `Send` (aya's `Ebpf`), so it stays on this task; only the `Send`
//! [`Sandbox::Concurrent`] and the boxed model cross into spawned tasks.

#![cfg(feature = "concurrent")]

use bee_core::Policy;
use bee_userspace::{AuditDemux, EnforcementPlan, Engine, ScopeMode, SystemResolver};
use tokio::task::JoinSet;

use crate::config::ProviderConfig;
use crate::episode::{
    materialize_workdir, run_loop, spec_from_scenario, EpisodeOptions, LoopOptions, ProgressSink,
};
use crate::provider::model_from_config;
use crate::sandbox::{self, Sandbox};
use crate::scenario::{Scenario, ScoringMode};
use crate::session::{EntryPoint, SessionSpec};
use crate::transcript::{EpisodeStatus, EpisodeTranscript, ScoreReport};

struct PreparedEpisode {
    index: usize,
    scenario: Scenario,
    provider: ProviderConfig,
    plan: EnforcementPlan,
    spec: SessionSpec,
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn prepare_episodes(
    episodes: Vec<(Scenario, ProviderConfig)>,
    resolver: &SystemResolver,
) -> (Vec<PreparedEpisode>, Vec<(usize, EpisodeTranscript)>) {
    let mut prepared = Vec::new();
    let mut failures = Vec::new();

    for (index, (scenario, provider)) in episodes.into_iter().enumerate() {
        // The session this episode asks for, as a concurrent batch entry. What a shared-engine batch
        // cannot run — MCP servers, `[policy.http]`, a widening ceiling, skills — is refused here, by
        // name, before any scope exists (024 FR-008); it used to be silently left out.
        let strip_env = sandbox::key_vars(
            (!provider.api_key_env.is_empty()).then_some(provider.api_key_env.as_str()),
        );
        // Autonomous, like any headless run; a concurrent batch has no progress stream to report on.
        let operator =
            crate::operator::Operator::autonomous(std::sync::Arc::new(crate::operator::NullOutput));
        let mut spec =
            spec_from_scenario(&scenario, strip_env, &EpisodeOptions::default(), operator);
        spec.entry = EntryPoint::Batch { concurrent: true };
        let result = crate::session::refuse_unsupported(&spec)
            .map_err(|e| e.to_string())
            .and_then(|()| {
                Policy::from_path(&scenario.policy_path)
                    .map_err(|e| format!("policy {}: {e}", scenario.policy_path.display()))
            })
            .and_then(|policy| {
                policy
                    .compile(resolver)
                    .map_err(|e| format!("policy compile: {e}"))
            })
            .and_then(|compiled| {
                EnforcementPlan::prepare(&compiled, ScopeMode::Enforce)
                    .map_err(|e| format!("enforcement plan: {e}"))
            });

        match result {
            Ok(plan) => prepared.push(PreparedEpisode {
                index,
                scenario,
                provider,
                plan,
                spec,
            }),
            Err(detail) => failures.push((
                index,
                EpisodeTranscript::setup_error(
                    scenario.id.clone(),
                    provider.model_id(),
                    EpisodeStatus::InfraError { detail },
                ),
            )),
        }
    }

    (prepared, failures)
}

/// Run every `(scenario, provider)` episode concurrently against one shared engine, returning the
/// transcripts in input order. A per-episode setup failure (bad model, policy, scope, or workdir)
/// becomes that episode's error transcript without affecting the others.
pub async fn run_concurrent(
    episodes: Vec<(Scenario, ProviderConfig)>,
    _progress: Option<ProgressSink>,
) -> Vec<EpisodeTranscript> {
    // Plan every policy before touching the kernel. Invalid policies become isolated per-episode
    // setup errors; valid peers continue to engine initialization and scope creation.
    let resolver = SystemResolver::current();
    let (prepared, mut indexed) = prepare_episodes(episodes, &resolver);
    if prepared.is_empty() {
        indexed.sort_by_key(|(i, _)| *i);
        return indexed.into_iter().map(|(_, t)| t).collect();
    }

    let mut engine = match Engine::init() {
        Ok(e) => e,
        Err(e) => {
            for episode in prepared {
                indexed.push((
                    episode.index,
                    EpisodeTranscript::setup_error(
                        episode.scenario.id,
                        episode.provider.model_id(),
                        EpisodeStatus::InfraError {
                            detail: format!("engine init: {e}"),
                        },
                    ),
                ));
            }
            indexed.sort_by_key(|(i, _)| *i);
            return indexed.into_iter().map(|(_, t)| t).collect();
        }
    };
    let stream = match engine.take_async_audit_stream("bee-concurrent") {
        Ok(s) => s,
        Err(e) => {
            for episode in prepared {
                indexed.push((
                    episode.index,
                    EpisodeTranscript::setup_error(
                        episode.scenario.id,
                        episode.provider.model_id(),
                        EpisodeStatus::InfraError {
                            detail: format!("async audit stream: {e}"),
                        },
                    ),
                ));
            }
            indexed.sort_by_key(|(i, _)| *i);
            return indexed.into_iter().map(|(_, t)| t).collect();
        }
    };
    let demux = AuditDemux::start(stream);

    let mut tasks: JoinSet<(usize, EpisodeTranscript)> = JoinSet::new();
    let mut cgroups: Vec<u64> = Vec::new();

    for PreparedEpisode {
        index: i,
        scenario,
        provider,
        plan,
        mut spec,
    } in prepared
    {
        // Record a setup failure as this episode's error transcript and move on.
        macro_rules! fail {
            ($status:expr) => {{
                indexed.push((
                    i,
                    EpisodeTranscript::setup_error(
                        scenario.id.clone(),
                        provider.model_id(),
                        $status,
                    ),
                ));
                continue;
            }};
        }

        let api_key = if provider.api_key_env.is_empty() {
            String::new()
        } else {
            std::env::var(&provider.api_key_env).unwrap_or_default()
        };
        let model = match model_from_config(&provider, &api_key) {
            Ok(m) => m,
            Err(e) => fail!(EpisodeStatus::ApiError {
                detail: e.to_string()
            }),
        };

        let scope_id = format!(
            "bee-conc-{}-{i}-{}",
            sanitize(&scenario.id),
            std::process::id()
        );
        let scope =
            match engine.create_scope(&scope_id, bee_userspace::cgroup::DEFAULT_PARENT, &plan) {
                Ok(s) => s,
                Err(e) => fail!(EpisodeStatus::InfraError {
                    detail: format!("create scope: {e}")
                }),
            };
        let cgroup_id = scope.cgroup_id;
        // Subscribe BEFORE the episode runs so no early events are missed.
        let subscription = demux.subscribe(cgroup_id);

        // Materialize the workdir sequentially on this task (avoids cross-episode fs races).
        if let Err(e) = materialize_workdir(&scenario.workdir) {
            demux.unsubscribe(cgroup_id);
            let _ = scope.teardown();
            fail!(EpisodeStatus::InfraError {
                detail: format!("workdir setup failed: {e}")
            });
        }

        spec.prebuilt_sandbox = Some(Sandbox::concurrent(
            scope,
            subscription,
            spec.strip_env.clone(),
        ));
        cgroups.push(cgroup_id);
        // The rest of the session — tool surface, escalation, system prompt — is built the way every
        // entry point builds it (024 FR-006), around the scope created on the shared engine.
        let mut session = match crate::session::build(spec, &|_| {}).await {
            Ok(s) => s,
            Err(e) => fail!(EpisodeStatus::InfraError {
                detail: e.to_string()
            }),
        };

        tasks.spawn(async move {
            let opts = LoopOptions {
                metrics: crate::metrics::Recorder::new(
                    "batch",
                    format!("batch:{}:{}", scenario.id, std::process::id()),
                ),
                escalation: session.escalation.take(),
                ..LoopOptions::default()
            };
            let scenario = Scenario {
                system_prompt: session.system_prompt.clone(),
                ..scenario
            };
            let mut t = run_loop(
                model.as_ref(),
                &scenario,
                &mut session.registry,
                &mut session.sandbox,
                &opts,
            )
            .await;
            t.consents = session.operator.take_log();
            if let Err(e) = session.shutdown().await {
                t.status = EpisodeStatus::InfraError { detail: e.clone() };
                eprintln!("bee: scope cleanup failed: {e}");
            }
            if scenario.mode == ScoringMode::Ctf {
                t.score = Some(ScoreReport::from_transcript(&t));
            }
            (i, t)
        });
    }

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(pair) => indexed.push(pair),
            Err(e) => {
                // A panicked/aborted task: we cannot recover its index, so surface it as a
                // best-effort infra error at the end (rare — the loop itself does not panic).
                indexed.push((
                    usize::MAX,
                    EpisodeTranscript::setup_error(
                        "unknown".into(),
                        "unknown".into(),
                        EpisodeStatus::InfraError {
                            detail: format!("episode task failed: {e}"),
                        },
                    ),
                ));
            }
        }
    }

    for cg in cgroups {
        demux.unsubscribe(cg);
    }
    demux.shutdown().await;

    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, t)| t).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderType;
    use std::path::{Path, PathBuf};

    fn write_policy(dir: &Path, name: &str, filesystem: &str) -> PathBuf {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!("[policy]\nname = \"{name}\"\nmode = \"enforce\"\n{filesystem}\n"),
        )
        .unwrap();
        path
    }

    fn scenario(id: &str, policy_path: PathBuf) -> Scenario {
        Scenario {
            lease_turns: None,
            context: Default::default(),
            stuck: Default::default(),
            finish: false,
            id: id.into(),
            policy_path,
            system_prompt: "test".into(),
            task: "test".into(),
            turn_limit: 1,
            timeout_secs: 1,
            tools: Vec::new(),
            mode: Default::default(),
            workdir: Default::default(),
            mcp: Default::default(),
            skills: Vec::new(),
            ceiling_policy_path: None,
            security: Default::default(),
        }
    }

    fn provider() -> ProviderConfig {
        ProviderConfig {
            context_window: None,
            provider: ProviderType::Mock,
            base_url: None,
            model: String::new(),
            api_key_env: String::new(),
            max_tokens: None,
            temperature: None,
            // Anthropic-only, and this is the `mock` backend: both left unset, which is what the
            // rest of the test fixtures do. (These fields arrived with 008 and this helper was not
            // updated, so `cargo test --features concurrent` had not compiled since.)
            thinking: None,
            effort: None,
            prompt_caching: true,
            script: Vec::new(),
        }
    }

    #[test]
    fn unsupported_policy_is_isolated_before_engine_initialization() {
        let dir = std::env::temp_dir().join(format!(
            "bee-concurrent-plan-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let valid_a = write_policy(&dir, "valid-a", "");
        let invalid = write_policy(
            &dir,
            "invalid",
            "[policy.filesystem]\n\"**/target\" = \"deny\"",
        );
        let valid_b = write_policy(&dir, "valid-b", "");

        let episodes = vec![
            (scenario("valid-a", valid_a), provider()),
            (scenario("invalid", invalid), provider()),
            (scenario("valid-b", valid_b), provider()),
        ];
        let (prepared, failures) = prepare_episodes(episodes, &SystemResolver::current());

        assert_eq!(
            prepared
                .iter()
                .map(|episode| episode.index)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, 1);
        assert!(matches!(
            &failures[0].1.status,
            EpisodeStatus::InfraError { detail }
                if detail.contains("cannot enforce filesystem segment rule")
        ));

        std::fs::remove_dir_all(dir).unwrap();
    }
}
