//! The batch runner (US2): one episode transcript per `(scenario, provider)` pair.
//!
//! This is the thin layer that composes *over* [`run_episode`] — it does not touch the loop. It
//! loads every scenario and provider upfront, then runs each pair **sequentially** (concurrency is
//! US4). The isolation property (US2 AS-2): a provider that can't be built (bad key, missing
//! `base_url`) yields an `infra_error` transcript for each of its scenarios; every other provider's
//! episodes run normally. A scenario/provider whose TOML can't even be *parsed* is a [`BatchError`]
//! (we can't name the model), which never aborts the batch either.

use std::path::PathBuf;
use std::sync::Arc;

use crate::config::ProviderConfig;
use crate::episode::{run_episode_with, ProgressSink};
use crate::provider::model_from_config;
use crate::scenario::Scenario;
use crate::transcript::{EpisodeStatus, EpisodeTranscript};

/// A progress sink shared across every episode in a batch (cloned per pair).
type SharedSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Render a batch's transcripts as a honeycomb status grid (003-visual-render, US7): one row per
/// scenario, its per-provider outcomes as colored dots, `N/M pass` on the right. Meant for the
/// human-facing summary (stderr), never the JSON artifact.
pub fn status_grid_summary(transcripts: &[EpisodeTranscript]) -> String {
    use crate::viz::grid::{status_grid, Status};
    // Group by scenario in first-seen order so multiple providers appear as attempts on one row.
    let mut order: Vec<String> = Vec::new();
    let mut by_scenario: std::collections::HashMap<String, Vec<Status>> =
        std::collections::HashMap::new();
    for t in transcripts {
        by_scenario.entry(t.scenario_id.clone()).or_insert_with(|| {
            order.push(t.scenario_id.clone());
            Vec::new()
        });
        by_scenario
            .get_mut(&t.scenario_id)
            .unwrap()
            .push(Status::from_episode(&t.status));
    }
    let rows: Vec<(String, Vec<Status>)> = order
        .into_iter()
        .map(|s| {
            let v = by_scenario.remove(&s).unwrap();
            (s, v)
        })
        .collect();
    status_grid(&rows)
}

/// What to run: the scenario and provider TOMLs to cross.
pub struct BatchConfig {
    /// Paths to scenario TOMLs.
    pub scenarios: Vec<PathBuf>,
    /// Paths to provider TOMLs.
    pub providers: Vec<PathBuf>,
    /// Operator-declared containment root for host-side workdir materialization, applied to every
    /// scenario in the batch. `None` means a per-episode temp directory. See
    /// [`crate::scenario::WorkdirSetup::root`].
    pub workdir_root: Option<PathBuf>,
}

/// The product of a batch: one transcript per runnable pair, plus per-pair setup errors (a TOML that
/// could not be read/parsed — distinct from a provider that parsed but could not be built, which is
/// an `infra_error` *transcript*).
pub struct BatchResult {
    pub transcripts: Vec<EpisodeTranscript>,
    pub errors: Vec<BatchError>,
}

/// A pair that never produced a transcript because a TOML failed to load.
#[derive(Debug, Clone)]
pub struct BatchError {
    pub scenario_path: PathBuf,
    pub provider_path: PathBuf,
    pub detail: String,
}

/// Run every `(scenario, provider)` pair sequentially, collecting one transcript per runnable pair.
///
/// `progress` (if any) is shared across all episodes; each per-episode line is prefixed with the
/// pair it came from.
pub async fn run_batch(config: &BatchConfig, progress: Option<ProgressSink>) -> BatchResult {
    // Share one sink across episodes: `ProgressSink` is an owned `Box`, so wrap it in an `Arc` and
    // hand each episode a fresh closure that forwards to it with a per-pair prefix.
    let shared: Option<SharedSink> = progress.map(Arc::from);

    // Load everything upfront. A scenario is validated (`from_path`); a provider is parsed *without*
    // validation so a semantically-invalid provider reaches `model_from_config` and becomes an
    // error transcript rather than a load error (US2 AS-2).
    let scenarios: Vec<(PathBuf, Result<Scenario, String>)> = config
        .scenarios
        .iter()
        .map(|p| {
            let loaded = Scenario::from_path(p)
                .map_err(|e| e.to_string())
                .map(|mut s| {
                    // Operator-declared, never scenario-declared (see `WorkdirSetup::root`).
                    s.workdir.root = config.workdir_root.clone();
                    s
                });
            (p.clone(), loaded)
        })
        .collect();
    let providers: Vec<(PathBuf, Result<ProviderConfig, String>)> = config
        .providers
        .iter()
        .map(|p| {
            (
                p.clone(),
                ProviderConfig::parse_unchecked(p).map_err(|e| e.to_string()),
            )
        })
        .collect();

    let mut transcripts = Vec::new();
    let mut errors = Vec::new();

    for (spath, sres) in &scenarios {
        for (ppath, pres) in &providers {
            let (scenario, cfg) = match (sres, pres) {
                (Err(detail), _) => {
                    errors.push(BatchError {
                        scenario_path: spath.clone(),
                        provider_path: ppath.clone(),
                        detail: format!("scenario: {detail}"),
                    });
                    continue;
                }
                (_, Err(detail)) => {
                    errors.push(BatchError {
                        scenario_path: spath.clone(),
                        provider_path: ppath.clone(),
                        detail: format!("provider: {detail}"),
                    });
                    continue;
                }
                (Ok(s), Ok(c)) => (s, c),
            };

            // Resolve the key from its env var (never the config file); empty is fine for `mock`
            // and for local OpenAI-compatible endpoints.
            let api_key = if cfg.api_key_env.is_empty() {
                String::new()
            } else {
                std::env::var(&cfg.api_key_env).unwrap_or_default()
            };

            // Say out loud which secret is about to be sent where. `--providers <dir>` globs a
            // directory rather than an audited list, so this is the operator's chance to notice a
            // provider file they did not write pointing their key at an endpoint they do not know.
            if let (Some(sink), Some(url)) = (shared.as_ref(), cfg.base_url.as_deref()) {
                if !api_key.is_empty() {
                    sink(&format!(
                        "provider {}: sending ${} to {url}",
                        ppath.display(),
                        cfg.api_key_env,
                    ));
                }
            }

            match model_from_config(cfg, &api_key) {
                Ok(model) => {
                    let key_env = (!cfg.api_key_env.is_empty()).then_some(cfg.api_key_env.as_str());
                    let ep_progress = shared.as_ref().map(|s| {
                        let s = s.clone();
                        let label = format!("{}/{}", scenario.id, cfg.model_id());
                        Box::new(move |line: &str| s(&format!("[{label}] {line}"))) as ProgressSink
                    });
                    // The provider file's window and reply limit size the context budget (025); a
                    // scenario's own `[context]` is merged over them in the loop.
                    let eopts = crate::episode::EpisodeOptions {
                        context: crate::context::ContextInputs {
                            provider_window: cfg.context_window,
                            max_tokens: cfg.max_tokens,
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    transcripts.push(
                        run_episode_with(model.as_ref(), scenario, key_env, ep_progress, eopts)
                            .await,
                    );
                }
                Err(e) => {
                    // Parseable but not buildable (e.g. `openai-compat` without `base_url`): record
                    // an `infra_error` transcript so this provider's failure is isolated (US2 AS-2).
                    transcripts.push(EpisodeTranscript::setup_error(
                        scenario.id.clone(),
                        cfg.model_id(),
                        EpisodeStatus::InfraError {
                            detail: e.to_string(),
                        },
                    ));
                }
            }
        }
    }

    BatchResult {
        transcripts,
        errors,
    }
}
