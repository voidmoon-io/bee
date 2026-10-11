//! `bee run` — the headless harness session (ADR-0002, consolidation issue 03).
//!
//! One episode, a batch of them, or a concurrent batch: run cardinality is a scheduling choice, not
//! a reason for a separate command. The artifact contract is the one `bee-episode` established and
//! that scripts depend on — transcript JSON on stdout, progress and diagnostics on stderr, so
//! piping is unaffected — as are its exit codes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use bee::{run_batch, run_episode_with, BatchConfig, EpisodeOptions, EpisodeTranscript, Scenario};

use crate::app::config::{self, EffectiveConfig, Flags};
use crate::app::session::{self, EX_DATAERR, EX_IOERR, EX_SOFTWARE, EX_USAGE};

const CMD: &str = "bee run";

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Scenario TOML (policy + task + limits). Omit and use --task for an ad-hoc run.
    #[arg(long, conflicts_with = "task")]
    pub scenario: Option<PathBuf>,
    /// Provider TOML (which model / endpoint, or a `mock` script). May also come from
    /// configuration; required somewhere unless --batch supplies its own.
    #[arg(long)]
    pub provider: Option<PathBuf>,
    /// An explicit configuration file, outranking discovered project and user configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,

    // --- batch mode: cross a set of scenarios with a set of providers ---
    /// Run every (scenario, provider) pair and emit one transcript each.
    #[arg(long)]
    pub batch: bool,
    /// Batch scenarios: a directory of `*.toml`, or a comma-separated list of paths.
    #[arg(long, requires = "batch")]
    pub scenarios: Option<String>,
    /// Batch providers: a directory of `*.toml`, or a comma-separated list of paths.
    #[arg(long, requires = "batch")]
    pub providers: Option<String>,
    /// Run the batch episodes concurrently. Requires building with `--features concurrent`
    /// (async audit demux + shared engine); an error otherwise.
    #[arg(long, requires = "batch")]
    pub concurrent: bool,

    // --- ad-hoc scenario (alternative to --scenario) ---
    /// The task/prompt to give the agent — builds a scenario on the fly (no TOML needed).
    #[arg(long)]
    pub task: Option<String>,
    /// Policy for the scope when using --task. May also come from configuration.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Capability ceiling a requested policy is attenuated against.
    #[arg(long)]
    pub ceiling_policy: Option<PathBuf>,
    /// System prompt for --task runs.
    #[arg(long, requires = "task")]
    pub system: Option<String>,
    /// Comma-separated tools for --task runs.
    #[arg(long, requires = "task")]
    pub tools: Option<String>,
    /// Max tool-call rounds for --task runs.
    #[arg(long, requires = "task")]
    pub turn_limit: Option<u32>,
    /// Wall-clock cap (seconds) for --task runs.
    #[arg(long, requires = "task")]
    pub timeout_secs: Option<u64>,

    /// Directory the scenario's `[scenario.workdir]` files and dirs must be created under.
    ///
    /// These are written on the host, as the launcher, before any sandbox exists, so the root is an
    /// operator decision and never a scenario one. Defaults to a per-episode temp directory; a
    /// scenario path that resolves outside the root is refused rather than rebased.
    #[arg(long)]
    pub workdir_root: Option<PathBuf>,

    /// Write the transcript JSON here instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Suppress the live per-turn progress lines on stderr.
    #[arg(long)]
    pub quiet: bool,
    /// Color theme (built-in name or a custom one from config). Overrides `BEE_THEME` and the
    /// config file. `auto` picks a flavor from the terminal's detected light/dark background.
    #[arg(long)]
    pub theme: Option<String>,
    /// How much screen the agent may claim: `none`, `panels`, `panels-wide`, or `takeover`.
    #[arg(long)]
    pub visual_level: Option<String>,
    /// Disable all motion — agent effects and bee's own chrome alike.
    #[arg(long)]
    pub no_animation: bool,
    /// Run with no kernel scope: tools execute as hardened, credential-stripped host processes.
    /// Required to start an unenforced session — bee will not fall back to one silently.
    #[arg(long, conflicts_with = "policy")]
    pub host: bool,
    /// Accept `[policy.http]` interception enforced by the proxy alone, when the kernel will not
    /// block: host mode, a build without `enforce`, or a policy in `mode = "observe"`. Without it
    /// such a session refuses to start. Deliberately not settable from any configuration file.
    #[arg(long)]
    pub http_scope_advisory: bool,
}

impl RunArgs {
    /// The flags this command contributes to configuration resolution.
    fn flags(&self) -> Flags {
        Flags {
            config: self.config.clone(),
            provider: self.provider.clone(),
            policy: self.policy.clone(),
            ceiling_policy: self.ceiling_policy.clone(),
            mcp_config: None,
            tools: self.tools.clone(),
            system: self.system.clone(),
            budget: None,
            turn_limit: self.turn_limit,
            timeout_secs: self.timeout_secs,
            theme: self.theme.clone(),
            visual_level: self.visual_level.clone(),
            no_animation: self.no_animation,
        }
    }

    /// Build the scenario from a TOML file (`--scenario`) or from the resolved configuration plus
    /// `--task`. The scenario file wins for scenario-shaped fields when present: it is an explicit
    /// artifact the operator named, and second-guessing it from a config file would make a
    /// checked-in scenario mean different things in different working directories.
    fn resolve_scenario(&self, cfg: &EffectiveConfig, cwd: &Path) -> Result<Scenario, String> {
        if let Some(path) = &self.scenario {
            let mut scenario = Scenario::from_path(path).map_err(|e| e.to_string())?;
            // The containment root for host-side workdir materialization comes from the operator,
            // never from the (untrusted) scenario file — see `WorkdirSetup::root`.
            scenario.workdir.root = self.workdir_root.clone();
            return Ok(scenario);
        }
        let task = self
            .task
            .as_ref()
            .ok_or("either --scenario or --task is required")?;
        // An enforced scope must have a real policy, and the `/dev/null` placeholder below is only
        // valid when nothing will compile it. That rule used to live here, as an enforce-gated
        // guard. It belongs to the enforcement invariant instead (`session::resolve_enforcement`),
        // which runs just after this and knows about `--host` — the guard here did not, so it
        // refused ad-hoc host-mode runs that the operator had explicitly asked for.
        Ok(Scenario {
            lease_turns: None,
            context: Default::default(),
            id: "adhoc".to_string(),
            policy_path: cfg
                .policy_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("/dev/null")),
            system_prompt: cfg.system.clone().unwrap_or_else(default_system_prompt),
            task: task.clone(),
            turn_limit: cfg.turn_limit,
            timeout_secs: cfg.timeout_secs,
            tools: cfg.tools.clone(),
            mode: Default::default(),
            workdir: Default::default(),
            // The user's and project's MCP servers and skills, as every other entry point has them
            // (024 FR-009). They used to be dropped here.
            mcp: match &cfg.mcp_config {
                Some(path) => bee::McpPolicy::from_path(path).map_err(|e| e.to_string())?,
                None => Default::default(),
            },
            skills: bee::SkillRegistry::default_roots(cwd),
            ceiling_policy_path: cfg.ceiling_path.clone(),
            // An ad-hoc run has no scenario file, so its security configuration comes from the
            // resolved config layers — the same operator-only `[security]` table `bee repl` reads.
            security: cfg.security.clone(),
        })
    }
}

fn default_system_prompt() -> String {
    "You are a coding agent operating in a sandbox. Use the available tools to accomplish the \
     task, then briefly report what you did and stop."
        .to_string()
}

/// Entry point. Builds the runtime here rather than at `main`, so `check`, `validate`, and `exec`
/// never enter one.
pub fn main(args: RunArgs) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{CMD}: cannot start the async runtime: {e}");
            return ExitCode::from(EX_SOFTWARE);
        }
    };
    runtime.block_on(run(args))
}

async fn run(args: RunArgs) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Batch mode carries its own providers, so it resolves configuration only for presentation.
    // Everything else needs a complete configuration before anything is contacted.
    if args.batch {
        return run_batch_mode(&args, &cwd).await;
    }

    let cfg = match config::resolve(&cwd, &args.flags()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{CMD}: {e}");
            return ExitCode::from(EX_USAGE);
        }
    };

    let scenario = match args.resolve_scenario(&cfg, &cwd) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{CMD}: scenario error: {e}");
            return ExitCode::from(EX_USAGE);
        }
    };

    // The enforcement invariant, before anything is contacted or spawned. A scenario file's own
    // `policy_path` counts as a configured policy — `/dev/null` is the long-standing "no policy"
    // placeholder and does not.
    let scenario_has_policy = scenario.policy_path != Path::new("/dev/null");
    match session::resolve_enforcement(
        scenario_has_policy || cfg.policy_path.is_some(),
        cfg.policy_path.is_some(),
        args.host,
    ) {
        // The episode's session is built by the library builder, which can run either way, so
        // `--host` means host on every build.
        Ok(session::Enforcement::Host) => session::announce_host_mode(CMD),
        Ok(session::Enforcement::Enforced) => {
            if let Err(e) = session::require_kernel_support() {
                eprintln!("{CMD}: {}", e.detail);
                return ExitCode::from(e.code);
            }
        }
        Err(e) => {
            eprintln!("{CMD}: {}", e.detail);
            return ExitCode::from(e.code);
        }
    }

    // `[policy.http]` (019): refuse before a provider is contacted when nothing would enforce it
    // as written — the build lacks interception, or the kernel will not block and the operator
    // has not said `--http-scope-advisory`.
    if let Err(detail) = check_http_scope(&scenario, args.host, args.http_scope_advisory) {
        eprintln!("{CMD}: {detail}");
        return ExitCode::from(EX_USAGE);
    }

    let session = match session::build(&cfg, CMD) {
        Ok(s) => s,
        Err(e) => return session::fail(CMD, &e),
    };

    let transcript = run_episode_with(
        session.model.as_ref(),
        &scenario,
        session.key_env.as_deref(),
        progress_sink(args.quiet),
        EpisodeOptions {
            http_scope_advisory: args.http_scope_advisory,
            enforcement: args.host.then_some(bee::session::Enforcement::Host),
            context: bee::context::ContextInputs {
                config: cfg.context,
                provider_window: cfg.provider.context_window,
                max_tokens: cfg.provider.max_tokens,
            },
        },
    )
    .await;

    let json = transcript.to_json();
    match &args.out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &json) {
                eprintln!("{CMD}: cannot write {}: {e}", path.display());
                return ExitCode::from(EX_IOERR);
            }
        }
        None => println!("{json}"),
    }

    ExitCode::from(bee::episode::exit_code(&transcript.status))
}

/// The `[policy.http]` gate for a single episode (019 T043/T044). The episode path re-checks; this
/// copy exists so the refusal is a usage error before anything is contacted.
fn check_http_scope(scenario: &Scenario, host: bool, advisory_ack: bool) -> Result<(), String> {
    let policy = match bee_core::Policy::from_path(&scenario.policy_path) {
        Ok(p) => p,
        // An unreadable policy is reported where it always was: when the episode loads it.
        Err(_) => return Ok(()),
    };
    if !policy.http.as_ref().is_some_and(|h| h.is_active()) {
        return Ok(());
    }
    // The one copy of the advisory rule (024 FR-011); here only so the refusal is a usage error before
    // a provider is contacted. The builder applies the same rule again.
    let enforcement = if cfg!(feature = "enforce") && !host {
        bee::session::Enforcement::Kernel
    } else {
        bee::session::Enforcement::Host
    };
    match bee::session::http_advisory(&policy, enforcement, advisory_ack) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Live progress → stderr, so the JSON artifact on stdout stays pipeable.
fn progress_sink(quiet: bool) -> Option<bee::ProgressSink> {
    if quiet {
        None
    } else {
        Some(Box::new(|line: &str| eprintln!("{CMD}: {line}")))
    }
}

/// Expand a `--scenarios` / `--providers` argument into concrete TOML paths. A value containing a
/// comma is a list; otherwise a directory expands to its sorted `*.toml` entries, and anything else
/// is a single path.
fn expand_paths(arg: &str) -> std::io::Result<Vec<PathBuf>> {
    if arg.contains(',') {
        return Ok(arg
            .split(',')
            .map(|s| PathBuf::from(s.trim()))
            .filter(|p| !p.as_os_str().is_empty())
            .collect());
    }
    let p = Path::new(arg);
    if p.is_dir() {
        let mut out: Vec<PathBuf> = std::fs::read_dir(p)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
            .collect();
        out.sort();
        Ok(out)
    } else {
        Ok(vec![PathBuf::from(arg)])
    }
}

/// Slug a model id for a filename: `anthropic/claude-opus-4-8` → `anthropic_claude-opus-4-8`.
fn slug(model_id: &str) -> String {
    model_id.replace('/', "_")
}

/// Batch: cross `--scenarios` with `--providers`, one transcript per pair. Exits nonzero iff a
/// setup error stopped a pair from running at all (a TOML that could not be loaded).
async fn run_batch_mode(args: &RunArgs, cwd: &Path) -> ExitCode {
    let (Some(scn_arg), Some(prov_arg)) = (&args.scenarios, &args.providers) else {
        eprintln!("{CMD}: --batch requires --scenarios and --providers");
        return ExitCode::from(EX_USAGE);
    };
    let scenarios = match expand_list(scn_arg, "--scenarios") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let providers = match expand_list(prov_arg, "--providers") {
        Ok(v) => v,
        Err(code) => return code,
    };

    // Batch supplies its own providers per pair, so resolution here is for presentation and
    // hardening only — the theme, the visual gate, and non-dumpable still have to be installed.
    install_presentation_for_batch(args, cwd);

    if args.concurrent {
        return run_concurrent_mode(
            scenarios,
            providers,
            args.workdir_root.clone(),
            &args.out,
            progress_sink(args.quiet),
        )
        .await;
    }

    let config = BatchConfig {
        scenarios,
        providers,
        workdir_root: args.workdir_root.clone(),
    };
    let result = run_batch(&config, progress_sink(args.quiet)).await;

    for e in &result.errors {
        eprintln!(
            "{CMD}: setup error [{} × {}]: {}",
            e.scenario_path.display(),
            e.provider_path.display(),
            e.detail
        );
    }

    // Human-facing status grid to stderr; stdout carries the JSON artifact.
    if !result.transcripts.is_empty() {
        eprint!("{}", bee::batch::status_grid_summary(&result.transcripts));
    }

    if let Err(code) = emit_transcripts(&result.transcripts, &args.out) {
        return code;
    }

    if result.errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_DATAERR)
    }
}

fn expand_list(arg: &str, flag: &str) -> Result<Vec<PathBuf>, ExitCode> {
    match expand_paths(arg) {
        Ok(v) if !v.is_empty() => Ok(v),
        Ok(_) => {
            eprintln!("{CMD}: {flag} matched no TOML files");
            Err(ExitCode::from(EX_USAGE))
        }
        Err(e) => {
            eprintln!("{CMD}: {flag}: {e}");
            Err(ExitCode::from(EX_USAGE))
        }
    }
}

/// Batch has no single provider to resolve, so it installs the presentation directly. A
/// configuration error here is a warning rather than a refusal: the batch's own per-pair providers
/// are what it actually needs, and failing the whole run over a theme would be disproportionate.
fn install_presentation_for_batch(args: &RunArgs, cwd: &Path) {
    if let Err(e) = bee::set_non_dumpable() {
        eprintln!("{CMD}: warning: could not set non-dumpable: {e}");
    }
    let flags = args.flags();
    match config::resolve_presentation(cwd, &flags) {
        Ok((theme, warning, visual)) => {
            if let Some(w) = warning {
                eprintln!("{CMD}: {w}");
            }
            bee::visual_gate::set(visual);
            bee::viz::theme::init_theme(theme);
        }
        Err(e) => eprintln!("{CMD}: warning: {e}"),
    }
}

/// Write transcripts to `--out` (one JSON file per transcript) or a JSON array to stdout.
fn emit_transcripts(
    transcripts: &[EpisodeTranscript],
    out: &Option<PathBuf>,
) -> Result<(), ExitCode> {
    match out {
        Some(dir) => {
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!("{CMD}: cannot create {}: {e}", dir.display());
                return Err(ExitCode::from(EX_IOERR));
            }
            for t in transcripts {
                let name = format!("{}_{}.json", t.scenario_id, slug(&t.model_id));
                let path = dir.join(&name);
                if let Err(e) = std::fs::write(&path, t.to_json()) {
                    eprintln!("{CMD}: cannot write {}: {e}", path.display());
                    return Err(ExitCode::from(EX_IOERR));
                }
            }
        }
        None => {
            let json = serde_json::to_string_pretty(transcripts)
                .unwrap_or_else(|e| format!("[/* serialize error: {e} */]"));
            println!("{json}");
        }
    }
    Ok(())
}

/// Concurrent batch: every pair against one shared engine. Only available with the `concurrent`
/// feature, which brings the async audit demux the shared engine needs.
#[cfg(feature = "concurrent")]
async fn run_concurrent_mode(
    scenario_paths: Vec<PathBuf>,
    provider_paths: Vec<PathBuf>,
    workdir_root: Option<PathBuf>,
    out: &Option<PathBuf>,
    progress: Option<bee::ProgressSink>,
) -> ExitCode {
    use bee::ProviderConfig;

    // Load and validate everything up front. Unlike sequential batch, a load failure aborts: the
    // shared-engine setup wants a clean input set rather than a per-pair error to collect.
    let mut scenarios = Vec::new();
    for p in &scenario_paths {
        match Scenario::from_path(p) {
            Ok(mut s) => {
                // Operator-declared, never scenario-declared (see `WorkdirSetup::root`).
                s.workdir.root = workdir_root.clone();
                scenarios.push(s)
            }
            Err(e) => {
                eprintln!("{CMD}: scenario {}: {e}", p.display());
                return ExitCode::from(EX_USAGE);
            }
        }
    }
    let mut providers = Vec::new();
    for p in &provider_paths {
        match ProviderConfig::from_path(p) {
            Ok(c) => providers.push(c),
            Err(e) => {
                eprintln!("{CMD}: provider {}: {e}", p.display());
                return ExitCode::from(EX_USAGE);
            }
        }
    }

    let episodes: Vec<(Scenario, ProviderConfig)> = scenarios
        .iter()
        .flat_map(|s| providers.iter().map(move |p| (s.clone(), p.clone())))
        .collect();

    let transcripts = bee::run_concurrent(episodes, progress).await;
    match emit_transcripts(&transcripts, out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Without the feature, `--concurrent` is an explicit refusal rather than a silent fall back to
/// sequential: the operator asked for concurrency and would otherwise believe they got it.
#[cfg(not(feature = "concurrent"))]
async fn run_concurrent_mode(
    _scenario_paths: Vec<PathBuf>,
    _provider_paths: Vec<PathBuf>,
    _workdir_root: Option<PathBuf>,
    _out: &Option<PathBuf>,
    _progress: Option<bee::ProgressSink>,
) -> ExitCode {
    eprintln!(
        "{CMD}: --concurrent requires building with --features concurrent \
         (async audit demux + shared engine)"
    );
    ExitCode::from(EX_USAGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::config::file::{load, Origin};
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        run: RunArgs,
    }

    // 024 FR-009: `bee run --task` keeps the user's and project's MCP servers and skills, like every
    // other entry point. It used to build its ad-hoc scenario with neither.
    #[test]
    fn a_task_keeps_the_configured_mcp_servers_and_skills() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        write(
            "p.toml",
            "[provider]\nprovider = \"mock\"\n\n[[provider.script]]\ntext = \"hi\"\n",
        );
        write(
            "mcp.toml",
            "[mcp]\nenabled = true\n\n[[mcp.servers]]\nname = \"fs\"\ntransport = \"stdio\"\ncommand = \"srv\"\n",
        );
        let cfg_path = write(
            "config.toml",
            "[provider]\npath = \"p.toml\"\n\n[mcp]\nconfig = \"mcp.toml\"\n",
        );
        let layer = load(&cfg_path, Origin::User).unwrap().unwrap();
        let args = Cli::parse_from(["bee", "--task", "list the files", "--host"]).run;
        let cfg = config::resolve_from_layers(&[layer], &args.flags()).unwrap();

        let scenario = args.resolve_scenario(&cfg, dir.path()).unwrap();
        assert!(scenario.mcp.enabled);
        assert_eq!(scenario.mcp.servers[0].name, "fs");
        assert_eq!(
            scenario.skills,
            bee::SkillRegistry::default_roots(dir.path()),
            "the same skill roots `bee repl` discovers from"
        );
    }
}
