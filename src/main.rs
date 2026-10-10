//! `bee` — the bee application and its sole host executable (ADR-0002). It adds no enforcement
//! logic of its own: every command here assembles `bee-core` + `bee-userspace` and gets out of the
//! way (constitution Principle V). See `contracts/cli.md` for the command surface + exit codes.
//!
//! The command tree grows over the consolidation (`.scratch/application-consolidation/`): `check`,
//! `validate`, and `exec` live here today; `run`, `repl`, and `metrics` arrive with the later
//! issues. Bare `bee` prints help — starting a session is always something the operator asked for.

mod app;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bee_core::Policy;
#[cfg(feature = "enforce")]
use bee_userspace::spawn;
use bee_userspace::{EnforcementPlan, Engine, EngineError, SystemResolver};
use clap::{Parser, Subcommand};

// Exit codes (contracts/cli.md).
const EX_POLICY: u8 = 64;
const EX_UNSUPPORTED: u8 = 65;
#[cfg_attr(not(feature = "enforce"), allow(dead_code))]
const EX_PRIVILEGED: u8 = 66;
const EX_INTERNAL: u8 = 70;

#[derive(Parser)]
#[command(
    name = "bee",
    version,
    about = "eBPF-enforced sandbox harness for coding agents",
    // Bare `bee` prints help rather than defaulting into a command: starting a session is always
    // something the operator asked for (ADR-0002).
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a headless harness session: one agent episode, a batch of them, or a concurrent batch.
    // Boxed because the session commands carry a far larger argument set than the diagnostics, and
    // an unboxed variant would make every `Cmd` the size of the biggest one.
    Run(Box<app::run::RunArgs>),
    /// Chat interactively with a sandboxed coding agent, inline or full-screen.
    Repl(Box<app::repl::ReplArgs>),
    /// Report on recorded LLM usage, cost, and latency.
    Metrics(app::metrics::MetricsArgs),
    /// Read the project's finding ledger, and adjudicate what is in it.
    ///
    /// Adjudication lives here, on the operator's side of the boundary, rather than in the agent's
    /// tool surface: a verdict is only worth anything because a person formed it (016 FR-020).
    #[cfg(feature = "findings")]
    Findings(app::findings::FindingsArgs),
    /// Work with recorded HTTP traffic: export it as HAR (019-http-intercept).
    #[cfg(feature = "intercept")]
    #[command(subcommand_required = true)]
    Http(app::http::HttpArgs),
    /// Print kernel support diagnostics and exit (never attaches).
    Check,
    /// Compile-check a policy, or check attenuation of a child against a parent.
    Validate {
        #[arg(long)]
        policy: PathBuf,
        /// If given, verify `--policy` is a subset of this parent policy.
        #[arg(long)]
        parent: Option<PathBuf>,
    },
    /// Run one host command inside a scope — a diagnostic for exercising a policy against a single
    /// process, with no agent involved. The primary journeys are `bee run` and `bee repl`.
    Exec {
        #[arg(long)]
        policy: PathBuf,
        /// Parent policy to attenuate against (subagent mode): the effective policy is
        /// `parent.derive(policy)`. Refuses to run if `policy` exceeds `parent` (FR-005).
        #[arg(long)]
        parent: Option<PathBuf>,
        /// Override the policy's `mode` (enforce|observe). Defaults to the policy file's mode.
        #[arg(long)]
        mode: Option<String>,
        #[arg(long, default_value = bee_userspace::cgroup::DEFAULT_PARENT)]
        parent_cgroup: String,
        /// Command and args after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Internal: run a ripgrep-library search and print `path:line:text`. The `search` tool execs
    /// this subcommand through the sandbox so the search runs *inside the scope* — every file it
    /// opens is mediated by the LSM. Hidden: it is not an operator-facing command, only the seam the
    /// tool uses to keep the library search under enforcement.
    #[command(hide = true)]
    SearchWorker(bee::search::SearchArgs),
    /// Internal: run a structural (tree-sitter) search and print `path:line:text`. Same seam as
    /// `search-worker` and for the same reason — the `ast_grep` tool execs this through the sandbox
    /// so the parse runs *inside the scope*, with every file it opens mediated by the LSM.
    #[cfg(feature = "astgrep")]
    #[command(hide = true)]
    AstgrepWorker(bee::astgrep::AstGrepArgs),
    /// Internal: read repository history and print one commit per line. Same seam again — the
    /// `git_log` tool execs this through the sandbox, so the object files and packs `gix` opens are
    /// mediated by the LSM rather than read from the harness.
    #[cfg(feature = "gitlog")]
    #[command(hide = true)]
    GitlogWorker(bee::gitlog::GitLogArgs),
    /// Internal: read a scanner's SARIF report and print normalised findings as JSONL.
    ///
    /// The second child of the scanner pipeline, and the reason there are two: the report is
    /// megabytes of mostly rule catalogue (research R4), so it is written to a file rather than
    /// piped — and reading that file in the *harness* would open a path inside the sandbox, which
    /// Constitution III forbids. So the normaliser is itself a scope-joined child.
    #[cfg(feature = "scanners")]
    #[command(hide = true)]
    SarifWorker(bee::sarif::SarifArgs),
    /// Internal: the session's HTTP(S) interception proxy (019-http-intercept).
    ///
    /// Spawned once per session by the harness into its own kernel scope — the *proxy scope* —
    /// with the harness-bound listening socket as fd 3 and the control channel on stdio. Hidden for
    /// the same reason as the other workers: it is a seam, not an operator command.
    #[cfg(feature = "intercept")]
    #[command(hide = true)]
    ProxyWorker {
        #[arg(long)]
        session: String,
    },
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Run(args) => app::run::main(*args),
        Cmd::Repl(args) => app::repl::main(*args),
        Cmd::Metrics(args) => app::metrics::main(args),
        #[cfg(feature = "findings")]
        Cmd::Findings(args) => app::findings::main(args),
        #[cfg(feature = "intercept")]
        Cmd::Http(args) => app::http::main(args),
        Cmd::Check => cmd_check(),
        Cmd::Validate { policy, parent } => cmd_validate(&policy, parent.as_deref()),
        Cmd::Exec {
            policy,
            parent,
            mode,
            parent_cgroup,
            command,
        } => cmd_exec(
            &policy,
            parent.as_deref(),
            mode.as_deref(),
            &parent_cgroup,
            &command,
        ),
        Cmd::SearchWorker(args) => cmd_search_worker(&args),
        #[cfg(feature = "astgrep")]
        Cmd::AstgrepWorker(args) => cmd_astgrep_worker(&args),
        #[cfg(feature = "gitlog")]
        Cmd::GitlogWorker(args) => cmd_gitlog_worker(&args),
        #[cfg(feature = "scanners")]
        Cmd::SarifWorker(args) => cmd_sarif_worker(&args),
        #[cfg(feature = "intercept")]
        Cmd::ProxyWorker { session } => bee::intercept::worker::run(&session),
    }
}

/// Normalise a scanner report inside the scope. Reached only via the `scan` tool.
///
/// Exit 0 means *the report was read and normalised* — which includes a report that legitimately
/// held no results. A read or parse failure exits non-zero with a diagnostic, so "could not read the
/// scanner's answer" can never be mistaken for "the scanner had no answer" (Constitution I).
#[cfg(feature = "scanners")]
fn cmd_sarif_worker(args: &bee::sarif::SarifArgs) -> ExitCode {
    match bee::sarif::run_worker(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bee sarif-worker: {e}");
            ExitCode::from(1)
        }
    }
}

/// Run the `ast_grep` tool's structural search, printing `path:line:text`. Reached only via the
/// tool, which execs `bee astgrep-worker …` inside the scope (see [`bee::astgrep`]).
///
/// The exit code carries the fail-closed distinction the whole feature rests on: **0 with no output
/// means parsed and found nothing**, while an unsupported language or an unparseable pattern exits
/// non-zero with a diagnostic. A refusal must never be readable as a clean scan (Constitution I).
#[cfg(feature = "astgrep")]
fn cmd_astgrep_worker(args: &bee::astgrep::AstGrepArgs) -> ExitCode {
    match bee::astgrep::run_worker(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bee astgrep-worker: {e}");
            ExitCode::from(1)
        }
    }
}

/// Run the `git_log` tool's history query. Reached only via the tool, which execs
/// `bee gitlog-worker …` inside the scope (see [`bee::gitlog`]).
///
/// The exit code is the contract: **0 with no output means the history was read and nothing matched**,
/// while a path outside any repository exits [`bee::gitlog::EXIT_NOT_A_REPOSITORY`] and an
/// unanswerable request exits [`bee::gitlog::EXIT_FAILED`]. The wrapper turns those into `Unavailable`
/// and `Failed`; without distinct codes all three would arrive as silence (Constitution I).
#[cfg(feature = "gitlog")]
fn cmd_gitlog_worker(args: &bee::gitlog::GitLogArgs) -> ExitCode {
    ExitCode::from(bee::gitlog::run_worker(args) as u8)
}

/// Run the `search` tool's library search, streaming results to stdout. Reached only via the tool,
/// which execs `bee search-worker …` inside the scope (see [`bee::search`]). A search/IO error exits
/// non-zero so the tool reports an error result; a file the LSM denied simply yields no matches.
fn cmd_search_worker(args: &bee::search::SearchArgs) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    match bee::search::run(args, &mut stdout) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bee search-worker: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_check() -> ExitCode {
    let support = Engine::supported();
    println!("{support}");
    if support.is_supported() {
        println!("=> enforcement available");
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_UNSUPPORTED)
    }
}

fn cmd_validate(policy: &Path, parent: Option<&Path>) -> ExitCode {
    let child = match Policy::from_path(policy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("policy error: {e}");
            return ExitCode::from(EX_POLICY);
        }
    };
    let (effective, attenuation) = match parent {
        None => (child, false),
        Some(parent_path) => match Policy::from_path(parent_path) {
            Ok(parent) => match parent.derive(child) {
                Ok(derived) => (derived, true),
                Err(e) => {
                    eprintln!("attenuation violation: {e}");
                    return ExitCode::from(EX_POLICY);
                }
            },
            Err(e) => {
                eprintln!("parent policy error: {e}");
                return ExitCode::from(EX_POLICY);
            }
        },
    };

    let resolver = SystemResolver::current();
    let mut compiled = match effective.compile(&resolver) {
        Ok(compiled) => compiled,
        Err(e) => {
            eprintln!("compile error: {e}");
            return ExitCode::from(EX_POLICY);
        }
    };
    // `[policy.http]` (019): compile the proxy scope too, and check the tool scope as a session
    // would install it — with the proxy loopback as its only network rule. The port is chosen at
    // session start; any value exercises the same plan.
    let worker = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot resolve the bee binary for the proxy scope: {e}");
            return ExitCode::from(EX_POLICY);
        }
    };
    match effective.compile_http(&resolver, &worker) {
        Ok(Some(http)) => {
            let proxy_scope = http.proxy_scope;
            compiled = bee_core::compiler::with_proxy_loopback(compiled, 1);
            if let Err(e) = EnforcementPlan::prepare(&proxy_scope, effective.mode.into()) {
                eprintln!("enforcement plan error (proxy scope): {e}");
                return ExitCode::from(EX_POLICY);
            }
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("compile error: {e}");
            return ExitCode::from(EX_POLICY);
        }
    }
    if let Err(e) = EnforcementPlan::prepare(&compiled, effective.mode.into()) {
        eprintln!("enforcement plan error: {e}");
        return ExitCode::from(EX_POLICY);
    }

    if attenuation {
        println!("attenuation OK: child is a runnable subset of parent");
    } else {
        println!("policy '{}' is valid and runnable", effective.name);
    }
    ExitCode::SUCCESS
}

/// `bee exec` — compile, plan, and run one host command in a scope. Diagnostic: no agent, no
/// session, no provider. The enforcement path it exercises is the same one the sessions use, which
/// is what makes it worth keeping as a harness-free way to prove a policy enforces.
fn cmd_exec(
    policy: &Path,
    parent: Option<&Path>,
    mode: Option<&str>,
    parent_cgroup: &str,
    command: &[String],
) -> ExitCode {
    if let Some(m) = mode {
        if m != "enforce" && m != "observe" {
            eprintln!("invalid --mode '{m}' (expected enforce|observe)");
            return ExitCode::from(EX_POLICY);
        }
    }
    let child = match Policy::from_path(policy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("policy error: {e}");
            return ExitCode::from(EX_POLICY);
        }
    };
    // Subagent mode: attenuate the child against its parent, refusing any over-grant (FR-005).
    let policy = match parent {
        None => child,
        Some(parent_path) => {
            let parent = match Policy::from_path(parent_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("parent policy error: {e}");
                    return ExitCode::from(EX_POLICY);
                }
            };
            match parent.derive(child) {
                Ok(derived) => derived,
                Err(e) => {
                    eprintln!("refusing to run: attenuation violation: {e}");
                    return ExitCode::from(EX_POLICY);
                }
            }
        }
    };
    // The policy's `mode` field is the source of truth; `--mode` overrides it if given.
    let mode: &str = mode.unwrap_or(match policy.mode {
        bee_core::Mode::Enforce => "enforce",
        bee_core::Mode::Observe => "observe",
    });
    // Compile and plan before touching the kernel so every unsupported capability fails early.
    let compiled = match policy.compile(&SystemResolver::current()) {
        Ok(compiled) => compiled,
        Err(e) => {
            eprintln!("compile error: {e}");
            return ExitCode::from(EX_POLICY);
        }
    };
    let scope_mode = if mode == "observe" {
        bee_userspace::ScopeMode::Observe
    } else {
        bee_userspace::ScopeMode::Enforce
    };
    let plan = match EnforcementPlan::prepare(&compiled, scope_mode) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("enforcement plan error: {e}");
            return ExitCode::from(EX_POLICY);
        }
    };
    #[cfg(not(feature = "enforce"))]
    let _ = &plan;

    // Fail-closed: refuse to run if the kernel cannot enforce (SC-007).
    match Engine::init() {
        Ok(engine) => {
            #[cfg(feature = "enforce")]
            {
                enforce_exec(engine, &policy.name, mode, parent_cgroup, command, &plan)
            }
            #[cfg(not(feature = "enforce"))]
            {
                let _ = (engine, parent_cgroup, command, mode);
                unreachable!("init() cannot return Ok without the enforce feature")
            }
        }
        Err(EngineError::Unsupported(diag)) => {
            eprintln!("refusing to run: kernel cannot enforce (fail-closed)\n{diag}");
            ExitCode::from(EX_UNSUPPORTED)
        }
        Err(EngineError::EnforceFeatureDisabled) => {
            eprintln!(
                "kernel supports BPF-LSM but this `bee` was built without enforcement.\n\
                 Rebuild with `--features enforce` on the nightly bpf toolchain to attach policies."
            );
            ExitCode::from(EX_INTERNAL)
        }
        Err(EngineError::Load(d)) => {
            eprintln!("failed to load/attach enforcement: {d}");
            ExitCode::from(EX_INTERNAL)
        }
    }
}

/// Full enforce path: create a scope cgroup, register it for enforcement, spawn the hardened command
/// into it, and stream audit events until it exits.
#[cfg(feature = "enforce")]
fn enforce_exec(
    mut engine: Engine,
    policy_name: &str,
    mode: &str,
    parent_cgroup: &str,
    command: &[String],
    plan: &EnforcementPlan,
) -> ExitCode {
    let scope_id = format!(
        "{}-{}",
        policy_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>(),
        std::process::id()
    );

    let scope = match engine.create_scope(&scope_id, parent_cgroup, plan) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("create scope failed: {e}");
            return ExitCode::from(EX_INTERNAL);
        }
    };
    let mut audit = match engine.take_audit_reader(&scope_id) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("audit reader failed: {e}");
            let _ = scope.teardown();
            return ExitCode::from(EX_INTERNAL);
        }
    };
    let join = match scope.join_closure() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("cgroup join setup failed: {e}");
            let _ = scope.teardown();
            return ExitCode::from(EX_INTERNAL);
        }
    };

    let (program, args) = command.split_first().expect("clap requires >=1 arg");
    let mut cmd = match spawn::hardened_command(program, args, Some(join)) {
        Ok(c) => c,
        Err(spawn::SpawnError::PrivilegedTarget(t)) => {
            eprintln!("refusing to sandbox privileged target: {t}");
            let _ = scope.teardown();
            return ExitCode::from(EX_PRIVILEGED);
        }
        Err(e) => {
            eprintln!("{e}");
            let _ = scope.teardown();
            return ExitCode::from(EX_INTERNAL);
        }
    };

    eprintln!(
        "bee: scope '{scope_id}' (cgroup id {}) — {mode} mode",
        scope.cgroup_id
    );
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("spawn failed: {e}");
            let _ = scope.teardown();
            return ExitCode::from(EX_INTERNAL);
        }
    };

    let mut print = |ev: bee_core::AuditEvent| eprintln!("{}", ev.to_json());
    let code = loop {
        let _ = audit.poll(200);
        audit.drain(&mut print);
        match child.try_wait() {
            Ok(Some(status)) => {
                audit.drain(&mut print); // final flush
                break status.code().unwrap_or(1) as u8;
            }
            Ok(None) => continue,
            Err(e) => {
                eprintln!("wait failed: {e}");
                break 1;
            }
        }
    };
    let _ = scope.teardown();
    ExitCode::from(code)
}
