//! `bee repl` — the interactive harness session (ADR-0002, consolidation issue 04).
//!
//! Built on the same session construction as `bee run`, so the enforcement path for a headless and
//! an interactive session is one piece of code rather than two that happen to agree. What stays
//! here is what genuinely belongs to an interactive session: the consent prompt, the startup
//! banner, the front-end choice, and the transcript on exit.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

use bee::repl::{run_repl, ReplConfig};

use crate::app::config::{self, Flags};
use crate::app::session::{self, EX_IOERR, EX_SOFTWARE, EX_USAGE};

const CMD: &str = "bee repl";

#[derive(Args, Debug)]
pub struct ReplArgs {
    /// Provider TOML (which model / endpoint, or a `mock` script). May also come from
    /// configuration.
    #[arg(long)]
    pub provider: Option<PathBuf>,
    /// An explicit configuration file, outranking discovered project and user configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Bee policy for the scope. Omit to run tools as hardened host processes with no kernel scope.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Capability ceiling for skill grants. A skill's `requires` block may widen `--policy` only up
    /// to this ceiling; you approve each within-ceiling request at startup. Omit ⇒ `--policy` is
    /// the ceiling ⇒ skills grant nothing.
    #[arg(long)]
    pub ceiling_policy: Option<PathBuf>,
    /// Override the session system prompt.
    #[arg(long)]
    pub system: Option<String>,
    /// Comma-separated tools the agent gets. `render` is included by default so the agent can draw
    /// charts/tables/sprites in the terminal (drop it from the list to disable visuals).
    #[arg(long)]
    pub tools: Option<String>,
    /// Max model calls per user message (safety cap against a runaway agent).
    #[arg(long)]
    pub budget: Option<u32>,
    /// Write the session transcript to this path on exit.
    #[arg(long)]
    pub save: Option<PathBuf>,
    /// Suppress the bee mascot animation at startup (on by default; also suppressible with
    /// `BEE_MASCOT=0`).
    #[arg(long)]
    pub no_bee: bool,
    /// Color theme (built-in name or a custom one from config). Overrides `BEE_THEME` and the
    /// config file. Built-ins: honeycomb (default), catppuccin-{mocha,latte,frappe,macchiato},
    /// dracula, nord, gruvbox, tokyo-night, rose-pine — or `auto` to pick a flavor from the
    /// terminal's detected light/dark background.
    #[arg(long)]
    pub theme: Option<String>,
    /// Standalone MCP config TOML (top-level `[mcp]` + `[[mcp.servers]]`). Requires building with
    /// `--features mcp`.
    #[arg(long)]
    pub mcp_config: Option<PathBuf>,
    /// Launch the full-screen TUI front-end. Requires building with `--features tui`.
    #[arg(long, conflicts_with = "no_tui")]
    pub tui: bool,
    /// Force the inline REPL, overriding `--tui`.
    #[arg(long)]
    pub no_tui: bool,
    /// How much screen the agent may claim: `none`, `panels` (default), `panels-wide`, or
    /// `takeover`. A ceiling, not a mode — a request above it is downgraded, never refused.
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
    /// block (a policy in `mode = "observe"`). Without it such a session refuses to start.
    /// Deliberately not settable from any configuration file.
    #[arg(long)]
    pub http_scope_advisory: bool,
}

impl ReplArgs {
    fn flags(&self) -> Flags {
        Flags {
            config: self.config.clone(),
            provider: self.provider.clone(),
            policy: self.policy.clone(),
            ceiling_policy: self.ceiling_policy.clone(),
            mcp_config: self.mcp_config.clone(),
            tools: self.tools.clone(),
            system: self.system.clone(),
            budget: self.budget,
            turn_limit: None,
            timeout_secs: None,
            theme: self.theme.clone(),
            visual_level: self.visual_level.clone(),
            no_animation: self.no_animation,
        }
    }
}

pub fn main(args: ReplArgs) -> ExitCode {
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
    runtime.block_on(repl(args))
}

async fn repl(args: ReplArgs) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let cfg = match config::resolve(&cwd, &args.flags()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{CMD}: {e}");
            return ExitCode::from(EX_USAGE);
        }
    };

    #[cfg(not(feature = "mcp"))]
    if cfg.mcp_config.is_some() {
        eprintln!("{CMD}: MCP configuration requires building with --features mcp");
        return ExitCode::from(EX_USAGE);
    }

    // The enforcement invariant, before a provider is contacted or a tool runs.
    match session::resolve_enforcement(cfg.policy.is_some(), cfg.policy.is_some(), args.host) {
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

    let session = match session::build(&cfg, CMD) {
        Ok(s) => s,
        Err(e) => return session::fail(CMD, &e),
    };

    // The context budget (025), built now so a bad `[context]` is refused before anything starts and
    // a guessed window is announced once.
    let context_inputs = bee::context::ContextInputs {
        config: cfg.context,
        provider_window: cfg.provider.context_window,
        max_tokens: cfg.provider.max_tokens,
    };
    let context = match bee::context::ContextManager::for_session(
        &context_inputs,
        None,
        session.model.id(),
    ) {
        Ok((ctx, notice)) => {
            if let Some(n) = notice {
                eprintln!("{CMD}: {n}");
            }
            ctx
        }
        Err(e) => {
            eprintln!("{CMD}: invalid [context]: {e}");
            return ExitCode::from(EX_USAGE);
        }
    };

    // MCP servers come from the configured file; a bad one is a usage error before anything starts.
    let mcp = match &cfg.mcp_config {
        Some(path) => match bee::McpPolicy::from_path(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{CMD}: mcp config error: {e}");
                return ExitCode::from(EX_USAGE);
            }
        },
        None => bee::McpPolicy::default(),
    };
    // Strip the provider key plus any MCP token variables from tool children (FR-018/FR-041).
    let mut strip_env = session::strip_vars(session.key_env.as_deref());
    strip_env.extend(mcp.token_env_names());

    // The session, built the one way every entry point builds it (024 FR-006). Consent here is the
    // interactive prompt: the operator is sitting in front of this session, so a capability asked for
    // is a question, not a pre-authorization.
    let spec = bee::session::SessionSpec {
        entry: if choose_frontend(&args) {
            bee::session::EntryPoint::Tui
        } else {
            bee::session::EntryPoint::Repl
        },
        label: "repl".into(),
        policy: cfg.policy.clone(),
        ceiling: cfg.ceiling.clone(),
        enforcement: if args.host {
            bee::session::Enforcement::Host
        } else {
            bee::session::Enforcement::Kernel
        },
        tools: cfg.tools.clone(),
        ctf_flag: None,
        skill_roots: bee::SkillRegistry::default_roots(&cwd),
        mcp,
        security: cfg.security.clone(),
        workdir: cwd.clone(),
        system_prompt: cfg
            .system
            .clone()
            .unwrap_or_else(|| ReplConfig::default().system_prompt),
        strip_env,
        http_scope_advisory: args.http_scope_advisory,
        lease_turns: None,
        consent: std::sync::Arc::new(prompt_consent as fn(&bee::skills::GrantRequest<'_>) -> bool),
        consent_timeout: std::time::Duration::from_secs(120),
    };
    let use_tui = spec.entry == bee::session::EntryPoint::Tui;
    let mut built = match bee::session::build(spec, &|line| eprintln!("{CMD}: {line}")).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{CMD}: {e}");
            return ExitCode::from(EX_USAGE);
        }
    };
    #[cfg(feature = "intercept")]
    if let Some(h) = &built.http {
        eprintln!(
            "{CMD}: HTTP interception on 127.0.0.1:{} ({} enforcement)",
            h.interceptor.port(),
            h.interceptor.enforcement().label()
        );
    }
    let policy_label = policy_label(&cfg, args.host);

    let config = ReplConfig {
        // The base prompt: `run_repl` adds the notes for the tools the session holds, as the builder
        // did for the snapshot.
        system_prompt: cfg
            .system
            .clone()
            .unwrap_or_else(|| ReplConfig::default().system_prompt),
        agent_turn_budget: cfg.budget,
        policy_label: policy_label.clone(),
        mascot: !args.no_bee && std::env::var_os("BEE_MASCOT").is_none_or(|v| v != "0"),
        #[cfg(feature = "mcp")]
        mcp_summary: built.mcp.as_ref().map(|b| b.summary()),
        tool_refresh: built.tool_refresh.clone(),
        skills: built.skills.clone(),
        visual: cfg.visual,
        escalation: built.escalation.take().map(bee::repl::ReplEscalation::new),
        #[cfg(feature = "intercept")]
        http_pane: built
            .http
            .as_ref()
            .map(|h| bee::intercept::pane::pane_source(h.interceptor.clone())),
        context: context_inputs,
        state: std::sync::Mutex::new(bee::repl::ReplState::with_context(context)),
        ..ReplConfig::default()
    };

    print_banner(&session, &cfg, &policy_label, &config);

    let session_out: Option<bee::repl::ReplSession> = {
        #[cfg(feature = "tui")]
        {
            if use_tui {
                if let Err(e) = bee::tui::run(
                    session.model.as_ref(),
                    &mut built.registry,
                    &mut built.sandbox,
                    &config,
                )
                .await
                {
                    eprintln!("{CMD}: tui error: {e}");
                }
                None
            } else {
                Some(
                    run_repl(
                        session.model.as_ref(),
                        &mut built.registry,
                        &mut built.sandbox,
                        &config,
                    )
                    .await,
                )
            }
        }
        #[cfg(not(feature = "tui"))]
        {
            if use_tui {
                eprintln!("{CMD}: --tui requires building with --features tui; running inline");
            }
            Some(
                run_repl(
                    session.model.as_ref(),
                    &mut built.registry,
                    &mut built.sandbox,
                    &config,
                )
                .await,
            )
        }
    };

    // The record of `[policy.http]`, read before the Interceptor is shut down.
    let http_header = built.http_header();
    // The config holds clones of the refresh source; drop it so shutdown releases the MCP servers,
    // then tear down in the session's one order: MCP servers, the Interceptor, the scopes (FR-012).
    drop(config);
    if let Err(e) = built.shutdown().await {
        eprintln!("{CMD}: WARNING: {e} — a process may have outlived enforcement");
    }

    if let Some(path) = &args.save {
        if let Some(mut transcript) = session_out
            .as_ref()
            .and_then(|s| s.transcript.as_ref())
            .cloned()
        {
            transcript.http_scope = http_header;
            let transcript = &transcript;
            match std::fs::write(path, transcript.to_json()) {
                Ok(()) => eprintln!("{CMD}: saved transcript to {}", path.display()),
                Err(e) => {
                    eprintln!("{CMD}: cannot write {}: {e}", path.display());
                    return ExitCode::from(EX_IOERR);
                }
            }
        }
    }

    ExitCode::SUCCESS
}

/// The banner's policy line: what the session runs under.
fn policy_label(cfg: &config::EffectiveConfig, host: bool) -> String {
    match (&cfg.policy_path, host) {
        (Some(p), false) => format!("{} (enforced)", p.display()),
        (None, false) => "policy (enforced)".to_string(),
        (_, true) => "none — host mode (no kernel scope)".to_string(),
    }
}

fn print_banner(
    session: &session::Session,
    cfg: &config::EffectiveConfig,
    policy_label: &str,
    repl_config: &ReplConfig,
) {
    println!("bee repl");
    println!("  model:  {}", session.model.id());
    println!("  policy: {policy_label}");
    println!("  tools:  {}", cfg.tools.join(", "));
    println!("  theme:  {}", bee::viz::theme::active_theme().name);
    println!(
        "  visual: {} (animations {})",
        cfg.visual.level.as_str(),
        if cfg.visual.animations { "on" } else { "off" }
    );
    if !repl_config.skills.is_empty() {
        println!(
            "  skills: {} ({} agent-loadable)",
            repl_config.skills.len(),
            repl_config.skills.model_facing().count()
        );
    }
    #[cfg(feature = "mcp")]
    if let Some(s) = &repl_config.mcp_summary {
        println!("  {}", s.lines().next().unwrap_or("mcp: configured"));
    }
    println!();
}

/// `--tui` is a request, not a command: piping, `TERM=dumb`, or a terminal below the hard floor all
/// fall back to the inline REPL with a one-line note, so the request never silently does nothing.
fn choose_frontend(args: &ReplArgs) -> bool {
    #[cfg(feature = "tui")]
    {
        use std::io::IsTerminal;
        let (cols, is_tty) = bee::viz::terminal_dims();
        let rows = terminal_rows().unwrap_or(24);
        let choice = bee::tui::frontend::choose(
            args.tui,
            args.no_tui,
            is_tty && std::io::stdout().is_terminal(),
            std::env::var("TERM").ok().as_deref(),
            (cols, rows),
        );
        if let Some(note) = &choice.note {
            eprintln!("{CMD}: {note}");
        }
        choice.frontend == bee::tui::frontend::Frontend::FullScreen
    }
    #[cfg(not(feature = "tui"))]
    {
        args.tui && !args.no_tui
    }
}

/// The terminal's row count via `TIOCGWINSZ` — the companion to `viz::terminal_dims`, which only
/// reports columns. The hard-floor check needs both. `None` off a tty.
#[cfg(feature = "tui")]
fn terminal_rows() -> Option<u16> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return None;
    }
    if let Some(rows) = std::env::var("LINES")
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|r| *r > 0)
    {
        return Some(rows);
    }
    // SAFETY: `winsize` is POD; `ioctl(TIOCGWINSZ)` only writes into it and returns 0 on success.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_row > 0 {
            return Some(ws.ws_row);
        }
    }
    None
}

/// Interactive skill-grant consent: prompt on stderr, read a y/N line from stdin. Any non-`y`
/// answer — including end-of-input — refuses, so the default is deny.
///
/// A plain function rather than a trait impl: `ConsentSink` is blanket-implemented for any
/// `Fn(&GrantRequest) -> bool`, which is exactly what a prompt is. This is the interactive
/// session's whole contribution to the otherwise-shared grant path.
fn prompt_consent(request: &bee::skills::GrantRequest<'_>) -> bool {
    use std::io::Write;
    // Every field here is skill-authored. Skill loading already refuses control characters in
    // frontmatter, but this prompt is the consent boundary itself and takes a `GrantRequest` from
    // any source, so it escapes what it prints rather than trusting an upstream check: a forged
    // prompt is a granted capability. One line per field, so nothing can smuggle in a second line.
    // `render_lines` escapes every field and covers every one — net and exec included, which this
    // prompt once silently omitted (019 P2).
    eprintln!();
    for line in request.render_lines() {
        eprintln!("{line}");
    }
    eprint!("grant these (within the ceiling)? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
