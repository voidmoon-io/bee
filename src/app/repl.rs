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
use bee::tools::registry_for;

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

    let mut registry = registry_for(&cfg.tools, None);

    // Strip the provider key plus any MCP token variables from tool children (FR-018/FR-041).
    #[cfg(feature = "mcp")]
    let mcp_policy = match &cfg.mcp_config {
        Some(path) => match bee::McpPolicy::from_path(path) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("{CMD}: mcp config error: {e}");
                return ExitCode::from(EX_USAGE);
            }
        },
        None => None,
    };

    #[cfg_attr(not(feature = "mcp"), allow(unused_mut))]
    let mut strip_env = session::strip_vars(session.key_env.as_deref());
    #[cfg(feature = "mcp")]
    if let Some(p) = &mcp_policy {
        strip_env.extend(p.token_env_names());
    }

    let skills = session::discover_skills(&cwd, CMD);

    // Grants resolve before the scope compiles, so the widened policy is what gets enforced.
    let resolved_policy = session::resolve_grants(
        cfg.policy.as_ref(),
        cfg.ceiling.as_ref(),
        &skills,
        &mut registry,
        &(prompt_consent as fn(&bee::skills::GrantRequest<'_>) -> bool),
        CMD,
    )
    .await;

    // The session's tool dependencies (024 FR-013): its skills, and the ledger and scanner grants
    // (016) of the grant-widened policy. After grant resolution, so a scanner a skill widened the
    // policy to include is visible; before the policy is moved into the scope, which is the last point
    // it can be read. `set_deps` rebuilds every tool registered so far, so each holds them; the
    // Interceptor joins once it is running.
    // The struct update supplies the feature-gated fields, which a slim build does not have.
    #[allow(clippy::needless_update)]
    let deps = bee::tools::ToolDeps {
        // Only model-facing skills make a `skill` tool worth offering; `/skill` reads the registry
        // regardless.
        skills: skills
            .model_facing()
            .next()
            .is_some()
            .then(|| skills.clone()),
        ..bee::tools::ToolDeps::default()
    }
    .with_security(
        &cfg.security,
        resolved_policy.as_ref(),
        &format!("repl-{}", std::process::id()),
    );
    registry.set_deps(std::sync::Arc::new(deps));
    let _ = registry.register("skill");

    // Dynamic capability grants (007-dynamic-grants). The floor is the resolved policy — the one the
    // scope is about to compile — so escalation can only ever widen what is actually enforced. The
    // ceiling is the operator's; absent one it equals the base, which disables widening entirely.
    //
    // Consent here is the same interactive prompt that gated the startup grants, not the episode
    // path's `AllowWithinCeiling`: the operator is sitting in front of this session, so a capability
    // asked for mid-session is a question, not a pre-authorization.
    let escalation = resolved_policy.as_ref().map(|base| {
        let ceiling = cfg.ceiling.clone().unwrap_or_else(|| base.clone());
        let hooks: Vec<Box<dyn bee::hooks::LoopHook>> = vec![
            Box::new(bee::grants::escalate::DenialEscalationHook {
                enabled: cfg.ceiling.is_some(),
            }),
            // 019 US3: a proxy refusal asks the operator — showing the exact host:port — whether to
            // widen the target scope, within the ceiling's `[policy.http]`.
            Box::new(bee::grants::escalate::ProxyRefusalHook {
                enabled: cfg.ceiling.is_some(),
            }),
            Box::new(bee::grants::escalate::SkillEscalationHook::new(
                skills.clone(),
            )),
        ];
        bee::repl::ReplEscalation::new(bee::grants::escalate::LoopEscalation {
            base: base.clone(),
            ceiling,
            hooks,
            consent: std::sync::Arc::new(
                prompt_consent as fn(&bee::skills::GrantRequest<'_>) -> bool,
            ),
            timeout: std::time::Duration::from_secs(120),
            default_ttl: bee::grants::Ttl::Forever,
        })
    });

    // `[policy.http]` (019): decided before the scope compiles — the proxy port becomes the tool
    // scope's only network rule — and refused here if nothing would block as the policy says.
    #[cfg(feature = "intercept")]
    let http_advisory: Option<String> = match resolved_policy.as_ref() {
        Some(p) if bee::intercept::session::wants_interception(Some(p)) => {
            match bee::intercept::session::advisory_reason(p, cfg!(feature = "enforce")) {
                Some(reason) if !args.http_scope_advisory => {
                    eprintln!(
                        "{CMD}: {}",
                        bee::intercept::session::advisory_refusal(&reason)
                    );
                    return ExitCode::from(EX_USAGE);
                }
                Some(reason) => {
                    eprintln!(
                        "{CMD}: {}",
                        bee::intercept::session::advisory_banner(&reason)
                    );
                    Some(reason)
                }
                None => None,
            }
        }
        _ => None,
    };
    #[cfg(not(feature = "intercept"))]
    if resolved_policy
        .as_ref()
        .and_then(|p| p.http.as_ref())
        .is_some_and(|h| h.is_active())
    {
        eprintln!(
            "{CMD}: the policy declares [policy.http] targets, but this bee was built without \
             --features intercept"
        );
        return ExitCode::from(EX_USAGE);
    }

    #[cfg_attr(not(feature = "intercept"), allow(unused_variables))]
    let (mut sbox, policy_label, http_prepared) =
        match session::build_sandbox(resolved_policy, cfg.policy_path.as_deref(), strip_env) {
            Ok(t) => t,
            Err(detail) => {
                eprintln!("{CMD}: {detail}");
                return ExitCode::from(EX_SOFTWARE);
            }
        };

    #[cfg(feature = "intercept")]
    let http_session = match http_prepared {
        Some(prepared) => {
            let enforcement = match &http_advisory {
                Some(reason) => bee::intercept::sidecar::Enforcement::Advisory {
                    reason: reason.clone(),
                },
                None => bee::intercept::sidecar::Enforcement::Kernel,
            };
            match bee::intercept::session::start(
                prepared,
                &mut sbox,
                &format!("repl-{}", std::process::id()),
                &cwd,
                enforcement,
            )
            .await
            {
                Ok(h) => {
                    let deps = (**registry.deps())
                        .clone()
                        .with_interceptor(h.interceptor.clone());
                    registry.set_deps(std::sync::Arc::new(deps));
                    eprintln!(
                        "{CMD}: HTTP interception on 127.0.0.1:{} ({} enforcement)",
                        h.interceptor.port(),
                        h.interceptor.enforcement().label()
                    );
                    Some(h)
                }
                Err(detail) => {
                    let _ = sbox.teardown();
                    eprintln!("{CMD}: HTTP interception: {detail}");
                    return ExitCode::from(EX_SOFTWARE);
                }
            }
        }
        None => None,
    };

    // Connect MCP servers, register their tools alongside the built-ins, and build the per-turn
    // refresh hook (FR-043). The bridge owns the stdio children for the session and is dropped
    // before the scope, so the children die inside the scope they were launched in.
    #[cfg(feature = "mcp")]
    let (mcp_bridge, mcp_summary, mcp_refresh) = match mcp_policy {
        Some(policy) => {
            let bridge = std::sync::Arc::new(bee::mcp::McpBridge::connect(policy, &sbox).await);
            bridge.register_into(&mut registry);
            let summary = bridge.summary();
            let hook = bridge.clone();
            let refresh: Box<dyn Fn(&mut bee::ToolRegistry) + Send + Sync> = Box::new(move |reg| {
                if hook.take_dirty() {
                    reg.remove_mcp_tools();
                    hook.register_into(reg);
                }
            });
            (Some(bridge), Some(summary), Some(refresh))
        }
        None => (None, None, None),
    };

    let config = ReplConfig {
        system_prompt: cfg
            .system
            .clone()
            .unwrap_or_else(|| ReplConfig::default().system_prompt),
        agent_turn_budget: cfg.budget,
        policy_label: policy_label.clone(),
        mascot: !args.no_bee && std::env::var_os("BEE_MASCOT").is_none_or(|v| v != "0"),
        #[cfg(feature = "mcp")]
        mcp_summary,
        #[cfg(feature = "mcp")]
        refresh_tools: mcp_refresh,
        skills: skills.clone(),
        visual: cfg.visual,
        escalation,
        #[cfg(feature = "intercept")]
        http_pane: http_session
            .as_ref()
            .map(|h| bee::intercept::pane::pane_source(h.interceptor.clone())),
        context: context_inputs,
        state: std::sync::Mutex::new(bee::repl::ReplState::with_context(context)),
        ..ReplConfig::default()
    };

    print_banner(&session, &cfg, &policy_label, &config);

    let use_tui = choose_frontend(&args);
    let session_out: Option<bee::repl::ReplSession> = {
        #[cfg(feature = "tui")]
        {
            if use_tui {
                if let Err(e) =
                    bee::tui::run(session.model.as_ref(), &mut registry, &mut sbox, &config).await
                {
                    eprintln!("{CMD}: tui error: {e}");
                }
                None
            } else {
                Some(run_repl(session.model.as_ref(), &mut registry, &mut sbox, &config).await)
            }
        }
        #[cfg(not(feature = "tui"))]
        {
            if use_tui {
                eprintln!("{CMD}: --tui requires building with --features tui; running inline");
            }
            Some(run_repl(session.model.as_ref(), &mut registry, &mut sbox, &config).await)
        }
    };

    // Drop the refresh hook (its bridge clone lives in `config`), then the bridge, killing the MCP
    // children — which live in the scope cgroup — before the scope itself is torn down.
    #[cfg(feature = "mcp")]
    {
        drop(config);
        drop(mcp_bridge);
    }
    // The proxy worker goes first: its sidecar scope is torn down before the tool scope (019 P4).
    #[cfg(feature = "intercept")]
    if let Some(h) = &http_session {
        h.shutdown().await;
    }
    if let Err(e) = sbox.teardown() {
        eprintln!("{CMD}: WARNING: {e} — a process may have outlived enforcement");
    }

    #[cfg(feature = "intercept")]
    let http_header = http_session
        .as_ref()
        .map(|h| bee::transcript::HttpSessionHeader {
            enforcement: h.interceptor.enforcement().label().into(),
            advisory_reason: http_advisory.clone(),
            advisory_acknowledged: http_advisory.is_some(),
        });
    #[cfg(not(feature = "intercept"))]
    let http_header: Option<bee::transcript::HttpSessionHeader> = None;
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
