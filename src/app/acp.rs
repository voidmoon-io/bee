//! `bee acp`: serve the Agent Client Protocol on stdin/stdout (026-acp).
//!
//! The protocol and the sessions live in the library ([`bee::acp`]); this is the process around them.
//! It decides once whether sessions are kernel-enforced, starts the one supervisor every session's
//! scope is created on, and builds each session the way `bee repl` builds one — configuration
//! resolved in the session's own working directory, the project layer untrusted.
//!
//! stdout carries only the protocol. Everything else — warnings, the host-mode banner, build lines —
//! goes to stderr, where an ACP client logs it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use bee::acp::{ClientMcpServer, OpenSession, OpenedSession, SessionFactory};
use bee::repl::ReplConfig;
use clap::Args;

use super::config::{self, Flags};
use super::session::{self, EX_SOFTWARE};

const CMD: &str = "bee acp";

#[derive(Args, Debug, Clone)]
pub struct AcpArgs {
    /// Provider configuration file (overrides configuration).
    #[arg(long)]
    pub provider: Option<PathBuf>,
    /// An explicit configuration file, layered above project and user configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// The policy every session runs under (overrides configuration).
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// The ceiling grants are bounded by.
    #[arg(long)]
    pub ceiling_policy: Option<PathBuf>,
    #[arg(long)]
    pub system: Option<String>,
    /// Comma-separated tool names.
    #[arg(long)]
    pub tools: Option<String>,
    /// Model turns per prompt.
    #[arg(long)]
    pub budget: Option<u32>,
    #[arg(long)]
    pub mcp_config: Option<PathBuf>,
    /// Run every session with no kernel scope, on purpose.
    #[arg(long, conflicts_with = "policy")]
    pub host: bool,
    /// Accept `[policy.http]` interception the kernel does not back.
    #[arg(long)]
    pub http_scope_advisory: bool,
}

impl AcpArgs {
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
            theme: None,
            visual_level: None,
            no_animation: true,
        }
    }
}

pub fn main(args: AcpArgs) -> ExitCode {
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
    runtime.block_on(acp(args))
}

async fn acp(args: AcpArgs) -> ExitCode {
    if args.host {
        session::announce_host_mode(CMD);
    } else if let Err(e) = session::require_kernel_support() {
        eprintln!("{CMD}: {}", e.detail);
        return ExitCode::from(e.code);
    }
    // One engine for the process: every session's scope is created on it (026 R3).
    #[cfg(feature = "enforce")]
    let supervisor = if args.host {
        None
    } else {
        match bee::supervisor::Supervisor::start() {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("{CMD}: {e}");
                return ExitCode::from(EX_SOFTWARE);
            }
        }
    };
    // `[acp] max_sessions` is the process's, from the configuration where bee was started.
    let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let max_sessions = config::resolve(&here, &args.flags())
        .map(|c| c.acp.max_sessions())
        .unwrap_or(config::file::AcpSection::DEFAULT_MAX_SESSIONS as usize);

    let factory = Arc::new(Factory {
        args,
        #[cfg(feature = "enforce")]
        supervisor,
    });
    match bee::acp::agent::serve(
        tokio::io::stdin(),
        tokio::io::stdout(),
        factory,
        max_sessions,
    )
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{CMD}: WARNING: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Factory {
    args: AcpArgs,
    #[cfg(feature = "enforce")]
    supervisor: Option<bee::supervisor::Supervisor>,
}

#[async_trait::async_trait]
impl SessionFactory for Factory {
    async fn open(&self, req: OpenSession) -> Result<OpenedSession, String> {
        let cfg = config::resolve(&req.cwd, &self.args.flags()).map_err(|e| e.to_string())?;
        let enforcement = session::resolve_enforcement(
            cfg.policy.is_some(),
            cfg.policy.is_some(),
            self.args.host,
        )
        .map_err(|e| e.detail)?;
        let model = session::build(&cfg, CMD).map_err(|e| e.detail)?;

        let mut notices = Vec::new();
        let mut mcp = match &cfg.mcp_config {
            Some(path) => {
                bee::McpPolicy::from_path(path).map_err(|e| format!("mcp config error: {e}"))?
            }
            None => bee::McpPolicy::default(),
        };
        add_client_mcp(&mut mcp, req.client_mcp, cfg.acp.client_mcp(), &mut notices);
        let mut strip_env = session::strip_vars(model.key_env.as_deref());
        strip_env.extend(mcp.token_env_names());

        let system_prompt = cfg
            .system
            .clone()
            .unwrap_or_else(|| ReplConfig::default().system_prompt);
        let spec = bee::session::SessionSpec {
            entry: bee::session::EntryPoint::Acp,
            label: req.id.clone(),
            policy: cfg.policy.clone(),
            ceiling: cfg.ceiling.clone(),
            enforcement: match enforcement {
                session::Enforcement::Host => bee::session::Enforcement::Host,
                session::Enforcement::Enforced => bee::session::Enforcement::Kernel,
            },
            tools: cfg.tools.clone(),
            ctf_flag: None,
            skill_roots: bee::SkillRegistry::default_roots(&req.cwd),
            mcp,
            security: cfg.security.clone(),
            workdir: req.cwd.clone(),
            system_prompt: system_prompt.clone(),
            strip_env,
            http_scope_advisory: self.args.http_scope_advisory,
            lease_turns: None,
            operator: req.operator,
            prebuilt_sandbox: None,
        };
        let lines = std::sync::Mutex::new(Vec::<String>::new());
        let report = |line: &str| {
            eprintln!("{CMD}: [{}] {line}", req.id);
            lines.lock().expect("report").push(line.to_string());
        };
        let mut built = self.build(spec, &report).await?;
        notices.extend(lines.into_inner().expect("report"));

        let context_inputs = bee::context::ContextInputs {
            config: cfg.context,
            provider_window: cfg.provider.context_window,
            max_tokens: cfg.provider.max_tokens,
        };
        let context =
            bee::context::ContextManager::for_session(&context_inputs, None, model.model.id())
                .map(|(ctx, notice)| {
                    notices.extend(notice);
                    ctx
                })
                .map_err(|e| format!("invalid [context]: {e}"))?;
        let stuck = cfg
            .stuck
            .resolve()
            .map_err(|e| format!("invalid [stuck]: {e}"))?;
        let escalation = built
            .escalation
            .take()
            .map(bee::repl::ReplEscalation::new)
            .transpose()
            .map_err(|e| format!("invalid escalation configuration: {e}"))?;
        let config = ReplConfig {
            system_prompt,
            agent_turn_budget: cfg.budget,
            policy_label: policy_label(cfg.policy_path.as_deref(), self.args.host),
            mascot: false,
            #[cfg(feature = "mcp")]
            mcp_summary: built.mcp.as_ref().map(|b| b.summary()),
            tool_refresh: built.tool_refresh.clone(),
            skills: built.skills.clone(),
            delegation: built.delegation(None).map(|d| {
                d.with_limits(cfg.delegation)
                    .with_harness_env(cfg.acp.harness_env_passthrough.clone().unwrap_or_default())
            }),
            visual: cfg.visual,
            escalation,
            context: context_inputs,
            stuck,
            state: std::sync::Mutex::new(bee::repl::ReplState::with_context(context)),
            ..ReplConfig::default()
        };
        Ok(OpenedSession {
            session: built,
            model: model.model,
            config,
            notices,
        })
    }
}

impl Factory {
    async fn build(
        &self,
        spec: bee::session::SessionSpec,
        report: &(dyn Fn(&str) + Sync),
    ) -> Result<bee::session::Session, String> {
        #[cfg(feature = "enforce")]
        if spec.enforcement == bee::session::Enforcement::Kernel {
            if let Some(sup) = &self.supervisor {
                return bee::session::build_on(spec, report, sup.clone())
                    .await
                    .map_err(|e| e.to_string());
            }
        }
        bee::session::build(spec, report)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Admit the client's stdio MCP servers when the operator allows it (`[acp] client_mcp`), under the
/// operator's MCP policy; otherwise say each was dropped (026 R7).
fn add_client_mcp(
    mcp: &mut bee::McpPolicy,
    client: Vec<ClientMcpServer>,
    allowed: bool,
    notices: &mut Vec<String>,
) {
    for s in client {
        if !allowed {
            notices.push(format!(
                "MCP server '{}' not started: client MCP servers are off ([acp] client_mcp)",
                s.name
            ));
            continue;
        }
        let server = bee::McpServerConfig {
            name: s.name.clone(),
            transport: bee::McpTransport::Stdio,
            command: Some(s.command.to_string_lossy().into_owned()),
            args: s.args,
            env: s.env.into_iter().collect(),
            url: None,
            token_env: None,
            allowed_tools: None,
            denied_tools: None,
        };
        if let Err(e) = server.validate() {
            notices.push(format!("MCP server '{}' not started: {e}", s.name));
            continue;
        }
        if mcp.servers.len() as u32 >= mcp.max_servers {
            notices.push(format!(
                "MCP server '{}' not started: the operator's limit of {} servers is reached",
                s.name, mcp.max_servers
            ));
            continue;
        }
        mcp.enabled = true;
        mcp.servers.push(server);
    }
}

fn policy_label(path: Option<&Path>, host: bool) -> String {
    match (path, host) {
        (_, true) => "host (unenforced)".to_string(),
        (Some(p), false) => format!("{} (enforced)", p.display()),
        (None, false) => "policy (enforced)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str) -> ClientMcpServer {
        ClientMcpServer {
            name: name.into(),
            command: "/usr/bin/t3-mcp".into(),
            args: vec!["--stdio".into()],
            env: vec![("T3_TOKEN".into(), "x".into())],
        }
    }

    // 026 T012: a client's servers start only when the operator allows them, within its limits.
    #[test]
    fn client_mcp_servers_need_the_operator_and_respect_its_limit() {
        let mut mcp = bee::McpPolicy::default();
        let mut notices = Vec::new();
        add_client_mcp(&mut mcp, vec![server("t3")], false, &mut notices);
        assert!(!mcp.enabled && mcp.servers.is_empty());
        assert!(notices[0].contains("[acp] client_mcp"), "{notices:?}");

        let mut mcp = bee::McpPolicy {
            max_servers: 1,
            ..bee::McpPolicy::default()
        };
        let mut notices = Vec::new();
        add_client_mcp(
            &mut mcp,
            vec![server("t3"), server("bad__name"), server("two")],
            true,
            &mut notices,
        );
        assert!(mcp.enabled);
        assert_eq!(mcp.servers.len(), 1);
        assert_eq!(mcp.servers[0].name, "t3");
        assert!(
            notices.iter().any(|n| n.contains("bad__name")),
            "{notices:?}"
        );
        assert!(
            notices.iter().any(|n| n.contains("limit of 1")),
            "{notices:?}"
        );
    }
}
