//! Shared harness for 019 intercept tests: a session built the way every entry point builds one
//! (`bee::session::build`, 024 T048) — host enforcement with `[policy.http]`, so the real `bee
//! proxy-worker` runs advisory (the host tier has no kernel scope) — and tools driven through its
//! registry the way a session does.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bee::intercept::sidecar::{HarnessResolver, Interceptor};
use bee::provider::ToolCall;
use bee::sandbox::{CallContext, CallOrigin};
use bee::session::{Enforcement, EntryPoint, SessionSpec};
use bee::tools::ToolResult;
use bee_core::{CompileError, ExecIdentity, Policy, Resolver};

pub struct Names(pub HashMap<String, Vec<IpAddr>>);

impl Resolver for Names {
    fn project_root(&self) -> &str {
        "/nonexistent/project"
    }
    fn home(&self) -> &str {
        "/nonexistent/home"
    }
    fn resolve_exec(&self, n: &str) -> Result<PathBuf, CompileError> {
        Ok(PathBuf::from(n))
    }
    fn resolve_exec_identity(&self, _: &Path) -> Result<ExecIdentity, CompileError> {
        unreachable!()
    }
    fn resolve_host(&self, h: &str) -> Result<Vec<IpAddr>, CompileError> {
        if let Ok(ip) = h.parse() {
            return Ok(vec![ip]);
        }
        self.0
            .get(h)
            .cloned()
            .ok_or_else(|| CompileError::UnresolvableHost(h.into(), "unknown".into()))
    }
}

/// A policy with a `[policy.http]` body, checked to compile against fixed names.
pub fn scope(body: &str, names: &[(&str, &str)]) -> Policy {
    let p = Policy::from_toml(&format!("[policy]\nname = \"t\"\n[policy.http]\n{body}\n")).unwrap();
    let n = Names(
        names
            .iter()
            .map(|(h, a)| (h.to_string(), vec![a.parse().unwrap()]))
            .collect(),
    );
    p.compile_http(&n, Path::new("/bin/true"))
        .unwrap()
        .expect("[policy.http] is active");
    p
}

pub fn resolver(names: &[(&str, &str)]) -> HarnessResolver {
    let m: HashMap<String, Vec<IpAddr>> = names
        .iter()
        .map(|(h, a)| (h.to_string(), vec![a.parse().unwrap()]))
        .collect();
    Arc::new(move |h: &str| m.get(h).cloned().ok_or_else(|| format!("no such host {h}")))
}

/// A built session, its running proxy, and a project directory of its own.
pub struct Session {
    pub session: bee::session::Session,
    pub icpt: Interceptor,
    pub dir: tempfile::TempDir,
    turn: u32,
}

impl Session {
    pub async fn start(policy: Policy, names: &[(&str, &str)], tools: &[&str]) -> Session {
        Session::start_with(policy, names, tools, |_| {}).await
    }

    /// [`Session::start`], with `edit` applied to the spec before it is built — a ceiling, an
    /// operator.
    pub async fn start_with(
        policy: Policy,
        names: &[(&str, &str)],
        tools: &[&str],
        edit: impl FnOnce(&mut SessionSpec),
    ) -> Session {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = SessionSpec {
            entry: EntryPoint::Headless,
            // The proxy's session id is `<label>-<pid>`: unique per test session.
            label: format!("test-{}", rand_suffix()),
            policy: Some(policy),
            ceiling: None,
            enforcement: Enforcement::Host,
            tools: tools.iter().map(|t| t.to_string()).collect(),
            ctf_flag: None,
            skill_roots: Vec::new(),
            mcp: Default::default(),
            security: Default::default(),
            workdir: dir.path().to_path_buf(),
            system_prompt: String::new(),
            strip_env: bee::sandbox::key_vars(None),
            // Host mode: the proxy alone enforces the scope.
            http_scope_advisory: true,
            lease_turns: None,
            operator: bee::operator::Operator::autonomous(Arc::new(bee::operator::NullOutput)),
            prebuilt_sandbox: None,
        };
        edit(&mut spec);
        let hosts = names
            .iter()
            .map(|(h, a)| (h.to_string(), a.parse().unwrap()))
            .collect();
        let session = bee::session::build_with(
            spec,
            &|_| {},
            PathBuf::from(env!("CARGO_BIN_EXE_bee")),
            hosts,
        )
        .await
        .expect("session builds");
        for name in tools {
            assert!(session.registry.contains(name), "a known tool: {name}");
        }
        let icpt = session
            .http
            .as_ref()
            .expect("[policy.http] starts the proxy")
            .interceptor
            .clone();
        Session {
            session,
            icpt,
            dir,
            turn: 0,
        }
    }

    /// One tool call, bracketed by `begin_call`/`end_call` exactly as the loops do. Returns the
    /// result and the call id.
    pub async fn call(&mut self, tool: &str, args: serde_json::Value) -> (ToolResult, String) {
        let (r, id, _) = self.call_with_events(tool, args).await;
        (r, id)
    }

    /// [`Session::call`], also returning the proxy events the call produced.
    pub async fn call_with_events(
        &mut self,
        tool: &str,
        args: serde_json::Value,
    ) -> (ToolResult, String, Vec<bee::proxy_event::ProxyEvent>) {
        self.turn += 1;
        let id = format!("call_{}_{}", self.turn, rand_suffix());
        self.session
            .sandbox
            .begin_call(CallContext {
                call_id: id.clone(),
                turn: self.turn,
                origin: CallOrigin::Tool,
            })
            .await;
        let r = self
            .session
            .registry
            .execute(
                &ToolCall {
                    id: id.clone(),
                    name: tool.into(),
                    arguments: args,
                },
                &self.session.sandbox,
            )
            .await;
        let events = self.session.sandbox.end_call().await;
        (r, id, events)
    }

    /// Parse a tool's JSON result (the body before any `[bee]` notices).
    pub fn json(r: &ToolResult) -> serde_json::Value {
        let body = r.content.split("\n[bee]").next().unwrap();
        let body = body.split("\n(").next().unwrap();
        serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", r.content))
    }
}

fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{}", N.fetch_add(1, Ordering::Relaxed))
}
