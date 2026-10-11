//! Shared harness for 019 intercept tests: compile a `[policy.http]` scope against fixed names, run
//! the real `bee proxy-worker` (advisory: the host tier has no kernel scope) under the real harness
//! side, and drive tools through a registry the way a session does.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bee::intercept::creds::ProxyCredentials;
use bee::intercept::sidecar::{Enforcement, HarnessResolver, Interceptor, InterceptorConfig};
use bee::provider::ToolCall;
use bee::sandbox::{CallContext, CallOrigin, Sandbox};
use bee::tools::{ToolRegistry, ToolResult};
use bee_core::compiler::HttpScope;
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

/// Compile a `[policy.http]` body against fixed names.
pub fn scope(body: &str, names: &[(&str, &str)]) -> HttpScope {
    let p = Policy::from_toml(&format!("[policy]\nname = \"t\"\n[policy.http]\n{body}\n")).unwrap();
    let n = Names(
        names
            .iter()
            .map(|(h, a)| (h.to_string(), vec![a.parse().unwrap()]))
            .collect(),
    );
    p.compile_http(&n, Path::new("/bin/true"))
        .unwrap()
        .unwrap()
        .http_scope
}

pub fn resolver(names: &[(&str, &str)]) -> HarnessResolver {
    let m: HashMap<String, Vec<IpAddr>> = names
        .iter()
        .map(|(h, a)| (h.to_string(), vec![a.parse().unwrap()]))
        .collect();
    Arc::new(move |h: &str| m.get(h).cloned().ok_or_else(|| format!("no such host {h}")))
}

/// A running proxy, a sandbox wired to it, and a registry of the given tools.
pub struct Session {
    pub icpt: Interceptor,
    pub sandbox: Sandbox,
    pub registry: ToolRegistry,
    pub dir: tempfile::TempDir,
    turn: u32,
}

impl Session {
    pub async fn start(scope: HttpScope, names: &[(&str, &str)], tools: &[&str]) -> Session {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let session = format!("test-{}-{}", std::process::id(), rand_suffix());
        let sid = session.clone();
        let spawn = Box::new(move || {
            let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_bee"));
            c.args(["proxy-worker", "--session", &sid]);
            Ok(c)
        });
        let icpt = Interceptor::start(
            InterceptorConfig {
                session_id: session,
                project_root: dir.path().to_path_buf(),
                http_scope: scope,
                enforcement: Enforcement::Advisory {
                    reason: "host test".into(),
                },
                resolver: resolver(names),
            },
            listener,
            spawn,
        )
        .await
        .expect("proxy starts");
        let mut sandbox = Sandbox::host(bee::sandbox::key_vars(None));
        ProxyCredentials::new(icpt.clone(), None).install(&mut sandbox);
        sandbox.set_http_scope_hook(bee::intercept::session::scope_hook(
            icpt.clone(),
            PathBuf::from("/bin/true"),
        ));
        // The Interceptor is running before any tool is named, so every tool is built holding it
        // (024 FR-013).
        let deps = bee::tools::ToolDeps::default().with_interceptor(icpt.clone());
        let mut registry = bee::tools::ToolRegistry::with_deps(std::sync::Arc::new(deps));
        for name in tools {
            registry.register(name).expect("a known tool");
        }
        Session {
            icpt,
            sandbox,
            registry,
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
        self.sandbox
            .begin_call(CallContext {
                call_id: id.clone(),
                turn: self.turn,
                origin: CallOrigin::Tool,
            })
            .await;
        let r = self
            .registry
            .execute(
                &ToolCall {
                    id: id.clone(),
                    name: tool.into(),
                    arguments: args,
                },
                &self.sandbox,
            )
            .await;
        let events = self.sandbox.end_call().await;
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
