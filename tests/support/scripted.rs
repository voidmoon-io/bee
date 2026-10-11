//! Scripted inputs for host orchestration tests (024-session-core, research R1): every input a tool
//! call reads, with no model, provider or kernel.
//!
//! * kernel audit — [`bee::sandbox::ScriptedAudit`] (the `test-support` feature), fed by a
//!   [`ScriptedTool`] as each attempt completes;
//! * proxy events — [`FakeCallHooks`], through the existing `CallHooks` seam;
//! * Target-scope widening — [`FakeHttpScope`], through the existing `HttpScopeHook` seam;
//! * consent — [`RecordingConsent`].
//!
//! Included with `#[path = "support/scripted.rs"] mod scripted;`, like `harness.rs`.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bee::provider::ToolSchema;
use bee::proxy_event::{ProxyEvent, ProxyEventKind};
use bee::sandbox::{CallContext, CallHooks, HttpScopeHook, Sandbox, ScriptedAudit};
use bee::skills::{ConsentSink, Decision, GrantRequest};
use bee::tools::{Tool, ToolResult};
use bee_core::AuditEvent;
use futures_util::future::BoxFuture;

/// The name every [`ScriptedTool`] registers under.
pub const SCRIPTED: &str = "scripted";

/// A kernel audit event. `scope_id` is `Some("proxy")` for a proxy-scope event, `None` for the tool
/// scope's.
pub fn ev(op: &str, target: &str, decision: &str, scope_id: Option<&str>) -> AuditEvent {
    AuditEvent {
        ts: "1970-01-01T00:00:00Z".into(),
        scope_id: scope_id.map(str::to_string),
        cgroup_id: 0,
        pid: None,
        tgid: None,
        op: op.into(),
        decision: decision.into(),
        errno: if decision == "denied" { 13 } else { 0 },
        target: target.into(),
    }
}

/// A proxy-layer refusal for `host:port`.
pub fn refusal(call_id: &str, host: &str, port: u16) -> ProxyEvent {
    ProxyEvent {
        ts: "1970-01-01T00:00:00Z".into(),
        session_id: "s".into(),
        call_id: Some(call_id.into()),
        layer: "proxy".into(),
        kind: ProxyEventKind::RefusedOutOfScope,
        host: host.into(),
        port,
        detail: serde_json::Value::Null,
    }
}

/// One attempt of a [`ScriptedTool`] call.
#[derive(Clone)]
pub struct Attempt {
    pub result: ToolResult,
    /// How long the attempt takes; with a paused clock, longer than the timeout makes it time out.
    pub delay: Option<Duration>,
    /// Tool-scope audit batches this attempt produces, queued when it **completes** — one per
    /// drain, so `vec![vec![], vec![late]]` delivers `late` on the drain after the call's first one.
    /// An attempt that times out is dropped before it completes and produces nothing.
    pub audit: Vec<Vec<AuditEvent>>,
}

impl Attempt {
    pub fn ok(content: &str) -> Self {
        Attempt {
            result: ToolResult::ok(content),
            delay: None,
            audit: vec![Vec::new()],
        }
    }

    pub fn error(content: &str) -> Self {
        Attempt {
            result: ToolResult::error(content),
            ..Attempt::ok("")
        }
    }

    /// This attempt's first drain returns `events`.
    pub fn with_audit(mut self, events: Vec<AuditEvent>) -> Self {
        self.audit = vec![events];
        self
    }

    /// Every drain batch this attempt produces, in order.
    pub fn with_batches(mut self, batches: Vec<Vec<AuditEvent>>) -> Self {
        self.audit = batches;
        self
    }

    pub fn taking(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// A tool whose attempts are scripted. Each `call` pops the next [`Attempt`]; once the script runs
/// out it returns `ok("unscripted")`. `calls()` counts every attempt started, timed out or not.
pub struct ScriptedTool {
    attempts: Mutex<VecDeque<Attempt>>,
    audit: Arc<ScriptedAudit>,
    calls: Arc<AtomicU32>,
}

impl ScriptedTool {
    pub fn new(audit: Arc<ScriptedAudit>, attempts: Vec<Attempt>) -> Self {
        ScriptedTool {
            attempts: Mutex::new(attempts.into()),
            audit,
            calls: Arc::new(AtomicU32::new(0)),
        }
    }

    /// A handle on the attempt counter that outlives the tool's move into a registry.
    pub fn counter(&self) -> Arc<AtomicU32> {
        self.calls.clone()
    }
}

#[async_trait::async_trait]
impl Tool for ScriptedTool {
    fn name(&self) -> &'static str {
        SCRIPTED
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: SCRIPTED.into(),
            description: "a scripted test tool".into(),
            parameters: serde_json::json!({ "type": "object" }),
        }
    }

    async fn call(&self, _arguments: serde_json::Value, _sandbox: &Sandbox) -> ToolResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let attempt = self
            .attempts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Attempt::ok("unscripted"));
        if let Some(d) = attempt.delay {
            tokio::time::sleep(d).await;
        }
        for batch in attempt.audit {
            self.audit.push_tool(batch);
        }
        attempt.result
    }
}

/// `CallHooks` returning scripted proxy events: each `take_events` for a call id pops that id's next
/// batch. Records every `begin`/`end`, as `"begin:<id>"` / `"end:<id>"`. `notes` are handed out once,
/// at the top of the next turn.
#[derive(Default)]
pub struct FakeCallHooks {
    events: Mutex<HashMap<String, VecDeque<Vec<ProxyEvent>>>>,
    pub log: Mutex<Vec<String>>,
    pub notes: Mutex<Vec<String>>,
}

impl FakeCallHooks {
    /// Queue the batch the next `end_call` for `call_id` returns.
    pub fn push(&self, call_id: &str, batch: Vec<ProxyEvent>) {
        self.events
            .lock()
            .unwrap()
            .entry(call_id.into())
            .or_default()
            .push_back(batch);
    }
}

impl CallHooks for FakeCallHooks {
    fn begin<'a>(&'a self, call: &'a CallContext) -> BoxFuture<'a, ()> {
        self.log
            .lock()
            .unwrap()
            .push(format!("begin:{}", call.call_id));
        Box::pin(async {})
    }

    fn end<'a>(&'a self, call: &'a CallContext) -> BoxFuture<'a, ()> {
        self.log
            .lock()
            .unwrap()
            .push(format!("end:{}", call.call_id));
        Box::pin(async {})
    }

    fn take_events(&self, call: &CallContext) -> Vec<ProxyEvent> {
        self.events
            .lock()
            .unwrap()
            .get_mut(&call.call_id)
            .and_then(VecDeque::pop_front)
            .unwrap_or_default()
    }

    fn turn_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.lock().unwrap())
    }
}

/// `HttpScopeHook` that accepts every widening and records the target list it was asked to apply.
#[derive(Default)]
pub struct FakeHttpScope {
    pub updates: Mutex<Vec<Vec<String>>>,
}

impl HttpScopeHook for FakeHttpScope {
    fn compile(
        &self,
        policy: &bee_core::Policy,
    ) -> Result<(bee_core::CompiledPolicy, bee_core::compiler::HttpScope), String> {
        let targets = policy
            .http
            .as_ref()
            .map(|h| h.targets.iter().map(|t| t.to_string()).collect())
            .unwrap_or_default();
        self.updates.lock().unwrap().push(targets);
        Ok((
            bee_core::CompiledPolicy::default(),
            bee_core::compiler::HttpScope {
                targets: Vec::new(),
                egress: Vec::new(),
                inspect: Vec::new(),
                insecure_upstream: Vec::new(),
                limits: Default::default(),
            },
        ))
    }

    fn update<'a>(
        &'a self,
        _scope: bee_core::compiler::HttpScope,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

/// What a [`RecordingConsent`] was asked: the requester and every capability kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub skill: String,
    pub tools: Vec<String>,
    pub filesystem: Vec<(String, String)>,
    pub net: Vec<String>,
    pub exec: Vec<String>,
    pub http_targets: Vec<String>,
}

/// A consent sink with a scripted answer and a log of every request.
pub struct RecordingConsent {
    pub answer: bool,
    pub log: Mutex<Vec<Asked>>,
}

impl RecordingConsent {
    pub fn new(answer: bool) -> Arc<Self> {
        Arc::new(RecordingConsent {
            answer,
            log: Mutex::new(Vec::new()),
        })
    }

    pub fn asked(&self) -> Vec<Asked> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ConsentSink for RecordingConsent {
    async fn confirm(&self, r: &GrantRequest<'_>) -> Decision {
        self.log.lock().unwrap().push(Asked {
            skill: r.skill.to_string(),
            tools: r.tools.to_vec(),
            filesystem: r
                .filesystem
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            net: r.net.to_vec(),
            exec: r.exec.to_vec(),
            http_targets: r.http_targets.to_vec(),
        });
        if self.answer {
            Decision::Granted
        } else {
            Decision::Denied
        }
    }
}
