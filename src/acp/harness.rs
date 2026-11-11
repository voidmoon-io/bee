//! **Outward** (026 US3): bee as the ACP *client* of an external harness — Claude Code, Codex,
//! OpenCode — run as a subagent inside a kernel scope of its own (contracts/harness-runtime.md).
//!
//! The harness is spawned through the child [`Sandbox`] exactly as a tool child is: it joins the
//! child scope before `exec`, gets the scope's cleared environment plus its agent's `env`, and —
//! with a proxy scope attached — a proxy credential of its own (a side call, attributed
//! `harness:<agent>`). bee then speaks ACP v1 to it over its stdin/stdout:
//!
//! - `initialize` advertising **no** client file-system or terminal methods: those would run in bee,
//!   outside the scope. Any the harness calls anyway is refused and recorded.
//! - `session/new` in the session's working directory with no MCP servers.
//! - one `session/prompt` with the task.
//!
//! Its permission requests are answered by bee, never a person (research R11): the first
//! `allow_once`, else the first `allow_always`, else `cancelled`. The kernel scope is the boundary,
//! not the harness's own prompts. Each answer is recorded.
//!
//! The protocol crate runs every handler on one dispatch loop (research R1), so the handlers here
//! only record and answer; the requests bee sends are awaited in the connection's body.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::v1::schema::{
    CancelNotification, ClientCapabilities, ContentBlock, FileSystemCapabilities, Implementation,
    InitializeRequest, NewSessionRequest, PermissionOptionKind, PromptRequest,
    RequestPermissionOutcome, RequestPermissionRequest, RequestPermissionResponse,
    SelectedPermissionOutcome, SessionNotification, SessionUpdate, StopReason, TextContent,
};
use agent_client_protocol::v1::{ConnectionTo, Dispatch};
use agent_client_protocol::{Agent, ByteStreams, Client, Error as AcpError, UntypedMessage};
use bee_core::AuditEvent;
use tokio::io::AsyncReadExt;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::sandbox::{CallContext, CallOrigin, Sandbox};
use crate::transcript::{HarnessRecord, HarnessToolCall, HarnessTurn, PermissionRecord};

/// How long a harness has to answer `session/cancel` before its scope is torn down (research R14).
pub const CANCEL_GRACE: Duration = Duration::from_secs(5);
/// How much of a harness's stderr is kept for its record.
const STDERR_TAIL: usize = 4096;
/// Cap on each recorded raw tool input or output.
const RAW_CAP: usize = 2048;

/// What to run, and for how long.
pub struct HarnessSpec<'a> {
    pub agent: &'a str,
    pub command: &'a std::path::Path,
    pub args: &'a [String],
    /// Added to the scope's cleared environment: the agent's `env`, then the operator's
    /// pass-through keys valued from bee's environment. Keys only reach the record.
    pub env: Vec<(String, String)>,
    pub prompt: &'a str,
    /// The shared deadline (018 FR-023).
    pub deadline: Instant,
    /// Where progress lines go, prefixed by the caller.
    pub progress: Option<Progress>,
}

/// Where a harness's progress lines go.
pub type Progress = Arc<dyn Fn(&str) + Send + Sync>;

/// How a harness run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessEnd {
    /// The prompt answered with this stop reason.
    Stopped(String),
    /// The deadline came first; bee cancelled and then cut it short.
    Deadline,
    /// It exited, broke the protocol, or could not start.
    Failed(String),
}

/// What a harness run left behind.
pub struct HarnessRun {
    pub record: HarnessRecord,
    pub end: HarnessEnd,
    /// The child scope's kernel events.
    pub audit: Vec<AuditEvent>,
    /// The harness's proxy events (refusals, rule hits), when it has a proxy.
    pub proxy_events: Vec<crate::proxy_event::ProxyEvent>,
}

impl HarnessRun {
    /// The text of its final turn: what the delegating model is told.
    pub fn report(&self) -> String {
        self.record
            .turns
            .last()
            .map(|t| t.text.trim().to_string())
            .unwrap_or_default()
    }
}

/// The record, shared with the handlers on the dispatch loop.
#[derive(Default)]
struct Seen {
    record: HarnessRecord,
    /// Set once bee has sent `session/cancel`: a permission asked after it is answered `cancelled`.
    cancelling: bool,
}

type Shared = Arc<Mutex<Seen>>;

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, Seen> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

fn capped(v: &serde_json::Value) -> String {
    let (s, _, _) = crate::transcript::truncate(v.to_string(), RAW_CAP);
    s
}

fn debug_name<T: std::fmt::Debug>(v: &T) -> String {
    let s = format!("{v:?}");
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Fold one `session/update` into the current turn.
fn record_update(seen: &Shared, update: SessionUpdate, progress: &Option<Progress>) {
    let mut s = lock(seen);
    if s.record.turns.is_empty() {
        s.record.turns.push(HarnessTurn::default());
    }
    let turn = s.record.turns.last_mut().expect("pushed above");
    match update {
        SessionUpdate::AgentMessageChunk(c) => {
            if let ContentBlock::Text(t) = c.content {
                turn.text.push_str(&t.text);
            }
        }
        SessionUpdate::AgentThoughtChunk(c) => {
            if let ContentBlock::Text(t) = c.content {
                turn.thoughts_len += t.text.len();
            }
        }
        SessionUpdate::ToolCall(tc) => {
            let line = format!("tool: {}", crate::safe_text::safe_line(&tc.title));
            turn.tool_calls.push(HarnessToolCall {
                id: tc.tool_call_id.to_string(),
                title: tc.title,
                kind: debug_name(&tc.kind),
                status: debug_name(&tc.status),
                raw_input: tc.raw_input.as_ref().map(capped),
                raw_output: tc.raw_output.as_ref().map(capped),
            });
            drop(s);
            if let Some(p) = progress {
                p(&line);
            }
        }
        SessionUpdate::ToolCallUpdate(u) => {
            let id = u.tool_call_id.to_string();
            let f = u.fields;
            let pos = turn.tool_calls.iter().position(|c| c.id == id);
            let call = match pos {
                Some(i) => &mut turn.tool_calls[i],
                None => {
                    turn.tool_calls.push(HarnessToolCall {
                        id,
                        ..HarnessToolCall::default()
                    });
                    turn.tool_calls.last_mut().expect("pushed")
                }
            };
            if let Some(t) = f.title {
                call.title = t;
            }
            if let Some(k) = f.kind {
                call.kind = debug_name(&k);
            }
            if let Some(st) = f.status {
                call.status = debug_name(&st);
            }
            if let Some(v) = f.raw_input {
                call.raw_input = Some(capped(&v));
            }
            if let Some(v) = f.raw_output {
                call.raw_output = Some(capped(&v));
            }
        }
        _ => {}
    }
}

/// Research R11: allow once ≫ allow always ≫ cancelled. Recorded.
fn answer_permission(seen: &Shared, req: &RequestPermissionRequest) -> RequestPermissionOutcome {
    let mut s = lock(seen);
    let offered: Vec<String> = req
        .options
        .iter()
        .map(|o| format!("{}:{}", debug_name(&o.kind), o.option_id))
        .collect();
    let pick = if s.cancelling {
        None
    } else {
        [
            PermissionOptionKind::AllowOnce,
            PermissionOptionKind::AllowAlways,
        ]
        .iter()
        .find_map(|k| req.options.iter().find(|o| o.kind == *k))
    };
    let (outcome, chosen) = match pick {
        Some(o) => (
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(o.option_id.clone())),
            format!("{}:{}", debug_name(&o.kind), o.option_id),
        ),
        None => (RequestPermissionOutcome::Cancelled, "cancelled".to_string()),
    };
    s.record.permissions.push(PermissionRecord {
        tool_call: req.tool_call.tool_call_id.to_string(),
        title: req.tool_call.fields.title.clone().unwrap_or_default(),
        offered,
        chosen,
        ts: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });
    outcome
}

/// Keep the last [`STDERR_TAIL`] bytes of `r`.
async fn tail(mut r: tokio::process::ChildStderr, into: Arc<Mutex<VecDeque<u8>>>) {
    let mut buf = [0u8; 1024];
    while let Ok(n) = r.read(&mut buf).await {
        if n == 0 {
            break;
        }
        let mut q = into.lock().unwrap_or_else(|e| e.into_inner());
        q.extend(&buf[..n]);
        while q.len() > STDERR_TAIL {
            q.pop_front();
        }
    }
}

/// Run one harness to its end. The sandbox must be the harness's own child scope; the caller tears
/// it down afterwards (and with it anything the harness left behind).
pub async fn run(sandbox: &mut Sandbox, spec: HarnessSpec<'_>) -> HarnessRun {
    let call = CallContext {
        call_id: format!("harness:{}", spec.agent),
        turn: 0,
        origin: CallOrigin::Harness(spec.agent.to_string()),
    };
    let seen: Shared = Arc::default();
    {
        let mut s = lock(&seen);
        s.record.command = spec.command.display().to_string();
        s.record.args = spec.args.to_vec();
        s.record.env_keys = spec.env.iter().map(|(k, _)| k.clone()).collect();
        s.record.protocol_version = super::PROTOCOL_VERSION;
    }
    // Its proxy credential, before it can start (a side call, like an MCP server's).
    sandbox.begin_side_call(&call).await;
    let stderr_tail: Arc<Mutex<VecDeque<u8>>> = Arc::default();
    let end = drive(sandbox, &spec, &call, &seen, &stderr_tail).await;
    let proxy_events = sandbox.end_side_call(&call).await;
    let audit = sandbox.drain_audit(None);
    let mut record = std::mem::take(&mut lock(&seen).record);
    record.stderr_tail = String::from_utf8_lossy(
        &stderr_tail
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect::<Vec<u8>>(),
    )
    .into_owned();
    record.stop_reason = match &end {
        HarnessEnd::Stopped(r) => r.clone(),
        HarnessEnd::Deadline => "deadline".into(),
        HarnessEnd::Failed(_) => {
            if record.stop_reason.is_empty() {
                "failed".into()
            } else {
                record.stop_reason
            }
        }
    };
    HarnessRun {
        record,
        end,
        audit,
        proxy_events,
    }
}

async fn drive(
    sandbox: &Sandbox,
    spec: &HarnessSpec<'_>,
    call: &CallContext,
    seen: &Shared,
    stderr_tail: &Arc<Mutex<VecDeque<u8>>>,
) -> HarnessEnd {
    let program = spec.command.to_string_lossy().into_owned();
    let mut cmd = match sandbox.tool_command_as(call, &program, spec.args) {
        Ok(c) => c,
        Err(e) => return HarnessEnd::Failed(format!("could not start {program}: {e}")),
    };
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    let cwd: PathBuf = sandbox
        .cwd()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return HarnessEnd::Failed(format!("could not start {program}: {e}")),
    };
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return HarnessEnd::Failed("the harness's pipes were not set up".into());
    };
    let tail_task = tokio::spawn(tail(stderr, stderr_tail.clone()));

    let (s_update, s_perm, s_other) = (seen.clone(), seen.clone(), seen.clone());
    let progress = spec.progress.clone();
    let deadline = tokio::time::Instant::from_std(spec.deadline);
    let prompt = spec.prompt.to_string();
    let seen_body = seen.clone();
    let connection = Client
        .v1()
        .name("bee")
        .on_receive_notification(
            async move |n: SessionNotification, _cx| {
                record_update(&s_update, n.update, &progress);
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |req: RequestPermissionRequest, responder, _cx| {
                let outcome = answer_permission(&s_perm, &req);
                responder.respond(RequestPermissionResponse::new(outcome))
            },
            agent_client_protocol::on_receive_request!(),
        )
        // Everything else the harness asks of its client — `fs/*`, `terminal/*`, anything newer —
        // is refused: bee advertised none of it, and it would run outside the scope (R12).
        .on_receive_dispatch(
            async move |d: Dispatch<UntypedMessage, UntypedMessage>, _cx| match d {
                Dispatch::Request(req, responder) => {
                    lock(&s_other)
                        .record
                        .refused_methods
                        .push(req.method.clone());
                    responder.respond_with_error(AcpError::method_not_found())
                }
                Dispatch::Notification(_) => Ok(()),
                Dispatch::Response(result, router) => router.route_with_result(result),
            },
            agent_client_protocol::on_receive_dispatch!(),
        )
        .connect_with(
            ByteStreams::new(stdin.compat_write(), stdout.compat()),
            async move |cx: ConnectionTo<Agent>| {
                Ok(converse(cx, cwd, prompt, deadline, seen_body).await)
            },
        );
    // A harness that ignores `session/cancel` is not waited on past the grace period.
    let hard = deadline + CANCEL_GRACE + Duration::from_secs(1);
    let end = match tokio::time::timeout_at(hard, connection).await {
        Ok(Ok(end)) => end,
        Ok(Err(e)) => HarnessEnd::Failed(format!("the harness broke the protocol or exited: {e}")),
        Err(_) => HarnessEnd::Deadline,
    };
    // Its stdin is closed by now (the transport is gone). Give it a moment, then kill it; the
    // caller's scope teardown takes anything it left behind.
    let exited = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    let status = match exited {
        Ok(Ok(st)) => Some(st),
        _ => {
            let _ = child.kill().await;
            None
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), tail_task).await;
    match end {
        HarnessEnd::Failed(why) => HarnessEnd::Failed(match status {
            Some(st) if !st.success() => format!("{why} ({st})"),
            _ => why,
        }),
        other => other,
    }
}

/// The client side of one delegation: handshake, one prompt, and the deadline.
async fn converse(
    cx: ConnectionTo<Agent>,
    cwd: PathBuf,
    prompt: String,
    deadline: tokio::time::Instant,
    seen: Shared,
) -> HarnessEnd {
    let init = InitializeRequest::new(ProtocolVersion::V1)
        .client_capabilities(
            ClientCapabilities::new()
                .fs(FileSystemCapabilities::new()
                    .read_text_file(false)
                    .write_text_file(false))
                .terminal(false),
        )
        .client_info(Implementation::new("bee", env!("CARGO_PKG_VERSION")));
    let init = match cx.send_request(init).block_task().await {
        Ok(r) => r,
        Err(e) => return HarnessEnd::Failed(format!("initialize: {e}")),
    };
    if init.protocol_version != ProtocolVersion::V1 {
        return HarnessEnd::Failed(format!(
            "the harness speaks ACP {:?}; bee speaks only version 1",
            init.protocol_version
        ));
    }
    if let Some(info) = &init.agent_info {
        lock(&seen).record.agent_info = Some(format!("{} {}", info.name, info.version));
    }
    let session = match cx
        .send_request(NewSessionRequest::new(cwd))
        .block_task()
        .await
    {
        Ok(r) => r.session_id,
        Err(e) => return HarnessEnd::Failed(format!("session/new: {e}")),
    };
    lock(&seen).record.turns.push(HarnessTurn::default());
    let mut pending = Box::pin(
        cx.send_request(PromptRequest::new(
            session.clone(),
            vec![ContentBlock::Text(TextContent::new(prompt))],
        ))
        .block_task(),
    );
    tokio::select! {
        r = &mut pending => match r {
            Ok(resp) => HarnessEnd::Stopped(stop_name(&resp.stop_reason)),
            Err(e) => HarnessEnd::Failed(format!("session/prompt: {e}")),
        },
        () = tokio::time::sleep_until(deadline) => {
            lock(&seen).cancelling = true;
            let _ = cx.send_notification(CancelNotification::new(session));
            // The protocol answers a cancelled prompt with `cancelled`; give it the grace period.
            let _ = tokio::time::timeout(CANCEL_GRACE, &mut pending).await;
            HarnessEnd::Deadline
        }
    }
}

fn stop_name(r: &StopReason) -> String {
    debug_name(r)
}
