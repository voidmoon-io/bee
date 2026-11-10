//! `bee acp`: bee as an ACP agent (026 contracts/acp-agent.md).
//!
//! The protocol crate runs every handler on one dispatch loop, and a handler that waits for a reply
//! to its own request deadlocks it (research R1). So the handlers here only forward each message to
//! [`serve`]'s loop and return. The loop and the tasks it starts do the work — building a session,
//! running an exchange, asking the client for consent — on bee's tokio runtime, sending updates and
//! requests on a clone of the connection.
//!
//! One prompt runs at a time per session, as its own task. `session/cancel` aborts that task:
//! dropping the exchange kills the tool processes it started (`tools/exec.rs`, `ChildOwner`) and any
//! subagent scope it opened, and the conversation is put back as it was before the prompt.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agent_client_protocol::v1::schema::{
    AgentCapabilities, CancelNotification, ContentBlock, EmbeddedResourceResource, Implementation,
    InitializeRequest, InitializeResponse, McpCapabilities, McpServer, NewSessionRequest,
    NewSessionResponse, PermissionOption, PermissionOptionKind, PromptCapabilities, PromptRequest,
    PromptResponse, RequestPermissionOutcome, RequestPermissionRequest, StopReason, TextContent,
    ToolCallContent, ToolCallUpdate, ToolCallUpdateFields, ToolKind,
};
use agent_client_protocol::v1::ConnectionTo;
use agent_client_protocol::{Agent, ByteStreams, Client, Error as AcpError};
use tokio::sync::mpsc;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use super::output::{agent_text, AcpOutput, ConnectionSink, UpdateSink};
use super::{ClientMcpServer, OpenSession, OpenedSession, SessionFactory};
use crate::operator::{ChannelConsent, ConsentReceiver, Decision, NullOutput, Operator};
use crate::provider::Conversation;
use crate::repl::{ExchangeOutcome, SteeringQueue};

/// A response, sent whenever the work behind it ends.
type Reply<T> = Box<dyn FnOnce(Result<T, AcpError>) + Send>;

enum Msg {
    New(NewSessionRequest, Reply<NewSessionResponse>),
    Opened {
        id: String,
        opened: Result<Box<OpenedSession>, String>,
        reply: Reply<NewSessionResponse>,
    },
    Prompt(PromptRequest, Reply<PromptResponse>),
    Cancel(CancelNotification),
}

/// One session between prompts: what an exchange borrows.
struct Live {
    opened: OpenedSession,
    conversation: Conversation,
    steering: SteeringQueue,
    /// The conversation's length when the running prompt began, so a cancel can put it back.
    turn_start: usize,
}

struct Slot {
    live: Arc<tokio::sync::Mutex<Live>>,
    running: Mutex<Option<tokio::task::AbortHandle>>,
}

/// Serve ACP on `input`/`output` until the client closes it, then shut every session down. A session
/// whose scope will not empty is returned as an error, never swallowed.
pub async fn serve<R, W>(
    input: R,
    output: W,
    factory: Arc<dyn SessionFactory>,
    max_sessions: usize,
) -> Result<(), String>
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
    W: tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel::<Msg>();
    let (t_new, t_prompt, t_cancel, t_loop) = (tx.clone(), tx.clone(), tx.clone(), tx);
    let transport = ByteStreams::new(output.compat_write(), input.compat());
    Agent
        .v1()
        .name("bee")
        .on_receive_request(
            async move |req: InitializeRequest, responder, _cx| {
                responder.respond(initialize_response(&req))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |req: NewSessionRequest, responder, _cx| {
                let reply: Reply<NewSessionResponse> = Box::new(move |r| {
                    let _ = responder.respond_with_result(r);
                });
                let _ = t_new.send(Msg::New(req, reply));
                Ok(())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |req: PromptRequest, responder, _cx| {
                let reply: Reply<PromptResponse> = Box::new(move |r| {
                    let _ = responder.respond_with_result(r);
                });
                let _ = t_prompt.send(Msg::Prompt(req, reply));
                Ok(())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_notification(
            async move |n: CancelNotification, _cx| {
                let _ = t_cancel.send(Msg::Cancel(n));
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .connect_with(transport, async move |cx: ConnectionTo<Client>| {
            Ok(run(cx, rx, t_loop, factory, max_sessions).await)
        })
        .await
        .map_err(|e| format!("acp connection: {e}"))?
}

/// The advertised capabilities (contracts/acp-agent.md, "initialize"). bee speaks only version 1,
/// whatever the client asked for, and offers no sign-in: its model comes from its own configuration.
pub fn initialize_response(_req: &InitializeRequest) -> InitializeResponse {
    InitializeResponse::new(agent_client_protocol::schema::ProtocolVersion::V1)
        .agent_capabilities(
            AgentCapabilities::new()
                .load_session(false)
                .prompt_capabilities(
                    PromptCapabilities::new()
                        .image(false)
                        .audio(false)
                        .embedded_context(true),
                )
                .mcp_capabilities(McpCapabilities::new().http(false).sse(false)),
        )
        .agent_info(Implementation::new("bee", env!("CARGO_PKG_VERSION")))
}

async fn run(
    cx: ConnectionTo<Client>,
    mut rx: mpsc::UnboundedReceiver<Msg>,
    tx: mpsc::UnboundedSender<Msg>,
    factory: Arc<dyn SessionFactory>,
    max_sessions: usize,
) -> Result<(), String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut sessions: HashMap<String, Arc<Slot>> = HashMap::new();
    let mut opening = 0usize;
    loop {
        let msg = tokio::select! {
            m = rx.recv() => match m { Some(m) => m, None => break },
            _ = cx.incoming_closed() => break,
        };
        match msg {
            Msg::New(req, reply) => {
                if sessions.len() + opening >= max_sessions {
                    reply(Err(AcpError::internal_error().data(format!(
                        "this bee serves at most {max_sessions} sessions at once ([acp] max_sessions)"
                    ))));
                    continue;
                }
                if let Err(why) = check_cwd(&req.cwd) {
                    reply(Err(AcpError::invalid_params().data(why)));
                    continue;
                }
                let (client_mcp, mut notices) = client_mcp(&req.mcp_servers);
                let id = format!(
                    "acp-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                );
                let (consent, consent_rx) = ChannelConsent::new();
                tokio::spawn(answer_consent(cx.clone(), id.clone(), consent_rx));
                let operator = Operator::interactive(consent, Arc::new(NullOutput));
                let request = OpenSession {
                    id: id.clone(),
                    cwd: req.cwd.clone(),
                    operator,
                    client_mcp,
                };
                opening += 1;
                let (factory, tx) = (factory.clone(), tx.clone());
                tokio::spawn(async move {
                    let opened = factory.open(request).await.map(|mut o| {
                        o.notices.append(&mut notices);
                        Box::new(o)
                    });
                    let _ = tx.send(Msg::Opened { id, opened, reply });
                });
            }
            Msg::Opened { id, opened, reply } => {
                opening -= 1;
                match opened {
                    Err(why) => reply(Err(AcpError::internal_error().data(why))),
                    Ok(mut opened) => {
                        let notices = std::mem::take(&mut opened.notices);
                        let conversation = Conversation {
                            system: crate::repl::effective_system_prompt(
                                &opened.config.system_prompt,
                                &opened.session.registry,
                            ),
                            messages: Vec::new(),
                        };
                        let live = Live {
                            opened: *opened,
                            conversation,
                            steering: Default::default(),
                            turn_start: 0,
                        };
                        sessions.insert(
                            id.clone(),
                            Arc::new(Slot {
                                live: Arc::new(tokio::sync::Mutex::new(live)),
                                running: Mutex::new(None),
                            }),
                        );
                        reply(Ok(NewSessionResponse::new(id.clone())));
                        let sink = ConnectionSink {
                            cx: cx.clone(),
                            session_id: id,
                        };
                        for n in notices {
                            sink.send(agent_text(&format!("bee: {n}\n")));
                        }
                    }
                }
            }
            Msg::Prompt(req, reply) => {
                let id = req.session_id.to_string();
                let Some(slot) = sessions.get(&id).cloned() else {
                    reply(Err(
                        AcpError::invalid_params().data(format!("unknown session {id}"))
                    ));
                    continue;
                };
                let text = match prompt_text(&req.prompt) {
                    Ok(t) => t,
                    Err(why) => {
                        reply(Err(AcpError::invalid_params().data(why)));
                        continue;
                    }
                };
                prompt(&slot, cx.clone(), id, text, reply);
            }
            Msg::Cancel(n) => {
                if let Some(slot) = sessions.get(&n.session_id.to_string()) {
                    if let Some(h) = slot.running.lock().expect("running").take() {
                        h.abort();
                    }
                }
            }
        }
    }
    shutdown(sessions).await
}

/// Start `text` as the session's prompt, unless one is already running.
fn prompt(
    slot: &Arc<Slot>,
    cx: ConnectionTo<Client>,
    id: String,
    text: String,
    reply: Reply<PromptResponse>,
) {
    let mut running = slot.running.lock().expect("running");
    if running.is_some() {
        reply(Err(
            AcpError::invalid_params().data("a prompt is already running in this session")
        ));
        return;
    }
    let live = slot.live.clone();
    let exchange = tokio::spawn(async move {
        let mut guard = live.lock_owned().await;
        let Live {
            opened,
            conversation,
            steering,
            turn_start,
        } = &mut *guard;
        *turn_start = conversation.messages.len();
        let output = AcpOutput::new(ConnectionSink { cx, session_id: id });
        let OpenedSession {
            session,
            model,
            config,
            ..
        } = opened;
        crate::repl::run_exchange(
            &text,
            model.as_ref(),
            conversation,
            &mut session.registry,
            &mut session.sandbox,
            config,
            &output,
            steering,
            None,
        )
        .await
    });
    *running = Some(exchange.abort_handle());
    drop(running);
    let slot = slot.clone();
    tokio::spawn(async move {
        let result = exchange.await;
        slot.running.lock().expect("running").take();
        match result {
            Ok(r) => reply(Ok(PromptResponse::new(stop_reason(&r.outcome)))),
            Err(e) if e.is_cancelled() => {
                // The exchange is gone; the conversation goes back to before the prompt, so no
                // half-finished call reaches the next request.
                let mut live = slot.live.lock().await;
                let start = live.turn_start;
                live.conversation.messages.truncate(start);
                reply(Ok(PromptResponse::new(StopReason::Cancelled)));
            }
            Err(e) => reply(Err(
                AcpError::internal_error().data(format!("prompt failed: {e}"))
            )),
        }
    });
}

/// How an exchange ended, as a stop reason (contracts/acp-agent.md). Errors end the turn normally:
/// the exchange has already said what went wrong through the session's output.
pub fn stop_reason(outcome: &ExchangeOutcome) -> StopReason {
    match outcome {
        ExchangeOutcome::BudgetExhausted => StopReason::MaxTurnRequests,
        ExchangeOutcome::ContextExhausted(_) => StopReason::MaxTokens,
        _ => StopReason::EndTurn,
    }
}

/// The user message a prompt carries: its text, embedded text resources, and resource links as
/// their URIs. Images and audio were not advertised, and are refused.
pub fn prompt_text(blocks: &[ContentBlock]) -> Result<String, String> {
    let mut parts = Vec::new();
    for b in blocks {
        match b {
            ContentBlock::Text(t) => parts.push(t.text.clone()),
            ContentBlock::Resource(r) => match &r.resource {
                EmbeddedResourceResource::TextResourceContents(t) => parts.push(format!(
                    "<resource uri=\"{}\" source=\"client\">\n{}\n</resource>",
                    t.uri, t.text
                )),
                _ => return Err("binary resources are not supported".into()),
            },
            ContentBlock::ResourceLink(l) => parts.push(l.uri.clone()),
            _ => return Err("only text prompts are supported (no image or audio)".into()),
        }
    }
    if parts.is_empty() {
        return Err("empty prompt".into());
    }
    Ok(parts.join("\n\n"))
}

/// The client's working directory must be absolute and an existing directory (026 R4). Whether the
/// session's policy may read it is checked once the policy is known.
pub fn check_cwd(cwd: &Path) -> Result<(), String> {
    if !cwd.is_absolute() {
        return Err(format!("cwd must be absolute: {}", cwd.display()));
    }
    match std::fs::metadata(cwd) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(format!("cwd is not a directory: {}", cwd.display())),
        Err(e) => Err(format!("cwd {}: {e}", cwd.display())),
    }
}

/// The client's MCP servers a session may be asked to start: stdio ones, passed on for the operator's
/// configuration to decide. HTTP and SSE servers would be reached from bee itself, outside the
/// scope, and are dropped here with a notice (026 R7).
pub fn client_mcp(servers: &[McpServer]) -> (Vec<ClientMcpServer>, Vec<String>) {
    let mut keep = Vec::new();
    let mut notices = Vec::new();
    for s in servers {
        match s {
            McpServer::Stdio(s) => keep.push(ClientMcpServer {
                name: s.name.clone(),
                command: s.command.clone(),
                args: s.args.clone(),
                env: s
                    .env
                    .iter()
                    .map(|e| (e.name.clone(), e.value.clone()))
                    .collect(),
            }),
            McpServer::Http(h) => notices.push(format!(
                "MCP server '{}' not started: bee starts only stdio servers, inside the session's scope",
                h.name
            )),
            McpServer::Sse(h) => notices.push(format!(
                "MCP server '{}' not started: bee starts only stdio servers, inside the session's scope",
                h.name
            )),
            _ => notices.push("an MCP server of an unknown kind was not started".into()),
        }
    }
    (keep, notices)
}

/// Put each of a session's consent questions to the client (026 R5). Only an explicit "allow" grants;
/// a rejection, a cancelled request, an error or a closed connection refuses. The operator's timeout
/// still applies: an unanswered question is refused there, whatever the client does later.
async fn answer_consent(cx: ConnectionTo<Client>, session_id: String, mut rx: ConsentReceiver) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    while let Some(ask) = rx.recv().await {
        let lines = ask.request.render_lines();
        let title = lines.first().cloned().unwrap_or_default();
        let content: Vec<ToolCallContent> =
            vec![ContentBlock::Text(TextContent::new(lines.join("\n"))).into()];
        let call = ToolCallUpdate::new(
            format!("consent-{}", SEQ.fetch_add(1, Ordering::Relaxed)),
            ToolCallUpdateFields::new()
                .title(title)
                .kind(ToolKind::Other)
                .content(content),
        );
        let request = RequestPermissionRequest::new(
            session_id.clone(),
            call,
            vec![
                PermissionOption::new("allow", "Allow", PermissionOptionKind::AllowOnce),
                PermissionOption::new("reject", "Reject", PermissionOptionKind::RejectOnce),
            ],
        );
        let decision = match cx.send_request(request).block_task().await {
            Ok(r) => match r.outcome {
                RequestPermissionOutcome::Selected(s) if s.option_id.to_string() == "allow" => {
                    Decision::Granted
                }
                _ => Decision::Denied,
            },
            Err(_) => Decision::Denied,
        };
        let _ = ask.reply.send(decision);
    }
}

/// Shut every session down in its one order once the client has gone: running prompts are aborted
/// first, so their processes are gone before the scopes are.
async fn shutdown(sessions: HashMap<String, Arc<Slot>>) -> Result<(), String> {
    let mut failures = Vec::new();
    for slot in sessions.values() {
        if let Some(h) = slot.running.lock().expect("running").take() {
            h.abort();
        }
    }
    for (id, slot) in sessions {
        let mut live = slot.live.lock().await;
        // The config holds clones of the MCP refresh source; drop it first so shutdown releases the
        // servers (as `bee repl` does).
        live.opened.config = crate::repl::ReplConfig::default();
        if let Err(e) = live.opened.session.shutdown().await {
            failures.push(format!("{id}: {e}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "a session's scope did not tear down: {}",
            failures.join("; ")
        ))
    }
}
