//! `bee acp` driven by a scripted ACP client over in-memory pipes (026 US1, US2; quickstart S2).
//!
//! The server under test is the library's [`bee::acp::agent::serve`]; the sessions it builds come from
//! a test factory: a host session around a scripted model, with the scripted-audit host sandbox where
//! a test needs a kernel denial (`test-support`). Kernel enforcement itself is proven by the VM cases
//! `acp-*`; what is proven here is the protocol and the consent path.
#![cfg(feature = "acp")]

#[path = "support/fixtures.rs"]
mod fixtures;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::v1::schema::{
    CancelNotification, ContentBlock, CreateTerminalRequest, InitializeRequest, McpServer,
    McpServerHttp, McpServerStdio, NewSessionRequest, PromptRequest, ReadTextFileRequest,
    RequestPermissionOutcome, RequestPermissionRequest, RequestPermissionResponse,
    SelectedPermissionOutcome, SessionNotification, SessionUpdate, StopReason, TextContent,
    ToolCallStatus, WriteTextFileRequest,
};
use agent_client_protocol::v1::ConnectionTo;
use agent_client_protocol::{Agent, ByteStreams, Client, Error as AcpError};
use bee::acp::{OpenSession, OpenedSession, SessionFactory};
use bee::provider::mock_model::MockModel;
use bee::provider::{StopReason as ModelStop, ToolCall, Turn};
use bee::repl::{ReplConfig, ReplEscalation};
use bee_core::{Access, Policy};
use fixtures::policy;
use serde_json::json;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

// ── Fixtures ────────────────────────────────────────────────────────────────────────────────────

fn tool_turn(id: &str, name: &str, args: serde_json::Value) -> Turn {
    Turn {
        text: None,
        tool_calls: vec![ToolCall {
            id: id.into(),
            name: name.into(),
            arguments: args,
        }],
        stop: ModelStop::ToolUse,
        usage: None,
    }
}

fn text_turn(t: &str) -> Turn {
    Turn {
        text: Some(t.into()),
        tool_calls: Vec::new(),
        stop: ModelStop::EndTurn,
        usage: None,
    }
}

/// Builds host sessions around one scripted model per session, in the order sessions open.
#[derive(Default)]
struct TestFactory {
    scripts: Mutex<VecDeque<Vec<Turn>>>,
    policy: Option<Policy>,
    ceiling: Option<Policy>,
    /// What each session's client MCP servers were, as the factory saw them.
    client_mcp: Mutex<Vec<String>>,
    /// The operator of the last session opened: its log is the session's consent record.
    operator: Mutex<Option<bee::operator::Operator>>,
    #[cfg(feature = "test-support")]
    audit: Option<Arc<bee::sandbox::ScriptedAudit>>,
}

#[async_trait::async_trait]
impl SessionFactory for TestFactory {
    async fn open(&self, req: OpenSession) -> Result<OpenedSession, String> {
        let script = self.scripts.lock().unwrap().pop_front().unwrap_or_default();
        self.client_mcp
            .lock()
            .unwrap()
            .extend(req.client_mcp.iter().map(|s| s.name.clone()));
        *self.operator.lock().unwrap() = Some(req.operator.clone());
        #[cfg(feature = "test-support")]
        let prebuilt = self
            .audit
            .as_ref()
            .map(|a| bee::Sandbox::host_scripted(Vec::new(), a.clone()));
        #[cfg(not(feature = "test-support"))]
        let prebuilt = None;
        let spec = bee::session::SessionSpec {
            entry: bee::session::EntryPoint::Acp,
            label: req.id.clone(),
            policy: self.policy.clone(),
            ceiling: self.ceiling.clone(),
            enforcement: bee::session::Enforcement::Host,
            tools: vec!["write_file".into(), "bash".into()],
            ctf_flag: None,
            skill_roots: Vec::new(),
            mcp: Default::default(),
            security: Default::default(),
            workdir: req.cwd.clone(),
            system_prompt: "test".into(),
            strip_env: Vec::new(),
            http_scope_advisory: false,
            lease_turns: None,
            operator: req.operator,
            prebuilt_sandbox: prebuilt,
        };
        let mut session = bee::session::build(spec, &|_| {})
            .await
            .map_err(|e| e.to_string())?;
        if session.sandbox.cwd().is_none() {
            session.sandbox.set_cwd(Some(req.cwd.clone()));
        }
        let escalation = session
            .escalation
            .take()
            .map(ReplEscalation::new)
            .transpose()?;
        let config = ReplConfig {
            system_prompt: "test".into(),
            escalation,
            ..ReplConfig::default()
        };
        Ok(OpenedSession {
            session,
            model: Box::new(MockModel::scripted(script)),
            config,
            notices: vec!["test session ready".into()],
        })
    }
}

/// What the client saw.
#[derive(Default)]
struct Seen {
    updates: Mutex<Vec<SessionUpdate>>,
    permissions: Mutex<Vec<RequestPermissionRequest>>,
    /// Answers to give permission requests, in order; none left ⇒ `cancelled`.
    answers: Mutex<VecDeque<&'static str>>,
    client_methods_used: AtomicBool,
}

impl Seen {
    fn text(&self) -> String {
        self.updates
            .lock()
            .unwrap()
            .iter()
            .filter_map(|u| match u {
                SessionUpdate::AgentMessageChunk(c) => match &c.content {
                    ContentBlock::Text(t) => Some(t.text.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }
}

/// Start `serve` with `factory`, connect a scripted client, run `body`, and return what the client
/// saw. The client advertises file-system and terminal methods so a test can prove bee never uses
/// them.
async fn with_client<R>(
    factory: Arc<TestFactory>,
    seen: Arc<Seen>,
    body: impl AsyncFnOnce(ConnectionTo<Agent>) -> Result<R, AcpError>,
) -> R {
    let (client_end, server_end) = tokio::io::duplex(1 << 20);
    let (sr, sw) = tokio::io::split(server_end);
    let server = tokio::spawn(bee::acp::agent::serve(sr, sw, factory, 4));
    let (cr, cw) = tokio::io::split(client_end);
    let (s1, s2, s3, s4, s5) = (
        seen.clone(),
        seen.clone(),
        seen.clone(),
        seen.clone(),
        seen.clone(),
    );
    let out = Client
        .v1()
        .on_receive_notification(
            async move |n: SessionNotification, _cx| {
                s1.updates.lock().unwrap().push(n.update);
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |req: RequestPermissionRequest, responder, _cx| {
                s2.permissions.lock().unwrap().push(req);
                let outcome = match s2.answers.lock().unwrap().pop_front() {
                    Some(id) => {
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(id))
                    }
                    None => RequestPermissionOutcome::Cancelled,
                };
                responder.respond(RequestPermissionResponse::new(outcome))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_r: ReadTextFileRequest, responder, _cx| {
                s3.client_methods_used.store(true, Ordering::SeqCst);
                responder.respond_with_error(AcpError::method_not_found())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_r: WriteTextFileRequest, responder, _cx| {
                s4.client_methods_used.store(true, Ordering::SeqCst);
                responder.respond_with_error(AcpError::method_not_found())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_r: CreateTerminalRequest, responder, _cx| {
                s5.client_methods_used.store(true, Ordering::SeqCst);
                responder.respond_with_error(AcpError::method_not_found())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .connect_with(
            ByteStreams::new(cw.compat_write(), cr.compat()),
            async move |cx: ConnectionTo<Agent>| {
                cx.send_request(
                    InitializeRequest::new(ProtocolVersion::V1).client_capabilities(
                        agent_client_protocol::v1::schema::ClientCapabilities::new()
                            .fs(
                                agent_client_protocol::v1::schema::FileSystemCapabilities::new()
                                    .read_text_file(true)
                                    .write_text_file(true),
                            )
                            .terminal(true),
                    ),
                )
                .block_task()
                .await?;
                body(cx).await
            },
        )
        .await
        .expect("client connection");
    // The client is gone: the server shuts its sessions down and returns.
    let served = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server returns once the client closes")
        .expect("server task");
    assert!(served.is_ok(), "{served:?}");
    out
}

fn text(prompt: &str) -> Vec<ContentBlock> {
    vec![ContentBlock::Text(TextContent::new(prompt.to_string()))]
}

async fn new_session(cx: &ConnectionTo<Agent>, cwd: &Path) -> Result<String, AcpError> {
    let r = cx
        .send_request(NewSessionRequest::new(cwd.to_path_buf()))
        .block_task()
        .await?;
    Ok(r.session_id.to_string())
}

fn factory(scripts: Vec<Vec<Turn>>) -> TestFactory {
    TestFactory {
        scripts: Mutex::new(scripts.into()),
        ..TestFactory::default()
    }
}

// ── US1 ─────────────────────────────────────────────────────────────────────────────────────────

// T009: version 1, nothing bee cannot do, no sign-in.
#[tokio::test]
async fn initialize_advertises_v1_and_no_client_methods() {
    let r = bee::acp::agent::initialize_response(&InitializeRequest::new(ProtocolVersion::V1));
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["protocolVersion"], 1, "{v}");
    assert_eq!(v["agentCapabilities"]["loadSession"], false, "{v}");
    assert_eq!(
        v["agentCapabilities"]["mcpCapabilities"]["http"], false,
        "{v}"
    );
    assert_eq!(
        v["agentCapabilities"]["mcpCapabilities"]["sse"], false,
        "{v}"
    );
    assert_eq!(
        v["agentCapabilities"]["promptCapabilities"]["image"], false,
        "{v}"
    );
    assert!(
        v["authMethods"].as_array().is_none_or(|a| a.is_empty()),
        "{v}"
    );
    assert_eq!(v["agentInfo"]["name"], "bee", "{v}");
}

// T010 (S2, SC-002): the reply streams, the call is reported on its id, and bee never touches the
// client's file-system or terminal methods although the client offered them.
#[tokio::test]
async fn a_prompt_streams_and_reports_its_tool_call() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("notes.txt");
    let f = Arc::new(factory(vec![vec![
        tool_turn(
            "c1",
            "write_file",
            json!({"path": target, "content": "one line\n"}),
        ),
        text_turn("Wrote notes.txt."),
    ]]));
    let seen = Arc::new(Seen::default());
    let cwd = dir.path().to_path_buf();
    let stop = with_client(f, seen.clone(), async |cx| {
        let id = new_session(&cx, &cwd).await?;
        let r = cx
            .send_request(PromptRequest::new(id, text("write the notes")))
            .block_task()
            .await?;
        Ok(r.stop_reason)
    })
    .await;
    assert_eq!(stop, StopReason::EndTurn);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "one line\n");
    let updates = seen.updates.lock().unwrap();
    let call = updates
        .iter()
        .position(|u| matches!(u, SessionUpdate::ToolCall(_)))
        .expect("a tool_call");
    let done = updates
        .iter()
        .position(|u| {
            matches!(u, SessionUpdate::ToolCallUpdate(c) if c.fields.status == Some(ToolCallStatus::Completed))
        })
        .expect("a completed tool_call_update");
    assert!(call < done);
    drop(updates);
    assert!(seen.text().contains("Wrote notes.txt."), "{}", seen.text());
    assert!(
        seen.text().contains("bee: test session ready"),
        "{}",
        seen.text()
    );
    assert!(!seen.client_methods_used.load(Ordering::SeqCst));
}

// T011: a working directory bee cannot use refuses the session, naming why.
#[tokio::test]
async fn session_new_refuses_a_bad_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    std::fs::write(&file, "").unwrap();
    let f = Arc::new(factory(Vec::new()));
    let errors = with_client(f, Arc::new(Seen::default()), async |cx| {
        let mut errors = Vec::new();
        for cwd in [
            PathBuf::from("relative/dir"),
            dir.path().join("missing"),
            file.clone(),
        ] {
            let e = new_session(&cx, &cwd).await.expect_err("refused");
            errors.push(format!("{e}"));
        }
        Ok(errors)
    })
    .await;
    assert!(errors[0].contains("absolute"), "{errors:?}");
    assert!(errors[1].contains("missing"), "{errors:?}");
    assert!(errors[2].contains("not a directory"), "{errors:?}");
}

// T012: HTTP servers are dropped with a notice; stdio ones reach the operator's configuration.
#[tokio::test]
async fn client_http_mcp_servers_are_dropped_and_stdio_ones_passed_on() {
    let dir = tempfile::tempdir().unwrap();
    let f = Arc::new(factory(vec![Vec::new()]));
    let seen = Arc::new(Seen::default());
    let cwd = dir.path().to_path_buf();
    with_client(f.clone(), seen.clone(), async |cx| {
        cx.send_request(NewSessionRequest::new(cwd.clone()).mcp_servers(vec![
            McpServer::Stdio(McpServerStdio::new("t3", "/usr/bin/true")),
            McpServer::Http(McpServerHttp::new("remote", "https://example.test/mcp")),
        ]))
        .block_task()
        .await?;
        Ok(())
    })
    .await;
    assert_eq!(*f.client_mcp.lock().unwrap(), vec!["t3".to_string()]);
    assert!(
        seen.text().contains("MCP server 'remote' not started"),
        "{}",
        seen.text()
    );
}

// T013 (S6): a cancelled prompt ends `cancelled` promptly, and the session goes on.
#[tokio::test]
async fn cancel_ends_the_turn_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let f = Arc::new(factory(vec![vec![
        tool_turn("c1", "bash", json!({"command": "sleep 30"})),
        text_turn("never"),
        text_turn("still here"),
    ]]));
    let seen = Arc::new(Seen::default());
    let cwd = dir.path().to_path_buf();
    let (first, took, second) = with_client(f, seen.clone(), async |cx| {
        let id = new_session(&cx, &cwd).await?;
        let started = Instant::now();
        let running = cx
            .send_request(PromptRequest::new(id.clone(), text("sleep")))
            .block_task();
        let cancel = async {
            tokio::time::sleep(Duration::from_millis(800)).await;
            cx.send_notification(CancelNotification::new(id.clone()))
        };
        let (r, sent) = tokio::join!(running, cancel);
        sent?;
        let took = started.elapsed();
        let next = cx
            .send_request(PromptRequest::new(id, text("again")))
            .block_task()
            .await?;
        Ok((r?.stop_reason, took, next.stop_reason))
    })
    .await;
    assert_eq!(first, StopReason::Cancelled);
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert_eq!(second, StopReason::EndTurn);
}

// ── US2 ─────────────────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "test-support")]
mod consent {
    use super::*;
    use bee::operator::{Reason, Verdict};

    fn denial(target: &Path) -> bee_core::AuditEvent {
        bee_core::AuditEvent {
            ts: "t".into(),
            scope_id: None,
            cgroup_id: 0,
            executor_cgroup_id: None,
            pid: Some(1),
            tgid: Some(1),
            op: "file_open".into(),
            decision: "denied".into(),
            errno: 13,
            target: target.display().to_string(),
        }
    }

    /// A session whose first `write_file` is kernel-denied (scripted), under a ceiling that covers
    /// the target, so the denial becomes a question for the client.
    async fn ask_once(answer: Option<&'static str>) -> (Arc<TestFactory>, Arc<Seen>, PathBuf) {
        let dir = tempfile::tempdir().unwrap().keep();
        let target = dir.join("grant").join("x");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let audit = Arc::new(bee::sandbox::ScriptedAudit::default());
        audit.push_tool(vec![denial(&target)]);
        let f = Arc::new(TestFactory {
            scripts: Mutex::new(
                vec![vec![
                    tool_turn("c1", "write_file", json!({"path": target, "content": "x"})),
                    text_turn("done"),
                ]]
                .into(),
            ),
            policy: Some(policy(&[(
                dir.join("work").to_str().unwrap(),
                Access::Write,
            )])),
            ceiling: Some(policy(&[(dir.to_str().unwrap(), Access::Write)])),
            audit: Some(audit),
            ..TestFactory::default()
        });
        let seen = Arc::new(Seen::default());
        if let Some(a) = answer {
            seen.answers.lock().unwrap().push_back(a);
        }
        with_client(f.clone(), seen.clone(), async |cx| {
            let id = new_session(&cx, &dir).await?;
            cx.send_request(PromptRequest::new(id, text("write it")))
                .block_task()
                .await?;
            Ok(())
        })
        .await;
        (f, seen, target)
    }

    fn log(f: &TestFactory) -> Vec<bee::operator::ConsentRecord> {
        f.operator.lock().unwrap().as_ref().unwrap().log()
    }

    // T022: the client's "allow" grants and the retried write lands; its "reject" refuses.
    #[tokio::test]
    async fn permission_allow_widens_and_reject_does_not() {
        let (f, seen, target) = ask_once(Some("allow")).await;
        assert_eq!(seen.permissions.lock().unwrap().len(), 1);
        let l = log(&f);
        assert_eq!(
            (l[0].decision, l[0].reason),
            (Verdict::Granted, Reason::Granted)
        );
        assert_eq!(l[0].operator, bee::operator::OperatorKind::Interactive);
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "x",
            "the retried write"
        );

        let (f, _seen, _) = ask_once(Some("reject")).await;
        let l = log(&f);
        assert_eq!(
            (l[0].decision, l[0].reason),
            (Verdict::Refused, Reason::DeniedByOperator)
        );
    }

    // T023: the request shows every capability it would grant.
    #[tokio::test]
    async fn permission_request_lists_every_capability() {
        let (_f, seen, target) = ask_once(Some("reject")).await;
        let asked = seen.permissions.lock().unwrap();
        let shown = serde_json::to_string(&asked[0]).unwrap();
        assert!(shown.contains("requests extra capabilities"), "{shown}");
        assert!(
            shown.contains(&format!("filesystem: {} = write", target.display())),
            "{shown}"
        );
        let kinds: Vec<_> = asked[0].options.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            vec![
                agent_client_protocol::v1::schema::PermissionOptionKind::AllowOnce,
                agent_client_protocol::v1::schema::PermissionOptionKind::RejectOnce
            ]
        );
    }

    // T024: a cancelled request refuses.
    #[tokio::test]
    async fn a_cancelled_permission_request_refuses() {
        // On a host sandbox the scripted denial stops nothing, so only the decision is checked here;
        // the VM case `acp-consent` proves the write stays kernel-denied.
        let (f, _seen, _) = ask_once(None).await;
        let l = log(&f);
        assert_eq!(l[0].decision, Verdict::Refused);
    }
}
