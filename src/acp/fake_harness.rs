//! `bee acp-fake-harness` (026 T003): a scripted ACP v1 agent standing in for Claude Code in tests
//! and VM cases. Compiled only with `test-support` or `vm-test`.
//!
//! On `session/prompt` it runs the JSON action list in `FAKE_HARNESS_SCRIPT` and reports each
//! action's outcome as an `agent_message_chunk` line, so a test reads what happened from the
//! harness's final turn — what bee reports to the delegating model. Actions:
//!
//! | Action | Does |
//! |---|---|
//! | `{"say": text}` | says `text` |
//! | `{"write": {"path", "text"}}` / `{"read": path}` | file I/O from inside the scope |
//! | `{"connect_via_proxy": {"host", "port"}}` | HTTP `CONNECT` through `HTTPS_PROXY`, with its credential |
//! | `{"connect_direct": {"host", "port"}}` | a plain TCP connect, bypassing the proxy |
//! | `{"fork_sleeper": secs}` | a detached `sleep` in its own session |
//! | `{"call_fs_read": path}` | asks its client for `fs/read_text_file` |
//! | `{"ask_permission": title}` | asks its client's permission (allow once / always / reject) |
//! | `{"run": [argv…]}` | runs a program (its exit and first stdout line) |
//! | `{"wait_file": {"path", "secs"}}` | waits for a file to appear |
//! | `{"sleep": secs}` | sleeps; `session/cancel` interrupts |
//! | `{"stderr": text}` | writes a line to stderr |
//! | `{"exit": code}` | exits at once, answering nothing |
//! | `{"stop": reason}` | the prompt's stop reason (`end_turn` by default) |

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_client_protocol::v1::schema::{
    AgentCapabilities, CancelNotification, ContentBlock, ContentChunk, Implementation,
    InitializeRequest, InitializeResponse, NewSessionRequest, NewSessionResponse, PermissionOption,
    PermissionOptionKind, PromptRequest, PromptResponse, ReadTextFileRequest,
    RequestPermissionOutcome, RequestPermissionRequest, SessionId, SessionNotification,
    SessionUpdate, StopReason, TextContent, ToolCallUpdate, ToolCallUpdateFields,
};
use agent_client_protocol::v1::ConnectionTo;
use agent_client_protocol::{Agent, ByteStreams, Client};
use serde_json::Value;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

/// Run the fake harness on stdio until its client closes it.
pub fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("fake harness: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let script: Vec<Value> = std::env::var("FAKE_HARNESS_SCRIPT")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    match rt.block_on(serve(script)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fake harness: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(script: Vec<Value>) -> Result<(), agent_client_protocol::Error> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let c2 = cancelled.clone();
    let transport = ByteStreams::new(
        tokio::io::stdout().compat_write(),
        tokio::io::stdin().compat(),
    );
    Agent
        .v1()
        .name("fake-harness")
        .on_receive_request(
            async move |req: InitializeRequest, responder, _cx| {
                let _ = req;
                responder.respond(
                    InitializeResponse::new(agent_client_protocol::schema::ProtocolVersion::V1)
                        .agent_capabilities(AgentCapabilities::new())
                        .agent_info(Implementation::new("fake-harness", "0.1")),
                )
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_req: NewSessionRequest, responder, _cx| {
                responder.respond(NewSessionResponse::new("fake-1"))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |req: PromptRequest, responder, cx: ConnectionTo<Client>| {
                let script = script.clone();
                let cancelled = cancelled.clone();
                let conn = cx.clone();
                cx.spawn(async move {
                    let stop = run_script(&conn, req.session_id, &script, &cancelled).await;
                    responder.respond(PromptResponse::new(stop))
                })
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_notification(
            async move |_n: CancelNotification, _cx| {
                c2.store(true, Ordering::SeqCst);
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .connect_to(transport)
        .await
}

fn say(cx: &ConnectionTo<Client>, session: &SessionId, text: String) {
    let _ = cx.send_notification(SessionNotification::new(
        session.clone(),
        SessionUpdate::AgentMessageChunk(ContentChunk::new(ContentBlock::Text(TextContent::new(
            text,
        )))),
    ));
}

async fn run_script(
    cx: &ConnectionTo<Client>,
    session: SessionId,
    script: &[Value],
    cancelled: &AtomicBool,
) -> StopReason {
    let mut stop = StopReason::EndTurn;
    for action in script {
        if cancelled.load(Ordering::SeqCst) {
            return StopReason::Cancelled;
        }
        let Some((name, arg)) = action.as_object().and_then(|o| o.iter().next()) else {
            continue;
        };
        let line = match name.as_str() {
            "say" => arg.as_str().unwrap_or_default().to_string(),
            "write" => {
                let path = arg["path"].as_str().unwrap_or_default();
                match std::fs::write(path, arg["text"].as_str().unwrap_or("x")) {
                    Ok(()) => format!("write {path}: ok"),
                    Err(e) => format!("write {path}: denied ({e})"),
                }
            }
            "read" => {
                let path = arg.as_str().unwrap_or_default();
                match std::fs::read(path) {
                    Ok(b) => format!("read {path}: ok ({} bytes)", b.len()),
                    Err(e) => format!("read {path}: denied ({e})"),
                }
            }
            "connect_via_proxy" => {
                let (host, port) = (
                    arg["host"].as_str().unwrap_or_default(),
                    arg["port"].as_u64().unwrap_or(443),
                );
                format!("connect_via_proxy {host}:{port}: {}", via_proxy(host, port))
            }
            "connect_direct" => {
                let (host, port) = (
                    arg["host"].as_str().unwrap_or_default(),
                    arg["port"].as_u64().unwrap_or(443),
                );
                let r = std::net::TcpStream::connect_timeout(
                    &match format!("{host}:{port}").parse() {
                        Ok(a) => a,
                        Err(e) => {
                            say(
                                cx,
                                &session,
                                format!("connect_direct {host}:{port}: bad address ({e})\n"),
                            );
                            continue;
                        }
                    },
                    Duration::from_secs(3),
                );
                match r {
                    Ok(_) => format!("connect_direct {host}:{port}: open"),
                    Err(e) => format!("connect_direct {host}:{port}: shut ({e})"),
                }
            }
            "fork_sleeper" => {
                use std::os::unix::process::CommandExt;
                let secs = arg.as_u64().unwrap_or(300).to_string();
                let mut c = std::process::Command::new("sleep");
                c.arg(&secs)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                // SAFETY: setsid is async-signal-safe; it detaches the sleeper from our session.
                unsafe {
                    c.pre_exec(|| {
                        libc::setsid();
                        Ok(())
                    });
                }
                match c.spawn() {
                    Ok(ch) => format!("fork_sleeper: pid {}", ch.id()),
                    Err(e) => format!("fork_sleeper: failed ({e})"),
                }
            }
            "call_fs_read" => {
                let path = arg.as_str().unwrap_or("/etc/hostname");
                match cx
                    .send_request(ReadTextFileRequest::new(session.clone(), path))
                    .block_task()
                    .await
                {
                    Ok(_) => "fs/read_text_file: answered".to_string(),
                    Err(e) => format!("fs/read_text_file: refused ({})", e.code),
                }
            }
            "ask_permission" => {
                let title = arg.as_str().unwrap_or("do it").to_string();
                let req = RequestPermissionRequest::new(
                    session.clone(),
                    ToolCallUpdate::new("perm-1", ToolCallUpdateFields::new().title(title)),
                    vec![
                        PermissionOption::new(
                            "always",
                            "Always",
                            PermissionOptionKind::AllowAlways,
                        ),
                        PermissionOption::new("once", "Once", PermissionOptionKind::AllowOnce),
                        PermissionOption::new("no", "No", PermissionOptionKind::RejectOnce),
                    ],
                );
                match cx.send_request(req).block_task().await {
                    Ok(r) => match r.outcome {
                        RequestPermissionOutcome::Selected(s) => {
                            format!("ask_permission: chose {}", s.option_id)
                        }
                        _ => "ask_permission: cancelled".to_string(),
                    },
                    Err(e) => format!("ask_permission: error ({e})"),
                }
            }
            "run" => {
                let argv: Vec<String> = arg
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let Some((prog, rest)) = argv.split_first() else {
                    continue;
                };
                match tokio::process::Command::new(prog).args(rest).output().await {
                    Ok(o) => format!(
                        "run {prog}: exit {}: {}",
                        o.status.code().unwrap_or(-1),
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .next()
                            .unwrap_or_default()
                    ),
                    Err(e) => format!("run {prog}: failed ({e})"),
                }
            }
            "wait_file" => {
                let path = arg["path"].as_str().unwrap_or_default().to_string();
                let until = std::time::Instant::now()
                    + Duration::from_secs(arg["secs"].as_u64().unwrap_or(10));
                while !std::path::Path::new(&path).exists() && std::time::Instant::now() < until {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                format!("wait_file {path}: {}", std::path::Path::new(&path).exists())
            }
            "sleep" => {
                let until = std::time::Instant::now()
                    + Duration::from_secs_f64(arg.as_f64().unwrap_or(1.0));
                while std::time::Instant::now() < until {
                    if cancelled.load(Ordering::SeqCst) {
                        say(cx, &session, "sleep: cancelled\n".into());
                        return StopReason::Cancelled;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                "sleep: done".to_string()
            }
            "stderr" => {
                eprintln!("{}", arg.as_str().unwrap_or_default());
                continue;
            }
            "exit" => {
                let _ = std::io::stderr().flush();
                std::process::exit(arg.as_i64().unwrap_or(3) as i32);
            }
            "stop" => {
                stop = match arg.as_str().unwrap_or("end_turn") {
                    "max_tokens" => StopReason::MaxTokens,
                    "max_turn_requests" => StopReason::MaxTurnRequests,
                    "refusal" => StopReason::Refusal,
                    _ => StopReason::EndTurn,
                };
                continue;
            }
            other => format!("{other}: unknown action"),
        };
        say(cx, &session, format!("{line}\n"));
    }
    stop
}

/// `CONNECT host:port` through `$HTTPS_PROXY`, with its userinfo as the credential. The status line.
fn via_proxy(host: &str, port: u64) -> String {
    let Ok(url) = std::env::var("HTTPS_PROXY") else {
        return "no HTTPS_PROXY".into();
    };
    let rest = url.trim_start_matches("http://");
    let (userinfo, addr) = match rest.rsplit_once('@') {
        Some((u, a)) => (Some(u), a),
        None => (None, rest),
    };
    let addr = addr.trim_end_matches('/');
    let mut s = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => return format!("proxy unreachable ({e})"),
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(u) = userinfo {
        let decoded = percent_decode(u);
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            b64(decoded.as_bytes())
        ));
    }
    req.push_str("\r\n");
    if let Err(e) = s.write_all(req.as_bytes()) {
        return format!("write failed ({e})");
    }
    let mut buf = [0u8; 512];
    match s.read(&mut buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string(),
        Err(e) => format!("read failed ({e})"),
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn b64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
