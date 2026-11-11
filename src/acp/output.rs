//! What a session shows its ACP client: bee's front-end events as `session/update` notifications
//! (026 contracts/acp-agent.md, "session/update mapping").
//!
//! An exchange runs its tool calls one at a time, so a result always belongs to the oldest call still
//! open: [`AcpOutput`] numbers calls as it sees them and pairs each result with that call.

use std::collections::VecDeque;
use std::sync::Mutex;

use agent_client_protocol::v1::schema::{
    ContentBlock, ContentChunk, SessionNotification, SessionUpdate, TextContent, ToolCall,
    ToolCallContent, ToolCallStatus, ToolCallUpdate, ToolCallUpdateFields, ToolKind,
};
use agent_client_protocol::v1::ConnectionTo;
use agent_client_protocol::Client;
use bee_core::AuditEvent;

use crate::repl::ReplOutput;
use crate::safe_text::safe_line;
use crate::tools::ToolResult;

/// Where an update goes. A trait so tests can collect updates without a connection.
pub trait UpdateSink: Send + Sync {
    fn send(&self, update: SessionUpdate);
}

/// The live sink: a notification on the client connection, for one session.
pub struct ConnectionSink {
    pub cx: ConnectionTo<Client>,
    pub session_id: String,
}

impl UpdateSink for ConnectionSink {
    fn send(&self, update: SessionUpdate) {
        // A closed connection cancels the session anyway; nothing to do with the error here.
        let _ = self
            .cx
            .send_notification(SessionNotification::new(self.session_id.clone(), update));
    }
}

/// bee's [`ReplOutput`] for one ACP session.
pub struct AcpOutput<S: UpdateSink> {
    sink: S,
    state: Mutex<CallState>,
}

#[derive(Default)]
struct CallState {
    next: u64,
    open: VecDeque<String>,
}

impl<S: UpdateSink> AcpOutput<S> {
    pub fn new(sink: S) -> Self {
        AcpOutput {
            sink,
            state: Mutex::new(CallState::default()),
        }
    }

    /// A line of bee's own, shown as the agent's words and marked as bee's.
    fn say(&self, text: &str) {
        self.sink.send(agent_text(&format!("bee: {text}\n")));
    }
}

/// An `agent_message_chunk` carrying `text`.
pub fn agent_text(text: &str) -> SessionUpdate {
    SessionUpdate::AgentMessageChunk(ContentChunk::new(ContentBlock::Text(TextContent::new(
        text.to_string(),
    ))))
}

/// How a client should draw a bee tool (contracts/acp-agent.md, `kind` mapping).
pub fn kind_of(tool: &str) -> ToolKind {
    match tool {
        "read_file" | "list_dir" | "source" | "gitlog" => ToolKind::Read,
        "write_file" | "edit_file" => ToolKind::Edit,
        "bash" | "exec" | "repro" => ToolKind::Execute,
        "http" | "fetch" => ToolKind::Fetch,
        "grep" | "glob" | "search" | "astgrep" => ToolKind::Search,
        _ => ToolKind::Other,
    }
}

/// The call's title: its name and a short, single-line view of its arguments.
fn title(name: &str, arguments: &serde_json::Value) -> String {
    const MAX: usize = 80;
    let args = match arguments {
        serde_json::Value::Object(m) if m.is_empty() => String::new(),
        serde_json::Value::Object(m) => m
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => format!("{k}={s}"),
                other => format!("{k}={other}"),
            })
            .collect::<Vec<_>>()
            .join(" "),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    let mut t = safe_line(&format!("{name} {args}")).trim().to_string();
    if t.chars().count() > MAX {
        t = t.chars().take(MAX - 1).collect::<String>() + "…";
    }
    t
}

impl<S: UpdateSink> ReplOutput for AcpOutput<S> {
    fn assistant_delta(&self, chunk: &str) {
        if !chunk.is_empty() {
            self.sink.send(agent_text(chunk));
        }
    }

    fn assistant_end(&self) {}

    fn tool_call(&self, name: &str, arguments: &serde_json::Value) {
        let id = {
            let mut st = self.state.lock().expect("acp output state");
            st.next += 1;
            let id = format!("call-{}", st.next);
            st.open.push_back(id.clone());
            id
        };
        self.sink.send(SessionUpdate::ToolCall(
            ToolCall::new(id, title(name, arguments))
                .kind(kind_of(name))
                .status(ToolCallStatus::InProgress)
                .raw_input(arguments.clone()),
        ));
    }

    fn tool_result(&self, result: &ToolResult, audit: &[AuditEvent]) {
        let Some(id) = self
            .state
            .lock()
            .expect("acp output state")
            .open
            .pop_front()
        else {
            return;
        };
        // The result is a tool's output: data, shown under the call it belongs to, never as bee's
        // own words. Control sequences are removed line by line.
        let mut text: String = result
            .content
            .lines()
            .map(safe_line)
            .collect::<Vec<_>>()
            .join("\n");
        for e in audit.iter().filter(|e| e.decision == "denied") {
            text.push_str(&format!(
                "\nkernel denied {} {}",
                safe_line(&e.op),
                safe_line(&e.target)
            ));
        }
        let status = if result.is_error {
            ToolCallStatus::Failed
        } else {
            ToolCallStatus::Completed
        };
        let content: Vec<ToolCallContent> = vec![ContentBlock::Text(TextContent::new(text)).into()];
        self.sink
            .send(SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                id,
                ToolCallUpdateFields::new().status(status).content(content),
            )));
    }

    fn error(&self, msg: &str) {
        self.say(&format!("error: {}", safe_line(msg)));
    }

    fn info(&self, msg: &str) {
        self.say(&safe_line(msg));
    }

    // Terminal furniture: a client draws its own.
    fn footer(&self, _msg: &str) {}
    fn render_widget(
        &self,
        _spec: &crate::render_spec::RenderSpec,
        _effect: Option<&crate::render_spec::EffectSpec>,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<SessionUpdate>>);
    impl UpdateSink for &Collect {
        fn send(&self, update: SessionUpdate) {
            self.0.lock().unwrap().push(update);
        }
    }

    fn denied(target: &str) -> AuditEvent {
        AuditEvent {
            ts: "t".into(),
            scope_id: Some("s".into()),
            cgroup_id: 1,
            executor_cgroup_id: None,
            pid: Some(1),
            tgid: Some(1),
            op: "file_open".into(),
            decision: "denied".into(),
            errno: 13,
            target: target.into(),
        }
    }

    #[test]
    fn a_call_and_its_result_share_an_id_and_the_denial_is_shown_on_it() {
        let c = Collect::default();
        let out = AcpOutput::new(&c);
        out.tool_call(
            "write_file",
            &serde_json::json!({"path": "/x", "content": "y"}),
        );
        out.tool_result(&ToolResult::error("write_file: denied"), &[denied("/x")]);
        let got = c.0.lock().unwrap();
        let SessionUpdate::ToolCall(call) = &got[0] else {
            panic!("{:?}", got[0])
        };
        assert_eq!(call.kind, ToolKind::Edit);
        assert_eq!(call.status, ToolCallStatus::InProgress);
        let SessionUpdate::ToolCallUpdate(update) = &got[1] else {
            panic!("{:?}", got[1])
        };
        assert_eq!(update.tool_call_id, call.tool_call_id);
        assert_eq!(update.fields.status, Some(ToolCallStatus::Failed));
        let shown = serde_json::to_string(&update.fields.content).unwrap();
        assert!(shown.contains("kernel denied file_open /x"), "{shown}");
    }

    #[test]
    fn tool_output_cannot_drive_the_client_terminal() {
        let c = Collect::default();
        let out = AcpOutput::new(&c);
        out.tool_call("bash", &serde_json::json!({"command": "x"}));
        out.tool_result(&ToolResult::ok("ok\u{1b}[2Jgone"), &[]);
        let shown = serde_json::to_string(&c.0.lock().unwrap()[1]).unwrap();
        assert!(!shown.contains("\\u001b"), "{shown}");
    }

    #[test]
    fn bee_lines_are_marked_as_bee() {
        let c = Collect::default();
        AcpOutput::new(&c).info("HTTP interception on");
        let shown = serde_json::to_string(&c.0.lock().unwrap()[0]).unwrap();
        assert!(shown.contains("bee: HTTP interception on"), "{shown}");
    }
}
