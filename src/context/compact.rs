//! The conversation's regions, and the edits compaction makes to them (025 research R4, R5, R7;
//! contracts/context.md).
//!
//! A conversation is a **preamble** (the first message: the task, or the REPL's first user message),
//! then a **head** of at most two messages bee inserted (a summary, a removal marker), then **turns**.
//! A turn is one `Assistant` message with everything after it up to the next one: its tool results,
//! and any notes, steering or user messages. The newest turns are the **recent window**; the turns
//! between the head and the window are the **middle**, the only place compaction edits.
//!
//! The head is known by position, from the count [`super::ContextManager`] keeps, never by its text: a
//! person in the REPL can type anything, including text that looks like bee's (analysis U2).

use crate::call::CallOutcome;
use crate::provider::{Conversation, Message, Provenance, ToolCall};
use crate::proxy_event::ProxyEventKind;

use super::budget;

/// The most denials a stub lists before "and N more".
pub const MAX_DENIALS: usize = 5;

/// How a call ended, as a stub states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteOutcome {
    Ok,
    Error,
    TimedOut,
    Denied,
    RefusedByHook,
    NotRun,
}

impl NoteOutcome {
    pub fn word(self) -> &'static str {
        match self {
            NoteOutcome::Ok => "ok",
            NoteOutcome::Error => "error",
            NoteOutcome::TimedOut => "timed out",
            NoteOutcome::Denied => "denied",
            NoteOutcome::RefusedByHook => "refused by hook",
            NoteOutcome::NotRun => "not run",
        }
    }
}

/// What a stub needs to know about a call, recorded when its result is pushed (R5): the message
/// itself carries no audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNote {
    pub tool: String,
    pub args_short: String,
    pub outcome: NoteOutcome,
    pub original_bytes: usize,
    pub denials: Vec<String>,
}

impl CallNote {
    /// The note for a call that ran, or was refused before running.
    pub fn from_outcome(call: &ToolCall, outcome: &CallOutcome) -> CallNote {
        let mut denials: Vec<String> = outcome
            .audit
            .iter()
            .filter(|e| e.decision == "denied" && e.scope_id.as_deref() != Some("proxy"))
            .map(|e| kernel_denial(&e.op, &e.target))
            .collect();
        denials.extend(
            outcome
                .proxy_events
                .iter()
                .filter(|e| e.kind == ProxyEventKind::RefusedOutOfScope)
                .map(|e| format!("proxy refused {}:{} (out of scope)", e.host, e.port)),
        );
        let result = &outcome.result;
        let state = if outcome.refused_by_hook.is_some() {
            NoteOutcome::RefusedByHook
        } else if outcome.timed_out {
            NoteOutcome::TimedOut
        } else if !denials.is_empty() {
            NoteOutcome::Denied
        } else if result.is_error {
            NoteOutcome::Error
        } else {
            NoteOutcome::Ok
        };
        CallNote {
            tool: call.name.clone(),
            args_short: args_short(call),
            outcome: state,
            original_bytes: result
                .original_len
                .unwrap_or(result.content.len())
                .max(result.content.len()),
            denials: cap_denials(denials),
        }
    }

    /// The note for a call that was never run (025 FR-034).
    pub fn not_run(call: &ToolCall) -> CallNote {
        CallNote {
            tool: call.name.clone(),
            args_short: args_short(call),
            outcome: NoteOutcome::NotRun,
            original_bytes: 0,
            denials: Vec::new(),
        }
    }

    /// A note from the message alone, for a result pushed without one.
    fn from_message(name: &str, content: &str, is_error: bool) -> CallNote {
        CallNote {
            tool: name.to_string(),
            args_short: String::new(),
            outcome: if is_error {
                NoteOutcome::Error
            } else {
                NoteOutcome::Ok
            },
            original_bytes: content.len(),
            denials: Vec::new(),
        }
    }

    /// How the call ended, in the stub's words.
    pub fn stub_outcome(&self) -> &'static str {
        self.outcome.word()
    }

    /// The text that replaces an elided result (contracts/context.md "Stub").
    pub fn stub(&self) -> String {
        let denials = if self.denials.is_empty() {
            String::new()
        } else {
            format!("; denied: {}", self.denials.join("; "))
        };
        format!(
            "[bee: result elided to save context] {}({}) → {}, {} bytes{denials}",
            self.tool,
            self.args_short,
            self.outcome.word(),
            self.original_bytes
        )
    }
}

/// `filesystem:/etc/shadow (open)` from a kernel audit event's `op` and `target`.
fn kernel_denial(op: &str, target: &str) -> String {
    let (kind, action) = if let Some(a) = op.strip_prefix("file_") {
        ("filesystem", a)
    } else if op.contains("exec") {
        ("exec", op)
    } else if op.contains("connect") || op.contains("send") || op.contains("bind") {
        ("network", op)
    } else {
        (op, op)
    };
    format!("{kind}:{target} ({action})")
}

fn cap_denials(mut d: Vec<String>) -> Vec<String> {
    if d.len() > MAX_DENIALS {
        let more = d.len() - MAX_DENIALS;
        d.truncate(MAX_DENIALS);
        d.push(format!("and {more} more"));
    }
    d
}

/// The call's arguments, cut to 80 characters.
fn args_short(call: &ToolCall) -> String {
    let full = call.arguments.to_string();
    if full.chars().count() > 80 {
        let cut: String = full.chars().take(80).collect();
        format!("{cut}…")
    } else {
        full
    }
}

/// The text of the marker left where turns were removed (contracts/context.md).
pub fn removal_marker(n: u32) -> String {
    format!("[bee] {n} earlier turns were removed to fit the context budget; their record is kept.")
}

/// One turn: `messages[start..end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnSpan {
    pub start: usize,
    pub end: usize,
}

/// The turns of `convo.messages[from..]`. Each begins at an `Assistant` message, except that anything
/// before the first one (a note, a steering line) belongs to the first turn.
pub fn segment(convo: &Conversation, from: usize) -> Vec<TurnSpan> {
    let len = convo.messages.len();
    if from >= len {
        return Vec::new();
    }
    let mut starts = vec![from];
    let mut seen = false;
    for (i, m) in convo.messages.iter().enumerate().skip(from) {
        if matches!(m, Message::Assistant { .. }) {
            if seen && i > from {
                starts.push(i);
            }
            seen = true;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(k, &start)| TurnSpan {
            start,
            end: starts.get(k + 1).copied().unwrap_or(len),
        })
        .collect()
}

/// The bytes `span` adds to a request.
pub fn span_bytes(convo: &Conversation, span: TurnSpan) -> usize {
    convo.messages[span.start..span.end]
        .iter()
        .map(budget::message_bytes)
        .sum()
}

/// The index into `spans` where the recent window begins: the newest turns that fit within `share` of
/// `budget_tokens`, never fewer than two (R4). Everything since the last `Assistant` is the last span,
/// so it is always inside.
pub fn recent_start(
    convo: &Conversation,
    spans: &[TurnSpan],
    ratio: f32,
    budget_tokens: u32,
    share: f32,
) -> usize {
    let room = (f64::from(budget_tokens) * f64::from(share)) as u64;
    let mut kept = 0usize;
    let mut used = 0u64;
    for span in spans.iter().rev() {
        let size = u64::from(budget::tokens(span_bytes(convo, *span), ratio));
        if kept < 2 || used + size <= room {
            used += size;
            kept += 1;
        } else {
            break;
        }
    }
    spans.len() - kept
}

/// Replace bulky tool results in `messages[from..to]` with stubs, oldest first, until `bytes` (the
/// request's current size, kept up to date here) is at most `target_bytes`. Returns how many results
/// were elided. A result is bulky above `bulky_bytes`; a stub is far smaller, so it is never elided
/// again.
pub fn elide(
    convo: &mut Conversation,
    notes: &std::collections::HashMap<String, CallNote>,
    from: usize,
    to: usize,
    bulky_bytes: usize,
    bytes: &mut usize,
    target_bytes: usize,
) -> u32 {
    let mut items = 0;
    for m in &mut convo.messages[from..to] {
        if *bytes <= target_bytes {
            break;
        }
        if let Message::ToolResult {
            call_id,
            name,
            content,
            is_error,
            provenance,
        } = m
        {
            if content.len() <= bulky_bytes {
                continue;
            }
            let stub = match notes.get(call_id.as_str()) {
                Some(n) => n.stub(),
                None => CallNote::from_message(name, content, *is_error).stub(),
            };
            *bytes = bytes.saturating_sub(content.len()) + stub.len();
            *content = stub;
            *provenance = Provenance::Harness;
            items += 1;
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolResult;
    use bee_core::AuditEvent;
    use serde_json::json;

    fn user(t: &str) -> Message {
        Message::User { text: t.into() }
    }

    fn asst(ids: &[&str]) -> Message {
        Message::Assistant {
            text: None,
            tool_calls: ids
                .iter()
                .map(|id| ToolCall {
                    id: id.to_string(),
                    name: "bash".into(),
                    arguments: json!({}),
                })
                .collect(),
        }
    }

    fn result(id: &str, content: &str) -> Message {
        Message::ToolResult {
            call_id: id.into(),
            name: "bash".into(),
            content: content.into(),
            is_error: false,
            provenance: Provenance::Child,
        }
    }

    fn convo(messages: Vec<Message>) -> Conversation {
        Conversation {
            system: "s".into(),
            messages,
        }
    }

    #[test]
    fn turns_begin_at_each_assistant_and_carry_what_follows() {
        let c = convo(vec![
            user("task"),
            user("note before the first turn"),
            asst(&["a"]),
            result("a", "x"),
            user("steering"),
            asst(&["b", "c"]),
            result("b", "x"),
            result("c", "x"),
            asst(&[]),
        ]);
        let spans = segment(&c, 1);
        assert_eq!(
            spans,
            vec![
                TurnSpan { start: 1, end: 5 },
                TurnSpan { start: 5, end: 8 },
                TurnSpan { start: 8, end: 9 },
            ]
        );
        assert!(segment(&c, 9).is_empty());
    }

    #[test]
    fn the_recent_window_keeps_at_least_two_turns() {
        let big = "x".repeat(3000);
        let c = convo(vec![
            user("task"),
            asst(&["a"]),
            result("a", &big),
            asst(&["b"]),
            result("b", &big),
            asst(&["c"]),
            result("c", &big),
            asst(&["d"]),
            result("d", "small"),
        ]);
        let spans = segment(&c, 1);
        // A share too small for even one turn: still the newest two.
        assert_eq!(recent_start(&c, &spans, 3.0, 1000, 0.01), 2);
        // Room for everything: the whole conversation is recent.
        assert_eq!(recent_start(&c, &spans, 3.0, 100_000, 0.5), 0);
        // Room for the small turn and one big one beyond the floor of two.
        assert_eq!(recent_start(&c, &spans, 3.0, 10_000, 0.25), 1);
    }

    fn outcome(result: ToolResult) -> CallOutcome {
        CallOutcome {
            result,
            audit: Vec::new(),
            denied_attempt_audit: Vec::new(),
            proxy_audit: Vec::new(),
            proxy_events: Vec::new(),
            denied_attempt_proxy_events: Vec::new(),
            retried: false,
            timed_out: false,
            escalations: Vec::new(),
            refused_by_hook: None,
        }
    }

    fn call(name: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "c".into(),
            name: name.into(),
            arguments: args,
        }
    }

    #[test]
    fn stubs_match_the_contract_byte_for_byte() {
        let c = call("bash", json!({"command": "cat big.log"}));
        let ok = CallNote::from_outcome(&c, &outcome(ToolResult::ok("x".repeat(48211))));
        assert_eq!(
            ok.stub(),
            "[bee: result elided to save context] bash({\"command\":\"cat big.log\"}) → ok, 48211 bytes"
        );

        let r = call("read_file", json!({"path": "/etc/shadow"}));
        let mut o = outcome(ToolResult::error(""));
        o.audit.push(AuditEvent {
            ts: String::new(),
            scope_id: None,
            cgroup_id: 0,
            pid: None,
            tgid: None,
            op: "file_open".into(),
            decision: "denied".into(),
            errno: 13,
            target: "/etc/shadow".into(),
        });
        assert_eq!(
            CallNote::from_outcome(&r, &o).stub(),
            "[bee: result elided to save context] read_file({\"path\":\"/etc/shadow\"}) → denied, \
             0 bytes; denied: filesystem:/etc/shadow (open)"
        );

        let words: Vec<_> = [
            (NoteOutcome::Error, "error"),
            (NoteOutcome::TimedOut, "timed out"),
            (NoteOutcome::RefusedByHook, "refused by hook"),
            (NoteOutcome::NotRun, "not run"),
        ]
        .into_iter()
        .map(|(o, w)| {
            let n = CallNote {
                outcome: o,
                ..CallNote::not_run(&c)
            };
            (n.stub(), w)
        })
        .collect();
        for (stub, word) in words {
            assert!(stub.contains(&format!(" → {word}, ")), "{stub}");
        }
    }

    #[test]
    fn denials_are_capped_at_five() {
        let d: Vec<String> = (0..8).map(|i| format!("d{i}")).collect();
        let capped = cap_denials(d);
        assert_eq!(capped.len(), 6);
        assert_eq!(capped[5], "and 3 more");
    }

    #[test]
    fn the_removal_marker_text() {
        assert_eq!(
            removal_marker(3),
            "[bee] 3 earlier turns were removed to fit the context budget; their record is kept."
        );
    }

    #[test]
    fn elision_stops_at_the_target_and_marks_the_stub_as_bee_s() {
        let big = "x".repeat(5000);
        let mut c = convo(vec![
            user("task"),
            asst(&["a"]),
            result("a", &big),
            asst(&["b"]),
            result("b", &big),
        ]);
        let mut bytes = budget::estimate_bytes(&c, &[]);
        let target = bytes - 4000;
        let n = elide(&mut c, &Default::default(), 1, 5, 1200, &mut bytes, target);
        assert_eq!(n, 1, "one elision reached the target");
        let Message::ToolResult {
            content,
            provenance,
            ..
        } = &c.messages[2]
        else {
            panic!()
        };
        assert!(content.starts_with("[bee: result elided to save context] bash() → ok, 5000 bytes"));
        assert_eq!(*provenance, Provenance::Harness);
        assert_eq!(
            bytes,
            budget::estimate_bytes(&c, &[]),
            "the running size stays exact"
        );
    }
}
