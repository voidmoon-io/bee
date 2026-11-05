//! [`MockModel`] — the offline, deterministic backend every host test uses (research H11).
//!
//! Constructed from a script (`Vec<Turn>`) or a closure `Fn(&Conversation) -> Turn`. It performs no
//! network I/O, so the loop, tools, truncation, malformed-arg handling, and `no_tool_calls` are all
//! testable without a provider key or a kernel.

use std::sync::Mutex;

use super::{Conversation, EventStream, Model, ModelError, StreamEvent, ToolSchema, Turn};

enum Script {
    /// Successive scripted turns; when exhausted, a graceful text-only turn ends the episode.
    Steps(Mutex<std::collections::VecDeque<Turn>>),
    /// A pure function of the current conversation.
    Closure(Box<dyn Fn(&Conversation) -> Turn + Send + Sync>),
}

/// A scripted [`Model`] for deterministic, offline tests.
pub struct MockModel {
    id: String,
    script: Script,
}

impl MockModel {
    /// Build from a fixed sequence of turns. Each `complete` pops the next; once empty, returns a
    /// text-only turn so the loop terminates as `no_tool_calls` rather than hanging.
    pub fn scripted(turns: Vec<Turn>) -> Self {
        MockModel {
            id: "mock/scripted".to_string(),
            script: Script::Steps(Mutex::new(turns.into())),
        }
    }

    /// Build from a closure that computes each turn from the conversation so far.
    pub fn from_fn<F>(f: F) -> Self
    where
        F: Fn(&Conversation) -> Turn + Send + Sync + 'static,
    {
        MockModel {
            id: "mock/closure".to_string(),
            script: Script::Closure(Box::new(f)),
        }
    }

    /// Override the reported id (which appears in the transcript).
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }
}

#[async_trait::async_trait]
impl Model for MockModel {
    fn id(&self) -> &str {
        &self.id
    }

    async fn complete(
        &self,
        convo: &Conversation,
        _tools: &[ToolSchema],
    ) -> Result<Turn, ModelError> {
        match &self.script {
            Script::Steps(q) => Ok(q
                .lock()
                .expect("mock script mutex")
                .pop_front()
                .unwrap_or_else(|| Turn::text("[mock] script exhausted"))),
            Script::Closure(f) => Ok(f(convo)),
        }
    }

    /// Emit the scripted turn's prose as word-sized [`StreamEvent::TextDelta`]s (rather than the
    /// single delta of the default fallback) so offline tests and `mock`-provider demos exercise the
    /// incremental render path the same way a live provider would.
    async fn stream(
        &self,
        convo: &Conversation,
        tools: &[ToolSchema],
    ) -> Result<EventStream, ModelError> {
        let turn = self.complete(convo, tools).await?;
        let mut events: Vec<Result<StreamEvent, ModelError>> = Vec::new();
        if let Some(text) = &turn.text {
            // Split on spaces, keeping each space attached to the following word so the reassembled
            // deltas concatenate back to the original text exactly.
            let mut rest = text.as_str();
            while !rest.is_empty() {
                let next = rest[1..].find(' ').map(|i| i + 1).unwrap_or(rest.len());
                let (chunk, tail) = rest.split_at(next);
                events.push(Ok(StreamEvent::TextDelta(chunk.to_string())));
                rest = tail;
            }
        }
        for tc in &turn.tool_calls {
            events.push(Ok(StreamEvent::ToolCall(tc.clone())));
        }
        events.push(Ok(StreamEvent::Done(turn)));
        Ok(Box::pin(futures_util::stream::iter(events)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{StopReason, ToolCall};
    use futures_util::StreamExt;

    /// Drain a stream into (concatenated text deltas, tool-call names, final Done turn).
    async fn drain(model: &dyn Model) -> (String, Vec<String>, Turn) {
        let convo = Conversation::new("sys", "hi");
        let mut s = model.stream(&convo, &[]).await.expect("stream opens");
        let (mut text, mut calls, mut done) = (String::new(), Vec::new(), None);
        while let Some(ev) = s.next().await {
            match ev.expect("event ok") {
                StreamEvent::TextDelta(d) => text.push_str(&d),
                StreamEvent::ToolCall(tc) => calls.push(tc.name),
                StreamEvent::Reasoning(_) => {}
                StreamEvent::Done(t) => done = Some(t),
            }
        }
        (text, calls, done.expect("stream ends with Done"))
    }

    #[tokio::test]
    async fn stream_reassembles_text_and_ends_with_done() {
        let model = MockModel::scripted(vec![Turn::text("hello there general kenobi")]);
        let (text, calls, done) = drain(&model).await;
        // The word-sized deltas concatenate back to exactly the original prose.
        assert_eq!(text, "hello there general kenobi");
        assert!(calls.is_empty());
        assert_eq!(done.text.as_deref(), Some("hello there general kenobi"));
        assert_eq!(done.stop, StopReason::EndTurn);
    }

    #[tokio::test]
    async fn stream_forwards_tool_calls_before_done() {
        let call = ToolCall {
            id: "1".into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": "ls" }),
        };
        let model = MockModel::scripted(vec![Turn::calls(vec![call])]);
        let (text, calls, done) = drain(&model).await;
        assert!(text.is_empty());
        assert_eq!(calls, vec!["bash".to_string()]);
        assert_eq!(done.tool_calls.len(), 1);
        assert_eq!(done.stop, StopReason::ToolUse);
    }
}
