//! Chat history model (008-grid-tui, US1 T015).
//!
//! An ordered list of messages; each is either prose (streamed and appended to) or an inline rendered
//! widget. The *view* (T016) virtualizes and draws these — this module is the pure model, so the
//! reducer and its tests need no terminal. Inline widgets will render through
//! `viz::buffer_render::render_into` at draw time.

use ratatui::text::Line;

use crate::render_spec::{EffectSpec, RenderSpec};

/// Who produced a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The operator.
    User,
    /// The model's prose.
    Assistant,
    /// Chrome: info / footer / errors / steering acks.
    System,
    /// Tool calls and their results.
    Tool,
}

/// A message's content: prose (appendable while streaming), markdown, or a rendered widget.
#[derive(Debug, Clone)]
pub enum Body {
    Text(String),
    /// Markdown the *sender* declared as markdown — a skill's instructions, say. Distinct from
    /// `Text` because guessing is unsafe: a tool result containing `**` is data, not emphasis (010).
    Markdown(String),
    Widget(Box<RenderSpec>, Option<EffectSpec>),
    /// The host mascot, animated only while visible.
    Mascot,
}

/// One entry in the transcript view.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: Role,
    pub body: Body,
    /// Whether the message is finished. Assistant prose starts open and closes on `AssistantEnd`;
    /// everything else arrives complete. The view renders closed prose as markdown and open prose
    /// raw — re-parsing a half-streamed message would flip it between code-block and paragraph on
    /// every delta as an unclosed fence opens and closes (010).
    pub done: bool,
    /// Rendered markdown rows and the width they were laid out for.
    ///
    /// Parsing is ~5× the cost of wrapping plain text, and the view re-lays the *whole* backlog every
    /// frame — at 60fps a few hundred messages would spend the entire frame budget re-parsing prose
    /// that has not changed since it arrived. Invalidated by anything that changes the source or the
    /// width (010).
    cache: Option<(u16, Vec<Line<'static>>)>,
}

impl ChatMessage {
    pub fn mascot() -> Self {
        Self {
            role: Role::System,
            body: Body::Mascot,
            done: true,
            cache: None,
        }
    }

    /// A prose message. Assistant prose is born open (it streams); everything else is complete the
    /// moment it exists.
    pub fn text(role: Role, s: impl Into<String>) -> Self {
        ChatMessage {
            role,
            body: Body::Text(s.into()),
            done: role != Role::Assistant,
            cache: None,
        }
    }

    /// A message whose sender declared it markdown (010). Complete on arrival — it never streams.
    pub fn markdown(role: Role, s: impl Into<String>) -> Self {
        ChatMessage {
            role,
            body: Body::Markdown(s.into()),
            done: true,
            cache: None,
        }
    }

    /// An inline widget message (a tool's visualization).
    pub fn widget(spec: RenderSpec) -> Self {
        ChatMessage {
            role: Role::Tool,
            body: Body::Widget(Box::new(spec), None),
            done: true,
            cache: None,
        }
    }

    /// An inline widget with an agent-requested effect (009 FR-022).
    pub fn widget_with_effect(spec: RenderSpec, effect: Option<EffectSpec>) -> Self {
        ChatMessage {
            role: Role::Tool,
            body: Body::Widget(Box::new(spec), effect),
            done: true,
            cache: None,
        }
    }

    /// Close the message to further appends — the point at which prose becomes markdown-renderable.
    pub fn mark_done(&mut self) {
        self.done = true;
        self.cache = None; // it was raw text a moment ago; it is markdown now
    }

    /// The markdown source this message should render as, if any: a block whose sender declared it
    /// markdown, or assistant prose that has finished streaming. Everything else is literal — a tool
    /// result containing `**` is data, not emphasis.
    pub fn markdown_source(&self) -> Option<&str> {
        match &self.body {
            Body::Markdown(t) => Some(t),
            Body::Text(t) if self.role == Role::Assistant && self.done => Some(t),
            _ => None,
        }
    }

    /// The message's rendered markdown rows at `width`, parsing only when the cache cannot answer.
    /// Returns `None` for a message that is not markdown.
    pub fn rendered_markdown(&mut self, width: u16) -> Option<&[Line<'static>]> {
        self.markdown_source()?;
        let stale = !matches!(&self.cache, Some((w, _)) if *w == width);
        if stale {
            let source = self.markdown_source().expect("checked above");
            let lines = super::markdown::render(source, width);
            self.cache = Some((width, lines));
        }
        self.cache.as_ref().map(|(_, lines)| lines.as_slice())
    }

    /// The already-rendered rows, but only if they were laid out for `width`. Read-only companion to
    /// [`Self::rendered_markdown`], for the layout pass that must not re-parse.
    pub fn cached_markdown(&self, width: u16) -> Option<&[Line<'static>]> {
        match &self.cache {
            Some((w, lines)) if *w == width => Some(lines),
            _ => None,
        }
    }

    /// Append streamed prose. Returns `false` if this message isn't a text body (so the caller starts
    /// a new one).
    pub fn push_str(&mut self, s: &str) -> bool {
        match &mut self.body {
            Body::Text(t) => {
                t.push_str(s);
                self.cache = None;
                true
            }
            // A widget has no prose to append to, and a markdown block arrives whole — appending to
            // one mid-render would re-parse a document that was never partial.
            Body::Widget(..) | Body::Markdown(_) | Body::Mascot => false,
        }
    }

    /// Whether this is an assistant prose message still open for streaming appends.
    pub fn is_open_assistant(&self) -> bool {
        self.role == Role::Assistant && matches!(self.body, Body::Text(_)) && !self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_declared_markdown_and_settled_prose_are_markdown() {
        let mut streaming = ChatMessage::text(Role::Assistant, "half a **sen");
        assert_eq!(streaming.markdown_source(), None, "still streaming");
        streaming.mark_done();
        assert!(streaming.markdown_source().is_some(), "settled");

        // A tool result containing `**` is data — rendering it would eat characters from output.
        let tool = ChatMessage::text(Role::Tool, "grep: **match**");
        assert_eq!(tool.markdown_source(), None);
        // Declared markdown is markdown whatever its role.
        assert!(ChatMessage::markdown(Role::System, "# skill")
            .markdown_source()
            .is_some());
    }

    #[test]
    fn the_render_cache_answers_only_for_the_width_it_was_built_at() {
        let mut m = ChatMessage::markdown(Role::System, "some **words** to lay out here");
        assert_eq!(m.cached_markdown(20), None, "nothing cached yet");
        let rows_at_20 = m.rendered_markdown(20).expect("markdown").len();
        assert!(m.cached_markdown(20).is_some());
        assert_eq!(m.cached_markdown(80), None, "a different width is a miss");

        // Re-laying at a wider pane replaces the cache rather than reusing rows sized for 20.
        let rows_at_80 = m.rendered_markdown(80).expect("markdown").len();
        assert!(rows_at_80 < rows_at_20, "wider pane, fewer rows");
        assert!(m.cached_markdown(80).is_some());
        assert_eq!(m.cached_markdown(20), None, "the stale entry is gone");
    }

    #[test]
    fn appending_and_settling_both_invalidate_the_cache() {
        let mut m = ChatMessage::text(Role::Assistant, "**one**");
        m.mark_done();
        m.rendered_markdown(40).expect("markdown");
        assert!(m.cached_markdown(40).is_some());

        // A closed message that reopens for more prose must not keep rows for the shorter text.
        m.done = false;
        assert!(m.push_str(" and **two**"));
        assert_eq!(m.cached_markdown(40), None, "append invalidated it");

        m.mark_done();
        assert_eq!(m.cached_markdown(40), None, "settling invalidated it too");
        let rows = m.rendered_markdown(40).expect("markdown");
        let text: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            text.contains("two"),
            "the appended half is rendered: {text:?}"
        );
    }
}
