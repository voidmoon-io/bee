//! `Message` — everything that can change the `App` (008-grid-tui, US1 T012 / data-model.md).
//!
//! The Elm-architecture input to [`super::app::update`]. Terminal events and [`SessionEvent`]s both
//! funnel into this one type. The `key_*` constructors let tests (and the event loop) build key
//! messages without naming crossterm at every call site.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::events::SessionEvent;

/// One thing that can change the model.
#[derive(Debug, Clone)]
pub enum Message {
    /// A key press.
    Key(KeyEvent),
    /// A bracketed paste.
    Paste(String),
    /// Terminal resized to `(cols, rows)`.
    Resize(u16, u16),
    /// Ctrl-Z suspend requested / resumed.
    Suspend,
    Resume,
    /// An animation tick (armed only while something animates).
    Tick,
    /// Scroll the chat flow by `n` rows, away from the newest content (wheel-up, PgUp, ↑).
    ScrollUp(u16),
    /// Scroll the chat flow by `n` rows, back toward the newest content (wheel-down, PgDn, ↓).
    ScrollDown(u16),
    /// The conversation core spoke. Boxed: a `SessionEvent` carries a whole `ToolResult`/`RenderSpec`,
    /// which would otherwise inflate every `Message` (a bare `Tick`) to its size.
    Session(Box<SessionEvent>),
    /// Actual exchange boundaries; busy-stop only means the provider's first event arrived.
    ExchangeStarted,
    ExchangeFinished(crate::repl::ExchangeOutcome),
    /// Quit the session.
    Quit,
}

impl Message {
    /// A plain character key.
    pub fn char(c: char) -> Self {
        Message::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }
    /// A character key with modifiers (e.g. Ctrl-C).
    pub fn char_mods(c: char, mods: KeyModifiers) -> Self {
        Message::Key(KeyEvent::new(KeyCode::Char(c), mods))
    }
    /// A bare key code (Enter, Tab, Up, …).
    pub fn key(code: KeyCode) -> Self {
        Message::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }
    /// A key code with modifiers (e.g. Shift+Enter for a soft newline).
    pub fn key_mods(code: KeyCode, mods: KeyModifiers) -> Self {
        Message::Key(KeyEvent::new(code, mods))
    }
    /// Wrap a [`SessionEvent`] as a message (boxes it — see the variant).
    pub fn session(ev: SessionEvent) -> Self {
        Message::Session(Box::new(ev))
    }
}
