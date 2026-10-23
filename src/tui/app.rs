//! `App` (Model) + the `update(&mut App, Message)` reducer (008-grid-tui, US1 T011/T013).
//!
//! Pure, renderer-agnostic state: feed a [`Message`] in, get mutated state out — no terminal, so the
//! whole thing is unit-testable (the tests at the bottom cover the acceptance behaviors). Side effects
//! (sending a submitted line to the model) are surfaced as data via [`App::take_outbox`], not done
//! here. Panels (US2) and the live-panel routing land in later tasks.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::chat::{ChatMessage, Role};
use super::effects::{Chrome, Effects};
use super::input::InputState;
use super::message::Message;
use super::overlay::Overlay;
use super::panels::PanelRegistry;
use crate::config::VisualConfig;
use crate::render_spec::RenderSpec;
use crate::tui::events::SessionEvent;

/// Which region has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Input,
    Chat,
    /// The panel column (or the panel overlay): j/k select, Space collapses, x closes.
    Panels,
}

/// Whether an assistant turn is in flight (drives the spinner / "thinking" line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    Idle,
    Streaming,
}

/// The responsive layout tier, derived purely from the terminal size (research D11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// ≥ 120 cols: chat + panel column.
    TwoPane,
    /// 80–119 (or short): a single chat pane; panels via overlay.
    SinglePane,
    /// Below the hard floor: only a "terminal too small" message.
    TooSmall,
}

impl LayoutMode {
    /// The tier for a `(cols, rows)` size (contracts/modes-and-cli.md responsive table): hard floor
    /// 40×10; a side-by-side panel column needs ≥ 120 cols **and** ≥ 24 rows — a wide-but-short
    /// terminal has no vertical room for panels beside chat, so it stays single-pane.
    pub fn from_size(cols: u16, rows: u16) -> Self {
        if cols < 40 || rows < 10 {
            LayoutMode::TooSmall
        } else if cols >= 120 && rows >= 24 {
            LayoutMode::TwoPane
        } else {
            LayoutMode::SinglePane
        }
    }
}

/// The full-screen application model.
pub struct App {
    pub chat: Vec<ChatMessage>,
    /// Model-owned panels rendered beside chat (US2). Empty in a US1 session.
    pub panels: PanelRegistry,
    pub input: InputState,
    pub focus: Focus,
    pub turn: TurnState,
    pub layout_mode: LayoutMode,
    pub size: (u16, u16),
    /// Lines scrolled up from the bottom; `0` = pinned to the newest content.
    pub scroll: usize,
    /// Whether new content keeps the view pinned to the bottom.
    pub follow_tail: bool,
    pub help_open: bool,
    /// Panel overlay toggle for single-pane layouts (`p`) — US3 T036. Ignored in `TwoPane`, where
    /// panels already have their own column.
    pub panels_visible: bool,
    pub should_quit: bool,
    /// One-key `gg` state: a `g` was pressed and we're waiting for the second.
    pub pending_g: bool,
    /// A submitted line the event loop must send to the model (drained via [`App::take_outbox`]).
    pub outbox: Option<String>,
    /// Text the user asked to yank (`y`); the event loop copies it via OSC 52 (US3 T035). Surfaced
    /// as data so the reducer stays pure — same pattern as [`App::outbox`].
    pub yank: Option<String>,
    /// A `Ctrl-Z` suspend request; the event loop performs the SIGTSTP dance (US3 T035).
    pub suspend_requested: bool,
    /// The live tachyonfx effects (009). Empty — and permanently so — when animations are off.
    pub effects: Effects,
    /// The three presentation axes for this session (009 FR-006a/FR-007).
    pub visual: VisualConfig,
    /// Time since the previous frame, set by the event loop before each draw and consumed by the
    /// effects pass. Passed as state rather than read from a clock inside `view` so a test can
    /// render a deterministic frame at any point on an effect's timeline.
    pub dt: Duration,
    /// The full-screen takeover, if one is up (009 US3). The `Option` is the whole of FR-020's
    /// at-most-one rule: a replacement is queued *inside* the overlay it replaces, so there is no
    /// second field where a stacked overlay could live.
    pub overlay: Option<Overlay>,
    /// When the last frame was drawn, for computing [`App::dt`].
    last_frame: Option<Instant>,
    /// Redraws caused by a periodic tick rather than by an event (009 SC-003). Event-driven draws
    /// are not counted — the claim under test is that an idle session wakes up zero times.
    pub periodic_redraws: u64,
    /// Chrome cues owed to the next frame (009 US5). Surfaced as data for the same reason
    /// [`App::outbox`] is: the reducer stays pure, and a cue can only be *played* by the renderer,
    /// which is the only thing that knows where the header and footer landed.
    pub chrome_cues: Vec<Chrome>,
    /// Whether the panel column is currently on screen, so its arrival animates once rather than on
    /// every frame it happens to be visible (009 US5).
    pub column_shown: bool,
    /// The model the session is talking to, shown in the header. Empty when unknown (tests).
    pub model_id: String,
    /// Which panel the operator has selected while the panel column has focus (index into the
    /// registry's insertion order, clamped by every consumer — panels come and go under it).
    pub panel_sel: usize,
    /// Count of session events received (deltas, tool calls, results). The header's working
    /// indicator takes its animation phase from this, so it moves exactly when data is flowing and
    /// holds still when the turn has stalled — motion as a report, not as decoration.
    pub activity: u64,
    /// A consent question on screen (024 T059). It swallows input until answered.
    pub consent: Option<ConsentModal>,
    /// The operator's answer to [`App::consent`], for the event loop to send (drained via
    /// [`App::take_consent_answer`]) — data, so the reducer stays pure.
    pub consent_answer: Option<crate::operator::Decision>,
}

/// A consent question: the request as the operator reads it, every capability on its own line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentModal {
    pub lines: Vec<String>,
}

impl App {
    /// A fresh session sized to the terminal.
    pub fn new(cols: u16, rows: u16) -> Self {
        App {
            chat: Vec::new(),
            panels: PanelRegistry::new(),
            input: InputState::default(),
            focus: Focus::Input,
            turn: TurnState::Idle,
            layout_mode: LayoutMode::from_size(cols, rows),
            size: (cols, rows),
            scroll: 0,
            follow_tail: true,
            help_open: false,
            panels_visible: false,
            should_quit: false,
            pending_g: false,
            outbox: None,
            yank: None,
            suspend_requested: false,
            effects: Effects::new(),
            visual: VisualConfig::default(),
            dt: Duration::ZERO,
            overlay: None,
            last_frame: None,
            periodic_redraws: 0,
            // Empty: a fresh `App` is a model, not a session. The session-start cues are queued by
            // `tui::run`, which is what actually *starts* — so rendering a constructed `App` (as
            // every 008 test does) shows settled chrome rather than the first frame of a fade.
            chrome_cues: Vec::new(),
            column_shown: false,
            model_id: String::new(),
            panel_sel: 0,
            activity: 0,
            consent: None,
            consent_answer: None,
        }
    }

    /// Put a consent question on screen.
    pub fn ask_consent(&mut self, lines: Vec<String>) {
        self.consent = Some(ConsentModal { lines });
        self.consent_answer = None;
    }

    /// Take the operator's answer, if they gave one since the last call.
    pub fn take_consent_answer(&mut self) -> Option<crate::operator::Decision> {
        self.consent_answer.take()
    }

    /// Take the question off screen unanswered — the operator stopped waiting.
    pub fn close_consent(&mut self) {
        self.consent = None;
    }

    /// A line from bee itself in the chat.
    pub fn system_line(&mut self, s: impl Into<String>) {
        self.push_line(Role::System, s);
    }

    /// The same session with the model's id in the header (008 header context).
    pub fn with_model(mut self, id: impl Into<String>) -> Self {
        self.model_id = id.into();
        self
    }

    /// The same session under an explicit visual configuration (009). Kept separate from
    /// [`App::new`] so 008's tests, which have no opinion about motion, stay untouched.
    pub fn with_visual(mut self, visual: VisualConfig) -> Self {
        self.visual = visual;
        self
    }

    /// Stamp the frame clock, setting [`App::dt`] to the time since the previous frame. The first
    /// frame gets a zero delta, so nothing jumps mid-animation on a session that has just started.
    pub fn tick_clock(&mut self, now: Instant) {
        self.dt = match self.last_frame {
            Some(prev) => now.saturating_duration_since(prev),
            None => Duration::ZERO,
        };
        self.last_frame = Some(now);
    }

    /// Whether a full-screen overlay is on screen — the scheduler's countdown state (FR-002).
    pub fn overlay_active(&self) -> bool {
        self.overlay.is_some()
    }

    /// Advance the overlay's state machine, dropping it once its fade-out has finished.
    ///
    /// Called from the event loop before each draw, so a TTL fires on the next frame rather than
    /// waiting for a keypress.
    pub fn advance_overlay(&mut self, now: Instant) {
        if let Some(o) = self.overlay.take() {
            self.overlay = o.advance(now);
        }
    }

    /// Show `spec` full-screen, replacing any overlay already up (FR-020).
    ///
    /// A replacement never stacks and never overlaps: the one on screen begins its fade-out and the
    /// newcomer waits for it to finish.
    pub fn show_overlay(&mut self, spec: RenderSpec, ttl_ms: Option<u32>, now: Instant) {
        let next = Overlay::new(spec, ttl_ms, &self.visual, now);
        match &mut self.overlay {
            Some(current) => current.replace_with(next, now),
            None => self.overlay = Some(next),
        }
    }

    /// Drop every running transition after a resize (008's resize strategy, 009 spec Edge Cases).
    ///
    /// Effects are pinned to the `Rect` they were registered with, and every snapshot was captured
    /// at the old size, so after a resize both describe a screen that no longer exists. Cancelling
    /// them means the next frame draws final content at the new geometry — the alternative, letting
    /// them play on against stale coordinates, paints over the wrong cells.
    pub fn invalidate_effects(&mut self) {
        if let Some(o) = &mut self.overlay {
            o.invalidate(&mut self.effects);
        }
        for panel in self.panels.iter_mut() {
            self.effects.cancel(panel.id.clone());
            panel.fx.prev = None;
            panel.pending = None;
        }
    }

    /// Take the pending outgoing user message, if any (the loop sends it to the model).
    pub fn take_outbox(&mut self) -> Option<String> {
        self.outbox.take()
    }

    /// Take the pending yank text, if any (the loop copies it via OSC 52).
    pub fn take_yank(&mut self) -> Option<String> {
        self.yank.take()
    }

    /// Take the pending suspend request (the loop performs the SIGTSTP dance).
    pub fn take_suspend(&mut self) -> bool {
        std::mem::take(&mut self.suspend_requested)
    }

    /// Whether the panel overlay should be drawn over chat: single-pane layouts only, toggled on,
    /// and only when there is something to show (US3 T036).
    pub fn overlay_open(&self) -> bool {
        self.panels_visible && self.layout_mode == LayoutMode::SinglePane && !self.panels.is_empty()
    }

    /// The text of the newest message that carries prose — what `y` yanks. Widgets have no text
    /// form worth putting on a clipboard, so they are skipped.
    fn newest_text(&self) -> Option<String> {
        self.chat.iter().rev().find_map(|m| match &m.body {
            // Markdown yanks as its source, which is the form worth pasting elsewhere.
            super::chat::Body::Text(t) | super::chat::Body::Markdown(t) if !t.trim().is_empty() => {
                Some(t.clone())
            }
            _ => None,
        })
    }

    /// Whether the panel region is on screen and can take focus: a populated column in `TwoPane`,
    /// or the open overlay in `SinglePane`.
    pub fn panels_reachable(&self) -> bool {
        !self.panels.is_empty() && (self.layout_mode == LayoutMode::TwoPane || self.panels_visible)
    }

    fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Input => Focus::Chat,
            // Panels join the cycle only while they are actually on screen — Tab never lands focus
            // on a region the operator cannot see.
            Focus::Chat if self.panels_reachable() => Focus::Panels,
            Focus::Chat => Focus::Input,
            Focus::Panels => Focus::Input,
        };
    }

    fn push_line(&mut self, role: Role, s: impl Into<String>) {
        self.chat.push(ChatMessage::text(role, s));
        self.autoscroll();
    }

    fn autoscroll(&mut self) {
        if self.follow_tail {
            self.scroll = 0;
        }
    }

    fn scroll_up(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_add(n);
        self.follow_tail = false;
    }

    fn scroll_down(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_sub(n);
        if self.scroll == 0 {
            self.follow_tail = true;
        }
    }

    fn scroll_to_top(&mut self) {
        self.scroll = usize::MAX; // the view clamps to the real maximum
        self.follow_tail = false;
    }

    fn scroll_to_bottom(&mut self) {
        self.scroll = 0;
        self.follow_tail = true;
    }

    fn submit(&mut self) {
        if let Some(text) = self.input.take() {
            self.chat.push(ChatMessage::text(Role::User, text.clone()));
            self.outbox = Some(text);
            self.scroll_to_bottom();
            // Submitting does not dismiss the overlay (US3 §6) — it arms the dismissal, so the
            // model's reply is what ends it (FR-019).
            if let Some(o) = &mut self.overlay {
                o.mark_superseded();
            }
        }
    }
}

/// The reducer: apply one [`Message`] to the model. Pure and total.
pub fn update(app: &mut App, msg: Message) {
    match msg {
        Message::Quit => app.should_quit = true,
        Message::Resize(cols, rows) => {
            app.size = (cols, rows);
            app.layout_mode = LayoutMode::from_size(cols, rows);
            app.invalidate_effects();
        }
        Message::Paste(s) => app.input.insert_str(&s),
        // Scrolling is focus-independent (010): the wheel and PgUp/PgDn move the chat flow whether
        // the operator is typing or reading, because neither is a text-editing gesture.
        Message::ScrollUp(n) => app.scroll_up(n as usize),
        Message::ScrollDown(n) => app.scroll_down(n as usize),
        Message::Tick | Message::Suspend | Message::Resume => {}
        Message::Key(key) => handle_key(app, key),
        Message::Session(ev) => handle_session(app, *ev),
    }
}

fn handle_key(app: &mut App, key: KeyEvent) {
    // A consent question outranks everything: `y` grants, `n` or Esc refuses, Ctrl-C still quits
    // (which refuses), and every other key is swallowed, so the input buffer is left as it was.
    if app.consent.is_some() {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let answer = match key.code {
            KeyCode::Char('c') if ctrl => {
                app.should_quit = true;
                Some(crate::operator::Decision::Denied)
            }
            KeyCode::Char('y' | 'Y') if !ctrl => Some(crate::operator::Decision::Granted),
            KeyCode::Char('n' | 'N') if !ctrl => Some(crate::operator::Decision::Denied),
            KeyCode::Esc => Some(crate::operator::Decision::Denied),
            _ => None,
        };
        if let Some(a) = answer {
            app.consent = None;
            app.consent_answer = Some(a);
        }
        return;
    }
    // The help overlay swallows input; `?` or Esc closes it.
    if app.help_open {
        if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc) {
            app.help_open = false;
        }
        return;
    }
    // An overlay is the most intrusive thing on screen, so Esc reaches it before focus dispatch —
    // the operator escapes a takeover from either focus, with one key, always (FR-016). It sits
    // *below* the help swallow (help is the more modal surface) and *above* the reserved Ctrl keys,
    // which keep their terminal meaning regardless.
    //
    // `q` is deliberately not bound: it keeps meaning quit in chat focus, so no key's
    // destructiveness depends on whether an overlay happens to be showing (research R6).
    if key.code == KeyCode::Esc {
        if let Some(o) = &mut app.overlay {
            o.dismiss(Instant::now());
            // Return before focus dispatch, so typed input survives the dismiss. A second Esc then
            // clears it as usual (US3 §2).
            return;
        }
    }
    // Reserved keys keep their terminal meaning in every focus (FR-017, contracts/keybindings.md).
    // Raw mode delivers them as key events rather than signals, so we re-create the semantics.
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            // SIGINT → clean quit (the loop restores on the way out).
            KeyCode::Char('c') => {
                app.should_quit = true;
                return;
            }
            // SIGTSTP → suspend; the loop leaves the alt-screen, re-raises, and redraws on resume.
            KeyCode::Char('z') => {
                app.suspend_requested = true;
                return;
            }
            // EOF quits, but only outside the input line (where it would eat a keystroke).
            KeyCode::Char('d') if app.focus != Focus::Input => {
                app.should_quit = true;
                return;
            }
            _ => {}
        }
    }
    if key.code == KeyCode::Tab {
        app.cycle_focus();
        return;
    }
    // Panels focus with no panels left (pruned, cleared, TTL'd) falls back to input rather than
    // routing keys at a region that isn't there.
    if app.focus == Focus::Panels && !app.panels_reachable() {
        app.focus = Focus::Input;
    }
    match app.focus {
        Focus::Input => handle_input_key(app, key),
        Focus::Chat => handle_chat_key(app, key),
        Focus::Panels => handle_panels_key(app, key),
    }
}

/// Keys while the panel column (or overlay) has focus: vertical selection, collapse, close.
fn handle_panels_key(app: &mut App, key: KeyEvent) {
    let len = app.panels.len();
    app.panel_sel = app.panel_sel.min(len.saturating_sub(1));
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') => app.help_open = true,
        KeyCode::Up | KeyCode::Char('k') => app.panel_sel = app.panel_sel.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            app.panel_sel = (app.panel_sel + 1).min(len.saturating_sub(1))
        }
        // Collapse is operator state: it survives the agent's upserts, so a panel the operator
        // folded away stays folded no matter how often its content refreshes.
        KeyCode::Char(' ') | KeyCode::Enter => app.panels.toggle_collapse_at(app.panel_sel),
        KeyCode::Char('x') => {
            app.panels.remove_at(app.panel_sel);
            if app.panels.is_empty() {
                // The region just vanished from under the focus.
                app.panels_visible = false;
                app.focus = Focus::Input;
            } else {
                app.panel_sel = app.panel_sel.min(app.panels.len() - 1);
            }
        }
        KeyCode::Char('i') => app.focus = Focus::Input,
        // Esc (or `p` where the overlay is what put panels on screen) leaves the region entirely.
        KeyCode::Char('p') | KeyCode::Esc => {
            app.panels_visible = false;
            app.focus = Focus::Input;
        }
        _ => {}
    }
}

fn handle_input_key(app: &mut App, key: KeyEvent) {
    let soft_newline =
        key.modifiers.contains(KeyModifiers::SHIFT) || key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Enter if soft_newline => app.input.newline(),
        KeyCode::Enter => app.submit(),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.input.insert_char(c)
        }
        KeyCode::Backspace => app.input.backspace(),
        KeyCode::Delete => app.input.delete(),
        KeyCode::Left => app.input.left(),
        KeyCode::Right => app.input.right(),
        KeyCode::Home => app.input.home(),
        KeyCode::End => app.input.end(),
        // Input history moved off the arrows (010). ↑/↓ now move within a soft-wrapped buffer when
        // there is a line to move to — which was previously impossible — and scroll the conversation
        // otherwise, so a single-line input always scrolls. Recall lives on the readline binding.
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.input.history_prev()
        }
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.input.history_next()
        }
        KeyCode::Up => {
            if !app.input.cursor_up() {
                app.scroll_up(1);
            }
        }
        KeyCode::Down => {
            if !app.input.cursor_down() {
                app.scroll_down(1);
            }
        }
        KeyCode::PageUp => app.scroll_up(10),
        KeyCode::PageDown => app.scroll_down(10),
        KeyCode::Esc => app.input.clear(),
        _ => {}
    }
}

fn handle_chat_key(app: &mut App, key: KeyEvent) {
    let was_g_pending = app.pending_g;
    app.pending_g = false;
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') => app.help_open = true,
        // Toggle the panel overlay (single-pane layouts, US3 T036). Bound in chat focus so `p` stays
        // an ordinary character while typing — the contract's "any" context, minus the input line.
        // Opening it moves focus to the panels: the overlay is what the operator just asked to
        // drive, and j/k/Space/x should work immediately rather than after a Tab.
        KeyCode::Char('p') => {
            app.panels_visible = !app.panels_visible;
            if app.panels_reachable() && app.panels_visible {
                app.focus = Focus::Panels;
            }
        }
        // Yank the newest prose message to the system clipboard via OSC 52 (FR-016, US3 T035).
        KeyCode::Char('y') => app.yank = app.newest_text(),
        // Esc closes the overlay first, before falling through to anything else.
        KeyCode::Esc if app.panels_visible => app.panels_visible = false,
        KeyCode::Char('i') | KeyCode::Enter => app.focus = Focus::Input,
        KeyCode::Char('g') => {
            if was_g_pending {
                app.scroll_to_top();
            } else {
                app.pending_g = true;
            }
        }
        KeyCode::Char('G') => app.scroll_to_bottom(),
        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(1),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(1),
        KeyCode::PageUp => app.scroll_up(10),
        KeyCode::PageDown => app.scroll_down(10),
        _ => {}
    }
}

/// The TUI's trust boundary for text, mirroring the inline REPL's (`repl::terminal`).
///
/// ratatui stores each grapheme as a cell symbol and flushes it to the terminal, so an ESC that
/// reaches the chat model reaches the terminal's parser too — the alternate screen is no shield.
/// Sanitizing here, where session events become chat messages, is the one choke point every
/// untrusted string passes through; styling and markdown rendering happen downstream, on clean text.
fn handle_session(app: &mut App, ev: SessionEvent) {
    use crate::safe_text::{safe_block, safe_line};

    // Every session event is data arriving; the header's working indicator phases off this count.
    app.activity = app.activity.wrapping_add(1);
    match ev {
        SessionEvent::AssistantDelta(s) => {
            let s = safe_block(&s).into_owned();
            // FR-019: the model's reply to a message the operator sent *since* the overlay appeared
            // dismisses it — the conversation has moved past what the overlay was showing. Prose
            // from the same turn that created it does not: an overlay is usually rendered by a tool
            // call whose explanation is still being written, and dismissing on that would make every
            // takeover vanish the instant the model finished describing it.
            if let Some(o) = &mut app.overlay {
                if o.superseded() {
                    o.dismiss(Instant::now());
                }
            }
            // Append to the currently-open assistant message, or start a new one.
            if let Some(last) = app.chat.last_mut() {
                if last.is_open_assistant() {
                    last.push_str(&s);
                    app.autoscroll();
                    return;
                }
            }
            app.chat.push(ChatMessage::text(Role::Assistant, s));
            app.turn = TurnState::Streaming;
            app.autoscroll();
        }
        // The prose block is finished: close it so the view renders it as markdown, and so the next
        // delta starts a fresh message rather than appending to a message the model has moved past.
        SessionEvent::AssistantEnd => {
            if let Some(last) = app.chat.last_mut() {
                if last.is_open_assistant() {
                    last.mark_done();
                }
            }
        }
        SessionEvent::ToolCall { name, arguments } => {
            app.push_line(
                Role::Tool,
                format!(
                    "▸ {}{}",
                    safe_line(&name),
                    safe_line(&compact_args(&arguments))
                ),
            );
        }
        SessionEvent::ToolResult { result, .. } => {
            let mark = if result.is_error { "✗" } else { "✓" };
            let line = safe_line(result.content.lines().next().unwrap_or_default());
            app.push_line(Role::Tool, format!("{mark} {line}"));
            // Flash the chat so the eye finds the result that belongs to the call above it — accent
            // for the ordinary case, the verdict colors when a run actually ended (FR-026).
            app.chrome_cues.push(if result.terminal {
                if result.is_error {
                    Chrome::EpisodeFail
                } else {
                    Chrome::EpisodePass
                }
            } else {
                Chrome::ToolResult
            });
        }
        SessionEvent::RenderWidget { spec, effect } => {
            app.chat.push(ChatMessage::widget_with_effect(spec, effect));
            app.autoscroll();
        }
        // A full-screen takeover (009 US3). It reached here only because the visual gate admitted
        // it — below `visual_level = takeover` this event is never emitted at all.
        SessionEvent::Overlay { spec, ttl_ms } => app.show_overlay(spec, ttl_ms, Instant::now()),
        // A targeted render: upsert into the panel column, never the chat flow (FR-008/009). Same id
        // replaces in place; the chat still shows the tool-result summary line separately.
        SessionEvent::PanelUpdate { id, spec } => app.panels.upsert(id, spec),
        // A lifecycle effect: create/replace (with an optional TTL), remove one, or clear them all.
        SessionEvent::PanelOp(op) => app.panels.apply(op),
        // Declared markdown (a skill's instructions): rendered styled, and never confused with the
        // Info lines around it, which are plain by nature.
        SessionEvent::Markdown(md) => {
            app.chat.push(ChatMessage::markdown(
                Role::System,
                safe_block(&md).into_owned(),
            ));
            app.autoscroll();
        }
        SessionEvent::Error(s) => app.push_line(Role::System, format!("error: {}", safe_block(&s))),
        SessionEvent::Info(s) | SessionEvent::Footer(s) | SessionEvent::Steering(s) => {
            app.push_line(Role::System, safe_block(&s).into_owned())
        }
        SessionEvent::Proxy(ev) => {
            app.push_line(Role::System, crate::repl::render_proxy_event(&ev))
        }
        // `/clear` dropped the model's message log; the pane holds the only other copy, so it goes
        // too (010). Panels are agent-owned view state rather than conversation, so they stay — the
        // command says "conversation history", and it means it.
        SessionEvent::Cleared => {
            app.chat.clear();
            app.scroll_to_bottom();
        }
        SessionEvent::TurnStarted => app.turn = TurnState::Streaming,
        SessionEvent::TurnDone => app.turn = TurnState::Idle,
    }
}

/// A compact one-line arg summary for a tool-call line (empty for no/`{}` args).
fn compact_args(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s == "{}" || s == "null" {
        String::new()
    } else {
        let short: String = s.chars().take(48).collect();
        format!(" {short}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new(120, 40)
    }

    fn type_str(a: &mut App, s: &str) {
        for c in s.chars() {
            update(a, Message::char(c));
        }
    }

    // ── 024 T059: the consent modal ─────────────────────────────────────────────────────────────

    use crate::operator::Decision;

    #[test]
    fn y_grants_and_closes_the_question() {
        let mut a = app();
        a.ask_consent(vec!["'w' requests extra capabilities:".into()]);
        update(&mut a, Message::char('y'));
        assert!(a.consent.is_none());
        assert_eq!(a.take_consent_answer(), Some(Decision::Granted));
        assert_eq!(a.take_consent_answer(), None, "an answer is taken once");
    }

    #[test]
    fn n_and_esc_refuse() {
        for msg in [
            Message::char('n'),
            Message::char('N'),
            Message::key(KeyCode::Esc),
        ] {
            let mut a = app();
            a.ask_consent(vec!["x".into()]);
            update(&mut a, msg);
            assert_eq!(a.take_consent_answer(), Some(Decision::Denied));
        }
    }

    #[test]
    fn the_question_swallows_other_keys_and_leaves_the_input_alone() {
        let mut a = app();
        type_str(&mut a, "half a thought");
        let before = a.input.text();
        a.ask_consent(vec!["x".into()]);
        for msg in [
            Message::char('q'),
            Message::char('x'),
            Message::key(KeyCode::Enter),
            Message::key(KeyCode::Backspace),
            Message::char('?'),
        ] {
            update(&mut a, msg);
        }
        assert!(a.consent.is_some(), "still asking");
        assert!(!a.should_quit && !a.help_open);
        assert_eq!(a.take_consent_answer(), None);
        assert_eq!(a.input.text(), before);
        assert!(a.outbox.is_none(), "Enter sent nothing");
    }

    #[test]
    fn ctrl_c_quits_and_refuses() {
        let mut a = app();
        a.ask_consent(vec!["x".into()]);
        update(&mut a, Message::char_mods('c', KeyModifiers::CONTROL));
        assert!(a.should_quit);
        assert_eq!(a.take_consent_answer(), Some(Decision::Denied));
    }

    #[test]
    fn typing_then_enter_submits_a_user_message_and_fills_outbox() {
        let mut a = app();
        type_str(&mut a, "hello");
        assert_eq!(a.input.text(), "hello");
        update(&mut a, Message::key(KeyCode::Enter));
        assert_eq!(a.take_outbox().as_deref(), Some("hello"));
        assert_eq!(a.chat.len(), 1);
        assert!(matches!(a.chat[0].role, Role::User));
        assert!(a.input.is_empty(), "input cleared after submit");
    }

    #[test]
    fn blank_submit_does_nothing() {
        let mut a = app();
        update(&mut a, Message::key(KeyCode::Enter));
        assert!(a.outbox.is_none());
        assert!(a.chat.is_empty());
    }

    #[test]
    fn shift_enter_inserts_a_newline_not_a_submit() {
        let mut a = app();
        type_str(&mut a, "a");
        update(
            &mut a,
            Message::key_mods(KeyCode::Enter, KeyModifiers::SHIFT),
        );
        type_str(&mut a, "b");
        assert_eq!(a.input.text(), "a\nb");
        assert!(a.outbox.is_none());
    }

    /// f040, TUI side: ratatui writes a cell's symbol straight to the terminal, so an ESC in the
    /// chat model is an ESC on the wire. Nothing untrusted may carry one into a message body.
    #[test]
    fn untrusted_session_text_reaches_the_chat_model_defanged() {
        use crate::tui::chat::Body;
        const ATTACK: &str = "ok\x1b[2J\x1b]0;pwned\x07\rDENIED nothing";

        let events = vec![
            SessionEvent::AssistantDelta(ATTACK.into()),
            SessionEvent::Markdown(ATTACK.into()),
            SessionEvent::Info(ATTACK.into()),
            SessionEvent::Error(ATTACK.into()),
            SessionEvent::ToolCall {
                name: ATTACK.into(),
                arguments: serde_json::json!({ "a": ATTACK }),
            },
            SessionEvent::ToolResult {
                result: crate::tools::ToolResult::ok(ATTACK),
                audit: Vec::new(),
            },
        ];
        let mut a = app();
        for ev in events {
            update(&mut a, Message::session(ev));
        }
        for msg in &a.chat {
            let (Body::Text(t) | Body::Markdown(t)) = &msg.body else {
                continue;
            };
            assert!(
                !t.chars().any(|c| c.is_control() && c != '\n'),
                "control character reached the chat model: {t:?}"
            );
            assert!(t.contains("\\x1b"), "text was dropped instead: {t:?}");
        }
    }

    #[test]
    fn streaming_deltas_coalesce_into_one_assistant_message() {
        let mut a = app();
        update(
            &mut a,
            Message::session(SessionEvent::AssistantDelta("Hel".into())),
        );
        update(
            &mut a,
            Message::session(SessionEvent::AssistantDelta("lo".into())),
        );
        assert_eq!(a.chat.len(), 1);
        assert!(matches!(a.chat[0].role, Role::Assistant));
        assert_eq!(a.turn, TurnState::Streaming);
        update(&mut a, Message::session(SessionEvent::TurnDone));
        assert_eq!(a.turn, TurnState::Idle);
    }

    #[test]
    fn tab_cycles_focus_and_ctrl_c_quits() {
        let mut a = app();
        assert_eq!(a.focus, Focus::Input);
        update(&mut a, Message::key(KeyCode::Tab));
        assert_eq!(a.focus, Focus::Chat);
        update(&mut a, Message::char_mods('c', KeyModifiers::CONTROL));
        assert!(a.should_quit);
    }

    #[test]
    fn tab_reaches_panels_only_when_they_are_on_screen() {
        // No panels: the cycle is input · chat, exactly as before panels focus existed.
        let mut bare = App::new(120, 24);
        update(&mut bare, Message::key(KeyCode::Tab));
        assert_eq!(bare.focus, Focus::Chat);
        update(&mut bare, Message::key(KeyCode::Tab));
        assert_eq!(bare.focus, Focus::Input);

        // A populated TwoPane column joins the cycle.
        let mut with = App::new(120, 24);
        with.panels
            .upsert("m", crate::render_spec::RenderSpec::Separator);
        update(&mut with, Message::key(KeyCode::Tab));
        assert_eq!(with.focus, Focus::Chat);
        update(&mut with, Message::key(KeyCode::Tab));
        assert_eq!(with.focus, Focus::Panels);
        update(&mut with, Message::key(KeyCode::Tab));
        assert_eq!(with.focus, Focus::Input);

        // SinglePane with the overlay closed: panels are off screen, so Tab skips them.
        let mut narrow = App::new(80, 24);
        narrow
            .panels
            .upsert("m", crate::render_spec::RenderSpec::Separator);
        update(&mut narrow, Message::key(KeyCode::Tab));
        update(&mut narrow, Message::key(KeyCode::Tab));
        assert_eq!(narrow.focus, Focus::Input);
    }

    #[test]
    fn panels_focus_selects_collapses_and_closes() {
        let mut a = App::new(120, 24);
        a.panels
            .upsert("one", crate::render_spec::RenderSpec::Separator);
        a.panels
            .upsert("two", crate::render_spec::RenderSpec::Separator);
        update(&mut a, Message::key(KeyCode::Tab));
        update(&mut a, Message::key(KeyCode::Tab));
        assert_eq!(a.focus, Focus::Panels);

        // j moves the selection down, k back up, both clamped.
        update(&mut a, Message::char('j'));
        assert_eq!(a.panel_sel, 1);
        update(&mut a, Message::char('j'));
        assert_eq!(a.panel_sel, 1, "clamped at the last panel");
        update(&mut a, Message::char('k'));
        assert_eq!(a.panel_sel, 0);

        // Space folds the selected panel; a fresh upsert must not unfold it (operator state).
        update(&mut a, Message::char(' '));
        assert!(a.panels.iter_panels().next().unwrap().collapsed);
        a.panels
            .upsert("one", crate::render_spec::RenderSpec::Separator);
        assert!(
            a.panels.iter_panels().next().unwrap().collapsed,
            "an agent upsert cannot unfold what the operator folded"
        );

        // x closes the selected panel; closing the last one returns focus to input.
        update(&mut a, Message::char('x'));
        assert_eq!(a.panels.len(), 1);
        assert_eq!(a.focus, Focus::Panels);
        update(&mut a, Message::char('x'));
        assert!(a.panels.is_empty());
        assert_eq!(a.focus, Focus::Input);
    }

    #[test]
    fn opening_the_overlay_focuses_panels_and_esc_leaves() {
        let mut a = App::new(80, 24); // SinglePane
        a.panels
            .upsert("m", crate::render_spec::RenderSpec::Separator);
        update(&mut a, Message::key(KeyCode::Tab)); // chat focus, where `p` lives
        update(&mut a, Message::char('p'));
        assert!(a.panels_visible);
        assert_eq!(a.focus, Focus::Panels, "the overlay opens ready to drive");
        update(&mut a, Message::key(KeyCode::Esc));
        assert!(!a.panels_visible);
        assert_eq!(a.focus, Focus::Input);
    }

    #[test]
    fn q_quits_from_chat_but_types_in_input() {
        let mut a = app();
        // In input focus, 'q' is text.
        update(&mut a, Message::char('q'));
        assert_eq!(a.input.text(), "q");
        assert!(!a.should_quit);
        // In chat focus, 'q' quits.
        a.input.clear();
        update(&mut a, Message::key(KeyCode::Tab));
        update(&mut a, Message::char('q'));
        assert!(a.should_quit);
    }

    #[test]
    fn help_overlay_toggles_and_swallows_keys() {
        let mut a = app();
        update(&mut a, Message::key(KeyCode::Tab)); // focus Chat
        update(&mut a, Message::char('?'));
        assert!(a.help_open);
        update(&mut a, Message::char('q')); // swallowed by help, not a quit
        assert!(!a.should_quit);
        update(&mut a, Message::key(KeyCode::Esc));
        assert!(!a.help_open);
    }

    #[test]
    fn scrolling_breaks_and_restores_tail_follow() {
        let mut a = app();
        update(&mut a, Message::key(KeyCode::Tab)); // Chat focus
        update(&mut a, Message::key(KeyCode::PageUp));
        assert!(!a.follow_tail);
        assert_eq!(a.scroll, 10);
        // gg jumps to top.
        update(&mut a, Message::char('g'));
        update(&mut a, Message::char('g'));
        assert_eq!(a.scroll, usize::MAX);
        // G returns to the bottom and re-follows.
        update(&mut a, Message::char('G'));
        assert_eq!(a.scroll, 0);
        assert!(a.follow_tail);
    }

    // --- 010: scrolling from the input line, the wheel, and /clear ------------------------------

    #[test]
    fn the_arrows_scroll_the_chat_from_the_input_line() {
        // The reported bug: ↑ from the input (the default focus) walked input history instead of
        // moving the conversation, and the scroll keys were reachable only after Tab.
        let mut a = app();
        assert_eq!(a.focus, Focus::Input);
        update(&mut a, Message::key(KeyCode::Up));
        assert_eq!(a.scroll, 1);
        assert!(!a.follow_tail);
        update(&mut a, Message::key(KeyCode::PageUp));
        assert_eq!(a.scroll, 11);
        update(&mut a, Message::key(KeyCode::PageDown));
        update(&mut a, Message::key(KeyCode::Down));
        assert_eq!(a.scroll, 0);
        assert!(a.follow_tail, "back at the bottom the view follows again");
    }

    #[test]
    fn the_arrows_move_within_a_multi_line_input_before_they_scroll() {
        let mut a = app();
        type_str(&mut a, "one");
        update(
            &mut a,
            Message::key_mods(KeyCode::Enter, KeyModifiers::SHIFT),
        );
        type_str(&mut a, "two");
        assert!(a.input.is_multiline());

        update(&mut a, Message::key(KeyCode::Up));
        assert_eq!(a.input.line_col(), (0, 3), "moved inside the buffer");
        assert!(a.follow_tail, "moving the cursor is not scrolling");

        // Nowhere left to go inside the buffer, so the same key now scrolls.
        update(&mut a, Message::key(KeyCode::Up));
        assert_eq!(a.input.line_col(), (0, 3));
        assert_eq!(a.scroll, 1);
    }

    #[test]
    fn ctrl_p_and_n_walk_the_input_history_now_that_the_arrows_do_not() {
        let mut a = app();
        type_str(&mut a, "first");
        update(&mut a, Message::key(KeyCode::Enter));
        type_str(&mut a, "second");
        update(&mut a, Message::key(KeyCode::Enter));
        assert!(a.input.is_empty());

        update(&mut a, Message::char_mods('p', KeyModifiers::CONTROL));
        assert_eq!(a.input.text(), "second");
        update(&mut a, Message::char_mods('p', KeyModifiers::CONTROL));
        assert_eq!(a.input.text(), "first");
        update(&mut a, Message::char_mods('n', KeyModifiers::CONTROL));
        assert_eq!(a.input.text(), "second");

        update(&mut a, Message::key(KeyCode::Up));
        assert_eq!(a.input.text(), "second", "↑ scrolled; it did not recall");
        assert_eq!(a.scroll, 1);
    }

    #[test]
    fn the_wheel_scrolls_from_either_focus() {
        let mut a = app();
        update(&mut a, Message::ScrollUp(3));
        assert_eq!(a.scroll, 3);
        assert!(!a.follow_tail);
        update(&mut a, Message::key(KeyCode::Tab));
        assert_eq!(a.focus, Focus::Chat);
        update(&mut a, Message::ScrollUp(3));
        assert_eq!(a.scroll, 6, "the wheel is focus-independent");
        update(&mut a, Message::ScrollDown(6));
        assert_eq!(a.scroll, 0);
        assert!(a.follow_tail);
    }

    #[test]
    fn clearing_the_conversation_empties_the_chat_pane() {
        // The reported bug: /clear emptied the model's message log and said so, but the pane went on
        // showing the whole conversation.
        let mut a = app();
        type_str(&mut a, "hello");
        update(&mut a, Message::key(KeyCode::Enter));
        update(
            &mut a,
            Message::session(SessionEvent::AssistantDelta("hi".into())),
        );
        a.panels.upsert("m", RenderSpec::Separator);
        update(&mut a, Message::ScrollUp(5));
        assert!(!a.chat.is_empty());

        update(&mut a, Message::session(SessionEvent::Cleared));
        assert!(a.chat.is_empty(), "the pane holds the only other copy");
        assert_eq!(a.scroll, 0);
        assert!(a.follow_tail);
        assert_eq!(
            a.panels.len(),
            1,
            "panels are agent-owned view state, not conversation"
        );
    }

    // --- US3 (T035/T036): overlay toggle, yank, and reserved keys -------------------------------

    #[test]
    fn p_toggles_the_panel_overlay_from_chat_but_types_in_input() {
        let mut a = app();
        // In input focus 'p' is just text.
        update(&mut a, Message::char('p'));
        assert_eq!(a.input.text(), "p");
        assert!(!a.panels_visible);

        a.input.clear();
        update(&mut a, Message::key(KeyCode::Tab)); // chat focus
        update(&mut a, Message::char('p'));
        assert!(a.panels_visible, "p opens the overlay");
        update(&mut a, Message::char('p'));
        assert!(!a.panels_visible, "p closes it again");
    }

    #[test]
    fn esc_closes_the_overlay() {
        let mut a = app();
        update(&mut a, Message::key(KeyCode::Tab));
        update(&mut a, Message::char('p'));
        update(&mut a, Message::key(KeyCode::Esc));
        assert!(!a.panels_visible);
    }

    #[test]
    fn overlay_open_requires_single_pane_and_content() {
        let mut a = App::new(80, 24); // SinglePane
        a.panels_visible = true;
        assert!(!a.overlay_open(), "nothing to show with no panels");
        a.panels.upsert("m", text_spec("x"));
        assert!(a.overlay_open());

        let mut wide = App::new(140, 40); // TwoPane — panels have their own column
        wide.panels_visible = true;
        wide.panels.upsert("m", text_spec("x"));
        assert!(!wide.overlay_open());
    }

    #[test]
    fn y_yanks_the_newest_prose_message() {
        let mut a = app();
        a.chat.push(ChatMessage::text(Role::User, "first"));
        a.chat.push(ChatMessage::text(Role::Assistant, "second"));
        update(&mut a, Message::key(KeyCode::Tab)); // chat focus
        update(&mut a, Message::char('y'));
        assert_eq!(a.take_yank().as_deref(), Some("second"));
        assert!(a.take_yank().is_none(), "taking drains it");
    }

    #[test]
    fn y_skips_widgets_which_have_no_text_form() {
        let mut a = app();
        a.chat.push(ChatMessage::text(Role::Assistant, "prose"));
        a.chat.push(ChatMessage::widget(text_spec("a widget")));
        update(&mut a, Message::key(KeyCode::Tab));
        update(&mut a, Message::char('y'));
        assert_eq!(a.take_yank().as_deref(), Some("prose"));
    }

    #[test]
    fn ctrl_z_requests_suspend_without_quitting() {
        let mut a = app();
        update(&mut a, Message::char_mods('z', KeyModifiers::CONTROL));
        assert!(!a.should_quit, "suspend is not a quit");
        assert!(a.take_suspend(), "the loop is told to suspend");
        assert!(!a.take_suspend(), "taking drains it");
    }

    #[test]
    fn ctrl_d_quits_outside_the_input_line_only() {
        // In input focus Ctrl-D must not end the session mid-typing.
        let mut a = app();
        update(&mut a, Message::char_mods('d', KeyModifiers::CONTROL));
        assert!(!a.should_quit);

        update(&mut a, Message::key(KeyCode::Tab)); // chat focus
        update(&mut a, Message::char_mods('d', KeyModifiers::CONTROL));
        assert!(a.should_quit);
    }

    #[test]
    fn resize_updates_layout_mode() {
        let mut a = app();
        assert_eq!(a.layout_mode, LayoutMode::TwoPane);
        update(&mut a, Message::Resize(90, 30));
        assert_eq!(a.layout_mode, LayoutMode::SinglePane);
        update(&mut a, Message::Resize(30, 8));
        assert_eq!(a.layout_mode, LayoutMode::TooSmall);
    }

    // --- US2 (T021): panel routing + upsert through the reducer ---------------------------------

    fn text_spec(s: &str) -> crate::render_spec::RenderSpec {
        crate::render_spec::RenderSpec::Text {
            content: s.into(),
            style: None,
            bold: false,
            dim: false,
        }
    }

    #[test]
    fn panel_update_upserts_into_panels_not_chat() {
        let mut a = app();
        update(
            &mut a,
            Message::session(SessionEvent::PanelUpdate {
                id: "metrics".into(),
                spec: text_spec("v1"),
            }),
        );
        // A targeted render populates the panel column and leaves chat untouched (FR-008).
        assert_eq!(a.panels.len(), 1);
        assert_eq!(a.panels.get("metrics"), Some(&text_spec("v1")));
        assert!(a.chat.is_empty(), "panel render must not append to chat");
    }

    #[test]
    fn re_rendering_a_panel_replaces_in_place_no_duplicate() {
        let mut a = app();
        for v in ["v1", "v2", "v3"] {
            update(
                &mut a,
                Message::session(SessionEvent::PanelUpdate {
                    id: "metrics".into(),
                    spec: text_spec(v),
                }),
            );
        }
        assert_eq!(
            a.panels.len(),
            1,
            "same id replaces — exactly one panel (SC-008)"
        );
        assert_eq!(a.panels.get("metrics"), Some(&text_spec("v3")));
    }

    #[test]
    fn panel_ops_remove_and_clear_through_the_reducer() {
        use crate::render_spec::PanelOp;
        let mut a = app();
        for id in ["a", "b", "c"] {
            update(
                &mut a,
                Message::session(SessionEvent::PanelOp(PanelOp::Upsert {
                    id: id.into(),
                    spec: text_spec("x"),
                    ttl_ms: None,
                    effect: None,
                })),
            );
        }
        assert_eq!(a.panels.len(), 3);

        update(
            &mut a,
            Message::session(SessionEvent::PanelOp(PanelOp::Remove { id: "b".into() })),
        );
        assert_eq!(a.panels.len(), 2);
        assert!(a.panels.get("b").is_none(), "removed panel is gone");

        update(
            &mut a,
            Message::session(SessionEvent::PanelOp(PanelOp::Clear)),
        );
        assert!(a.panels.is_empty(), "clear reclaims the whole column");
    }

    #[test]
    fn inline_render_goes_to_chat_not_panels() {
        let mut a = app();
        update(
            &mut a,
            Message::session(SessionEvent::RenderWidget {
                spec: text_spec("inline"),
                effect: None,
            }),
        );
        assert_eq!(a.chat.len(), 1, "inline render appends a chat widget");
        assert!(a.panels.is_empty(), "inline render never touches panels");
    }
    // --- 009 US3: the takeover the operator can always escape -----------------------------------

    fn takeover(a: &mut App, ttl_ms: Option<u32>) {
        update(
            a,
            Message::session(SessionEvent::Overlay {
                spec: text_spec("chart"),
                ttl_ms,
            }),
        );
    }

    #[test]
    fn esc_dismisses_the_takeover_and_leaves_typed_text_alone() {
        // FR-016 / US3 §2. The operator escaping a takeover must not also lose the sentence they
        // were in the middle of writing — that would make Esc a key you hesitate over.
        let mut a = app();
        type_str(&mut a, "half a thought");
        takeover(&mut a, None);
        assert!(a.overlay_active());

        update(&mut a, Message::key(KeyCode::Esc));
        assert_eq!(a.input.text(), "half a thought", "the text survives");
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Dismissing),
            "one keypress starts the fade-out"
        );

        // The second Esc does what Esc always did.
        a.overlay = None;
        update(&mut a, Message::key(KeyCode::Esc));
        assert!(a.input.is_empty(), "and then clears the input as usual");
    }

    #[test]
    fn esc_dismisses_from_chat_focus_too() {
        let mut a = app();
        takeover(&mut a, None);
        update(&mut a, Message::key(KeyCode::Tab)); // chat focus
        update(&mut a, Message::key(KeyCode::Esc));
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Dismissing)
        );
    }

    #[test]
    fn esc_with_no_takeover_still_clears_input_and_still_hides_panels() {
        // A regression guard on 008: adding a higher-precedence Esc must not change what Esc does
        // when there is no overlay to dismiss.
        let mut a = app();
        type_str(&mut a, "text");
        update(&mut a, Message::key(KeyCode::Esc));
        assert!(a.input.is_empty());

        let mut b = App::new(80, 24);
        b.panels.upsert("m", text_spec("x"));
        b.panels_visible = true;
        update(&mut b, Message::key(KeyCode::Tab));
        update(&mut b, Message::key(KeyCode::Esc));
        assert!(!b.panels_visible);
    }

    #[test]
    fn help_outranks_the_takeover_because_it_is_the_more_modal_surface() {
        let mut a = app();
        takeover(&mut a, None);
        a.help_open = true;
        update(&mut a, Message::key(KeyCode::Esc));
        assert!(!a.help_open, "help closes first");
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Entering),
            "the takeover is untouched"
        );
    }

    #[test]
    fn q_is_not_a_dismiss_key() {
        // Research R6: `q` keeps meaning quit in chat focus, so no key's destructiveness depends on
        // whether an overlay happens to be showing.
        let mut a = app();
        takeover(&mut a, None);
        update(&mut a, Message::key(KeyCode::Tab)); // chat focus
        update(&mut a, Message::char('q'));
        assert!(a.should_quit, "q still quits");
    }

    #[test]
    fn submitting_keeps_the_takeover_and_the_models_reply_ends_it() {
        // US3 §6 and FR-019 are the two halves of one rule: the operator can keep working while an
        // overlay is up, and the conversation moving on is what retires it.
        let mut a = app();
        takeover(&mut a, None);
        type_str(&mut a, "what about q99?");
        update(&mut a, Message::key(KeyCode::Enter));
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Entering),
            "submitting does not dismiss it"
        );

        update(
            &mut a,
            Message::session(SessionEvent::AssistantDelta("looking".into())),
        );
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Dismissing),
            "the reply to that message does"
        );
    }

    #[test]
    fn same_turn_prose_leaves_the_takeover_alone() {
        // An overlay is rendered by a tool call whose explanation is still being written. Dismissing
        // on that prose would make every takeover vanish the instant it was described.
        let mut a = app();
        takeover(&mut a, None);
        update(
            &mut a,
            Message::session(SessionEvent::AssistantDelta("here is the chart".into())),
        );
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Entering)
        );
    }

    #[test]
    fn a_second_takeover_replaces_the_first_rather_than_stacking() {
        // FR-020, enforced structurally: `App` holds one `Option`, so there is nowhere for a second
        // overlay to live except queued inside the first.
        let mut a = app();
        takeover(&mut a, None);
        takeover(&mut a, Some(5_000));
        assert_eq!(
            a.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Dismissing),
            "the first one is on its way out"
        );
    }

    #[test]
    fn the_chat_scroll_position_survives_the_whole_takeover_cycle() {
        // FR-018: the chat comes back exactly as the operator left it. Nothing in the overlay path
        // touches `scroll`, and this is the test that keeps it that way.
        let mut a = app();
        for i in 0..40 {
            a.push_line(Role::Assistant, format!("line {i}"));
        }
        update(&mut a, Message::key(KeyCode::Tab));
        update(&mut a, Message::key(KeyCode::Up));
        update(&mut a, Message::key(KeyCode::Up));
        let scrolled = a.scroll;
        assert!(scrolled > 0, "scrolled up from the tail");

        takeover(&mut a, Some(1_000));
        assert_eq!(a.scroll, scrolled, "unchanged while the overlay is up");
        update(&mut a, Message::key(KeyCode::Esc));
        a.overlay = None;
        assert_eq!(a.scroll, scrolled, "and unchanged after it leaves");
    }

    #[test]
    fn a_resize_cancels_transitions_rather_than_playing_them_at_stale_coordinates() {
        // Spec edge case. An effect is pinned to the Rect it was registered with, so after a resize
        // it would paint over the wrong cells.
        let mut a = app();
        a.panels.upsert("m", text_spec("x"));
        let area = ratatui::layout::Rect::new(0, 0, 20, 5);
        crate::tui::effects::apply(
            &mut a.effects,
            Some("m"),
            &crate::tui::effects::panel_enter_spec(),
            &crate::tui::effects::ResolveCtx {
                color: true,
                ..crate::tui::effects::ResolveCtx::agent(a.visual, area)
            },
        );
        assert!(a.effects.is_running());

        update(&mut a, Message::Resize(100, 30));
        let mut buf = ratatui::buffer::Buffer::empty(area);
        a.effects.process(Duration::from_millis(16), &mut buf, area);
        assert!(!a.effects.is_running(), "no transition outlives the resize");
    }
}
