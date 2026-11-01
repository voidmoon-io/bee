//! The default [`ReplOutput`](super::ReplOutput): renders the session through a rustyline
//! [`ExternalPrinter`](rustyline::ExternalPrinter) so agent output scrolls *above* the live input
//! line without corrupting whatever the user is typing (which is what lets streaming output and
//! concurrent steering input coexist).
//!
//! Color is inline escapes (no color crate) and is suppressed when `NO_COLOR` is set (per
//! <https://no-color.org>). Assistant prose streams in, word-wrapped a line at a time as it
//! arrives; tool calls and results are indented and tagged; audit denials are called out in bold
//! red; a dim footer summarizes each exchange.
//!
//! **Every text method of the [`ReplOutput`] impl below sanitizes its input** through
//! [`crate::safe_text`] before doing anything else. This is the trust boundary: what arrives here is
//! model prose, tool output, and audit targets — attacker-reachable text that a terminal would
//! otherwise read as a command language and use to erase, rewrite, or forge what the operator sees.
//! Escaping happens first and painting second, so bee's own SGR sequences are always added to
//! already-clean text and nothing the harness draws is ever escaped.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bee_core::AuditEvent;
use rustyline::ExternalPrinter;
use tokio::task::JoinHandle;

use super::ReplOutput;
use crate::render_spec::{AnimationSpec, EffectSpec, RenderSpec};
use crate::safe_text::{safe_block, safe_line};
use crate::tools::ToolResult;
use crate::viz::theme::Role;
use crate::viz::{animator, glyph, palette, sprite_render};

#[cfg(feature = "durable-sessions")]
pub(super) struct PipePrinter;
#[cfg(feature = "durable-sessions")]
impl ExternalPrinter for PipePrinter {
    fn print(&mut self, msg: String) -> rustyline::Result<()> {
        use std::io::Write;
        std::io::stdout().lock().write_all(msg.as_bytes())?;
        Ok(())
    }
}

/// The kind of element occupying the single "active animated element" slot (FR-031).
const KIND_NONE: u8 = 0;
const KIND_SPINNER: u8 = 1;
const KIND_ANIM: u8 = 2;

/// Width to word-wrap assistant prose to.
const WRAP_WIDTH: usize = 88;
/// Max lines of a single tool result to print before eliding the rest.
const MAX_RESULT_LINES: usize = 40;
/// Max characters of a tool call's argument JSON to show on the call line.
const MAX_ARG_CHARS: usize = 100;
/// How often the "working" spinner advances a frame.
const SPINNER_INTERVAL: Duration = Duration::from_millis(90);
/// Braille spinner frames.
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A shared handle to the external printer — shared between the render path and the spinner task.
type SharedPrinter = Arc<Mutex<Box<dyn ExternalPrinter + Send>>>;

/// Render one spinner frame's text (dim when color is on). `tick` selects the glyph; once a second
/// has passed, the elapsed time is appended so a long wait reads as progress, not a hang.
fn spinner_frame(tick: u64, start: Instant, color: bool) -> String {
    let glyph = SPINNER_FRAMES[(tick as usize) % SPINNER_FRAMES.len()];
    let elapsed = start.elapsed().as_secs_f64();
    let text = if elapsed >= 1.0 {
        format!("{glyph} thinking… {elapsed:.1}s")
    } else {
        format!("{glyph} thinking…")
    };
    if color {
        format!("\x1b[2m{text}\x1b[0m")
    } else {
        text
    }
}

/// The mutable state of the in-progress streamed assistant paragraph. Deltas arrive a few tokens at
/// a time; we buffer the current visual line and emit it (wrapped) as soon as it fills or a newline
/// lands, so prose appears line-by-line as the model generates it.
#[derive(Default)]
struct StreamState {
    /// Whether the leading blank separator line for this assistant block has been printed.
    started: bool,
    /// The current, not-yet-emitted visual line (never contains `\n`, kept within `WRAP_WIDTH`).
    line: String,
}

/// Writes the REPL through a rustyline external printer (with ANSI color unless `NO_COLOR` is set).
pub struct TerminalOutput {
    color: bool,
    printer: SharedPrinter,
    stream: Mutex<StreamState>,
    /// Whether the single animated element (spinner **or** sprite animation) is running — shared with
    /// the background task, which stops when it clears (FR-031: only one at a time).
    spinning: Arc<AtomicBool>,
    /// Which element occupies the slot: [`KIND_NONE`] / [`KIND_SPINNER`] / [`KIND_ANIM`].
    kind: Arc<AtomicU8>,
    /// How many terminal rows the active element drew (1 for the spinner, `⌈H/2⌉` for an animation) —
    /// read when it stops to set [`Self::reclaim_rows`].
    active_rows: Arc<AtomicUsize>,
    /// Rows the next emitted line must reclaim in place (0 = none). Generalizes the spinner's
    /// single-row reclaim to `N` rows (research D14); `N = 1` reproduces the legacy byte sequence.
    reclaim_rows: Arc<AtomicUsize>,
    /// The running spinner/animation task, if any.
    spin_task: Mutex<Option<JoinHandle<()>>>,
}

impl TerminalOutput {
    /// Build a terminal output over an external printer taken from the active editor. Honors
    /// `NO_COLOR` (any value ⇒ no escapes).
    pub fn new(printer: Box<dyn ExternalPrinter + Send>) -> Self {
        TerminalOutput {
            color: std::env::var_os("NO_COLOR").is_none(),
            printer: Arc::new(Mutex::new(printer)),
            stream: Mutex::new(StreamState::default()),
            spinning: Arc::new(AtomicBool::new(false)),
            kind: Arc::new(AtomicU8::new(KIND_NONE)),
            active_rows: Arc::new(AtomicUsize::new(0)),
            reclaim_rows: Arc::new(AtomicUsize::new(0)),
            spin_task: Mutex::new(None),
        }
    }

    /// Paint `text` in a semantic [`Role`] from the active theme, honoring this output's color
    /// decision (made once at construction). Replaces the 003 `paint(code, …)` — the color role is
    /// now in the name, not a magic SGR string (005-themes, FR-044/FR-027).
    fn role(&self, role: Role, text: &str) -> String {
        palette::role_if(self.color, role, text)
    }

    /// Print one line above the input line. A trailing newline is added; the external printer
    /// redraws the prompt beneath it. If a spinner row is pending reclaim, the line reuses that row
    /// in place (cursor up + clear) so no "thinking…" residue is left behind. Printer errors are
    /// swallowed — a REPL should not abort a session because one line failed to render.
    fn emit(&self, line: &str) {
        if let Ok(mut p) = self.printer.lock() {
            let _ =
                p.print(reclaim_prefix(self.reclaim_rows.swap(0, Ordering::SeqCst)) + line + "\n");
        }
    }

    /// Emit a multi-row block (a sprite frame): the first row honors a pending reclaim, the rest print
    /// plainly beneath it.
    fn emit_block(&self, rows: &[String]) {
        if rows.is_empty() {
            return;
        }
        if let Ok(mut p) = self.printer.lock() {
            let mut out = reclaim_prefix(self.reclaim_rows.swap(0, Ordering::SeqCst));
            out.push_str(&rows[0]);
            out.push('\n');
            for r in &rows[1..] {
                out.push_str(r);
                out.push('\n');
            }
            let _ = p.print(out);
        }
    }

    /// Stop whatever animated element is active (spinner or animation), leaving its rows reclaimable
    /// by the next emitted line. Idempotent when nothing is active.
    fn stop_active(&self) {
        if self.kind.swap(KIND_NONE, Ordering::SeqCst) == KIND_NONE {
            return;
        }
        self.spinning.store(false, Ordering::SeqCst);
        self.reclaim_rows
            .store(self.active_rows.load(Ordering::SeqCst), Ordering::SeqCst);
        if let Some(h) = self.spin_task.lock().expect("spin task").take() {
            h.abort();
        }
    }

    /// Start playing a sprite [`AnimationSpec`] in place (Slice 2, FR-030): pre-render the frames, emit
    /// frame 0, then drive the rest from a background task via the pure [`animator`] seam. Claims the
    /// single active slot, stopping any spinner/animation first (FR-031).
    fn start_animation(&self, spec: &AnimationSpec) {
        self.stop_active(); // FR-031 + SC-017: preempt a running spinner/animation
        if spec.frames.is_empty() {
            return;
        }
        let (_, tty) = crate::viz::terminal_dims();
        let mode = sprite_render::detect_color_mode();
        let color = self.color && tty;
        let frames: Vec<Vec<String>> = spec
            .frames
            .iter()
            .map(|f| sprite_render::render_frame_with(f, mode, color))
            .collect();
        let n_rows = frames.first().map(|f| f.len()).unwrap_or(0);
        if n_rows == 0 {
            return;
        }
        self.spinning.store(true, Ordering::SeqCst);
        self.kind.store(KIND_ANIM, Ordering::SeqCst);
        self.active_rows.store(n_rows, Ordering::SeqCst);
        self.emit_block(&frames[0]); // instant first paint

        let seq = animator::playback(spec);
        let repeat = spec.cycles == 0;
        let interval = Duration::from_millis(spec.interval_ms.clamp(50, 1000));
        let printer = self.printer.clone();
        let spinning = self.spinning.clone();
        let kind = self.kind.clone();
        let active_rows = self.active_rows.clone();
        let reclaim_rows = self.reclaim_rows.clone();
        let handle = tokio::spawn(async move {
            'outer: loop {
                for &idx in seq.iter().skip(1) {
                    tokio::time::sleep(interval).await;
                    let Ok(mut p) = printer.lock() else {
                        break 'outer;
                    };
                    if !spinning.load(Ordering::SeqCst) {
                        break 'outer;
                    }
                    let _ = p.print(animator::redraw_block(&frames[idx]));
                    drop(p);
                }
                if !repeat || !spinning.load(Ordering::SeqCst) {
                    break;
                }
            }
            // Natural completion: mark the drawn rows reclaimable and release the slot.
            if kind.swap(KIND_NONE, Ordering::SeqCst) != KIND_NONE {
                spinning.store(false, Ordering::SeqCst);
                reclaim_rows.store(active_rows.load(Ordering::SeqCst), Ordering::SeqCst);
            }
        });
        *self.spin_task.lock().expect("spin task") = Some(handle);
    }

    /// Emit the current buffered assistant line and clear it.
    fn flush_line(&self, st: &mut StreamState) {
        let line = std::mem::take(&mut st.line);
        self.emit(&line);
    }
}

/// Display width of a string in columns (char count; good enough for wrap decisions on prose).
fn width(s: &str) -> usize {
    s.chars().count()
}

/// The cursor sequence that makes an emitted line reclaim `n` drawn rows in place. `n == 1` reproduces
/// the legacy spinner bytes exactly (regression gate, SC-012); `n > 1` erases the block to end of
/// screen (the printer redraws the prompt beneath).
fn reclaim_prefix(n: usize) -> String {
    match n {
        0 => String::new(),
        1 => "\x1b[1A\r\x1b[2K".to_string(),
        k => format!("\x1b[{k}A\r\x1b[0J"),
    }
}

impl ReplOutput for TerminalOutput {
    fn assistant_delta(&self, chunk: &str) {
        // Prose, so newlines are data; every other control is not. Sanitizing per chunk is safe
        // because an escape sequence split across two chunks is still escaped character by
        // character — the ESC alone is enough to defang the sequence.
        let chunk = safe_block(chunk);
        let mut st = self.stream.lock().expect("stream state");
        if !st.started {
            self.emit(""); // blank separator before the assistant block
            st.started = true;
        }
        for c in chunk.chars() {
            if c == '\n' {
                self.flush_line(&mut st);
                continue;
            }
            st.line.push(c);
            if width(&st.line) > WRAP_WIDTH {
                // Greedy wrap: break at the last space, else hard-break an over-long word.
                if let Some(sp) = st.line.rfind(' ') {
                    let tail = st.line[sp + 1..].to_string();
                    st.line.truncate(sp);
                    self.flush_line(&mut st);
                    st.line = tail;
                } else {
                    self.flush_line(&mut st);
                }
            }
        }
    }

    fn assistant_end(&self) {
        let mut st = self.stream.lock().expect("stream state");
        if !st.line.is_empty() {
            self.flush_line(&mut st);
        }
        st.started = false;
    }

    fn tool_event(&self, event: &crate::repl::presentation::CallEvent) {
        for line in safe_block(&event.text()).lines() {
            self.emit(line);
        }
    }

    fn tool_call(&self, name: &str, arguments: &serde_json::Value) {
        let args = clip(&safe_line(&arguments.to_string()), MAX_ARG_CHARS);
        let name = safe_line(name);
        let line = format!("  {} {name} {args}", glyph::ARROW);
        self.emit(&self.role(Role::Dim, &line)); // dim
    }

    fn tool_result(&self, result: &ToolResult, audit: &[AuditEvent]) {
        let (mark, role) = if result.is_error {
            (glyph::CROSS, Role::Error)
        } else {
            (glyph::CHECK, Role::Success)
        };
        let content = if result.content.trim().is_empty() {
            "(no output)".to_string()
        } else {
            safe_block(&result.content).into_owned()
        };

        let lines: Vec<&str> = content.lines().collect();
        let shown = lines.len().min(MAX_RESULT_LINES);
        for (i, line) in lines.iter().take(shown).enumerate() {
            let prefixed = if i == 0 {
                format!("  {mark} {line}")
            } else {
                format!("    {line}")
            };
            self.emit(&self.role(role, &prefixed));
        }
        if lines.len() > shown {
            let more = lines.len() - shown;
            self.emit(&self.role(Role::Dim, &format!("    … {more} more line(s)")));
        }

        // Kernel denials stand out in bold error color regardless of the result glyph above.
        for e in audit {
            if e.decision == "denied" {
                // The denied target is a path the model chose; it reaches the operator's screen
                // verbatim, so it is exactly the string an attacker would load with an escape.
                let line = format!(
                    "  {} DENIED {} {}",
                    glyph::WARN,
                    safe_line(&e.op),
                    safe_line(&e.target)
                );
                self.emit(&palette::bold_role_if(self.color, Role::Error, &line));
                // bold red
            }
        }
    }

    fn error(&self, msg: &str) {
        let msg = safe_block(msg);
        self.emit(&self.role(Role::Error, &format!("error: {msg}"))); // red
    }

    fn info(&self, msg: &str) {
        // `info` carries harness-composed lines, but those lines interpolate untrusted names (a
        // skill's, a tool's, a transcript path) and `markdown` defaults straight into it with a
        // skill's whole body. None of bee's own callers pass pre-painted text, so sanitizing the
        // whole message costs nothing and closes every one of those paths at one point.
        self.emit(&self.role(Role::Info, &safe_block(msg))); // yellow / info
    }

    fn footer(&self, msg: &str) {
        self.emit(&self.role(Role::Dim, &safe_block(msg))); // dim
    }

    fn steering(&self, msg: &str) {
        // accent — user's steering nudge
        self.emit(&self.role(Role::Accent, &safe_block(msg)));
    }

    fn render_widget(&self, spec: &RenderSpec, _effect: Option<&EffectSpec>) {
        // Sprites/animations use the hand-rolled half-block renderer (truecolor, Slice 2); every other
        // widget goes through the headless ratatui pipeline (FR-025). Each row goes through the same
        // `ExternalPrinter` path as every other line — no alt-screen, no raw mode (SC-011).
        match spec {
            RenderSpec::Sprite { spec } => {
                let (_, tty) = crate::viz::terminal_dims();
                let mode = sprite_render::detect_color_mode();
                for line in sprite_render::render_frame_with(spec, mode, self.color && tty) {
                    self.emit(&line);
                }
            }
            RenderSpec::Animation { spec } => self.start_animation(spec),
            other => {
                let (width, _tty) = crate::viz::terminal_dims();
                for line in crate::viz::render_to_ansi(other, width, 40) {
                    self.emit(&line);
                }
            }
        }
    }

    fn busy_start(&self) {
        // Idempotent for the spinner; a running animation is preempted (FR-031).
        if self.kind.load(Ordering::SeqCst) == KIND_SPINNER {
            return;
        }
        self.stop_active();
        self.spinning.store(true, Ordering::SeqCst);
        self.kind.store(KIND_SPINNER, Ordering::SeqCst);
        self.active_rows.store(1, Ordering::SeqCst);
        let start = Instant::now();
        // Draw the first frame synchronously so feedback is instant on send (honoring a pending
        // reclaim so it reuses a prior element's row); then let a background task advance it in place.
        self.emit(&spinner_frame(0, start, self.color));
        let printer = self.printer.clone();
        let spinning = self.spinning.clone();
        let color = self.color;
        let handle = tokio::spawn(async move {
            let mut tick = 1u64;
            loop {
                tokio::time::sleep(SPINNER_INTERVAL).await;
                let Ok(mut p) = printer.lock() else { break };
                // Re-check under the printer lock so we never draw a frame after a reclaiming
                // emit has already reused the spinner row.
                if !spinning.load(Ordering::SeqCst) {
                    break;
                }
                // Redraw the row directly above the prompt in place.
                let _ = p.print(format!(
                    "\x1b[1A\r\x1b[2K{}\n",
                    spinner_frame(tick, start, color)
                ));
                drop(p);
                tick += 1;
            }
        });
        *self.spin_task.lock().expect("spin task") = Some(handle);
    }

    fn busy_stop(&self) {
        // Only stops the spinner; an animation is ended by the next `busy_start` or by completion.
        if self.kind.load(Ordering::SeqCst) != KIND_SPINNER {
            return;
        }
        self.stop_active();
    }
}

/// The first `max` chars of `s`'s single-line form, with an ellipsis when clipped.
fn clip(s: &str, max: usize) -> String {
    let one_line: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > max {
        let kept: String = one_line.chars().take(max).collect();
        format!("{kept}…")
    } else {
        one_line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// An [`ExternalPrinter`] that captures printed messages into a shared buffer.
    #[derive(Clone, Default)]
    struct CapturePrinter(Arc<Mutex<String>>);

    impl ExternalPrinter for CapturePrinter {
        fn print(&mut self, msg: String) -> rustyline::Result<()> {
            self.0.lock().unwrap().push_str(&msg);
            Ok(())
        }
    }

    fn term() -> (TerminalOutput, Arc<Mutex<String>>) {
        let buf = Arc::new(Mutex::new(String::new()));
        let printer = CapturePrinter(buf.clone());
        // Force color off so assertions match raw text.
        let mut t = TerminalOutput::new(Box::new(printer));
        t.color = false;
        (t, buf)
    }

    #[test]
    fn streamed_deltas_reassemble_into_wrapped_lines() {
        let (t, buf) = term();
        // Feed a paragraph in arbitrary chunks; the emitted text (minus wrap newlines) must contain
        // the original words in order.
        for chunk in ["Hello ", "there, ", "how can ", "I help", " you today?"] {
            t.assistant_delta(chunk);
        }
        t.assistant_end();
        let out = buf.lock().unwrap().clone();
        let collapsed: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            collapsed.contains("Hello there, how can I help you today?"),
            "got: {out:?}"
        );
    }

    #[test]
    fn long_line_wraps_at_width() {
        let (t, buf) = term();
        let words = "lorem ipsum ".repeat(30); // well over WRAP_WIDTH
        t.assistant_delta(&words);
        t.assistant_end();
        let out = buf.lock().unwrap().clone();
        for line in out.lines().filter(|l| !l.is_empty()) {
            assert!(width(line) <= WRAP_WIDTH, "line exceeds width: {line:?}");
        }
    }

    #[test]
    fn no_color_emits_no_escapes() {
        let (t, buf) = term();
        t.info("hi");
        assert!(!buf.lock().unwrap().contains("\x1b["));
    }

    /// f040: nothing the model or a tool says may reach the terminal as a control sequence. Color is
    /// off here, so *any* ESC in the buffer came from the payload rather than from bee's palette.
    #[test]
    fn untrusted_text_cannot_emit_control_sequences() {
        // Screen-clear, window-title set, and a `\r` line-overwrite — the three cheap forgeries.
        const ATTACK: &str = "\x1b[2J\x1b]0;pwned\x07ok\rDENIED nothing";

        /// Drive one output method with the attack payload and assert nothing interpretable escapes.
        fn check(name: &str, emit: impl Fn(&TerminalOutput)) {
            let (t, buf) = term();
            emit(&t);
            let out = buf.lock().unwrap().clone();
            assert!(
                !out.chars().any(|c| c.is_control() && c != '\n'),
                "{name} leaked a control character: {out:?}"
            );
            assert!(out.contains("\\x1b"), "{name} dropped the text: {out:?}");
        }

        check("assistant_delta", |t| {
            t.assistant_delta(ATTACK);
            t.assistant_end();
        });
        check("tool_call", |t| {
            t.tool_call(ATTACK, &serde_json::json!({ "arg": ATTACK }))
        });
        check("tool_result", |t| {
            t.tool_result(&ToolResult::ok(ATTACK), &[])
        });
        check("info", |t| t.info(ATTACK));
        check("error", |t| t.error(ATTACK));
        check("footer", |t| t.footer(ATTACK));
        check("steering", |t| t.steering(ATTACK));
    }

    /// The denied target is model-chosen and lands in the line the operator most needs to trust.
    #[test]
    fn a_denied_audit_target_cannot_forge_its_own_line() {
        let (t, buf) = term();
        t.tool_result(
            &ToolResult::ok("ok"),
            &[AuditEvent {
                ts: "2026-07-25T00:00:00Z".into(),
                scope_id: None,
                cgroup_id: 0,
                pid: None,
                tgid: None,
                op: "open".into(),
                decision: "denied".into(),
                errno: 13,
                target: "/etc/shadow\x1b[2K\rALLOWED /tmp/x".into(),
            }],
        );
        let out = buf.lock().unwrap().clone();
        assert!(
            !out.chars().any(|c| c.is_control() && c != '\n'),
            "audit line leaked a control character: {out:?}"
        );
        assert!(out.contains("DENIED open /etc/shadow"), "got: {out:?}");
    }

    #[tokio::test]
    async fn spinner_draws_immediately_then_reclaims_its_row() {
        let (t, buf) = term();
        t.busy_start();
        // The first frame is drawn synchronously — instant feedback on send.
        {
            let s = buf.lock().unwrap();
            assert!(s.contains("thinking…"), "spinner frame missing: {s:?}");
            assert!(
                s.contains(SPINNER_FRAMES[0]),
                "spinner glyph missing: {s:?}"
            );
        }
        // Stop before the ~90ms task ticks, then emit real output: it must reuse the spinner's row
        // in place (cursor-up + clear-line) rather than leaving a "thinking…" line behind.
        t.busy_stop();
        t.info("real output");
        let s = buf.lock().unwrap().clone();
        assert!(
            s.contains("\x1b[1A\r\x1b[2Kreal output"),
            "row not reclaimed in place: {s:?}"
        );
    }

    fn tiny_anim() -> AnimationSpec {
        // 2×4 px → 2 terminal rows per frame; 2 frames.
        let px = vec![
            Some((255, 0, 0)),
            None,
            None,
            Some((0, 255, 0)),
            Some((0, 0, 255)),
            None,
            None,
            Some((255, 255, 0)),
        ];
        let f = crate::render_spec::SpriteSpec {
            width: 2,
            height: 4,
            pixels: px,
        };
        AnimationSpec {
            frames: vec![f.clone(), f],
            interval_ms: 150,
            bounce: false,
            cycles: 1,
        }
    }

    #[tokio::test]
    async fn animation_preempts_spinner() {
        // SC-017: starting a sprite animation while the spinner runs stops the spinner.
        let (t, _buf) = term();
        t.busy_start();
        assert_eq!(t.kind.load(Ordering::SeqCst), KIND_SPINNER);
        t.render_widget(&RenderSpec::Animation { spec: tiny_anim() }, None);
        assert_eq!(
            t.kind.load(Ordering::SeqCst),
            KIND_ANIM,
            "the animation must claim the slot from the spinner"
        );
        t.stop_active();
    }

    #[tokio::test]
    async fn animation_reclaims_all_its_rows() {
        // SC-016(c): a 2-row animation, once stopped, leaves 2 rows for the next output to reclaim.
        let (t, buf) = term();
        t.render_widget(&RenderSpec::Animation { spec: tiny_anim() }, None);
        t.stop_active();
        assert_eq!(
            t.reclaim_rows.load(Ordering::SeqCst),
            2,
            "should reclaim 2 rows"
        );
        t.info("done");
        assert!(
            buf.lock().unwrap().contains("\x1b[2A\r\x1b[0J"),
            "N-row reclaim sequence missing"
        );
    }

    #[test]
    fn spinner_frame_shows_glyph_and_advances() {
        // Fresh start: under a second, no elapsed suffix, glyph advances with the tick.
        let start = Instant::now();
        let f = spinner_frame(3, start, false);
        assert!(f.contains(SPINNER_FRAMES[3]), "glyph missing: {f:?}");
        assert!(f.contains("thinking…"));
        assert_ne!(
            spinner_frame(0, start, false),
            spinner_frame(1, start, false)
        );
    }

    #[test]
    fn clip_collapses_and_truncates() {
        assert_eq!(clip("a  b\n c", 100), "a b c");
        let long = clip(&"x".repeat(200), 10);
        assert!(long.ends_with('…'));
        assert_eq!(long.chars().count(), 11);
    }
}
