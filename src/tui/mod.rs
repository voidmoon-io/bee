//! The full-screen TUI front-end (008-grid-tui, M3–M4). Feature-gated behind `tui`.
//!
//! Architecture: The Elm Architecture (Model → Message → update → view) over the harness's tokio
//! loop, consuming [`crate::tui::events::SessionEvent`]s beside terminal input. The [`run`] event loop
//! (T018) selects over crossterm's async [`EventStream`], the `SessionEvent` channel, and an
//! on-demand tick, driving the shared [`crate::repl::run_exchange`] turn loop through a
//! [`SessionSink`] — the same engine the inline REPL uses (T005/T006), so both front-ends stay in
//! lock-step. `theme_bridge` (T007) is implemented; `--tui` launch wiring lands in T019.

pub mod app;
pub mod chat;
pub mod effects;
// The TUI's event sink: the shared turn loop's output as a stream of events (008, moved from
// `bee::session` by 024 so that name can hold the Session builder).
pub mod events;
pub mod frontend;
pub mod input;
pub mod markdown;
pub mod message;
pub mod overlay;
pub mod panels;
pub mod term;
pub mod theme_bridge;
pub mod view;

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::EventStream;
use futures_util::StreamExt;

use crate::metrics::Recorder;
use crate::provider::{Conversation, Model};
use crate::render_spec::RenderSpec;
use crate::repl::{effective_system_prompt, run_exchange, ReplConfig, SteeringQueue};
use crate::sandbox::Sandbox;
use crate::tools::ToolRegistry;
use crate::tui::events::SessionSink;

use app::{update, App};
use chat::{ChatMessage, Role};
use message::Message;
use term::{message_from_event, Tui};

/// How often the "working…" indicator repaints during a turn. A turn always ticks at least this
/// often even with no effects running, because the spinner has to move.
const SPINNER_TICK: Duration = Duration::from_millis(120);

/// Run the full-screen TUI front-end to completion (008-grid-tui, US1 T018).
///
/// Owns the same conversation core as [`crate::repl::run_repl`] — a [`Conversation`], a steering
/// queue, and a metrics recorder — minus the readline editor, since input arrives through
/// crossterm instead. Each submitted line drives one [`run_exchange`] turn via a [`SessionSink`];
/// the loop pumps streaming tokens, tool results, and denials into the model as they arrive, so the
/// screen stays live and Ctrl-C quits promptly even mid-turn. Returns once the user quits (or the
/// input stream closes), with the terminal already restored.
pub async fn run(
    model: &dyn Model,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    config: &ReplConfig,
) -> io::Result<()> {
    // Shared conversation core, identical to the inline REPL's setup (session/mod.rs).
    let mut conversation = Conversation {
        system: effective_system_prompt(&config.system_prompt, registry),
        messages: Vec::new(),
    };
    let steering: SteeringQueue = Arc::new(Mutex::new(VecDeque::new()));
    let recorder = Recorder::new("tui", format!("tui:{}", std::process::id()));

    // Enter the alternate screen + raw mode; the panic hook (installed here) restores first. The
    // guard then covers the abnormal exits — an early `?` return or a panic unwinding through the
    // loop restore the terminal on drop (contracts/modes-and-cli.md; T010).
    let mut terminal = term::init();
    let mut restore_guard = term::RestoreGuard::terminal();
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let mut app = App::new(cols, rows)
        .with_visual(config.visual)
        .with_model(model.id().to_string());
    // bee's own opening: the header fades up and the footer slides in behind it (US5 §1, FR-026).
    app.chrome_cues
        .extend([effects::Chrome::Header, effects::Chrome::Footer]);

    // Greeting, mirroring the inline REPL's info banner — plus the resting-pose mascot when enabled,
    // which also exercises the sprite→Buffer rasterizer (T008) on the full-screen path.
    if config.mascot {
        app.chat.push(ChatMessage::widget(RenderSpec::Sprite {
            spec: crate::viz::bee::sprite(),
        }));
        // It evolves out of block glyphs rather than popping in (US5 §2). Gated on the existing
        // `BEE_MASCOT` opt-in, because a session that asked for no mascot gets no mascot animation.
        app.chrome_cues.push(effects::Chrome::Mascot);
    }
    app.chat.push(ChatMessage::text(
        Role::System,
        format!(
            "interactive session — {} — type a message, ? for help, q to quit",
            model.id()
        ),
    ));

    let mut events = EventStream::new();

    // The Elm loop: draw, then wait for the next thing that changes the model.
    while !app.should_quit {
        let now = std::time::Instant::now();
        app.panels.prune(now);
        // The overlay's TTL and its phase changes fire here rather than on a keypress, so a takeover
        // expires on time in a session nobody is touching (FR-017).
        app.advance_overlay(now);
        // Publish the drawable regions so the render tool can reject widgets this screen can't show.
        crate::viz::viewport::set(view::viewport_for(&app));
        app.tick_clock(now);
        refresh_http_pane(&mut app, config);
        terminal.draw(|f| view::view(&mut app, f))?;

        // A submitted line starts a model turn; drive it to completion while still pumping the UI.
        if let Some(text) = app.take_outbox() {
            #[allow(clippy::too_many_arguments)]
            run_turn(
                &mut app,
                &mut terminal,
                &mut events,
                &text,
                model,
                &mut conversation,
                registry,
                sandbox,
                config,
                &steering,
                recorder.as_ref(),
            )
            .await?;
            continue;
        }

        // Idle: block on a single terminal event, apply it, loop back to redraw — unless the
        // scheduler says this session owes periodic wakeups (motion, an overlay countdown, or a
        // panel TTL). With none of those this stays a pure blocking wait (no idle CPU).
        let next = match tick_interval(&app) {
            Some(period) => tokio::select! {
                ev = events.next() => ev,
                _ = tokio::time::sleep(period) => {
                    app.periodic_redraws += 1;
                    continue;
                }
            },
            None => events.next().await,
        };
        match next {
            Some(Ok(ev)) => {
                if let Some(msg) = message_from_event(ev) {
                    update(&mut app, msg);
                }
                if drain_intents(&mut app, &mut terminal) {
                    terminal.clear()?; // returned from suspend — repaint the whole screen
                }
            }
            // A read error or the stream ending both mean input is gone — exit cleanly.
            Some(Err(_)) | None => break,
        }
    }

    // Normal exit (quit / Ctrl-C / Ctrl-D / closed input): restore explicitly, then disarm the guard
    // so its Drop doesn't restore a second time (contracts/modes-and-cli.md: normal-quit row).
    term::restore();
    restore_guard.disarm();
    Ok(())
}

/// How long the loop may sleep before it must redraw on its own — the scheduler of FR-002, as a
/// pure function of the model so its wakeup budget is testable without a terminal.
///
/// The three states, in the order the spec fixes:
///
/// 1. **Motion** — effects are running: ~60fps, because that is what an animation costs.
/// 2. **Countdown** — no effects but an overlay is up: 1Hz, enough to tick the dismiss countdown and
///    fire the TTL. A 120s overlay must cost ~120 wakeups, not ~7200.
/// 3. **Idle** — `None`: fully event-driven, zero periodic redraws (SC-003).
///
/// The panel-TTL wake from 008 sits below all three: it is not a render state, just the coarse poll
/// that expires timed panels, and it exists only while a panel actually carries a TTL.
fn tick_interval(app: &App) -> Option<Duration> {
    if app.effects.is_running() {
        Some(Duration::from_millis(16))
    } else if app.overlay_active() {
        Some(Duration::from_secs(1))
    } else if app.panels.has_expiring() {
        Some(Duration::from_millis(250))
    } else {
        None
    }
}

/// Act on the side-effect intents the (pure) reducer surfaced: copy a yanked message via OSC 52, and
/// perform the `Ctrl-Z` suspend/resume dance (US3 T035). Returns `true` if the terminal was handed
/// back to the shell and re-acquired, so the caller can force a full redraw.
fn drain_intents(app: &mut App, terminal: &mut Tui) -> bool {
    if let Some(text) = app.take_yank() {
        // Best-effort: an emulator that ignores OSC 52 simply doesn't copy; never fail the session.
        let _ = term::osc52_copy(&text);
    }
    if app.take_suspend() {
        *terminal = term::suspend_and_resume();
        return true;
    }
    false
}

/// Drive one user→model exchange to completion while keeping the UI live (008-grid-tui, T018).
///
/// The [`run_exchange`] future borrows the conversation core; we poll it inside `tokio::select!`
/// beside the `SessionEvent` channel (streaming output), terminal input (so Ctrl-C / resize stay
/// responsive), and an on-demand tick (redraws the "working…" indicator). Every branch redraws on
/// the next loop turn. Quitting mid-turn drops the exchange future, cancelling the in-flight call.
#[allow(clippy::too_many_arguments)]
async fn run_turn(
    app: &mut App,
    terminal: &mut Tui,
    events: &mut EventStream,
    text: &str,
    model: &dyn Model,
    conversation: &mut Conversation,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    config: &ReplConfig,
    steering: &SteeringQueue,
    recorder: Option<&Recorder>,
) -> io::Result<()> {
    let (sink, mut rx) = SessionSink::new();
    let exchange = run_exchange(
        text,
        model,
        conversation,
        registry,
        sandbox,
        config,
        &sink,
        steering,
        recorder,
    );
    tokio::pin!(exchange);

    // The tick exists only for the duration of a turn — the "on-demand" tick (T018): it paces the
    // "working…" indicator's redraws and idles completely between turns. While effects are running
    // it tightens to the scheduler's 16ms so animations advance smoothly mid-turn (FR-002).
    let mut turn_done = false;

    loop {
        let now = std::time::Instant::now();
        app.panels.prune(now);
        app.advance_overlay(now);
        crate::viz::viewport::set(view::viewport_for(app));
        app.tick_clock(now);
        refresh_http_pane(app, config);
        terminal.draw(|f| view::view(app, f))?;
        let period = tick_interval(app).unwrap_or(SPINNER_TICK).min(SPINNER_TICK);
        // A mid-turn quit (Ctrl-C / q from chat focus) drops `exchange`, cancelling the call.
        if app.should_quit {
            return Ok(());
        }

        tokio::select! {
            // Guarded so a completed future is never polled again.
            _ = &mut exchange, if !turn_done => {
                turn_done = true;
                // The exchange emits its trailing events (footer/TurnDone) before returning; fold
                // them in, redraw once more via the loop head, then finish.
                while let Ok(ev) = rx.try_recv() {
                    update(app, Message::session(ev));
                }
            }
            Some(ev) = rx.recv() => update(app, Message::session(ev)),
            maybe = events.next() => match maybe {
                Some(Ok(ev)) => {
                    if let Some(msg) = message_from_event(ev) {
                        update(app, msg);
                    }
                    if drain_intents(app, terminal) {
                        terminal.clear()?;
                    }
                }
                Some(Err(_)) | None => app.should_quit = true,
            },
            _ = tokio::time::sleep(period) => app.periodic_redraws += 1,
        }

        // Once the turn has ended and its trailing events are drained, one final redraw + return.
        if turn_done {
            refresh_http_pane(app, config);
            terminal.draw(|f| view::view(app, f))?;
            return Ok(());
        }
    }
}

/// Upsert the live HTTP history pane when new exchanges have arrived (019 US9). A no-op in a session
/// without `[policy.http]`, and between arrivals.
fn refresh_http_pane(app: &mut App, config: &ReplConfig) {
    if let Some(source) = &config.http_pane {
        if let Some(spec) = source() {
            app.panels.upsert("http", spec);
        }
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;
    use crate::config::VisualConfig;
    use crate::render_spec::RenderSpec;
    use crate::tui::effects::{self, Origin, ResolveCtx};
    use ratatui::layout::Rect;

    /// How many periodic wakeups this session costs over `window` — zero when the loop is purely
    /// event-driven. The scheduler's decision *is* the wakeup budget, so measuring it here measures
    /// SC-003 without standing up a terminal and a tokio runtime.
    fn wakeups(app: &App, window: Duration) -> u128 {
        match tick_interval(app) {
            Some(period) => window.as_nanos() / period.as_nanos(),
            None => 0,
        }
    }

    #[test]
    fn an_idle_session_never_wakes_up_on_its_own() {
        // SC-003: no effects, no overlay, no expiring panel — nothing to redraw for.
        let mut app = App::new(120, 24);
        app.panels.upsert("m", RenderSpec::Separator);
        assert!(tick_interval(&app).is_none());
        assert_eq!(wakeups(&app, Duration::from_secs(60)), 0);
    }

    #[test]
    fn running_effects_put_the_loop_in_its_60fps_state() {
        let mut app = App::new(120, 24);
        let ctx = ResolveCtx::agent(app.visual, Rect::new(0, 0, 20, 5));
        assert!(effects::apply(
            &mut app.effects,
            Some("m"),
            &effects::panel_enter_spec(),
            &ctx
        ));
        assert_eq!(tick_interval(&app), Some(Duration::from_millis(16)));
    }

    #[test]
    fn a_motionless_session_can_never_reach_the_60fps_state() {
        // FR-006c, structurally: with animations off nothing registers, so `is_running()` is false
        // forever and state 1 is unreachable no matter what the agent asks for.
        let mut app = App::new(120, 24).with_visual(VisualConfig {
            animations: false,
            ..VisualConfig::default()
        });
        let ctx = ResolveCtx::agent(app.visual, Rect::new(0, 0, 20, 5));
        for origin in [Origin::Agent, Origin::Chrome] {
            let ctx = ResolveCtx { origin, ..ctx };
            assert!(!effects::apply(
                &mut app.effects,
                Some("m"),
                &effects::panel_enter_spec(),
                &ctx
            ));
        }
        assert!(!app.effects.is_running());
        assert!(tick_interval(&app).is_none());
        assert_eq!(wakeups(&app, Duration::from_secs(60)), 0);
    }

    #[test]
    fn a_showing_overlay_costs_one_wakeup_per_second_not_sixty() {
        // SC-003 / FR-002 state 2: the countdown needs a redraw per second, and that is all it
        // needs. A 10-second overlay budget of ≤ 15 is the assertion the spec names; holding the
        // motion state instead would cost 600.
        let t0 = std::time::Instant::now();
        let mut app = App::new(120, 24);
        app.show_overlay(RenderSpec::Separator, Some(10_000), t0);
        // Past the entrance, with no effects left running.
        app.advance_overlay(t0 + Duration::from_millis(250));
        assert_eq!(
            app.overlay.as_ref().map(|o| o.phase()),
            Some(crate::tui::overlay::Phase::Showing)
        );
        assert!(!app.effects.is_running(), "nothing is animating");

        assert_eq!(tick_interval(&app), Some(Duration::from_secs(1)));
        assert_eq!(wakeups(&app, Duration::from_secs(10)), 10);
        assert!(wakeups(&app, Duration::from_secs(10)) <= 15);
    }

    #[test]
    fn an_overlay_countdown_still_ticks_with_animations_disabled() {
        // FR-015: the countdown is information, not motion, so the kill switch does not silence it.
        let t0 = std::time::Instant::now();
        let mut app = App::new(120, 24).with_visual(VisualConfig {
            animations: false,
            ..VisualConfig::default()
        });
        app.show_overlay(RenderSpec::Separator, Some(10_000), t0);
        app.advance_overlay(t0);
        assert_eq!(
            tick_interval(&app),
            Some(Duration::from_secs(1)),
            "still 1Hz — but never 60fps, because nothing was registered"
        );
        assert!(!app.effects.is_running());
    }

    #[test]
    fn the_loop_goes_quiet_again_once_the_overlay_is_gone() {
        let t0 = std::time::Instant::now();
        let mut app = App::new(120, 24);
        app.show_overlay(RenderSpec::Separator, Some(1_000), t0);
        app.advance_overlay(t0 + Duration::from_millis(1_300));
        assert!(app.overlay.is_none());
        assert!(tick_interval(&app).is_none(), "back to fully event-driven");
    }

    #[test]
    fn a_timed_panel_polls_coarsely_and_stops_once_it_expires() {
        // 008's TTL wake is not a render state — it's the coarse poll that expires panels, and it
        // lives below all three of FR-002's states.
        let mut app = App::new(120, 24);
        app.panels.apply(crate::render_spec::PanelOp::Upsert {
            id: "flash".into(),
            spec: RenderSpec::Separator,
            ttl_ms: Some(50),
            effect: None,
        });
        assert_eq!(tick_interval(&app), Some(Duration::from_millis(250)));

        app.panels
            .prune(std::time::Instant::now() + Duration::from_millis(100));
        assert!(
            tick_interval(&app).is_none(),
            "the poll retires with the panel"
        );
    }
}
