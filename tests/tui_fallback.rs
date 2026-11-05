#![cfg(feature = "tui")]
//! T031 — front-end selection and honest fallback (008-grid-tui, US3; contracts/modes-and-cli.md).
//!
//! `--tui` is a request, not a guarantee. This pins the decision matrix through the public
//! `tui::frontend::choose`, which takes every input explicitly — no terminal, no env poking, so the
//! whole matrix runs in CI.
//!
//! The invariant that matters most: a requested full-screen session that degrades to inline must
//! always say why (SC-004 — `--tui` never silently does nothing).

use bee::tui::frontend::{choose, Frontend, HARD_FLOOR};

/// A capable terminal, so each test varies exactly one input.
const CAPABLE: (u16, u16) = (200, 60);

#[test]
fn non_tty_falls_back_to_inline_with_a_note() {
    let c = choose(true, false, false, Some("xterm-256color"), CAPABLE);
    assert_eq!(c.frontend, Frontend::Inline, "piped output must run inline");
    assert!(
        c.note
            .expect("a degraded --tui explains itself")
            .contains("not a terminal"),
        "the note should name the reason"
    );
}

#[test]
fn term_dumb_falls_back_to_inline_with_a_note() {
    let c = choose(true, false, true, Some("dumb"), CAPABLE);
    assert_eq!(c.frontend, Frontend::Inline);
    assert!(c.note.expect("note").contains("TERM=dumb"));
}

#[test]
fn below_the_hard_floor_falls_back_and_names_both_sizes() {
    let c = choose(true, false, true, Some("xterm"), (30, 8));
    assert_eq!(c.frontend, Frontend::Inline);
    let note = c.note.expect("note");
    assert!(note.contains("30×8"), "actual size: {note}");
    assert!(note.contains("40×10"), "required minimum: {note}");
}

#[test]
fn a_capable_terminal_runs_full_screen_silently() {
    let c = choose(true, false, true, Some("xterm-256color"), CAPABLE);
    assert_eq!(c.frontend, Frontend::FullScreen);
    assert!(c.note.is_none(), "an honored request needs no explanation");
}

#[test]
fn exactly_at_the_floor_still_runs_full_screen() {
    assert_eq!(
        choose(true, false, true, Some("xterm"), HARD_FLOOR).frontend,
        Frontend::FullScreen,
        "the floor is inclusive"
    );
}

#[test]
fn the_default_is_full_screen_and_no_tui_is_inline_without_a_note() {
    // Neither flag: the full-screen UI is the default on a capable terminal.
    let d = choose(false, false, true, Some("xterm"), CAPABLE);
    assert_eq!(d.frontend, Frontend::FullScreen);
    assert!(d.note.is_none());

    // --no-tui is deliberate, and wins over --tui.
    for c in [
        choose(false, true, true, Some("xterm"), CAPABLE),
        choose(true, true, true, Some("xterm"), CAPABLE),
    ] {
        assert_eq!(c.frontend, Frontend::Inline);
        assert!(c.note.is_none(), "an explicit opt-out is not a fallback");
    }
}

#[test]
fn piping_without_a_request_runs_inline_silently() {
    let c = choose(false, false, false, Some("xterm"), CAPABLE);
    assert_eq!(c.frontend, Frontend::Inline);
    assert!(
        c.note.is_none(),
        "piping `bee repl` is ordinary, not a degraded request"
    );
}

#[test]
fn no_color_does_not_force_the_inline_path() {
    // NO_COLOR degrades the TUI to monochrome (FR-014); it is deliberately not an input to `choose`,
    // so a capable terminal still gets the full-screen UI.
    assert_eq!(
        choose(true, false, true, Some("xterm"), CAPABLE).frontend,
        Frontend::FullScreen
    );
}
