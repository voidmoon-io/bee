//! Front-end selection and honest fallback (008-grid-tui, US3 T033; contracts/modes-and-cli.md).
//!
//! The full-screen UI is the default front-end, but not a guarantee: piping the output, a `TERM=dumb`
//! terminal, or a window below the hard floor all make it the wrong answer. [`choose`] is the whole decision,
//! kept **pure** (every input passed in, nothing read from the environment) so the matrix is unit
//! testable without a terminal.
//!
//! The rule the contract insists on: an explicit `--tui` must never silently "do nothing". Whenever
//! a requested full-screen session degrades to inline, [`Choice::note`] carries a one-line reason
//! for stderr.

/// Which front-end to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    /// The classic line-based REPL — byte-for-byte the output it has always produced (SC-004).
    Inline,
    /// The full-screen alt-screen TUI.
    FullScreen,
}

/// The chosen front-end plus an optional one-line explanation for a degraded choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub frontend: Frontend,
    /// `Some` only when `--tui` was requested explicitly but could not be honored.
    pub note: Option<String>,
}

impl Choice {
    fn inline(note: impl Into<String>) -> Self {
        Choice {
            frontend: Frontend::Inline,
            note: Some(note.into()),
        }
    }
    fn plain(frontend: Frontend) -> Self {
        Choice {
            frontend,
            note: None,
        }
    }
}

/// The hard floor below which a full-screen UI has nowhere to draw (contracts/modes-and-cli.md).
pub const HARD_FLOOR: (u16, u16) = (40, 10);

/// Decide the front-end (contracts/modes-and-cli.md `choose_frontend`).
///
/// * `tui` / `no_tui` — the CLI flags (they conflict, so at most one is set). Full screen is the
///   default; `tui` only makes a fallback explain itself.
/// * `stdout_is_tty` — false when piped or redirected.
/// * `term` — the `TERM` environment value.
/// * `size` — the terminal's `(cols, rows)`.
///
/// `NO_COLOR` is deliberately **not** an input: it degrades the TUI to monochrome, it does not force
/// the inline path (FR-014).
pub fn choose(
    tui: bool,
    no_tui: bool,
    stdout_is_tty: bool,
    term: Option<&str>,
    size: (u16, u16),
) -> Choice {
    if no_tui {
        return Choice::plain(Frontend::Inline);
    }
    // The full-screen UI is the default. A terminal that cannot host it falls back to inline: with a
    // note when `--tui` asked for it explicitly, silently otherwise — piping `bee repl` is ordinary,
    // not a degraded request.
    let fallback = |note: String| {
        if tui {
            Choice::inline(note)
        } else {
            Choice::plain(Frontend::Inline)
        }
    };
    if !stdout_is_tty {
        return fallback(
            "--tui ignored: stdout is not a terminal (piped or redirected); running inline".into(),
        );
    }
    if term.is_some_and(|t| t.eq_ignore_ascii_case("dumb")) {
        return fallback(
            "--tui ignored: TERM=dumb cannot drive a full-screen UI; running inline".into(),
        );
    }
    let (cols, rows) = size;
    if cols < HARD_FLOOR.0 || rows < HARD_FLOOR.1 {
        return fallback(format!(
            "--tui ignored: terminal is {cols}×{rows}, below the {}×{} minimum; running inline",
            HARD_FLOOR.0, HARD_FLOOR.1
        ));
    }
    Choice::plain(Frontend::FullScreen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_full_screen_and_the_opt_out_is_inline() {
        assert_eq!(
            choose(false, false, true, Some("xterm"), (200, 60)),
            Choice::plain(Frontend::FullScreen)
        );
        // --no-tui is a deliberate choice, so it is silent — and wins even over --tui.
        for tui in [false, true] {
            assert_eq!(
                choose(tui, true, true, Some("xterm"), (200, 60)),
                Choice::plain(Frontend::Inline)
            );
        }
    }

    #[test]
    fn an_unrequested_fallback_is_silent() {
        // Piping `bee repl` (or a dumb or tiny terminal) without asking for --tui is not a
        // degraded request, so it carries no note.
        for c in [
            choose(false, false, false, Some("xterm"), (200, 60)),
            choose(false, false, true, Some("dumb"), (200, 60)),
            choose(false, false, true, Some("xterm"), (10, 4)),
        ] {
            assert_eq!(c, Choice::plain(Frontend::Inline));
        }
    }

    #[test]
    fn a_capable_terminal_gets_the_full_screen_ui() {
        assert_eq!(
            choose(true, false, true, Some("xterm-256color"), (120, 40)),
            Choice::plain(Frontend::FullScreen)
        );
    }

    #[test]
    fn piping_falls_back_inline_with_a_note() {
        let c = choose(true, false, false, Some("xterm"), (200, 60));
        assert_eq!(c.frontend, Frontend::Inline);
        assert!(c.note.unwrap().contains("not a terminal"));
    }

    #[test]
    fn term_dumb_falls_back_inline_with_a_note() {
        for t in ["dumb", "DUMB"] {
            let c = choose(true, false, true, Some(t), (200, 60));
            assert_eq!(c.frontend, Frontend::Inline);
            assert!(c.note.unwrap().contains("TERM=dumb"));
        }
    }

    #[test]
    fn a_terminal_below_the_hard_floor_falls_back_with_the_size_in_the_note() {
        let c = choose(true, false, true, Some("xterm"), (30, 8));
        assert_eq!(c.frontend, Frontend::Inline);
        let note = c.note.unwrap();
        assert!(note.contains("30×8"), "note names the actual size: {note}");
        assert!(note.contains("40×10"), "and the minimum: {note}");
    }

    #[test]
    fn exactly_at_the_floor_is_still_full_screen() {
        assert_eq!(
            choose(true, false, true, Some("xterm"), HARD_FLOOR).frontend,
            Frontend::FullScreen
        );
    }

    #[test]
    fn a_missing_term_is_not_treated_as_dumb() {
        assert_eq!(
            choose(true, false, true, None, (100, 30)).frontend,
            Frontend::FullScreen
        );
    }

    #[test]
    fn every_degraded_choice_explains_itself() {
        // The contract's rule: --tui must never silently do nothing.
        let degraded = [
            choose(true, false, false, Some("xterm"), (200, 60)),
            choose(true, false, true, Some("dumb"), (200, 60)),
            choose(true, false, true, Some("xterm"), (10, 4)),
        ];
        for c in degraded {
            assert_eq!(c.frontend, Frontend::Inline);
            assert!(c.note.is_some(), "a degraded --tui must carry a note");
        }
    }
}
