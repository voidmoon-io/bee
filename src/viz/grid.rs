//! The honeycomb status grid (003-visual-render, FR-026, US7): a compact pass/fail dot grid for
//! batch/episode output. The [`dot_cell`] helper is shared with the render pipeline's `DotGrid`
//! widget so both surfaces draw dots identically (analysis finding I2).

use crate::transcript::EpisodeStatus;
use crate::viz::glyph::{DOT_FAIL, DOT_PASS, DOT_SKIP};
use crate::viz::palette::{self, POLLEN, SMOKE, STING};

/// A dot's colored state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    /// Map an [`EpisodeStatus`] to a grid status (contracts/honeycomb.md table). `Completed`/
    /// `Captured` pass; hard failures and `NotCaptured` fail; a text-only turn is neutral.
    pub fn from_episode(status: &EpisodeStatus) -> Status {
        match status {
            EpisodeStatus::Completed | EpisodeStatus::Captured { .. } => Status::Pass,
            EpisodeStatus::NoToolCalls => Status::Skip,
            EpisodeStatus::Timeout
            | EpisodeStatus::ApiError { .. }
            | EpisodeStatus::InfraError { .. }
            | EpisodeStatus::NotCaptured
            | EpisodeStatus::Terminated { .. } => Status::Fail,
        }
    }
}

/// The `(glyph, SGR code)` for a status dot — the single place dot appearance is decided, shared by
/// [`status_grid`] and the render pipeline's `DotGrid` widget (finding I2).
pub fn dot_cell(status: Status) -> (&'static str, &'static str) {
    match status {
        Status::Pass => (DOT_PASS, POLLEN),
        Status::Fail => (DOT_FAIL, STING),
        Status::Skip => (DOT_SKIP, SMOKE),
    }
}

/// Render a colored status dot (honors `NO_COLOR` via [`palette::paint`]).
pub fn dot(status: Status) -> String {
    let (glyph, code) = dot_cell(status);
    palette::paint(code, glyph)
}

/// Render the pass/fail dot grid: each row is `name  <dots>  N/M pass`, names left-aligned to the
/// widest name, the fraction right-aligned. `rows` pairs a scenario name with its per-attempt
/// statuses. Colors suppressed under `NO_COLOR` (AS-3); glyphs always present.
pub fn status_grid(rows: &[(String, Vec<Status>)]) -> String {
    let name_w = rows
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (name, dots) in rows {
        let pass = dots.iter().filter(|s| matches!(s, Status::Pass)).count();
        let total = dots.len();
        let dot_str: Vec<String> = dots.iter().map(|s| dot(*s)).collect();
        out.push_str(&format!(
            "  {name:<name_w$}   {}    {pass}/{total} pass\n",
            dot_str.join(" "),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both color states in one serial test: `NO_COLOR` is process-global, so toggling it across two
    // parallel tests in the same binary would race (SC-013 + AS-3).
    #[test]
    fn status_grid_color_and_no_color() {
        let _no_color = crate::viz::palette::lock_no_color();
        // Color on (SC-013): 3 green + 1 red dot, fraction present.
        std::env::remove_var("NO_COLOR");
        let rows = vec![(
            "scenario".to_string(),
            vec![Status::Pass, Status::Pass, Status::Pass, Status::Fail],
        )];
        let out = status_grid(&rows);
        assert_eq!(
            out.matches(&format!("\x1b[32m{DOT_PASS}")).count(),
            3,
            "3 green: {out:?}"
        );
        assert_eq!(
            out.matches(&format!("\x1b[31m{DOT_FAIL}")).count(),
            1,
            "1 red: {out:?}"
        );
        assert!(out.contains("3/4 pass"));

        // Color off (AS-3): glyphs remain, no SGR.
        std::env::set_var("NO_COLOR", "1");
        let out = status_grid(&rows);
        std::env::remove_var("NO_COLOR");
        assert!(!out.contains("\x1b["), "no SGR under NO_COLOR: {out:?}");
        assert!(out.contains(DOT_PASS), "glyph still present: {out:?}");
    }
}
