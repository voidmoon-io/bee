//! The visual permission gate (009-tachyonfx-effects, US2): how much screen the agent may claim.
//!
//! [`VisualLevel`] is a **ceiling**, not a mode — level `takeover` permits everything the lower
//! levels permit. A request above the ceiling is **downgraded, never refused** (FR-009): the model
//! gets a working visual plus a note saying what happened, so it can adapt on the next turn. Failing
//! the tool call instead would make a level-`panels` session error every time the model reached for
//! a takeover, which teaches the model to stop rendering at all.
//!
//! The gate runs **before any panel or overlay state mutates** — in the render tool, on the way out
//! of the script evaluation — so the downgraded target is the only one anything downstream ever
//! sees. It lives at the crate root rather than under `tui` (where tasks.md placed it) because the
//! render tool is not feature-gated: an inline-REPL or headless session resolves a level too, and a
//! gate the render tool cannot call in a headless build would be no gate at all.

use std::sync::RwLock;

use crate::config::{VisualConfig, VisualLevel};
use crate::render_spec::RenderTarget;

/// The reserved panel id an `Overlay` downgrades onto (research R7).
///
/// Reserved rather than generated: repeat downgrades must upsert the *same* panel, so a model that
/// asks for takeover every turn replaces one panel instead of filling the column. It satisfies the
/// existing 1–32 char `[a-z0-9_-]` id rule unchanged, and a script naming it directly is an error.
pub const TAKEOVER_PANEL_ID: &str = "takeover";

/// Appended to `ToolResult.content` when the level admits no model-owned regions at all.
pub const NOTE_TO_INLINE: &str = "downgraded to inline: visual level is none";
/// Appended when the level allows panels but not a full-screen takeover.
pub const NOTE_TO_PANEL: &str = "downgraded to panel: visual level does not allow takeover";

/// What the gate decided: where the render actually goes, and what to tell the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gated {
    /// The target to act on. Never higher than the requested one.
    pub target: RenderTarget,
    /// The note for `ToolResult.content`. `None` when the request passed through untouched — a
    /// permitted render says nothing, so the model's context isn't padded with non-events.
    pub note: Option<&'static str>,
}

impl Gated {
    fn passthrough(target: RenderTarget) -> Self {
        Gated { target, note: None }
    }
}

/// Apply the downgrade matrix (contracts/visual-levels.md, FR-009).
///
/// | Level | Requested | Result |
/// |---|---|---|
/// | any | `Inline` | `Inline` — always passes through |
/// | `none` | `Panel`/`Overlay` | `Inline` + [`NOTE_TO_INLINE`] |
/// | `panels`/`panels-wide` | `Panel` | unchanged |
/// | `panels`/`panels-wide` | `Overlay` | `Panel{"takeover"}` + [`NOTE_TO_PANEL`] |
/// | `takeover` | `Overlay` | unchanged; its TTL is capped separately by [`resolve_ttl`] |
pub fn gate(level: VisualLevel, requested: RenderTarget) -> Gated {
    match (level, requested) {
        // Inline is the floor. Nothing can downgrade past it, so it is never gated.
        (_, RenderTarget::Inline) => Gated::passthrough(RenderTarget::Inline),

        (VisualLevel::None, _) => Gated {
            target: RenderTarget::Inline,
            note: Some(NOTE_TO_INLINE),
        },

        (_, RenderTarget::Panel { id }) => Gated::passthrough(RenderTarget::Panel { id }),

        (VisualLevel::Takeover, overlay @ RenderTarget::Overlay { .. }) => {
            Gated::passthrough(overlay)
        }
        // Panels and panels-wide both stop short of the full screen: the request lands in the
        // reserved panel instead, which is a working visual rather than an error.
        (_, RenderTarget::Overlay { .. }) => Gated {
            target: RenderTarget::Panel {
                id: TAKEOVER_PANEL_ID.to_string(),
            },
            note: Some(NOTE_TO_PANEL),
        },
    }
}

/// The widest a panel may be at `level`, given the terminal's `cols` (FR-011).
///
/// This is the *level's* budget only. The caller takes `min` of this and 008's own panel-column
/// width, and 008's "this widget needs at least N columns" script error still applies afterward —
/// the level narrows the budget, it never suppresses the minimum-width failure.
pub fn panel_width_cap(level: VisualLevel, cols: u16) -> u16 {
    // The tier→fraction table lives on `VisualLevel` beside the tier definitions; stating it a
    // second time here is how the two would drift. `None` has no fraction because it draws no panel
    // at all, which is a zero budget rather than an unlimited one.
    match level.panel_width_fraction() {
        Some((num, den)) => cols.saturating_mul(num) / den.max(1),
        None => 0,
    }
}

/// The lifetime a takeover actually gets: `min(requested, configured)` (FR-021).
///
/// An agent request is clamped **silently** — it is a hint, and a model asking for two minutes of
/// full screen should still get the operator's thirty seconds rather than a failed tool call. That
/// is the opposite of the *configured* ceiling, where an out-of-range value is a hard startup error
/// (`config::VisualConfig`): a human writing 600 in a config file made a mistake worth surfacing.
pub fn resolve_ttl(requested_ms: Option<u32>, cfg: &VisualConfig) -> u32 {
    let ceiling_ms = cfg.takeover_ttl_secs.saturating_mul(1000);
    match requested_ms {
        Some(ms) => ms.min(ceiling_ms),
        None => ceiling_ms,
    }
}

static ACTIVE: RwLock<Option<VisualConfig>> = RwLock::new(None);

/// Publish the session's resolved presentation axes. Called once at startup, after the CLI, the
/// environment and the scenario file have been folded together.
///
/// Process-global for the same reason [`crate::viz::viewport`] is: the render tool runs in-process
/// with no session handle, and threading a config through the Python engine's closures would put the
/// configuration into every builder type on the drawing API.
pub fn set(cfg: VisualConfig) {
    if let Ok(mut g) = ACTIVE.write() {
        *g = Some(cfg);
    }
}

/// The session's presentation axes, or the defaults when nothing has been published (headless runs,
/// batch episodes, tests) — a headless caller has no screen to protect, so the default ceiling
/// applies rather than a locked-down one.
pub fn active() -> VisualConfig {
    ACTIVE.read().ok().and_then(|g| *g).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel(id: &str) -> RenderTarget {
        RenderTarget::Panel { id: id.to_string() }
    }

    #[test]
    fn inline_passes_through_at_every_level() {
        for level in [
            VisualLevel::None,
            VisualLevel::Panels,
            VisualLevel::PanelsWide,
            VisualLevel::Takeover,
        ] {
            assert_eq!(
                gate(level, RenderTarget::Inline),
                Gated {
                    target: RenderTarget::Inline,
                    note: None
                },
                "inline is the floor at {level:?}"
            );
        }
    }

    #[test]
    fn level_none_routes_panels_and_overlays_inline_with_the_contract_note() {
        // SC-004: the note text is the contract, not a paraphrase — the model reads it.
        for requested in [panel("metrics"), RenderTarget::Overlay { ttl_ms: None }] {
            let g = gate(VisualLevel::None, requested);
            assert_eq!(g.target, RenderTarget::Inline);
            assert_eq!(g.note, Some("downgraded to inline: visual level is none"));
        }
    }

    #[test]
    fn panels_and_panels_wide_admit_panels_untouched() {
        for level in [VisualLevel::Panels, VisualLevel::PanelsWide] {
            let g = gate(level, panel("metrics"));
            assert_eq!(g.target, panel("metrics"));
            assert_eq!(g.note, None, "a permitted render says nothing");
        }
    }

    #[test]
    fn an_overlay_below_takeover_lands_in_the_reserved_panel() {
        for level in [VisualLevel::Panels, VisualLevel::PanelsWide] {
            let g = gate(
                level,
                RenderTarget::Overlay {
                    ttl_ms: Some(5_000),
                },
            );
            assert_eq!(g.target, panel(TAKEOVER_PANEL_ID));
            assert_eq!(
                g.note,
                Some("downgraded to panel: visual level does not allow takeover")
            );
        }
    }

    #[test]
    fn a_repeated_downgrade_upserts_one_panel_rather_than_stacking() {
        // FR-020's shape, one level down: every downgrade names the same reserved id, so a model
        // that asks for takeover on every turn cannot fill the column with takeover panels.
        let first = gate(VisualLevel::Panels, RenderTarget::Overlay { ttl_ms: None });
        let second = gate(
            VisualLevel::Panels,
            RenderTarget::Overlay {
                ttl_ms: Some(1_000),
            },
        );
        assert_eq!(first.target, second.target);
    }

    #[test]
    fn takeover_admits_the_overlay_with_its_request_intact() {
        let requested = RenderTarget::Overlay {
            ttl_ms: Some(5_000),
        };
        let g = gate(VisualLevel::Takeover, requested.clone());
        assert_eq!(g.target, requested);
        assert_eq!(g.note, None);
    }

    #[test]
    fn the_width_cap_is_a_third_at_panels_and_a_half_above_it() {
        // SC-005, at a 120-column terminal.
        assert_eq!(panel_width_cap(VisualLevel::None, 120), 0);
        assert_eq!(panel_width_cap(VisualLevel::Panels, 120), 40);
        assert_eq!(panel_width_cap(VisualLevel::PanelsWide, 120), 60);
        assert_eq!(panel_width_cap(VisualLevel::Takeover, 120), 60);
    }

    #[test]
    fn the_width_cap_floors_rather_than_rounds_up() {
        // A cap that rounded up could hand the agent one column more than the tier allows.
        assert_eq!(panel_width_cap(VisualLevel::Panels, 100), 33);
        assert_eq!(panel_width_cap(VisualLevel::PanelsWide, 101), 50);
    }

    #[test]
    fn an_agent_ttl_request_is_clamped_silently_to_the_configured_ceiling() {
        // FR-021 / US2 §6: 90s asked, 20s configured, 20s granted — no error.
        let cfg = VisualConfig {
            takeover_ttl_secs: 20,
            ..VisualConfig::default()
        };
        assert_eq!(resolve_ttl(Some(90_000), &cfg), 20_000);
        assert_eq!(
            resolve_ttl(Some(5_000), &cfg),
            5_000,
            "under the cap survives"
        );
        assert_eq!(
            resolve_ttl(None, &cfg),
            20_000,
            "no request means the configured lifetime"
        );
    }

    #[test]
    fn the_published_config_is_what_the_gate_reads_and_defaults_when_unset() {
        // Nothing published (headless, batch, tests) means the default ceiling, not a locked one.
        assert_eq!(active().level, VisualLevel::Panels);
    }
}
