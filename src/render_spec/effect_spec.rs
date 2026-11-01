//! [`EffectSpec`] (009-tachyonfx-effects) — the declarative description of a terminal effect.
//!
//! **This type deliberately contains NO tachyonfx or ratatui types** (contracts/effect-spec.md),
//! for the same reason [`crate::render_spec::RenderSpec`] contains no ratatui or Monty types: it is a
//! pure serde value recorded verbatim in the episode transcript, so `tachyonfx` never leaks toward
//! `bee-core` through the transcript (SC-009, Constitution V). It compiles in the headless build;
//! resolution to a live `tachyonfx::Effect` happens only in `tui::effects`, behind the `tui` feature.
//!
//! Durations are clamped to [`MIN_MS`]..=[`MAX_MS`] **at construction** (FR-023), so the recorded
//! value is always the effective one and replaying a transcript reproduces the original animation
//! rather than a differently-clamped approximation.

use serde::{Deserialize, Serialize};

/// Shortest effect duration. Below this an animation reads as a flicker rather than a transition.
pub const MIN_MS: u32 = 100;
/// Longest effect duration. Above this the agent is holding the operator's attention, not decorating.
pub const MAX_MS: u32 = 2000;

/// Clamp a requested duration into the permitted band (FR-023). Applied on construction *and* on
/// deserialize — defense in depth, so a hand-edited transcript cannot smuggle a 60-second fade past
/// the band. Non-positive and absurd values clamp rather than error: an effect is decoration, and a
/// model that guesses badly should still get a working render.
pub fn clamp_ms(ms: i64) -> u32 {
    ms.clamp(MIN_MS as i64, MAX_MS as i64) as u32
}

/// The direction an effect travels. Distinct from [`crate::render_spec::Direction`], which is a
/// *layout* axis (vertical/horizontal) — these are the four cardinal senses a slide or sweep moves
/// in, and they map to `tachyonfx::Motion` in the runtime layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectDirection {
    /// Enters from / exits toward the left edge.
    #[default]
    Left,
    Right,
    Top,
    Bottom,
}

impl EffectDirection {
    /// Parse a Python direction string, falling back to [`EffectDirection::Left`] for anything
    /// unrecognized (contracts/rhai-effect-api.md). Canonicalized at *construction*, so the recorded
    /// transcript never contains a bogus direction.
    pub fn parse(s: &str) -> Self {
        match s {
            "right" => Self::Right,
            "top" => Self::Top,
            "bottom" => Self::Bottom,
            // "left" and everything else.
            _ => Self::Left,
        }
    }
}

/// A declarative effect description, produced by the Python render API and resolved to a live
/// tachyonfx effect by `tui::effects` (contracts/effect-spec.md).
///
/// Variants split into two categories that behave differently under `NO_COLOR` (FR-006):
/// *color* effects ([`Self::FadeIn`], [`Self::FadeOut`], [`Self::Pulse`], [`Self::Glow`]) become
/// instant no-ops, while *text* effects still play — a monochrome terminal keeps its motion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectSpec {
    /// Fade from the background toward the content.
    FadeIn { ms: u32 },
    /// Fade from the content toward the background.
    FadeOut { ms: u32 },
    /// Characters coalesce out of random noise (tachyonfx `coalesce`).
    DissolveIn { ms: u32 },
    /// Characters dissolve into random noise (tachyonfx `dissolve`).
    DissolveOut { ms: u32 },
    /// Content slides in from `direction`.
    SlideIn { direction: EffectDirection, ms: u32 },
    /// Content slides out toward `direction`.
    SlideOut { direction: EffectDirection, ms: u32 },
    /// A colored wave reveals the content.
    SweepIn { direction: EffectDirection, ms: u32 },
    /// A colored wave hides the content.
    SweepOut { direction: EffectDirection, ms: u32 },
    /// A single flash of `color` that fades back — for status changes. `color` is a theme role name
    /// or a `#RRGGBB` literal; unknown values resolve to the `info` role at *render* time, because
    /// which roles exist depends on the active theme (005-themes).
    Pulse { color: String, ms: u32 },
    /// Lighten toward white and back — a gentle breathing effect.
    Glow { ms: u32 },
    /// Characters morph through block glyphs into the real content.
    EvolveIn { ms: u32 },
    /// Content devolves into block glyphs, then disappears.
    EvolveOut { ms: u32 },
}

impl EffectSpec {
    /// Whether this effect works by changing colors. Color effects are suppressed under `NO_COLOR`
    /// (FR-006); text effects are not.
    pub fn is_color(&self) -> bool {
        matches!(
            self,
            Self::FadeIn { .. } | Self::FadeOut { .. } | Self::Pulse { .. } | Self::Glow { .. }
        )
    }

    /// The requested duration.
    pub fn ms(&self) -> u32 {
        match self {
            Self::FadeIn { ms }
            | Self::FadeOut { ms }
            | Self::DissolveIn { ms }
            | Self::DissolveOut { ms }
            | Self::SlideIn { ms, .. }
            | Self::SlideOut { ms, .. }
            | Self::SweepIn { ms, .. }
            | Self::SweepOut { ms, .. }
            | Self::Pulse { ms, .. }
            | Self::Glow { ms }
            | Self::EvolveIn { ms }
            | Self::EvolveOut { ms } => *ms,
        }
    }

    /// Re-clamp after deserialization (see [`clamp_ms`]).
    pub fn clamped(mut self) -> Self {
        let c = clamp_ms(self.ms() as i64);
        match &mut self {
            Self::FadeIn { ms }
            | Self::FadeOut { ms }
            | Self::DissolveIn { ms }
            | Self::DissolveOut { ms }
            | Self::SlideIn { ms, .. }
            | Self::SlideOut { ms, .. }
            | Self::SweepIn { ms, .. }
            | Self::SweepOut { ms, .. }
            | Self::Pulse { ms, .. }
            | Self::Glow { ms }
            | Self::EvolveIn { ms }
            | Self::EvolveOut { ms } => *ms = c,
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<EffectSpec> {
        vec![
            EffectSpec::FadeIn { ms: 300 },
            EffectSpec::FadeOut { ms: 300 },
            EffectSpec::DissolveIn { ms: 300 },
            EffectSpec::DissolveOut { ms: 300 },
            EffectSpec::SlideIn {
                direction: EffectDirection::Left,
                ms: 400,
            },
            EffectSpec::SlideOut {
                direction: EffectDirection::Right,
                ms: 400,
            },
            EffectSpec::SweepIn {
                direction: EffectDirection::Top,
                ms: 400,
            },
            EffectSpec::SweepOut {
                direction: EffectDirection::Bottom,
                ms: 400,
            },
            EffectSpec::Pulse {
                color: "sting".into(),
                ms: 200,
            },
            EffectSpec::Glow { ms: 500 },
            EffectSpec::EvolveIn { ms: 600 },
            EffectSpec::EvolveOut { ms: 600 },
        ]
    }

    #[test]
    fn every_variant_round_trips() {
        for spec in all_variants() {
            let json = serde_json::to_string(&spec).expect("serialize");
            let back: EffectSpec = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(spec, back, "round trip failed for {json}");
        }
    }

    #[test]
    fn the_tag_is_kind_and_snake_case() {
        let json = serde_json::to_string(&EffectSpec::SlideIn {
            direction: EffectDirection::Left,
            ms: 400,
        })
        .expect("serialize");
        assert!(json.contains(r#""kind":"slide_in""#), "got {json}");
        assert!(json.contains(r#""direction":"left""#), "got {json}");
    }

    #[test]
    fn durations_clamp_into_the_band() {
        assert_eq!(clamp_ms(5000), MAX_MS);
        assert_eq!(clamp_ms(10), MIN_MS);
        assert_eq!(clamp_ms(0), MIN_MS);
        assert_eq!(clamp_ms(-1), MIN_MS);
        assert_eq!(clamp_ms(400), 400);
    }

    #[test]
    fn deserialize_re_clamps_out_of_band_durations() {
        // A hand-edited transcript must not smuggle a 60s fade past the band.
        let spec: EffectSpec =
            serde_json::from_str(r#"{"kind":"fade_in","ms":60000}"#).expect("deserialize");
        assert_eq!(spec.clamped().ms(), MAX_MS);
    }

    #[test]
    fn unknown_kind_is_an_error_not_a_silent_no_op() {
        let r: Result<EffectSpec, _> = serde_json::from_str(r#"{"kind":"teleport","ms":300}"#);
        assert!(r.is_err(), "unknown kind must not deserialize");
    }

    #[test]
    fn unknown_direction_canonicalizes_to_left_at_construction() {
        assert_eq!(EffectDirection::parse("sideways"), EffectDirection::Left);
        assert_eq!(EffectDirection::parse(""), EffectDirection::Left);
        assert_eq!(EffectDirection::parse("right"), EffectDirection::Right);
        assert_eq!(EffectDirection::parse("top"), EffectDirection::Top);
        assert_eq!(EffectDirection::parse("bottom"), EffectDirection::Bottom);
    }

    #[test]
    fn color_and_text_variants_are_classified_for_no_color() {
        // Only these four are suppressed under NO_COLOR (FR-006); the rest keep their motion.
        for spec in all_variants() {
            let expected = matches!(
                spec,
                EffectSpec::FadeIn { .. }
                    | EffectSpec::FadeOut { .. }
                    | EffectSpec::Pulse { .. }
                    | EffectSpec::Glow { .. }
            );
            assert_eq!(spec.is_color(), expected, "misclassified {spec:?}");
        }
    }
}
