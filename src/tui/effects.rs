//! The effects pipeline (009-tachyonfx-effects): resolve [`EffectSpec`] data into live tachyonfx
//! effects, own them, and advance them each frame.
//!
//! **This module is the single chokepoint** every effect passes through (research R5). That matters
//! for FR-006c: when animations are disabled, [`resolve`] returns `None` for everything, nothing is
//! ever registered, [`Effects::is_running`] is permanently false, and the render loop therefore
//! *cannot* enter its 60fps state. Suppression is structural rather than a rule each of a dozen call
//! sites has to remember.
//!
//! Effects are applied to the ratatui [`Buffer`] **after** widgets render and **before** the buffer
//! is flushed (FR-001) — they transform already-drawn cells, they do not draw.
//!
//! Determinism: tachyonfx carries its own seeded `SimpleRng` and has no `rand` dependency, so the
//! character-scatter effects reproduce for a given area and timeline. That is what makes the
//! snapshot assertions below meaningful rather than flaky.

use std::time::Duration;

use ratatui::buffer::Buffer;
use ratatui::layout::{Offset, Position, Rect};
use ratatui::style::Color;
use tachyonfx::{blit_buffer_region, fx, Effect, EffectManager, Motion, SimpleRng};

use crate::config::{VisualConfig, VisualLevel};
use crate::render_spec::{EffectDirection, EffectSpec};
use crate::viz::buffer_render::theme_to_ratatui_color;
use crate::viz::palette;
use crate::viz::theme::{self, Role};

/// How wide the leading gradient is on slide/sweep effects, in cells. Not agent-tunable: the Rhai
/// surface exposes direction and duration only, and this is a house value chosen so the wave reads
/// as a wave at typical panel widths (contracts/rhai-effect-api.md).
const GRADIENT_LEN: u16 = 8;
/// Per-cell timing jitter on slide/sweep. A little randomness stops the edge looking like a ruler.
const RANDOMNESS: u16 = 15;
/// How far [`EffectSpec::Glow`] lightens before returning.
const GLOW_AMOUNT: f32 = 0.4;
/// Fixed seed for the erosion pattern. Fixed rather than random so a fade-out reproduces frame to
/// frame — an erosion that rerolled each frame would shimmer instead of dissolving.
const ERODE_SEED: u32 = 0x9E37_79B9;

/// Default entrance transition for a newly created panel (FR-003).
pub const PANEL_ENTER_MS: u32 = 300;
/// Default transition when a panel's content is replaced (FR-004).
pub const PANEL_UPDATE_MS: u32 = 400;
/// Overlay entrance / exit fade (FR-018).
pub const OVERLAY_FADE_MS: u32 = 200;

/// Where an effect came from. Only agent-originated effects are gated by [`VisualLevel`]: harness
/// chrome is bee's own UI, and `visual_level` governs the agent (FR-006d).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Requested by a model script, or applied automatically to a model-owned panel.
    Agent,
    /// bee's own UI transitions (FR-026). Not overridable by the agent, and not restricted by level.
    Chrome,
}

/// Everything [`resolve`] needs to decide whether — and how — an effect should exist.
#[derive(Debug, Clone, Copy)]
pub struct ResolveCtx {
    /// The three presentation axes.
    pub visual: VisualConfig,
    /// The region the effect will play in. A zero-area region is a no-op rather than a crash.
    pub area: Rect,
    pub origin: Origin,
    /// Whether ANSI color may be emitted. Threaded rather than read from the environment so tests
    /// can exercise both states without mutating process-global state.
    pub color: bool,
}

impl ResolveCtx {
    /// A context for an agent-originated effect under the current process color setting.
    pub fn agent(visual: VisualConfig, area: Rect) -> Self {
        ResolveCtx {
            visual,
            area,
            origin: Origin::Agent,
            color: palette::is_color_enabled(),
        }
    }

    /// A context for a harness-chrome effect (FR-026).
    pub fn chrome(visual: VisualConfig, area: Rect) -> Self {
        ResolveCtx {
            origin: Origin::Chrome,
            ..Self::agent(visual, area)
        }
    }
}

/// Resolve a declarative [`EffectSpec`] into a live tachyonfx effect.
///
/// `None` means **"render the final content now, register nothing"** — never "fail". An effect is
/// decoration; a tool call must not break because the operator turned animations off. The four
/// suppression conditions (contracts/motion-control.md):
///
/// | Condition | Suppresses |
/// |---|---|
/// | animations disabled | every variant, every origin (FR-006b) |
/// | `NO_COLOR` | the four color variants only (FR-006) |
/// | zero-area region | every variant (spec Edge Cases) |
/// | `visual_level = none` | every **agent** variant (FR-024) — chrome still plays |
pub fn resolve(spec: &EffectSpec, ctx: &ResolveCtx) -> Option<Effect> {
    if suppressed(spec, ctx) {
        return None;
    }
    Some(build(spec, ctx))
}

/// The suppression half of [`resolve`], factored out so composite transitions that cannot be
/// expressed as a single [`EffectSpec`] (see [`panel_update`]) still consult exactly one gate.
fn suppressed(spec: &EffectSpec, ctx: &ResolveCtx) -> bool {
    if !ctx.visual.animations {
        return true;
    }
    if ctx.area.width == 0 || ctx.area.height == 0 {
        return true;
    }
    if ctx.origin == Origin::Agent && ctx.visual.level == VisualLevel::None {
        return true;
    }
    // Color effects have nothing to say on a monochrome terminal, but text effects keep their
    // motion — a NO_COLOR user has not asked for a still screen (FR-006).
    spec.is_color() && !ctx.color
}

/// Map a resolved spec to its tachyonfx construction (research R3).
///
/// Ten of the twelve are direct calls. Two are composites, because tachyonfx has no such primitive:
/// [`EffectSpec::Pulse`] is a there-and-back fade pair, and [`EffectSpec::Glow`] is a ping-ponged
/// lighten. One inverts naming: bee's `dissolve_in` is tachyonfx's `coalesce` (characters
/// *reforming*), because bee names all twelve by their `_in`/`_out` sense.
fn build(spec: &EffectSpec, ctx: &ResolveCtx) -> Effect {
    // `EffectTimer: From<u32>` reads the value as milliseconds, which is exactly what an
    // `EffectSpec` carries — no Duration round-trip needed.
    let ms = |m: u32| m;
    let bg = role_color(Role::Info);
    match spec {
        EffectSpec::FadeIn { ms: m } => fx::fade_from(bg, bg, ms(*m)),
        EffectSpec::FadeOut { ms: m } => fx::fade_to(bg, bg, ms(*m)),
        // Naming inverts against tachyonfx: "in" means the content arrives.
        EffectSpec::DissolveIn { ms: m } => fx::coalesce(ms(*m)),
        EffectSpec::DissolveOut { ms: m } => fx::dissolve(ms(*m)),
        EffectSpec::SlideIn { direction, ms: m } => {
            fx::slide_in(motion(*direction), GRADIENT_LEN, RANDOMNESS, bg, ms(*m))
        }
        EffectSpec::SlideOut { direction, ms: m } => {
            fx::slide_out(motion(*direction), GRADIENT_LEN, RANDOMNESS, bg, ms(*m))
        }
        EffectSpec::SweepIn { direction, ms: m } => {
            fx::sweep_in(motion(*direction), GRADIENT_LEN, RANDOMNESS, bg, ms(*m))
        }
        EffectSpec::SweepOut { direction, ms: m } => {
            fx::sweep_out(motion(*direction), GRADIENT_LEN, RANDOMNESS, bg, ms(*m))
        }
        // Composite: flash toward the color, then back. Half the budget each way.
        EffectSpec::Pulse { color, ms: m } => {
            let c = named_color(color);
            let half = ms((*m).max(2) / 2);
            fx::sequence(&[fx::fade_to_fg(c, half), fx::fade_from_fg(c, half)])
        }
        // Composite: lighten and return, which is what "breathing" means here.
        EffectSpec::Glow { ms: m } => fx::ping_pong(fx::lighten(
            Some(GLOW_AMOUNT),
            Some(GLOW_AMOUNT),
            ms((*m).max(2) / 2),
        )),
        EffectSpec::EvolveIn { ms: m } => {
            fx::evolve_into(fx::EvolveSymbolSet::BlocksHorizontal, ms(*m))
        }
        EffectSpec::EvolveOut { ms: m } => {
            fx::evolve_from(fx::EvolveSymbolSet::BlocksHorizontal, ms(*m))
        }
    }
    .with_area(ctx.area)
}

/// The default entrance for a newly created panel (FR-003): a fade from the `info` role.
pub fn panel_enter_spec() -> EffectSpec {
    EffectSpec::FadeIn { ms: PANEL_ENTER_MS }
}

/// The default transition when a panel's content is replaced (FR-004): the outgoing content
/// dissolves while the incoming content coalesces, in parallel.
///
/// Returned as a pair rather than one spec because the two halves target different buffers — the
/// snapshot of the old content and the freshly rendered new content.
pub fn panel_update_specs() -> (EffectSpec, EffectSpec) {
    (
        EffectSpec::DissolveOut {
            ms: PANEL_UPDATE_MS,
        },
        EffectSpec::DissolveIn {
            ms: PANEL_UPDATE_MS,
        },
    )
}

/// Build the panel-replacement transition over a snapshot of the outgoing content (FR-004).
///
/// The two halves target different content — `prev` is the panel as it looked before the update,
/// while the incoming content is whatever the widget just drew into the buffer — so this cannot be
/// one [`EffectSpec`]. It routes through the same suppression gate as everything else, and returns
/// `None` for the same four reasons [`resolve`] does.
///
/// Realized as a sequence over one budget rather than two literally-simultaneous shaders: tachyonfx
/// effects transform the cells that are already in the buffer, so blending two *sources* per cell is
/// not something the stock primitives can express. The first half blits the outgoing snapshot back
/// over the freshly drawn content and dissolves it away; the second half coalesces the new content
/// that was underneath all along. On screen that is the cross-fade — old scatters out, new forms in.
pub fn panel_update(prev: Buffer, ctx: &ResolveCtx) -> Option<Effect> {
    let (out_spec, in_spec) = panel_update_specs();
    if suppressed(&out_spec, ctx) || suppressed(&in_spec, ctx) {
        return None;
    }
    let half = (PANEL_UPDATE_MS / 2).max(1);
    let origin = ctx.area;
    Some(
        fx::sequence(&[
            fx::parallel(&[blit(prev, origin, half), fx::dissolve(half)]),
            fx::coalesce(half),
        ])
        .with_area(ctx.area),
    )
}

/// The outgoing content erodes away, revealing whatever the frame drew underneath (FR-018).
///
/// This is the overlay's fade-out. It is not a dissolve: a dissolve blanks cells, so the chat would
/// snap back all at once when the effect ended. Here each cell either still shows the departing
/// content or has already given way to the content beneath it, so the chat returns *through* the
/// overlay rather than after it.
///
/// Routed through the same suppression gate as everything else, so an animation-disabled session
/// gets `None` and the overlay simply vanishes on the next redraw.
pub fn erode(prev: Buffer, ctx: &ResolveCtx) -> Option<Effect> {
    if suppressed(
        &EffectSpec::DissolveOut {
            ms: OVERLAY_FADE_MS,
        },
        ctx,
    ) {
        return None;
    }
    let area = ctx.area;
    Some(
        fx::effect_fn_buf(prev, OVERLAY_FADE_MS, move |prev, ctx, buf| {
            // A fresh RNG per frame from a fixed seed, walked in a fixed order: a cell that survived
            // at 30% has therefore also survived at 20%, so the erosion only ever grows. Reseeding
            // per frame is what tachyonfx's own `Dissolve` does, for the same reason.
            let mut rng = SimpleRng::new(ERODE_SEED);
            let alpha = ctx.alpha();
            for y in area.y..area.bottom() {
                for x in area.x..area.right() {
                    let survives = rng.gen_f32() > alpha;
                    let pos = Position::new(x, y);
                    if survives && prev.area.contains(pos) && buf.area.contains(pos) {
                        buf[pos] = prev[pos].clone();
                    }
                }
            }
        })
        .with_area(area),
    )
}

/// Copy `area` out of `buf` into a standalone buffer — the snapshot an [`erode`] plays back.
pub fn capture(area: Rect, buf: &Buffer) -> Buffer {
    let mut snap = Buffer::empty(area);
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            let pos = Position::new(x, y);
            if buf.area.contains(pos) {
                snap[pos] = buf[pos].clone();
            }
        }
    }
    snap
}

/// An effect that draws `src` over `area` on every tick for `ms`, changing nothing else.
///
/// Used as the floor of the update transition: the dissolve running beside it needs the *outgoing*
/// content in the buffer to eat away at, and the widget has already overwritten it with the new one.
fn blit(src: Buffer, area: Rect, ms: u32) -> Effect {
    fx::effect_fn_buf(src, ms, move |src, _ctx, buf| {
        blit_buffer_region(
            src,
            src.area,
            buf,
            Offset {
                x: i32::from(area.x),
                y: i32::from(area.y),
            },
        );
    })
}

// --- Harness chrome (US5) ---------------------------------------------------------------------
//
// bee's own UI moves with the same vocabulary it gives the agent, but through a separate door: every
// preset below resolves with `Origin::Chrome` and registers **unkeyed**, so no agent panel name can
// address, cancel, or replace one (FR-028). The agent picks its own effects; it does not get to pick
// bee's. The motion switch still silences all of it — that axis is the operator's, not the agent's.

/// The header's session-start fade (FR-026).
pub const CHROME_HEADER_MS: u32 = 300;
/// The footer's session-start slide.
pub const CHROME_FOOTER_MS: u32 = 300;
/// A tool-call line acknowledging its result, and the pass/fail flash at the end of an episode.
pub const CHROME_PULSE_MS: u32 = 500;
/// The mascot materializing at startup.
pub const CHROME_MASCOT_MS: u32 = 600;

/// Which piece of bee's own UI a chrome effect belongs to (FR-026).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chrome {
    /// The header fades up from the background at session start.
    Header,
    /// The footer slides up into place beneath it.
    Footer,
    /// A tool-call line flashes `accent` when its result lands, so the eye finds the pair.
    ToolResult,
    /// An episode finished: `success` or `error`, depending.
    EpisodePass,
    EpisodeFail,
    /// The mascot materializes out of block glyphs.
    Mascot,
}

impl Chrome {
    /// The effect this preset plays. Chrome speaks the same twelve-verb vocabulary the agent does —
    /// there is no second, privileged effect language.
    fn spec(self) -> EffectSpec {
        match self {
            Chrome::Header => EffectSpec::FadeIn {
                ms: CHROME_HEADER_MS,
            },
            Chrome::Footer => EffectSpec::SlideIn {
                direction: EffectDirection::Bottom,
                ms: CHROME_FOOTER_MS,
            },
            Chrome::ToolResult => EffectSpec::Pulse {
                color: "accent".into(),
                ms: CHROME_PULSE_MS,
            },
            Chrome::EpisodePass => EffectSpec::Pulse {
                color: "success".into(),
                ms: CHROME_PULSE_MS,
            },
            Chrome::EpisodeFail => EffectSpec::Pulse {
                color: "error".into(),
                ms: CHROME_PULSE_MS,
            },
            // Block glyphs resolving into the bee, rather than the old pop-in (US5 §2).
            Chrome::Mascot => EffectSpec::EvolveIn {
                ms: CHROME_MASCOT_MS,
            },
        }
    }
}

/// Play a chrome preset over `area` (FR-026, FR-028).
///
/// Unkeyed on purpose: `EffectManager::unique` cancels by key, so a keyed chrome effect would be
/// cancellable by any agent panel that happened to share the name. With no key there is nothing for
/// the agent to name.
///
/// Returns whether anything was registered — `false` under the motion switch, which is the one axis
/// that reaches chrome (FR-006b). `visual_level` does not: it governs the agent, and this is bee's
/// own UI (FR-006d).
pub fn chrome(effects: &mut Effects, which: Chrome, area: Rect, visual: VisualConfig) -> bool {
    let ctx = ResolveCtx::chrome(visual, area);
    chrome_with_context(effects, which, &ctx)
}

fn chrome_with_context(effects: &mut Effects, which: Chrome, ctx: &ResolveCtx) -> bool {
    apply(effects, None, &which.spec(), ctx)
}

/// The panel column arriving: it slides in from the right edge when the first panel is created
/// (FR-026).
///
/// Motion along the axis that actually changed — the chat pane giving up width — so the movement
/// says what happened rather than merely marking that something did.
///
/// tasks.md called for tachyonfx's `stretch` here. That one belongs to the small family (with
/// `resize_area`) that must be applied *before* widgets render, because it resizes the area they
/// draw into; this pipeline applies effects after rendering (FR-001), where `stretch` collapses the
/// drawn column and never gives it back. `slide_in` is the post-render effect with the same reading.
pub fn column_appear(effects: &mut Effects, area: Rect, visual: VisualConfig) -> bool {
    let ctx = ResolveCtx::chrome(visual, area);
    apply(
        effects,
        None,
        &EffectSpec::SlideIn {
            direction: EffectDirection::Right,
            ms: CHROME_FOOTER_MS,
        },
        &ctx,
    )
}

fn motion(d: EffectDirection) -> Motion {
    match d {
        EffectDirection::Left => Motion::LeftToRight,
        EffectDirection::Right => Motion::RightToLeft,
        EffectDirection::Top => Motion::UpToDown,
        EffectDirection::Bottom => Motion::DownToUp,
    }
}

fn role_color(role: Role) -> Color {
    theme_to_ratatui_color(theme::active_theme().get(role))
}

/// Resolve a `pulse` color string against the active theme. Unknown names fall back to the `info`
/// role — resolved *here* rather than at construction, because which palette entries exist depends
/// on the theme active at render time (005-themes).
fn named_color(name: &str) -> Color {
    let t = theme::active_theme();
    theme_to_ratatui_color(&theme::resolve_color_name(t, name))
}

/// Owns the live effects and advances them (FR-001, research R4).
///
/// Keyed by `String`, which is the panel name for panel transitions and a reserved key for the
/// overlay. tachyonfx's `unique(key, fx)` cancels any running effect sharing a key, which *is*
/// FR-005 — a second update to a panel mid-transition replaces the first rather than stacking on it.
/// Chrome effects are added unkeyed, so no agent panel name can cancel or replace them (FR-028).
#[derive(Default)]
pub struct Effects {
    manager: EffectManager<String>,
}

impl std::fmt::Debug for Effects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Effects")
            .field("running", &self.is_running())
            .finish()
    }
}

impl Effects {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a keyed effect, cancelling any running effect with the same key (FR-005).
    pub fn add_keyed(&mut self, key: impl Into<String>, effect: Effect) {
        let fx = self.manager.unique(key.into(), effect);
        self.manager.add_effect(fx);
    }

    /// Register an unkeyed effect — used for harness chrome, which the agent cannot address and
    /// therefore cannot cancel (FR-028).
    pub fn add(&mut self, effect: Effect) {
        self.manager.add_effect(effect);
    }

    /// Cancel a keyed effect if one is running.
    pub fn cancel(&mut self, key: impl Into<String>) {
        self.manager.cancel_unique_effect(key.into());
    }

    /// Whether any effect is still active. Drives the render loop's motion state (FR-002 state 1);
    /// when animations are disabled this is always false, because nothing is ever registered.
    pub fn is_running(&self) -> bool {
        self.manager.is_running()
    }

    /// Advance every active effect by `dt` and apply it to `buf` (FR-001). Called after widgets
    /// render, before the buffer is flushed.
    pub fn process(&mut self, dt: Duration, buf: &mut Buffer, area: Rect) {
        // tachyonfx carries its own compact `Duration`; convert at the boundary so callers
        // keep speaking std.
        self.manager.process_effects(dt.into(), buf, area);
    }
}

/// Convenience: resolve and register in one step, honoring every suppression rule. Returns whether
/// an effect was actually registered — `false` means the caller should show final content
/// immediately, which is the correct behavior in every suppressed case.
pub fn apply(
    effects: &mut Effects,
    key: Option<&str>,
    spec: &EffectSpec,
    ctx: &ResolveCtx,
) -> bool {
    match resolve(spec, ctx) {
        Some(fx) => {
            match key {
                Some(k) => effects.add_keyed(k, fx),
                None => effects.add(fx),
            }
            true
        }
        None => false,
    }
}

/// A fixed-step clock for testing effects without a terminal or a real one (T015).
///
/// Real frames redraw the widget *and then* apply effects, so a harness that only advanced the
/// manager over a static buffer would test something the renderer never does — `coalesce` would have
/// nothing to reform. [`Timeline::run`] therefore redraws base content into a fresh buffer each
/// step, exactly like [`crate::tui::view::view`], and captures the result at named offsets.
///
/// Determinism comes free: tachyonfx seeds its own `SimpleRng` and pulls in no `rand`, so the same
/// area and the same step sequence produce the same frames on every run.
#[cfg(test)]
pub(crate) struct Timeline {
    area: Rect,
    step: Duration,
}

#[cfg(test)]
impl Timeline {
    /// A timeline over `area` advancing one 16ms frame at a time — the 60fps state of FR-002.
    pub(crate) fn frames(area: Rect) -> Self {
        Timeline {
            area,
            step: Duration::from_millis(16),
        }
    }

    /// Advance `effects` to the last requested offset, capturing a buffer snapshot at each.
    ///
    /// `draw` paints the base content — the widget's own output — into a fresh buffer before the
    /// effects for that frame are applied. A snapshot for offset `t` is taken on the first frame
    /// whose elapsed time has reached `t`, so `at(0)` is the pre-animation frame.
    pub(crate) fn run(
        &self,
        effects: &mut Effects,
        at: &[Duration],
        mut draw: impl FnMut(&mut Buffer),
    ) -> Vec<Buffer> {
        let mut captured = Vec::with_capacity(at.len());
        let mut elapsed = Duration::ZERO;
        let mut next = 0usize;
        loop {
            let mut buf = Buffer::empty(self.area);
            draw(&mut buf);
            // Every frame runs the effects pass, including the first — which advances by zero, the
            // same delta `App::tick_clock` hands the first frame of a real session. That is what
            // makes a t=0 snapshot show the *start* of the animation rather than the raw widget.
            let dt = if elapsed.is_zero() {
                Duration::ZERO
            } else {
                self.step
            };
            effects.process(dt, &mut buf, self.area);
            while next < at.len() && at[next] <= elapsed {
                captured.push(buf.clone());
                next += 1;
            }
            if next >= at.len() {
                return captured;
            }
            elapsed += self.step;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome(effects: &mut Effects, which: Chrome, area: Rect, visual: VisualConfig) -> bool {
        chrome_with_context(
            effects,
            which,
            &ResolveCtx {
                visual,
                area,
                origin: Origin::Chrome,
                color: true,
            },
        )
    }
    use crate::config::VisualConfig;
    use ratatui::style::{Modifier, Style};

    fn area() -> Rect {
        Rect::new(0, 0, 20, 5)
    }

    /// Base content for the timeline tests: a filled block of text with a distinct style, so both
    /// symbol mutations (dissolve/coalesce) and color mutations (fade) are visible.
    ///
    /// Both colors are explicit. `Color::Reset` has no place on a gradient, so a faded cell comes
    /// back as whatever concrete color `Reset` resolves to rather than as `Reset` itself — a real
    /// property of color interpolation, but not the one these tests are about.
    fn draw_base(buf: &mut Buffer) {
        for y in buf.area.y..buf.area.bottom() {
            for x in buf.area.x..buf.area.right() {
                buf[(x, y)].set_symbol("X").set_style(
                    Style::default()
                        .fg(Color::Rgb(200, 200, 200))
                        .bg(Color::Rgb(20, 20, 30)),
                );
            }
        }
    }

    fn symbols(buf: &Buffer) -> String {
        let mut s = String::new();
        for y in buf.area.y..buf.area.bottom() {
            for x in buf.area.x..buf.area.right() {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    fn colors(buf: &Buffer) -> Vec<(Color, Color)> {
        let mut v = Vec::new();
        for y in buf.area.y..buf.area.bottom() {
            for x in buf.area.x..buf.area.right() {
                let c = &buf[(x, y)];
                v.push((c.fg, c.bg));
            }
        }
        v
    }

    fn ctx(visual: VisualConfig, color: bool, origin: Origin) -> ResolveCtx {
        ResolveCtx {
            visual,
            area: area(),
            origin,
            color,
        }
    }

    fn on() -> VisualConfig {
        VisualConfig::default()
    }

    fn motionless() -> VisualConfig {
        VisualConfig {
            animations: false,
            ..VisualConfig::default()
        }
    }

    fn all_specs() -> Vec<EffectSpec> {
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
                color: "error".into(),
                ms: 200,
            },
            EffectSpec::Glow { ms: 500 },
            EffectSpec::EvolveIn { ms: 600 },
            EffectSpec::EvolveOut { ms: 600 },
        ]
    }

    #[test]
    fn every_variant_resolves_when_nothing_suppresses_it() {
        let c = ctx(on(), true, Origin::Agent);
        for spec in all_specs() {
            assert!(resolve(&spec, &c).is_some(), "{spec:?} failed to resolve");
        }
    }

    #[test]
    fn disabling_animations_suppresses_everything_including_chrome() {
        // FR-006b: the kill switch reaches every origin. This is what makes FR-006c structural —
        // nothing registered means `is_running()` is permanently false.
        for origin in [Origin::Agent, Origin::Chrome] {
            let c = ctx(motionless(), true, origin);
            for spec in all_specs() {
                assert!(
                    resolve(&spec, &c).is_none(),
                    "{spec:?} survived the kill switch at {origin:?}"
                );
            }
        }
    }

    #[test]
    fn no_color_suppresses_color_effects_but_keeps_text_motion() {
        // FR-006: a monochrome terminal is not a request for a still screen.
        let c = ctx(on(), false, Origin::Agent);
        for spec in all_specs() {
            let resolved = resolve(&spec, &c).is_some();
            assert_eq!(
                resolved,
                !spec.is_color(),
                "{spec:?} misbehaved under NO_COLOR"
            );
        }
    }

    #[test]
    fn a_zero_area_region_is_a_no_op_not_a_crash() {
        for area in [
            Rect::new(0, 0, 0, 5),
            Rect::new(0, 0, 20, 0),
            Rect::new(0, 0, 0, 0),
        ] {
            let c = ResolveCtx {
                area,
                ..ctx(on(), true, Origin::Agent)
            };
            for spec in all_specs() {
                assert!(resolve(&spec, &c).is_none(), "{spec:?} at {area:?}");
            }
        }
    }

    #[test]
    fn visual_level_none_strips_agent_effects_but_not_chrome() {
        // FR-006d / FR-024: the level governs the agent; chrome is bee's own UI.
        let level_none = VisualConfig {
            level: VisualLevel::None,
            ..VisualConfig::default()
        };
        let agent = ctx(level_none, true, Origin::Agent);
        let chrome = ctx(level_none, true, Origin::Chrome);
        for spec in all_specs() {
            assert!(resolve(&spec, &agent).is_none(), "agent {spec:?}");
            assert!(resolve(&spec, &chrome).is_some(), "chrome {spec:?}");
        }
    }

    #[test]
    fn a_keyed_effect_cancels_the_previous_one_with_the_same_key() {
        // FR-005: the panel name is the key, so a second update mid-transition replaces the first
        // rather than stacking a second animation on top of it.
        let mut e = Effects::new();
        let c = ctx(on(), true, Origin::Agent);
        let mut buf = Buffer::empty(area());

        assert!(apply(&mut e, Some("metrics"), &all_specs()[0], &c));
        e.process(Duration::from_millis(16), &mut buf, area());
        assert!(e.is_running());

        assert!(apply(&mut e, Some("metrics"), &all_specs()[2], &c));
        // Drain: with the first effect cancelled, only the second's budget remains. If both were
        // live this would still be running well past a single effect's duration.
        for _ in 0..80 {
            e.process(Duration::from_millis(16), &mut buf, area());
        }
        assert!(!e.is_running(), "cancelled effect kept the loop alive");
    }

    #[test]
    fn different_keys_do_not_interfere() {
        let mut e = Effects::new();
        let c = ctx(on(), true, Origin::Agent);
        let mut buf = Buffer::empty(area());
        apply(&mut e, Some("a"), &all_specs()[0], &c);
        apply(&mut e, Some("b"), &all_specs()[1], &c);
        e.process(Duration::from_millis(16), &mut buf, area());
        assert!(e.is_running());
        e.cancel("a");
        e.process(Duration::from_millis(16), &mut buf, area());
        assert!(e.is_running(), "cancelling 'a' must not cancel 'b'");
    }

    #[test]
    fn nothing_registers_when_motion_is_off_so_the_loop_never_ticks() {
        // FR-006c, the structural guarantee: an animation-disabled session cannot enter the 60fps
        // state, because there is never anything to advance.
        let mut e = Effects::new();
        let c = ctx(motionless(), true, Origin::Agent);
        for spec in all_specs() {
            assert!(!apply(&mut e, Some("panel"), &spec, &c));
        }
        assert!(!e.is_running());
    }

    #[test]
    fn apply_reports_false_when_suppressed_so_callers_show_final_content() {
        let mut e = Effects::new();
        let suppressed = ctx(motionless(), true, Origin::Agent);
        assert!(!apply(&mut e, Some("p"), &all_specs()[0], &suppressed));
        let live = ctx(on(), true, Origin::Agent);
        assert!(apply(&mut e, Some("p"), &all_specs()[0], &live));
    }

    #[test]
    fn the_panel_defaults_are_a_fade_in_and_a_dissolve_pair() {
        assert!(matches!(panel_enter_spec(), EffectSpec::FadeIn { .. }));
        let (out, in_) = panel_update_specs();
        assert!(matches!(out, EffectSpec::DissolveOut { .. }));
        assert!(matches!(in_, EffectSpec::DissolveIn { .. }));
    }

    // --- US1: the animation actually plays, and stops when told to (T022/T023/T025/T027/T028) ----

    #[test]
    fn a_panel_entrance_starts_at_the_theme_color_and_lands_on_the_final_content() {
        // SC-001: at t=0 the region is the fade-from color, at 150ms it is neither that nor the
        // final content, and by 300ms the widget's own colors are on screen untouched.
        let mut e = Effects::new();
        let c = ctx(on(), true, Origin::Agent);
        assert!(apply(&mut e, Some("m"), &panel_enter_spec(), &c));

        let shots = Timeline::frames(area()).run(
            &mut e,
            &[
                Duration::ZERO,
                Duration::from_millis(150),
                Duration::from_millis(PANEL_ENTER_MS as u64),
            ],
            draw_base,
        );

        let mut finished = Buffer::empty(area());
        draw_base(&mut finished);
        let fade_from = role_color(Role::Info);

        assert!(
            colors(&shots[0]).iter().all(|(fg, _)| *fg == fade_from),
            "t=0 must be the fade-from color, not the widget's"
        );
        assert_ne!(
            colors(&shots[1]),
            colors(&shots[0]),
            "t=150ms must have moved off the starting color"
        );
        assert_ne!(
            colors(&shots[1]),
            colors(&finished),
            "t=150ms must not have arrived yet"
        );
        assert_eq!(
            colors(&shots[2]),
            colors(&finished),
            "t=300ms must be the widget's final colors"
        );
        assert_eq!(
            symbols(&shots[1]),
            symbols(&finished),
            "a fade moves color, never glyphs"
        );
    }

    #[test]
    fn a_panel_update_dissolves_the_old_content_then_coalesces_the_new() {
        // SC-002. The outgoing content is a snapshot; the incoming content is what the widget draws
        // every frame, so the base painter here is the *new* content throughout.
        let mut prev = Buffer::empty(area());
        for y in area().y..area().bottom() {
            for x in area().x..area().right() {
                prev[(x, y)].set_symbol("O");
            }
        }
        let draw_new = |buf: &mut Buffer| {
            for y in buf.area.y..buf.area.bottom() {
                for x in buf.area.x..buf.area.right() {
                    buf[(x, y)].set_symbol("N");
                }
            }
        };

        let mut e = Effects::new();
        let c = ctx(on(), true, Origin::Agent);
        let fx = panel_update(prev, &c).expect("update transition");
        e.add_keyed("m", fx);

        let total = PANEL_UPDATE_MS as u64;
        let shots = Timeline::frames(area()).run(
            &mut e,
            &[
                Duration::ZERO,
                Duration::from_millis(total / 4),
                Duration::from_millis(total * 3 / 4),
                Duration::from_millis(total),
            ],
            draw_new,
        );

        assert!(
            symbols(&shots[0]).chars().all(|ch| ch == 'O'),
            "t=0 still shows the outgoing content: {:?}",
            symbols(&shots[0])
        );
        let quarter = symbols(&shots[1]);
        assert!(
            quarter.contains('O') && quarter.contains(' '),
            "a quarter in, the old content is part-dissolved: {quarter:?}"
        );
        let three_quarters = symbols(&shots[2]);
        assert!(
            three_quarters.contains('N') && three_quarters.contains(' '),
            "three quarters in, the new content is part-formed: {three_quarters:?}"
        );
        assert!(
            symbols(&shots[3]).chars().all(|ch| ch == 'N'),
            "by the end only the new content remains: {:?}",
            symbols(&shots[3])
        );
    }

    #[test]
    fn an_erosion_reveals_the_content_underneath_rather_than_blanking_it() {
        // FR-018, the overlay's fade-out. A dissolve would blank cells and snap the chat back at
        // the end; this hands each cell over individually, so the content underneath comes through
        // the gaps while the departing content is still visible in the rest.
        let mut departing = Buffer::empty(area());
        for y in area().y..area().bottom() {
            for x in area().x..area().right() {
                departing[(x, y)].set_symbol("O");
            }
        }
        let draw_under = |buf: &mut Buffer| {
            for y in buf.area.y..buf.area.bottom() {
                for x in buf.area.x..buf.area.right() {
                    buf[(x, y)].set_symbol("U");
                }
            }
        };

        let mut e = Effects::new();
        let c = ctx(on(), true, Origin::Chrome);
        e.add_keyed("overlay", erode(departing, &c).expect("erosion"));

        let total = OVERLAY_FADE_MS as u64;
        let shots = Timeline::frames(area()).run(
            &mut e,
            &[
                Duration::ZERO,
                Duration::from_millis(total / 2),
                Duration::from_millis(total),
            ],
            draw_under,
        );

        assert!(
            symbols(&shots[0]).chars().all(|ch| ch == 'O'),
            "at t=0 the departing content still owns every cell: {:?}",
            symbols(&shots[0])
        );
        let midway = symbols(&shots[1]);
        assert!(
            midway.contains('O') && midway.contains('U'),
            "midway both are on screen at once — that is the reveal: {midway:?}"
        );
        assert!(!midway.contains(' '), "no cell is ever blanked: {midway:?}");
        assert!(
            symbols(&shots[2]).chars().all(|ch| ch == 'U'),
            "by the end only the content underneath remains: {:?}",
            symbols(&shots[2])
        );
    }

    #[test]
    fn an_erosion_only_ever_grows() {
        // The pattern is reseeded identically each frame, so a cell that has given way stays given
        // away. Without that the fade would shimmer — cells flicking back and forth.
        let mut departing = Buffer::empty(area());
        for y in area().y..area().bottom() {
            for x in area().x..area().right() {
                departing[(x, y)].set_symbol("O");
            }
        }
        let mut e = Effects::new();
        let c = ctx(on(), true, Origin::Chrome);
        e.add_keyed("overlay", erode(departing, &c).expect("erosion"));

        let shots = Timeline::frames(area()).run(
            &mut e,
            &[
                Duration::from_millis(64),
                Duration::from_millis(128),
                Duration::from_millis(192),
            ],
            |buf| {
                for y in buf.area.y..buf.area.bottom() {
                    for x in buf.area.x..buf.area.right() {
                        buf[(x, y)].set_symbol("U");
                    }
                }
            },
        );
        let remaining: Vec<usize> = shots
            .iter()
            .map(|s| symbols(s).chars().filter(|c| *c == 'O').count())
            .collect();
        assert!(
            remaining[0] >= remaining[1] && remaining[1] >= remaining[2],
            "the departing content must only ever shrink: {remaining:?}"
        );
    }

    #[test]
    fn an_erosion_is_suppressed_with_the_rest_when_motion_is_off() {
        let c = ctx(motionless(), true, Origin::Chrome);
        assert!(erode(Buffer::empty(area()), &c).is_none());
    }

    #[test]
    fn character_effects_keep_moving_under_no_color_without_touching_a_single_color() {
        // SC-010 / FR-006: NO_COLOR removes color, not motion. A dissolve still mutates glyphs; the
        // fg/bg of every cell is exactly what the widget drew, so nothing can emit a color escape
        // that the widget did not already ask for.
        let mut e = Effects::new();
        let c = ctx(on(), false, Origin::Agent);
        assert!(apply(
            &mut e,
            Some("m"),
            &EffectSpec::DissolveIn { ms: 300 },
            &c
        ));

        let shots = Timeline::frames(area()).run(
            &mut e,
            &[Duration::ZERO, Duration::from_millis(150)],
            draw_base,
        );
        let mut base = Buffer::empty(area());
        draw_base(&mut base);

        assert_ne!(
            symbols(&shots[1]),
            symbols(&base),
            "the dissolve must still mutate glyphs under NO_COLOR"
        );
        for shot in &shots {
            assert_eq!(
                colors(shot),
                colors(&base),
                "no cell's color may change under NO_COLOR"
            );
            assert!(
                shot.content()
                    .iter()
                    .all(|c| c.modifier == Modifier::empty()),
                "no modifier is introduced either"
            );
        }
    }

    #[test]
    fn the_env_kill_switch_leaves_the_first_frame_already_final() {
        // FR-006b/c, SC-011: `BEE_NO_ANIMATION=1` resolves to animations-off, which registers
        // nothing at all — so the very first frame is the finished content and `is_running()` never
        // becomes true, which is what keeps the loop out of its 60fps state.
        // `true` is what `resolve` passes when `BEE_NO_ANIMATION` is present in the environment;
        // injected rather than set, so this test doesn't race other threads over a process global.
        let off = VisualConfig::resolve_with(None, false, None, true, None)
            .expect("BEE_NO_ANIMATION resolves");
        assert!(!off.animations, "the env var must disable motion");

        let mut e = Effects::new();
        let c = ctx(off, true, Origin::Agent);
        assert!(!apply(&mut e, Some("m"), &panel_enter_spec(), &c));
        assert!(panel_update(Buffer::empty(area()), &c).is_none());
        assert!(
            !e.is_running(),
            "an animation-disabled session never has motion to advance"
        );

        let shots = Timeline::frames(area()).run(
            &mut e,
            &[Duration::ZERO, Duration::from_millis(300)],
            draw_base,
        );
        let mut finished = Buffer::empty(area());
        draw_base(&mut finished);
        for shot in &shots {
            assert_eq!(symbols(shot), symbols(&finished));
            assert_eq!(colors(shot), colors(&finished));
        }
    }

    #[test]
    fn the_three_axes_compose_without_cancelling_each_other_out() {
        // SC-012 / FR-006d: NO_COLOR + motion on + `visual_level = none`. The agent gets nothing,
        // bee's own chrome still animates its glyphs, and no color moves anywhere.
        let level_none = VisualConfig {
            level: VisualLevel::None,
            ..VisualConfig::default()
        };
        let spec = EffectSpec::DissolveIn { ms: 300 };

        let agent = ctx(level_none, false, Origin::Agent);
        assert!(
            resolve(&spec, &agent).is_none(),
            "at level none the agent animates nothing"
        );

        let mut e = Effects::new();
        let chrome = ctx(level_none, false, Origin::Chrome);
        assert!(
            apply(&mut e, None, &spec, &chrome),
            "chrome is bee's own UI"
        );

        let shots = Timeline::frames(area()).run(
            &mut e,
            &[Duration::ZERO, Duration::from_millis(150)],
            draw_base,
        );
        let mut base = Buffer::empty(area());
        draw_base(&mut base);
        assert_ne!(
            symbols(&shots[1]),
            symbols(&base),
            "chrome text effects still move"
        );
        assert_eq!(colors(&shots[1]), colors(&base), "and still move no color");
    }

    // --- US5 (T063/T064): bee's own chrome ------------------------------------------------------

    fn all_chrome() -> Vec<Chrome> {
        vec![
            Chrome::Header,
            Chrome::Footer,
            Chrome::ToolResult,
            Chrome::EpisodePass,
            Chrome::EpisodeFail,
            Chrome::Mascot,
        ]
    }

    #[test]
    fn every_chrome_preset_plays_in_an_ordinary_session() {
        let mut e = Effects::new();
        for cue in all_chrome() {
            assert!(
                chrome(&mut e, cue, area(), on()),
                "{cue:?} did not register"
            );
        }
        assert!(column_appear(&mut e, area(), on()));
    }

    #[test]
    fn chrome_is_unkeyed_so_no_agent_panel_can_cancel_it() {
        // FR-028. Cancellation works by key; chrome has none, so there is nothing for the agent to
        // name. Even a panel called after every reserved-sounding word cannot touch it.
        let mut e = Effects::new();
        assert!(chrome(&mut e, Chrome::Header, area(), on()));
        let mut buf = Buffer::empty(area());
        e.process(Duration::from_millis(16), &mut buf, area());
        assert!(e.is_running());

        for name in ["header", "footer", "chrome", "mascot", "takeover", ""] {
            e.cancel(name);
        }
        e.process(Duration::from_millis(16), &mut buf, area());
        assert!(
            e.is_running(),
            "an agent cancelled bee's own chrome by naming a panel"
        );
    }

    #[test]
    fn an_agent_effect_on_any_key_cannot_replace_a_chrome_effect() {
        // The other half of FR-028: `unique(key, fx)` replaces same-keyed effects, and chrome has no
        // key to collide with — so registering agent effects leaves it running, not replaced.
        let mut e = Effects::new();
        chrome(&mut e, Chrome::Footer, area(), on());
        let c = ctx(on(), true, Origin::Agent);
        for key in ["a", "b", "c"] {
            apply(&mut e, Some(key), &panel_enter_spec(), &c);
        }
        let mut buf = Buffer::empty(area());
        // Drain past the agent effects' 300ms but not past the footer's slide.
        for _ in 0..12 {
            e.process(Duration::from_millis(16), &mut buf, area());
        }
        assert!(
            e.is_running(),
            "chrome outlives the agent effects around it"
        );
    }

    #[test]
    fn chrome_still_plays_at_visual_level_none() {
        // FR-006d / US5 §3: the level governs the agent. An operator who gives the agent no screen
        // has not asked bee to stop moving its own UI.
        let level_none = VisualConfig {
            level: VisualLevel::None,
            ..VisualConfig::default()
        };
        let mut e = Effects::new();
        for cue in all_chrome() {
            assert!(
                chrome(&mut e, cue, area(), level_none),
                "{cue:?} was stripped by a level that governs the agent"
            );
        }
        assert!(column_appear(&mut e, area(), level_none));
    }

    #[test]
    fn no_chrome_plays_when_motion_is_off_and_the_loop_never_ticks() {
        // US5 §4/§5 and FR-006b: the motion switch is the one axis that *does* reach chrome, and
        // nothing registering is what keeps the 60fps state unreachable.
        let mut e = Effects::new();
        for cue in all_chrome() {
            assert!(
                !chrome(&mut e, cue, area(), motionless()),
                "{cue:?} survived the kill switch"
            );
        }
        assert!(!column_appear(&mut e, area(), motionless()));
        assert!(!e.is_running());
    }

    #[test]
    fn the_header_fade_starts_at_the_theme_color_and_lands_on_the_real_header() {
        // US5 §1: background-colored cells at t=0, the header's own colors by 300ms.
        let mut e = Effects::new();
        assert!(chrome(&mut e, Chrome::Header, area(), on()));
        let shots = Timeline::frames(area()).run(
            &mut e,
            &[
                Duration::ZERO,
                Duration::from_millis(CHROME_HEADER_MS as u64),
            ],
            draw_base,
        );
        let mut finished = Buffer::empty(area());
        draw_base(&mut finished);
        let fade_from = role_color(Role::Info);
        assert!(colors(&shots[0]).iter().all(|(fg, _)| *fg == fade_from));
        assert_eq!(colors(&shots[1]), colors(&finished));
    }

    #[test]
    fn the_mascot_materializes_out_of_block_glyphs() {
        // US5 §2: an `evolve_into`, not the old pop-in — so midway the cells hold substituted
        // glyphs rather than the final sprite.
        let mut e = Effects::new();
        assert!(chrome(&mut e, Chrome::Mascot, area(), on()));
        let shots = Timeline::frames(area()).run(
            &mut e,
            &[
                Duration::from_millis(CHROME_MASCOT_MS as u64 / 2),
                Duration::from_millis(CHROME_MASCOT_MS as u64),
            ],
            draw_base,
        );
        let mut finished = Buffer::empty(area());
        draw_base(&mut finished);
        assert_ne!(
            symbols(&shots[0]),
            symbols(&finished),
            "midway it is still evolving"
        );
        assert_eq!(symbols(&shots[1]), symbols(&finished), "and arrives whole");
    }

    #[test]
    fn the_verdict_pulses_use_the_success_and_error_roles() {
        // FR-026: pass and fail are different colors because they mean different things.
        assert!(matches!(
            Chrome::EpisodePass.spec(),
            EffectSpec::Pulse { ref color, .. } if color == "success"
        ));
        assert!(matches!(
            Chrome::EpisodeFail.spec(),
            EffectSpec::Pulse { ref color, .. } if color == "error"
        ));
        assert!(matches!(
            Chrome::ToolResult.spec(),
            EffectSpec::Pulse { ref color, .. } if color == "accent"
        ));
    }

    #[test]
    fn chrome_speaks_the_same_vocabulary_the_agent_does() {
        // There is no second, privileged effect language: every preset is one of the twelve.
        for cue in all_chrome() {
            let spec = cue.spec();
            assert!(
                all_specs()
                    .iter()
                    .any(|s| std::mem::discriminant(s) == std::mem::discriminant(&spec)),
                "{cue:?} used an effect outside the twelve"
            );
        }
    }

    #[test]
    fn directions_map_onto_tachyonfx_motions() {
        assert_eq!(motion(EffectDirection::Left), Motion::LeftToRight);
        assert_eq!(motion(EffectDirection::Right), Motion::RightToLeft);
        assert_eq!(motion(EffectDirection::Top), Motion::UpToDown);
        assert_eq!(motion(EffectDirection::Bottom), Motion::DownToUp);
    }
}
