//! Panel registry (008-grid-tui, US2): the model-owned named regions rendered beside chat.
//!
//! Insertion-ordered, unique ids, upsert semantics — the same id **replaces** its spec in place
//! (FR-009), a new id **appends** a panel (FR-008). Coalescing (FR-011) is automatic: only the latest
//! spec per id is retained, so a burst of `render_to("m", …)` between two redraws collapses to the
//! last one drawn.
//!
//! **Lifecycle**: panels used to be create-or-replace only, so they accumulated unbounded and each
//! new one shrank the rest. [`PanelOp`] closes that: a script can remove one panel, clear them all,
//! or attach a TTL so a panel expires on its own ([`PanelRegistry::prune`] drops expired entries on
//! each redraw).
//!
//! The data model names this `IndexMap<PanelId, RenderSpec>`; it is realized as an insertion-ordered
//! `Vec` to keep the default build dependency-free (a session holds a handful of panels, so the
//! linear upsert is immaterial and the observable semantics are identical).

use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use super::effects::{self, Effects, ResolveCtx};
use crate::config::VisualConfig;
use crate::render_spec::{EffectSpec, PanelOp, RenderSpec};

/// The transition a panel owes the effects pipeline on its next render (009 US1).
///
/// Which one it is falls out of the create-vs-replace distinction the registry already draws — the
/// caller never picks a transition, so a panel cannot animate as if it were new when it wasn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// First upsert under this name: fade in (FR-003).
    Enter,
    /// Content replaced in place: dissolve the old, coalesce the new (FR-004).
    Update,
}

/// Per-panel effect state (009 T017).
///
/// It holds the outgoing content and nothing else. Cancellation deliberately does **not** live here:
/// a stored effect handle would have to be reconciled by hand at every re-upsert, whereas
/// `EffectManager::unique` already cancels by panel name for free (FR-005, research R4).
#[derive(Debug, Clone, Default)]
pub struct EffectSlot {
    /// The panel's last rendered content, the outgoing half of an update transition. `None` until
    /// the panel has been drawn once — which is why a brand-new panel gets an entrance, not a
    /// cross-fade from nothing.
    pub prev: Option<Buffer>,
    /// When the pending transition was first requested. A burst of upserts between two redraws
    /// coalesces to one transition (FR-011) that still dates from the first of them, so rapid
    /// updates don't keep pushing the animation's start into the future.
    pub started: Option<Instant>,
    /// A transition the agent asked for with `widget.effect(e)` (009 FR-022). It replaces the
    /// default for the next render only — consumed when the transition is registered, so the panel
    /// returns to its default behavior rather than repeating the request forever.
    pub requested: Option<EffectSpec>,
}

/// One live panel: its id, current content, optional expiry, and pending transition.
#[derive(Debug, Clone)]
pub struct Panel {
    pub id: String,
    pub spec: RenderSpec,
    /// When set, the panel is dropped by [`PanelRegistry::prune`] once this instant passes.
    pub expires_at: Option<Instant>,
    /// The transition owed at the next render, cleared once registered.
    pub pending: Option<Transition>,
    pub fx: EffectSlot,
    /// Folded down to its label row by the operator (Space in panels focus). **Operator state**:
    /// upserts replace the spec but never unfold a panel — the agent doesn't get to override what
    /// the operator chose not to look at.
    pub collapsed: bool,
}

/// The ordered set of live panels. `Default` is empty (US1 has none).
#[derive(Debug, Default, Clone)]
pub struct PanelRegistry {
    panels: Vec<Panel>,
}

impl PanelRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        PanelRegistry::default()
    }

    /// Apply one lifecycle op (008-grid-tui, US2). `now` anchors any TTL, so callers/tests control
    /// the clock.
    pub fn apply_at(&mut self, op: PanelOp, now: Instant) {
        match op {
            PanelOp::Upsert {
                id,
                spec,
                ttl_ms,
                effect,
            } => {
                let expires_at = ttl_ms.map(|ms| now + Duration::from_millis(ms));
                self.upsert_with_expiry(&id, spec, expires_at);
                // The agent's requested transition replaces the default for this update (FR-022).
                // `None` leaves the default in place — it means "the usual transition for this
                // target", never "no animation"; suppressing motion is the kill switch's job.
                if let (Some(p), Some(e)) = (self.get_mut(&id), effect) {
                    p.fx.requested = Some(e);
                }
            }
            PanelOp::Remove { id } => self.remove(&id),
            PanelOp::Clear => self.clear(),
        }
    }

    /// Apply one lifecycle op against the current clock.
    pub fn apply(&mut self, op: PanelOp) {
        self.apply_at(op, Instant::now());
    }

    /// Insert a new panel, or replace an existing one's spec **in place** (FR-008/009). Insertion
    /// order is preserved on replace, so a panel never jumps position when it updates.
    pub fn upsert(&mut self, id: impl Into<String>, spec: RenderSpec) {
        self.upsert_with_expiry(id, spec, None);
    }

    /// [`PanelRegistry::upsert`] with an explicit expiry instant.
    ///
    /// Also records the transition the panel now owes (009 FR-003/FR-004): a new name owes an
    /// entrance, an existing one owes an update. Nothing is registered with the effects pipeline
    /// here — the panel's `Rect` isn't known until it renders (see [`register_transition`]).
    pub fn upsert_with_expiry(
        &mut self,
        id: impl Into<String>,
        spec: RenderSpec,
        expires_at: Option<Instant>,
    ) {
        let id = id.into();
        let now = Instant::now();
        match self.panels.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.spec = spec;
                p.expires_at = expires_at;
                // An entrance still pending (the panel was created and replaced before it ever drew)
                // stays an entrance — there is no old content to cross-fade from.
                if p.pending != Some(Transition::Enter) {
                    p.pending = Some(Transition::Update);
                }
                p.fx.started.get_or_insert(now);
            }
            None => self.panels.push(Panel {
                id,
                spec,
                expires_at,
                pending: Some(Transition::Enter),
                fx: EffectSlot {
                    started: Some(now),
                    ..EffectSlot::default()
                },
                collapsed: false,
            }),
        }
    }

    /// Mutable access to a panel by id, for the renderer's snapshot/registration pass.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Panel> {
        self.panels.iter_mut().find(|p| p.id == id)
    }

    /// Panels in insertion order, mutably — the renderer walks this to register transitions and
    /// snapshot each panel's drawn content.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Panel> {
        self.panels.iter_mut()
    }

    /// Remove panel `id`; a no-op when it isn't present.
    pub fn remove(&mut self, id: &str) {
        self.panels.retain(|p| p.id != id);
    }

    /// Toggle panel `idx`'s collapsed state (insertion order); a no-op out of range.
    pub fn toggle_collapse_at(&mut self, idx: usize) {
        if let Some(p) = self.panels.get_mut(idx) {
            p.collapsed = !p.collapsed;
        }
    }

    /// Remove the panel at `idx` (insertion order); a no-op out of range.
    pub fn remove_at(&mut self, idx: usize) {
        if idx < self.panels.len() {
            self.panels.remove(idx);
        }
    }

    /// Panels in insertion order, with their full state — what the renderer walks.
    pub fn iter_panels(&self) -> impl Iterator<Item = &Panel> {
        self.panels.iter()
    }

    /// Remove every panel.
    pub fn clear(&mut self) {
        self.panels.clear();
    }

    /// Drop panels whose TTL has elapsed. Returns how many were dropped (so a caller can redraw).
    pub fn prune(&mut self, now: Instant) -> usize {
        let before = self.panels.len();
        self.panels
            .retain(|p| p.expires_at.is_none_or(|exp| exp > now));
        before - self.panels.len()
    }

    /// Whether any panel carries a TTL — the event loop arms a tick only when this is true.
    pub fn has_expiring(&self) -> bool {
        self.panels.iter().any(|p| p.expires_at.is_some())
    }

    /// The current spec for `id`, if a panel by that name exists.
    pub fn get(&self, id: &str) -> Option<&RenderSpec> {
        self.panels.iter().find(|p| p.id == id).map(|p| &p.spec)
    }

    /// Panels in insertion order as `(id, spec)` — the render order down the column.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &RenderSpec)> {
        self.panels.iter().map(|p| (p.id.as_str(), &p.spec))
    }

    /// Number of live panels.
    pub fn len(&self) -> usize {
        self.panels.len()
    }

    /// Whether there are no panels (US1 state — the panel column is hidden).
    pub fn is_empty(&self) -> bool {
        self.panels.is_empty()
    }
}

/// Where a panel landed on screen this frame: its bordered box and the content region inside it.
#[derive(Debug, Clone, Copy)]
pub struct PanelArea {
    /// The whole panel including its border.
    pub outer: Rect,
    /// The content region the widget drew into.
    pub inner: Rect,
}

/// Register the transition a panel owes, now that its on-screen `Rect` is known (T018/T019).
///
/// Split this way because the two halves genuinely belong in different places: *which* transition is
/// owed is panel state (create vs replace, and what the outgoing content was), while *where* it plays
/// is only knowable once the layout has run. The renderer calls this; it never chooses an effect.
///
/// The panel name is the effect key, which is what makes FR-005 automatic — a second update landing
/// mid-transition cancels the first through `EffectManager::unique` instead of stacking on it.
///
/// Returns whether an effect was registered. `false` means the final content is already on screen and
/// nothing further will change it, which is the correct outcome for every suppressed case.
pub fn register_transition(
    panel: &mut Panel,
    effects: &mut Effects,
    at: PanelArea,
    visual: VisualConfig,
) -> bool {
    let Some(pending) = panel.pending.take() else {
        return false;
    };
    panel.fx.started = None;
    // A log tail appends every few moments; dissolving the whole panel per append would be constant
    // churn saying nothing. The new line arriving at the bottom *is* the report, so updates play no
    // transition — the entrance (and any effect the agent explicitly requested) still does.
    if pending == Transition::Update
        && panel.fx.requested.is_none()
        && matches!(panel.spec, RenderSpec::LogTail { .. })
    {
        return false;
    }
    // An agent-requested transition replaces the default for both create and replace, and plays over
    // the whole panel — the agent asked for *this* motion, not for a variation on the default.
    if let Some(spec) = panel.fx.requested.take() {
        let ctx = ResolveCtx::agent(visual, at.outer);
        return effects::apply(effects, Some(&panel.id), &spec, &ctx);
    }
    match pending {
        // The whole panel arrives, border and all.
        Transition::Enter => {
            let ctx = ResolveCtx::agent(visual, at.outer);
            effects::apply(effects, Some(&panel.id), &effects::panel_enter_spec(), &ctx)
        }
        // Only the content changes on an update; dissolving the border too would read as the panel
        // flickering rather than as its data being replaced.
        Transition::Update => {
            let ctx = ResolveCtx::agent(visual, at.inner);
            match panel.fx.prev.clone() {
                Some(prev) => match effects::panel_update(prev, &ctx) {
                    Some(fx) => {
                        effects.add_keyed(panel.id.clone(), fx);
                        true
                    }
                    None => false,
                },
                // No snapshot means the panel was replaced before it ever drew, so there is nothing
                // to dissolve — it enters instead of half-playing a cross-fade.
                None => {
                    effects::apply(effects, Some(&panel.id), &effects::panel_enter_spec(), &ctx)
                }
            }
        }
    }
}

/// Snapshot a panel's freshly drawn content as the outgoing half of its *next* update (T019).
///
/// Taken from the real frame buffer after the widget renders, so the cross-fade starts from what the
/// operator actually saw — borders, theme colors and all — rather than from a re-render.
pub fn snapshot_render(panel: &mut Panel, area: Rect, buf: &Buffer) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    panel.fx.prev = Some(effects::capture(area, buf));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> RenderSpec {
        RenderSpec::Text {
            content: s.into(),
            style: None,
            bold: false,
            dim: false,
        }
    }

    #[test]
    fn upsert_appends_new_and_replaces_existing_in_place() {
        let mut r = PanelRegistry::new();
        r.upsert("metrics", text("v1"));
        r.upsert("logs", text("l1"));
        r.upsert("metrics", text("v2")); // replace, not duplicate
        assert_eq!(r.len(), 2, "same id replaces — no duplicate panel");
        // Order preserved: metrics stays first even though it was updated last.
        let ids: Vec<&str> = r.iter().map(|(id, _)| id).collect();
        assert_eq!(ids, ["metrics", "logs"]);
        assert_eq!(r.get("metrics"), Some(&text("v2")), "shows the latest spec");
    }

    #[test]
    fn coalescing_keeps_only_the_last_spec_per_id() {
        // A burst of updates to one id between redraws collapses to the last (FR-011).
        let mut r = PanelRegistry::new();
        for i in 0..5 {
            r.upsert("m", text(&format!("v{i}")));
        }
        assert_eq!(r.len(), 1);
        assert_eq!(r.get("m"), Some(&text("v4")));
    }

    #[test]
    fn remove_drops_one_panel_and_is_a_noop_when_absent() {
        let mut r = PanelRegistry::new();
        r.upsert("a", text("1"));
        r.upsert("b", text("2"));
        r.apply(PanelOp::Remove { id: "a".into() });
        assert_eq!(r.len(), 1);
        assert!(r.get("a").is_none());
        r.apply(PanelOp::Remove { id: "nope".into() }); // absent → no panic, no change
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn clear_drops_every_panel() {
        let mut r = PanelRegistry::new();
        for id in ["a", "b", "c"] {
            r.upsert(id, text("x"));
        }
        r.apply(PanelOp::Clear);
        assert!(r.is_empty());
    }

    #[test]
    fn ttl_panels_expire_on_prune_and_others_survive() {
        let now = Instant::now();
        let mut r = PanelRegistry::new();
        r.apply_at(
            PanelOp::Upsert {
                id: "flash".into(),
                spec: text("brief"),
                ttl_ms: Some(100),
                effect: None,
            },
            now,
        );
        r.apply_at(
            PanelOp::Upsert {
                id: "keep".into(),
                spec: text("forever"),
                ttl_ms: None,
                effect: None,
            },
            now,
        );
        assert!(r.has_expiring());

        // Before the deadline nothing is dropped.
        assert_eq!(r.prune(now + Duration::from_millis(50)), 0);
        assert_eq!(r.len(), 2);

        // After it, only the TTL panel goes.
        assert_eq!(r.prune(now + Duration::from_millis(150)), 1);
        assert_eq!(r.len(), 1);
        assert!(r.get("keep").is_some());
        assert!(!r.has_expiring());
    }

    // --- US1 (T017–T019, T024): transitions and their cancellation --------------------------------

    fn panel_area() -> PanelArea {
        let outer = Rect::new(0, 0, 20, 6);
        PanelArea {
            outer,
            inner: Rect::new(1, 1, 18, 4),
        }
    }

    /// Paint `ch` across a panel's content region, the way a widget would.
    fn draw(buf: &mut ratatui::buffer::Buffer, at: Rect, ch: &str, style: ratatui::style::Style) {
        for y in at.y..at.bottom() {
            for x in at.x..at.right() {
                buf[(x, y)].set_symbol(ch).set_style(style);
            }
        }
    }

    #[test]
    fn a_new_panel_owes_an_entrance_and_a_replaced_one_owes_an_update() {
        let mut r = PanelRegistry::new();
        r.upsert("m", text("v1"));
        assert_eq!(r.get_mut("m").unwrap().pending, Some(Transition::Enter));

        // Consuming the transition clears it: a redraw with no new content animates nothing.
        r.get_mut("m").unwrap().pending = None;
        r.upsert("m", text("v2"));
        assert_eq!(r.get_mut("m").unwrap().pending, Some(Transition::Update));
    }

    #[test]
    fn a_panel_replaced_before_it_ever_drew_still_enters() {
        // No outgoing content exists yet, so there is nothing to cross-fade from (FR-011: the burst
        // coalesces to one transition, and it is the entrance).
        let mut r = PanelRegistry::new();
        r.upsert("m", text("v1"));
        r.upsert("m", text("v2"));
        assert_eq!(r.get_mut("m").unwrap().pending, Some(Transition::Enter));
    }

    #[test]
    fn a_burst_of_updates_between_redraws_keeps_the_first_request_time() {
        // FR-011: the transition coalesces, and it still dates from the update that started it, so
        // rapid writes can't push the animation's start indefinitely into the future.
        let mut r = PanelRegistry::new();
        r.upsert("m", text("v1"));
        r.get_mut("m").unwrap().pending = None;
        r.get_mut("m").unwrap().fx.started = None;

        r.upsert("m", text("v2"));
        let first = r.get_mut("m").unwrap().fx.started.expect("update is timed");
        r.upsert("m", text("v3"));
        assert_eq!(
            r.get_mut("m").unwrap().fx.started,
            Some(first),
            "the second write joins the pending transition rather than restarting it"
        );
    }

    #[test]
    fn a_second_update_mid_transition_replaces_the_first_instead_of_stacking_on_it() {
        // FR-005 / US1 §3. The discriminator is what's on screen one frame after the second update:
        // with cancellation the outgoing snapshot shows in its own colors, whereas a surviving
        // entrance would still be dragging every cell toward the theme's fade-from color.
        let at = panel_area();
        let content = ratatui::style::Style::default()
            .fg(ratatui::style::Color::Rgb(200, 200, 200))
            .bg(ratatui::style::Color::Rgb(20, 20, 30));
        let fade_from = crate::viz::buffer_render::theme_to_ratatui_color(
            crate::viz::theme::active_theme().get(crate::viz::theme::Role::Info),
        );
        assert_ne!(
            fade_from,
            ratatui::style::Color::Rgb(200, 200, 200),
            "the test needs the theme color to differ from the content color"
        );

        let mut r = PanelRegistry::new();
        let mut e = Effects::new();
        let visual = VisualConfig::default();

        // Frame 1: the panel is created, so it enters — and its content is snapshotted.
        r.upsert("m", text("v1"));
        let mut buf = ratatui::buffer::Buffer::empty(at.outer);
        draw(&mut buf, at.inner, "O", content);
        assert!(register_transition(
            r.get_mut("m").unwrap(),
            &mut e,
            at,
            visual
        ));
        snapshot_render(r.get_mut("m").unwrap(), at.inner, &buf);
        e.process(Duration::ZERO, &mut buf, at.outer);

        // ~50ms later, mid-entrance, the content is replaced.
        for _ in 0..3 {
            let mut f = ratatui::buffer::Buffer::empty(at.outer);
            draw(&mut f, at.inner, "O", content);
            e.process(Duration::from_millis(16), &mut f, at.outer);
        }
        r.upsert("m", text("v2"));
        let mut frame = ratatui::buffer::Buffer::empty(at.outer);
        draw(&mut frame, at.inner, "N", content);
        assert!(register_transition(
            r.get_mut("m").unwrap(),
            &mut e,
            at,
            visual
        ));
        e.process(Duration::ZERO, &mut frame, at.outer);

        for y in at.inner.y..at.inner.bottom() {
            for x in at.inner.x..at.inner.right() {
                let cell = &frame[(x, y)];
                assert_ne!(
                    cell.fg, fade_from,
                    "the cancelled entrance is still painting at ({x},{y})"
                );
            }
        }

        // And the update owns the panel alone: it settles within its own budget, then the panel is
        // simply the new content.
        let frames = (crate::tui::effects::PANEL_UPDATE_MS / 16) + 2;
        let mut last = frame;
        for _ in 0..frames {
            last = ratatui::buffer::Buffer::empty(at.outer);
            draw(&mut last, at.inner, "N", content);
            e.process(Duration::from_millis(16), &mut last, at.outer);
        }
        assert!(!e.is_running(), "nothing may outlive one update budget");
        for y in at.inner.y..at.inner.bottom() {
            for x in at.inner.x..at.inner.right() {
                assert_eq!(last[(x, y)].symbol(), "N");
            }
        }
    }

    #[test]
    fn a_suppressed_transition_registers_nothing_and_says_so() {
        // FR-006c at the panel level: with motion off the caller is told `false`, which means the
        // final content is already on screen.
        let mut r = PanelRegistry::new();
        let mut e = Effects::new();
        r.upsert("m", text("v1"));
        let off = VisualConfig {
            animations: false,
            ..VisualConfig::default()
        };
        assert!(!register_transition(
            r.get_mut("m").unwrap(),
            &mut e,
            panel_area(),
            off
        ));
        assert!(!e.is_running());
        assert!(
            r.get_mut("m").unwrap().pending.is_none(),
            "the transition is consumed either way — it never queues up for later"
        );
    }

    #[test]
    fn re_upserting_without_a_ttl_clears_a_previous_expiry() {
        let now = Instant::now();
        let mut r = PanelRegistry::new();
        r.apply_at(
            PanelOp::Upsert {
                id: "m".into(),
                spec: text("v1"),
                ttl_ms: Some(10),
                effect: None,
            },
            now,
        );
        r.apply_at(
            PanelOp::Upsert {
                id: "m".into(),
                spec: text("v2"),
                ttl_ms: None,
                effect: None,
            },
            now,
        );
        assert_eq!(
            r.prune(now + Duration::from_secs(60)),
            0,
            "expiry was lifted"
        );
        assert_eq!(r.get("m"), Some(&text("v2")));
    }
    // --- 009 US4 (T055): the agent's requested transition ----------------------------------------

    #[test]
    fn an_agent_requested_effect_replaces_the_default_transition() {
        // FR-022: `chart.effect(slide_in("left", 400))` is directional intent, and it must actually
        // be what plays — otherwise the whole Python surface is decoration on decoration.
        let mut r = PanelRegistry::new();
        r.apply(PanelOp::Upsert {
            id: "m".into(),
            spec: text("v1"),
            ttl_ms: None,
            effect: Some(EffectSpec::SlideIn {
                direction: crate::render_spec::EffectDirection::Left,
                ms: 400,
            }),
        });
        assert_eq!(
            r.get_mut("m").unwrap().fx.requested,
            Some(EffectSpec::SlideIn {
                direction: crate::render_spec::EffectDirection::Left,
                ms: 400,
            })
        );

        let mut e = Effects::new();
        assert!(register_transition(
            r.get_mut("m").unwrap(),
            &mut e,
            panel_area(),
            VisualConfig::default()
        ));
        assert!(e.is_running());
        assert!(
            r.get_mut("m").unwrap().fx.requested.is_none(),
            "the request is consumed, not repeated on every later update"
        );
    }

    #[test]
    fn a_requested_effect_lasts_as_long_as_it_asked_for() {
        // US4 §1: a 400ms slide is active for 400ms — not the panel default's 300.
        let at = panel_area();
        let mut r = PanelRegistry::new();
        let mut e = Effects::new();
        r.apply(PanelOp::Upsert {
            id: "m".into(),
            spec: text("v1"),
            ttl_ms: None,
            effect: Some(EffectSpec::SlideIn {
                direction: crate::render_spec::EffectDirection::Left,
                ms: 400,
            }),
        });
        register_transition(r.get_mut("m").unwrap(), &mut e, at, VisualConfig::default());

        let mut buf = ratatui::buffer::Buffer::empty(at.outer);
        // Still animating a whisker before its budget...
        for _ in 0..23 {
            e.process(Duration::from_millis(16), &mut buf, at.outer);
        }
        assert!(e.is_running(), "a 400ms effect is still live at ~368ms");
        // ...and finished after it.
        for _ in 0..5 {
            e.process(Duration::from_millis(16), &mut buf, at.outer);
        }
        assert!(!e.is_running(), "and done by ~448ms");
    }

    #[test]
    fn no_request_means_the_default_transition_not_a_still_panel() {
        // `None` is the absence of a *request*, never a request for stillness.
        let mut r = PanelRegistry::new();
        let mut e = Effects::new();
        r.apply(PanelOp::Upsert {
            id: "m".into(),
            spec: text("v1"),
            ttl_ms: None,
            effect: None,
        });
        assert!(register_transition(
            r.get_mut("m").unwrap(),
            &mut e,
            panel_area(),
            VisualConfig::default()
        ));
        assert!(e.is_running(), "the default entrance still plays");
    }

    #[test]
    fn a_requested_effect_is_still_subject_to_the_kill_switch() {
        // FR-006b outranks FR-022: asking for a specific effect is not a way around the operator's
        // motion setting.
        let mut r = PanelRegistry::new();
        let mut e = Effects::new();
        r.apply(PanelOp::Upsert {
            id: "m".into(),
            spec: text("v1"),
            ttl_ms: None,
            effect: Some(EffectSpec::Glow { ms: 500 }),
        });
        let off = VisualConfig {
            animations: false,
            ..VisualConfig::default()
        };
        assert!(!register_transition(
            r.get_mut("m").unwrap(),
            &mut e,
            panel_area(),
            off
        ));
        assert!(!e.is_running());
    }
}
