//! Python visual output validation, independent of the interpreter and renderer.
use crate::render_spec::{EffectSpec, PanelOp, RenderSpec};
use crate::visual_gate;
use serde::{Deserialize, Serialize};
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderOutcome {
    pub inline: Option<RenderSpec>,
    pub inline_effect: Option<EffectSpec>,
    pub overlay: Option<(RenderSpec, Option<u32>, Option<EffectSpec>)>,
    pub panel_ops: Vec<PanelOp>,
    pub render_calls: u32,
}
impl RenderOutcome {
    pub fn is_empty(&self) -> bool {
        self.inline.is_none() && self.panel_ops.is_empty() && self.overlay.is_none()
    }
}
const HARD_FLOOR: (u16, u16) = (40, 10);

/// Fail the script when the active surface cannot display `spec` (008-grid-tui).
///
/// The render tool has no screen of its own, so without this a script could commit a 10-column grid
/// into a 48-column panel — or anything at all into a 30×8 terminal — and the model would be told
/// "Rendered …" while nothing legible appeared. Every message names the concrete next action so the
/// agent can adapt rather than repeat itself.
///
/// Skipped entirely when the viewport is unconstrained (headless episodes, batch runs, tests), so a
/// non-interactive run never fails a render.
fn check_fits(spec: &RenderSpec, panel_id: Option<&str>) -> Result<(), String> {
    let vp = crate::viz::viewport::get();
    if !vp.constrained {
        return Ok(());
    }

    // 1. Nothing is displayable below the hard floor. Full-screen only: the inline REPL scrolls, so
    // its height is never a constraint — only width can make output unreadable there.
    if vp.full_screen && (vp.cols < HARD_FLOOR.0 || vp.rows < HARD_FLOOR.1) {
        return Err(format!(
            "render: the terminal is too small to display anything ({}×{}; {}×{} minimum). \
             Ask the operator to enlarge the terminal before rendering.",
            vp.cols, vp.rows, HARD_FLOOR.0, HARD_FLOOR.1
        ));
    }

    let need = crate::viz::buffer_render::min_width(spec);

    match panel_id {
        // 2. An inline render must fit the chat pane.
        None => {
            if vp.inline_cols > 0 && need > vp.inline_cols {
                return Err(format!(
                    "render: this widget needs at least {need} columns but the chat pane is only {}. \
                     Simplify it (fewer grid columns / table columns) or split it across turns.",
                    vp.inline_cols
                )
                );
            }
        }
        Some(id) => {
            // In the inline REPL a panel render falls back into the chat flow, so the panel column's
            // limits don't apply — check it against the inline width instead.
            if !vp.full_screen {
                if vp.inline_cols > 0 && need > vp.inline_cols {
                    return Err(format!(
                        "render_to: this widget needs at least {need} columns but the surface is \
                         only {}. Simplify it or render fewer columns.",
                        vp.inline_cols
                    ));
                }
                return Ok(());
            }
            // 3. A *new* panel needs a free slot; updating an existing one always fits.
            if !vp.has_panel(id) && vp.panel_slots_free == 0 {
                return Err(format!(
                    "render_to: the panel column is full ({} live, no room for {id:?}). \
                     Call remove_panel(id) or clear_panels() to reclaim space, or reuse one of these \
                     ids: {}.",
                    vp.live_panels.len(),
                    vp.live_panels.join(", ")
                )
                );
            }
            // 4. And it must fit the column's width.
            if vp.panel_cols > 0 && need > vp.panel_cols {
                return Err(format!(
                    "render_to: this widget needs at least {need} columns but a panel is only {} \
                     wide. Use fewer grid/table columns, or render() it inline where there is more \
                     room ({} columns).",
                    vp.panel_cols, vp.inline_cols
                ));
            }
        }
    }
    Ok(())
}

/// Validate a panel id (contracts/rhai-panel-api.md): 1–32 chars of `[a-z0-9_-]`. A bad id is a
/// fail-closed script error, matching the drawing API's error style.
fn validate_panel_id(id: &str) -> Result<(), String> {
    // `takeover` is the id an over-ambitious `render_fullscreen` is downgraded onto (research R7).
    // A script that writes to it directly would be able to forge or clobber a downgraded takeover,
    // so it is reserved — the error names the verb the script actually wanted.
    if id == visual_gate::TAKEOVER_PANEL_ID {
        return Err(format!(
            "render_to: panel id {id:?} is reserved for downgraded full-screen renders. \
             Use render_fullscreen(widget) to request a takeover, or pick another id."
        ));
    }
    if id.is_empty() || id.len() > 32 {
        return Err(format!(
            "render_to: panel id must be 1–32 chars (got {})",
            id.len()
        ));
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-'))
    {
        return Err(format!(
            "render_to: panel id {id:?} has an invalid char {bad:?} (want [a-z0-9_-])"
        ));
    }
    Ok(())
}

pub async fn evaluate(script: &str, sandbox: &crate::Sandbox) -> Result<RenderOutcome, String> {
    let indent = script
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    let source = script
        .lines()
        .map(|line| line.get(indent..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let response = crate::python::execute(
        crate::python::Request::Start {
            source,
            inputs: serde_json::Value::Null,
            visual: true,
        },
        sandbox,
    )
    .await?;
    let mut outcome: RenderOutcome = match response {
        crate::python::Response::Complete { value } => {
            serde_json::from_value(value).map_err(|e| e.to_string())?
        }
        crate::python::Response::Error { message } => return Err(message),
        _ => return Err("visual scripts cannot call tools".into()),
    };
    validate_outcome(&mut outcome)?;
    Ok(outcome)
}

fn validate_spec(spec: &RenderSpec) -> Result<(), String> {
    use RenderSpec::*;
    if spec.nesting_depth() > 4 {
        return Err("layout nesting exceeds max depth 4".into());
    }
    if spec.element_count() > 500 {
        return Err("total elements exceed 500".into());
    }
    match spec {
        Sprite { spec } => {
            if !(1..=32).contains(&spec.width)
                || !(1..=32).contains(&spec.height)
                || spec.pixels.len() != usize::from(spec.width) * usize::from(spec.height)
            {
                return Err("sprite dimensions must be 1..=32 and match pixels".into());
            }
        }
        Animation { spec } => {
            if spec.frames.is_empty()
                || spec.frames.len() > 16
                || !(50..=1000).contains(&spec.interval_ms)
            {
                return Err("animation requires 1..=16 frames and 50..=1000 ms".into());
            }
            let first = &spec.frames[0];
            for frame in &spec.frames {
                validate_spec(&Sprite {
                    spec: frame.clone(),
                })?;
                if (frame.width, frame.height) != (first.width, first.height) {
                    return Err("animation frame dimensions differ".into());
                }
            }
        }
        Layout { children, .. } => {
            for child in children {
                validate_spec(child)?;
            }
        }
        Grid {
            rows,
            cols,
            cells,
            col_weights,
            row_weights,
            gap,
        } => {
            if !(1..=12).contains(rows)
                || !(1..=12).contains(cols)
                || cells.len() > 64
                || col_weights.len() > 12
                || row_weights.len() > 12
                || gap.is_some_and(|g| g > 4)
            {
                return Err("grid exceeds limits".into());
            }
            let mut occupied = std::collections::BTreeSet::new();
            for cell in cells {
                if cell.row_span == 0
                    || cell.col_span == 0
                    || u32::from(cell.row) + u32::from(cell.row_span) > u32::from(*rows)
                    || u32::from(cell.col) + u32::from(cell.col_span) > u32::from(*cols)
                {
                    return Err("grid cell exceeds bounds".into());
                }
                for r in cell.row..cell.row + cell.row_span {
                    for c in cell.col..cell.col + cell.col_span {
                        if !occupied.insert((r, c)) {
                            return Err("grid cells overlap".into());
                        }
                    }
                }
                validate_spec(&cell.content)?;
            }
        }
        Gauge { value, .. } if !value.is_finite() || !(0.0..=1.0).contains(value) => {
            return Err("invalid gauge".into())
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_outcome(outcome: &mut RenderOutcome) -> Result<(), String> {
    if outcome.panel_ops.len() > 64 || outcome.render_calls > 1000 {
        return Err("render output exceeds limits".into());
    }
    if let Some(spec) = &outcome.inline {
        validate_spec(spec)?;
        check_fits(spec, None)?;
    }
    if let Some((spec, ttl, effect)) = &mut outcome.overlay {
        validate_spec(spec)?;
        if ttl == &Some(0) {
            return Err("TTL must be positive".into());
        }
        *ttl = ttl.map(|v| v.min(86_400_000));
        if let Some(e) = effect {
            *e = e.clone().clamped();
        }
    }
    if let Some(e) = &mut outcome.inline_effect {
        *e = e.clone().clamped();
    }
    for op in &mut outcome.panel_ops {
        match op {
            PanelOp::Upsert {
                id,
                spec,
                ttl_ms,
                effect,
            } => {
                validate_panel_id(id)?;
                validate_spec(spec)?;
                check_fits(spec, Some(id))?;
                if *ttl_ms == Some(0) {
                    return Err("TTL must be positive".into());
                }
                *ttl_ms = ttl_ms.map(|v| v.min(86_400_000));
                if let Some(e) = effect {
                    *e = e.clone().clamped();
                }
            }
            PanelOp::Remove { id } => validate_panel_id(id)?,
            PanelOp::Clear => {}
        }
    }
    Ok(())
}
