//! Python visual scripting through the bounded Monty worker.
use crate::config::VisualLevel;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::{Tool, ToolResult};
use crate::visual_gate;
use serde_json::json;
const SCHEMA_DESC: &str = include_str!("../python/visual-api.txt");

/// The text summary the model gets back: what was drawn and where it went. Never pixels (FR-023).
fn summarize(outcome: &crate::render_api::RenderOutcome) -> String {
    use crate::render_spec::{PanelOp, RenderSpec};

    let mut parts: Vec<String> = Vec::new();
    if let Some(spec) = &outcome.inline {
        let mut s = format!("Rendered {} inline", spec.summary_noun());
        // A fully-transparent sprite renders as blank rows — say so rather than look broken.
        if let RenderSpec::Sprite { spec: sp } = spec {
            if sp.is_fully_transparent() {
                s.push_str(" (note: sprite is fully transparent)");
            }
        }
        parts.push(s);
    }
    for op in &outcome.panel_ops {
        parts.push(match op {
            PanelOp::Upsert {
                id,
                spec,
                ttl_ms: None,
                ..
            } => format!("rendered {} to panel {id:?}", spec.summary_noun()),
            PanelOp::Upsert {
                id,
                spec,
                ttl_ms: Some(ms),
                ..
            } => format!(
                "rendered {} to panel {id:?} (expires in {ms}ms)",
                spec.summary_noun()
            ),
            PanelOp::Remove { id } => format!("removed panel {id:?}"),
            PanelOp::Clear => "cleared all panels".to_string(),
        });
    }

    let mut summary = parts.join("; ");
    summary.push('.');
    // Capitalize when the first clause came from a panel op rather than the inline branch.
    if let Some(first) = summary.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    if outcome.render_calls > 1 && outcome.inline.is_some() && outcome.panel_ops.is_empty() {
        summary.push_str(&format!(
            " (note: {} earlier render(s) discarded; showing the last)",
            outcome.render_calls - 1
        ));
    }
    summary
}

/// Apply the visual permission gate to everything a script produced (009 US2, T029/T032).
///
/// Runs **before any panel state mutates** — the outcome here is what becomes session events, so a
/// downgrade is not a correction applied later, it is the only decision anything downstream sees.
/// Returns the gated outcome plus the notes to append to the model's summary (FR-009, FR-010).
///
/// At `visual_level = none` the agent owns no regions at all, so panel upserts route inline. Inline
/// holds one widget, so the last upsert wins — the same last-writer-wins rule `render()` has always
/// had. Removes and clears simply drop: there are no panels for them to act on.
pub fn apply_visual_gate(
    mut outcome: crate::render_api::RenderOutcome,
    level: VisualLevel,
) -> (crate::render_api::RenderOutcome, Vec<&'static str>) {
    use crate::render_spec::{PanelOp, RenderTarget};

    let mut notes = Vec::new();
    let mut note = |n: Option<&'static str>| {
        if let Some(n) = n {
            if !notes.contains(&n) {
                notes.push(n);
            }
        }
    };

    // A takeover first: it is the highest target, so it is the one most likely to be downgraded.
    if let Some((spec, ttl_ms, effect)) = outcome.overlay.take() {
        let gated = visual_gate::gate(level, RenderTarget::Overlay { ttl_ms });
        note(gated.note);
        match gated.target {
            RenderTarget::Overlay { ttl_ms } => outcome.overlay = Some((spec, ttl_ms, effect)),
            // One tier down: the reserved panel. Repeat downgrades upsert the same id, so a model
            // asking for takeover every turn replaces one panel instead of filling the column.
            RenderTarget::Panel { id } => outcome.panel_ops.push(PanelOp::Upsert {
                id,
                spec,
                ttl_ms: ttl_ms.map(u64::from),
                effect,
            }),
            RenderTarget::Inline => {
                outcome.inline = Some(spec);
                outcome.inline_effect = effect;
            }
        }
    }

    // At `visual_level = none` the agent owns no regions at all, so panel upserts route inline.
    // Inline holds one widget, so the last upsert wins — the same last-writer-wins rule `render()`
    // has always had. Removes and clears simply drop: there are no panels for them to act on.
    if level == VisualLevel::None && !outcome.panel_ops.is_empty() {
        for op in std::mem::take(&mut outcome.panel_ops) {
            match op {
                PanelOp::Upsert {
                    id, spec, effect, ..
                } => {
                    note(visual_gate::gate(level, RenderTarget::Panel { id }).note);
                    outcome.inline = Some(spec);
                    outcome.inline_effect = effect;
                }
                PanelOp::Remove { .. } | PanelOp::Clear => {}
            }
        }
    }
    (outcome, notes)
}

#[derive(Default)]
pub struct RenderTool;
impl RenderTool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Tool for RenderTool {
    fn name(&self) -> &'static str {
        "render"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "render".to_string(),
            description: SCHEMA_DESC.to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "A Python script that builds one visualization and ends with render(widget)." }
                },
                "required": ["script"]
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let script = match arguments.get("script").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return ToolResult::invalid_args("render", "missing string field 'script'"),
        };

        match crate::render_api::evaluate(&script, sandbox).await {
            Ok(outcome) => {
                if outcome.is_empty() {
                    return ToolResult::error("render: script produced no visualization");
                }
                // The gate runs here, on the way out of the script and before any of this becomes a
                // session event — so nothing downstream ever sees a target above the ceiling.
                let (outcome, notes) = apply_visual_gate(outcome, visual_gate::active().level);
                if outcome.is_empty() {
                    return ToolResult::error("render: script produced no visualization");
                }
                let mut summary = summarize(&outcome);
                for note in &notes {
                    summary.push_str(&format!(" ({note})"));
                }
                // A takeover and an inline widget are both single-slot, so the overlay wins the
                // `render_spec`/`render_target` pair when a script commits both — it is the more
                // specific request. Panel ops ride alongside either way.
                match outcome.overlay {
                    Some((spec, ttl_ms, effect)) => ToolResult {
                        panel_ops: outcome.panel_ops,
                        inline_effect: effect,
                        ..ToolResult::rendered_to(
                            summary,
                            spec,
                            crate::render_spec::RenderTarget::Overlay { ttl_ms },
                        )
                    },
                    None => ToolResult::rendered_with_ops(
                        summary,
                        outcome.inline,
                        outcome.panel_ops,
                        outcome.inline_effect,
                    ),
                }
            }
            Err(e) => ToolResult::error(format!("render: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render_api::RenderOutcome;
    use crate::render_spec::{PanelOp, RenderSpec};

    fn text(s: &str) -> RenderSpec {
        RenderSpec::Text {
            content: s.into(),
            style: None,
            bold: false,
            dim: false,
        }
    }

    fn upsert(id: &str, body: &str) -> PanelOp {
        PanelOp::Upsert {
            id: id.into(),
            spec: text(body),
            ttl_ms: None,
            effect: None,
        }
    }

    /// The gate is a pure function of the level, so every row is exercised without touching the
    /// process-global config that the live tool reads.
    fn gated(level: VisualLevel, ops: Vec<PanelOp>) -> (RenderOutcome, Vec<&'static str>) {
        apply_visual_gate(
            RenderOutcome {
                inline: None,
                inline_effect: None,
                overlay: None,
                panel_ops: ops,
                render_calls: 1,
            },
            level,
        )
    }

    #[test]
    fn panels_survive_at_every_level_that_allows_them() {
        for level in [
            VisualLevel::Panels,
            VisualLevel::PanelsWide,
            VisualLevel::Takeover,
        ] {
            let (out, notes) = gated(level, vec![upsert("metrics", "v1")]);
            assert_eq!(out.panel_ops.len(), 1, "the panel op survives at {level:?}");
            assert!(out.inline.is_none(), "and does not also render inline");
            assert!(notes.is_empty(), "a permitted render says nothing");
        }
    }

    #[test]
    fn level_none_routes_a_panel_inline_and_tells_the_model_why() {
        // FR-009/FR-010: the model gets a working visual plus the note, so it can adapt next turn.
        let (out, notes) = gated(VisualLevel::None, vec![upsert("metrics", "v1")]);
        assert!(out.panel_ops.is_empty(), "no panel state may be mutated");
        assert_eq!(out.inline, Some(text("v1")), "the content still renders");
        assert_eq!(notes, vec![crate::visual_gate::NOTE_TO_INLINE]);
    }

    #[test]
    fn the_note_reaches_the_models_summary_verbatim() {
        // SC-004: what the model reads is the contract's exact string.
        let (out, notes) = gated(VisualLevel::None, vec![upsert("metrics", "v1")]);
        let mut summary = summarize(&out);
        for note in &notes {
            summary.push_str(&format!(" ({note})"));
        }
        assert!(
            summary.contains("downgraded to inline: visual level is none"),
            "got: {summary}"
        );
        assert!(summary.starts_with("Rendered"), "got: {summary}");
    }

    #[test]
    fn several_downgraded_panels_collapse_to_one_widget_and_one_note() {
        // Inline holds a single widget, so the last write wins — the rule `render()` has always
        // had. Repeating the same note once per panel would just pad the model's context.
        let (out, notes) = gated(
            VisualLevel::None,
            vec![upsert("a", "first"), upsert("b", "second")],
        );
        assert_eq!(out.inline, Some(text("second")));
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn removes_and_clears_drop_silently_at_level_none() {
        // There are no panels to act on, so tidying up a column that never existed is not news.
        let (out, notes) = gated(
            VisualLevel::None,
            vec![PanelOp::Remove { id: "a".into() }, PanelOp::Clear],
        );
        assert!(out.panel_ops.is_empty());
        assert!(out.inline.is_none());
        assert!(notes.is_empty());
    }

    #[test]
    fn an_inline_render_is_untouched_at_every_level() {
        for level in [
            VisualLevel::None,
            VisualLevel::Panels,
            VisualLevel::PanelsWide,
            VisualLevel::Takeover,
        ] {
            let (out, notes) = apply_visual_gate(
                RenderOutcome {
                    inline: Some(text("hi")),
                    inline_effect: None,
                    overlay: None,
                    panel_ops: Vec::new(),
                    render_calls: 1,
                },
                level,
            );
            assert_eq!(
                out.inline,
                Some(text("hi")),
                "inline is the floor at {level:?}"
            );
            assert!(notes.is_empty());
        }
    }
}
