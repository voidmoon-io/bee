//! T022 — transcript replay reconstructs panel state (008-grid-tui, US2; SC-009).
//!
//! Panels carry no live-only state: every targeted render is recorded as an ordinary `ToolResult`
//! (with a `RenderTarget::Panel`) in the transcript. Replaying folds those updates last-writer-wins
//! per id, in first-seen insertion order, reproducing exactly the panel column the session ended
//! with. This test builds a transcript by hand and asserts the fold — no terminal, no `tui` feature.

use bee::provider::{ToolCall, Usage};
use bee::render_spec::{RenderSpec, RenderTarget};
use bee::transcript::{EpisodeStatus, EpisodeTranscript, RecordedCall, Timing, TranscriptTurn};
use bee::ToolResult;

fn text(s: &str) -> RenderSpec {
    RenderSpec::Text {
        content: s.into(),
        style: None,
        bold: false,
        dim: false,
    }
}

/// A recorded `render` call that committed `spec` to `target`.
fn render_call(id: &str, target: RenderTarget, spec: RenderSpec) -> RecordedCall {
    RecordedCall {
        denied_attempt_audit: Vec::new(),
        denied_attempt_proxy_events: Vec::new(),
        escalations: Vec::new(),
        retried: false,
        timed_out: false,
        refused_by_hook: None,
        proxy_events: Vec::new(),
        call: ToolCall {
            id: id.into(),
            name: "render".into(),
            arguments: serde_json::json!({ "script": "…" }),
        },
        result: ToolResult::rendered_to("Rendered.", spec, target),
        audit: vec![],
    }
}

fn turn(index: u32, calls: Vec<RecordedCall>) -> TranscriptTurn {
    TranscriptTurn {
        notes: Vec::new(),
        index,
        assistant_text: None,
        calls,
        duration_ms: 1,
    }
}

fn transcript(turns: Vec<TranscriptTurn>) -> EpisodeTranscript {
    EpisodeTranscript {
        http_scope: None,
        scenario_id: "s".into(),
        model_id: "mock/x".into(),
        status: EpisodeStatus::Completed,
        turns,
        audit_trail: vec![],
        timing: Timing::default(),
        usage: None::<Usage>,
        score: None,
    }
}

#[test]
fn replay_folds_last_writer_wins_per_panel_in_insertion_order() {
    let panel = |id: &str| RenderTarget::Panel { id: id.into() };
    let t = transcript(vec![
        // Turn 0: metrics appears, then logs appears.
        turn(
            0,
            vec![
                render_call("c1", panel("metrics"), text("m-v1")),
                render_call("c2", panel("logs"), text("l-v1")),
            ],
        ),
        // Turn 1: metrics is updated in place; an inline render is ignored by the panel fold.
        turn(
            1,
            vec![
                render_call("c3", panel("metrics"), text("m-v2")),
                render_call("c4", RenderTarget::Inline, text("just chat")),
            ],
        ),
    ]);

    let panels = t.replay_panels();
    let ids: Vec<&str> = panels.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        ids,
        ["metrics", "logs"],
        "first-seen insertion order preserved"
    );
    assert_eq!(
        panels[0].spec,
        text("m-v2"),
        "metrics folded to its latest spec"
    );
    assert_eq!(panels[1].spec, text("l-v1"), "logs unchanged");
}

#[test]
fn inline_only_transcript_reconstructs_no_panels() {
    let t = transcript(vec![turn(
        0,
        vec![render_call("c1", RenderTarget::Inline, text("chat only"))],
    )]);
    assert!(t.panel_updates().is_empty());
    assert!(t.replay_panels().is_empty());
}

/// A recorded `render` call that requested `ops` on the panel column.
fn ops_call(id: &str, ops: Vec<bee::render_spec::PanelOp>) -> RecordedCall {
    RecordedCall {
        denied_attempt_audit: Vec::new(),
        denied_attempt_proxy_events: Vec::new(),
        escalations: Vec::new(),
        retried: false,
        timed_out: false,
        refused_by_hook: None,
        proxy_events: Vec::new(),
        call: ToolCall {
            id: id.into(),
            name: "render".into(),
            arguments: serde_json::json!({ "script": "…" }),
        },
        result: ToolResult::rendered_with_ops("Rendered.", None, ops, None),
        audit: vec![],
    }
}

#[test]
fn replay_applies_remove_and_clear_not_just_upserts() {
    use bee::render_spec::PanelOp;
    let up = |id: &str, v: &str| PanelOp::Upsert {
        id: id.into(),
        spec: text(v),
        ttl_ms: None,
        effect: None,
    };
    let t = transcript(vec![
        turn(
            0,
            vec![ops_call(
                "c1",
                vec![up("a", "1"), up("b", "2"), up("c", "3")],
            )],
        ),
        // Remove one, then re-add a fresh panel.
        turn(
            1,
            vec![ops_call(
                "c2",
                vec![PanelOp::Remove { id: "b".into() }, up("d", "4")],
            )],
        ),
    ]);
    let ids: Vec<String> = t.replay_panels().into_iter().map(|p| p.id).collect();
    assert_eq!(
        ids,
        ["a", "c", "d"],
        "removed panel is gone; order preserved"
    );

    // A clear wipes everything recorded before it.
    let t2 = transcript(vec![
        turn(0, vec![ops_call("c1", vec![up("a", "1"), up("b", "2")])]),
        turn(
            1,
            vec![ops_call("c2", vec![PanelOp::Clear, up("fresh", "9")])],
        ),
    ]);
    let ids2: Vec<String> = t2.replay_panels().into_iter().map(|p| p.id).collect();
    assert_eq!(ids2, ["fresh"], "clear wipes prior panels");
}

#[test]
fn ttl_panels_replay_with_their_last_content() {
    use bee::render_spec::PanelOp;
    // Expiry is live-session wall-clock state; a replay has no meaningful "now", so a TTL panel
    // replays with whatever it last held rather than vanishing.
    let t = transcript(vec![turn(
        0,
        vec![ops_call(
            "c1",
            vec![PanelOp::Upsert {
                id: "flash".into(),
                spec: text("brief"),
                ttl_ms: Some(50),
                effect: None,
            }],
        )],
    )]);
    let panels = t.replay_panels();
    assert_eq!(panels.len(), 1);
    assert_eq!(panels[0].spec, text("brief"));
}

#[test]
fn panel_updates_lists_every_targeted_render_in_order() {
    let panel = |id: &str| RenderTarget::Panel { id: id.into() };
    let t = transcript(vec![turn(
        0,
        vec![
            render_call("c1", panel("a"), text("1")),
            render_call("c2", panel("a"), text("2")),
            render_call("c3", panel("b"), text("3")),
        ],
    )]);
    // Every update is retained (not folded) here, in call order.
    let updates = t.panel_updates();
    assert_eq!(updates.len(), 3);
    assert_eq!(updates[0].id, "a");
    assert_eq!(updates[1].spec, text("2"));
    assert_eq!(updates[2].id, "b");
}
