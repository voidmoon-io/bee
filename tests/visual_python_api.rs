use bee::render_api::RenderOutcome;
use bee::render_spec::{EffectSpec, PanelOp, RenderSpec};
static VP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Build an engine wired to a fresh context and run `script`, returning what it produced.
/// Does **not** touch the viewport lock — callers below hold it.
fn run_inner(script: &str) -> Result<RenderOutcome, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(bee::render_api::evaluate(
            script,
            &bee::Sandbox::host(vec![]),
        ))
}

/// Run `script` against an **unconstrained** viewport (the headless default), serialized so a
/// concurrent fit-guard test can't leak its viewport into this one.
fn run(script: &str) -> Result<RenderOutcome, String> {
    let _g = VP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    bee::viz::viewport::reset();
    run_inner(script)
}

#[test]
fn markdown_commits_its_source_not_a_rendering() {
    // 010: the spec carries source, so the transcript stays renderer-free and a replay
    // re-renders at the width the replaying terminal has.
    // `r##` because the markdown content contains `"#`, which would close an `r#` literal.
    let out = run(r##"render(markdown("# Title\n\nbody **here**"));"##).unwrap();
    let spec = out.inline.expect("committed inline");
    match spec {
        RenderSpec::Markdown { content } => {
            assert!(content.contains("# Title"));
            assert!(content.contains("**here**"), "source, verbatim");
        }
        other => panic!("expected a markdown spec, got {other:?}"),
    }
}

#[test]
fn a_markdown_block_takes_an_effect_and_a_panel_like_any_other_widget() {
    // `effect` mutates the widget rather than chaining, so this is the two-statement form the
    // rest of the surface uses.
    let out = run(r##"w = markdown("# Notes"); w.effect(fade_in(300)); render_to("notes", w);"##)
        .unwrap();
    assert_eq!(out.panel_ops.len(), 1);
    assert!(matches!(
        &out.panel_ops[0],
        PanelOp::Upsert {
            effect: Some(EffectSpec::FadeIn { ms: 300 }),
            ..
        }
    ));
}

#[test]
fn log_tail_builds_lines_with_and_without_levels() {
    let out = run(concat!(
        r#"l = log_tail("denials");"#,
        r#"l.line("policy loaded");"#,
        r#"l.line("open /etc/shadow blocked", "error");"#,
        r#"l.max_rows(4);"#,
        r#"render_to("audit", l);"#,
    ))
    .unwrap();
    let [PanelOp::Upsert { id, spec, .. }] = &out.panel_ops[..] else {
        panic!("expected one upsert, got {:?}", out.panel_ops);
    };
    assert_eq!(id, "audit");
    match spec {
        RenderSpec::LogTail {
            title,
            lines,
            max_rows,
        } => {
            assert_eq!(title, "denials");
            assert_eq!(max_rows, &Some(4));
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0].level, None);
            assert_eq!(lines[1].level.as_deref(), Some("error"));
        }
        other => panic!("expected a log tail, got {other:?}"),
    }
}

#[test]
fn render_commits_inline_and_no_panel_ops() {
    let out = run(r#"render(text("hi"));"#).unwrap();
    assert!(out.inline.is_some());
    assert!(out.panel_ops.is_empty());
}

#[test]
fn render_to_emits_an_upsert() {
    let out = run(r#"render_to("metrics", text("hi"));"#).unwrap();
    assert!(
        out.inline.is_none(),
        "a panel render does not also go inline"
    );
    assert!(matches!(
        &out.panel_ops[..],
        [PanelOp::Upsert { id, ttl_ms: None, .. }] if id == "metrics"
    ));
}

#[test]
fn inline_and_panels_coexist_in_one_script() {
    // The old single-commit model let a later render_to clobber an earlier inline render.
    let out = run(r#"render(text("chat")); render_to("a", text("A")); render_to("b", text("B"));"#)
        .unwrap();
    assert!(out.inline.is_some(), "the inline render survives");
    assert_eq!(out.panel_ops.len(), 2, "both panels are addressed");
}

#[test]
fn render_to_ttl_carries_the_expiry_and_rejects_non_positive() {
    let out = run(r#"render_to_ttl("flash", text("x"), 500);"#).unwrap();
    assert!(matches!(
        &out.panel_ops[..],
        [PanelOp::Upsert {
            ttl_ms: Some(500),
            ..
        }]
    ));
    assert!(run(r#"render_to_ttl("flash", text("x"), 0);"#).is_err());
    assert!(run(r#"render_to_ttl("flash", text("x"), -5);"#).is_err());
}

#[test]
fn ttl_is_clamped_to_a_day() {
    let out = run(r#"render_to_ttl("f", text("x"), 999999999);"#).unwrap();
    assert!(matches!(
        &out.panel_ops[..],
        [PanelOp::Upsert { ttl_ms: Some(ms), .. }] if *ms == 24 * 60 * 60 * 1000
    ));
}

#[test]
fn remove_panel_and_clear_panels_emit_ops() {
    let out = run(r#"remove_panel("old");"#).unwrap();
    assert!(matches!(&out.panel_ops[..], [PanelOp::Remove { id }] if id == "old"));

    let out = run(r#"clear_panels();"#).unwrap();
    assert!(matches!(&out.panel_ops[..], [PanelOp::Clear]));
}

#[test]
fn ops_keep_script_order() {
    let out = run(r#"clear_panels(); render_to("a", text("A")); remove_panel("b");"#).unwrap();
    assert!(matches!(out.panel_ops[0], PanelOp::Clear));
    assert!(matches!(out.panel_ops[1], PanelOp::Upsert { .. }));
    assert!(matches!(out.panel_ops[2], PanelOp::Remove { .. }));
}

// --- Fit guard: fail the script when the surface can't display the widget -------------------
//
// These publish process-global viewport state, so they share one mutex and reset afterwards.
use bee::viz::viewport::{self, Viewport};

/// Run `script` with `vp` published, always restoring the unconstrained default.
fn run_with_viewport(vp: Viewport, script: &str) -> Result<RenderOutcome, String> {
    let _g = VP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    viewport::set(vp);
    let out = run_inner(script);
    viewport::reset();
    out
}

/// A roomy full-screen viewport: 120×40, 70-col chat, 48-col panels, slots to spare.
fn roomy() -> Viewport {
    Viewport {
        cols: 120,
        rows: 40,
        inline_cols: 70,
        panel_cols: 48,
        panel_rows: 1,
        panel_slots_free: 5,
        live_panels: vec!["existing".into()],
        full_screen: true,
        constrained: true,
    }
}

#[test]
fn headless_never_fails_a_render() {
    // The default (unconstrained) viewport must not reject anything — episodes and batch runs
    // have no screen at all.
    let _g = VP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    viewport::reset();
    assert!(run_inner(r#"render(grid(2, 12));"#).is_ok());
}

#[test]
fn a_terminal_below_the_hard_floor_fails_every_render() {
    let vp = Viewport {
        cols: 30,
        rows: 8,
        ..roomy()
    };
    let err = run_with_viewport(vp, r#"render(text("hi"));"#).unwrap_err();
    assert!(err.contains("too small"), "got: {err}");
    assert!(err.contains("40×10"), "message names the minimum: {err}");
}

#[test]
fn a_widget_wider_than_the_chat_pane_fails_inline() {
    // A 12-column grid needs ≥96 columns; the chat pane is 70.
    let err = run_with_viewport(roomy(), r#"render(grid(1, 12));"#).unwrap_err();
    assert!(err.contains("at least"), "got: {err}");
    assert!(err.contains("70"), "message names the actual width: {err}");
}

#[test]
fn a_widget_wider_than_a_panel_fails_and_suggests_inline() {
    // 8 columns ≥ 64 > the 48-col panel, but still fits the 70-col chat pane.
    let err = run_with_viewport(roomy(), r#"render_to("m", grid(1, 8));"#).unwrap_err();
    assert!(err.contains("panel is only 48"), "got: {err}");
    assert!(
        err.contains("inline"),
        "should point at the roomier surface: {err}"
    );
}

#[test]
fn a_new_panel_fails_when_the_column_is_full_but_an_update_still_works() {
    let full = Viewport {
        panel_slots_free: 0,
        ..roomy()
    };
    let err = run_with_viewport(full.clone(), r#"render_to("brand-new", text("x"));"#).unwrap_err();
    assert!(err.contains("panel column is full"), "got: {err}");
    assert!(
        err.contains("remove_panel") && err.contains("clear_panels"),
        "message names the escape hatch: {err}"
    );
    assert!(err.contains("existing"), "and lists reusable ids: {err}");

    // Updating a panel that already exists needs no free slot.
    assert!(run_with_viewport(full, r#"render_to("existing", text("x"));"#).is_ok());
}

#[test]
fn ttl_renders_are_fit_checked_too() {
    let full = Viewport {
        panel_slots_free: 0,
        ..roomy()
    };
    assert!(run_with_viewport(full, r#"render_to_ttl("new", text("x"), 500);"#).is_err());
}

#[test]
fn the_inline_repl_only_constrains_width_not_height() {
    // Height is unbounded there (it scrolls), so a short terminal must not fail a render.
    let inline = Viewport {
        cols: 50,
        rows: 0,
        inline_cols: 50,
        full_screen: false,
        constrained: true,
        ..Viewport::unconstrained()
    };
    assert!(run_with_viewport(inline.clone(), r#"render(text("hi"));"#).is_ok());
    // A panel render falls back inline there, so it's checked against the inline width.
    assert!(run_with_viewport(inline, r#"render_to("m", grid(1, 12));"#).is_err());
}

#[test]
fn render_to_accepts_the_full_legal_charset() {
    assert!(run(r#"render_to("ab_9-z", text("x"));"#).is_ok());
}

#[test]
fn panel_ids_are_validated_on_every_entry_point() {
    // Empty, oversized, and out-of-charset ids all fail closed (contracts/rhai-panel-api.md).
    assert!(run(r#"render_to("", text("x"));"#).is_err());
    let long = "a".repeat(33);
    assert!(run(&format!(r#"render_to("{long}", text("x"));"#)).is_err());
    assert!(
        run(r#"render_to("Metrics", text("x"));"#).is_err(),
        "uppercase rejected"
    );
    assert!(
        run(r#"render_to("a b", text("x"));"#).is_err(),
        "space rejected"
    );
    assert!(
        run(r#"render_to("pan/el", text("x"));"#).is_err(),
        "slash rejected"
    );
    assert!(
        run(r#"remove_panel("Nope");"#).is_err(),
        "remove validates too"
    );
    assert!(
        run(r#"render_to_ttl("Nope", text("x"), 10);"#).is_err(),
        "ttl validates too"
    );
}
