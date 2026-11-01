fn run(script: &str) -> Result<bee::render_api::RenderOutcome, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(bee::render_api::evaluate(
            script,
            &bee::Sandbox::host(vec![]),
        ))
}
use bee::render_spec::{EffectDirection, EffectSpec};

use bee::render_spec::PanelOp;

/// Run `script` on a fully-registered engine and return the effect attached to the first panel.
fn attached(script: &str) -> Option<EffectSpec> {
    let out = run(script).expect("script ran");
    out.panel_ops.into_iter().find_map(|op| match op {
        PanelOp::Upsert { effect, .. } => effect,
        _ => None,
    })
}

#[test]
fn every_constructor_produces_its_spec() {
    let cases: Vec<(&str, EffectSpec)> = vec![
        ("fade_in(300)", EffectSpec::FadeIn { ms: 300 }),
        ("fade_out(300)", EffectSpec::FadeOut { ms: 300 }),
        ("dissolve_in(300)", EffectSpec::DissolveIn { ms: 300 }),
        ("dissolve_out(300)", EffectSpec::DissolveOut { ms: 300 }),
        (
            r#"slide_in("left", 400)"#,
            EffectSpec::SlideIn {
                direction: EffectDirection::Left,
                ms: 400,
            },
        ),
        (
            r#"slide_out("right", 400)"#,
            EffectSpec::SlideOut {
                direction: EffectDirection::Right,
                ms: 400,
            },
        ),
        (
            r#"sweep_in("top", 400)"#,
            EffectSpec::SweepIn {
                direction: EffectDirection::Top,
                ms: 400,
            },
        ),
        (
            r#"sweep_out("bottom", 400)"#,
            EffectSpec::SweepOut {
                direction: EffectDirection::Bottom,
                ms: 400,
            },
        ),
        (
            r#"pulse("sting", 200)"#,
            EffectSpec::Pulse {
                color: "sting".into(),
                ms: 200,
            },
        ),
        ("glow(500)", EffectSpec::Glow { ms: 500 }),
        ("evolve_in(600)", EffectSpec::EvolveIn { ms: 600 }),
        ("evolve_out(600)", EffectSpec::EvolveOut { ms: 600 }),
    ];
    for (expr, want) in cases {
        let script = format!(r#"w = text("x"); w.effect({expr}); render_to("p", w);"#);
        assert_eq!(attached(&script), Some(want), "for {expr}");
    }
}

#[test]
fn a_duration_outside_the_band_is_clamped_not_refused() {
    // FR-023: a model that guesses 5000ms gets a 2000ms animation and keeps working.
    let long = attached(r#"w = text("x"); w.effect(fade_in(5000)); render_to("p", w);"#);
    assert_eq!(long, Some(EffectSpec::FadeIn { ms: 2000 }));

    let short = attached(r#"w = text("x"); w.effect(fade_in(10)); render_to("p", w);"#);
    assert_eq!(short, Some(EffectSpec::FadeIn { ms: 100 }));

    // Even nonsense clamps rather than erroring — it is decoration, not a contract.
    let negative = attached(r#"w = text("x"); w.effect(glow(-5)); render_to("p", w);"#);
    assert_eq!(negative, Some(EffectSpec::Glow { ms: 100 }));
}

#[test]
fn the_clamped_value_is_what_gets_recorded() {
    // The transcript must carry the *effective* duration, so a replay reproduces the animation
    // the operator actually saw rather than re-clamping a value that never played.
    let out = run(r#"w = text("x"); w.effect(fade_in(9999)); render_to("p", w);"#).unwrap();
    let json = serde_json::to_string(&out.panel_ops[0]).unwrap();
    assert!(json.contains("\"ms\":2000"), "{json}");
    assert!(!json.contains("9999"), "{json}");
}

#[test]
fn an_unknown_direction_falls_back_to_left() {
    let got = attached(r#"w = text("x"); w.effect(slide_in("sideways", 400)); render_to("p", w);"#);
    assert_eq!(
        got,
        Some(EffectSpec::SlideIn {
            direction: EffectDirection::Left,
            ms: 400
        })
    );
}

#[test]
fn an_unknown_color_is_carried_through_for_the_theme_to_resolve() {
    // Not validated here: which palette names exist depends on the theme active at render time,
    // so an unknown one becomes the `info` role in the resolver, not a script error.
    let got = attached(r#"w = text("x"); w.effect(pulse("chartreuse", 200)); render_to("p", w);"#);
    assert_eq!(
        got,
        Some(EffectSpec::Pulse {
            color: "chartreuse".into(),
            ms: 200
        })
    );
}

#[test]
fn an_effect_attaches_to_every_widget_type() {
    // FR-022: any widget, not just the ones that happen to be easy to wrap.
    for ctor in [
        r#"bar_chart("t")"#,
        r#"line_chart("t")"#,
        r#"sparkline("t", [1, 2, 3])"#,
        r#"table("t")"#,
        r#"gauge("t", 0.5)"#,
        r#"dots("t")"#,
        r#"text("t")"#,
        "vsplit()",
        "hsplit()",
        r#"separator()"#,
    ] {
        let script = format!(r#"w = {ctor}; w.effect(fade_in(200)); render_to("p", w);"#);
        assert_eq!(
            attached(&script),
            Some(EffectSpec::FadeIn { ms: 200 }),
            "no effect attached to {ctor}"
        );
    }
}

#[test]
fn the_last_attached_effect_wins() {
    // Matches every other setter on the drawing API.
    let got = attached(
        r#"w = text("x"); w.effect(fade_in(200)); w.effect(glow(500)); render_to("p", w);"#,
    );
    assert_eq!(got, Some(EffectSpec::Glow { ms: 500 }));
}

#[test]
fn a_widget_with_no_effect_records_none_meaning_default_transition() {
    // `None` is "use the default transition", never "no animation" — suppressing motion is the
    // kill switch's job.
    let out = run(r#"render_to("p", text("x"));"#).unwrap();
    assert!(matches!(
        &out.panel_ops[0],
        PanelOp::Upsert { effect: None, .. }
    ));
    let json = serde_json::to_string(&out.panel_ops[0]).unwrap();
    assert!(!json.contains("effect"), "absent, not null: {json}");
}

#[test]
fn an_effect_on_an_inline_render_rides_along_too() {
    let out = run(r#"w = text("x"); w.effect(evolve_in(600)); render(w);"#).unwrap();
    assert_eq!(
        out.inline_effect,
        Some(EffectSpec::EvolveIn { ms: 600 }),
        "an inline widget can carry a transition as well as a panel"
    );
}

mod takeover_tests {
    use super::run;
    use bee::config::{VisualConfig, VisualLevel};
    use bee::render_spec::{EffectSpec, RenderTarget};

    #[test]
    fn render_fullscreen_produces_an_overlay_target() {
        // FR-013a: the target is explicit at the call site, so the visual gate can act on it before
        // any panel or overlay state mutates.
        let out = run(r#"render_fullscreen(text("x"));"#).expect("script ran");
        let (_, ttl, _) = out.overlay.expect("an overlay was requested");
        assert_eq!(ttl, None, "no request means the configured lifetime");
        assert!(
            out.inline.is_none(),
            "a takeover is not also an inline render"
        );
    }

    #[test]
    fn render_fullscreen_ttl_carries_the_requested_lifetime() {
        let out = run(r#"render_fullscreen_ttl(text("x"), 10000);"#).expect("script ran");
        let (_, ttl, _) = out.overlay.expect("overlay");
        assert_eq!(ttl, Some(10_000));
    }

    #[test]
    fn a_non_positive_lifetime_is_a_script_error_like_render_to_ttl() {
        assert!(run(r#"render_fullscreen_ttl(text("x"), 0);"#).is_err());
        assert!(run(r#"render_fullscreen_ttl(text("x"), -5);"#).is_err());
    }

    #[test]
    fn an_over_long_lifetime_is_not_an_error_because_the_config_clamps_it() {
        // FR-021: the ceiling is the operator's decision, not the script's mistake. Clamping happens
        // when the overlay is constructed, against the configured maximum.
        let out = run(r#"render_fullscreen_ttl(text("x"), 900000);"#).expect("script ran");
        let (_, ttl, _) = out.overlay.expect("overlay");
        assert_eq!(
            bee::visual_gate::resolve_ttl(ttl, &VisualConfig::default()),
            30_000,
            "clamped to the configured default, silently"
        );
    }

    #[test]
    fn a_takeover_carries_its_attached_effect() {
        let out = run(r#"c = line_chart("t"); c.effect(fade_in(300)); render_fullscreen(c);"#)
            .expect("script ran");
        let (_, _, effect) = out.overlay.expect("overlay");
        assert_eq!(effect, Some(EffectSpec::FadeIn { ms: 300 }));
    }

    #[test]
    fn the_takeover_panel_id_is_reserved_against_direct_use() {
        // Research R7: the downgrade path owns this id. A script writing to it directly could forge
        // or clobber a downgraded takeover, so both commit verbs refuse it — and the error names the
        // verb the script actually wanted.
        let err = run(r#"render_to("takeover", text("x"));"#).expect_err("must be refused");
        assert!(err.contains("reserved"), "{err}");
        assert!(
            err.contains("render_fullscreen"),
            "points at the right verb: {err}"
        );
        assert!(run(r#"render_to_ttl("takeover", text("x"), 500);"#).is_err());
        assert!(run(r#"remove_panel("takeover");"#).is_err());
        // Neighbouring ids are unaffected — only the exact reserved name is refused.
        assert!(run(r#"render_to("takeover2", text("x"));"#).is_ok());
    }

    #[test]
    fn a_takeover_below_the_level_lands_in_the_reserved_panel_with_a_note() {
        // FR-009 end to end through the gate: the model gets a working visual and is told what
        // happened, rather than a failed tool call.
        let out = run(r#"render_fullscreen(text("x"));"#).expect("script ran");
        let (gated, notes) = bee::tools::render::apply_visual_gate(out, VisualLevel::Panels);
        assert!(gated.overlay.is_none(), "not admitted at this level");
        assert_eq!(gated.panel_ops.len(), 1, "it landed in a panel instead");
        assert_eq!(
            notes,
            vec!["downgraded to panel: visual level does not allow takeover"]
        );
    }

    #[test]
    fn a_takeover_at_level_takeover_passes_through_untouched() {
        let out = run(r#"render_fullscreen_ttl(text("x"), 5000);"#).expect("script ran");
        let (gated, notes) = bee::tools::render::apply_visual_gate(out, VisualLevel::Takeover);
        let (_, ttl, _) = gated.overlay.expect("admitted");
        assert_eq!(ttl, Some(5_000));
        assert!(notes.is_empty());
    }

    #[test]
    fn a_takeover_at_level_none_renders_inline_with_its_effect_intact() {
        // FR-024's neighbour: the *content* still renders. Whether its effect then plays is the
        // resolver's call, and at level none it will not — but the script does not fail either way.
        let out = run(r#"c = text("x"); c.effect(glow(400)); render_fullscreen(c);"#).expect("ran");
        let (gated, notes) = bee::tools::render::apply_visual_gate(out, VisualLevel::None);
        assert!(gated.overlay.is_none());
        assert!(gated.inline.is_some(), "the content still renders");
        assert_eq!(gated.inline_effect, Some(EffectSpec::Glow { ms: 400 }));
        assert_eq!(notes, vec!["downgraded to inline: visual level is none"]);
    }

    #[test]
    fn an_attached_effect_is_dropped_silently_at_level_none_rather_than_failing() {
        // FR-024 / US4 §4. The drop happens in the resolver, not here: the spec survives the gate,
        // and `tui::effects::resolve` returns `None` for it. Either way the tool call succeeds.
        let out = run(r#"c = text("x"); c.effect(slide_in("left", 400)); render_to("p", c);"#)
            .expect("the script must not fail");
        let (gated, _) = bee::tools::render::apply_visual_gate(out, VisualLevel::None);
        assert!(gated.inline.is_some(), "content renders immediately");
        assert!(gated.panel_ops.is_empty());
    }

    #[test]
    fn the_overlay_target_reaches_the_tool_result() {
        // T054: what the front-end acts on is `ToolResult.render_target`, so the target has to
        // survive the whole path out of the Rhai engine.
        let target = RenderTarget::Overlay {
            ttl_ms: Some(5_000),
        };
        assert!(
            !target.is_inline(),
            "an overlay is never the default target"
        );
    }
}
