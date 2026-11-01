//! Configurable themes (005-themes), end-to-end through the process-wide active theme. This test
//! binary installs `catppuccin-mocha` once (the `OnceLock` active theme is per-process, so a single
//! binary pins a single theme) and exercises the global render paths: the `palette` role functions
//! (US11.1 / SC-029) and the Python-driven chart color resolution through the headless buffer pipeline
//! (SC-033). Per-theme *resolution* and *rendering* logic is unit-tested in `viz::theme` / `viz::palette`
//! without the global, so those SCs don't need a binary each.

use bee::render_spec::{Bar, RenderSpec};
use bee::viz::{self, palette, render_to_ansi};

/// Install mocha + a truecolor, color-enabled terminal for every test in this binary. Idempotent:
/// all tests here want the same ambient state, so setting it repeatedly can't produce a conflicting
/// result even under parallel execution.
fn setup_mocha_truecolor() {
    std::env::remove_var("NO_COLOR");
    std::env::set_var("COLORTERM", "truecolor");
    viz::init_theme(viz::themes::catppuccin_mocha());
}

#[test]
fn info_role_renders_mocha_truecolor() {
    // SC-029 / US11.1: with catppuccin-mocha active, info() (#f9e2af) emits the truecolor escape,
    // not the basic-ANSI yellow.
    setup_mocha_truecolor();
    let out = palette::info("banner");
    assert!(
        out.contains("\x1b[38;2;249;226;175m"),
        "expected mocha truecolor: {out:?}"
    );
    assert!(
        !out.contains("\x1b[33m"),
        "must not be basic ANSI yellow: {out:?}"
    );
}

#[test]
fn error_role_renders_mocha_red() {
    // US11.1: a denied/error state uses the theme's red (#f38ba8 = 243;139;168), not basic 31.
    setup_mocha_truecolor();
    let out = palette::error("denied");
    assert!(
        out.contains("\x1b[38;2;243;139;168m"),
        "expected mocha red: {out:?}"
    );
}

#[test]
fn chart_accent_color_resolves_through_theme() {
    // SC-033: a bar chart colored "accent" picks up mocha's blue (#89b4fa = 137;180;250) as truecolor
    // through the headless ratatui buffer pipeline.
    setup_mocha_truecolor();
    let spec = RenderSpec::BarChart {
        title: "load".into(),
        bars: vec![
            Bar {
                label: "a".into(),
                value: 10,
            },
            Bar {
                label: "b".into(),
                value: 30,
            },
        ],
        x_label: None,
        y_label: None,
        color: Some("accent".into()),
    };
    let joined = render_to_ansi(&spec, 60, 40).join("\n");
    assert!(
        joined.contains("38;2;137;180;250"),
        "expected mocha accent bars: {joined:?}"
    );
}

#[test]
fn extended_palette_color_resolves() {
    // A chart referencing an extended color name (mocha "peach" = #fab387 = 250;179;135) resolves
    // through theme.extended.
    setup_mocha_truecolor();
    let spec = RenderSpec::BarChart {
        title: "x".into(),
        bars: vec![Bar {
            label: "a".into(),
            value: 5,
        }],
        x_label: None,
        y_label: None,
        color: Some("peach".into()),
    };
    let joined = render_to_ansi(&spec, 40, 40).join("\n");
    assert!(
        joined.contains("38;2;250;179;135"),
        "expected peach bars: {joined:?}"
    );
}
