//! The 009 example scripts actually run (T065).
//!
//! Examples in a spec directory rot silently: the API moves, the script stops parsing, and nobody
//! notices until someone copies it. Running them here makes them executable documentation — if the
//! Python surface changes shape, this fails before the docs mislead anyone.

use bee::render_api::RenderOutcome;

/// Run one example against a fresh engine, returning what it drew.
fn run_example(name: &str) -> RenderOutcome {
    // CARGO_MANIFEST_DIR *is* the workspace root: the application package is the root package.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("specs/009-tachyonfx-effects/examples")
        .join(name);
    let script = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(bee::render_api::evaluate(
            &script,
            &bee::Sandbox::host(vec![]),
        ))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn panel_fade_in_draws_a_panel_and_requests_no_effect() {
    // The default case: the entrance is the harness's job, so the script asks for nothing.
    let out = run_example("panel-fade-in.py");
    assert_eq!(out.panel_ops.len(), 1);
    assert!(
        matches!(
            &out.panel_ops[0],
            bee::render_spec::PanelOp::Upsert { effect: None, .. }
        ),
        "the example is about the default transition, so it must not request one"
    );
}

#[test]
fn slide_dashboard_attaches_a_distinct_effect_to_each_panel() {
    use bee::render_spec::{EffectSpec, PanelOp};
    let out = run_example("slide-dashboard.py");
    assert_eq!(out.panel_ops.len(), 3, "three panels");

    let effects: Vec<Option<EffectSpec>> = out
        .panel_ops
        .iter()
        .map(|op| match op {
            PanelOp::Upsert { effect, .. } => effect.clone(),
            _ => None,
        })
        .collect();
    assert!(
        effects.iter().all(|e| e.is_some()),
        "every panel in this example carries directional intent: {effects:?}"
    );
    assert!(
        matches!(effects[0], Some(EffectSpec::SlideIn { .. })),
        "got {:?}",
        effects[0]
    );
    assert!(
        matches!(effects[1], Some(EffectSpec::SweepIn { .. })),
        "got {:?}",
        effects[1]
    );
}

#[test]
fn status_pulse_flashes_a_theme_role() {
    use bee::render_spec::{EffectSpec, PanelOp};
    let out = run_example("status-pulse.py");
    let PanelOp::Upsert { effect, .. } = &out.panel_ops[0] else {
        panic!("expected an upsert");
    };
    assert!(
        matches!(effect, Some(EffectSpec::Pulse { color, .. }) if color == "sting"),
        "got {effect:?}"
    );
}

#[test]
fn fullscreen_chart_requests_a_takeover_with_its_own_lifetime() {
    let out = run_example("fullscreen-chart.py");
    let (_, ttl, effect) = out.overlay.expect("a takeover was requested");
    assert_eq!(ttl, Some(15_000), "the script's own lifetime, pre-clamp");
    assert!(effect.is_some(), "and its entrance");
    assert!(
        out.panel_ops.is_empty(),
        "a takeover is not also a panel render"
    );
}

#[test]
fn every_example_in_the_directory_is_covered() {
    // A new example that nothing runs is a new example that can rot. This is the guard.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("specs/009-tachyonfx-effects/examples");
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .expect("examples directory")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".py"))
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "fullscreen-chart.py",
            "panel-fade-in.py",
            "slide-dashboard.py",
            "status-pulse.py",
        ],
        "add a test above for any new example, then update this list"
    );
}
