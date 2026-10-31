//! The `render` tool's fail-closed Rhai boundary (003-visual-render, US6, FR-020/FR-021): resource
//! limits and deny-by-default (SC-009/SC-010) plus the no-render / multiple-render edge cases. These
//! validate the sandbox *before* trusting it — Constitution I.

use bee::render_spec::RenderSpec;
use bee::sandbox::Sandbox;
use bee::tools::render::RenderTool;
use bee::tools::Tool;

fn host() -> Sandbox {
    Sandbox::host(Vec::new())
}

async fn run(script: &str) -> bee::tools::ToolResult {
    let tool = RenderTool::new();
    tool.call(serde_json::json!({ "script": script }), &host())
        .await
}

#[tokio::test]
async fn loop_hits_operation_limit() {
    // SC-009: an infinite loop is terminated by the engine's op budget, fast.
    let start = std::time::Instant::now();
    let r = run("loop {}").await;
    assert!(
        start.elapsed().as_millis() < 500,
        "should terminate quickly"
    );
    assert!(r.is_error, "expected error result");
    assert!(
        r.content.to_lowercase().contains("operation limit"),
        "message should mention the op limit: {}",
        r.content
    );
    assert!(r.render_spec.is_none());
}

#[tokio::test]
async fn unregistered_function_is_denied() {
    // SC-010: a function that is not in the drawing API does not exist.
    let r = run("no_such_drawing_fn();").await;
    assert!(r.is_error);
    assert!(
        r.content.to_lowercase().contains("not found"),
        "expected 'not found': {}",
        r.content
    );
}

#[tokio::test]
async fn no_io_module_available() {
    // SC-010: importing a module resolves nothing (no module resolver registered).
    let r = run("import \"std\" as m; m::foo();").await;
    assert!(r.is_error, "import must fail: {}", r.content);
}

#[tokio::test]
async fn script_with_no_render_is_an_error() {
    let r = run("let x = 1 + 2;").await;
    assert!(r.is_error);
    assert!(r.content.contains("no visualization"), "got: {}", r.content);
}

#[tokio::test]
async fn last_render_wins_with_discard_note() {
    let script = r#"
        let a = bar_chart("first"); a.bar("x", 1); render(a);
        let b = bar_chart("second"); b.bar("y", 2); render(b);
    "#;
    let r = run(script).await;
    assert!(!r.is_error, "got: {}", r.content);
    match r.render_spec {
        Some(RenderSpec::BarChart { title, .. }) => assert_eq!(title, "second"),
        other => panic!("expected the last BarChart, got {other:?}"),
    }
    assert!(
        r.content.contains("discarded"),
        "summary should note discard: {}",
        r.content
    );
}

#[tokio::test]
async fn bar_chart_builds_expected_spec() {
    let script = r#"
        let c = bar_chart("Sizes");
        c.bar("a", 10); c.bar("b", 20); c.bar("c", 30);
        render(c);
    "#;
    let r = run(script).await;
    assert!(!r.is_error, "got: {}", r.content);
    assert!(!r.content.contains('\u{1b}'), "summary must be ANSI-free");
    match r.render_spec {
        Some(RenderSpec::BarChart { bars, title, .. }) => {
            assert_eq!(title, "Sizes");
            assert_eq!(bars.len(), 3);
            assert_eq!(bars[1].label, "b");
            assert_eq!(bars[2].value, 30);
        }
        other => panic!("expected BarChart, got {other:?}"),
    }
}

// --- Slice 2: sprite/animation caps (⛔FAIL-FIRST — the fail-closed drawing boundary) ---

#[tokio::test]
async fn sprite_over_32_is_rejected() {
    let r = run(r#"let p = palette(); let s = sprite(40, 40, p); render(s);"#).await;
    assert!(r.is_error, "40×40 must be rejected: {}", r.content);
    assert!(r.content.contains("dimensions"), "got: {}", r.content);
}

#[tokio::test]
async fn oversized_palette_is_rejected() {
    // 33 distinct entries exceeds the 32-entry cap.
    let script = r##"
        let p = palette();
        let keys = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q",
                    "r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G"];  // 33 distinct
        for k in keys { p.set(k, "#010203"); }
        let s = sprite(2, 2, p); render(s);
    "##;
    let r = run(script).await;
    assert!(
        r.is_error,
        "oversized palette must be rejected: {}",
        r.content
    );
    assert!(r.content.contains("palette"), "got: {}", r.content);
}

#[tokio::test]
async fn bad_hex_color_is_rejected() {
    let r = run(r##"let p = palette(); p.set("K", "#zzzz"); let s = sprite(2, 2, p); render(s);"##)
        .await;
    assert!(r.is_error, "bad hex must be rejected: {}", r.content);
    assert!(
        r.content.to_lowercase().contains("color"),
        "got: {}",
        r.content
    );
}

#[tokio::test]
async fn too_many_frames_is_rejected() {
    let script = r##"
        let p = palette(); p.set("K", "#101010");
        let a = animation(150);
        for i in 0..17 { let s = sprite(2, 2, p); a.add(s); }
        render(a);
    "##;
    let r = run(script).await;
    assert!(r.is_error, "17 frames must be rejected: {}", r.content);
    assert!(r.content.contains("16 frames"), "got: {}", r.content);
}

#[tokio::test]
async fn mismatched_frame_dims_is_rejected() {
    let script = r#"
        let p = palette();
        let a = animation(150);
        a.add(sprite(4, 4, p));
        a.add(sprite(8, 8, p));
        render(a);
    "#;
    let r = run(script).await;
    assert!(
        r.is_error,
        "mismatched dims must be rejected: {}",
        r.content
    );
    assert!(r.content.contains("dimensions"), "got: {}", r.content);
}

#[tokio::test]
async fn interval_is_clamped_not_an_error() {
    // A too-fast interval is clamped to 50ms, not rejected.
    let script = r##"
        let p = palette(); p.set("K", "#101010");
        let a = animation(5);     // below the 50ms floor
        a.add(sprite(2, 2, p));
        render(a);
    "##;
    let r = run(script).await;
    assert!(!r.is_error, "clamped interval must succeed: {}", r.content);
    match r.render_spec {
        Some(RenderSpec::Animation { spec }) => {
            assert_eq!(spec.interval_ms, 50, "clamped to floor")
        }
        other => panic!("expected Animation, got {other:?}"),
    }
}

#[tokio::test]
async fn bee_functions_are_callable() {
    // SC-018: bee_sprite() and bee_animation() build valid specs from a Rhai script.
    let s = run("render(bee_sprite());").await;
    assert!(!s.is_error, "bee_sprite: {}", s.content);
    match s.render_spec {
        Some(RenderSpec::Sprite { spec }) => {
            assert_eq!((spec.width, spec.height), (24, 24));
            assert!(!spec.is_fully_transparent(), "the bee has pixels");
        }
        other => panic!("expected Sprite, got {other:?}"),
    }
    let a = run("render(bee_animation());").await;
    assert!(!a.is_error, "bee_animation: {}", a.content);
    match a.render_spec {
        Some(RenderSpec::Animation { spec }) => assert_eq!(spec.frames.len(), 6),
        other => panic!("expected Animation, got {other:?}"),
    }
}

#[tokio::test]
async fn transparent_sprite_summary_notes_it() {
    // M1: a fully-transparent sprite's summary says so.
    let r = run(r#"let p = palette(); let s = sprite(4, 4, p); render(s);"#).await;
    assert!(!r.is_error, "got: {}", r.content);
    assert!(
        r.content.contains("fully transparent"),
        "summary should note it: {}",
        r.content
    );
}

#[tokio::test]
async fn nesting_over_four_is_rejected() {
    // 5 levels of vsplit exceeds the depth-4 structural cap (grid-tui raised it from 3 to make a
    // grid-of-splits legal; contracts/rhai-api.md).
    let script = r#"
        let l1 = vsplit(); let l2 = vsplit(); let l3 = vsplit(); let l4 = vsplit(); let l5 = vsplit();
        l5.add(text("x")); l4.add(l5); l3.add(l4); l2.add(l3); l1.add(l2);
        render(l1);
    "#;
    let r = run(script).await;
    assert!(r.is_error, "deep nesting must be rejected: {}", r.content);
    assert!(r.content.contains("nesting"), "got: {}", r.content);
}
