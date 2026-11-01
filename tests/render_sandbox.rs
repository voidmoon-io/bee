//! The `render` tool's fail-closed Python boundary (003-visual-render, US6, FR-020/FR-021): resource
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
async fn loop_hits_execution_deadline() {
    // SC-009: an infinite loop is terminated by the interpreter's time budget, fast.
    let start = std::time::Instant::now();
    let r = run(r#"while True: pass"#).await;
    assert!(
        start.elapsed().as_millis() < 3000,
        "should terminate quickly"
    );
    assert!(r.is_error, "expected error result");
    assert!(
        r.content.to_lowercase().contains("time limit"),
        "message should mention the time limit: {}",
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
    let r = run(r#"x = 1 + 2;"#).await;
    assert!(r.is_error);
    assert!(r.content.contains("no visualization"), "got: {}", r.content);
}

#[tokio::test]
async fn last_render_wins_with_discard_note() {
    let script = r#"a = bar_chart("first"); a.bar("x", 1); render(a);
b = bar_chart("second"); b.bar("y", 2); render(b);"#;
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
    let script = r#"c = bar_chart("Sizes");
c.bar("a", 10); c.bar("b", 20); c.bar("c", 30);
render(c);"#;
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
    let r = run(r#"p = palette(); s = sprite(40, 40, p); render(s);"#).await;
    assert!(r.is_error, "40×40 must be rejected: {}", r.content);
    assert!(r.content.contains("dimensions"), "got: {}", r.content);
}

#[tokio::test]
async fn oversized_palette_is_rejected() {
    // 33 distinct entries exceeds the 32-entry cap.
    let script = r##"p = palette();
keys = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q",
            "r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G"];  # 33 distinct
for k in keys: p.set(k, "#010203");
s = sprite(2, 2, p); render(s);"##;
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
    let r = run(r##"p = palette(); p.set("K", "#zzzz"); s = sprite(2, 2, p); render(s);"##).await;
    assert!(r.is_error, "bad hex must be rejected: {}", r.content);
    assert!(
        r.content.to_lowercase().contains("color"),
        "got: {}",
        r.content
    );
}

#[tokio::test]
async fn too_many_frames_is_rejected() {
    let script = r##"p = palette(); p.set("K", "#101010");
a = animation(150);

for i in range(0, 17):
    s = sprite(2, 2, p); a.add(s);

render(a);"##;
    let r = run(script).await;
    assert!(r.is_error, "17 frames must be rejected: {}", r.content);
    assert!(r.content.contains("16 frames"), "got: {}", r.content);
}

#[tokio::test]
async fn mismatched_frame_dims_is_rejected() {
    let script = r#"p = palette();
a = animation(150);
a.add(sprite(4, 4, p));
a.add(sprite(8, 8, p));
render(a);"#;
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
    let script = r##"p = palette(); p.set("K", "#101010");
a = animation(5);     # below the 50ms floor
a.add(sprite(2, 2, p));
render(a);"##;
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
    // SC-018: bee_sprite() and bee_animation() build valid specs from a Python script.
    let s = run("render(bee_sprite());").await;
    assert!(!s.is_error, "bee_sprite: {}", s.content);
    match s.render_spec {
        Some(RenderSpec::Sprite { spec }) => {
            assert_eq!(
                (spec.width, spec.height),
                (
                    bee::viz::bee::sprite().width,
                    bee::viz::bee::sprite().height
                )
            );
            assert!(!spec.is_fully_transparent(), "the bee has pixels");
        }
        other => panic!("expected Sprite, got {other:?}"),
    }
    let a = run("render(bee_animation());").await;
    assert!(!a.is_error, "bee_animation: {}", a.content);
    match a.render_spec {
        Some(RenderSpec::Animation { spec }) => {
            assert_eq!(spec.frames.len(), bee::viz::bee::animation().frames.len())
        }
        other => panic!("expected Animation, got {other:?}"),
    }
}

#[tokio::test]
async fn transparent_sprite_summary_notes_it() {
    // M1: a fully-transparent sprite's summary says so.
    let r = run(r#"p = palette(); s = sprite(4, 4, p); render(s);"#).await;
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
    let script = r#"l1 = vsplit(); l2 = vsplit(); l3 = vsplit(); l4 = vsplit(); l5 = vsplit();
l5.add(text("x")); l4.add(l5); l3.add(l4); l2.add(l3); l1.add(l2);
render(l1);"#;
    let r = run(script).await;
    assert!(r.is_error, "deep nesting must be rejected: {}", r.content);
    assert!(r.content.contains("nesting"), "got: {}", r.content);
}
