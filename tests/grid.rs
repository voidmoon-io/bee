//! The N×M grid (grid-tui, M1): the `RenderSpec::Grid` renderer and the Python `grid()` surface.
//! Covers cell placement, spanning (a cell's Rect is the union of its base tracks), the structural
//! counts (element/nesting), and the fail-closed validation (overlap, out-of-bounds, dimension cap).

use bee::render_spec::{GridCell, RenderSpec};
use bee::tools::render::RenderTool;
use bee::tools::Tool;
use bee::viz::{render_to_ansi, spec_height};

fn text(s: &str) -> RenderSpec {
    RenderSpec::Text {
        content: s.into(),
        style: None,
        bold: false,
        dim: false,
    }
}

fn cell(row: u16, col: u16, content: RenderSpec) -> GridCell {
    GridCell {
        row,
        col,
        row_span: 1,
        col_span: 1,
        title: None,
        content,
    }
}

// --- Renderer -------------------------------------------------------------------------------------

#[test]
fn grid_renders_each_cell_content() {
    std::env::set_var("NO_COLOR", "1");
    let grid = RenderSpec::Grid {
        rows: 2,
        cols: 2,
        col_weights: Vec::new(),
        row_weights: Vec::new(),
        gap: None,
        cells: vec![
            cell(0, 0, text("alpha")),
            cell(0, 1, text("bravo")),
            cell(1, 0, text("charlie")),
            cell(1, 1, text("delta")),
        ],
    };
    let joined = render_to_ansi(&grid, 60, 40).join("\n");
    for word in ["alpha", "bravo", "charlie", "delta"] {
        assert!(joined.contains(word), "missing {word:?} in:\n{joined}");
    }
    std::env::remove_var("NO_COLOR");
}

#[test]
fn spanning_cell_unions_its_tracks() {
    std::env::set_var("NO_COLOR", "1");
    // A single cell spanning the full 3 columns of the top row should occupy the whole width, so a
    // long string survives farther right than a single 1/3-width column would allow.
    let grid = RenderSpec::Grid {
        rows: 2,
        cols: 3,
        col_weights: Vec::new(),
        row_weights: Vec::new(),
        gap: None,
        cells: vec![GridCell {
            row: 0,
            col: 0,
            row_span: 1,
            col_span: 3,
            title: None,
            content: text("wide-content-that-needs-room"),
        }],
    };
    let lines = render_to_ansi(&grid, 60, 40);
    let first = &lines[0];
    assert!(
        first.contains("wide-content-that-needs-room"),
        "spanning cell should keep the full string: {first:?}"
    );
    std::env::remove_var("NO_COLOR");
}

#[test]
fn grid_counts_elements_and_nesting() {
    // A grid is one nesting level (like a vsplit); a nested vsplit inside a cell adds another.
    let inner = RenderSpec::Layout {
        direction: bee::render_spec::Direction::Vertical,
        children: vec![text("a"), text("b")],
    };
    let grid = RenderSpec::Grid {
        rows: 1,
        cols: 1,
        col_weights: Vec::new(),
        row_weights: Vec::new(),
        gap: None,
        cells: vec![cell(0, 0, inner)],
    };
    assert_eq!(grid.nesting_depth(), 2, "grid(1) + inner vsplit(1)");
    assert_eq!(grid.element_count(), 0, "text carries no data elements");
    assert!(grid.summary_noun().contains("1×1 grid"));
    // Non-empty height so it always draws something.
    assert!(spec_height(&grid, 40) >= 1);
}

#[test]
fn sprite_rasterizes_into_a_buffer_cell() {
    // 008-grid-tui T008: a 2×2 sprite → one half-block row of 2 cells. Top-left over bottom-left is a
    // `▄` with fg=bottom, bg=top; top-right with a transparent bottom is a `▀` with fg=top.
    use bee::render_spec::SpriteSpec;
    use bee::viz::rasterize_sprite_into;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::Color;

    let red = Some((255, 0, 0));
    let green = Some((0, 255, 0));
    let blue = Some((0, 0, 255));
    let spec = SpriteSpec {
        width: 2,
        height: 2,
        // row-major: (0,0)=red (0,1)=green  /  (1,0)=blue (1,1)=transparent
        pixels: vec![red, green, blue, None],
    };
    let area = Rect::new(0, 0, 2, 1);
    let mut buf = Buffer::empty(area);
    rasterize_sprite_into(&spec, area, &mut buf);

    let left = &buf[(0, 0)];
    assert_eq!(left.symbol(), "▄");
    assert_eq!(left.fg, Color::Rgb(0, 0, 255)); // bottom-left = blue
    assert_eq!(left.bg, Color::Rgb(255, 0, 0)); // top-left = red

    let right = &buf[(1, 0)];
    assert_eq!(right.symbol(), "▀"); // only the top pixel is opaque
    assert_eq!(right.fg, Color::Rgb(0, 255, 0)); // top-right = green
}

// --- Python surface (through the real sandboxed RenderTool) ------------------------------------------

async fn run(script: &str) -> bee::tools::ToolResult {
    RenderTool::new()
        .call(
            serde_json::json!({ "script": script }),
            &bee::sandbox::Sandbox::host(Vec::new()),
        )
        .await
}

#[tokio::test]
async fn grid_script_commits_a_grid_spec() {
    let r = run(r#"g = grid(2, 2);
g.cell(0, 0, text("hi"));
g.cell(1, 1, gauge("m", 0.5));
render(g);"#)
    .await;
    assert!(!r.is_error, "unexpected error: {}", r.content);
    match r.render_spec {
        Some(RenderSpec::Grid {
            rows, cols, cells, ..
        }) => {
            assert_eq!((rows, cols), (2, 2));
            assert_eq!(cells.len(), 2);
        }
        other => panic!("expected a Grid, got {other:?}"),
    }
}

#[tokio::test]
async fn grid_spanning_cell_is_accepted() {
    let r = run(r#"g = grid(2, 3);
g.span(0, 0, 1, 3, line_chart("throughput"));
render(g);"#)
    .await;
    assert!(!r.is_error, "span should be legal: {}", r.content);
    assert!(matches!(r.render_spec, Some(RenderSpec::Grid { .. })));
}

#[tokio::test]
async fn overlapping_cells_are_rejected() {
    let r = run(r#"g = grid(2, 2);
g.span(0, 0, 2, 2, text("big"));
g.cell(1, 1, text("clash"));
render(g);"#)
    .await;
    assert!(r.is_error, "overlap must fail");
    assert!(
        r.content.to_lowercase().contains("overlap"),
        "message should mention overlap: {}",
        r.content
    );
}

#[tokio::test]
async fn out_of_bounds_cell_is_rejected() {
    let r = run(r#"g = grid(2, 2);
g.cell(5, 5, text("nope"));
render(g);"#)
    .await;
    assert!(r.is_error, "out-of-bounds must fail");
    assert!(
        r.content.to_lowercase().contains("exceeds"),
        "message should mention exceeds: {}",
        r.content
    );
}

#[tokio::test]
async fn oversized_grid_is_rejected() {
    let r = run(r#"g = grid(20, 20); render(g);"#).await;
    assert!(r.is_error, "20×20 exceeds the 12×12 cap");
    assert!(
        r.content.contains("1..=12"),
        "message should mention the dimension cap: {}",
        r.content
    );
}

#[tokio::test]
async fn shipped_example_script_runs() {
    // Guard the documented example against rot: it must commit a grid without error.
    let script = include_str!("../specs/003-visual-render/examples/grid-dashboard.py");
    let r = run(script).await;
    assert!(!r.is_error, "example must run cleanly: {}", r.content);
    match r.render_spec {
        Some(RenderSpec::Grid {
            rows, cols, cells, ..
        }) => {
            assert_eq!((rows, cols), (2, 3));
            assert_eq!(cells.len(), 4, "3 gauges + 1 spanning table");
        }
        other => panic!("example should render a Grid, got {other:?}"),
    }
}

// ── 019-http-intercept US9 (T089): the live HTTP history pane ─────────────────────────────────────
//
// Pinned as a snapshot. One row carries an ANSI escape and a bidi override from a target-controlled
// path and host: they must draw as visible, inert text through `safe_text`, never as control.
#[cfg(feature = "intercept")]
#[test]
fn the_http_history_pane_renders_hostile_text_inert() {
    use bee::intercept::pane::{history_spec, PaneRow};
    let row = |id: &str, method: &str, host: &str, path: &str, status: &str| PaneRow {
        id: id.into(),
        method: method.into(),
        host: host.into(),
        path: path.into(),
        status: status.into(),
        bytes: "512".into(),
        ms: "12".into(),
        origin: "tool".into(),
    };
    let spec = history_spec(&[
        row("Eabc-1", "GET", "app.test", "/search?q=1", "200"),
        row(
            "Eabc-2",
            "POST",
            "app.test",
            "/api/\u{1b}[31mred\u{1b}[0m",
            "500",
        ),
        row("Eabc-3", "GET", "evil\u{202e}gpj.exe", "/admin", "403"),
    ]);
    let lines = bee::viz::render_to_ansi(&spec, 100, 10);
    let joined = lines.join("\n");
    // No raw escape or bidi control survives into the drawn text.
    let drawn: String = lines
        .iter()
        .map(|l| strip_sgr(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!drawn.contains('\u{202e}'), "{drawn}");
    assert!(!drawn.contains("\u{1b}[31m"), "{drawn}");
    insta::assert_snapshot!("http_history_pane", drawn);
    assert!(joined.contains("Eabc-2"));
}

/// The renderer's own SGR styling is fine; strip it so the snapshot shows the text a user reads.
#[cfg(feature = "intercept")]
fn strip_sgr(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}
