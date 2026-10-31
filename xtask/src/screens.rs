//! `cargo xtask viz-screens` — render the **whole TUI** at representative states and sizes to SVG,
//! through the real `view()` on a headless backend. The gallery shows widgets in isolation; this
//! shows the composed product — header, chat flow, panel column, input, footer — which is the level
//! visual review actually happens at.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use bee::render_spec::{Bar, Point, RenderSpec, Row, Series};
use bee::tui::app::{App, TurnState};
use bee::tui::chat::{ChatMessage, Role};
use bee::tui::view;
use bee::viz::{theme, themes};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use crate::gallery::buffer_to_svg;

struct Screen {
    name: &'static str,
    cols: u16,
    rows: u16,
    build: fn() -> App,
}

const SCREENS: &[Screen] = &[
    Screen {
        name: "welcome_narrow",
        cols: 80,
        rows: 24,
        build: welcome,
    },
    Screen {
        name: "welcome_wide",
        cols: 120,
        rows: 32,
        build: welcome,
    },
    Screen {
        name: "session_wide",
        cols: 120,
        rows: 32,
        build: session_wide,
    },
    Screen {
        name: "session_narrow_overlay",
        cols: 80,
        rows: 24,
        build: session_narrow,
    },
    Screen {
        name: "panel_focus",
        cols: 120,
        rows: 32,
        build: panel_focus,
    },
    Screen {
        name: "help",
        cols: 100,
        rows: 28,
        build: help_open,
    },
    Screen {
        name: "takeover",
        cols: 100,
        rows: 28,
        build: takeover,
    },
];

fn welcome() -> App {
    let mut app = App::new(80, 24).with_model("claude-opus-4-8");
    app.chat.push(ChatMessage::mascot());
    app.chat.push(ChatMessage::text(
        Role::System,
        "interactive session — claude-opus-4-8 — type a message, ? for help, q to quit",
    ));
    app
}

/// A mid-session two-pane frame: conversation with tool traffic, an inline chart, live panels, a
/// half-typed reply, and a streaming turn so the header's working indicator shows.
fn session_wide() -> App {
    let mut app = App::new(120, 32).with_model("claude-opus-4-8");
    app.chat.push(ChatMessage::text(
        Role::System,
        "interactive session — type a message, ? for help, q to quit",
    ));
    app.chat.push(ChatMessage::text(
        Role::User,
        "run the test suite and chart the latency",
    ));
    app.chat.push(ChatMessage::text(
        Role::Tool,
        "▸ bash(cargo test --workspace)",
    ));
    app.chat.push(ChatMessage::text(
        Role::Tool,
        "✓ 363 passed; 0 failed (4.2s)",
    ));
    let mut reply = ChatMessage::text(
        Role::Assistant,
        "All **363 tests pass**. Latency stayed inside the budget:\n\n\
         - p50 holds near `8ms` across the run\n\
         - p99 spikes once at cold start, then settles\n\n\
         The hot loop after the fix:\n\n\
         ```rust\n\
         pub fn measure(reqs: &[Request]) -> Stats {\n\
         \x20   let mut hist = Histogram::new();\n\
         \x20   for r in reqs {\n\
         \x20       hist.record(r.elapsed_ms); // no alloc in the loop\n\
         \x20   }\n\
         \x20   hist.stats()\n\
         }\n\
         ```",
    );
    reply.mark_done();
    app.chat.push(reply);
    app.chat.push(ChatMessage::widget(RenderSpec::LineChart {
        title: "Latency (ms)".into(),
        series: vec![
            Series {
                label: "p50".into(),
                points: pts(&[5.0, 8.0, 6.0, 12.0, 7.0, 9.0, 8.0, 7.0]),
            },
            Series {
                label: "p99".into(),
                points: pts(&[25.0, 40.0, 30.0, 55.0, 35.0, 33.0, 38.0, 31.0]),
            },
        ],
    }));
    app.panels.upsert(
        "tests",
        RenderSpec::Table {
            title: "Suites".into(),
            headers: vec!["suite".into(), "pass".into(), "time".into()],
            rows: vec![
                row(&["unit", "142", "1.2s"], None),
                row(&["integration", "38", "14.8s"], None),
                row(&["e2e", "15", "42.1s"], None),
            ],
        },
    );
    app.panels.upsert(
        "throughput",
        RenderSpec::Sparkline {
            title: "req/s".into(),
            data: vec![4, 7, 6, 9, 12, 9, 14, 11, 16, 13, 18, 15, 12, 14, 17],
        },
    );
    app.turn = TurnState::Streaming;
    app.activity = 3;
    app.input.insert_str("looks good — ship it");
    app
}

/// The panel column being driven: focus on the panels, a collapsed table, the denial tail
/// selected, footer hints following the focus.
fn panel_focus() -> App {
    use bee::render_spec::LogLine;
    use bee::tui::app::Focus;

    let mut app = App::new(120, 32).with_model("claude-opus-4-8");
    app.chat
        .push(ChatMessage::text(Role::User, "run it under the strict policy"));
    app.chat
        .push(ChatMessage::text(Role::Tool, "▸ bash(cargo test) [policy: strict]"));
    app.panels.upsert(
        "tests",
        RenderSpec::Table {
            title: "Suites".into(),
            headers: vec!["suite".into(), "pass".into()],
            rows: vec![row(&["unit", "142"], None), row(&["e2e", "15"], None)],
        },
    );
    app.panels.upsert(
        "denials",
        RenderSpec::LogTail {
            title: "sandbox denials".into(),
            lines: vec![
                LogLine { text: "policy strict loaded (22 rules)".into(), level: Some("info".into()) },
                LogLine { text: "exec /usr/bin/cc allowed".into(), level: Some("debug".into()) },
                LogLine { text: "connect 140.82.112.3:443 outside scope".into(), level: Some("warn".into()) },
                LogLine { text: "open /etc/shadow blocked".into(), level: Some("error".into()) },
                LogLine { text: "exec /usr/bin/curl blocked".into(), level: Some("error".into()) },
            ],
            max_rows: Some(6),
        },
    );
    app.panels.upsert(
        "throughput",
        RenderSpec::Sparkline {
            title: "req/s".into(),
            data: vec![4, 7, 6, 9, 12, 9, 14, 11, 16, 13],
        },
    );
    app.panels.toggle_collapse_at(0); // the table folded out of the way
    app.focus = Focus::Panels;
    app.panel_sel = 1; // the denial tail selected
    app
}

/// The 80×24 floor: single pane, panels reachable only through the `p` overlay — shown open.
fn session_narrow() -> App {
    let mut app = App::new(80, 24).with_model("claude-opus-4-8");
    app.chat
        .push(ChatMessage::text(Role::User, "watch the deploy"));
    app.chat.push(ChatMessage::text(
        Role::Tool,
        "▸ deploy(production-us-east-1)",
    ));
    app.panels.upsert(
        "deploy",
        RenderSpec::Gauge {
            title: "rollout".into(),
            value: 0.73,
            label: Some("73% (58/80 pods)".into()),
            color: None,
        },
    );
    app.panels_visible = true;
    app
}

fn help_open() -> App {
    let mut app = App::new(100, 28).with_model("claude-opus-4-8");
    app.chat.push(ChatMessage::text(Role::User, "hello"));
    app.help_open = true;
    app
}

fn takeover() -> App {
    let mut app = App::new(100, 28).with_model("claude-opus-4-8");
    app.chat
        .push(ChatMessage::text(Role::User, "show the bars"));
    app.show_overlay(
        RenderSpec::BarChart {
            title: "Quarterly Revenue".into(),
            bars: vec![
                Bar {
                    label: "Q1".into(),
                    value: 120,
                },
                Bar {
                    label: "Q2".into(),
                    value: 185,
                },
                Bar {
                    label: "Q3".into(),
                    value: 95,
                },
                Bar {
                    label: "Q4".into(),
                    value: 210,
                },
            ],
            x_label: None,
            y_label: None,
            color: None,
        },
        Some(30_000),
        std::time::Instant::now(),
    );
    app
}

fn pts(ys: &[f64]) -> Vec<Point> {
    ys.iter()
        .enumerate()
        .map(|(i, &y)| Point { x: i as f64, y })
        .collect()
}

fn row(cells: &[&str], color: Option<&str>) -> Row {
    Row {
        cells: cells.iter().map(|c| (*c).into()).collect(),
        color: color.map(Into::into),
    }
}

/// One clean frame of the settled UI. Screens render as a **motionless** session (FR-006c): with
/// animations off nothing registers, so the first frame *is* the frame an operator reads. Looping a
/// live-effects session to completion instead hands back the transition's final processed frame —
/// fade washes and fade-from-black backgrounds included — which is a picture of the animation, not
/// of the UI.
fn render_settled(app: &mut App, cols: u16, rows: u16) -> Result<Buffer> {
    app.visual = bee::config::VisualConfig {
        animations: false,
        ..app.visual
    };
    let mut term = Terminal::new(TestBackend::new(cols, rows))?;
    app.dt = Duration::from_millis(16);
    term.draw(|f| view::view(app, f))?;
    Ok(term.backend().buffer().clone())
}

pub fn run(theme_name: &str, out_dir: Option<&Path>) -> Result<()> {
    // One theme per process (`init_theme` is once): pick it up front. Default is the truecolor
    // mocha so exports show what a modern terminal shows; pass `--theme honeycomb` for the
    // basic-ANSI floor.
    let theme = themes::builtin(theme_name)
        .ok_or_else(|| anyhow::anyhow!("unknown theme {theme_name:?}"))?;
    theme::init_theme(theme);

    let dir = out_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("xtask/screens"));
    std::fs::create_dir_all(&dir)?;
    for screen in SCREENS {
        let mut app = (screen.build)();
        let buf = render_settled(&mut app, screen.cols, screen.rows)?;
        let svg = buffer_to_svg(&buf, screen.name);
        let path = dir.join(format!("{}.svg", screen.name));
        std::fs::write(&path, &svg)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}
