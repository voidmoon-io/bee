//! [`RenderSpec`] (003-visual-render, US6) — the validated, renderable output of a `render`-tool
//! Python script. Produced by the render tool, consumed by [`crate::repl::ReplOutput::render_widget`]
//! and [`crate::viz::render_to_ansi`].
//!
//! **This type deliberately contains NO ratatui or Monty types** (research D5): it is a pure serde
//! value so it can be recorded verbatim in the episode transcript (`ToolResult.render_spec`) and
//! re-rendered later, and so `ratatui`/`monty` never leak toward `bee-core` through the transcript
//! (NFR-002/SC-019). It is `#[non_exhaustive]` — Slice 2 adds `Sprite`/`Animation` additively.

use serde::{Deserialize, Serialize};

pub mod effect_spec;

pub use effect_spec::{clamp_ms, EffectDirection, EffectSpec};

/// One bar of a [`RenderSpec::BarChart`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bar {
    pub label: String,
    pub value: i64,
}

/// A named line-chart series (a sequence of [`Point`]s).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Series {
    pub label: String,
    pub points: Vec<Point>,
}

/// One `(x, y)` data point of a [`Series`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

/// One labelled row of a [`RenderSpec::Heatmap`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeatRow {
    pub label: String,
    pub values: Vec<f64>,
}

/// One table row: its cells plus an optional row color (palette or basic-ANSI name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub cells: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// One line of a [`RenderSpec::LogTail`]: its text plus an optional severity level
/// (`error`/`warn`/`info`/`debug`/`trace`) that drives the gutter marker and color.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogLine {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// One labelled dot of a [`RenderSpec::DotGrid`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dot {
    pub label: String,
    pub state: DotState,
}

/// The colored state of a [`Dot`]: green / red / neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DotState {
    Pass,
    Fail,
    Skip,
}

/// serde default for [`GridCell`] spans (a cell covers one track unless told otherwise).
fn default_span() -> u16 {
    1
}

/// One cell of a [`RenderSpec::Grid`] (grid-tui, M1): a widget placed at `(row, col)`, optionally
/// spanning multiple tracks. `content` is any [`RenderSpec`], so the whole component system nests
/// inside a grid. Pure serde like everything else here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GridCell {
    pub row: u16,
    pub col: u16,
    #[serde(default = "default_span")]
    pub row_span: u16,
    #[serde(default = "default_span")]
    pub col_span: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub content: RenderSpec,
}

/// A widget plus the transition the agent asked for (009-tachyonfx-effects, FR-022).
///
/// The pair exists because a [`RenderSpec`] is content and an [`EffectSpec`] is motion, and 008's
/// transcripts must keep deserializing byte-identically — so the effect rides *beside* the spec
/// rather than inside it. `effect: None` means "use the default transition for this target", never
/// "no animation": suppressing motion is the kill switch's job, not the absence of a request.
#[derive(Debug, Clone, PartialEq)]
pub struct Renderable {
    pub spec: RenderSpec,
    pub effect: Option<EffectSpec>,
}

impl Renderable {
    /// A widget with no agent-requested transition — the default entrance applies.
    pub fn plain(spec: RenderSpec) -> Self {
        Renderable { spec, effect: None }
    }

    /// Attach (or replace) the requested transition. Last write wins, matching every other
    /// builder setter on the drawing API.
    pub fn with_effect(mut self, effect: EffectSpec) -> Self {
        self.effect = Some(effect);
        self
    }
}

impl From<RenderSpec> for Renderable {
    fn from(spec: RenderSpec) -> Self {
        Renderable::plain(spec)
    }
}

/// A layout direction — maps to a ratatui `Direction` at render time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Vertical,
    Horizontal,
}

/// Where a rendered spec is sent (008-grid-tui): the chat flow, or a named persistent panel. Pure
/// serde so the render tool result and the episode transcript can carry it (contracts/rhai-panel-api).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum RenderTarget {
    /// Flows inline into the conversation — the default and today's behavior.
    #[default]
    Inline,
    /// A named, persistent, model-owned panel; re-rendering the same `id` replaces it in place.
    Panel { id: String },
    /// A full-screen overlay covering the chat area (009-tachyonfx-effects, FR-013a). Requires
    /// `visual_level = "takeover"`; below that the visual gate downgrades it to a panel, and at
    /// `none` to inline. The target is carried explicitly rather than inferred from a widget
    /// property or a magic panel id, so the gate can act before any state mutates.
    ///
    /// `ttl_ms` is what the *script* asked for; the lifetime actually granted is
    /// `min(requested, configured)`, resolved once at construction
    /// (`visual_gate::resolve_ttl`). `None` means "use the configured lifetime".
    Overlay {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_ms: Option<u32>,
    },
}

impl RenderTarget {
    /// True for the default inline target — used by serde to skip the field for inline results.
    pub fn is_inline(&self) -> bool {
        matches!(self, RenderTarget::Inline)
    }
}

/// One effect a render script requests on the panel column (008-grid-tui, US2 lifecycle).
///
/// Panels were create-or-replace only, which let them accumulate unbounded with no model-side way to
/// reclaim space. These ops close that gap: a script can remove one panel, clear them all, or give a
/// panel a TTL so it expires on its own. Pure serde like every other render type, so the ops record
/// in the transcript and replay exactly (NFR-002/SC-019).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PanelOp {
    /// Create panel `id`, or replace its content in place if it already exists (FR-008/009).
    /// `ttl_ms`, when set, expires the panel that long after this update.
    Upsert {
        id: String,
        spec: RenderSpec,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_ms: Option<u64>,
        /// An agent-requested transition (009, FR-022). `None` means "use the default transition
        /// for this target" — **not** "no animation". Suppressing animation is the motion switch's
        /// job, never the absence of an effect. Skipped when absent so 008 transcripts round-trip
        /// byte-identically.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect: Option<EffectSpec>,
    },
    /// Remove panel `id` if it exists; a no-op when it doesn't.
    Remove { id: String },
    /// Remove every panel.
    Clear,
}

/// A full-screen takeover request (009-tachyonfx-effects, FR-013a) — what `render_fullscreen` and
/// `render_fullscreen_ttl` produce. At most one survives a script (last writer wins, like the inline
/// commit), which is how FR-020's "no stacking" starts being true before the TUI ever sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayRequest {
    pub spec: RenderSpec,
    /// Requested lifetime. `None` uses the configured default. The configured maximum is a hard cap:
    /// a longer request is clamped down, a shorter one is honored (FR-021).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<EffectSpec>,
}

/// A pixel-art sprite (003-visual-render, Slice 2, FR-028): a `width × height` grid of RGB pixels,
/// row-major, `None` = transparent. Rendered via the half-block technique (`viz::sprite_render`) to
/// `⌈height/2⌉` terminal rows. Like every [`RenderSpec`] member it is pure serde (no ratatui/Monty) so
/// it records in the transcript and re-renders later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpriteSpec {
    /// Pixel columns (1..=32).
    pub width: u16,
    /// Pixel rows (1..=32).
    pub height: u16,
    /// Row-major RGB pixels; `None` = transparent. `len() == width * height`.
    pub pixels: Vec<Option<(u8, u8, u8)>>,
}

impl SpriteSpec {
    /// The pixel at `(x, y)`, or `None` if out of bounds or transparent.
    pub fn pixel(&self, x: u16, y: u16) -> Option<(u8, u8, u8)> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.pixels
            .get((y as usize) * (self.width as usize) + x as usize)
            .copied()
            .flatten()
    }

    /// True when every pixel is transparent (renders as blank rows; the tool summary notes it).
    pub fn is_fully_transparent(&self) -> bool {
        self.pixels.iter().all(Option::is_none)
    }
}

/// A frame animation (003-visual-render, Slice 2, FR-029): 1–16 same-dimensioned [`SpriteSpec`]
/// frames plus playback parameters. Driven in place by `viz::animator` + `TerminalOutput`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnimationSpec {
    /// 1..=16 frames, all identical `(width, height)`.
    pub frames: Vec<SpriteSpec>,
    /// Per-frame duration, clamped 50..=1000 ms.
    pub interval_ms: u64,
    /// Ping-pong playback (`0,1,…,k,…,1`).
    pub bounce: bool,
    /// Full cycles then stop; `0` = loop until interrupted.
    pub cycles: u32,
}

/// The validated, renderable output of a Python render script. Variants mirror the Python drawing API
/// (contracts/rhai-api.md). Slice 1 covers the static widgets; `Sprite`/`Animation` land in Slice 2
/// (hence `#[non_exhaustive]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RenderSpec {
    BarChart {
        title: String,
        bars: Vec<Bar>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        y_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        color: Option<String>,
    },
    LineChart {
        title: String,
        series: Vec<Series>,
    },
    ScatterPlot {
        title: String,
        series: Vec<Series>,
    },
    AreaChart {
        title: String,
        series: Vec<Series>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        color: Option<String>,
    },
    Heatmap {
        title: String,
        rows: Vec<HeatRow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        color: Option<String>,
    },
    Sparkline {
        title: String,
        data: Vec<u64>,
    },
    /// A bottom-anchored stream tail: the newest lines that fit, oldest scrolling off the top —
    /// built for feeds like sandbox denials landing while an episode runs. Levels are marked with a
    /// letter as well as a color, so the stream still reads in monochrome.
    LogTail {
        title: String,
        lines: Vec<LogLine>,
        /// Content rows shown (default 8): the tail keeps the newest `max_rows` lines.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_rows: Option<u16>,
    },
    Table {
        title: String,
        headers: Vec<String>,
        rows: Vec<Row>,
    },
    Gauge {
        title: String,
        value: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        color: Option<String>,
    },
    DotGrid {
        title: String,
        dots: Vec<Dot>,
    },
    Text {
        content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        style: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        bold: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        dim: bool,
    },
    AsciiArt {
        lines: Vec<String>,
    },
    /// A markdown block the agent asked to have rendered (010). Carried as **source**, never as
    /// styled spans: the transcript stays renderer-free (NFR-002) and a replay re-renders at
    /// whatever width the terminal reading it happens to have.
    Markdown {
        content: String,
    },
    Separator,
    Layout {
        direction: Direction,
        children: Vec<RenderSpec>,
    },
    /// A static pixel-art sprite (Slice 2, FR-028).
    Sprite {
        spec: SpriteSpec,
    },
    /// A frame animation (Slice 2, FR-029).
    Animation {
        spec: AnimationSpec,
    },
    /// A model-defined N×M grid of cells, each holding any widget (grid-tui, M1). `rows`/`cols` are
    /// the track counts; `*_weights` size the tracks proportionally (empty = equal); `gap` is the
    /// inter-track spacing. Cells are validated non-overlapping and in-bounds at build time.
    Grid {
        rows: u16,
        cols: u16,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        col_weights: Vec<u16>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        row_weights: Vec<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gap: Option<u16>,
        cells: Vec<GridCell>,
    },
}

impl RenderSpec {
    /// The number of drawable data elements this spec (and its children) carries — bars, table rows,
    /// and line-chart points summed. Used by the render API to enforce the 500-element structural cap
    /// (contracts/rhai-api.md Constraints).
    pub fn element_count(&self) -> usize {
        match self {
            RenderSpec::BarChart { bars, .. } => bars.len(),
            RenderSpec::LineChart { series, .. }
            | RenderSpec::ScatterPlot { series, .. }
            | RenderSpec::AreaChart { series, .. } => series.iter().map(|s| s.points.len()).sum(),
            RenderSpec::Heatmap { rows, .. } => rows.iter().map(|r| r.values.len()).sum(),
            RenderSpec::Sparkline { data, .. } => data.len(),
            RenderSpec::LogTail { lines, .. } => lines.len(),
            RenderSpec::Table { rows, .. } => rows.len(),
            RenderSpec::DotGrid { dots, .. } => dots.len(),
            RenderSpec::Layout { children, .. } => children.iter().map(|c| c.element_count()).sum(),
            RenderSpec::Grid { cells, .. } => cells.iter().map(|c| c.content.element_count()).sum(),
            RenderSpec::Sprite { .. } => 1,
            RenderSpec::Animation { spec } => spec.frames.len(),
            _ => 0,
        }
    }

    /// The maximum layout-nesting depth of this spec (a non-layout is depth 0). Used to enforce the
    /// ≤ 3 nesting cap.
    pub fn nesting_depth(&self) -> usize {
        match self {
            RenderSpec::Layout { children, .. } => {
                1 + children
                    .iter()
                    .map(|c| c.nesting_depth())
                    .max()
                    .unwrap_or(0)
            }
            RenderSpec::Grid { cells, .. } => {
                1 + cells
                    .iter()
                    .map(|c| c.content.nesting_depth())
                    .max()
                    .unwrap_or(0)
            }
            _ => 0,
        }
    }

    /// A plain-text (no-ANSI) rendering of this spec — the fallback used by any [`ReplOutput`] that
    /// does not override `render_widget` (FR-024 / US6 AS-5). Always non-blank.
    pub fn to_ascii(&self) -> String {
        match self {
            RenderSpec::BarChart { title, bars, .. } => {
                let mut s = format!("{title}\n");
                let max = bars.iter().map(|b| b.value).max().unwrap_or(1).max(1);
                for b in bars {
                    let filled = ((b.value.max(0) as f64 / max as f64) * 20.0) as usize;
                    s.push_str(&format!(
                        "  {:<12} {} {}\n",
                        b.label,
                        "#".repeat(filled),
                        b.value
                    ));
                }
                s
            }
            RenderSpec::LineChart { title, series }
            | RenderSpec::ScatterPlot { title, series, .. }
            | RenderSpec::AreaChart { title, series, .. } => {
                let mut s = format!("{title}\n");
                for ser in series {
                    s.push_str(&format!("  {} ({} points)\n", ser.label, ser.points.len()));
                }
                s
            }
            RenderSpec::Heatmap { title, rows, .. } => {
                let mut s = format!("{title}\n");
                for r in rows {
                    s.push_str(&format!("  {}: {:?}\n", r.label, r.values));
                }
                s
            }
            RenderSpec::Sparkline { title, data } => {
                format!("{title}\n  {data:?}\n")
            }
            RenderSpec::LogTail { title, lines, .. } => {
                let mut s = format!("{title}\n");
                for l in lines {
                    match &l.level {
                        Some(lv) => s.push_str(&format!("  [{lv}] {}\n", l.text)),
                        None => s.push_str(&format!("  {}\n", l.text)),
                    }
                }
                s
            }
            RenderSpec::Table {
                title,
                headers,
                rows,
            } => {
                let mut s = format!("{title}\n  {}\n", headers.join(" | "));
                for r in rows {
                    s.push_str(&format!("  {}\n", r.cells.join(" | ")));
                }
                s
            }
            RenderSpec::Gauge {
                title,
                value,
                label,
                ..
            } => {
                let pct = label
                    .clone()
                    .unwrap_or_else(|| format!("{:.0}%", value * 100.0));
                format!("{title}: {pct}\n")
            }
            RenderSpec::DotGrid { title, dots } => {
                let mut s = format!("{title}\n  ");
                for d in dots {
                    s.push(match d.state {
                        DotState::Pass => 'P',
                        DotState::Fail => 'F',
                        DotState::Skip => '-',
                    });
                    s.push(' ');
                }
                s.push('\n');
                s
            }
            RenderSpec::Text { content, .. } => format!("{content}\n"),
            // Markdown source *is* the plain-text form — that is the point of markdown — so the
            // ASCII fallback prints it as written rather than stripping anything.
            RenderSpec::Markdown { content } => format!("{content}\n"),
            RenderSpec::AsciiArt { lines } => format!("{}\n", lines.join("\n")),
            RenderSpec::Separator => "----\n".to_string(),
            RenderSpec::Layout { children, .. } => children
                .iter()
                .map(|c| c.to_ascii())
                .collect::<Vec<_>>()
                .join("\n"),
            RenderSpec::Sprite { spec } => format!("[sprite {}×{}]\n", spec.width, spec.height),
            RenderSpec::Animation { spec } => {
                format!("[animation: {} frames]\n", spec.frames.len())
            }
            RenderSpec::Grid {
                rows, cols, cells, ..
            } => {
                let mut s = format!("[grid {rows}×{cols}]\n");
                for c in cells {
                    s.push_str(&format!("  ({},{}) {}", c.row, c.col, c.content.to_ascii()));
                }
                s
            }
        }
    }

    /// A short human-readable label for the tool summary (contracts/render-tool.md).
    pub fn summary_noun(&self) -> String {
        match self {
            RenderSpec::BarChart { title, bars, .. } => {
                format!("a bar chart {title:?} with {} bars", bars.len())
            }
            RenderSpec::LineChart { title, series } => {
                format!("a line chart {title:?} with {} series", series.len())
            }
            RenderSpec::ScatterPlot { title, series, .. } => {
                format!("a scatter plot {title:?} with {} series", series.len())
            }
            RenderSpec::AreaChart { title, series, .. } => {
                format!("an area chart {title:?} with {} series", series.len())
            }
            RenderSpec::Heatmap { title, rows, .. } => {
                let cols = rows.first().map_or(0, |r| r.values.len());
                format!("a heatmap {title:?} ({}×{})", rows.len(), cols)
            }
            RenderSpec::Sparkline { title, data } => {
                format!("a sparkline {title:?} with {} points", data.len())
            }
            RenderSpec::LogTail { title, lines, .. } => {
                format!("a log tail {title:?} with {} lines", lines.len())
            }
            RenderSpec::Table {
                title,
                headers,
                rows,
            } => {
                format!(
                    "a {}-column table {title:?} with {} rows",
                    headers.len(),
                    rows.len()
                )
            }
            RenderSpec::Gauge { title, value, .. } => {
                format!("a gauge {title:?} at {:.0}%", value * 100.0)
            }
            RenderSpec::DotGrid { title, dots } => {
                format!("a dot grid {title:?} with {} dots", dots.len())
            }
            RenderSpec::Text { .. } => "a text block".to_string(),
            RenderSpec::Markdown { .. } => "a markdown block".to_string(),
            RenderSpec::AsciiArt { lines } => format!("ASCII art ({} lines)", lines.len()),
            RenderSpec::Separator => "a separator".to_string(),
            RenderSpec::Layout {
                direction,
                children,
            } => {
                let dir = match direction {
                    Direction::Vertical => "vsplit",
                    Direction::Horizontal => "hsplit",
                };
                format!("a {dir} layout ({} widgets)", children.len())
            }
            RenderSpec::Sprite { spec } => format!("a {}×{} sprite", spec.width, spec.height),
            RenderSpec::Animation { spec } => {
                format!("a {}-frame animation", spec.frames.len())
            }
            RenderSpec::Grid {
                rows, cols, cells, ..
            } => {
                format!("a {rows}×{cols} grid with {} cells", cells.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_target_serde_roundtrips() {
        // Default is Inline (008-grid-tui); Panel carries its id. Both survive a serde round-trip.
        assert_eq!(RenderTarget::default(), RenderTarget::Inline);
        for t in [
            RenderTarget::Inline,
            RenderTarget::Panel {
                id: "metrics".into(),
            },
        ] {
            let json = serde_json::to_string(&t).expect("serialize");
            let back: RenderTarget = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(t, back);
        }
    }
}
