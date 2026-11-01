# Feature Specification: bee Visual Rendering & Design Language

> Runtime update: Rhai has been replaced by Monty Python. The original syntax below is historical; use [the Python API](../../docs/python-visuals.md) and the `.py` examples in this directory.

**Feature Branch**: `003-visual-render`

**Created**: 2026-07-20

**Status**: Draft

**Depends on**: `002-llm-harness` (the tool trait, registry, `ReplOutput`, `ToolResult`, `TerminalOutput`, and the REPL exchange loop)

**Input**: "Build a visual rendering layer for the harness so the agent can declare its own views — charts, graphs, status grids, ASCII art — via a Rhai scripting sandbox, rendered inline through ratatui's `Buffer` into the existing rustyline output path. The rendering API doubles as the project's visual design language: a shared glyph vocabulary, palette, and layout primitives used by both the agent's `render` tool and bee's own chrome (banners, spinners, pass/fail indicators, episode summaries)."

---

## Overview

The bee harness today renders everything as flat text: tool results dump stdout, the REPL prints
ANSI-colored lines through rustyline's `ExternalPrinter`, and pass/fail outcomes are bare strings in
a JSON transcript. There is no visual identity — no shared palette, no glyph vocabulary, no
structural rendering beyond word wrap and indentation.

This feature adds two things at once, because they share the same substrate:

1. **A `render` tool** that lets the LLM agent declare visualizations by writing Rhai scripts against
   a registered rendering API. The agent can generate bar charts, tables, sparklines, gauges, status
   grids, tree views, and composed layouts — all sandboxed by Rhai's built-in resource limits and the
   fact that only drawing primitives are registered (no I/O, no FFI, no network). The rendered output
   appears inline in the REPL scrollback as ANSI art, word-wrapped exactly like tool output. The model
   sees a text summary, not the rendered pixels.

2. **A project-wide visual design language** (`bee_harness::viz`) that codifies the palette, glyphs,
   layout primitives, and status indicators the entire project uses. The REPL chrome (banners, the
   spinner, tool call/result rendering, exchange footers, pass/fail grids in batch output) migrates to
   this vocabulary. The agent's rendering API is a superset of the same primitives — `viz` is the
   foundation, the `render` tool exposes it to the model via Rhai.

The design language has a name: **honeycomb**. Because bee.

---

## Motivation

### Why Rhai, not a fixed JSON schema

A declarative JSON enum (`{ "kind": "bar_chart", "data": [...] }`) gives the agent a fixed menu of
chart types. Every new visualization means a new Rust enum variant, a schema update, recompile,
redeploy. The agent is a slot-filler, not an author.

Rhai gives the agent an authoring surface with a controlled blast radius. The agent writes a short
script that calls registered functions — it can sort, filter, compute derived values, conditionally
format, compose layouts — but the only side effects the script can produce are calls to the drawing
API. This is closer to how Claude generates React components: the model writes rendering logic, not
just data.

Rhai's safety properties make this viable:

- **No I/O**: no filesystem, no network, no FFI — nothing exists unless `register_fn` exposes it.
- **Don't-Panic guarantee**: Rhai will not bring down the host process.
- **Hard resource limits**: max operations, max call depth, max string/array/map size, max expression
  nesting depth — all configurable, all enforced at the engine level.
- **Pure Rust**: no C deps, no unsafe (passes Miri), no runtime.

The `render` tool does **not** run in the cgroup sandbox. It runs Rhai in the harness process.
Rhai's own sandbox is the confinement boundary for rendering; the kernel sandbox confines tool
children that touch the filesystem and network. Two sandboxes, two threat models, cleanly layered.

### Why ratatui, not raw ANSI

ratatui widgets (`BarChart`, `Table`, `Sparkline`, `Gauge`, `LineChart`, `Paragraph`, `Block`) are
mature, correct, and handle Unicode width, color, and layout math. Writing the same rendering by hand
in ANSI escapes is a mistake factory. ratatui can render to a headless `Buffer` without a terminal
backend — no alt-screen, no raw mode, no crossterm, no fight with rustyline. The buffer is converted
row-by-row to ANSI-escaped strings and emitted through the existing `ExternalPrinter` path.

---

## Design Language: honeycomb

### Palette

Six semantic colors, expressed as ANSI SGR codes (inline escapes, no color crate — consistent with
the existing `terminal.rs` approach). Suppressed when `NO_COLOR` is set.

| Name        | SGR code | Hex (for docs/web) | Used for |
|-------------|----------|---------------------|----------|
| `honey`     | `33` (yellow) | `#E5A100` | Info, banners, the bee identity |
| `pollen`    | `32` (green)  | `#5FAF5F` | Success, pass, allowed, ✓ |
| `sting`     | `31` (red)    | `#D75F5F` | Error, fail, denied, ✗ |
| `smoke`     | `2` (dim)     | `#808080` | Dim/secondary: footers, metadata, tool args |
| `royal`     | `36` (cyan)   | `#5FAFAF` | Accent: steering messages, highlights, links |
| `comb`      | `0` (reset)   | `#D4D4D4` | Default text (terminal fg) |

Bold variants via `1;{code}` for emphasis: bold red for `⚠ DENIED`, bold yellow for banners.

### Glyph vocabulary

Every glyph in the project's terminal output is drawn from this set. Nothing ad-hoc.

| Glyph | Unicode | Name | Meaning |
|-------|---------|------|---------|
| `●`   | U+25CF  | `dot_pass` | Pass / success / green state |
| `●`   | U+25CF  | `dot_fail` | Fail / error / red state (same glyph, different color) |
| `○`   | U+25CB  | `dot_skip` | Skipped / pending / neutral |
| `▸`   | U+25B8  | `arrow` | Tool call indicator (existing) |
| `✓`   | U+2713  | `check` | Successful tool result (existing) |
| `✗`   | U+2717  | `cross` | Error tool result (existing) |
| `⚠`   | U+26A0  | `warn` | Kernel denial / warning (existing) |
| `⬡`   | U+2B21  | `hex` | The bee/honeycomb identity glyph |
| `─`   | U+2500  | `hline` | Horizontal rule / separator |
| `│`   | U+2502  | `vline` | Vertical separator |
| `┌┐└┘` | box drawing | `corners` | Box frame (matches ratatui `Borders`) |

The spinner frames remain the existing braille set (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`).

### The bee

An optional ASCII art bee rendered on REPL startup (behind a `--bee` flag or an env var, not forced
on people who find it annoying). Small enough to fit in the space the current single-line banner
uses — 3-4 lines max.

```text
    \  /
     ⬡
    /  \   bee v0.1.0 · anthropic/claude-sonnet-4-6 · enforce
```

Or, for the nerds:

```text
  \_/
  (⬡)  bee v0.1.0 · interactive session
  / \
```

The exact art is bikeshed. The spec constrains it to: max 4 lines, ASCII + the hex glyph, no
mandatory display.

### Status grid

A compact pass/fail indicator for batch and episode results. Each cell is a colored dot:

```text
  read-denied-ssh     ● ● ● ○    3/4 pass
  write-allowed       ● ● ● ●    4/4 pass
  ctf-suid-escape     ✗ ● ○ ○    1/4 pass
```

The grid primitive is available in both the `viz` module (for the harness's own batch output) and
the Rhai rendering API (so the agent can render test results the same way).

### Layout

Two structural primitives for composed views:

- **`vsplit`** — vertical stack (widgets rendered top to bottom, separated by a blank line)
- **`hsplit`** — horizontal split (widgets rendered side by side, columns separated by `│`)

These map to ratatui's `Layout` with `Direction::Vertical` / `Direction::Horizontal`. Max nesting
depth: 3 (enforced by the Rhai API, not just Rhai's expression depth limit).

---

## User Scenarios & Testing

### User Story 6 — Agent-Declared Visualization (Priority: P2)

During a REPL session, the agent calls the `render` tool with a Rhai script that builds a
visualization from data it gathered via earlier tool calls. The harness evaluates the script in Rhai's
sandbox (in-process, not in the cgroup), renders the result to a ratatui `Buffer`, converts the
buffer to ANSI lines, and emits them inline in the REPL scrollback. The model receives a text summary
of what was rendered (e.g., "Rendered a bar chart with 5 bars titled 'File Sizes'"), not the ANSI art,
so the model's context window is not polluted with visual noise.

**Why this priority**: P2 because it depends on US1/US5 (the REPL and tool infrastructure) being
stable, but is self-contained — it adds one tool, one Rhai engine, one `ReplOutput` method, and
touches nothing in the enforcement path.

**Independent Test**: Run a REPL exchange (via `run_exchange` with a `MockModel`) where the model
calls `render` with a Rhai script that builds a bar chart. Verify that (a) the `ReplOutput` receives
a `render_widget` call with a valid `RenderSpec`, (b) the `ToolResult.content` returned to the model
is a text summary (not ANSI), and (c) the Rhai engine rejects a script that exceeds the operation
limit.

**Acceptance Scenarios**:

1. **Given** a Rhai script that builds a 5-bar chart via `bar_chart()` + `chart.bar(label, value)`,
   **When** the `render` tool executes it, **Then** the `RenderSpec` contains 5 bars with the correct
   labels and values, and the text summary returned to the model mentions the chart title and bar
   count.
2. **Given** a Rhai script that attempts an infinite loop (`loop { }`), **When** the `render` tool
   executes it, **Then** Rhai terminates the script with an `ErrorTerminated` after hitting
   `max_operations`, and the tool returns `is_error: true` with a message mentioning the limit.
3. **Given** a Rhai script that calls an unregistered function (e.g., `std::fs::read`), **When** the
   `render` tool executes it, **Then** the script fails with a "function not found" error and the
   tool returns `is_error: true`.
4. **Given** a Rhai script that builds a `vsplit` containing a gauge and a table, **When** rendered to
   a `Buffer`, **Then** the buffer's height equals the gauge's height plus a separator plus the
   table's height, and both widgets are full-width.
5. **Given** a `ReplOutput` that does not override `render_widget` (e.g., the test `Collector`),
   **When** a `RenderSpec` is produced, **Then** the default implementation emits a plain-text ASCII
   fallback (a text table, not a blank).

---

### User Story 7 — Unified Visual Chrome (Priority: P3)

The REPL's existing terminal output (banners, tool call/result rendering, exchange footers, the
spinner, audit denial callouts) migrates from ad-hoc inline ANSI escapes to the `viz` module's
palette and glyph constants. Batch episode output gains a status grid. The visual identity is
consistent across every surface that emits to a terminal.

**Why this priority**: P3 because it is a refactor of existing rendering with no new functionality
(except the status grid for batch output). It can be done incrementally — one rendering site at a
time — without breaking tests or the existing output contract.

**Independent Test**: Run the existing `TerminalOutput` tests after the migration. All assertions on
rendered text pass unchanged (the glyphs and colors are the same, just sourced from `viz` constants
instead of inline literals). Additionally, run the new status-grid unit test: given 4 episode results
(3 pass, 1 fail), the rendered grid contains 3 green dots and 1 red dot.

**Acceptance Scenarios**:

1. **Given** the existing `TerminalOutput` test suite, **When** the color/glyph constants are
   replaced with `viz::palette` and `viz::glyph` references, **Then** all tests pass without
   assertion changes.
2. **Given** a batch of 4 episode transcripts (3 `Completed`, 1 `Timeout`), **When** rendered as a
   status grid, **Then** the output contains 3 `●` in green and 1 `●` in red, with scenario names
   left-aligned and a summary fraction right-aligned.
3. **Given** `NO_COLOR=1` in the environment, **When** any `viz` rendering function is called,
   **Then** no ANSI escape sequences appear in the output (glyphs are still present, colors are not).

---

### Edge Cases

- **Rhai script produces no render calls**: The script runs, produces no widget (e.g., `let x = 1;`).
  The tool returns `is_error: true` with "script produced no visualization".
- **Rhai script calls `render()` multiple times**: Only the last call's widget is used; the tool
  returns a warning in the summary noting that earlier renders were discarded.
- **Very wide chart data**: A bar chart with 200 bars at terminal width 80 is unreadable. The Rhai
  API caps rendered width to the terminal width (or a configurable max, default 100 columns) and
  height to a configurable max (default 30 rows). Data exceeding the visual capacity is elided with
  a note.
- **Unicode in labels**: ratatui handles Unicode width correctly; the Rhai `String` type is UTF-8.
  Labels with CJK characters or emoji will render at their correct display width.
- **Terminal width unknown**: When stdout is not a tty (piped output, CI), the renderer falls back to
  80 columns and suppresses color (as if `NO_COLOR` were set). Sprites degrade to a monochrome
  block-character rendering (█ for opaque pixels, space for transparent).
- **No truecolor support**: If `COLORTERM` is not `truecolor` or `24bit`, the half-block renderer
  quantizes sprite colors to the 256-color palette (find nearest in the xterm-256 cube). If the
  terminal supports only 16 colors, quantize further. The sprite is recognizable but not pretty.
- **Animation during a tool call**: If the agent renders an animation and then makes another tool
  call in the same turn, the animation is stopped (same as the spinner) and its rows are reclaimed
  before the tool result is printed. No visual artifact.
- **Very fast animation**: Frame intervals below 50ms are clamped to 50ms to avoid hammering the
  terminal with redraws. Intervals above 1000ms are clamped to 1000ms.
- **All-transparent sprite**: A sprite with no opaque pixels renders as blank space (height/2 rows
  of spaces). The tool result summary notes "sprite is fully transparent."
- **Rhai engine construction cost**: The `Engine` is built once per REPL session (or once per harness
  invocation), not per tool call. Function registration happens at construction. Per-call cost is
  just `eval_with_scope`.

---

## Requirements

### Functional Requirements

- **FR-019**: The harness MUST provide a `render` tool that accepts a `{ "script": string }` argument
  containing a Rhai script, evaluates it against a registered rendering API, and returns a
  `ToolResult` whose `content` is a text summary of the rendered visualization.
- **FR-020**: The Rhai engine used by the `render` tool MUST be configured with hard resource limits:
  max operations (default 10,000), max call levels (default 16), max expression depth (default 32
  global / 16 in functions), max string size (default 64 KB), max array size (default 1,000), max
  map size (default 100). These limits MUST be non-negotiable by the script.
- **FR-021**: The Rhai engine MUST NOT expose any I/O, filesystem, network, FFI, or process-control
  functions. Only the rendering API functions listed in the Rendering API section below are
  registered. The `eval` keyword MUST be disabled.
- **FR-022**: The `render` tool MUST NOT execute inside the cgroup sandbox (`Sandbox`). It runs
  Rhai in the harness process. The `sandbox` parameter to `Tool::call` is ignored.
- **FR-023**: The `ToolResult` produced by the `render` tool MUST carry a `RenderSpec` (a new
  optional field) that the `ReplOutput` implementation can use to render the visualization. The
  `content` field (the text sent to the model) MUST be a human-readable summary, not the rendered
  ANSI output.
- **FR-024**: The `ReplOutput` trait MUST gain a `render_widget(&self, spec: &RenderSpec)` method
  with a default implementation that emits a plain-text ASCII fallback.
- **FR-025**: `TerminalOutput` MUST implement `render_widget` by rendering the `RenderSpec` to a
  ratatui `Buffer` (headless, no terminal backend), converting each buffer row to an ANSI-escaped
  string, and emitting it through the existing `ExternalPrinter`.
- **FR-026**: The `viz` module MUST define the honeycomb palette, glyph vocabulary, and status-grid
  renderer as public constants and functions usable by any crate in the workspace.
- **FR-027**: The existing `TerminalOutput` MUST migrate its inline ANSI escape literals and glyph
  characters to `viz` module references. No behavioral change; only the source of the constants
  changes.

- **FR-028**: The Rhai rendering API MUST support a `sprite(w, h, palette)` constructor and a
  `sprite.paint(rows)` method that accepts an array of strings where each character maps to a palette
  color. Max sprite dimensions: 32×32 pixels. Unknown palette characters MUST be treated as
  transparent.
- **FR-029**: The Rhai rendering API MUST support an `animation(ms)` constructor that accepts a
  frame interval (clamped to 50–1000ms), with `anim.add(sprite)` for appending frames (max 16),
  `anim.bounce(bool)` for ping-pong playback, and `anim.cycles(n)` for loop count.
- **FR-030**: `TerminalOutput` MUST render sprites using the half-block technique (`▄` U+2584 with
  truecolor fg/bg ANSI escapes), producing `height/2` terminal rows per frame. Static sprites are
  emitted inline. Animated sprites are rendered via a background tokio task using the same
  cursor-rewrite mechanism as the spinner (`\x1b[{N}A` + clear + redraw), with the `reclaim` flag
  set on completion so subsequent output overwrites the sprite rows.
- **FR-031**: Only one animated element (sprite animation or spinner) MAY be active at a time.
  Starting a new animation MUST stop any running spinner or prior animation.
- **FR-032**: The `viz::bee` module MUST provide a built-in 16×16 bee sprite and a 3-frame wing-flap
  animation as constants, available both to the harness chrome and to the Rhai API via `bee_sprite()`
  and `bee_animation()`.

### Non-Functional Requirements

- **NFR-001**: Rhai script evaluation MUST complete within 50ms for a script of up to 10,000
  operations. The rendering path (Buffer → ANSI lines) MUST complete within 10ms for a 100×30
  buffer. Neither path blocks the tokio runtime (both are synchronous and fast).
- **NFR-002**: The `rhai` and `ratatui` dependencies MUST NOT propagate to `bee-core` or
  `bee-common`. They are confined to `bee-harness`.
- **NFR-003**: The `render` tool MUST be opt-in per scenario (listed in the scenario's `tools`
  array). It is NOT in the `DEFAULT_TOOLS` set — an agent only gets it when the scenario or REPL
  config enables it.

---

## Rendering API (Rhai-registered functions)

All functions below are registered on the Rhai `Engine` at construction. They operate on opaque Rust
types (`ChartBuilder`, `TableBuilder`, `LayoutBuilder`, etc.) exposed to Rhai as custom types with
getters, setters, and methods.

### Charts

| Function | Signature (Rhai) | Description |
|----------|-----------------|-------------|
| `bar_chart(title)` | `fn(String) -> Chart` | Create a bar chart builder. |
| `chart.bar(label, value)` | `fn(&mut Chart, String, i64)` | Add a bar. |
| `chart.x_label(s)` | `fn(&mut Chart, String)` | Set x-axis label. |
| `chart.y_label(s)` | `fn(&mut Chart, String)` | Set y-axis label. |
| `chart.color(name)` | `fn(&mut Chart, String)` | Set bar color (palette name or basic ANSI name). |
| `line_chart(title)` | `fn(String) -> Chart` | Create a line chart builder. |
| `chart.series(label)` | `fn(&mut Chart, String) -> Series` | Add a named series. |
| `series.point(x, y)` | `fn(&mut Series, f64, f64)` | Add a data point. |
| `sparkline(title, data)` | `fn(String, Array) -> Spark` | Create a sparkline from an array of integers. |

### Tables

| Function | Signature (Rhai) | Description |
|----------|-----------------|-------------|
| `table(title)` | `fn(String) -> Table` | Create a table builder. |
| `table.header(cols)` | `fn(&mut Table, Array)` | Set column headers (array of strings). |
| `table.row(cells)` | `fn(&mut Table, Array)` | Add a row (array of strings). |
| `table.row_colored(cells, color)` | `fn(&mut Table, Array, String)` | Add a row with a color. |

### Status & Indicators

| Function | Signature (Rhai) | Description |
|----------|-----------------|-------------|
| `gauge(title, value)` | `fn(String, f64) -> Gauge` | A 0.0–1.0 progress gauge. |
| `gauge.label(s)` | `fn(&mut Gauge, String)` | Override the percentage label. |
| `gauge.color(name)` | `fn(&mut Gauge, String)` | Set fill color. |
| `dots(title)` | `fn(String) -> DotGrid` | A pass/fail dot grid. |
| `dots.pass(label)` | `fn(&mut DotGrid, String)` | Add a green dot with label. |
| `dots.fail(label)` | `fn(&mut DotGrid, String)` | Add a red dot with label. |
| `dots.skip(label)` | `fn(&mut DotGrid, String)` | Add a neutral dot with label. |

### Decorative / Identity

| Function | Signature (Rhai) | Description |
|----------|-----------------|-------------|
| `text(content)` | `fn(String) -> Text` | A styled text block (ratatui `Paragraph`). |
| `text.style(name)` | `fn(&mut Text, String)` | Apply a palette color. |
| `text.bold()` | `fn(&mut Text)` | Bold modifier. |
| `text.dim()` | `fn(&mut Text)` | Dim modifier. |
| `ascii_art(lines)` | `fn(Array) -> Art` | Render an array of strings as fixed-width art (no wrapping). |
| `separator()` | `fn() -> Sep` | A horizontal rule (`─` repeated to width). |

### Sprites & Animation

The agent (and the project's own chrome) can define 16×16 pixel-art sprites rendered via the
half-block technique: Unicode `▄` (U+2584) with truecolor ANSI (`\x1b[38;2;R;G;Bm` fg,
`\x1b[48;2;R;G;Bm` bg), packing two vertical pixels into one terminal cell. A 16×16 sprite
occupies 16 columns × 8 terminal rows — small enough to sit inline in the scrollback.

Sprites are painted from a bitmap string where each character maps to a palette entry. The format
is deliberately LLM-friendly: a visual grid the model can "see" and edit, not a binary blob.

```rhai
let pal = palette();
pal.set(".", "transparent");
pal.set("K", "#1A1A1A");     // black (body outline)
pal.set("Y", "#E5A100");     // yellow (body)
pal.set("W", "#FFFFFF");     // white (wings)
pal.set("B", "#4A90D9");     // blue (wing tint)
pal.set("R", "#D75F5F");     // red (sting tip)

let bee = sprite(16, 16, pal);
bee.paint([
    "......KK........",
    "....KKWWKK......",
    "...KWWBBWWK.....",
    "...KWBWWBWK.....",
    "..KKWWWWWWKK....",
    "..KYYYYYYYYYK...",
    ".KYYYYKYYYYYK...",
    ".KYYYKKYYKK.K...",
    ".KYYYYYYYYYK....",
    "..KYYYYYYKK.....",
    "..KKYYYYKK......",
    "...KYYYYK.......",
    "....KKKK........",
    "......KK........",
    ".....KRRK.......",
    "......KK........",
]);

render(bee);
```

#### Animation

Multiple frames at a specified interval, rendered in-place using the same cursor-rewrite mechanism
as the existing REPL spinner (`\x1b[{N}A` to move up N rows, clear and redraw). A background tokio
task advances frames; the `reclaim` logic from the spinner handles cleanup when real output arrives.

```rhai
let pal = palette();
pal.set(".", "transparent");
pal.set("K", "#1A1A1A");
pal.set("Y", "#E5A100");
pal.set("W", "#FFFFFF");

// Wing-flap animation: 3 frames, 150ms each
let frame1 = sprite(16, 16, pal);
frame1.paint([
    "......KK........",
    "....KKWWKK......",     // wings up
    "...KWWWWWWK.....",
    "..KYYYYYYYYYK...",
    // ... body ...
]);

let frame2 = sprite(16, 16, pal);
frame2.paint([
    "................",
    "......KK........",
    "...KWWKKWWK.....",     // wings mid
    "..KYYYYYYYYYK...",
    // ... body ...
]);

let frame3 = sprite(16, 16, pal);
frame3.paint([
    "................",
    "......KK........",
    "....KK..KK......",     // wings down
    "..KYYYYYYYYYK...",
    // ... body ...
]);

let anim = animation(150);   // ms per frame
anim.add(frame1);
anim.add(frame2);
anim.add(frame3);
anim.bounce(true);           // play forward then reverse (1-2-3-2-1-2-3-…)
anim.cycles(3);              // play 3 full cycles then stop (0 = infinite until interrupted)

render(anim);
```

| Function | Signature (Rhai) | Description |
|----------|-----------------|-------------|
| `palette()` | `fn() -> Palette` | Create an empty color palette. |
| `pal.set(char, color)` | `fn(&mut Palette, String, String)` | Map a single character to a hex color or `"transparent"`. |
| `sprite(w, h, pal)` | `fn(i64, i64, Palette) -> Sprite` | Create a sprite canvas. Max 32×32. |
| `sprite.paint(rows)` | `fn(&mut Sprite, Array)` | Paint from an array of strings (one per pixel row). Each character is looked up in the palette. Unknown characters → transparent. |
| `sprite.set(x, y, color)` | `fn(&mut Sprite, i64, i64, String)` | Set one pixel by hex color. |
| `sprite.fill(color)` | `fn(&mut Sprite, String)` | Fill the entire canvas. |
| `animation(ms)` | `fn(i64) -> Animation` | Create an animation with the given frame interval (min 50ms, max 1000ms). |
| `anim.add(sprite)` | `fn(&mut Animation, Sprite)` | Append a frame. Max 16 frames. |
| `anim.bounce(b)` | `fn(&mut Animation, bool)` | Ping-pong playback (default false). |
| `anim.cycles(n)` | `fn(&mut Animation, i64)` | Number of full cycles (0 = loop until next output, default 1). |

#### Rendering pipeline

```text
  Rhai script
      │
      ▼
  SpriteSpec { width, height, frames: Vec<Vec<Option<(u8,u8,u8)>>> }
      │
      ▼
  half_block_render(frame) → Vec<String>     ← one ANSI string per terminal row
      │                                         (height/2 rows, each with fg+bg
      │                                          truecolor escapes per column)
      ▼
  ┌─ static (1 frame) ──→ emit lines via ExternalPrinter (inline in scrollback)
  │
  └─ animated (N frames) ──→ emit first frame, then spawn a tokio task that:
                               • sleeps frame_interval
                               • prints \x1b[{H}A (cursor up H rows)
                               • redraws all H lines with the next frame
                               • stops after `cycles` iterations or when
                                 `spinning` flag is cleared (same as spinner)
                               • sets `reclaim` so next real output
                                 overwrites the sprite rows in place
```

#### Constraints

- Max sprite dimensions: 32×32 pixels (16 columns × 16 terminal rows in half-blocks). The default
  and recommended size is 16×16 (16 cols × 8 rows).
- Max frames per animation: 16.
- Frame interval: 50ms–1000ms (enforced by the API function, not Rhai limits).
- Max palette entries: 32 colors.
- Transparent pixels: rendered as the terminal's default background (no bg escape emitted for that
  cell's half; if both halves are transparent, emit a space with no color).
- Truecolor required: if the terminal does not support truecolor (`COLORTERM != "truecolor"` and
  `COLORTERM != "24bit"`), the renderer quantizes to the 256-color palette. If even that is missing,
  it falls back to the 16 basic ANSI colors. Sprite quality degrades but nothing breaks.
- The animation task is the same architectural pattern as the spinner: a shared `AtomicBool` flag,
  a `JoinHandle`, and the `reclaim` mechanism for cleaning up drawn rows. Only one animation OR
  spinner can be active at a time (starting an animation stops a running spinner, and vice versa).

#### The project bee

The honeycomb design language includes a built-in 16×16 bee sprite and a 3-frame wing-flap animation,
defined as constants in `viz::bee`. These are used by:

- **REPL startup banner** (opt-in via `--bee` or `BEE_MASCOT=1`): the animated bee plays once beside
  the session info line, then the rows are reclaimed.
- **Episode completion**: a static bee is rendered beside the final status line for completed
  episodes (a small reward for patience).
- **The agent**: the bee sprite and animation are available in the Rhai API as `bee_sprite()` and
  `bee_animation()` — the agent can include the project mascot in its visualizations.

The bee is not forced on anyone. It is opt-in in the REPL, absent in batch mode, and available but
not default in the Rhai API.

### Layout & Composition

| Function | Signature (Rhai) | Description |
|----------|-----------------|-------------|
| `vsplit()` | `fn() -> Layout` | Vertical stack. |
| `hsplit()` | `fn() -> Layout` | Horizontal columns. |
| `layout.add(widget)` | `fn(&mut Layout, Dynamic)` | Add any widget to the layout. |
| `render(widget)` | `fn(Dynamic)` | Commit the widget for display. |

### Constraints (enforced by the API, not Rhai limits)

- Max layout nesting depth: 3.
- Max total bars/rows/points across all widgets in one script: 500.
- Max rendered width: 120 columns (or terminal width, whichever is smaller).
- Max rendered height: 40 rows.
- Exceeding any constraint returns an error from the registered function, which Rhai surfaces as a
  script error → `ToolResult::error`.

---

## Key Entities

### `RenderSpec` (enum, serde)

The validated, renderable output of a Rhai script. Produced by the `render` tool, consumed by
`ReplOutput::render_widget`. Variants mirror the Rhai API surface:

```text
BarChart { title, bars: Vec<Bar>, x_label, y_label, color }
LineChart { title, series: Vec<Series> }
Sparkline { title, data: Vec<u64> }
Table { title, headers: Vec<String>, rows: Vec<Row> }
Gauge { title, value: f64, label, color }
DotGrid { title, dots: Vec<Dot> }
Text { content, style }
AsciiArt { lines: Vec<String> }
Sprite { spec: SpriteSpec }
Animation { spec: AnimationSpec }
Separator
Layout { direction: Direction, children: Vec<RenderSpec> }
```

`RenderSpec` is serializable (serde) so it can be recorded in episode transcripts (the spec itself,
not the rendered pixels). A future web viewer or analysis tool can re-render from the spec.

### `SpriteSpec` (struct, serde, nested in `RenderSpec::Sprite`)

A pixel grid with an associated palette.

```text
SpriteSpec {
    width: u16,                              // pixel columns (max 32)
    height: u16,                             // pixel rows (max 32)
    pixels: Vec<Option<(u8, u8, u8)>>,       // row-major RGBA (None = transparent)
}
```

### `AnimationSpec` (struct, serde, nested in `RenderSpec::Animation`)

A sequence of sprite frames with playback parameters.

```text
AnimationSpec {
    frames: Vec<SpriteSpec>,                 // 1–16 frames, all same dimensions
    interval_ms: u64,                        // per-frame duration (50–1000)
    bounce: bool,                            // ping-pong playback
    cycles: u32,                             // 0 = loop until interrupted
}
```

### `RenderContext` (Rhai evaluation context)

A `Clone`-able, `Send`-able context pushed into the Rhai `Scope` before evaluation. Accumulates
the widget tree as the script runs. After evaluation, `ctx.take()` extracts the `RenderSpec`.

### `viz` module (`bee_harness::viz`)

The project's visual vocabulary. Public API:

```rust
pub mod palette {
    pub const HONEY: &str = "33";     // yellow — info, identity
    pub const POLLEN: &str = "32";    // green — success
    pub const STING: &str = "31";     // red — error
    pub const SMOKE: &str = "2";      // dim — secondary
    pub const ROYAL: &str = "36";     // cyan — accent
    pub fn paint(code: &str, text: &str) -> String;   // wraps in SGR if color enabled
    pub fn bold(code: &str, text: &str) -> String;    // bold variant
    pub fn is_color_enabled() -> bool;                // checks NO_COLOR
}

pub mod glyph {
    pub const DOT_PASS: &str = "●";    // U+25CF, colored pollen
    pub const DOT_FAIL: &str = "●";    // U+25CF, colored sting
    pub const DOT_SKIP: &str = "○";    // U+25CB, colored smoke
    pub const ARROW: &str = "▸";       // tool call
    pub const CHECK: &str = "✓";       // success result
    pub const CROSS: &str = "✗";       // error result
    pub const WARN: &str = "⚠";        // denial
    pub const HEX: &str = "⬡";         // bee identity
    pub const HLINE: &str = "─";       // horizontal rule
}

pub fn status_grid(results: &[(String, Status)]) -> String;  // renders the dot grid
pub fn render_to_ansi(spec: &RenderSpec, max_width: u16, max_height: u16) -> Vec<String>;

pub mod sprite {
    pub fn render_frame(spec: &SpriteSpec) -> Vec<String>;    // one frame → half-block ANSI lines
    pub fn quantize_256(r: u8, g: u8, b: u8) -> u8;          // truecolor → xterm-256 nearest
    pub fn quantize_16(r: u8, g: u8, b: u8) -> u8;           // truecolor → basic ANSI nearest
    pub enum ColorMode { TrueColor, Ansi256, Ansi16 }
    pub fn detect_color_mode() -> ColorMode;                  // checks COLORTERM env
}

pub mod bee {
    pub fn sprite() -> SpriteSpec;                            // the 16×16 bee
    pub fn animation() -> AnimationSpec;                      // 3-frame wing-flap, 150ms, bounce
}
```

---

## Architecture

### Where the `render` tool sits in the existing stack

```text
                    ┌──────────────────────────────────────────────────┐
                    │  Model (Claude / GPT / Mock)                    │
                    │  ToolCall { name: "render", args: { script } }  │
                    └───────────────────┬──────────────────────────────┘
                                        │
                    ┌───────────────────▼──────────────────────────────┐
                    │  ToolRegistry::execute                           │
                    │  ├─ bash, read_file, write_file  → Sandbox      │
                    │  └─ render                       → Rhai (⬡)     │
                    └───────────────────┬──────────────────────────────┘
                                        │
              ┌─────────────────────────┼──────────────────────────────┐
              │ render tool (in-process)│                              │
              │                        ▼                              │
              │  ┌─────────────────────────────┐                      │
              │  │ Rhai Engine                  │                      │
              │  │  max_ops: 10,000             │                      │
              │  │  max_call_levels: 16         │                      │
              │  │  max_string: 64KB            │                      │
              │  │  registered: bar_chart,      │                      │
              │  │    table, gauge, dots,        │                      │
              │  │    vsplit, hsplit, render, …  │                      │
              │  │  NOT registered: anything     │                      │
              │  │    involving I/O, FFI, eval   │                      │
              │  └──────────────┬───────────────┘                      │
              │                 │ RenderSpec                            │
              │                 ▼                                      │
              │  ToolResult {                                          │
              │    content: "Rendered bar chart 'File Sizes' (5 bars)" │
              │    render_spec: Some(RenderSpec::BarChart { … })       │
              │  }                                                     │
              └────────────────────────────┬───────────────────────────┘
                                           │
                    ┌──────────────────────▼──────────────────────────┐
                    │  ReplOutput::tool_result + render_widget         │
                    │                                                  │
                    │  TerminalOutput:                                  │
                    │    spec → ratatui Buffer (headless)               │
                    │    Buffer → Vec<String> (ANSI lines)             │
                    │    lines → ExternalPrinter (inline scrollback)   │
                    │                                                  │
                    │  Collector (test):                                │
                    │    spec → ASCII fallback text                     │
                    └──────────────────────────────────────────────────┘
```

### Security boundaries

```text
  ┌─────────────────────────────────────────────────────────────────┐
  │ Harness process (non-dumpable, owns API keys)                   │
  │                                                                 │
  │  ┌────────────────────────┐    ┌─────────────────────────────┐  │
  │  │ Rhai sandbox           │    │ Cgroup/eBPF sandbox          │  │
  │  │ (render tool)          │    │ (bash, file tools)           │  │
  │  │                        │    │                              │  │
  │  │ ✗ No I/O               │    │ ✗ No API keys (env stripped) │  │
  │  │ ✗ No FFI               │    │ ✗ Policy-denied paths        │  │
  │  │ ✗ No eval              │    │ ✗ /proc/<harness>/environ    │  │
  │  │ ✗ Bounded CPU (ops)    │    │ ✓ Allowed paths only         │  │
  │  │ ✗ Bounded memory       │    │ ✓ Audit trail                │  │
  │  │ ✓ Drawing API only     │    │                              │  │
  │  └────────────────────────┘    └─────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────┘
```

The two sandboxes never interact. The render tool ignores the `Sandbox` parameter. A Rhai script
cannot invoke bash or read files. A bash command cannot invoke the Rhai engine.

---

## Success Criteria

- **SC-008**: A `MockModel`-driven REPL exchange where the agent calls `render` with a bar-chart
  script produces a `RenderSpec::BarChart` that the test `Collector` receives via `render_widget`,
  with correct labels and values, and the `ToolResult.content` returned to the model is a text
  summary (not ANSI).
- **SC-009**: A Rhai script containing `loop { }` is terminated by the engine within 50ms and
  produces `ToolResult { is_error: true }` mentioning the operation limit.
- **SC-010**: A Rhai script calling an unregistered function (e.g., `import "std"`, or any function
  not in the Rendering API) fails with a Rhai error and produces `ToolResult { is_error: true }`.
- **SC-011**: The `TerminalOutput` renders a `RenderSpec::BarChart` to inline ANSI lines via
  `ExternalPrinter` without entering alt-screen or raw mode, and the output contains box-drawing
  characters and colored bars.
- **SC-012**: After migrating `terminal.rs` to `viz` constants, all existing `TerminalOutput` tests
  pass without assertion changes.
- **SC-013**: The `status_grid` function, given 3 pass and 1 fail results, produces output containing
  3 green `●` and 1 red `●` (verified by checking for the palette SGR codes in the output string).
- **SC-014**: A composed layout (`vsplit` containing a gauge and a table) renders to a buffer whose
  height is the sum of the children's heights plus separators, and whose width fills the available
  space.
- **SC-015**: A 16×16 sprite with 4 palette colors renders to 8 terminal rows of half-block
  characters, each row containing truecolor ANSI escapes. Transparent pixels produce no background
  escape for their half of the cell.
- **SC-016**: A 3-frame animation at 150ms renders the first frame immediately, then a background
  task redraws in place (verified by the `CapturePrinter` receiving cursor-up sequences between
  frames). After the specified cycles complete, the `reclaim` flag is set.
- **SC-017**: Starting a sprite animation while the spinner is running stops the spinner (the
  `spinning` flag is cleared) before the animation begins.
- **SC-018**: The built-in `bee_sprite()` and `bee_animation()` functions are callable from a Rhai
  script and produce valid `SpriteSpec` / `AnimationSpec` values.
- **SC-019**: `rhai` and `ratatui` do not appear in `bee-core`'s or `bee-common`'s dependency tree
  (`cargo tree -p bee-core` / `cargo tree -p bee-common` shows neither).

---

## Dependencies

### New crate dependencies (bee-harness only)

```toml
[dependencies]
rhai = { version = "1", default-features = false, features = ["only_i64"] }
ratatui = { version = "0.29", default-features = false }
```

`rhai` with `only_i64`: disables unused integer types, cuts code size. No `unchecked` (that would
disable safety limits). No `std` features that expose I/O.

`ratatui` with no default features: gives us `Buffer`, `Rect`, widget types, and `Style` without
pulling in `crossterm` or any terminal backend. Pure rendering math.

### What is NOT added

- `crossterm` — not needed; we render to a headless `Buffer` and convert to ANSI ourselves.
- A color crate (`owo-colors`, `colored`, `ansi_term`) — we stick with inline SGR escapes and
  `NO_COLOR`, consistent with the existing approach.

---

## Project Structure

### New files

```text
bee-harness/src/
├── viz.rs                   # the honeycomb design language: palette, glyphs, status_grid,
│                            # render_to_ansi (Buffer → Vec<String>)
├── viz/
│   ├── palette.rs           # color constants + paint/bold helpers
│   ├── glyph.rs             # glyph constants
│   ├── grid.rs              # status_grid renderer
│   ├── buffer_render.rs     # RenderSpec → ratatui Buffer → ANSI lines
│   ├── sprite_render.rs     # SpriteSpec → half-block ANSI lines (truecolor, 256, 16 fallbacks)
│   ├── animator.rs          # background tokio task for sprite animations (same pattern as spinner)
│   └── bee.rs               # the built-in 16×16 bee sprite + 3-frame wing-flap animation
├── tools/
│   └── render.rs            # the render tool: Rhai engine + registered API
├── render_spec.rs           # RenderSpec enum + builder types + serde
└── render_api.rs            # Rhai function registrations (register_fn calls)
```

### Modified files

```text
bee-harness/Cargo.toml       # add rhai, ratatui deps
bee-harness/src/tools.rs     # add "render" to is_known_tool; register in registry_for
bee-harness/src/repl.rs      # ReplOutput gains render_widget; exchange loop checks render_spec
bee-harness/src/repl/terminal.rs  # migrate to viz constants; implement render_widget
bee-harness/src/transcript.rs     # ToolResult gains render_spec: Option<RenderSpec>
```

### Spec files

```text
specs/003-visual-render/
├── spec.md                  # this file
├── contracts/
│   ├── render-tool.md       # render tool I/O contract (Rhai script in, RenderSpec + summary out)
│   ├── rhai-api.md          # registered Rhai functions — the agent-facing rendering API
│   └── honeycomb.md         # the design language: palette, glyphs, layout rules
└── examples/
    ├── bar-chart.rhai       # example agent scripts
    ├── dashboard.rhai
    ├── dot-grid.rhai
    ├── pixel-bee.rhai       # the bee sprite with wing-flap animation
    └── status-sprite.rhai   # a sprite that changes color based on pass/fail
```

---

## Constitution Check

| Principle | Assessment |
|-----------|------------|
| **I. Deny-by-Default & Fail-Closed** | PASS. The Rhai engine registers only drawing functions; everything else is denied by omission. A script that tries to access anything outside the API fails. Resource limits are non-optional. |
| **II. Capability Attenuation** | N/A. The render tool is not in the enforcement path and does not interact with scopes or policies. |
| **III. Kernel Enforcement Is Authoritative** | PASS. The render tool does not touch the kernel sandbox. It is a pure in-process computation with its own (Rhai) confinement. The two sandboxes are independent. |
| **IV. Policy-as-Data** | PASS. The render tool's availability is configured in the scenario's `tools` list (declarative TOML). The Rhai API surface is fixed at compile time (registered functions). |
| **V. Library-First, Runtime-Free Core** | PASS. `rhai` and `ratatui` are confined to `bee-harness`. `bee-core` and `bee-common` gain no new dependencies. The `viz` module is in `bee-harness`, not `bee-core`. |
| **Security/Platform** | PASS. The Rhai sandbox is defense-in-depth atop the existing cgroup sandbox. A model that gets `render` cannot use it to read files, exec processes, or exfiltrate data. The worst a malicious script can do is burn 10,000 Rhai operations (~50ms) and produce a garbled chart. |

**Result: no violations.**

---

## Assumptions

- LLMs (Claude, GPT-4o) can generate syntactically valid Rhai. Rhai's syntax is JavaScript-adjacent,
  which models handle well. The `render` tool's schema description includes a brief Rhai syntax
  primer and the full list of available functions, so the model has the API surface in its tool
  definition. If a model generates invalid Rhai, the error message is fed back as a tool result and
  the model can retry (same pattern as a malformed `bash` command).
- The headless ratatui `Buffer` API (render widgets to an in-memory buffer without a terminal
  backend) is stable and works as documented. This is core ratatui functionality, not an edge case.
- The `ExternalPrinter` can handle ANSI-escaped strings with box-drawing characters and colors. This
  is already true — the existing spinner and tool output use ANSI escapes via the same path.
- The inline rendering approach (charts in the scrollback) is preferable to an alt-screen approach
  (full-screen takeover) for the initial implementation. An alt-screen interactive mode (scroll/zoom
  a chart) is a follow-on feature, not scoped here.
- The render tool is most useful in the REPL (US5). In batch/episode mode, the `RenderSpec` is
  recorded in the transcript but not rendered to a terminal (there may not be one). A future web
  transcript viewer could re-render from the spec.

