# Contract: sprite & animation API (Slice 2)

The Rhai sprite/animation/palette/bee functions, the half-block rendering contract, and the
`TerminalOutput` animator contract. Additive to Slice 1's `render` tool — same engine, same
`ToolResult`/`RenderSpec` flow. Implements FR-028…FR-032.

---

## Rhai functions (registered on the Slice-1 engine)

### Palette

| Function | Rhai signature | Description |
|----------|----------------|-------------|
| `palette()` | `fn() -> Palette` | Empty color palette (≤ 32 entries). |
| `pal.set(char, color)` | `fn(&mut Palette, String, String)` | Map a 1-char key to `"#RRGGBB"` or `"transparent"`. Bad hex → error. |

### Sprite

| Function | Rhai signature | Description |
|----------|----------------|-------------|
| `sprite(w, h, pal)` | `fn(i64, i64, Palette) -> Sprite` | Canvas, max 32×32 (else error). |
| `sprite.paint(rows)` | `fn(&mut Sprite, Array)` | One string per pixel row; each char → palette color; unknown → transparent. |
| `sprite.set(x, y, color)` | `fn(&mut Sprite, i64, i64, String)` | Set one pixel by hex color. |
| `sprite.fill(color)` | `fn(&mut Sprite, String)` | Fill the whole canvas. |

### Animation

| Function | Rhai signature | Description |
|----------|----------------|-------------|
| `animation(ms)` | `fn(i64) -> Animation` | Frame interval, clamped 50–1000 ms. |
| `anim.add(sprite)` | `fn(&mut Animation, Sprite)` | Append a frame (≤ 16; same dims; else error). |
| `anim.bounce(b)` | `fn(&mut Animation, bool)` | Ping-pong playback (default false). |
| `anim.cycles(n)` | `fn(&mut Animation, i64)` | Full cycles then stop; 0 = loop until interrupted (default 1). |

### Identity

| Function | Rhai signature | Description |
|----------|----------------|-------------|
| `bee_sprite()` | `fn() -> Sprite` | The built-in 24×24 bee (SC-018). |
| `bee_animation()` | `fn() -> Animation` | The 6-frame flap-and-wink greeting (120 ms/frame, no bounce). |

`render(widget)` and `layout.add(widget)` accept `Sprite` and `Animation`. An `Animation` inside a
layout renders **frame 0 only** (a layout is a static composition; the summary notes it).

### Caps (API-enforced → Rhai error → `ToolResult::error`)

| Cap | Limit |
|-----|-------|
| Sprite dimensions | ≤ 32×32 px |
| Frames per animation | ≤ 16 |
| Palette entries | ≤ 32 |
| Frame interval | clamped to 50–1000 ms (not an error) |

### Example

```rhai
let pal = palette();
pal.set(".", "transparent");
pal.set("K", "#1A1A1A");
pal.set("Y", "#E5A100");
let s = sprite(16, 16, pal);
s.paint([ "......KK........", /* … 16 rows … */ ]);
render(s);
```

Summary to the model: `Rendered a 16×16 sprite.` (INV-1 from render-tool.md still holds — no ANSI in
the summary.)

---

## Half-block rendering contract (`viz::sprite_render`)

- A `W×H` sprite renders to `⌈H/2⌉` terminal rows × `W` columns. Two vertical pixels pack into one
  cell; the glyph is chosen by which halves are opaque (research D12):
  - both opaque → `▄` (U+2584), `bg` = top pixel, `fg` = bottom pixel;
  - only top opaque → `▀` (U+2580), `fg` = top, **no bg escape**;
  - only bottom opaque → `▄`, `fg` = bottom, **no bg escape**;
  - both transparent → space, no color.
- **SC-015**: a 16×16 sprite with 4 palette colors → 8 rows of half-block cells, each row carrying
  truecolor escapes; transparent pixels emit no background escape for their half.
- **Color modes** (research D13): `TrueColor` (`38;2;`/`48;2;`) when `COLORTERM` ∈ {truecolor, 24bit};
  else `quantize_256` → `38;5;`/`48;5;`; else `quantize_16` → basic ANSI. Off-tty / `NO_COLOR` →
  monochrome block chars, no SGR.

---

## Animator contract (`viz::animator` + `TerminalOutput`)

- **Static sprite** (`render_widget(RenderSpec::Sprite)`): render the frame and emit its rows inline
  through the `ExternalPrinter` (no cursor rewrite).
- **Animation** (`render_widget(RenderSpec::Animation)`):
  1. Stop any running spinner or prior animation first — there is **one** active-animation slot
     (`spinning: AtomicBool` + `spin_task`); starting an animation clears `spinning` (**SC-017**).
  2. Emit frame 0's `⌈H/2⌉` rows synchronously (instant first paint).
  3. Spawn a tokio task: every `interval_ms`, print `\x1b[{N}A` (up N), redraw N lines of the next
     frame, re-checking the active flag under the printer lock; advance per `bounce`; stop after
     `cycles` full cycles (0 = until interrupted). **SC-016**: the `CapturePrinter` sees cursor-up
     sequences between frames; after the cycles complete, `reclaim_rows` is set to `N`.
  4. `reclaim_rows` (was the spinner's single-row `reclaim`) makes the next real output overwrite all
     `N` sprite rows in place — no residue (same as the spinner at `N = 1`; regression gate).
- **FR-031**: only one animated element at a time — the shared slot makes this structural.
- **Tool call mid-animation**: the animation stops and its rows are reclaimed before the tool result
  prints (Edge Case), exactly as `busy_stop` already handles the spinner.

---

## The bee (FR-032)

`viz::bee::sprite()` / `viz::bee::animation()` provide the 24×24 bee and a six-frame greeting
(120 ms/frame, one cycle, no bounce), built once via `OnceLock`. The greeting flutters, winks,
and settles back to the static pose. Artwork and palette live in `src/viz/bee/art.rs`, shared
with the WASM visual fixtures without importing the application dependency graph.

The full-screen REPL animates the mascot while its chat entry is visible: a brief flutter and wink
every 4.8 seconds, with no redraws during the resting pause. Its clock pauses offscreen, under
help/panel/takeover overlays and consent dialogs, or below the terminal's minimum size. `BEE_NO_ANIMATION` or
`visual.animations = false` holds the resting pose. The inline REPL keeps a static banner so
background cursor movement cannot interfere with readline.

The mascot occupies 24 columns × 12 terminal rows; suppress it with
`--no-bee` or `BEE_MASCOT=0`. The Rhai `bee_sprite()` and `bee_animation()` helpers expose the
same artwork. Existing animation-off and monochrome rendering behavior still applies.

### Session expressions

The full-screen mascot follows typed events: exchange start means thinking, tool calls mean working,
and tool results return it to thinking or concern. Actual exchange completion triggers a brief nod
that settles into an attentive pose; exhausting the turn budget shows the waiting expression.
Errors, kernel denials, cancellation, exhausted context, and stuck detection suppress the completion
celebration for that exchange. The provider's
`TurnDone` callback only ends its busy indicator and does not mean the exchange succeeded.

Each expression has a static pose when animations are disabled. Completion and concern animations
settle and stop scheduling redraws. The header keeps a plain-text activity label even when the
mascot scrolls out of view; errors remain in the chat. Waiting means control has returned to the
operator, not a guess about questions in generated prose.

Preview a state with `cargo run --example bee_preview -- --animate --mood working`.
Available moods: `idle`, `thinking`, `working`, `finished`, `waiting`, and `concerned`.
`--moods-json` exports the expression sequences for visual review.
