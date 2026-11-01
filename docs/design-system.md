# The Bee TUI Design System

The shared visual language for everything bee prints to a terminal — the REPL chrome, the
`render` tool, batch/episode output, and the mascot. One vocabulary, drawn from `bee_harness::viz`,
so the output reads as a single system whether it's a status dot or the startup banner.

> **Authoritative token spec:** palette, glyphs, status grid, layout primitives, and rendering caps
> live in [`specs/003-visual-render/contracts/honeycomb.md`](../specs/003-visual-render/contracts/honeycomb.md).
> This document is the front door: the principles that govern the whole system, plus the **mascot &
> sprite** conventions that the contract left to "Slice 2."

---

## Principles

These are non-negotiable and already hold across the codebase — keep them holding.

1. **Color is semantic, never decorative.** Nothing hardcodes a hex or SGR code at a call site. Six
   roles — `success` `error` `info` `dim` `accent` `text` — resolve through the active theme
   (`viz::palette` → `viz::theme`). Add meaning by picking a role, not a color.
2. **Monochrome is the floor, color is enhancement.** Every signal must survive `NO_COLOR`
   (honored per <https://no-color.org>) and a non-tty. Dots keep their glyph; the sprite degrades to
   block silhouettes; denials keep the `⚠` and the word `DENIED`. Never let color be the *only*
   carrier of state — pair it with a glyph or a letter.
3. **One glyph vocabulary.** Every glyph in project output comes from `viz::glyph` (`●○▸✓✗⚠⬡─│`).
   Nothing ad-hoc. A new state reuses an existing glyph before it invents one.
4. **Theme by indirection.** A new theme is one entry in `viz::themes` (a token→color map), never a
   code change at a render site. `honeycomb` is the default and is byte-identical to the pre-theming
   basic-ANSI output; Catppuccin ×4, Dracula, and Nord ship alongside it.
5. **Spatial stability.** Banners, status lines, and dot grids keep fixed positions and fixed column
   order. Chrome doesn't rearrange itself between frames.
6. **The terminal is ours; untrusted text is data.** Model prose, tool output, audit targets, and
   skill metadata are attacker-reachable, and a terminal reads text as a command language — an ESC
   can clear the screen, a `\r` can rewrite the line above, a bidi override can reorder what was
   already drawn. Every such string passes through `safe_text::safe_block`/`safe_line` at the point
   it enters a front-end (`repl::terminal`'s `ReplOutput` impl; `tui::app::handle_session`), and
   only *then* gets styled. Sanitize the payload, then paint it — never the reverse, or the escaping
   would eat bee's own color.

## Identity

| Element | What | Where |
|---|---|---|
| **Honey yellow** | `#E5A100` — the chrome's brand color; info and banners | `palette::HONEY` / `Role::Info` |
| **`⬡` hexagon** | the inline identity glyph (honeycomb cell) | `glyph::HEX` |
| **The bee** | the 24×24 mascot, greeting, and session expressions | `viz::bee` |

The name is the whole metaphor: a **bee** in a **honeycomb**, working the cells. Yellow-and-black is
the identity — which is exactly why the mascot must *read* as a bee (see below).

---

## Mascot & sprite system

The mascot is a **24×24 pixel sprite** rendered with vertical half-blocks — two stacked pixels per
terminal cell (`▀▄█`), so 24 rows of pixels become **12 rows of text**, 24 columns wide. Truecolor
when available, quantized to 256/16 colors otherwise, block silhouette under `NO_COLOR`. Pipeline:
`viz::bee` (bitmap) → `viz::sprite_render::render_frame_with` → ANSI. No image protocol, no new crate.

### Authoring a sprite

The resting bitmap in `src/viz/bee/art.rs` has 24 rows of exactly 24 characters. The terminal and
WASM visual fixtures share this artwork and palette. These are artwork colors, separate from the
semantic roles used by chrome. Each character is a **palette letter**:

| Letter | Color | Role in the bee |
|---|---|---|
| `K` | `#423029` dark brown | outline, eyes, stripes |
| `H` | `#FFD766` light honey | face |
| `Y` | `#EFAD32` honey gold | body and shading |
| `W` | `#EFFAF7` off-white | wings, eyes |
| `B` | `#91C8CC` pale blue | wing edges |
| `R` | `#E58450` warm orange | cheeks |
| `.` | transparent | background (emits no escape) |

Unknown palette letters are transparent. Tests check the bitmap dimensions; rows are not padded.

### What makes it read as a bee

The mascot faces the operator with crooked antennae, a sidelong glance, and a small grin.
Paired wings flank the face; dark horizontal stripes cross the abdomen, with short legs below.
Expressions change the eyes, mouth, antenna, or head tilt while keeping the same canvas, so the
chat layout stays stable between poses.

Verify the silhouette in monochrome first — if the black-and-white block outline doesn't say "bee,"
color won't save it.

### Animation

`sprite()` returns the resting pose. `animation()` exposes a six-frame greeting at 120 ms/frame:
flutter, wink, and settle, for one cycle without bouncing. Both are deterministic and cached with
`OnceLock`; callers supply elapsed time for playback.

The full-screen REPL repeats the greeting every 4.8 seconds while the mascot is idle and visible.
Its clock pauses offscreen, under help/panel/takeover overlays, and below the terminal's minimum
size. Held poses sleep until the next visible change, including across loop boundaries. The inline
REPL uses a static banner to avoid interfering with readline.

Typed exchange and tool events select thinking, working, finished, waiting, or concerned expressions.
Completion nods once and settles into an attentive pose; concern also settles without ongoing ticks.
Errors and kernel denials suppress the completion celebration. Motion-off sessions show a static
expression, and the header retains a text activity label even when the mascot scrolls out of view.
See the [sprite contract](../specs/003-visual-render/contracts/sprite-api.md) for the state semantics.

### Preview

```sh
cargo run --example bee_preview                    # static sprite, real pipeline
cargo run --example bee_preview -- --animate       # idle greeting loop
cargo run --example bee_preview -- --animate --mood working
BEE_MASCOT=0 ./target/debug/bee repl ...            # or --no-bee to suppress
NO_COLOR=1 cargo run --example bee_preview          # check the monochrome floor
```

---

## Component inventory

The reusable chrome pieces, all built from the tokens + glyphs above:

| Component | Glyphs / tokens | Used for |
|---|---|---|
| **Startup banner** | honey title + `⬡` + mascot | REPL identity header |
| **Status dot grid** | `●` pollen / `●` sting / `○` smoke | batch & episode pass/fail (`viz::status_grid`) |
| **Tool-call line** | `▸` arrow, `✓`/`✗` result, dim args | live tool execution in the REPL |
| **Denial line** | bold `⚠ DENIED` in sting-red | kernel/policy denials |
| **Spinner** | braille `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` | in-flight work |
| **Rules / splits** | `─` `│`, `vsplit`/`hsplit` (max depth 4) | layout separators |
| **Grid** | `grid(rows, cols)` → cells hold any widget; spans union tracks | model-defined N×M dashboards ([plan](./grid-tui-plan.md)) |

Render widgets — charts, gauges, tables, dot grids, sprites, grids — are authored in Python
([Python drawing API](./python-visuals.md), `render_api`) and validated into a pure-serde `RenderSpec`. The full component pipeline and the
grid system live in [the grid TUI plan](./grid-tui-plan.md).

### Full-screen surface (008-grid-tui)

`bee repl --tui` (build with `--features tui`) adds a full-screen front-end over the same
conversation core the inline REPL uses, so both stay in lock-step.

| Element | Form | Used for |
|---|---|---|
| **Regions** | header · chat · input · footer, fixed positions | the frame never reflows between turns |
| **Panel** | bordered block titled with its id, right-hand column | model-owned live output (`render_to`) |
| **Panel overlay** | centered popup over chat, toggled with `p` | panels on single-pane (< 120 col) layouts |
| **Help overlay** | `?` — full key reference | discoverability ladder (footer → `?`) |
| **Overflow note** | `+N more — remove_panel()/clear_panels()` | honest report when panels exceed the column |
| **Too-small** | `terminal too small (min 40×10)` | below the hard floor; nothing else is drawn |

Panel rules that shape the design: a panel is **replaced in place** by id (never duplicated), panels
are sized to their **content** rather than split evenly, and a widget that cannot be displayed fails
the script with an actionable message instead of drawing a smear. Inline widgets render through the
same truecolor buffer path as panels — never an ASCII placeholder.

New chrome should compose these before introducing anything new. If a state needs a color, it needs
a role; if it needs a mark, it needs a glyph from the vocabulary.

---

## Motion & visual permissions (009-tachyonfx-effects)

Effects are **decoration**. Nothing about them may change what a render *means*, and no tool call
may fail because of one — a suppressed effect renders the final content immediately.

### Three independent axes

They compose freely: a session can have full color, full takeover rights, and zero motion.

| Axis | Off switch | Governs | Reaches bee's own chrome? |
|---|---|---|---|
| **Color** | `NO_COLOR=1` | the four color effects (fade, pulse, glow) | yes — but text effects keep moving |
| **Motion** | `--no-animation`, `BEE_NO_ANIMATION` | *all* motion | **yes** — this is the operator's switch |
| **Screen** | `--visual-level`, `BEE_VISUAL_LEVEL` | how much screen the **agent** may claim | **no** — the level governs the agent only |

`BEE_NO_ANIMATION` is presence-is-truth, like `NO_COLOR`: `BEE_NO_ANIMATION=0` still disables. That
is surprising read alone and consistent with the convention bee already implements.

With motion off, nothing is ever registered — so the render loop cannot enter its 60fps state. That
is structural, not a rule each call site remembers: everything routes through one resolver.

### Visual levels

`--visual-level` takes `none`, `panels` (default), `panels-wide`, or `takeover`. It is a **ceiling**,
not a mode: a request above it is **downgraded, never refused**, and the tool result tells the model
what happened so it can adapt next turn. Erroring instead would teach the model to stop rendering.
An unrecognized value is a startup error — a policy that cannot be compiled is refused, never
silently weakened.

| Level | Panels | Panel width | Takeover |
|---|---|---|---|
| `none` | ✗ (renders inline) | — | ✗ |
| `panels` *(default)* | ✓ | ⌊w/3⌋ | ✗ |
| `panels-wide` | ✓ | ⌊w/2⌋ | ✗ |
| `takeover` | ✓ | ⌊w/2⌋ | ✓ |

### Takeover keys

A full-screen takeover always carries its own way out, in its bottom row: ``Esc`` to dismiss ·
auto-dismiss in {N}s. It expires on its own (`takeover_ttl_secs`, default 30, max 120), it never
covers the input line, and the operator can keep typing and submitting throughout.

`Esc` dismisses from either focus and **leaves typed text intact** — a second `Esc` clears the input
as usual. `q` is deliberately **not** bound to dismiss: it keeps meaning quit in chat focus, so no
key's destructiveness depends on whether an overlay happens to be showing.

### Chrome vs agent

bee's own UI moves with the same twelve-verb vocabulary it gives the agent — there is no second,
privileged effect language. But chrome registers *unkeyed*, and cancellation works by key, so no
panel the agent can name will ever cancel or replace it. The agent picks its own effects; it does
not get to pick bee's.

---

## Checklist for new TUI work

- [ ] Colors come from a `Role`, not a literal SGR/hex.
- [ ] Readable with `NO_COLOR=1` and off a tty (glyph/layout still carries the meaning).
- [ ] Any new glyph is justified against the existing vocabulary first.
- [ ] A new theme would be a `viz::themes` entry, not a render-site change.
- [ ] Sprites verified in monochrome silhouette before judging the color.
- [ ] Fixed column order; chrome doesn't reflow between frames.
- [ ] Full-screen work restores the terminal on **every** exit path (quit / Ctrl-C / Ctrl-Z / panic).
- [ ] Anything drawn in a panel is also reachable on a narrow terminal (the `p` overlay).
- [ ] Motion is decoration: with `BEE_NO_ANIMATION` set, the same content is on screen immediately.
- [ ] Any new effect goes through `tui::effects::resolve` — never registered at a call site directly.
- [ ] New chrome effects register **unkeyed**, so the agent cannot address them.
- [ ] Untrusted text is sanitized where it enters the front-end, before any styling is applied.
