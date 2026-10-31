# `cargo xtask` — bee's developer tasks

Today this is one pipeline: **visual regression testing for the TUI**.

bee's terminal UI is ratatui widgets with a [tachyonfx](https://github.com/ratatui/tachyonfx) effects
pass applied to the buffer after they draw (009-tachyonfx-effects). the bee application package already asserts
that pipeline at the *cell* level — `tui::effects::Timeline` steps effects frame by frame and checks
symbols and colors. This checks it at the *pixel* level: the same widget calls and the same effect
constructors are compiled to WebAssembly with [Ratzilla](https://github.com/ratatui/ratzilla), drawn
in a real browser, and screenshotted at fixed time offsets. The PNGs are diffed against baselines
committed under `xtask/baselines/`.

```
xtask/
├── src/main.rs        the runner: viz-serve, viz-snapshot, viz-update
├── src/serve.rs       a throwaway static server for dist/
├── viz-web/           the WASM preview app (ratzilla + ratatui + tachyonfx)
│   ├── src/scenes.rs  ← the scene list. This is the file you edit.
│   ├── src/mascot.rs  shared bee artwork, as half-block glyphs
│   ├── src/palette.rs bee's catppuccin-mocha role colors
│   └── assets/        the bundled monospace font
├── puppeteer/         the headless-Chrome screenshot driver
└── baselines/         committed baseline PNGs (git-tracked)
```

## Prerequisites

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked trunk
(cd xtask/puppeteer && npm ci)     # also downloads Puppeteer's pinned Chromium
```

The snapshot driver uses Puppeteer 25 and needs Node.js 22.12 or newer. On npm versions that
block dependency install scripts, run `node xtask/puppeteer/node_modules/puppeteer/install.mjs`
after `npm ci` to install Chromium.

The runner checks for all three before it uses them and prints the install command if one is
missing. They are deliberately *not* Cargo dependencies — dragging a JS toolchain and a WASM bundler
into the dependency graph to run three commands would be worse than asking for them.

## Commands

| Command | What it does |
|---|---|
| `cargo xtask viz-serve` | `trunk serve` + open a browser. Every scene plays in turn, in real time, captioned. For eyeballing. |
| `cargo xtask viz-snapshot` | `trunk build --release`, serve `dist/` on an ephemeral port, screenshot all 15 scenes (46 frames), diff against `baselines/`. Exit 0 on match, 1 on drift. |
| `cargo xtask viz-update` | The same, but writes the screenshots to `baselines/` instead of comparing. |
| `cargo xtask viz-gallery` | Render every `RenderSpec` widget headlessly — ANSI to the terminal and/or SVGs to `xtask/gallery/` — through bee's own `buffer_render`, so what it shows is exactly what the TUI draws. |
| `cargo xtask viz-screens` | Render the **full TUI** (header · chat · panels · input · footer) at representative states and sizes to SVGs in `xtask/screens/`, through the real `view()` on a headless backend. `--theme <name>` picks a built-in theme (default `catppuccin-mocha`). |

Run these **from the repository root**. Cargo resolves an alias's `--manifest-path` against the
current directory and has no way to make it repo-relative, so `cargo xtask` from a subdirectory
fails with "manifest path `xtask/Cargo.toml` does not exist". Everything past that first hop is
anchored to the xtask crate's own directory.

Useful flags: `--scene <name>` (repeatable) restricts to one scene; `--no-build` reuses an existing
`dist/`; `viz-serve --port N --no-open`.

When a comparison fails, the actual and diff PNGs land in `xtask/shots/` (git-ignored) and the JSON
report names every scene that moved.

## The scenes

Fifteen, covering all twelve `EffectSpec` variants an agent can request plus the three compositions
bee builds for itself:

| Scene | Base drawing | Effect |
|---|---|---|
| `fade_in` / `fade_out` | bordered paragraph | `fx::fade_from` / `fx::fade_to` (300ms) |
| `dissolve_in` / `dissolve_out` | 4-row table | `fx::coalesce` / `fx::dissolve` (300ms) |
| `slide_in_left` / `slide_out_right` | 5-bar chart | `fx::slide_in(LeftToRight)` / `fx::slide_out(RightToLeft)` (400ms) |
| `sweep_in_top` / `sweep_out_bottom` | gauge at 67% | `fx::sweep_in(UpToDown)` / `fx::sweep_out(DownToUp)` (400ms) |
| `pulse_accent` | status line | `fade_to_fg` + `fade_from_fg` (200ms) |
| `glow` | bordered block | `fx::ping_pong(fx::lighten)` (500ms) |
| `evolve_in` / `evolve_out` | the bee mascot | `fx::evolve_into` / `fx::evolve_from(BlocksHorizontal)` (600ms) |
| `panel_update` | `O` content → `N` content | dissolve-out then coalesce-in (400ms) |
| `chrome_header` | header bar | `fx::fade_from` (300ms) |
| `chrome_footer` | footer hint bar | `fx::slide_in(DownToUp)` (300ms) |

Each is captured at `t=0`, `t=ms/2` and `t=ms` — start, halfway, end. Three points, because two
would only prove the effect started and finished; the midpoint is the one that catches a changed
interpolation curve.

`panel_update` is the exception, captured at the quarters instead (four frames, 46 baselines in
total). It is two sequential halves, so at its exact midpoint the old content has finished
dissolving and the new has not begun coalescing: the frame is blank *by construction*, which is also
what a completely broken transition would produce. the bee application package's own test for this transition
samples the same quarter and three-quarter offsets, for the same reason.

One baseline is worth knowing about: `fade_in_0` is a solid block of the `info` color. That is
correct — `fx::fade_from(INFO, INFO, …)` sets both foreground and background to the role color on
its opening frame, so nothing is legible yet, and the bee application package asserts exactly that ("t=0 must be
the fade-from color, not the widget's"). It still pins the fade-from color and the scene geometry;
it just cannot tell you anything about the text.

## Adding a scene

Append a `Scene` to `SCENES` in `viz-web/src/scenes.rs`:

```rust
Scene {
    name: "my_scene",
    about: "what it demonstrates",
    ms: 300,
    times: &[0, 150, 300],          // the offsets to screenshot
    cols: 44,
    rows: 7,
    draw: draw_panel,               // paints widgets; called fresh every frame
    effect: |area| seeded(fx::coalesce(300)).with_area(area),
},
```

Wrap the effect in `seeded(...)` if it scatters cells — `dissolve`, `coalesce`, `slide_in`,
`slide_out` — or its baseline will not reproduce. On a composite, seed the leaves, not the wrapper.
See the note on determinism below.

Then `cargo xtask viz-update --scene my_scene` to write its three baselines, and commit them.

Nothing else needs touching. The page publishes the scene list on `data-bee-manifest` and the
Puppeteer driver reads it from there, so there is no second list to keep in sync.

## Design notes

**`viz-web` does not depend on the bee application package, on purpose.** That crate's tree is tokio, rig-core,
aya, rustyline and rhai; none of it compiles to wasm32. So the scenes are self-contained
reproductions: the same ratatui widget calls, and the tachyonfx constructors copied out of
`src/tui/effects.rs` argument for argument — same `GRADIENT_LEN`, same `RANDOMNESS`,
same `Motion` mapping, same two composites, same durations.

What that buys is honest but bounded. These screenshots do **not** prove bee's own code is correct;
the bee application package's own tests do that. They prove that the *upstream surface bee stands on* still draws
what it drew — that a ratatui or tachyonfx bump has not silently changed a border glyph, a gradient
curve, or the block set an `evolve` substitutes. That is the failure mode cell-level assertions in
bee are least likely to catch, because they assert against expectations written at the same time as
the code.

**Time is stepped, never measured.** Effects advance in fixed 16ms increments, including a
zero-length first frame — the same stepping the bee application package's `Timeline` uses, and the reason a `t=0`
capture shows the animation's opening frame rather than the untouched widget. Nothing in the pipeline
screenshots a real-time animation "about halfway through".

**The scatter effects are explicitly seeded, because tachyonfx's are not deterministic.** This is
the one place the scenes deliberately diverge from the bee application package, and it is worth stating plainly
because bee's own source says otherwise. `tui/effects.rs` documents that "tachyonfx carries its own
seeded `SimpleRng` and has no `rand` dependency, so the character-scatter effects reproduce for a
given area and timeline". The first half is true and the conclusion does not follow: `dissolve`,
`coalesce`, `slide_in` and `slide_out` build their per-cell thresholds from `SimpleRng::default()`,
and under tachyonfx's `std` (or `wasm`) feature that constructor seeds itself from
`SystemTime::now()`. They differ every run. Measured here: unseeded, eight of the 46 frames failed
against baselines taken minutes earlier, by up to 18% of their pixels.

the bee application package's tests do not notice because they assert *structural* properties of these effects —
"some cells still show `O` and some show a space" — never an exact frame. Nothing in bee is broken by
this; the docstring is just wrong about why, and anyone who adds a pinned frame snapshot of a
dissolve on the strength of it will get a flaky test.

The scenes pin them with `Effect::with_rng(SimpleRng::new(SEED))`. Note that the seed must go on
each **leaf**: `fx::sequence` and `fx::parallel` inherit the `Shader` trait's no-op `set_rng`, so
seeding a composite compiles, returns an `Effect`, and does nothing. `sweep_in`/`sweep_out` need no
seeding — those construct `SimpleRng::new(0)` internally and were already reproducible, which the
first run confirmed by being the only scatter scenes that passed.

**The font is bundled.** A baseline PNG is a claim about pixels, and pixels come from glyph outlines.
Puppeteer pins its own Chromium; `assets/DejaVuSansMono.ttf` (Bitstream Vera license, redistribution
granted — see the bundled `DejaVuSansMono.LICENSE.txt`) pins the other half. With the system
monospace instead, the same commit would render differently on every machine and every diff would be
noise.

There is a corollary worth stating plainly: baselines are still specific to a Chromium version and to
Linux font rasterization. A Puppeteer major bump can legitimately move every pixel. When that
happens, look at a couple of diffs to confirm the change is rasterization rather than layout, then
`viz-update`.

**Rendering is on demand, not on navigation.** The page exposes `bee_render(scene, t)` and the driver
calls it 46 times against one page load. Beyond being much faster, it is what lets the driver await
`document.fonts.ready` *before* anything measures a cell: Ratzilla's `DomBackend` sizes its grid from
`getBoundingClientRect()` at construction, and a page that rendered during load could measure the
fallback font and build a differently-sized grid.

**Nothing here touches bee's build.** `xtask` is in the root workspace's `exclude` list, `viz-web` is
excluded from `xtask`'s own workspace, and no shipping crate can reach either. `cargo build`,
`cargo test` and `cargo clippy --workspace --all-targets` are unaffected — that is a requirement, not
an accident, and `.cargo/config.toml` contains only the `xtask` alias for the same reason.

## Mascot

The bee is a cheeky 24×24 pixel sidekick with crooked antennae, a sideways glance, and a grin.
`src/viz/bee/art.rs` owns its resting bitmap and six-color palette; the terminal and WASM fixtures
both read it. The short `bee_animation()` greeting adds a wing flutter and one wink, ending on
the resting pose. `cargo run --example bee_preview` shows the actual terminal rendering;
add `-- --animate` for its idle loop (Ctrl-C to stop). The full-screen REPL runs the same loop
while the mascot is visible, pausing offscreen or when covered. `BEE_NO_ANIMATION` keeps it still;
`cargo xtask viz-screens` includes welcome screens at 80×24 and 120×32. Export the actual
animation frames as JSON with `cargo run --example bee_preview -- --json`.

Session expressions follow exchange and tool events. Try
`cargo run --example bee_preview -- --animate --mood thinking` (also `working`, `finished`,
`waiting`, or `concerned`). Motion-off sessions keep the matching static expression.
Use `--moods-json` to export all the expression sequences.
