//! `bee::viz` — the **honeycomb** visual design language (003-visual-render, FR-026): the
//! project's shared palette, glyph vocabulary, status grid, and the `RenderSpec` → headless ratatui
//! `Buffer` → ANSI-lines pipeline. Consumed by both the REPL chrome (`repl::terminal`) and the
//! `render` tool. `ratatui`/`monty` live only under this crate (NFR-002/SC-019).

pub mod animator;
pub mod background;
pub mod bee;
pub mod buffer_render;
pub mod glyph;
pub mod grid;
pub mod palette;
pub mod sprite_render;
pub mod theme;
pub mod themes;
pub mod viewport;

pub use buffer_render::{rasterize_sprite_into, render_to_ansi, spec_height, terminal_dims};
pub use grid::{status_grid, Status};
pub use sprite_render::{render_frame, ColorMode};
pub use theme::{active_theme, init_theme, Role, Theme, ThemeColor};
