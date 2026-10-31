//! The shared bee mascot, drawn as half-block glyphs for the visual effect fixtures.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};

// Share the artwork without pulling the application's native dependencies into WASM.
#[path = "../../../src/viz/bee/art.rs"]
mod art;

pub const COLS: u16 = art::SIZE;
pub const ROWS: u16 = art::SIZE / 2;
const LOWER: &str = "▄";
const UPPER: &str = "▀";

fn at(x: u16, y: u16) -> Option<Color> {
    art::REST
        .get(usize::from(y))
        .and_then(|row| row.as_bytes().get(usize::from(x)))
        .and_then(|&c| art::pixel(c))
        .map(|(r, g, b)| Color::Rgb(r, g, b))
}

/// Draw the mascot into `buf`, top-left aligned inside `area`.
///
/// The glyph choice follows bee's rule exactly, and for the same reason: a transparent half must
/// emit no color of its own. Both halves opaque uses `▄` with the top pixel as the *background*;
/// a lone top half uses `▀`; a lone bottom half uses `▄`.
pub fn draw(buf: &mut Buffer, area: Rect) {
    for r in 0..ROWS {
        for x in 0..COLS {
            let (cx, cy) = (area.x + x, area.y + r);
            if !buf.area.contains((cx, cy).into()) {
                continue;
            }
            let top = at(x, 2 * r);
            let bottom = at(x, 2 * r + 1);
            let cell = &mut buf[(cx, cy)];
            match (top, bottom) {
                (None, None) => {
                    cell.set_symbol(" ");
                }
                (Some(t), Some(b)) => {
                    cell.set_symbol(LOWER)
                        .set_style(Style::default().fg(b).bg(t));
                }
                (Some(t), None) => {
                    cell.set_symbol(UPPER).set_style(Style::default().fg(t));
                }
                (None, Some(b)) => {
                    cell.set_symbol(LOWER).set_style(Style::default().fg(b));
                }
            }
        }
    }
}
