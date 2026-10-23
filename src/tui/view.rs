//! `view(&App, &mut Frame)` — the full-screen layout (008-grid-tui, US1 T016 + the `?` help overlay
//! T016a; the too-small message from US3 T034 is handled here too).
//!
//! Header · chat (scrollable) · input · footer hint bar. Regions are in fixed positions (FR-007). All
//! color comes from the theme bridge, so `NO_COLOR` degrades to monochrome (FR-014). Panels (US2)
//! render into a right-hand column added in T028.

use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Wrap,
};
use ratatui::Frame;

use super::app::{App, Focus, LayoutMode, TurnState};
use super::chat::{Body, Role};
use super::effects::{self, Chrome};
use super::panels::{self, PanelArea};
use super::theme_bridge::{badge_style, dim_style, role_style, role_style_bold};
use crate::render_spec::{EffectSpec, RenderSpec};
use crate::viz::theme::Role as ThemeRole;

/// Draw the whole UI for the current model state.
///
/// Takes `&mut App` because the frame is where the effects pipeline lives (009 FR-001): panel
/// transitions can only be registered once the layout has assigned each panel a `Rect`, and the
/// effects pass mutates the buffer after every widget has drawn into it.
pub fn view(app: &mut App, frame: &mut Frame<'_>) {
    let area = frame.area();

    if app.layout_mode == LayoutMode::TooSmall {
        too_small(frame, area);
        return;
    }

    // header (1) · chat (fill) · input (3, bordered) · footer (1)
    let [header, chat, input, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(app, frame, header);
    // In TwoPane with live panels, split a right-hand panel column off the chat area (FR-012); with
    // no panels (US1) chat keeps the full width, so the US1 layout is untouched.
    if app.layout_mode == LayoutMode::TwoPane && !app.panels.is_empty() {
        let panel_w = panel_column_width(chat.width, app.visual.level);
        let [chat_area, panel_area] =
            Layout::horizontal([Constraint::Min(20), Constraint::Length(panel_w)]).areas(chat);
        render_chat(app, frame, chat_area);
        render_panels(app, frame, panel_area);
        // The column's first appearance is a *layout* change — the chat pane giving up width — so it
        // gets its own arrival, distinct from the entrance of the panel inside it (FR-026).
        if !app.column_shown {
            app.column_shown = true;
            effects::column_appear(&mut app.effects, panel_area, app.visual);
        }
    } else {
        render_chat(app, frame, chat);
        // Once the column is gone the next one arrives fresh, rather than sliding in silently.
        app.column_shown = false;
    }
    // The takeover covers the chat area and nothing else — the header stays readable and the input
    // line stays live, so the operator can keep typing and submitting throughout (FR-014).
    if app.overlay.is_some() {
        render_takeover(app, frame, chat);
    }
    render_input(app, frame, input);
    render_footer(app, frame, footer);

    // Chrome cues, now that the layout has assigned every region (US5, FR-026). Drained here rather
    // than queued forever: a cue describes a moment, and a moment that has passed is not owed.
    play_chrome(app, header, chat, footer);

    // Single-pane layouts have no panel column, so `p` overlays the panels above chat (US3 T036).
    if app.overlay_open() {
        render_panel_overlay(app, frame, area);
    }
    if app.help_open {
        render_help(frame, area);
    }

    // Effects transform cells that are already drawn (FR-001), so this is the last thing the frame
    // does: every widget above has painted, and ratatui flushes as soon as we return.
    app.effects.process(app.dt, frame.buffer_mut(), area);
}

/// Play the chrome cues the model queued, against the regions this frame laid out (US5, FR-026).
///
/// Every one registers unkeyed with `Origin::Chrome`, so the agent can neither trigger nor cancel
/// bee's own UI — but the motion switch silences all of it, because that axis belongs to the
/// operator (FR-006b/FR-006d).
fn play_chrome(app: &mut App, header: Rect, chat: Rect, footer: Rect) {
    if app.chrome_cues.is_empty() {
        return;
    }
    let visual = app.visual;
    for cue in std::mem::take(&mut app.chrome_cues) {
        let area = match cue {
            Chrome::Header => header,
            Chrome::Footer => footer,
            // The verdict and the tool-result flash belong to the conversation, so they play over
            // the chat area — which is where the line the operator is looking for just appeared.
            Chrome::ToolResult | Chrome::EpisodePass | Chrome::EpisodeFail | Chrome::Mascot => chat,
        };
        effects::chrome(&mut app.effects, cue, area, visual);
    }
}

/// The full-screen takeover (009 US3, T038/T039): the agent's widget over the chat area, with the
/// operator's way out pinned to the bottom row.
///
/// The hint is laid out **first** and the content gets what's left, so the escape hatch can never be
/// the thing that gets clipped (FR-015). An overlay the operator cannot see how to leave is exactly
/// the failure this feature has to not have.
///
/// A dismissing overlay draws no content: the chat below has already rendered, and the fade-out
/// effect paints the departing overlay back over it, eroding as it goes.
fn render_takeover(app: &mut App, frame: &mut Frame<'_>, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let now = std::time::Instant::now();
    let Some(overlay) = &mut app.overlay else {
        return;
    };

    if overlay.draws_content() {
        frame.render_widget(Clear, area);
        // Hint row first: `Min(0)` lets the content shrink to nothing before the hint gives up a
        // single row.
        let [body, hint_row] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
        if body.width > 0 && body.height > 0 {
            crate::viz::buffer_render::render_into(&overlay.spec, body, frame.buffer_mut());
        }
        frame.render_widget(
            Paragraph::new(Line::styled(overlay.hint(now), dim_style())),
            hint_row,
        );
        overlay.snapshot(area, frame.buffer_mut());
    }
    overlay.register(&mut app.effects, area, &app.visual);
}

/// The single-pane panel overlay (US3 T036): panels stacked in a bordered popup over the chat, so a
/// narrow terminal can still see model-owned output. Toggled with `p`, closed with `p`/`Esc`.
fn render_panel_overlay(app: &mut App, frame: &mut Frame<'_>, area: Rect) {
    let w = area.width.saturating_sub(4).clamp(20, 72);
    // Sized to the panels it holds (label row + content each, plus the popup border), not to the
    // screen: a popup showing one gauge over a 40-row terminal was a window of empty space.
    let content: u16 = app
        .panels
        .iter()
        .map(|(_, spec)| {
            crate::viz::buffer_render::spec_height(spec, w.saturating_sub(3)).saturating_add(1)
        })
        .sum();
    let h = content
        .saturating_add(2)
        .clamp(5, area.height.saturating_sub(4).max(5));
    let popup = center(area, w, h);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(role_style(ThemeRole::Info))
        .title(Span::styled(
            format!(" panels ({}) ", app.panels.len()),
            role_style_bold(ThemeRole::Info),
        ))
        .title_bottom(Span::styled(" p/Esc close ", dim_style()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    if inner.width > 0 && inner.height > 0 {
        render_panels(app, frame, inner);
    }
}

/// The working indicator's frames: a three-cell comb filling with honey and draining again — bee's
/// own spinner, not the stock braille one. Its phase comes from [`App::activity`], not a clock: it
/// advances when session events arrive and freezes when the stream stalls, so the comb *is* a
/// report of data flowing rather than an animation asserting liveness the session may not have.
const WORKING_FRAMES: [&str; 6] = ["⬡⬡⬡", "⬢⬡⬡", "⬢⬢⬡", "⬢⬢⬢", "⬡⬢⬢", "⬡⬡⬢"];

fn render_header(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let mut left = vec![Span::styled(" bee ", badge_style(ThemeRole::Info))];
    if !app.model_id.is_empty() {
        left.push(Span::styled(format!("  {}", app.model_id), dim_style()));
    }
    let mut right: Vec<Span<'_>> = Vec::new();
    if app.turn == TurnState::Streaming {
        // A motionless session gets a full, still comb: state shown, nothing moving (FR-006c's
        // spirit — the operator turned motion off, and a phase that ticks per event is motion).
        let cells = if app.visual.animations {
            WORKING_FRAMES[app.activity as usize % WORKING_FRAMES.len()]
        } else {
            "⬢⬢⬢"
        };
        right.push(Span::styled(
            format!("{cells} working "),
            role_style(ThemeRole::Info),
        ));
    }
    // Left context, right status, gap in between — one line, no border, position is the hierarchy.
    let used: usize = left
        .iter()
        .chain(right.iter())
        .map(|s| s.content.chars().count())
        .sum();
    let mut spans = left;
    spans.push(Span::raw(
        " ".repeat((area.width as usize).saturating_sub(used)),
    ));
    spans.extend(right);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_footer(app: &App, frame: &mut Frame<'_>, area: Rect) {
    // The most useful keys (contracts/keybindings.md), trimmed to what actually fits so a narrow
    // terminal never truncates mid-hint. `p` is advertised only where the overlay is the *only* way
    // to see panels — exactly the case where it matters most.
    // Hints follow the focus: the panel column has its own verbs, and advertising Enter-to-send
    // while j/k/Space/x are what the keys actually do would be the footer lying.
    let mut parts: Vec<(&str, &str)> = if app.focus == Focus::Panels {
        vec![
            ("j/k", "select"),
            ("Space", "collapse"),
            ("x", "close"),
            ("Tab", "focus"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        let show_p = !app.panels.is_empty() && app.layout_mode == LayoutMode::SinglePane;
        let mut parts: Vec<(&str, &str)> = vec![
            ("Enter", "send"),
            ("↑↓/PgUp·Dn", "scroll"),
            ("Tab", "focus"),
        ];
        if show_p {
            parts.push(("p", "panels"));
        }
        parts.extend([("y", "yank"), ("?", "help"), ("q", "quit")]);
        parts
    };

    // Shed the least essential hints first; help/quit (and the destructive `x`) always survive.
    // Width accounting mirrors the span layout below: " " lead, "key label", "   " between hints.
    let width = area.width as usize;
    let hint_len = |parts: &[(&str, &str)]| {
        2 + parts
            .iter()
            .map(|(k, l)| k.chars().count() + 1 + l.chars().count())
            .sum::<usize>()
            + parts.len().saturating_sub(1) * 3
    };
    for droppable in ["yank", "scroll", "select", "collapse", "focus"] {
        if hint_len(&parts) <= width {
            break;
        }
        parts.retain(|(_, l)| *l != droppable);
    }
    // Key in the accent, action dimmed: scannable as chords, quiet as a whole line.
    let mut spans = vec![Span::raw(" ")];
    for (i, (key, label)) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(*key, role_style(ThemeRole::Accent)));
        spans.push(Span::styled(format!(" {label}"), dim_style()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_input(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let focused = app.focus == Focus::Input;
    let border = if focused {
        role_style(ThemeRole::Accent)
    } else {
        dim_style()
    };
    // Rounded, untitled: the prompt glyph says what the box is, so a " input " label was chrome
    // spent restating the obvious. Focus is carried by border color *and* the prompt's weight.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Prompt column first, text beside it — separate rects so the wrap and cursor arithmetic on the
    // text are untouched by the marker.
    let [prompt_col, text_area] =
        Layout::horizontal([Constraint::Length(2), Constraint::Min(1)]).areas(inner);
    let prompt = if focused {
        role_style_bold(ThemeRole::Accent)
    } else {
        dim_style()
    };
    frame.render_widget(Paragraph::new(Line::styled("❯", prompt)), prompt_col);

    let text = app.input.text();
    frame.render_widget(
        Paragraph::new(text.as_str()).wrap(Wrap { trim: false }),
        text_area,
    );

    // The cursor follows its real position in the buffer (010) — ↑/↓ can now move between the soft
    // newlines Shift-Enter makes, so drawing it always at the end would misreport where typing lands.
    // Soft *wrapping* of one long line is still not tracked; only hard newlines are.
    if focused {
        let (row, col) = app.input.line_col();
        let x = text_area.x + (col as u16).min(text_area.width.saturating_sub(1));
        let y = text_area.y + (row as u16).min(text_area.height.saturating_sub(1));
        frame.set_cursor_position(Position::new(x, y));
    }
}

/// The tallest an inline widget may grow in the chat flow, so one big chart can't swallow the pane.
const MAX_INLINE_WIDGET_ROWS: u16 = 24;

/// One laid-out row-unit of the chat flow. Text is pre-wrapped to the pane width, so every `Line` is
/// exactly one row and the scroll arithmetic is exact (no hidden re-wrap by `Paragraph`).
enum Item<'a> {
    Line(Line<'static>),
    /// A row already rendered and cached on the message (010) — borrowed, not re-parsed.
    Cached(&'a Line<'static>),
    /// An inline widget, the number of rows it occupies, and its optional effect.
    Widget(&'a RenderSpec, u16, Option<&'a EffectSpec>),
}

impl Item<'_> {
    fn height(&self) -> u16 {
        match self {
            Item::Line(_) | Item::Cached(_) => 1,
            Item::Widget(_, h, _) => *h,
        }
    }
}

/// Width of the scrollbar gutter reserved on the right of the chat pane (010).
pub(crate) const CHAT_GUTTER: u16 = 1;

/// Split the scrollbar gutter off the right edge of the chat pane. Reserved unconditionally rather
/// than only while content overflows: a gutter that appeared on overflow would re-wrap the entire
/// flow at that exact moment, shifting every line sideways under the reader's eye.
fn split_gutter(area: Rect) -> (Rect, Option<Rect>) {
    if area.width <= CHAT_GUTTER {
        return (area, None);
    }
    let text = Rect {
        width: area.width - CHAT_GUTTER,
        ..area
    };
    let gutter = Rect {
        x: area.x + area.width - CHAT_GUTTER,
        width: CHAT_GUTTER,
        ..area
    };
    (text, Some(gutter))
}

fn render_chat(app: &mut App, frame: &mut Frame<'_>, area: Rect) {
    let (area, gutter) = split_gutter(area);
    let width = area.width.max(1);
    // Refresh any markdown whose cache cannot answer for this width, so the layout pass below is
    // pure lookup. Parsing the backlog every frame is what this avoids (010).
    for msg in app.chat.iter_mut() {
        msg.rendered_markdown(width);
    }
    let items = chat_items(app, width);
    let total: usize = items.iter().map(|i| usize::from(i.height())).sum();
    let height = usize::from(area.height);

    // Bottom-anchored virtualized scroll: `scroll` counts rows up from the newest. Heights here are
    // the *rendered* heights, so the newest content always lands flush against the bottom edge.
    let max_offset = total.saturating_sub(height);
    let scroll_up = app.scroll.min(max_offset);
    let top = max_offset.saturating_sub(scroll_up);
    let bottom = top.saturating_add(height);

    let mut y = 0usize; // absolute row index within the whole flow
    let mut pending_effects: Vec<(EffectSpec, Rect)> = Vec::new();
    for item in &items {
        let h = usize::from(item.height());
        let end = y.saturating_add(h);
        // Skip anything entirely above or below the visible window.
        if end > top && y < bottom {
            let skip = top.saturating_sub(y); // rows of this item hidden above the fold
            let draw_y = area.y + y.saturating_sub(top) as u16;
            let avail = (bottom.min(end) - top.max(y))
                .min(usize::from(area.bottom().saturating_sub(draw_y)))
                as u16;
            match item {
                Item::Line(l) => {
                    if avail > 0 {
                        frame.render_widget(
                            Paragraph::new(l.clone()),
                            Rect::new(area.x, draw_y, area.width, 1),
                        );
                    }
                }
                Item::Cached(l) => {
                    if avail > 0 {
                        frame.render_widget(
                            Paragraph::new((*l).clone()),
                            Rect::new(area.x, draw_y, area.width, 1),
                        );
                    }
                }
                Item::Widget(spec, wh, effect) => {
                    let widget_rect = Rect::new(area.x, draw_y, width.min(area.width), avail);
                    blit_widget(
                        frame,
                        spec,
                        *wh,
                        width,
                        area,
                        draw_y,
                        skip.min(u16::MAX as usize) as u16,
                        avail,
                    );
                    if let Some(fx) = effect {
                        pending_effects.push(((*fx).clone(), widget_rect));
                    }
                }
            }
        }
        y = end;
    }

    // One-shot effect drain: take() each widget's EffectSpec so it fires exactly once,
    // not every frame. The rects were captured during the render pass above.
    for msg in app.chat.iter_mut() {
        if let Body::Widget(_, ref mut effect @ Some(_)) = msg.body {
            effect.take();
        }
    }
    for (spec, rect) in pending_effects {
        let ctx = super::effects::ResolveCtx::agent(app.visual, rect);
        super::effects::apply(&mut app.effects, None, &spec, &ctx);
    }

    // Where the reader is in the flow. Drawn only when the conversation is taller than the pane —
    // a fully-visible conversation has no scroll position worth reporting.
    if let (Some(gutter), true) = (gutter, total > height) {
        let mut state = ScrollbarState::new(total)
            .position(top)
            .viewport_content_length(height);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(dim_style())
                .thumb_style(role_style(ThemeRole::Accent))
                .begin_symbol(None)
                .end_symbol(None),
            gutter,
            &mut state,
        );
    }
}

/// Draw an inline widget richly (the same truecolor path panels use) into the chat flow, honoring
/// partial scroll: the widget is rendered once into a scratch buffer at full height, then the visible
/// row window is blitted into the frame. This is what makes an inline `render(widget)` look like a
/// real visualization instead of a dim ASCII blob.
#[allow(clippy::too_many_arguments)]
fn blit_widget(
    frame: &mut Frame<'_>,
    spec: &RenderSpec,
    widget_rows: u16,
    width: u16,
    area: Rect,
    draw_y: u16,
    skip: u16,
    avail: u16,
) {
    if avail == 0 || width == 0 || widget_rows == 0 {
        return;
    }
    let full = Rect::new(0, 0, width, widget_rows);
    let mut scratch = Buffer::empty(full);
    crate::viz::buffer_render::render_into(spec, full, &mut scratch);

    let dst = frame.buffer_mut();
    for row in 0..avail {
        let src_y = skip + row;
        if src_y >= widget_rows {
            break;
        }
        let dy = draw_y + row;
        if dy >= area.bottom() {
            break;
        }
        for x in 0..width.min(area.width) {
            let dx = area.x + x;
            if dx >= area.right() {
                break;
            }
            dst[(dx, dy)] = scratch[(x, src_y)].clone();
        }
    }
}

/// Lay the chat out into row-units (see [`Item`]). Text wraps to the pane width; widgets get their
/// natural rendered height, capped so one chart can't fill the pane.
fn chat_items(app: &App, width: u16) -> Vec<Item<'_>> {
    let mut out: Vec<Item<'_>> = Vec::new();
    let wrap_w = width.max(8) as usize;
    for msg in &app.chat {
        // Markdown, already rendered by the refresh pass — borrowed rather than rebuilt.
        if let Some(lines) = msg.cached_markdown(width) {
            out.extend(lines.iter().map(Item::Cached));
            out.push(Item::Line(Line::raw("")));
            continue;
        }
        match &msg.body {
            // Finished assistant prose renders as markdown (010): the model writes it either way, so
            // showing it raw just litters the pane with `#` and `**`. Still-streaming prose stays
            // raw — an unclosed fence would make a half-written message flicker between code block
            // and paragraph on every delta.
            Body::Text(t) if msg.role == Role::Assistant && msg.done => {
                out.extend(
                    super::markdown::render(t, width)
                        .into_iter()
                        .map(Item::Line),
                );
            }
            // Markdown the sender declared as such (a skill body), regardless of role.
            Body::Markdown(t) => {
                out.extend(
                    super::markdown::render(t, width)
                        .into_iter()
                        .map(Item::Line),
                );
            }
            Body::Text(t) => {
                let style = line_style(msg.role);
                // The operator's own words get a gutter marker instead of a text prefix: `❯` in the
                // accent on the first row, a matching indent on wrapped rows so the message reads as
                // one block. Everything else is unmarked — tool lines already carry ▸/✓/✗ from the
                // reducer, and marking every row marks nothing.
                let user = msg.role == Role::User;
                let body_w = if user {
                    wrap_w.saturating_sub(2)
                } else {
                    wrap_w
                };
                for (i, wl) in textwrap::wrap(t, body_w.max(4)).into_iter().enumerate() {
                    let line = match (user, i) {
                        (true, 0) => Line::from(vec![
                            Span::styled("❯ ", role_style(ThemeRole::Accent)),
                            Span::styled(wl.into_owned(), style),
                        ]),
                        (true, _) => {
                            Line::from(vec![Span::raw("  "), Span::styled(wl.into_owned(), style)])
                        }
                        _ => Line::styled(wl.into_owned(), style),
                    };
                    out.push(Item::Line(line));
                }
            }
            Body::Widget(spec, effect) => {
                let h = crate::viz::buffer_render::spec_height(spec, width)
                    .clamp(1, MAX_INLINE_WIDGET_ROWS);
                out.push(Item::Widget(spec, h, effect.as_ref()));
            }
        }
        out.push(Item::Line(Line::raw(""))); // blank between messages
    }
    out
}

/// Render the right-hand panel column (008-grid-tui, US2 T028): each live panel a bordered block
/// titled with its id, stacked in insertion order and given an equal share of the column height. The
/// panel's widget is drawn richly (truecolor) into the block's inner rect via `buffer_render`, which
/// clips any overflow to the region (FR-012).
/// Smallest useful panel: its gutter label plus two content rows.
const MIN_PANEL_ROWS: u16 = 3;

/// How wide the panel column may be: 008's own sizing, narrowed by the visual level's cap (FR-011).
///
/// `min(level_cap, 008_cap)` per contracts/visual-levels.md — the level narrows the budget, it never
/// widens it. 008's own "this widget needs at least N columns" script error still fires afterward on
/// whatever budget survives; the cap changes how much room there is, not whether the check runs.
///
/// Note that 008's 50-column ceiling binds before either level cap on any terminal wide enough for a
/// two-pane layout (≥120 cols ⇒ ⌊w/3⌋ ≥ 40, and the base is clamped to 50), so `panels-wide` widens
/// nothing there today. It is not dead: it still separates the tiers on narrower surfaces, and it is
/// the tier that admits `Overlay` requests one step below takeover.
pub(crate) fn panel_column_width(cols: u16, level: crate::config::VisualLevel) -> u16 {
    let base = (cols / 3).clamp(30, 50).min(cols.saturating_sub(20));
    base.min(crate::visual_gate::panel_width_cap(level, cols))
}

/// The drawable regions this layout offers, published for the render tool's fit checks
/// (008-grid-tui). Derived with the *same* constants `view` lays out with, so the tool can never
/// accept a widget this renderer would then have to mangle.
pub fn viewport_for(app: &App) -> crate::viz::viewport::Viewport {
    let (cols, rows) = app.size;
    // Mirror `view`: header(1) + input(3) + footer(1) are chrome; the rest is the body.
    let body_rows = rows.saturating_sub(5);
    let two_pane = app.layout_mode == LayoutMode::TwoPane && !app.panels.is_empty();

    let (inline_cols, panel_w) = if two_pane {
        let pw = panel_column_width(cols, app.visual.level);
        (cols.saturating_sub(pw), pw)
    } else if app.layout_mode == LayoutMode::TwoPane {
        // No panels yet, but a column *would* be carved out as soon as one appears.
        (cols, panel_column_width(cols, app.visual.level))
    } else {
        (cols, 0)
    };

    // How many more MIN_PANEL_ROWS-sized panels the column can seat.
    let used: u16 = (app.panels.len() as u16).saturating_mul(MIN_PANEL_ROWS);
    let panel_slots_free = body_rows.saturating_sub(used) / MIN_PANEL_ROWS.max(1);

    crate::viz::viewport::Viewport {
        cols,
        rows,
        // Net of `render_chat`'s scrollbar gutter, or the tool would accept a widget one column
        // wider than the flow can actually draw (010). `cols` above stays the true terminal width.
        inline_cols: inline_cols.saturating_sub(CHAT_GUTTER),
        // Interior width/height of a panel, net of its border.
        panel_cols: panel_w.saturating_sub(2),
        panel_rows: MIN_PANEL_ROWS.saturating_sub(2).max(1),
        panel_slots_free,
        live_panels: app.panels.iter().map(|(id, _)| id.to_string()).collect(),
        full_screen: true,
        constrained: true,
    }
}

/// Draw the panel column, then let each panel claim the transition it owes (009 T018/T019).
///
/// Registration happens here rather than at upsert time because a transition needs the panel's
/// `Rect`, which only exists after this function has laid the column out. The outgoing snapshot for
/// the *next* update is taken from this frame's buffer on the way out.
fn render_panels(app: &mut App, frame: &mut Frame<'_>, area: Rect) {
    // A zero-width column is what `visual_level = none` produces (its cap is 0). Panels should never
    // reach the TUI at that level — the gate routes them inline — but drawing into no space is a
    // no-op either way, so this stays a guard rather than an assertion.
    if app.panels.is_empty() || area.height == 0 || area.width == 0 {
        return;
    }
    // Size each panel to its *content* (label + natural widget height) rather than splitting the
    // column evenly. An even split starved every panel once a few accumulated — 13 panels in 28 rows
    // left each with 3 rows showing a title and nothing else. Greedy top-down allocation keeps early
    // panels legible and reports the overflow honestly instead of silently squeezing everything.
    //
    // No box around the panel: nearly every widget draws its own titled border, so a panel border
    // put two frames between the column edge and the data — the exact nesting the clutter audit
    // caps at one. The panel's id becomes a one-row gutter label (`▍ id`) above the widget instead.
    let inner_w = area.width.saturating_sub(1).max(1);
    let mut y = area.y;
    let mut shown = 0usize;
    // Where each panel landed, so the transition pass below can register against the real Rect
    // without re-deriving the greedy layout.
    let mut placed: Vec<(String, PanelArea)> = Vec::new();

    let focused = app.focus == Focus::Panels;
    let sel = app.panel_sel.min(app.panels.len().saturating_sub(1));
    let entries: Vec<(String, bool)> = app
        .panels
        .iter_panels()
        .map(|p| (p.id.clone(), p.collapsed))
        .collect();

    for (i, (id, collapsed)) in entries.iter().enumerate() {
        let spec = app.panels.get(id).expect("panel exists this frame");
        let remaining = area.bottom().saturating_sub(y);
        // A collapsed panel is exactly its label row; an expanded one needs label + content.
        let need = if *collapsed { 1 } else { MIN_PANEL_ROWS };
        // Keep a row free for the "+N more" note if this isn't the last panel and space is tight.
        let more_after = entries.len() - shown > 1;
        let reserve = u16::from(more_after && remaining <= need + 1);
        if remaining.saturating_sub(reserve) < need {
            break;
        }
        let h = if *collapsed {
            1
        } else {
            let desired = crate::viz::buffer_render::spec_height(spec, inner_w).saturating_add(1);
            desired.clamp(MIN_PANEL_ROWS, remaining - reserve)
        };
        let rect = Rect::new(area.x, y, area.width, h);

        // The comb cell is bee's bullet: honey marker, accent id — the same two-tone the header
        // badge establishes. Filled comb = expanded, hollow = collapsed; reverse video marks the
        // selection while the column has focus (the one universally-supported selection signal).
        let marker = if *collapsed { "⬡" } else { "⬢" };
        let selected = focused && i == sel;
        let rv = |s: Style| {
            if selected {
                s.add_modifier(ratatui::style::Modifier::REVERSED)
            } else {
                s
            }
        };
        let mut label = vec![
            Span::styled(marker, rv(role_style(ThemeRole::Info))),
            Span::styled(format!(" {id}"), rv(role_style_bold(ThemeRole::Accent))),
        ];
        if *collapsed {
            label.push(Span::styled(" ⋯", rv(dim_style())));
        }
        frame.render_widget(
            Paragraph::new(Line::from(label)),
            Rect::new(rect.x, rect.y, rect.width, 1),
        );
        if !collapsed {
            let inner = Rect::new(rect.x + 1, rect.y + 1, inner_w, h - 1);
            if inner.width > 0 && inner.height > 0 {
                crate::viz::buffer_render::render_into(spec, inner, frame.buffer_mut());
            }
            // Collapsed panels register no transition and snapshot nothing — there is no content
            // region for an effect to play over.
            placed.push((id.to_string(), PanelArea { outer: rect, inner }));
        }
        y += h;
        shown += 1;
    }

    // Now that every panel has a Rect: register whatever transition it owes, then snapshot the
    // content it just drew as the outgoing half of its *next* update (FR-003, FR-004).
    let visual = app.visual;
    for (id, at) in placed {
        let Some(panel) = app.panels.get_mut(&id) else {
            continue;
        };
        panels::register_transition(panel, &mut app.effects, at, visual);
        panels::snapshot_render(panel, at.inner, frame.buffer_mut());
    }

    // Tell the truth about anything that didn't fit, and point at the way to reclaim space.
    let hidden = app.panels.len() - shown;
    if hidden > 0 {
        let note_y = area.bottom().saturating_sub(1).max(area.y);
        frame.render_widget(
            Paragraph::new(Line::styled(
                format!(" +{hidden} more — remove_panel()/clear_panels() "),
                dim_style(),
            )),
            Rect::new(area.x, note_y, area.width, 1),
        );
    }
}

fn line_style(role: Role) -> Style {
    match role {
        // Weight distinguishes the operator's words; the accent lives in the `❯` gutter marker so
        // a long user message doesn't become a wall of accent color.
        Role::User => role_style_bold(ThemeRole::Text),
        Role::Assistant => role_style(ThemeRole::Text),
        Role::System => dim_style(),
        Role::Tool => dim_style(),
    }
}

fn too_small(frame: &mut Frame<'_>, area: Rect) {
    let msg = Paragraph::new("terminal too small (min 40×10)")
        .alignment(Alignment::Center)
        .style(dim_style());
    frame.render_widget(msg, center(area, 32, 1));
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let key_col = 13usize;
    let keys = [
        ("Enter", "send message (Shift+Enter: newline)"),
        (
            "↑ ↓  wheel",
            "scroll the chat (or move within a multi-line input)",
        ),
        ("Ctrl-P/N", "previous / next input history"),
        ("PgUp PgDn", "page the chat"),
        ("gg G", "top / bottom"),
        ("Tab", "cycle focus (input · chat · panels)"),
        ("p", "toggle panel overlay (narrow layouts)"),
        ("j k  Space  x", "panels focus: select · collapse · close"),
        ("y", "yank newest message (OSC 52)"),
        ("? Esc", "close this help"),
        ("q  Ctrl-C", "quit"),
        ("Ctrl-Z", "suspend (fg to resume)"),
    ];
    // No inner heading: the box's " help " title already names it, and two labels for one popup is
    // exactly the duplicate-signal clutter the design doc tells us to cut.
    let mut lines = Vec::new();
    for (k, desc) in keys {
        lines.push(Line::from(vec![
            Span::styled(format!(" {k:<key_col$}"), role_style(ThemeRole::Accent)),
            Span::styled(desc.to_string(), Style::default()),
        ]));
    }
    // Wide enough for the longest binding line (plus borders and a right pad) — a fixed width
    // clipped descriptions mid-word on the very screen that exists to explain things.
    let w = keys
        .iter()
        .map(|(k, d)| 1 + key_col.max(k.chars().count()) + d.chars().count())
        .max()
        .unwrap_or(44) as u16
        + 3;
    let popup = center(area, w, (lines.len() as u16) + 2);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(role_style(ThemeRole::Info))
                .title(Span::styled(" help ", role_style_bold(ThemeRole::Info))),
        ),
        popup,
    );
}

/// A `w×h` rectangle centered in `area` (clamped to it).
fn center(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render_spec::RenderSpec;
    use crate::tui::chat::{ChatMessage, Role};
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::Terminal;

    // Render the view onto a fixed-size headless backend and return its symbols as text. Symbols are
    // color-independent, so these snapshots are deterministic without touching NO_COLOR (research D12).
    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).expect("test backend");
        term.draw(|f| view(app, f)).expect("draw");
        symbols(term.backend().buffer())
    }

    /// Render, then keep rendering until every transition has finished — the frame an operator
    /// actually reads. Content assertions use this: mid-animation a `stretch` or an `evolve` is
    /// *supposed* to be holding glyphs back, so asserting on frame 1 would be asserting on the
    /// moment before the UI has said anything.
    fn render_settled(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).expect("test backend");
        term.draw(|f| view(app, f)).expect("draw");
        for _ in 0..120 {
            if !app.effects.is_running() {
                break;
            }
            app.dt = std::time::Duration::from_millis(16);
            term.draw(|f| view(app, f)).expect("draw");
        }
        assert!(
            !app.effects.is_running(),
            "the UI never settled — an effect is running longer than two seconds"
        );
        symbols(term.backend().buffer())
    }

    fn symbols(buf: &Buffer) -> String {
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_header_chat_input_and_footer() {
        let mut app = App::new(80, 20);
        app.chat.push(ChatMessage::text(Role::User, "hello bee"));
        app.chat
            .push(ChatMessage::text(Role::Assistant, "hi there"));
        let out = render(&mut app, 80, 20);
        assert!(out.contains("bee"), "header missing:\n{out}");
        assert!(out.contains("❯ hello bee"), "user line missing:\n{out}");
        assert!(out.contains("hi there"), "assistant line missing:\n{out}");
        assert!(out.contains("╭"), "input border missing:\n{out}");
        assert!(out.contains("q quit"), "footer hint missing:\n{out}");
    }

    #[test]
    fn too_small_terminal_shows_a_message_not_a_broken_layout() {
        let mut app = App::new(30, 8); // below the 40×10 floor
        let out = render(&mut app, 30, 8);
        assert!(out.contains("terminal too small"), "got:\n{out}");
    }

    #[test]
    fn help_overlay_lists_keybindings() {
        let mut app = App::new(80, 20);
        app.help_open = true;
        let out = render(&mut app, 80, 20);
        assert!(out.contains("help"), "help title missing:\n{out}");
        assert!(out.contains("quit"), "help body missing:\n{out}");
    }

    // --- US2 (T030): a live panel renders beside chat, not over it ------------------------------

    #[test]
    fn panel_renders_beside_chat_in_two_pane() {
        // TwoPane needs ≥120 cols; a panel then splits off a right-hand column (FR-012).
        let mut app = App::new(120, 24);
        app.chat.push(ChatMessage::text(Role::User, "show metrics"));
        app.panels.upsert(
            "metrics",
            RenderSpec::Table {
                title: "Latency".into(),
                headers: vec!["p50".into(), "p99".into()],
                rows: vec![crate::render_spec::Row {
                    cells: vec!["12ms".into(), "88ms".into()],
                    color: None,
                }],
            },
        );
        let out = render_settled(&mut app, 120, 24);
        assert!(out.contains("metrics"), "panel title missing:\n{out}");
        assert!(out.contains("Latency"), "panel content missing:\n{out}");
        assert!(
            out.contains("❯ show metrics"),
            "chat still present beside the panel:\n{out}"
        );
    }

    #[test]
    fn inline_widget_renders_richly_not_as_ascii_placeholder() {
        // Regression: inline widgets used to go through `to_ascii()` + dim styling, so a sprite showed
        // as the literal text "[sprite 16×16]" and a table as a gray blob. They now take the same
        // truecolor buffer path panels use.
        let mut app = App::new(80, 24);
        app.chat.push(ChatMessage::widget(RenderSpec::Sprite {
            spec: crate::viz::bee::sprite(),
        }));
        let out = render(&mut app, 80, 24);
        assert!(
            !out.contains("[sprite"),
            "sprite must rasterize, not print its ASCII placeholder:\n{out}"
        );
        assert!(
            out.contains('▀') || out.contains('▄') || out.contains('█'),
            "expected half-block sprite pixels:\n{out}"
        );
    }

    #[test]
    fn newest_content_is_visible_at_the_bottom_past_a_tall_widget() {
        // Regression: chat heights were counted pre-wrap while `Paragraph` re-wrapped at draw time,
        // so once a tall/wide widget entered the flow the bottom-anchoring drifted and the newest
        // lines fell off-screen. Heights are now the rendered heights.
        let mut app = App::new(80, 20);
        for i in 0..30 {
            app.chat.push(ChatMessage::text(
                Role::Assistant,
                format!("filler line {i}"),
            ));
        }
        app.chat.push(ChatMessage::widget(RenderSpec::BarChart {
            title: "big chart".into(),
            bars: (0..8)
                .map(|i| crate::render_spec::Bar {
                    label: format!("bar-{i}"),
                    value: i * 10,
                })
                .collect(),
            x_label: None,
            y_label: None,
            color: None,
        }));
        app.chat
            .push(ChatMessage::text(Role::Assistant, "THE NEWEST LINE"));
        let out = render(&mut app, 80, 20);
        assert!(
            out.contains("THE NEWEST LINE"),
            "newest message must be visible at the bottom:\n{out}"
        );
    }

    #[test]
    fn a_collapsed_panel_shows_its_label_and_none_of_its_content() {
        let mut app = App::new(120, 24);
        app.panels.upsert(
            "metrics",
            RenderSpec::Text {
                content: "CPU 82%".into(),
                style: None,
                bold: false,
                dim: false,
            },
        );
        let open = render_settled(&mut app, 120, 24);
        assert!(open.contains("⬢ metrics"), "expanded marker:\n{open}");
        assert!(open.contains("CPU 82%"), "content shown:\n{open}");

        app.panels.toggle_collapse_at(0);
        let folded = render_settled(&mut app, 120, 24);
        assert!(folded.contains("⬡ metrics"), "hollow marker:\n{folded}");
        assert!(
            !folded.contains("CPU 82%"),
            "content hidden while folded:\n{folded}"
        );
    }

    #[test]
    fn overflowing_panels_report_what_is_hidden() {
        // Many panels no longer get squeezed to unreadable 3-row slivers in silence: the ones that
        // fit render at content height, and the column says how many are hidden.
        let mut app = App::new(120, 24);
        for i in 0..12 {
            app.panels.upsert(
                format!("panel-{i}"),
                RenderSpec::Table {
                    title: format!("t{i}"),
                    headers: vec!["a".into()],
                    rows: vec![crate::render_spec::Row {
                        cells: vec!["1".into()],
                        color: None,
                    }],
                },
            );
        }
        let out = render_settled(&mut app, 120, 24);
        assert!(out.contains("more"), "overflow note missing:\n{out}");
        assert!(
            out.contains("remove_panel") || out.contains("clear_panels"),
            "note should point at the way to reclaim space:\n{out}"
        );
    }

    // --- US3 (T032): responsive layouts, the overlay, and NO_COLOR --------------------------------

    #[test]
    fn narrow_terminal_hides_the_panel_column_and_the_overlay_brings_panels_back() {
        // Below 120 cols there is no room for a side-by-side column, so panels are invisible until
        // `p` opens the overlay (T036) — the gap that made panel output unreachable on a narrow term.
        let mut app = App::new(80, 24);
        app.chat.push(ChatMessage::text(Role::User, "hello"));
        app.panels.upsert(
            "metrics",
            RenderSpec::Text {
                content: "CPU 82%".into(),
                style: None,
                bold: false,
                dim: false,
            },
        );
        assert_eq!(app.layout_mode, LayoutMode::SinglePane);

        let closed = render(&mut app, 80, 24);
        assert!(
            !closed.contains("CPU 82%"),
            "panel hidden while the overlay is closed:\n{closed}"
        );

        app.panels_visible = true;
        let open = render(&mut app, 80, 24);
        assert!(
            open.contains("CPU 82%"),
            "overlay reveals the panel:\n{open}"
        );
        assert!(open.contains("panels"), "overlay is labelled:\n{open}");
    }

    #[test]
    fn the_overlay_is_single_pane_only() {
        // In TwoPane the panels already have a column, so `p` must not stack an overlay on top.
        let mut app = App::new(140, 40);
        app.panels.upsert("m", RenderSpec::Separator);
        app.panels_visible = true;
        assert_eq!(app.layout_mode, LayoutMode::TwoPane);
        assert!(!app.overlay_open(), "no overlay when a real column exists");
    }

    #[test]
    fn a_wide_but_short_terminal_stays_single_pane() {
        // 120+ cols but under 24 rows has no vertical room for panels beside chat (T034).
        assert_eq!(LayoutMode::from_size(160, 20), LayoutMode::SinglePane);
        assert_eq!(LayoutMode::from_size(160, 24), LayoutMode::TwoPane);
    }

    #[test]
    fn every_region_still_renders_without_color() {
        // NO_COLOR degrades to monochrome but must never blank a region (FR-014, SC-005). Symbols are
        // color-independent, so a matching symbol grid proves the layout survives unstyled.
        let mut app = App::new(120, 24);
        app.chat.push(ChatMessage::text(Role::User, "hello bee"));
        app.panels.upsert(
            "metrics",
            RenderSpec::Text {
                content: "CPU 82%".into(),
                style: None,
                bold: false,
                dim: false,
            },
        );
        let out = render_settled(&mut app, 120, 24);
        for expected in ["bee", "❯ hello bee", "metrics", "CPU 82%", "╭", "q quit"] {
            assert!(out.contains(expected), "{expected:?} missing:\n{out}");
        }
    }

    #[test]
    fn the_footer_advertises_yank_always_and_p_only_when_the_overlay_is_the_way_in() {
        // Wide + no panels: no reason to mention `p`.
        let mut wide = App::new(120, 24);
        let out = render(&mut wide, 120, 24);
        assert!(out.contains("y yank"), "yank hint missing:\n{out}");
        assert!(!out.contains("p panels"), "no overlay to advertise:\n{out}");

        // Narrow + panels: the overlay is the only way to see them, so `p` is advertised.
        let mut narrow = App::new(80, 24);
        narrow.panels.upsert("m", RenderSpec::Separator);
        let out = render(&mut narrow, 80, 24);
        assert!(out.contains("p panels"), "overlay hint missing:\n{out}");
    }

    #[test]
    fn the_footer_never_truncates_mid_hint_on_a_narrow_terminal() {
        // It sheds low-priority hints rather than getting cut off; quit must always survive.
        let mut app = App::new(50, 20);
        app.panels.upsert("m", RenderSpec::Separator);
        let out = render(&mut app, 50, 20);
        let footer = out.lines().last().unwrap_or_default();
        assert!(
            footer.contains("q quit"),
            "quit hint must survive:\n{footer}"
        );
        assert!(
            footer.chars().filter(|c| !c.is_whitespace()).count() > 0,
            "footer is not blank"
        );
    }

    #[test]
    fn panel_column_appears_only_when_populated() {
        // Same app, same size: the right-hand column exists only once a panel is upserted, so a US1
        // session (no panels) renders exactly as before — chat keeps the full width.
        let base = || {
            let mut a = App::new(120, 24);
            a.chat.push(ChatMessage::text(Role::Assistant, "hi"));
            a
        };
        let empty = render_settled(&mut base(), 120, 24);
        assert!(
            !empty.contains("metrics"),
            "no panel title when empty:\n{empty}"
        );

        let mut with = base();
        with.panels.upsert("metrics", RenderSpec::Separator);
        let populated = render_settled(&mut with, 120, 24);
        assert!(
            populated.contains("metrics"),
            "panel appears once populated:\n{populated}"
        );
        assert_ne!(empty, populated, "the panel column changes the layout");
    }

    // --- 009 US1 (T018/T020): the render path is what puts effects on screen ---------------------

    #[test]
    fn drawing_a_new_panel_registers_its_entrance_and_snapshots_what_it_drew() {
        // The whole US1 loop through the real renderer: layout assigns the panel a Rect, the
        // transition is registered against it, and the drawn content is kept as the outgoing half of
        // the next update.
        let mut app = App::new(120, 24);
        app.panels.upsert("metrics", RenderSpec::Separator);
        assert!(!app.effects.is_running(), "nothing animates before a frame");

        render(&mut app, 120, 24);
        assert!(app.effects.is_running(), "the panel entered");
        let panel = app.panels.get_mut("metrics").expect("panel");
        assert!(panel.pending.is_none(), "the transition was consumed");
        assert!(
            panel.fx.prev.is_some(),
            "the drawn content is the next update's outgoing half"
        );
    }

    // --- 009 US2 (T030/T034/T035): the level bounds what the agent gets ------------------------

    fn with_level(level: crate::config::VisualLevel) -> crate::config::VisualConfig {
        crate::config::VisualConfig {
            level,
            ..crate::config::VisualConfig::default()
        }
    }

    #[test]
    fn the_panel_column_never_exceeds_the_levels_share_of_the_screen() {
        // SC-005, measured on the real Rect the layout hands the column. `panels` is a third,
        // `panels-wide` a half — and 008's own sizing still narrows it further where it is stricter.
        for cols in [120u16, 160, 200] {
            let third = cols / 3;
            let half = cols / 2;
            assert!(
                panel_column_width(cols, crate::config::VisualLevel::Panels) <= third,
                "panels exceeded a third at {cols} cols"
            );
            assert!(
                panel_column_width(cols, crate::config::VisualLevel::PanelsWide) <= half,
                "panels-wide exceeded a half at {cols} cols"
            );
        }
    }

    #[test]
    fn a_wider_level_is_never_narrower_than_a_stricter_one() {
        // The tiers are a ceiling, so they must be monotonic. On a two-pane terminal 008's own
        // 50-column ceiling binds before either level cap, which is why these are `<=` and why
        // `panels-wide` widens nothing at these sizes — it separates the tiers on narrower
        // surfaces, and it is the tier one step below takeover.
        for cols in [120u16, 160, 200] {
            let strict = panel_column_width(cols, crate::config::VisualLevel::Panels);
            let wide = panel_column_width(cols, crate::config::VisualLevel::PanelsWide);
            assert!(strict <= wide, "tiers inverted at {cols} cols");
        }
        assert_eq!(
            panel_column_width(80, crate::config::VisualLevel::Panels),
            26,
            "below 008's clamp the level cap is what binds"
        );
        assert_eq!(
            panel_column_width(80, crate::config::VisualLevel::PanelsWide),
            30
        );
    }

    #[test]
    fn level_none_leaves_no_column_for_the_agent_at_all() {
        // FR-010: the gate routes panels inline before they ever reach the TUI, and even if one
        // arrived anyway there is no width for it to occupy.
        assert_eq!(panel_column_width(120, crate::config::VisualLevel::None), 0);
        let mut app = App::new(120, 24).with_visual(with_level(crate::config::VisualLevel::None));
        app.panels.upsert("metrics", RenderSpec::Separator);
        let out = render(&mut app, 120, 24);
        assert!(
            !out.contains("metrics"),
            "no panel column at level none:\n{out}"
        );
        assert_eq!(
            viewport_for(&app).panel_cols,
            0,
            "and the render tool is told so"
        );
    }

    #[test]
    fn level_none_strips_agent_effects_while_chrome_keeps_moving() {
        // FR-006d / FR-024 / T031: the level governs the agent. Motion is a separate axis, so
        // bee's own chrome is untouched by it.
        let visual = with_level(crate::config::VisualLevel::None);
        let area = Rect::new(0, 0, 20, 5);
        let spec = crate::tui::effects::panel_enter_spec();
        assert!(
            crate::tui::effects::resolve(
                &spec,
                &crate::tui::effects::ResolveCtx::agent(visual, area)
            )
            .is_none(),
            "an agent effect is stripped entirely"
        );
        assert!(
            crate::tui::effects::resolve(
                &spec,
                &crate::tui::effects::ResolveCtx::chrome(visual, area)
            )
            .is_some(),
            "chrome is bee's own UI, not the agent's"
        );
    }

    // --- 010: markdown in the chat pane ---------------------------------------------------------

    #[test]
    fn settled_assistant_prose_renders_as_markdown_and_streaming_prose_does_not() {
        let mut app = App::new(120, 40);
        app.chat
            .push(ChatMessage::text(Role::Assistant, "a **bold** claim"));

        // Still streaming: shown verbatim, because an unclosed fence would make the message flicker
        // between code block and paragraph on every delta.
        let open = render_settled(&mut app, 60, 12);
        assert!(open.contains("**bold**"), "raw while open:\n{open}");

        // Closed: the markup became style, so the asterisks are gone from the glyphs.
        app.chat.last_mut().unwrap().mark_done();
        let closed = render_settled(&mut app, 60, 12);
        assert!(closed.contains("bold"), "the word survived:\n{closed}");
        assert!(
            !closed.contains("**"),
            "the asterisks became weight:\n{closed}"
        );
    }

    #[test]
    fn a_declared_markdown_block_renders_styled_whatever_its_role() {
        // A skill body arrives as System-role markdown; it is rendered because the *sender* said it
        // is markdown, not because anything sniffed the content.
        let mut app = App::new(120, 40);
        app.chat.push(ChatMessage::markdown(
            Role::System,
            "# Skill\n\nuse **care**",
        ));
        let out = render_settled(&mut app, 60, 12);
        assert!(out.contains("Skill"), "heading text present:\n{out}");
        assert!(out.contains("care"));
        assert!(!out.contains("**"), "emphasis became style:\n{out}");
    }

    #[test]
    fn only_assistant_prose_is_treated_as_markdown() {
        // A tool result that happens to contain `**` is data, not markup — rendering it as markdown
        // would silently eat characters out of a command's output.
        let mut app = App::new(120, 40);
        app.chat
            .push(ChatMessage::text(Role::Tool, "✓ grep found **match**"));
        let out = render_settled(&mut app, 60, 12);
        assert!(out.contains("**match**"), "left verbatim:\n{out}");
    }

    #[test]
    fn the_published_viewport_reflects_the_level_so_the_tool_sizes_to_it() {
        // The render tool checks widgets against `panel_cols`; if that were the un-capped width the
        // tool would accept a widget the renderer then had to mangle.
        let mut app = App::new(120, 24).with_visual(with_level(crate::config::VisualLevel::Panels));
        app.panels.upsert("m", RenderSpec::Separator);
        let vp = viewport_for(&app);
        assert!(vp.panel_cols > 0 && vp.panel_cols <= 120 / 3);
        // Net of the panel column *and* the scrollbar gutter (010): `inline_cols` is what the chat
        // flow can actually draw into, not the width of the region it was handed.
        assert_eq!(vp.inline_cols, 120 - (vp.panel_cols + 2) - CHAT_GUTTER);
        assert_eq!(
            vp.cols, 120,
            "the reported terminal width is still the truth"
        );
    }

    // --- 009 US3 (T038/T039/T044/T046): the takeover and its escape hatch ----------------------

    fn with_takeover(cols: u16, rows: u16, ttl_ms: Option<u32>) -> App {
        let mut app = App::new(cols, rows);
        app.show_overlay(
            RenderSpec::Text {
                content: "TAKEOVER-BODY".into(),
                style: None,
                bold: false,
                dim: false,
            },
            ttl_ms,
            std::time::Instant::now(),
        );
        app
    }

    #[test]
    fn the_takeover_covers_chat_but_never_the_input_line() {
        // FR-014: the operator keeps typing throughout, so the input border and its contents must
        // still be on screen with a full-screen overlay up.
        let mut app = with_takeover(100, 24, Some(30_000));
        app.input.insert_str("still typing");
        let out = render(&mut app, 100, 24);
        assert!(out.contains("TAKEOVER-BODY"), "overlay content:\n{out}");
        assert!(out.contains("❯"), "the input prompt survives:\n{out}");
        assert!(out.contains("still typing"), "and so does the text:\n{out}");
        assert!(out.contains("bee"), "the header is never covered:\n{out}");
    }

    #[test]
    fn the_dismiss_hint_sits_in_the_overlays_last_row() {
        // FR-015. The hint's position is fixed so the operator never has to hunt for it.
        let mut app = with_takeover(100, 24, Some(12_000));
        let out = render(&mut app, 100, 24);
        let lines: Vec<&str> = out.lines().collect();
        // header(1) + chat(fill) + input(3) + footer(1): the overlay's last row is the one directly
        // above the input block.
        let hint_row = lines.len() - 5;
        assert!(
            lines[hint_row].contains("Esc to dismiss"),
            "hint not in the overlay's last row (row {hint_row}):\n{out}"
        );
        assert!(
            lines[hint_row].contains("auto-dismiss in 12s"),
            "countdown missing:\n{out}"
        );
    }

    #[test]
    fn the_hint_wins_the_last_row_even_when_the_content_has_no_room() {
        // The escape hatch must never be the thing that gets clipped, so it is laid out before the
        // content rather than after it.
        let mut app = with_takeover(60, 10, Some(5_000));
        let out = render(&mut app, 60, 10);
        assert!(out.contains("Esc to dismiss"), "hint dropped:\n{out}");
    }

    #[test]
    fn the_hint_is_present_without_color_just_unstyled() {
        // SC-010's shape for the overlay: `NO_COLOR` removes the dim treatment, never the text.
        let mut app = with_takeover(100, 24, Some(8_000));
        let out = render(&mut app, 100, 24);
        assert!(out.contains("Esc to dismiss"), "{out}");
    }

    #[test]
    fn a_dismissed_takeover_gives_the_chat_back() {
        // SC-006/FR-018: one frame after the dismissal completes, the chat is on screen again.
        let mut app = with_takeover(100, 24, Some(30_000));
        app.chat
            .push(ChatMessage::text(Role::Assistant, "underlying chat"));
        let covered = render(&mut app, 100, 24);
        assert!(!covered.contains("underlying chat"), "covered:\n{covered}");

        let now = std::time::Instant::now();
        app.overlay.as_mut().expect("overlay").dismiss(now);
        app.advance_overlay(now + std::time::Duration::from_millis(250));
        assert!(app.overlay.is_none(), "the fade-out finished");

        let restored = render(&mut app, 100, 24);
        assert!(
            restored.contains("underlying chat"),
            "the chat is back:\n{restored}"
        );
        assert!(!restored.contains("TAKEOVER-BODY"), "{restored}");
    }

    #[test]
    fn an_expired_takeover_is_gone_from_the_buffer() {
        // SC-007: absent after ttl + the 200ms fade.
        let t0 = std::time::Instant::now();
        let mut app = App::new(100, 24);
        app.show_overlay(
            RenderSpec::Text {
                content: "TAKEOVER-BODY".into(),
                style: None,
                bold: false,
                dim: false,
            },
            Some(1_000),
            t0,
        );
        app.advance_overlay(t0 + std::time::Duration::from_millis(1_250));
        assert!(app.overlay.is_none(), "expired and faded out");
        let out = render(&mut app, 100, 24);
        assert!(!out.contains("TAKEOVER-BODY"), "{out}");
    }

    #[test]
    fn a_zero_height_chat_area_makes_the_takeover_a_no_op() {
        // Spec edge case: no room is not a crash. Below the hard floor the layout shows the
        // too-small message and the overlay never gets an area at all.
        let mut app = with_takeover(30, 8, Some(5_000));
        let out = render(&mut app, 30, 8);
        assert!(out.contains("terminal too small"), "{out}");
    }

    #[test]
    fn a_motionless_session_draws_panels_with_no_effect_at_all() {
        // FR-006c end to end: same frame, same panel, nothing registered — so the loop has nothing
        // to advance and the operator sees final content immediately.
        let mut app = App::new(120, 24).with_visual(crate::config::VisualConfig {
            animations: false,
            ..crate::config::VisualConfig::default()
        });
        app.panels.upsert("metrics", RenderSpec::Separator);
        let out = render(&mut app, 120, 24);
        assert!(!app.effects.is_running(), "no motion may be registered");
        assert!(out.contains("metrics"), "the panel is on screen regardless");
    }
}
