# Model-owned live panels (008-grid-tui, US2 quickstart Scenario B). The model addresses a widget
# to a NAMED panel with render_to(panel_id, widget) instead of render(widget). The panel persists
# beside the chat flow, and re-rendering the same id ("metrics") replaces it in place across turns —
# no scrollback churn, no duplicate panels. Untargeted render() still commits inline into chat.
#
# panel_id must be 1-32 chars of [a-z0-9_-] a bad id is a script error (fail-closed).
#
# Panel lifecycle — panels share one column, so each extra panel shrinks the rest:
#   render_to(id, w)               create or replace in place
#   render_to_ttl(id, w, ttl_ms)   same, but auto-expires
#   remove_panel(id)               close one panel, reclaim its space
#   clear_panels()                 close every panel
# A single script may address several panels, and mix panel and inline output.

# Stale panels from an earlier run: reclaim their space first.
remove_panel("scratch")

g = grid(2, 2)

p50 = gauge("p50", 0.24)
p50.label("120ms")
p50.color("pollen")
g.cell(0, 0, p50)

p99 = gauge("p99", 0.71)
p99.label("880ms")
p99.color("honey")
g.cell(0, 1, p99)

errs = table("errors")
errs.header(["route", "5xx"])
errs.row_colored(["/checkout", "3"], "sting")
errs.row_colored(["/search", "0"], "pollen")
g.span(1, 0, 1, 2, errs) # full-width bottom row

render_to("metrics", g) # → the "metrics" panel, updated in place on every re-render

# A transient note that disappears on its own after 10s — no cleanup call needed.
note = text("deploy started")
note.color("royal")
render_to_ttl("deploy", note, 10000)

# And something inline in the chat flow, in the same script.
render(text("metrics panel refreshed"))
