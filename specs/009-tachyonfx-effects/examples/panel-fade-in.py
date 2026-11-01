# The default case: no effect requested at all.
#
# A panel appearing for the first time fades in on its own, and replacing its content
# dissolves the old into the new. That is FR-003/FR-004 — the model does not ask for it
# and cannot forget it, which is the point. Reach for `effect()` only when the motion
# carries meaning the default cannot.

chart = bar_chart("CPU usage")
chart.bar("core-0", 72)
chart.bar("core-1", 55)
chart.bar("core-2", 61)
chart.bar("core-3", 48)
chart.color("honey")

render_to("metrics", chart)
