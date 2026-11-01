# A composed dashboard (003-visual-render, US6): a vertical split stacking a progress gauge over a
# results table. Layouts nest up to depth 3.
g = gauge("Coverage", 0.82)
g.color("pollen")

t = table("Test Results")
t.header(["suite", "pass", "fail"])
t.row(["viz", "12", "0"])
t.row_colored(["render", "8", "1"], "sting")
t.row(["chrome", "6", "0"])

dash = vsplit()
dash.add(g)
dash.add(t)
render(dash)
