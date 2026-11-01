# A model-defined N×M grid (grid-tui, M1): three gauges across the top row, a full-width results
# table spanning all three columns of the bottom row. Cells hold any widget spans union their
# tracks. The model picks the dimensions and fills the cells it wants.
g = grid(2, 3)

cpu = gauge("CPU", 0.82)
cpu.color("honey")
g.cell(0, 0, cpu)

mem = gauge("MEM", 0.51)
mem.color("honey")
g.cell(0, 1, mem)

net = gauge("NET", 0.13)
net.color("royal")
g.cell(0, 2, net)

t = table("recent")
t.header(["host", "status"])
t.row_colored(["web-1", "ok"], "pollen")
t.row_colored(["web-2", "down"], "sting")
g.span(1, 0, 1, 3, t) # row, col, row_span, col_span, widget

render(g)
