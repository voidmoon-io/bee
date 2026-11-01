# A simple bar chart (003-visual-render, US6). The model gathers data via earlier tool calls, then
# declares a visualization by calling the `render` tool with a script like this.
c = bar_chart("File Sizes (KB)")
c.bar("main.rs", 340)
c.bar("lib.rs", 120)
c.bar("tools.rs", 88)
c.bar("repl.rs", 210)
c.bar("viz.rs", 64)
c.color("honey")
render(c)
