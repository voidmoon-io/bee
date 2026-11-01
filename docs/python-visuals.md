# Python visual scripting

The `render` tool accepts Python interpreted by Monty 1.4.0. Rhai scripts are no longer accepted. No CPython installation or Python packages are required. Recorded `RenderSpec` values still replay without executing the original script.

```python
chart = bar_chart("File sizes")
for name, size in [("main.rs", 340), ("lib.rs", 120)]:
    chart.bar(name, size)
render(chart)
```

The [drawing API supplied to the model](../src/python/visual-api.txt) lists the available widgets and effects. Runnable examples live in [visual examples](../specs/003-visual-render/examples) and [effect examples](../specs/009-tachyonfx-effects/examples).

## Migrating scripts

Remove `let`, use `True` and `False`, replace braces with indented Python blocks, and use `range(start, end)` for loops. Replace `//` comments with `#`. Dot-grid `.pass(label)` becomes `.passed(label)` because `pass` is a Python keyword. Existing chart, grid, sprite, panel and effect function names remain available, including `.row_colored(values, color)`.

Monty supports a subset of Python. Imports of arbitrary packages, class inheritance, filesystem access, environment access, network access and subprocesses are unavailable. Visual scripts cannot call tools. Use earlier tool results to construct the visualization.

## Execution and limits

Each render runs in a fresh, disposable `bee python-worker` child in the session's sandbox. The hidden worker is part of the same executable. Enforced policies must permit executing the Bee binary, as with the other native workers; this change adds no implicit grants. The parent applies a three-second wall-clock timeout and bounded process I/O; the interpreter has a one-second execution budget, a 64 MiB memory budget and a recursion limit. Cancellation terminates and reaps the child using Bee's subprocess owner. On Linux a parent-death guard is installed before exec so the worker cannot survive its supervisor.

Source is limited to 64 KiB and returned JSON to 1 MiB. Rust validates the resulting visuals independently of the Python builders: 500 elements per widget tree, nesting depth four, grids up to 12×12 with 64 cells, sprites up to 32×32, and animations up to 16 frames. Viewport fit checks and the existing visual permission gate still apply. Python exceptions return a tool error without publishing partially produced visuals. `print` output is discarded; the tool returns the visual's text summary to the model.

The worker also supports suspended `call_tool` continuations for codemode. That protocol is not itself authorization to run a tool: durable admission, budget accounting and recovery belong to the session driver. Durable sessions now schedule sequential calls to registered `read_file`, `list_directory` and `search` tools; see [implementation status](../specs/023-codemode/implementation.md).
