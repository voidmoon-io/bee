# Python drawing builders. Rust validates the complete output before presentation.
import copy

_bee_output = {"inline": None, "inline_effect": None, "overlay": None, "panel_ops": [], "render_calls": 0}

def _copy(value):
    return copy.deepcopy(value)

def _spec(widget):
    value = _copy(widget.data)
    if value["kind"] == "animation":
        return {"kind": "sprite", "spec": value["spec"]["frames"][0]}
    return value

class Widget:
    def __init__(self, kind, **fields):
        self.data = {"kind": kind, **fields}
        self.transition = None
    def effect(self, value):
        self.transition = value
    def color(self, value):
        self.data["style" if self.data["kind"] == "text" else "color"] = value
    def style(self, value):
        self.color(value)
    def bold(self):
        self.data["bold"] = True
    def dim(self):
        self.data["dim"] = True
    def label(self, value):
        self.data["label"] = value
    def x_label(self, value):
        self.data["x_label"] = value
    def y_label(self, value):
        self.data["y_label"] = value
    def bar(self, label, value):
        self.data["bars"].append({"label": label, "value": int(value)})
    def series(self, label):
        points = []
        self.data["series"].append({"label": label, "points": points})
        return Series(points)
    def header(self, values):
        self.data["headers"] = [str(v) for v in values]
    def row(self, first, second=None):
        if self.data["kind"] == "heatmap":
            self.data["rows"].append({"label": first, "values": second})
        else:
            self.data["rows"].append({"cells": [str(v) for v in first], "color": second})
    def row_colored(self, values, color):
        self.row(values, color)
    def clone(self):
        return _copy(self)
    def passed(self, label):
        self.data["dots"].append({"label": label, "state": "pass"})
    def fail(self, label):
        self.data["dots"].append({"label": label, "state": "fail"})
    def skip(self, label):
        self.data["dots"].append({"label": label, "state": "skip"})
    def line(self, text, level=None):
        self.data["lines"].append({"text": text, "level": level})
    def max_rows(self, value):
        self.data["max_rows"] = max(1, min(100, value))
    def add(self, widget):
        if self.data["kind"] == "animation":
            frames = self.data["spec"]["frames"]
            frame = _copy(widget.data["spec"])
            if len(frames) >= 16:
                raise ValueError("animation max 16 frames")
            if frames and (frame["width"] != frames[0]["width"] or frame["height"] != frames[0]["height"]):
                raise ValueError("animation frames must have matching dimensions")
            frames.append(frame)
        else:
            self.data["children"].append(_spec(widget))
    def bounce(self, value):
        self.data["spec"]["bounce"] = value
    def cycles(self, value):
        self.data["spec"]["cycles"] = max(0, value)
    def cell(self, row, col, widget):
        self.span(row, col, 1, 1, widget)
    def span(self, row, col, rows, cols, widget):
        if min(row, col) < 0 or min(rows, cols) < 1 or row+rows > self.data["rows"] or col+cols > self.data["cols"]:
            raise ValueError("grid cell exceeds bounds")
        for cell in self.data["cells"]:
            if row < cell["row"]+cell["row_span"] and cell["row"] < row+rows and col < cell["col"]+cell["col_span"] and cell["col"] < col+cols:
                raise ValueError("grid cells overlap")
        self.data["cells"].append({"row": row, "col": col, "row_span": rows, "col_span": cols, "content": _spec(widget)})
    def col_weights(self, values):
        self.data["col_weights"] = [max(1, min(65535, v)) for v in values]
    def row_weights(self, values):
        self.data["row_weights"] = [max(1, min(65535, v)) for v in values]
    def gap(self, value):
        self.data["gap"] = max(0, min(4, value))

class Series:
    def __init__(self, points):
        self.points = points
    def point(self, x, y):
        self.points.append({"x": x, "y": y})

def bar_chart(title): return Widget("bar_chart", title=title, bars=[])
def line_chart(title): return Widget("line_chart", title=title, series=[])
def scatter(title): return Widget("scatter_plot", title=title, series=[])
def area_chart(title): return Widget("area_chart", title=title, series=[])
def heatmap(title): return Widget("heatmap", title=title, rows=[])
def sparkline(title, data): return Widget("sparkline", title=title, data=[max(0, int(v)) for v in data])
def table(title): return Widget("table", title=title, headers=[], rows=[])
def gauge(title, value): return Widget("gauge", title=title, value=max(0.0, min(1.0, value)))
def dots(title): return Widget("dot_grid", title=title, dots=[])
def text(content): return Widget("text", content=content, bold=False, dim=False)
def markdown(content): return Widget("markdown", content=content)
def ascii_art(lines): return Widget("ascii_art", lines=lines)
def separator(): return Widget("separator")
def log_tail(title): return Widget("log_tail", title=title, lines=[], max_rows=8)
def vsplit(): return Widget("layout", direction="vertical", children=[])
def hsplit(): return Widget("layout", direction="horizontal", children=[])
def grid(rows, cols):
    if min(rows, cols) < 1 or max(rows, cols) > 12: raise ValueError("grid dimensions must be 1..=12")
    return Widget("grid", rows=rows, cols=cols, cells=[], gap=1)

def _color(value):
    if value == "transparent": return None
    if len(value) != 7 or value[0] != "#": raise ValueError("invalid hex color")
    try:
        return [int(value[i:i+2], 16) for i in [1, 3, 5]]
    except ValueError:
        raise ValueError("invalid hex color")

class Palette:
    def __init__(self): self.colors = {}
    def set(self, key, value):
        if len(key) != 1: raise ValueError("palette key must be one character")
        if key not in self.colors and len(self.colors) >= 32: raise ValueError("palette max 32 entries")
        self.colors[key] = _color(value)

def palette(): return Palette()

class Sprite:
    def effect(self, value):
        self.transition = value
    def clone(self):
        return _copy(self)
    def __init__(self, width, height, pal):
        if min(width, height) < 1 or max(width, height) > 32: raise ValueError("sprite dimensions must be 1..=32")
        self.data = {"kind": "sprite", "spec": {"width": width, "height": height, "pixels": [None]*(width*height)}}
        self.transition = None
        self.colors = _copy(pal.colors)
    def paint(self, rows):
        spec = self.data["spec"]
        for y, row in enumerate(rows[:spec["height"]]):
            for x, key in enumerate(row[:spec["width"]]):
                spec["pixels"][y*spec["width"]+x] = self.colors.get(key)
    def set(self, x, y, color):
        spec = self.data["spec"]
        if x < 0 or y < 0 or x >= spec["width"] or y >= spec["height"]: raise ValueError("pixel exceeds bounds")
        spec["pixels"][y*spec["width"]+x] = _color(color)
    def fill(self, color):
        spec = self.data["spec"]
        spec["pixels"] = [_color(color)]*(spec["width"]*spec["height"])

def sprite(width, height, pal): return Sprite(width, height, pal)
def animation(ms): return Widget("animation", spec={"frames": [], "interval_ms": max(50, min(1000, ms)), "bounce": False, "cycles": 1})
def bee_sprite(): return Widget("sprite", spec=_copy(_bee_sprite))
def bee_animation(): return Widget("animation", spec=_copy(_bee_animation))

def _effect(kind, ms, direction=None, color=None):
    value = {"kind": kind, "ms": max(100, min(2000, ms))}
    if direction is not None: value["direction"] = direction if direction in ["left", "right", "top", "bottom"] else "left"
    if color is not None: value["color"] = color
    return value

def fade_in(ms): return _effect("fade_in", ms)
def fade_out(ms): return _effect("fade_out", ms)
def dissolve_in(ms): return _effect("dissolve_in", ms)
def dissolve_out(ms): return _effect("dissolve_out", ms)
def evolve_in(ms): return _effect("evolve_in", ms)
def evolve_out(ms): return _effect("evolve_out", ms)
def slide_in(direction, ms): return _effect("slide_in", ms, direction)
def slide_out(direction, ms): return _effect("slide_out", ms, direction)
def sweep_in(direction, ms): return _effect("sweep_in", ms, direction)
def sweep_out(direction, ms): return _effect("sweep_out", ms, direction)
def pulse(color, ms): return _effect("pulse", ms, color=color)
def glow(ms): return _effect("glow", ms)

def render(widget):
    _bee_output["inline"] = _copy(widget.data)
    _bee_output["inline_effect"] = _copy(widget.transition)
    _bee_output["render_calls"] += 1

def render_to(panel_id, widget): render_to_ttl(panel_id, widget, None)
def render_to_ttl(panel_id, widget, ttl_ms):
    if ttl_ms is not None and ttl_ms <= 0: raise ValueError("TTL must be positive")
    _bee_output["panel_ops"].append({"op": "upsert", "id": panel_id, "spec": _copy(widget.data), "effect": _copy(widget.transition), "ttl_ms": None if ttl_ms is None else min(86400000, ttl_ms)})
    _bee_output["render_calls"] += 1

def remove_panel(panel_id): _bee_output["panel_ops"].append({"op": "remove", "id": panel_id})
def clear_panels(): _bee_output["panel_ops"].append({"op": "clear"})
def render_fullscreen(widget): render_fullscreen_ttl(widget, None)
def render_fullscreen_ttl(widget, ttl_ms):
    if ttl_ms is not None and ttl_ms <= 0: raise ValueError("TTL must be positive")
    _bee_output["overlay"] = [_copy(widget.data), None if ttl_ms is None else min(86400000, ttl_ms), _copy(widget.transition)]
    _bee_output["render_calls"] += 1
