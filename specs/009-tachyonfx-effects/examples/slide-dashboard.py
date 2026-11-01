# Directional intent: several panels, each entering from the side its data came from.
#
# The direction is the message — a left slide reads as "this arrived from upstream", a top
# sweep as "this dropped in from above". Durations outside 100–2000ms clamp silently, and an
# unrecognized direction becomes `left`, so a guess degrades instead of failing the call.

latency = table("Latency")
latency.header(["route", "p50", "p99"])
latency.row(["/api/search", "12ms", "88ms"])
latency.row(["/api/user", "8ms", "34ms"])
latency.effect(slide_in("left", 400))
render_to("latency", latency)

traffic = sparkline("Requests/s", [12, 19, 24, 31, 28, 44, 51, 47, 39])
traffic.effect(sweep_in("top", 500))
render_to("traffic", traffic)

saturation = gauge("Queue depth", 0.68)
saturation.label("68% full")
saturation.color("pollen")
saturation.effect(fade_in(300))
render_to("queue", saturation)
