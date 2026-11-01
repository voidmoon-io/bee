# A full-screen takeover, for something worth the whole screen.
#
# Only granted at `visual_level = "takeover"`. Below that the visual gate downgrades it to a
# panel and tells the model so in the tool result — the render still works, it is just smaller.
# The lifetime asked for here is capped by the operator's `takeover_ttl_secs`, silently, and
# the operator can always dismiss earlier with Esc.

throughput = line_chart("Throughput over the incident window")
before = throughput.series("baseline")
before.point(0.0, 1200.0)
before.point(1.0, 1180.0)
before.point(2.0, 1210.0)
before.point(3.0, 1195.0)

during = throughput.series("incident")
during.point(0.0, 1200.0)
during.point(1.0, 640.0)
during.point(2.0, 210.0)
during.point(3.0, 890.0)

throughput.effect(fade_in(300))
render_fullscreen_ttl(throughput, 15000)
