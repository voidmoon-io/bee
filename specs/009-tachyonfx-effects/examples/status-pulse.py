# A status change, flashed rather than merely written.
#
# `pulse` is one flash toward a color and back — for the moment a thing *becomes* failing,
# not for its steady state. The color is a theme role name, resolved against whatever theme
# is active at render time an unknown name falls back to `info` rather than erroring.

suite = dots("integration suite")
suite.passed("auth_login")
suite.passed("auth_refresh")
suite.fail("auth_revoke")
suite.passed("billing_charge")
suite.skip("billing_refund")
suite.effect(pulse("sting", 400))

render_to("suite", suite)
