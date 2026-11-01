# The project mascot (003-visual-render, Slice 2, FR-032).
#
# The simplest form — the built-in wing-flap animation:
#
#     render(bee_animation())
#
# Or build a bee by hand from a palette + bitmap. Each character in a paint() row is looked up in
# the palette unknown characters (and ".") are transparent. A 16x16 sprite renders as 16 columns x
# 8 terminal rows via the half-block technique.

pal = palette()
pal.set(".", "transparent")
pal.set("K", "#1A1A1A")     # outline
pal.set("Y", "#E5A100")     # honey body
pal.set("W", "#FFFFFF")     # wings
pal.set("R", "#D75F5F")     # sting

bee = sprite(16, 16, pal)
bee.paint([
    "......KK........",
    "....KKWWKK......",
    "...KWWWWWWK.....",
    "..KKWWWWWWKK....",
    "..KYYYYYYYYYK...",
    ".KYYYYKYYYYYK...",
    ".KYYYKKYYKK.K...",
    ".KYYYYYYYYYK....",
    "..KYYYYYYKK.....",
    "..KKYYYYKK......",
    "...KYYYYK.......",
    "....KKKK........",
    "......KK........",
    ".....KRRK.......",
    "......KK........",
    "................",
])

render(bee)
