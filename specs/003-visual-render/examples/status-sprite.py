# A sprite whose color reflects a pass/fail outcome (003-visual-render, Slice 2). The agent computes
# `passed` from data it gathered, then paints a check (green) or a cross (red) accordingly — the same
# bitmap, a different palette entry.

passed = True   # e.g. derived from a prior tool call

pal = palette()
pal.set(".", "transparent")
pal.set("#", "#5FAF5F" if passed else "#D75F5F")   # pollen vs sting

icon = sprite(8, 8, pal)
if passed:
    icon.paint([          # a check mark
        "........",
        ".......#",
        "......##",
        "#....##.",
        "##..##..",
        ".####...",
        "..##....",
        "........",
    ])
else:
    icon.paint([          # a cross
        "........",
        ".#....#.",
        "..#..#..",
        "...##...",
        "...##...",
        "..#..#..",
        ".#....#.",
        "........",
    ])

render(icon)
