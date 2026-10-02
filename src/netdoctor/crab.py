"""Клешня — пиксельный краб-маскот netdoctor. Рисуется полублоками ▀▄: 1 символ = 2 пикселя."""

from rich.text import Text

PALETTE = {
    "R": "#ff6a4d",  # панцирь
    "D": "#c4392b",  # тень, ножки, стебельки
    "L": "#ffb39e",  # блик
    "W": "#ffffff",  # белок глаза
    "K": "#16161e",  # зрачок, рот
    "B": "#5cc8ff",  # капля пота / слеза
    "P": "#ff9fbd",  # румянец
}
W = 24


def sym(left):
    """Строка из левой половины + её зеркала."""
    return left + left[::-1]


def blank():
    return "." * W


def put(row, col, s):
    return row[:col] + s + row[col + len(s):]


BODY = [sym(x) for x in (
    "............",  # 0  клешни
    "............",  # 1
    "............",  # 2
    "............",  # 3
    "...RRR.WWW..",  # 4  глаза
    "....R..WWW..",  # 5
    ".....R..D...",  # 6  стебельки
    "......DRRRRR",  # 7  панцирь
    "....RRRRRRRR",  # 8
    "...RRRRRRRRR",  # 9
    "..RRRRRRRRRR",  # 10
    "..RRRRRRRRRR",  # 11
    "...DRRRRRRRR",  # 12
    "....DDRRRRRR",  # 13
    "...D..D..D..",  # 14 ножки
    "..D..D..D...",  # 15
)]

CLAWS = {
    "open": {0: "..RR.RR.....", 1: ".RRR.RRR....", 2: ".RRRRRRR....", 3: "..RRRRR....."},
    "snap": {0: "....RR......", 1: ".RRRRRRR....", 2: ".RRRRRRR....", 3: "..RRRRR....."},
}
LEGS_ALT = {14: sym("..D..D..D..."), 15: sym("..D..D..D...").replace("D", ".", 0)}

# глаза: строки 4-5, левый глаз в колонках 7-9 (правый — зеркально)
EYES = {
    "normal": ("WWW", "WKK"),
    "happy": (".K.", "K.K"),
    "think": ("WKK", "WWW"),
    "worried": ("WWW", "KKW"),
    "sad": ("KK.", "WKW"),
}
# рот: {строка: (колонка, рисунок)}
MOUTHS = {
    "normal": {10: (9, "K....K"), 11: (10, "KKKK")},
    "happy": {10: (9, "K....K"), 11: (10, "KPPK")},
    "think": {11: (11, "KK")},
    "worried": {11: (10, "KKKK")},
    "sad": {10: (10, "KKKK"), 11: (9, "K....K")},
}


def crab_text(mood="normal", frame=0, blush=None):
    if mood not in EYES:
        mood = "normal"
    g = list(BODY)
    # клешни
    if mood == "sad":
        for r, left in {8: "R.R.........", 9: "RRR.........", 10: ".R.........."}.items():
            g[r] = put(g[r], 0, left[:3])
            g[r] = put(g[r], W - 3, left[:3][::-1])
        g[4] = put(g[4], 3, "...")
        g[5] = put(g[5], 4, ".")
        g[6] = put(g[6], 5, ".")
        g[4] = put(g[4], W - 6, "...")
        g[5] = put(g[5], W - 5, ".")
        g[6] = put(g[6], W - 6, ".")
    else:
        for r, left in CLAWS["open" if frame % 2 == 0 else "snap"].items():
            g[r] = sym(left)
    # ножки шевелятся
    if frame % 2:
        g[14], g[15] = sym("..D..D..D..."), sym("...D..D..D..")
    # глаза
    top, bot = EYES[mood]
    g[4] = put(put(g[4], 7, top), W - 10, top[::-1])
    g[5] = put(put(g[5], 7, bot), W - 10, bot[::-1])
    # блик на панцире
    g[9] = put(g[9], 4, "LL")
    g[10] = put(g[10], 3, "L")
    # рот
    for r, (c, s) in MOUTHS[mood].items():
        g[r] = put(g[r], c, s)
    if blush if blush is not None else mood == "happy":
        g[11] = put(put(g[11], 4, "PP"), W - 6, "PP")
    if mood == "worried":
        g[2] = put(g[2], W - 3, "B")
        g[3] = put(g[3], W - 3, "B")
    if mood == "sad":
        g[6] = put(g[6], 7, "B")
        g[7] = put(g[7], 7, "B")
    return render(g)


def render(grid):
    out = Text()
    for r in range(0, len(grid), 2):
        for a, b in zip(grid[r], grid[r + 1]):
            ca, cb = PALETTE.get(a), PALETTE.get(b)
            if ca and cb:
                if ca == cb:
                    out.append("█", style=ca)
                else:
                    out.append("▀", style="%s on %s" % (ca, cb))
            elif ca:
                out.append("▀", style=ca)
            elif cb:
                out.append("▄", style=cb)
            else:
                out.append(" ")
        if r + 2 < len(grid):
            out.append("\n")
    return out
