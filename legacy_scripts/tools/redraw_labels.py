"""Redraw pre-drawn Japanese labels in English, in place, in a graphics file.

Usage:  python tools/redraw_labels.py [SHEET ...]      (default: every sheet)

For screens whose labels are pixels in one big image, drawn once each (the
album/file screen in FILESEL.NBN, the exam results board, ...; game-internals
7), unlike the Options glyph strip (tools/make_option_labels.py). A sheet is
a grid of file blocks the game uploads side by side to VRAM (found with
tools/emu/watch_exec.py on the upload routine 0x8004435C), each `width` x
`height` px at `bpp` bits per pixel.

Each label gives the box (x0, y0, x1, y1, inclusive, in the sheet's pixel
coordinates) of the Japanese text and the English. Inside the box every pixel
of the label's ink colour (given, or the most common non-background value)
becomes the row's background (the most common other value in that row of the
box); then the English is drawn in the ink colour with the pair font
(tokipatch/pairfont.py), proportionally spaced, capitals starting on the box's
top row. `width` (optional) is the room to the right the English may use;
it defaults to the space up to the edge of the label's box (1 px kept
free). A label whose English is empty is just erased.

Writes translation/graphics/<sheet>_<block>.png for every block it changes
and translation/<json>: image patches (only the changed rectangles) with the
CRC32 of the pixels they replace. Re-run after changing a label.
"""

from __future__ import annotations

import collections
import json
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tokipatch import pairfont, png  # noqa: E402

# Label: (x0, y0, x1, y1, english[, options])
SHEETS = {
    "filesel_panel": {
        "file": "CDROM/FUKUTEST/FILESEL.NBN", "json": "album_screen.json", "bpp": 8,
        "width": 128, "height": 128,
        "grid": [[0x24000, 0x28000, 0x2C000], [0x30000, 0x34000, 0x38000]],
        "labels": [
            (217, 28, 227, 38, "/"),          # 年  (19__年__月__日 -> 19__/__/__)
            (249, 28, 257, 38, "/"),          # 月
            (280, 28, 287, 38, ""),           # 日
            (120, 45, 163, 55, "Name"),
            (121, 61, 163, 71, "Nickname"),
            (121, 77, 164, 87, "Club"),
            (121, 95, 165, 105, "Clears"),
            (261, 95, 271, 105, ""),          # 人 after the count
            (17, 88, 46, 98, "Sys.", {"ink": 0xDB, "erase": [0x86], "shadow": (0x86, 1, 0)}),   # 有/無 follows
            # buttons (normal state): fill 0xA6, outline 0x3A over a gradient
            (20, 27, 52, 39, "Copy", {"fill": 0xA6, "outline": 0x3A, "top": 29}),
            (63, 27, 96, 39, "New", {"fill": 0xA6, "outline": 0x3A, "top": 29}),
            (20, 45, 53, 57, "Clear", {"fill": 0xA6, "outline": 0x3A, "top": 47}),
            (63, 45, 96, 57, "Load", {"fill": 0xA6, "outline": 0x3A, "top": 47}),
        ],
    },
    "filesel_strip": {
        "file": "CDROM/FUKUTEST/FILESEL.NBN", "json": "album_screen.json", "bpp": 8,
        "width": 128, "height": 128,
        "grid": [[0x1A000, 0x3C000, 0x1E000, 0x40550]],
        "labels": [
            # stat names (parameter panel), same short forms as the main screen
            (13, 48, 39, 58, "Health"),
            (13, 64, 39, 74, "Lit."),
            (13, 80, 39, 90, "Sci."),
            (13, 96, 39, 106, "Art"),
            (190, 39, 216, 49, "Sport"),
            (190, 56, 216, 66, "Trivia"),
            (190, 72, 216, 82, "Looks"),
            (190, 88, 216, 98, "Guts"),
            (184, 104, 223, 114, "Stress"),
            # girls' ratings: given names, as in the game's speaker labels
            (67, 48, 91, 58, "Shiori", {"x": 65, "width": 29, "tight": True, "narrow": True}),
            (67, 64, 91, 74, "Mio", {"x": 65, "width": 29, "tight": True, "narrow": True}),
            (67, 80, 91, 90, "Yuina", {"x": 65, "width": 29, "tight": True, "narrow": True}),
            (67, 97, 91, 107, "Ayako", {"x": 65, "width": 29, "tight": True, "narrow": True}),
            (136, 40, 160, 50, "Saki", {"x": 134, "width": 29, "tight": True, "narrow": True}),
            (136, 56, 160, 66, "Yukari", {"x": 134, "width": 29, "tight": True, "narrow": True}),
            (136, 72, 160, 82, "Nozomi", {"x": 134, "width": 29, "tight": True, "narrow": True}),
            (143, 89, 153, 99, "Mira", {"x": 134, "width": 29, "tight": True, "narrow": True}),
            (271, 7, 309, 17, "Rei", {"x": 270, "tight": True, "narrow": True}),
            (271, 24, 309, 34, "Yuko", {"x": 270, "tight": True, "narrow": True}),
            (271, 40, 309, 50, "Megumi", {"x": 270, "tight": True, "narrow": True}),
            (271, 56, 309, 66, "Yumi", {"x": 270, "tight": True, "narrow": True}),
            (278, 72, 302, 82, "Miharu", {"x": 271, "tight": True, "narrow": True}),
            # system file present / absent badges next to the System tab
            (241, 55, 252, 65, "Y", {"x": 245}),
            (240, 87, 252, 97, "N", {"x": 244}),
            # white titles
            (131, 3, 205, 13, "Stats"),
            (131, 17, 216, 28, "Girls' ratings"),
            (8, 112, 87, 122, "Clears"),
            # buttons (highlighted sprites): fill 0xB1, outline 0xB2
            (4, 3, 36, 15, "Copy", {"fill": 0xB1, "outline": 0xB2, "top": 5}),
            (55, 3, 88, 15, "New", {"fill": 0xB1, "outline": 0xB2, "top": 5}),
            (324, 13, 360, 25, "Load", {"fill": 0xB1, "outline": 0xB2, "top": 15}),
            (324, 45, 357, 57, "Clear", {"fill": 0xB1, "outline": 0xB2, "top": 47}),
        ],
    },
    "name_entry": {
        # Name entry side buttons (NAME_ENT.NBN, 4bpp, 64-byte rows; frames
        # 16-25 of its table at 0x1AF58 draw them, highlighted by CLUT).
        "file": "CDROM/NAME_ENT/NAME_ENT.NBN", "json": "name_entry_buttons.json", "bpp": 4,
        "width": 128, "height": 128, "grid": [[0x0]],
        "labels": [
            (35, 25, 61, 38, "Done", {"ink": 9, "erase": [10], "shadow": (10, 1, 1), "center": True, "top": 28}),
            (35, 41, 61, 54, "Hira", {"ink": 9, "erase": [10], "shadow": (10, 1, 1), "center": True, "top": 44}),
            (67, 41, 95, 54, "Sym", {"ink": 9, "erase": [10], "shadow": (10, 1, 1), "center": True, "top": 43}),
            (35, 57, 61, 70, "Kata", {"ink": 9, "erase": [10], "shadow": (10, 1, 1), "center": True, "top": 60}),
            (67, 57, 95, 70, "Kanji", {"ink": 9, "erase": [10], "shadow": (10, 1, 1), "center": True, "top": 59, "narrow": True}),
        ],
    },
    # Town News headlines (EXE frames 126-133 over MAINROM.NBN chunks 2, 7 and
    # 11; game-internals 7): each a 24-row strip, part 1 up to 128 px plus a
    # tail part stored elsewhere. The English fits part 1; the tails are cleared.
    "news_chunk2": {
        "file": "CDROM/FUKUTEST/MAINROM.NBN", "json": "town_news_banners.json", "bpp": 4,
        "width": 128, "height": 128, "grid": [[0x4000]],
        "labels": [
            (0, 0, 127, 23, "Central Park", {"big": True, "ink": 2, "shadow": 4}),
            (0, 24, 119, 47, "Museum opens", {"big": True, "ink": 7, "shadow": 9,
                                              "also_clear": [(120, 24, 127, 47)]}),   # tail of headline 1
            (0, 48, 111, 71, "Aquarium", {"big": True, "ink": 12, "shadow": 14}),
            (0, 72, 127, 95, "New stadium", {"big": True, "ink": 2, "shadow": 4,
                                             "also_clear": [(112, 48, 127, 71)]}),    # its own tail
            (0, 96, 111, 119, "Garden guide", {"big": True, "ink": 7, "shadow": 9,
                                              "also_clear": [(112, 96, 127, 119)]}),   # tail of headline 6
        ],
    },
    "news_chunk7": {
        "file": "CDROM/FUKUTEST/MAINROM.NBN", "json": "town_news_banners.json", "bpp": 4,
        "width": 128, "height": 128, "grid": [[0xE000]],
        "labels": [
            (0, 0, 127, 23, "Bowling", {"big": True, "ink": 12, "shadow": 14}),
            (0, 24, 127, 47, "Karaoke opens", {"big": True, "ink": 2, "shadow": 4}),
            (0, 48, 127, 71, "Planetarium", {"big": True, "ink": 7, "shadow": 9}),
        ],
    },
    "news_tails": {
        # tails of headlines 6 (chunk 2, right of headline 5), 7 and 8 (chunk 11)
        "file": "CDROM/FUKUTEST/MAINROM.NBN", "json": "town_news_banners.json", "bpp": 4,
        "width": 128, "height": 128, "grid": [[0x16000]],
        "labels": [
            (0, 104, 47, 127, "", {"big": True, "ink": 0, "shadow": 0}),
        ],
    },
    "examine": {
        # The end-of-term exam results screen (ETC.EXN): a copy of MAINROM.NBN
        # chunks 4 and 9 (patched like main_screen.json, in exam_results.json)
        # plus the board's title. 4bpp, 64 bytes per row.
        "file": "CDROM/FUKUTEST/EXAMINE.NBN", "json": "exam_results.json", "bpp": 4,
        "width": 128, "height": 416, "grid": [[0x0]],
        "labels": [
            (0, 314, 111, 325, "Exam results", {"ink": 9, "erase": [10], "shadow": (10, 1, 1), "x": 21}),
        ],
    },
}

# School-trip RPG battles (RPG_BAT.EXN): each BATTLE/*.BIN with a command menu
# carries its own copy of the 128x128 8bpp UI chunk (cells 0-255 of its frame
# table; game-internals 7, BATTLE), at the offset given here. Commands 攻撃/防御/奥義
# are 32x16 cells: bright (ink 0x18, shade 0x1A) at (96,24), (96,40), (96,0)
# and dim (0x10/0x12) at (56,72), (56,88), (80,112). "Attack" is 32 px and
# the cell has no room for its shadow, hence Fight.
_BATTLE_BRIGHT = {"ink": 0x18, "erase": [0x1A], "shadow": (0x1A, 1, 1), "center": True}
_BATTLE_DIM = {"ink": 0x10, "erase": [0x12], "shadow": (0x12, 1, 1), "center": True}
_MISS = ["#...#.#........",
         "##.##....##..##",
         "#.#.#.#.#...#..",
         "#...#.#..#...#.",
         "#...#.#...#...#",
         "#...#.#.##..##."]
for _name, _off in (("PARK", 0x80), ("UTYU", 0x80), ("VS_PARK", 0x80), ("VS_UTYU", 0x80),
                    ("VS_HABU", 0x20A10), ("VS_ROBO", 0x2B258), ("VS_UFO", 0x2D35C),
                    ("VS_KUMA", 0x188F0), ("VS_SIKA", 0x188D8)):
    SHEETS[f"battle_{_name.lower()}"] = {
        "file": f"CDROM/BATTLE/{_name}.BIN", "json": "battle_menu.json", "bpp": 8,
        "width": 128, "height": 128, "grid": [[_off]],
        "labels": [
            (96, 24, 127, 39, "Fight", {**_BATTLE_BRIGHT, "top": 27}),
            (96, 40, 127, 55, "Guard", {**_BATTLE_BRIGHT, "top": 43}),
            (96, 0, 127, 12, "Skill", {**_BATTLE_BRIGHT, "top": 1}),
            (56, 72, 87, 87, "Fight", {**_BATTLE_DIM, "top": 75}),
            (56, 88, 87, 103, "Guard", {**_BATTLE_DIM, "top": 91}),
            (80, 112, 111, 124, "Skill", {**_BATTLE_DIM, "top": 113}),
            # ミス, a 16x8 cell in two colours: a 6-row hand-drawn "Miss"
            (40, 72, 55, 78, "Miss", {**_BATTLE_DIM, "center": False, "x": 40, "top": 73, "bitmap": _MISS}),
            (40, 80, 55, 86, "Miss", {"ink": 0xEE, "erase": [0xEF], "shadow": (0xEF, 1, 1),
                                      "x": 40, "top": 81, "bitmap": _MISS}),
        ],
    }


NARROW_DROP2 = set("ouhaegyndbpqcr")   # letters that still read with their middle column removed


def word(text: str, tight: bool = False, narrow: bool = False):
    """(width, rows) of `text` in the pair font, proportional: each letter's
    inked columns plus a 1 px gap; a space is 3 px. With `tight`, the gap is
    dropped where the two letters' facing columns don't share a row or a
    diagonal neighbour (for boxes a few pixels too narrow). rows: 12 lists
    of bools. With `narrow`, round lowercase letters lose their middle
    column and i keeps only its stem (4 px and 1 px wide)."""
    cols = []
    for ch in text:
        rows = pairfont.letter_rows(ch)
        used = [c for c in range(5) if any(r >> (4 - c) & 1 for r in rows)]
        if not used:
            cols += [[False] * 12] * 3
            continue
        keep = range(min(used), max(used) + 1)
        if narrow and ch in NARROW_DROP2:
            keep = [c for c in keep if c != 2]
        elif narrow and ch == "i":
            keep = [2]
        letter = [[bool(r >> (4 - c) & 1) for r in rows] for c in keep]
        if cols and tight and cols[-1] == [False] * 12 and len(cols) > 1:
            last, first = cols[-2], letter[0]
            touch = any(first[y] and any(last[yy] for yy in (y - 1, y, y + 1) if 0 <= yy < 12) for y in range(12))
            if not touch:
                cols.pop()
        cols += letter
        cols.append([False] * 12)
    if cols:
        cols.pop()  # no gap after the last letter
    return len(cols), [[cols[x][y] for x in range(len(cols))] for y in range(12)]


class Sheet:
    def __init__(self, spec, data: bytes):
        self.spec, self.data = spec, data
        self.w, self.h, self.bpp = spec["width"], spec["height"], spec["bpp"]
        self.stride = self.w * self.bpp // 8
        self.canvas = {o: bytearray(data[o:o + self.stride * self.h]) for row in spec["grid"] for o in row}
        self.changed = collections.defaultdict(set)   # block -> {(x, y)}

    def _at(self, x, y):
        block = self.spec["grid"][y // self.h][x // self.w]
        return block, x % self.w, y % self.h

    def get(self, x, y, original=False):
        block, bx, by = self._at(x, y)
        buf = self.data[block:block + self.stride * self.h] if original else self.canvas[block]
        if self.bpp == 8:
            return buf[by * self.stride + bx]
        v = buf[by * self.stride + bx // 2]
        return v >> 4 if bx & 1 else v & 15

    def put(self, x, y, v):
        block, bx, by = self._at(x, y)
        buf = self.canvas[block]
        if self.bpp == 8:
            buf[by * self.stride + bx] = v
        else:
            i = by * self.stride + bx // 2
            buf[i] = (buf[i] & 0x0F) | (v << 4) if bx & 1 else (buf[i] & 0xF0) | v
        self.changed[block].add((bx, by))


def redraw_outlined(sheet: Sheet, label):
    """Buttons: a fill colour with a 1 px outline over a gradient. The glyph
    (fill and outline pixels) is replaced by the nearest background pixel to
    its left in the row (the gradient runs horizontally), then the English
    is drawn centred in the box, fill plus outline."""
    x0, y0, x1, y1, text, opt = label
    fill, outline = opt["fill"], opt["outline"]
    glyph = {fill, outline}
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            if sheet.get(x, y) in glyph:
                xx = x - 1
                while xx >= 0 and sheet.get(xx, y) in glyph:
                    xx -= 1
                sheet.put(x, y, sheet.get(xx, y))
    w, rows = word(text, opt.get("tight", False), opt.get("narrow", False))
    left = (x0 + x1 + 1 - w) // 2
    top = opt.get("top", y0 + 1) - 1      # caps from font row 1
    ink = {(left + gx, top + gy) for gy in range(12) for gx in range(w) if rows[gy][gx]}
    edge = {(x + dx, y + dy) for x, y in ink for dx in (-1, 0, 1) for dy in (-1, 0, 1)} - ink
    if any(not (x0 - 1 <= x <= x1 + 1 and y0 - 1 <= y <= y1 + 1) for x, y in edge):
        raise SystemExit(f"{text!r} doesn't fit its button box")
    for x, y in edge:
        sheet.put(x, y, outline)
    for x, y in ink:
        sheet.put(x, y, fill)


def big_word(text: str):
    """(width, rows) of `text` as headline letters: the pair font doubled in
    height and emboldened (each column drawn twice): 6 px wide letters, 2 px
    apart (a space 5 px), 22 rows from the font's row 1."""
    cols = []
    for ch in text:
        rows = pairfont.letter_rows(ch)
        used = [c for c in range(5) if any(r >> (4 - c) & 1 for r in rows)]
        if not used:
            cols += [[False] * 12] * 5
            continue
        letter = [[bool(r >> (4 - c) & 1) for r in rows] for c in range(min(used), max(used) + 1)]
        if ch in "mwMWN":
            # 1 px gaps between their strokes: emboldening would close them
            bold = [list(c) for c in letter] + [[False] * 12]
        else:
            bold = [list(c) for c in letter] + [[False] * 12]
            for i, c in enumerate(letter):
                bold[i + 1] = [a or b for a, b in zip(bold[i + 1], c)]
        cols += bold + [[False] * 12]
    if cols:
        cols.pop()
    w = len(cols)
    grid = [[False] * w for _ in range(22)]
    for x, c in enumerate(cols):
        for r in range(1, 12):
            if c[r]:
                grid[2 * (r - 1)][x] = grid[2 * (r - 1) + 1][x] = True
    return w, grid


def redraw_big(sheet: Sheet, label):
    """Headlines: clear the box to transparent (0), then draw the English big
    and bold in `ink` with a 1 px `shadow` down-right (the original's two
    main colours), from row y0 + 2."""
    x0, y0, x1, y1, text, opt = label
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            sheet.put(x, y, 0)
    for bx0, by0, bx1, by1 in opt.get("also_clear", ()):
        for y in range(by0, by1 + 1):
            for x in range(bx0, bx1 + 1):
                sheet.put(x, y, 0)
    if not text:
        return
    w, grid = big_word(text)
    if w > x1 - x0:
        raise SystemExit(f"{text!r} is {w} px wide, the headline has {x1 - x0}")
    left = x0 + (x1 - x0 - w) // 2 if opt.get("center", True) else x0
    top = y0 + 2
    for gy in range(22):
        for gx in range(w):
            if grid[gy][gx]:
                sheet.put(left + gx + 1, top + gy + 1, opt["shadow"])
    for gy in range(22):
        for gx in range(w):
            if grid[gy][gx]:
                sheet.put(left + gx, top + gy, opt["ink"])


def redraw(sheet: Sheet, label):
    x0, y0, x1, y1, text = label[:5]
    opt = label[5] if len(label) > 5 else {}
    if "outline" in opt:
        return redraw_outlined(sheet, label)
    if opt.get("big"):
        return redraw_big(sheet, label)
    box = [(x, y) for y in range(y0, y1 + 1) for x in range(x0, x1 + 1)]
    # Row backgrounds from a slightly wider window, so a full-width stroke
    # (the bottom of 日) still has a background to restore.
    lo, hi = max(0, x0 - 6), min(len(sheet.spec["grid"][0]) * sheet.w - 1, x1 + 6)
    rows = {y: collections.Counter(sheet.get(x, y) for x in range(lo, hi + 1)) for y in range(y0 - 1, y1 + 2)}
    ink = opt.get("ink")
    if ink is None:
        counts = collections.Counter(sheet.get(x, y) for x, y in box
                                     if sheet.get(x, y) != rows[y].most_common(1)[0][0])
        ink = counts.most_common(1)[0][0]
    # Background per row: the most common non-ink value inside the box (box
    # rows can be striped), else in the wider window.
    erase = {ink, *opt.get("erase", ())}
    bgs = {}
    for y, c in rows.items():
        inside = collections.Counter(v for v in (sheet.get(x, y) for x in range(x0, x1 + 1)) if v not in erase)
        bgs[y] = inside.most_common(1)[0][0] if inside else next(v for v, _ in c.most_common() if v not in erase)
    for x, y in box:
        if sheet.get(x, y) in erase:
            sheet.put(x, y, bgs[y])
    if not text:
        return
    if "bitmap" in opt:     # hand-drawn letters for cells too small for the pair font
        glyph = [[c == "#" for c in row] for row in opt["bitmap"]]
        w = w0 = len(glyph[0])
    else:
        w, glyph = word(text, opt.get("tight", False), opt.get("narrow", False))
        w0 = w
    left = opt.get("x", (x0 + x1 + 1 - w0) // 2 if opt.get("center") else x0)
    room = opt.get("width")
    if room is None:
        # up to the edge of the box: the first column, right of the label,
        # where a row isn't its background any more
        right, limit = x1 + 1, len(sheet.spec["grid"][0]) * sheet.w
        while right < limit and all(sheet.get(right, y) == bgs[y] for y in range(y0, y1 + 1)):
            right += 1
        room = right - 1 - left
    if opt.get("center"):
        room = x1 + 1 - left
    if w > room:
        raise SystemExit(f"{text!r} is {w} px wide, the room is {room}")
    top = opt.get("top", y0) - 1        # pixel row of the font's row 0 (capitals start one below)
    shadow = opt.get("shadow")          # (value, dx, dy): a drop shadow, as on the System tab
    if shadow:
        sv, sdx, sdy = shadow
        for gy in range(len(glyph)):
            for gx in range(w):
                if glyph[gy][gx]:
                    sheet.put(left + gx + sdx, top + gy + sdy, sv)
    for gy in range(len(glyph)):
        for gx in range(w):
            if glyph[gy][gx]:
                sheet.put(left + gx, top + gy, ink)


def build(names):
    by_json = collections.defaultdict(list)
    for name in names:
        spec = SHEETS[name]
        data = (ROOT / "extracted" / spec["file"]).read_bytes()
        sheet = Sheet(spec, data)
        for label in spec["labels"]:
            redraw(sheet, label)
        gdir = ROOT / "translation" / "graphics"
        for block, pts in sorted(sheet.changed.items()):
            pts = {p for p in pts if sheet.get(*_abs(sheet, block, p)) != sheet.get(*_abs(sheet, block, p), original=True)}
            if not pts:
                continue
            png_name = f"{name}_{block:05x}.png"
            pixels = bytearray()
            for by in range(sheet.h):
                for bx in range(sheet.w):
                    pixels.append(sheet.get(*_abs(sheet, block, (bx, by))))
            png.write_indexed(gdir / png_name, sheet.w, sheet.h, bytes(pixels), [(i, i, i) for i in range(256)])
            rects = _rects(pts)
            orig = bytearray()
            for rx, ry, rw, rh in rects:
                for yy in range(ry, ry + rh):
                    for xx in range(rx, rx + rw):
                        orig.append(sheet.get(*_abs(sheet, block, (xx, yy)), original=True))
            entry = {"file": spec["file"], "png": f"graphics/{png_name}", "pixels": f"0x{block:X}",
                     "stride": sheet.stride, "x": 0, "y": 0, "rects": rects,
                     "original_crc32": f"0x{zlib.crc32(orig):08x}"}
            if sheet.bpp != 8:
                entry["bpp"] = sheet.bpp
            by_json[spec["json"]].append(entry)
    return by_json


def _abs(sheet, block, p):
    for gy, row in enumerate(sheet.spec["grid"]):
        if block in row:
            return row.index(block) * sheet.w + p[0], gy * sheet.h + p[1]
    raise KeyError(block)


def _rects(pts):
    """Bounding boxes of the changed pixels, one per 16-row band."""
    bands = collections.defaultdict(list)
    for x, y in pts:
        bands[y // 16].append((x, y))
    out = []
    for _, ps in sorted(bands.items()):
        xs, ys = [p[0] for p in ps], [p[1] for p in ps]
        out.append([min(xs), min(ys), max(xs) - min(xs) + 1, max(ys) - min(ys) + 1])
    return out


DESCRIPTIONS = {
    "battle_menu.json": ("School-trip RPG battle command menu (RPG_BAT.EXN): 攻撃/防御/奥義 -> Fight/Guard/Skill, bright "
                         "and dim copies, redrawn in the UI chunk every BATTLE/*.BIN with a menu carries "
                         "(game-internals 7, BATTLE) by tools/redraw_labels.py."),
    "town_news_banners.json": ("Town News headline banners (the eight 中央公園紹介 … プラネタリウム特集 strips in "
                               "MAINROM.NBN chunks 2 and 7, drawn by EXE frames 126-133; game-internals 7), redrawn "
                               "big and bold in each headline's own colours by tools/redraw_labels.py; the tails the "
                               "frames take from elsewhere are cleared."),
    "name_entry_buttons.json": ("Name entry side buttons in NAME_ENT/NAME_ENT.NBN (game-internals 6d): かな/カナ/記号/漢字/終了 "
                                "-> Hira/Kata/Sym/Kanji/Done, redrawn in place by tools/redraw_labels.py. The 名前:/あだ名: "
                                "captions aren't in this sheet (not found yet)."),
    "exam_results.json": ("End-of-term exam results screen graphics in FUKUTEST/EXAMINE.NBN (loaded by ETC.EXN): "
                          "the stat labels and calendar characters are an exact copy of MAINROM.NBN chunks 9 and 4, "
                          "patched with main_screen.json's images; the board title 期末試験結果発表 is redrawn by "
                          "tools/redraw_labels.py. Not seen on screen: the exam day isn't reachable by forcing a state "
                          "(docs/testing.md)."),
    "album_screen.json": ("Album (save file) screen graphics in FILESEL.NBN (game-internals 7): the info panel's "
                          "labels (Name, Nickname, Club, Clears, the date header), the parameter panel's stat names "
                          "and the girls' ratings page's names, redrawn in place by tools/redraw_labels.py."),
}


def main() -> None:
    names = sys.argv[1:] or list(SHEETS)
    for js, images in build(names).items():
        path = ROOT / "translation" / js
        doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        keep = [i for i in doc.get("images", []) if not any(i["png"] == n["png"] for n in images)
                and not any(i["png"].startswith(f"graphics/{s}_") for s in names)]
        doc["description"] = DESCRIPTIONS.get(js, doc.get("description", ""))
        doc["images"] = keep + images
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{js}: {len(doc['images'])} image patch(es)")


if __name__ == "__main__":
    main()
