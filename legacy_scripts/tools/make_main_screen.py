"""Generates the English main-screen graphics in translation/graphics/.

Usage:  python tools/make_main_screen.py path/to/game.cue

The main screen (stat panel + vertical calendar) is drawn from sprite cells in
CDROM/FUKUTEST/MAINROM.NBN: 4bpp, 64-byte rows, uploaded in 8 KB chunks of
128x128 px (docs/game-internals.md §7, "MAINROM.NBN"). This tool redraws:

  main_stat_labels.png - chunk 9 (file 0x12000), x 96..127, rows 0..119:
    the three 32x40 label columns of the stat panel (sprite frame 0x3D,
    parts 25-27): 体調 芸術 容姿 / 文系 運動 根性 / 理系 雑学 ストレス,
    one label every 14 rows.

  main_calendar.png - chunk 4 (file 0x8000), rows 0..31:
    the weekday cells (月 x112 row 0; 火 水 木 金 土 日 at x 0..80 row 16),
    used by sprite frames 0x52-0x58, and the 年 cell (x96 row 16), which
    becomes a "/" separator. translation/main_screen.json points the 月 and
    日 suffix parts of the calendar frame (0x3C) at that cell too, so the
    month and day suffixes stop sharing art with Monday and Sunday.

Text is drawn in palette index 9 with a drop shadow in index 10 at (+1, +1),
like the original labels. Re-run after changing a word or a glyph, then copy
the printed original_crc32 values into translation/main_screen.json.
"""

from __future__ import annotations

import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tokipatch import pairfont, png  # noqa: E402
from tokipatch.cd import Track  # noqa: E402
from tokipatch.iso9660 import list_files  # noqa: E402
from tokipatch.__main__ import parse_cue  # noqa: E402

FILE = "CDROM/FUKUTEST/MAINROM.NBN"
STRIDE = 64                                   # bytes per row (128 px at 4bpp)
GRAPHICS = Path(__file__).resolve().parents[2] / "translation" / "graphics"
FILL, SHADOW = 9, 10

# Stat labels, top to bottom as they're stored (one 40-row block per panel
# column). At most LABEL_WIDTH px including the shadow; the "-" sprite
# starts right after.
LABELS = ["Health", "Art", "Looks",           # 体調 芸術 容姿
          "Lit.", "Sport", "Guts",            # 文系 運動 根性
          "Sci.", "Trivia", "Stress"]         # 理系 雑学 ストレス
LABEL_X, LABEL_WIDTH, LABEL_PITCH = 97, 27, 14

# Weekday cells: (x, y) of each 16x16 cell in chunk 4.
WEEKDAYS = [("Mo", 112, 0), ("Tu", 0, 16), ("We", 16, 16), ("Th", 32, 16),
            ("Fr", 48, 16), ("Sa", 64, 16), ("Su", 80, 16)]
SEPARATOR = (96, 16)                          # was 年

# Condensed proportional font for the stat labels: (top row, rows). Capitals
# are 7 rows tall (rows 0-6), lowercase x-height 5 (rows 2-6), descenders to
# row 8. Letters are 1-5 px wide, 1 px apart.
SMALL = {
    "A": (0, [".##.", "#..#", "#..#", "####", "#..#", "#..#", "#..#"]),
    "B": (0, ["###.", "#..#", "#..#", "###.", "#..#", "#..#", "###."]),
    "C": (0, [".##.", "#..#", "#...", "#...", "#...", "#..#", ".##."]),
    "D": (0, ["###.", "#..#", "#..#", "#..#", "#..#", "#..#", "###."]),
    "E": (0, ["####", "#...", "#...", "###.", "#...", "#...", "####"]),
    "F": (0, ["####", "#...", "#...", "###.", "#...", "#...", "#..."]),
    "G": (0, [".##.", "#..#", "#...", "#.##", "#..#", "#..#", ".###"]),
    "H": (0, ["#..#", "#..#", "#..#", "####", "#..#", "#..#", "#..#"]),
    "I": (0, ["###", ".#.", ".#.", ".#.", ".#.", ".#.", "###"]),
    "J": (0, ["..##", "...#", "...#", "...#", "...#", "#..#", ".##."]),
    "K": (0, ["#..#", "#..#", "#.#.", "##..", "#.#.", "#..#", "#..#"]),
    "L": (0, ["#...", "#...", "#...", "#...", "#...", "#...", "####"]),
    "M": (0, ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"]),
    "N": (0, ["#..#", "##.#", "##.#", "#.##", "#.##", "#..#", "#..#"]),
    "O": (0, [".##.", "#..#", "#..#", "#..#", "#..#", "#..#", ".##."]),
    "P": (0, ["###.", "#..#", "#..#", "###.", "#...", "#...", "#..."]),
    "Q": (0, [".##.", "#..#", "#..#", "#..#", "#..#", "#.#.", ".#.#"]),
    "R": (0, ["###.", "#..#", "#..#", "###.", "#.#.", "#..#", "#..#"]),
    "S": (0, [".###", "#...", "#...", ".##.", "...#", "...#", "###."]),
    "T": (0, ["###", ".#.", ".#.", ".#.", ".#.", ".#.", ".#."]),
    "U": (0, ["#..#", "#..#", "#..#", "#..#", "#..#", "#..#", ".##."]),
    "V": (0, ["#...#", "#...#", "#...#", ".#.#.", ".#.#.", "..#..", "..#.."]),
    "W": (0, ["#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"]),
    "X": (0, ["#...#", ".#.#.", ".#.#.", "..#..", ".#.#.", ".#.#.", "#...#"]),
    "Y": (0, ["#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."]),
    "Z": (0, ["####", "...#", "..#.", ".#..", ".#..", "#...", "####"]),
    "a": (2, [".##.", "...#", ".###", "#..#", ".###"]),
    "b": (0, ["#...", "#...", "###.", "#..#", "#..#", "#..#", "###."]),
    "c": (2, [".##", "#..", "#..", "#..", ".##"]),
    "d": (0, ["...#", "...#", ".###", "#..#", "#..#", "#..#", ".###"]),
    "e": (2, [".##.", "#..#", "####", "#...", ".###"]),
    "f": (0, ["..#", ".#.", "###", ".#.", ".#.", ".#.", ".#."]),
    "g": (2, [".###", "#..#", "#..#", ".###", "...#", ".##."]),
    "h": (0, ["#...", "#...", "###.", "#..#", "#..#", "#..#", "#..#"]),
    "i": (0, ["#", ".", "#", "#", "#", "#", "#"]),
    "j": (0, [".#", "..", ".#", ".#", ".#", ".#", ".#", ".#", "#."]),
    "k": (0, ["#...", "#...", "#..#", "#.#.", "##..", "#.#.", "#..#"]),
    "l": (0, ["#", "#", "#", "#", "#", "#", "#"]),
    "m": (2, ["####.", "#.#.#", "#.#.#", "#.#.#", "#.#.#"]),
    "n": (2, ["###.", "#..#", "#..#", "#..#", "#..#"]),
    "o": (2, [".##.", "#..#", "#..#", "#..#", ".##."]),
    "p": (2, ["###.", "#..#", "#..#", "###.", "#...", "#..."]),
    "q": (2, [".###", "#..#", "#..#", ".###", "...#", "...#"]),
    "r": (2, ["#.#", "##.", "#..", "#..", "#.."]),
    "s": (2, [".##", "#..", ".#.", "..#", "##."]),
    "t": (1, [".#.", "###", ".#.", ".#.", ".#.", "..#"]),
    "u": (2, ["#..#", "#..#", "#..#", "#..#", ".###"]),
    "v": (2, ["#...#", "#...#", ".#.#.", ".#.#.", "..#.."]),
    "w": (2, ["#...#", "#.#.#", "#.#.#", "#.#.#", ".#.#."]),
    "x": (2, ["#.#", "#.#", ".#.", "#.#", "#.#"]),
    "y": (2, ["#..#", "#..#", "#..#", ".###", "...#", ".##."]),
    "z": (2, ["####", "..#.", ".#..", "#...", "####"]),
    ".": (6, ["#"]),
    "-": (3, ["###"]),
    "&": (0, [".#..", "#.#.", "#.#.", ".#..", "#.##", "#.#.", ".#.#"]),
    "/": (0, ["..#", "..#", ".#.", ".#.", ".#.", "#..", "#.."]),
    " ": (0, [".."]),
}


def small_width(word: str) -> int:
    return sum(len(SMALL[c][1][0]) for c in word) + len(word) - 1


def draw(canvas, width: int, x: int, y: int, top: int, rows) -> None:
    """Draw glyph rows ('#' = ink) with the drop shadow, at (x, y + top)."""
    ink = [(x + i, y + top + j) for j, row in enumerate(rows)
           for i, c in enumerate(row) if c == "#"]
    for px, py in ink:
        canvas[(py + 1) * width + px + 1] = SHADOW
    for px, py in ink:
        canvas[py * width + px] = FILL


def big_rows(ch: str):
    """A letter from the dialogue pair font: (top row, rows of '#'/'.')."""
    top, rows = pairfont.GLYPHS[ch]
    return top, rows


def pixels(data: bytes, base: int, x: int, y: int, w: int, h: int) -> bytearray:
    out = bytearray()
    for row in range(y, y + h):
        for col in range(x, x + w):
            byte = data[base + row * STRIDE + col // 2]
            out.append((byte >> (4 * (col & 1))) & 15)
    return out


def palette():
    # Display colours only (the patcher copies indices). 0 = panel green.
    pal = [(16 * i, 16 * i, 16 * i) for i in range(16)]
    pal[0], pal[FILL], pal[SHADOW] = (24, 104, 24), (184, 208, 216), (24, 40, 24)
    return pal + [(0, 0, 0)] * 240


def make_labels(data: bytes):
    base, x0, w, h = 0x12000, 96, 32, 120
    canvas = bytearray(w * h)                 # everything else in the rect is blank
    for i, word in enumerate(LABELS):
        width = small_width(word) + 1         # + shadow
        if width > LABEL_WIDTH:
            raise ValueError(f"label {word!r} is {width}px wide, max {LABEL_WIDTH}")
        x = LABEL_X - x0
        y = (i // 3) * 40 + (i % 3) * LABEL_PITCH + 2
        for c in word:
            top, rows = SMALL[c]
            draw(canvas, w, x, y, top, rows)
            x += len(rows[0]) + 1
    crc = zlib.crc32(pixels(data, base, x0, 0, w, h))
    png.write_indexed(GRAPHICS / "main_stat_labels.png", w, h, bytes(canvas), palette())
    return crc


def make_calendar(data: bytes):
    base, w, h = 0x8000, 128, 32
    canvas = pixels(data, base, 0, 0, w, h)
    cells = [(x, y) for _, x, y in WEEKDAYS] + [SEPARATOR]
    for x, y in cells:
        for row in range(y, y + 16):
            for col in range(x, x + 16):
                canvas[row * w + col] = 0
    for word, cx, cy in WEEKDAYS:
        glyphs = [big_rows(c) for c in word]
        text_w = 6 * len(glyphs) - 1
        x = cx + (14 - text_w) // 2
        for top, rows in glyphs:             # pair-font rows line up with the kanji rows
            draw(canvas, w, x, cy, top, rows)
            x += 6
    sx, sy = SEPARATOR
    draw(canvas, w, sx + 4, sy, 1, ["....#", "...#.", "...#.", "..#..", "..#..", ".#...",
                                     ".#...", "#....", "#...."])
    # rects in the PNG: Monday's cell, then the 火..年 row
    rects = [[112, 0, 16, 16], [0, 16, 112, 16]]
    crc = zlib.crc32(b"".join(pixels(data, base, x, y, rw, rh) for x, y, rw, rh in rects))
    png.write_indexed(GRAPHICS / "main_calendar.png", w, h, bytes(canvas), palette())
    return crc, rects


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    cue = Path(sys.argv[1])
    _, data_name = parse_cue(cue)
    with Track(cue.parent / Path(data_name).name) as track:
        entry = list_files(track)[FILE]
        data = track.read_file(entry.lba, entry.size)
    print(f"main_stat_labels.png  original_crc32 {make_labels(data):#010x}")
    crc, rects = make_calendar(data)
    print(f"main_calendar.png     original_crc32 {crc:#010x}  rects {rects}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
