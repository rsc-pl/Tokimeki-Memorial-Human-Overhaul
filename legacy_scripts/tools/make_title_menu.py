"""Generates the English title menu graphics in translation/graphics/.

Usage:  python tools/make_title_menu.py path/to/game.cue

The title menu (ゲームスタート / オプション) is built from 16x16 cells in 8bpp
bitmaps inside CDROM/FUKUTEST/TITLE.NBN (128 px wide rows):

  title_menu.png - block at 0x60000:
    y=68   ゲームスタート (selected, blue)    オ  (unselected)
    y=84   ゲームスタート (unselected, grey)  プ  (unselected)
    y=100  シ ョ ン (unselected); rest of this row is unrelated art

  title_menu_options_selected.png - block at 0x5C000:
    y=52, x=48..127  オプション (selected, blue), one contiguous strip;
    x<48 on these rows is the pointing-hand cursor, don't touch

The game draws each item's cells side by side, so English text is drawn as one
strip and sliced back into the same cells. Re-run this after changing the
font or wording, or edit the PNGs by hand in any indexed-colour editor. Copy
the printed original_crc32 values into translation/title_menu.json.
"""

from __future__ import annotations

import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tokipatch import png  # noqa: E402
from tokipatch.cd import Track  # noqa: E402
from tokipatch.iso9660 import list_files  # noqa: E402
from tokipatch.__main__ import parse_cue  # noqa: E402

FILE = "CDROM/FUKUTEST/TITLE.NBN"
STRIDE = 128
PALETTE = 0x4E000                         # the menu's CLUT (13th uploaded)
GRAPHICS = Path(__file__).resolve().parents[2] / "translation" / "graphics"

# (outline index, first gradient index) of the two text styles in the menu CLUT
BLUE, GREY = (8, 2), (24, 18)
GRADIENT = [0, 1, 2, 3, 4, 5, 5, 4, 3, 2, 1, 0]   # fill rows 2..13 of a cell

FONT = {
    "G": [".#######.", "#########", "##.....##", "##.......", "##.......", "##..#####",
          "##..#####", "##.....##", "##.....##", "##.....##", "#########", ".#######."],
    "A": ["...###...", "..#####..", ".##...##.", ".##...##.", "##.....##", "##.....##",
          "#########", "#########", "##.....##", "##.....##", "##.....##", "##.....##"],
    "M": ["##.....##", "###...###", "####.####", "##.###.##", "##..#..##", "##.....##",
          "##.....##", "##.....##", "##.....##", "##.....##", "##.....##", "##.....##"],
    "E": ["#########", "#########", "##.......", "##.......", "##.......", "#######..",
          "#######..", "##.......", "##.......", "##.......", "#########", "#########"],
    "S": [".#######.", "#########", "##.....##", "##.......", "##.......", "########.",
          ".########", ".......##", ".......##", "##.....##", "#########", ".#######."],
    "T": ["#########", "#########", "...###...", "...###...", "...###...", "...###...",
          "...###...", "...###...", "...###...", "...###...", "...###...", "...###..."],
    "R": ["########.", "#########", "##.....##", "##.....##", "##.....##", "#########",
          "########.", "##...##..", "##....##.", "##.....##", "##.....##", "##.....##"],
    "O": [".#######.", "#########", "##.....##", "##.....##", "##.....##", "##.....##",
          "##.....##", "##.....##", "##.....##", "##.....##", "#########", ".#######."],
    "P": ["########.", "#########", "##.....##", "##.....##", "##.....##", "#########",
          "########.", "##.......", "##.......", "##.......", "##.......", "##......."],
    "I": ["######", "######", "..##..", "..##..", "..##..", "..##..",
          "..##..", "..##..", "..##..", "..##..", "######", "######"],
    "N": ["##.....##", "###....##", "####...##", "##.#...##", "##.##..##", "##..#..##",
          "##..##.##", "##...#.##", "##...####", "##....###", "##.....##", "##.....##"],
    " ": ["....."] * 12,
}


def render_strip(word: str, width: int, style) -> list:
    """Return 16 rows of `width` palette indices with `word` centred."""
    outline, base = style
    text_w = sum(len(FONT[c][0]) + 1 for c in word) - 1
    if text_w + 2 > width:
        raise ValueError(f"{word!r} is {text_w + 2}px wide, only {width}px available")
    fill = [[False] * width for _ in range(16)]
    x = (width - text_w) // 2
    for c in word:
        glyph = FONT[c]
        for gy, line in enumerate(glyph):
            for gx, ch in enumerate(line):
                if ch == "#":
                    fill[2 + gy][x + gx] = True
        x += len(glyph[0]) + 1

    rows = []
    for y in range(16):
        row = []
        for x in range(width):
            if fill[y][x]:
                row.append(base + GRADIENT[y - 2])
            elif any(fill[y + dy][x + dx]
                     for dy in (-1, 0, 1) for dx in (-1, 0, 1)
                     if 0 <= y + dy < 16 and 0 <= x + dx < width):
                row.append(outline)
            else:
                row.append(0)
        rows.append(row)
    return rows


class Sheet:
    """A region of the 8bpp bitmap, exported to a blank PNG we draw into.

    The original pixels are only read to compute original_crc32. The PNG
    itself starts blank (index 0), so no game artwork ends up in the repo;
    the patcher only copies the `rects` areas anyway.
    """

    def __init__(self, data: bytes, pixels: int, x: int, y: int, width: int, height: int, rects):
        self.width, self.rects = width, rects
        original = b"".join(
            data[pixels + (y + r) * STRIDE + x:pixels + (y + r) * STRIDE + x + width]
            for r in range(height))
        self.canvas = bytearray(width * height)
        self.crc = 0
        for rx, ry, rw, rh in rects:
            for r in range(ry, ry + rh):
                self.crc = zlib.crc32(original[r * width + rx:r * width + rx + rw], self.crc)

    def blit(self, rows: list, src_x: int, dst_x: int, dst_y: int, w: int = 16) -> None:
        for y in range(16):
            for x in range(w):
                self.canvas[(dst_y + y) * self.width + dst_x + x] = rows[y][src_x + x]

    def save(self, name: str, palette) -> None:
        out = GRAPHICS / name
        out.parent.mkdir(parents=True, exist_ok=True)
        png.write_indexed(out, self.width, len(self.canvas) // self.width, bytes(self.canvas), palette)
        print(f"wrote {out}  original_crc32={self.crc:#010x}")


def main() -> None:
    cue = Path(sys.argv[1])
    _, data_name = parse_cue(cue)
    with Track(cue.parent / Path(data_name).name) as track:
        entry = list_files(track)[FILE]
        data = track.read_file(entry.lba, entry.size)

    palette = []
    for i in range(256):
        c = int.from_bytes(data[PALETTE + i * 2:PALETTE + i * 2 + 2], "little")
        r, g, b = c & 31, (c >> 5) & 31, (c >> 10) & 31
        palette.append(((r << 3) | (r >> 2), (g << 3) | (g >> 2), (b << 3) | (b >> 2)))

    # Main menu sheet: GAME START (selected + unselected), OPTIONS (unselected)
    sheet = Sheet(data, 0x60000, 0, 68, 128, 48, [[0, 0, 128, 32], [0, 32, 48, 16]])
    for row, style in ((0, BLUE), (1, GREY)):
        strip = render_strip("GAME START", 112, style)
        for cell in range(7):
            sheet.blit(strip, cell * 16, cell * 16, row * 16)
    # Unselected OPTIONS: 5 cells scattered over the sheet, in on-screen order
    strip = render_strip("OPTIONS", 80, GREY)
    for i, (dx, dy) in enumerate([(112, 0), (112, 16), (0, 32), (16, 32), (32, 32)]):
        sheet.blit(strip, i * 16, dx, dy)
    sheet.save("title_menu.png", palette)

    # Selected OPTIONS: one contiguous 80x16 strip
    selected = Sheet(data, 0x5C000, 48, 52, 80, 16, [[0, 0, 80, 16]])
    selected.blit(render_strip("OPTIONS", 80, BLUE), 0, 0, 0, w=80)
    selected.save("title_menu_options_selected.png", palette)


if __name__ == "__main__":
    main()
