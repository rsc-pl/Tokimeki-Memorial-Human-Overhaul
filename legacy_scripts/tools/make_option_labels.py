"""Generate English labels for the title Options sub-screens (OPTION.NBN).

Usage:  python tools/make_option_labels.py

The choice words on the Text Speed, Icon Mode, Cursor Speed and Voice Mode
sub-screens are sprite *frames* in CDROM/FUKUTEST/OPTION.NBN (game-internals
6c): a frame table at file offset 0x132D8 (RAM 0x801C32D8) points at frames
of `s16 parts, x, y, 0` followed by 14-byte parts `x, y, cell, attr, 0, w,
h`. A label frame has one 16x16 part per Japanese character, 14 px apart,
and comes in pairs (normal attr 0x2000, highlighted 0x2100). `cell` counts
8x8 tiles of a 128 px wide 8bpp strip whose rows 0-127 are file
0x0000-0x3FFF and rows 128-255 file 0xC000-0xFFFF.

The strip is nearly full, so this tool reuses only what is safe:
- the tiles of the Japanese glyphs that only these labels used (the glyph
  cells of 遅い, 普通, 速い, 超, フリー, 初期状態, 変更, ×ボタンでカット), and
- tiles that are blank in the original and that no remaining frame uses.
Glyph cells no frame references are left alone: the Icon Mode screen draws
one of them (cell 36, under the フリー label) from code, and overwriting it
put a stray line under "Free".

English is drawn with the pair font (tokipatch/pairfont.py), proportionally
spaced, in the sheet's own style (colour index 0x37 down to 0x31 by row, a
0xE2 shadow one pixel down-right). Each distinct word is one strip, packed
into free 16 px tall runs of tiles; a frame is a list of words (V.Slow is
"V." + the Slow strip, as the original shares 遅い between 遅い and 超遅い),
and may not use more parts than it had.

Writes translation/graphics/option_labels_0000.png and _c000.png and
translation/option_labels.json (image patches with the CRC of the replaced
pixels, byte patches rewriting the frames). Re-run after changing a label.
"""

from __future__ import annotations

import itertools
import json
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tokipatch import pairfont, png  # noqa: E402

FILE = "CDROM/FUKUTEST/OPTION.NBN"
BASE, TABLE = 0x801B0000, 0x132D8
BLOCKS = (0x0000, 0xC000)          # strip rows 0-127 and 128-255
SHADOW = 0xE2
ROW_COLOUR = {4: 0x37, 5: 0x37, 6: 0x37, 7: 0x37, 8: 0x36, 9: 0x35, 10: 0x34,
              11: 0x33, 12: 0x32, 13: 0x31, 14: 0x31, 15: 0x31}

# Normal frame -> words drawn side by side; the highlighted copy is the next
# frame. The Mouse sub-screen (27-39, needs a PlayStation Mouse) and the
# graphic Extras entries (51-61, 117, only after a clear) stay Japanese:
# the strip has no room left for them (game-internals 6c).
LABELS = {
    11: ["V.", "Slow"], 13: ["Slow"], 15: ["Norm"], 17: ["Fast"], 19: ["V.", "Fast"],
    25: ["Free"],
    41: ["Init"], 43: ["Edit"],
    49: ["Skip X"],
}


def frames(data: bytes):
    out, i = [], 0
    while True:
        p = struct.unpack_from("<I", data, TABLE + 4 * i)[0]
        if not BASE <= p < BASE + len(data):
            return out
        o = p - BASE
        n = struct.unpack_from("<h", data, o)[0]
        out.append((o, [list(struct.unpack_from("<hhhhhhh", data, o + 8 + 14 * k)) for k in range(n)]))
        i += 1


def part_tiles(part):
    _, _, cell, _, _, w, h = part
    return {cell + ty * 16 + tx for ty in range((h + 7) // 8) for tx in range((w + 7) // 8)}


def tile_offset(tile: int) -> int:
    """File offset of a tile's top-left pixel."""
    block, t = divmod(tile, 256)
    return BLOCKS[block] + (t // 16) * 8 * 128 + (t % 16) * 8


def word_pixels(text: str):
    """(width, 16 rows of colour indices) for `text`, proportionally spaced:
    each letter takes its inked columns plus a 1 px gap (where the shadow
    falls); a space is 3 px."""
    cols = []
    for ch in text:
        rows = pairfont.letter_rows(ch)
        used = [c for c in range(5) if any(r >> (4 - c) & 1 for r in rows)]
        if not used:
            cols += [[0] * 12] * 3
            continue
        for c in range(min(used), max(used) + 1):
            cols.append([r >> (4 - c) & 1 for r in rows])
        cols.append([0] * 12)
    w = len(cols)
    ink = [[False] * w for _ in range(16)]
    for x, col in enumerate(cols):
        for r, bit in enumerate(col):
            ink[4 + r][x] = bool(bit)
    px = [[0] * w for _ in range(16)]
    for y in range(16):
        for x in range(w):
            if ink[y][x]:
                px[y][x] = ROW_COLOUR[y]
            elif y and x and ink[y - 1][x - 1]:
                px[y][x] = SHADOW
    return w, px


def free_runs(free):
    """Maximal horizontal runs of free 16 px tall tile columns: [(tile, cols)].
    Runs start on even tile rows only, like the original glyph cells, so two
    runs never share a tile row."""
    runs, seen = [], set()
    for t in sorted(free):
        if t in seen or t + 16 not in free or (t % 256) // 16 % 2:
            continue
        n = 0
        while (t + n) // 16 == t // 16 and t + n in free and t + n + 16 in free:
            seen.add(t + n)
            n += 1
        runs.append((t, n))
    return runs


def pack(words, runs, max_parts):
    """Assign each word (id -> tile columns needed) to pieces of runs, using as
    few pieces as possible; max_parts limits the pieces per word. Returns
    {word: [(tile, cols)]} or None. Exhaustive over orders: the sets are small."""
    best = None
    names = sorted(words, key=lambda k: -words[k])
    for order in itertools.permutations(names):
        avail = [list(r) for r in runs]
        out, ok = {}, True
        for name in order:
            need, pieces = words[name], []
            # one piece if any run holds it all (smallest that fits), else largest first
            fit = sorted((r for r in avail if r[1] >= need), key=lambda r: r[1])
            if fit:
                r = fit[0]
                pieces.append((r[0], need))
                r[0] += need
                r[1] -= need
            else:
                for r in sorted(avail, key=lambda r: -r[1]):
                    if need <= 0 or not r[1]:
                        break
                    take = min(r[1], need)
                    pieces.append((r[0], take))
                    r[0] += take
                    r[1] -= take
                    need -= take
                if need > 0 or len(pieces) > max_parts[name]:
                    ok = False
                    break
            out[name] = pieces
        if ok:
            total = sum(len(p) for p in out.values())
            if best is None or total < best[0]:
                best = (total, out)
    return best and best[1]


def main() -> None:
    data = bytearray((ROOT / "extracted" / FILE).read_bytes())
    fr = frames(data)
    ours = set(LABELS) | {f + 1 for f in LABELS}

    kept, mine = set(), set()
    for i, (_, parts) in enumerate(fr):
        for p in parts:
            (mine if i in ours else kept).update(part_tiles(p))

    def blank(t):
        o = tile_offset(t)
        return all(data[o + r * 128:o + r * 128 + 8] == bytes(8) for r in range(8))

    # Block 0's tile row 0 carries other data in its pixel rows 0-3: never touched.
    free = {t for t in range(512) if t >= 16 and t not in kept and (t in mine or blank(t))}

    strips = {}
    for words in LABELS.values():
        for wd in words:
            strips.setdefault(wd, word_pixels(wd))
    need = {wd: (w + 7) // 8 for wd, (w, _) in strips.items()}
    # Pieces allowed per word: the fewest parts of any frame using it, minus
    # the parts its other words take (at least one each).
    max_parts = {}
    for f, words in LABELS.items():
        n = len(fr[f][1])
        for wd in words:
            max_parts[wd] = min(max_parts.get(wd, 99), n - (len(words) - 1))
    placed = pack(need, free_runs(free), max_parts)
    if placed is None:
        raise SystemExit("the labels don't fit in the free tiles of the OPTION.NBN strip")

    canvas = {b: bytearray(data[b:b + 0x4000]) for b in BLOCKS}
    rects = {b: [] for b in BLOCKS}
    word_parts = {}
    for wd, pieces in placed.items():
        w, px = strips[wd]
        x0, parts = 0, []
        for tile, cols in pieces:
            block = BLOCKS[tile // 256]
            base = tile_offset(tile) - block
            for y in range(16):
                for x in range(cols * 8):
                    canvas[block][base + y * 128 + x] = px[y][x0 + x] if x0 + x < w else 0
            rects[block].append((base, cols * 8))
            parts.append((x0, tile, cols * 8))
            x0 += cols * 8
        word_parts[wd] = (w, parts)

    patches = []
    for f in sorted(LABELS):
        layout, x = [], 0
        for wd in LABELS[f]:
            w, parts = word_parts[wd]
            layout += [(x + px_, tile, pw) for px_, tile, pw in parts]
            x += w
        for frame in (f, f + 1):
            fo, fparts = fr[frame]
            attr = fparts[0][3]
            body = b"".join(struct.pack("<hhhhhhh", px_, 0, tile, attr, 0, pw, 16) for px_, tile, pw in layout)
            old = bytes(data[fo:fo + 8 + len(body)])
            rep = struct.pack("<h", len(layout)) + old[2:8] + body
            patches.append({"file": FILE, "offset": f"0x{fo:X}", "original": old.hex(),
                            "replacement": rep.hex(), "comment": f"frame {frame}: {''.join(LABELS[f])}"})

    images = []
    gdir = ROOT / "translation" / "graphics"
    grey = [(i, i, i) for i in range(256)]
    for block in BLOCKS:
        if not rects[block]:
            continue
        name = f"option_labels_{block:04x}.png"
        png.write_indexed(gdir / name, 128, 128, bytes(canvas[block]), grey)
        rect_list = [[off % 128, off // 128, rw, 16] for off, rw in sorted(rects[block])]
        orig = bytearray()
        for x, y, rw, h in rect_list:
            for r in range(h):
                orig += data[block + (y + r) * 128 + x: block + (y + r) * 128 + x + rw]
        images.append({"file": FILE, "png": f"graphics/{name}", "pixels": f"0x{block:X}",
                       "stride": 128, "x": 0, "y": 0, "rects": rect_list,
                       "original_crc32": f"0x{zlib.crc32(orig):08x}"})
    for stale in gdir.glob("option_labels_*.png"):
        if not any(i["png"].endswith(stale.name) for i in images):
            stale.unlink()
    doc = {
        "description": ("Title > Options sub-screen choice words (Text Speed, Cursor Speed, Icon Mode, Voice Mode), "
                        "pre-drawn sprite frames in OPTION.NBN (game-internals 6c): English drawn with the pair font in "
                        "the sheet's style into the tiles of the replaced glyphs and blank tiles, and each frame's parts "
                        "rewritten. Generated by tools/make_option_labels.py. TYPE-A/B and ON/OFF stay (already Latin); "
                        "the Mouse sub-screen and the graphic Extras entries stay Japanese (no room)."),
        "images": images,
        "bytes": patches,
    }
    (ROOT / "translation" / "option_labels.json").write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n",
                                                             encoding="utf-8")
    used = sum(c for p in placed.values() for _, c in p)
    print(f"{len(LABELS)} labels, {len(strips)} word strips, {used} tile columns used, "
          f"{sum(n for _, n in free_runs(free)) - used} left")


if __name__ == "__main__":
    main()
