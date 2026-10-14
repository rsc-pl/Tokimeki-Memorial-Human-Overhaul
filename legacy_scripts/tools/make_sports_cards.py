"""Redraw the sports-day instruction cards in English (TAIIKU/*SETU.BIN).

Usage:  python tools/make_sports_cards.py [--preview DIR]

Each event of the sports day (TAIIKU.EXN) opens with a parchment card
explaining the controls. The card is a full-screen 320x256 8bpp tile picture
(game-internals 7, "Sports day instruction cards"):

- a tile header `u32 pages, u8 8, 8, 4, 4, u32 0x400, u32 blocks`, followed by
  `blocks` block maps of 4x4 u32 entries (byte 0 = flips: bit 0 vertical,
  bit 1 horizontal; byte 2 = tile index in its page, 16 tiles per row;
  byte 3 = page);
- a screen header (20 bytes, `.. 20 20 04 04 01 S ..`, row stride S*0x20)
  followed by 8 rows of 10 u32 block numbers;
- the pages: 128x128 8bpp, 16 KiB each (where they are isn't in the file;
  the loader works it out, so they're listed below, found by decoding).

EXE routine 0x8004D3C8 draws one 32x32 block, decoding each tile with
0x8004D6B8 and uploading it to VRAM with 0x8004435C.

The English is drawn on the decoded picture (the text area is plain
parchment, colour 0x17): body text with the pair font (tokipatch/pairfont.py)
in the card's ink 0x11, words in [brackets] in its red 0x2A, and ○ copied
from the original card. The title uses hollow letters (an outline of the bold
pair font), like the original's. Then the picture is re-encoded with as few
changes as possible:

- cells that didn't change keep their tile;
- a changed cell reuses any kept tile with the same pixels (also flipped),
  else takes a tile slot no unchanged cell uses any more, preferring the
  slots of the replaced Japanese glyphs;
- blocks are rebuilt the same way, reusing the block numbers that no longer
  appear on the screen. Block 0 is never used: the caller (0x8004D1C8-)
  skips screen entries whose low 16 bits are 0, leaving that 32x32 area
  undrawn.

Writes translation/sports_day_cards.json: image patches over the changed
tiles (with the CRC of the pixels they replace) and byte patches for the
changed block maps and screen entries. With --preview, also writes each
card's English picture as a PNG there.
"""

from __future__ import annotations

import json
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "legacy_scripts" / "tools"))
from tokipatch import pairfont, png  # noqa: E402

BG, INK, RED = 0x17, 0x11, 0x2A
TEXT_BOX = (50, 36, 270, 172)          # x0, y0, x1, y1 (inclusive) of the card's plain parchment
TITLE_TOP = 41                         # rows 41-54 hold the title
LINE_TOPS = (74, 90, 106, 122, 138, 154)
LEFT = 58

# file, tile header, screen header, pages, title, lines, and each line's
# right limit (the girl standing at the card's lower right covers the rest).
CARDS = [
    {"file": "CDROM/TAIIKU/SPSETU.BIN", "tiles": 0xE000, "screen": 0xF190, "pages": [0x2000, 0x6000],
     "title": "Spoon Relay",
     "lines": ["If the ball rolls [left], press [L];",
               "if it rolls [right], press [R].",
               "Keep it balanced so it won't fall!",
               "Mash the [○ button]",
               "to run."],
     "limits": [262, 262, 262, 206, 176, 176]},
    {"file": "CDROM/TAIIKU/KASETU.BIN", "tiles": 0xE008, "screen": 0xF218, "pages": [0x2000, 0x6000],
     "title": "Borrowing Race",
     "lines": ["Find the [girl] named in the",
               "envelope with the [D-pad]",
               "and take her to the goal.",
               "Pick the [girl] to bring",
               "with the [○ button].",
               "Mash [○] to run!"],
     "limits": [262, 266, 262, 206, 222, 254]},
    {"file": "CDROM/TAIIKU/TASETU.BIN", "tiles": 0x12008, "screen": 0x13198, "pages": [0x2000, 0x6000],
     "title": "Ball Rolling",
     "lines": ["First, choose your [partner].",
               "During the game, use the [D-pad]",
               "to move [in all four directions]",
               "and push the ball with [○].",
               "Push [evenly from left and right]."],
     "limits": [262, 262, 266, 266, 254]},
    {"file": "CDROM/TAIIKU/NINSETU.BIN", "tiles": 0x1E008, "screen": 0x201B0, "pages": [0xE000, 0x12000],
     "title": "Three-Legged Race",
     "lines": ["[Follow my voice] and [press the]",
               "[buttons] right on the beat.",
               "Press the wrong one and we'll",
               "fall over, so be careful.",
               "[First, the left (L) button].",
               "Ready?"],
     "limits": [262, 262, 262, 262, 262, 262]},
    {"file": "CDROM/TAIIKU/NINSETU.BIN", "tiles": 0x1F020, "screen": 0x239EC, "pages": [0x16000, 0x1A000],
     "title": "Three-Legged Race",
     "lines": ["[Follow my voice] and [press the]",
               "[buttons] right on the beat, please.",
               "Press the wrong one and we'll",
               "fall over.",
               "[We start with the left (L) button].",
               "Are you ready?"],
     "limits": [262, 266, 262, 262, 266, 262]},
]


class Picture:
    def __init__(self, data: bytes, card):
        self.data = data
        self.pages = card["pages"]
        th = card["tiles"]
        self.nblocks = struct.unpack_from("<I", data, th + 12)[0]
        self.bm = th + 16
        sh = card["screen"]
        if data[sh + 4:sh + 8] != b"\x20\x20\x04\x04" or data[th + 4:th + 8] != b"\x08\x08\x04\x04":
            raise SystemExit(f"{card['file']}: no tile picture at {th:#x}/{sh:#x}")
        self.rows0, self.stride = sh + 0x14, data[sh + 9] * 0x20
        self.screen = [[self.screen_at(r, c) for c in range(10)] for r in range(8)]
        self.blocks = [[struct.unpack_from("<I", data, self.bm + 64 * b + 4 * k)[0] for k in range(16)]
                       for b in range(self.nblocks)]

    def screen_at(self, r, c):
        return struct.unpack_from("<I", self.data, self.rows0 + r * self.stride + 4 * c)[0]

    def slot_offset(self, page, idx):
        return self.pages[page] + (idx // 16) * 8 * 128 + (idx % 16) * 8

    def tile(self, entry, data=None):
        """8x8 pixels of a map entry (flips applied), as 64 bytes."""
        data = data or self.data
        fl, idx, page = entry & 0xFF, (entry >> 16) & 0xFF, entry >> 24
        o = self.slot_offset(page, idx)
        rows = [bytes(data[o + y * 128:o + y * 128 + 8]) for y in range(8)]
        if fl & 2:
            rows = [r[::-1] for r in rows]
        if fl & 1:
            rows = rows[::-1]
        return b"".join(rows)

    def decode(self):
        img = bytearray(320 * 256)
        for r in range(8):
            for c in range(10):
                for k, e in enumerate(self.blocks[self.screen[r][c]]):
                    t = self.tile(e)
                    x, y = c * 32 + (k % 4) * 8, r * 32 + (k // 4) * 8
                    for yy in range(8):
                        img[(y + yy) * 320 + x:(y + yy) * 320 + x + 8] = t[yy * 8:yy * 8 + 8]
        return img


def cell(img, cx, cy):
    return b"".join(bytes(img[(cy * 8 + y) * 320 + cx * 8:(cy * 8 + y) * 320 + cx * 8 + 8]) for y in range(8))


def flips(t: bytes):
    rows = [t[i:i + 8] for i in range(0, 64, 8)]
    yield 0, t
    yield 2, b"".join(r[::-1] for r in rows)
    yield 1, b"".join(rows[::-1])
    yield 3, b"".join(r[::-1] for r in rows[::-1])


def circle_glyph(img):
    """The red ○ of the spoon relay card (line 5, x 58-70): rows of bools."""
    rows = []
    for y in range(137, 150):
        rows.append([img[y * 320 + x] in (RED, 0x2B) for x in range(58, 71)])
    while rows and not any(rows[0]):
        rows.pop(0)
    while rows and not any(rows[-1]):
        rows.pop()
    cols = [x for x in range(13) if any(r[x] for r in rows)]
    return [r[min(cols):max(cols) + 1] for r in rows]


def letter(ch, circle):
    if ch == "○":
        return circle, 1          # (rows, top offset)
    rows = pairfont.letter_rows(ch)
    used = [c for c in range(5) if any(r >> (4 - c) & 1 for r in rows)]
    if not used:
        return [[False] * 3 for _ in range(12)], 0
    return [[bool(r >> (4 - c) & 1) for c in range(min(used), max(used) + 1)] for r in rows], 0


def draw_line(img, text, x, top, limit, circle):
    red, cx = False, x
    for ch in text:
        if ch in "[]":
            red = ch == "["
            continue
        rows, dy = letter(ch, circle)
        w = len(rows[0])
        for gy, row in enumerate(rows):
            for gx, on in enumerate(row):
                if on:
                    img[(top + dy + gy) * 320 + cx + gx] = RED if red else INK
        cx += w + 1
    if cx - 2 > limit:
        raise SystemExit(f"{text!r} reaches x {cx - 2}, the limit is {limit}")


def draw_title(img, text):
    """Hollow letters: the outline (ink) around the bold pair font."""
    shape = set()
    x = 0
    for ch in text:
        rows, _ = letter(ch, None)
        w = len(rows[0])
        for gy, row in enumerate(rows):
            for gx, on in enumerate(row):
                if on:
                    shape |= {(x + gx, gy), (x + gx + 1, gy)}
        x += w + 4 if ch != " " else 5
    width = x - 3
    if width > TEXT_BOX[2] - TEXT_BOX[0] - 4:
        raise SystemExit(f"title {text!r} is {width} px wide")
    left = (TEXT_BOX[0] + TEXT_BOX[2] + 1 - width) // 2
    top = TITLE_TOP + 1
    for gx, gy in {(a + dx, b + dy) for a, b in shape for dx in (-1, 0, 1) for dy in (-1, 0, 1)} - shape:
        img[(top + gy) * 320 + left + gx] = INK


def build_card(card, data: bytearray, preview: Path | None):
    pic = Picture(bytes(data), card)
    orig = pic.decode()
    img = bytearray(orig)
    circle = circle_glyph(Picture(SPOON, CARDS[0]).decode())
    x0, y0, x1, y1 = TEXT_BOX
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            img[y * 320 + x] = BG
    draw_title(img, card["title"])
    for i, line in enumerate(card["lines"]):
        draw_line(img, line, LEFT, LINE_TOPS[i] - 1, card["limits"][i], circle)
    if preview:
        clut = [struct.unpack_from("<H", data, 2 * i)[0] for i in range(256)]
        pal = [((c & 31) * 255 // 31, (c >> 5 & 31) * 255 // 31, (c >> 10 & 31) * 255 // 31) for c in clut]
        png.write_indexed(preview / f"{Path(card['file']).stem}_{card['tiles']:x}.png", 320, 256, bytes(img), pal)

    # cell entries: (r, c, k) -> entry
    entries = {}
    for r in range(8):
        for c in range(10):
            for k, e in enumerate(pic.blocks[pic.screen[r][c]]):
                entries[(r, c, k)] = e
    def cxy(r, c, k):
        return c * 4 + k % 4, r * 4 + k // 4
    changed = [key for key in entries if cell(img, *cxy(*key)) != cell(orig, *cxy(*key))]
    keep = {key: e for key, e in entries.items() if key not in changed}
    slot = lambda e: ((e >> 24) & 0xFF, (e >> 16) & 0xFF)
    used = {slot(e) for e in keep.values()}
    jp = []                       # slots of the replaced glyphs first
    for key in changed:
        s = slot(entries[key])
        if s not in used and s not in jp:
            jp.append(s)
    blank = [(p, i) for p in range(len(pic.pages)) for i in range(256)
             if (p, i) not in used and (p, i) not in jp and not any(pic.tile(i << 16 | p << 24))]
    free = jp + blank
    pool = {}
    for e in keep.values():
        for f, t in flips(pic.tile(e)):
            pool.setdefault(t, (e & ~0xFF) | ((e & 0xFF) ^ f))
    new_pixels = {}
    final = dict(keep)
    for key in changed:
        t = cell(img, *cxy(*key))
        if t not in pool:
            if not free:
                raise SystemExit(f"{card['file']}: out of tile slots")
            p, i = free.pop(0)
            new_pixels[(p, i)] = t
            e = p << 24 | i << 16
            for f, ft in flips(t):
                pool.setdefault(ft, e | f)
        final[key] = pool[t]

    # blocks
    want = {(r, c): tuple(final[(r, c, k)] for k in range(16)) for r in range(8) for c in range(10)}
    orig_blocks = {b: tuple(pic.blocks[b]) for b in range(pic.nblocks)}
    by_content = {}
    for b, content in orig_blocks.items():
        by_content.setdefault(content, b)
    screen = {}
    for pos, content in want.items():
        if content in by_content:
            screen[pos] = by_content[content]
    still = set(screen.values()) | {pic.screen[r][c] for r in range(8) for c in range(10)
                                    if (r, c) not in want}
    # block 0 means "nothing here": the caller (0x8004D248) skips it
    free_blocks = [b for b in range(1, pic.nblocks) if b not in still]
    new_blocks = {}
    for pos, content in sorted(want.items()):
        if pos in screen:
            continue
        hit = next((b for b, cnt in new_blocks.items() if cnt == content), None)
        if hit is None:
            if not free_blocks:
                raise SystemExit(f"{card['file']}: out of block numbers")
            hit = free_blocks.pop(0)
            new_blocks[hit] = content
        screen[pos] = hit
    # apply to data
    for (p, i), t in new_pixels.items():
        o = pic.slot_offset(p, i)
        for y in range(8):
            data[o + y * 128:o + y * 128 + 8] = t[y * 8:y * 8 + 8]
    for b, content in new_blocks.items():
        struct.pack_into("<16I", data, pic.bm + 64 * b, *content)
    for (r, c), b in screen.items():
        struct.pack_into("<I", data, pic.rows0 + r * pic.stride + 4 * c, b)
    check = Picture(bytes(data), card).decode()
    if check != img:
        raise SystemExit(f"{card['file']}: re-encoded picture doesn't match")
    return pic, new_pixels, len(changed), len(free_blocks)


SPOON = b""


def main() -> None:
    global SPOON
    args = sys.argv[1:]
    preview = Path(args[args.index("--preview") + 1]) if "--preview" in args else None
    if preview:
        preview.mkdir(parents=True, exist_ok=True)
    SPOON = (ROOT / "extracted" / CARDS[0]["file"]).read_bytes()
    files = {}
    for card in CARDS:
        files.setdefault(card["file"], bytearray((ROOT / "extracted" / card["file"]).read_bytes()))
    tiles = {}
    for card in CARDS:
        pic, new_pixels, n_changed, spare = build_card(card, files[card["file"]], preview)
        for (p, i) in new_pixels:
            tiles.setdefault((card["file"], pic.pages[p]), set()).add(i)
        print(f"{card['file']} @{card['tiles']:#x}: {n_changed} cells changed, {len(new_pixels)} tiles redrawn, "
              f"{spare} block numbers spare")

    images, patches = [], []
    gdir = ROOT / "translation" / "graphics"
    grey = [(i, i, i) for i in range(256)]
    for (fname, page), idxs in sorted(tiles.items()):
        orig = (ROOT / "extracted" / fname).read_bytes()
        new = files[fname]
        name = f"sports_card_{Path(fname).stem.lower()}_{page:05x}.png"
        png.write_indexed(gdir / name, 128, 128, bytes(new[page:page + 0x4000]), grey)
        rects = [[(i % 16) * 8, (i // 16) * 8, 8, 8] for i in sorted(idxs)]
        before = bytearray()
        for x, y, w, h in rects:
            for yy in range(y, y + h):
                before += orig[page + yy * 128 + x:page + yy * 128 + x + w]
        images.append({"file": fname, "png": f"graphics/{name}", "pixels": f"0x{page:X}", "stride": 128,
                       "x": 0, "y": 0, "rects": rects, "original_crc32": f"0x{zlib.crc32(before):08x}"})
    for fname, new in files.items():
        orig = (ROOT / "extracted" / fname).read_bytes()
        pages = [range(p, p + 0x4000) for c in CARDS if c["file"] == fname for p in c["pages"]]
        i = 0
        while i < len(orig):
            if new[i] != orig[i] and not any(i in r for r in pages):
                j = i
                while j < len(orig) and (new[j] != orig[j] or new[j:j + 8] != orig[j:j + 8]) \
                        and not any(j in r for r in pages):
                    j += 1
                a, b = i & ~3, (j + 3) & ~3
                patches.append({"file": fname, "offset": f"0x{a:X}", "original": orig[a:b].hex(),
                                "replacement": bytes(new[a:b]).hex(), "comment": "block maps / screen map"})
                i = b
            else:
                i += 1
    doc = {
        "description": ("Sports day instruction cards (TAIIKU/SPSETU, KASETU, TASETU, NINSETU.BIN: spoon relay, "
                        "borrowing race, ball rolling, three-legged race in two versions), tile pictures redrawn in "
                        "English and re-encoded by tools/make_sports_cards.py (game-internals 7)."),
        "images": images,
        "bytes": patches,
    }
    (ROOT / "translation" / "sports_day_cards.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(images)} image patches, {len(patches)} byte patches")


if __name__ == "__main__":
    main()
