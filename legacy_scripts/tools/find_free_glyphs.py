"""List font glyphs (JIS level-1 kanji) the game's text never uses.

Usage:  python tools/find_free_glyphs.py EXTRACTED_DIR

Writes translation/font/free_glyphs.txt: one Shift-JIS code per line (hex).
The patcher used to redraw these glyphs as pre-drawn English letter pairs.
It now composes pairs in a renderer hook (docs/game-internals.md §6f) and
doesn't use this list; it's kept as research data (spare font slots).

A kanji counts as USED if it appears in either:
  - a run of 2+ Shift-JIS characters where >= 30% are kana/punctuation
    (real Japanese text; random binary data rarely passes), anywhere on the
    disc except audio/video, or
  - a short (<= 6 chars) NUL-bounded string in a text-bearing directory
    (catches kanji-only names and labels).
Everything else in the font's kanji range is free. Re-run after big
discoveries about where text lives.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "translation" / "font" / "free_glyphs.txt"

RUN = re.compile(rb"(?:[\x81-\x9f\xe0-\xea][\x40-\x7e\x80-\xfc])+")
MEDIA = ("XA_G", "DADIR", "VAB_SE", "VAB_SEQ")
TEXT_DIRS = {".", "CDROM/SERIFU", "CDROM/SPEAKTST", "CDROM/BUNKA", "CDROM/EXEDIR", "CDROM/MASTER",
             "CDROM/EVENT", "CDROM/SHIAI", "CDROM/TAIIKU", "CDROM/BATTLE", "CDROM/TARA_OBJ",
             "CDROM/END_OBJ", "CDROM/PROLODIR", "CDROM/NAME_ENT", "CDROM/EN_GAME"}
KANJI_FIRST, KANJI_END = 0x889F, 0x9873   # level-1 kanji present in the game font


def kana_or_punct(code: int) -> bool:
    return 0x8140 <= code <= 0x81FC or 0x829F <= code <= 0x8396


def main() -> None:
    root_dir = Path(sys.argv[1])
    used = set()
    for root, _, names in os.walk(root_dir):
        key = Path(os.path.relpath(root, root_dir)).as_posix()
        if any(m in key for m in MEDIA) or key == "CDROM/BS":
            continue
        for name in names:
            if name.endswith((".STR", ".tsv")):
                continue
            data = (Path(root) / name).read_bytes()
            for m in RUN.finditer(data):
                s = m.group()
                codes = [s[k] << 8 | s[k + 1] for k in range(0, len(s), 2)]
                texty = len(codes) >= 2 and sum(map(kana_or_punct, codes)) / len(codes) >= 0.3
                isolated = (key in TEXT_DIRS and len(codes) <= 6
                            and (m.start() == 0 or data[m.start() - 1] == 0)
                            and (m.end() >= len(data) or data[m.end()] == 0))
                if texty or isolated:
                    used.update(codes)

    free = [c for c in range(KANJI_FIRST, KANJI_END)
            if 0x40 <= (c & 0xFF) <= 0xFC and (c & 0xFF) != 0x7F and c not in used]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(f"{c:04X}\n" for c in free), encoding="ascii")
    print(f"{len(free)} free glyphs written to {OUT}")


if __name__ == "__main__":
    main()
