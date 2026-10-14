"""Show the space budget of each string in a translation (or dump) file.

Usage:
  python tools/dialogue_budget.py translation/shiori_dates.json [--all] [--range START END]
  python tools/dialogue_budget.py extracted/dumps/DATE_FU.json --all --range 0x18F4 0x1EDC

For every `dialogue` line it prints the string's own slot (its bytes, NUL
and padding: what the English may use without borrowing), the free gap the
slot is part of (slots of neighbouring translated lines merge into one gap;
pointer lists split them), and the English bytes. Flags:

  OVER-GAP   longer than any gap: can't fit wherever it goes
  over-slot  longer than its own slot: fits only by taking space elsewhere

Then it runs the patcher's real packing on a copy of the file and says
whether the block fits (`share_identical` is honoured). Untranslated lines
don't add space: --all counts every line as if translated (planning with a
dump, where "text" is empty, shows each string's budget). Reads the files in
extracted/ and never prints the Japanese, only offsets and numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tokipatch import font, patcher, script  # noqa: E402


class Edit:
    def __init__(self, data: bytes):
        self.original = data
        self.data = bytearray(data)
        self.log = []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("json")
    ap.add_argument("--all", action="store_true", help="count untranslated lines too")
    ap.add_argument("--range", nargs=2, type=lambda s: int(s, 0), metavar=("START", "END"),
                    help="only lines with START <= offset <= END")
    args = ap.parse_args()
    doc = json.loads(Path(args.json).read_text(encoding="utf-8"))
    pairs = font.PairEncoder()

    for item in doc.get("dialogue", []):
        path = ROOT / "extracted" / item["file"].lstrip("/")
        data = path.read_bytes()
        lines = [x for x in item["lines"] if args.all or x["text"]]
        if args.range:
            lines = [x for x in lines if args.range[0] <= int(x["offset"], 16) <= args.range[1]]
        if not lines:
            continue
        slots = {}
        for x in lines:
            off = int(x["offset"], 16)
            cap = len(script.encode_original(x["original"])) + 1
            while (off + cap) % 4 and data[off + cap] == 0:
                cap += 1
            slots[off] = cap
        gaps, gap_of = [], {}
        for off in sorted(slots):
            if gaps and gaps[-1][1] == off:
                gaps[-1][1] = off + slots[off]
            else:
                gaps.append([off, off + slots[off]])
            gap_of[off] = len(gaps) - 1
        largest = max(b - a for a, b in gaps)
        print(f"{item['file']}: {len(lines)} line(s), {len(gaps)} gap(s), "
              f"{sum(slots.values())} bytes, largest gap {largest}")
        print("  offset   slot  gap  english")
        for x in sorted(lines, key=lambda x: int(x["offset"], 16)):
            off = int(x["offset"], 16)
            a, b = gaps[gap_of[off]]
            need = len(script.encode_english(x["text"], pairs)[0]) + 1 if x["text"] else 0
            flag = ""
            if need > largest:
                flag = "OVER-GAP"
            elif need > slots[off]:
                flag = "over-slot"
            print(f"  {off:#07x} {slots[off]:5} {b - a:4}  {need or '-':>7}  {flag}")
        todo = [x for x in lines if x["text"]]
        if not todo:
            continue
        block = patcher.DialogueBlock(item["file"], int(item["base"], 0),
                                      [patcher.DialogueLine(int(x["offset"], 16), x["original"], x["text"])
                                       for x in todo], Path(args.json).name,
                                      item.get("max_cells", script.MAX_CELLS),
                                      bool(item.get("share_identical", False)))
        edit = Edit(data)
        try:
            patcher.apply_dialogue(block, edit, pairs)
            print(f"  packs: {edit.log[-1]}")
        except ValueError as e:
            print(f"  DOES NOT PACK: {e}")


if __name__ == "__main__":
    main()
