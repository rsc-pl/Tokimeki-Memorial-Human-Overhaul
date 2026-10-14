"""Find Shift-JIS text in extracted game files.

Usage:
  python tools/find_text.py EXTRACTED_DIR_OR_FILE [--min N] [--grep REGEX] [--all]

Prints  <file>  <offset>  <bytes available>  <text>  for every run of at least
--min (default 2) double-byte characters that contains kana, or every run with
--all. "bytes available" is what an in-place replacement may use, including the
terminator (same rule as tokipatch.patcher.apply_string); "-" means the run isn't
null-terminated, so it's probably inside script bytecode.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

KANA = re.compile("[ぁ-んァ-ン]")


def is_lead(b: int) -> bool:
    return 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEA


def runs(data: bytes, minchars: int):
    i, n = 0, len(data)
    while i < n - 1:
        j = i
        while j < n - 1 and is_lead(data[j]) and 0x40 <= data[j + 1] <= 0xFC and data[j + 1] != 0x7F:
            j += 2
        if (j - i) // 2 >= minchars:
            try:
                yield i, j, data[i:j].decode("shift_jis")
            except UnicodeDecodeError:
                pass
            i = j
        else:
            i += 1


def capacity(data: bytes, start: int, end: int) -> str:
    if end >= len(data) or data[end] != 0:
        return "-"
    cap = end - start + 1
    while (start + cap) % 4 and start + cap < len(data) and data[start + cap] == 0:
        cap += 1
    return str(cap)


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--min", type=int, default=2)
    ap.add_argument("--grep")
    ap.add_argument("--all", action="store_true", help="include runs without kana (mostly noise)")
    args = ap.parse_args()

    paths = [args.path] if args.path.is_file() else sorted(p for p in args.path.rglob("*") if p.is_file())
    pattern = re.compile(args.grep) if args.grep else None
    for p in paths:
        data = p.read_bytes()
        for start, end, s in runs(data, args.min):
            if not args.all and not KANA.search(s):
                continue
            if pattern and not pattern.search(s):
                continue
            print(f"{p}\t{start:#07x}\t{capacity(data, start, end)}\t{s}")


if __name__ == "__main__":
    main()
