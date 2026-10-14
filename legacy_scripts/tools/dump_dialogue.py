"""Dump the dialogue strings of a script file as a translation skeleton.

Usage:
  python tools/dump_dialogue.py extracted/CDROM/SERIFU/EVENT_KI.BIN [--disc-path CDROM/SERIFU/EVENT_KI.BIN]
                                [--base 0x80198000] [--range START END] [--rejected] [-o out.json]

Finds the file's load address (the base its string pointers are relative to)
unless --base is given, then lists every string some pointer points at, as
"dialogue" lines with an empty "text". Fill in "text" and put the file in
translation/ (see docs/translation-guide.md, "Dialogue").

Pointer targets that decode as text but don't start a string (pointers into
the middle of one, or a wrong base) are counted on stderr; --rejected lists
them so they can be audited.

Write dumps outside the repo (e.g. into extracted/): an untranslated dump is
a copy of the Japanese script and must not be committed (docs/PS1_BUILD_SAFETY.md, no-game-data rule).
"""

from __future__ import annotations

import argparse
import collections
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tokipatch import script  # noqa: E402


def starts_string(data: bytes, base: int, off: int) -> bool:
    """Whether `off` can be the first byte of a string, not its middle.

    A string starts the file, follows a NUL, or follows an aligned pointer
    table: script files interleave short tables of pointers with the strings
    they list (EVENT_FU.BIN 0x62C follows the word at 0x628). A pointer into
    a script file has a third byte below 0x20, which is neither Shift-JIS nor
    a control code, so no string can run through such a word.
    """
    if off == 0 or data[off - 1] == 0:
        return True
    # A byte below 0x40 that isn't the line-break code can't be part of a
    # string (it's neither a Shift-JIS byte nor a control code). TEL.EXN puts
    # strings straight after tables of 4-byte records like `27 00 00 03`
    # (game-internals 6m), so this is a string start too.
    if data[off - 1] < 0x40 and data[off - 1] != script.LINE_BREAK:
        return True
    if off % 4 or off < 4:
        return False
    # ...or a record whose last byte happens to be 0x20 (`xx 00 00 20`):
    # the NULs two bytes back mean no string runs into this word.
    if data[off - 2] == 0:
        return True
    word = struct.unpack_from("<I", data, off - 4)[0]
    return base <= word < base + len(data)


def string_at(data: bytes, base: int, off: int):
    if not 0 <= off < len(data) or data[off] == 0 or not starts_string(data, base, off):
        return None
    try:
        raw = script.read_string(data, off)
        text = script.decode(raw)
    except ValueError:
        return None
    return text if any(ord(c) > 0x7F for c in text) else None


def targets(data: bytes, base: int, rejected: dict = None):
    """{offset: text} of every dialogue string some pointer points at.

    If `rejected` is given, it collects {offset: reason} for pointer targets
    inside the file that decode as text but aren't taken, so they can be
    audited instead of silently disappearing.
    """
    found = {}
    for pos in range(0, len(data) - 3, 4):
        off = struct.unpack_from("<I", data, pos)[0] - base
        if off in found or not 0 <= off < len(data):
            continue
        text = string_at(data, base, off)
        if text is not None:
            found[off] = text
        elif rejected is not None and off not in rejected and data[off] != 0:
            try:
                text = script.decode(script.read_string(data, off))
            except ValueError:
                continue
            rejected[off] = "not at a string start (interior pointer?)" \
                if any(ord(c) > 0x7F for c in text) else "no Japanese text"
    return found


def guess_base(data: bytes) -> int:
    """The load address that makes the most pointers land on strings.

    Candidates come from a 0x800 grid and from votes (pointer value minus a
    string start), because not every base is 0x800-aligned: GASSH_FU.BIN's
    is 0x801B4400.
    """
    words = [struct.unpack_from("<I", data, pos)[0] for pos in range(0, len(data) - 3, 4)]
    best = (0, 0)
    for base in range(0x80010000, 0x80200000, 0x800):
        lo, hi = base, base + len(data)
        hits = sum(1 for w in words if lo <= w < hi)
        if hits > best[1]:
            best = (base, hits)
    candidates = set(range(best[0] - 0x10000, best[0] + 0x10000, 0x800))

    starts = [off for off in range(len(data))
              if (off == 0 or data[off - 1] == 0) and script._is_lead(data[off])]
    pointers = [w for w in words if 0x80010000 <= w < 0x80200000]
    sample = pointers[::max(1, len(pointers) // 128)]
    votes = collections.Counter(w - s for w in sample for s in starts if w - s >= 0x80010000)
    candidates.update(b for b, _ in votes.most_common(8))
    return max(sorted(candidates), key=lambda b: len(targets(data, b)))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--disc-path", help="path on the disc (default: guessed from PATH)")
    ap.add_argument("--base", type=lambda s: int(s, 0))
    ap.add_argument("--range", nargs=2, type=lambda s: int(s, 0), metavar=("START", "END"),
                    help="only strings at file offsets in [START, END)")
    ap.add_argument("--rejected", action="store_true",
                    help="list pointer targets that decode as text but aren't string starts")
    ap.add_argument("-o", "--output", type=Path)
    args = ap.parse_args()

    data = args.path.read_bytes()
    base = args.base if args.base is not None else guess_base(data)
    disc = args.disc_path or "/".join(args.path.parts[args.path.parts.index("CDROM"):]) \
        if "CDROM" in args.path.parts else args.path.name
    in_range = (lambda off: args.range[0] <= off < args.range[1]) if args.range else (lambda off: True)
    rejected = {}
    lines = []
    for off, text in sorted(targets(data, base, rejected).items()):
        if in_range(off):
            lines.append({"offset": f"{off:#x}", "original": text, "text": ""})
    rejected = {off: why for off, why in rejected.items() if in_range(off)}
    if rejected:
        print(f"{len(rejected)} pointer target(s) decode as text but were left out"
              + ("" if args.rejected else " (list them with --rejected)"), file=sys.stderr)
        if args.rejected:
            for off, why in sorted(rejected.items()):
                print(f"  {off:#x}: {why}", file=sys.stderr)
    doc = {"description": "", "dialogue": [{"file": disc, "base": f"{base:#x}", "lines": lines}]}
    out = json.dumps(doc, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(out + "\n", encoding="utf-8")
        print(f"{len(lines)} strings, base {base:#x} -> {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
