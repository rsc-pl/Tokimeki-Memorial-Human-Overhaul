"""Repack a run of in-place strings the code addresses, and repoint the code.

Usage:
  python tools/repack_words.py CDROM/EXEDIR/DATE.EXN --region 0x28B20 0x28E90
      --texts extracted/tables/DATE_EXN_banners.json [--base 0x80132000]
      [--max-len 20] [--comment "..."] -o translation/extra/date_banners.json

Some overlays keep a run of short strings that the code reaches only one
way: `lui` + `addiu` building the string's address for a strcpy (the date
place banners in DATE.EXN, game-internals 6k; the trip's city names in
SHUGAKU.EXN, 6y). Many English words don't fit a 4- or 6-byte Japanese
slot, but the run as a whole has room. This tool:

1. finds every NUL-terminated string in [START, END) and every `lui`/`addiu`
   pair (tools/code_strings.address_builds) that builds an address in the
   run; it refuses if one doesn't point at a string start, if a data word
   in the file points into the run, or if a string has no reader at all;
2. lays out the English (pair-encoded, NUL-terminated, 2-byte aligned)
   from START, storing identical English once (each reader gets its own
   pointer anyway), and fills the rest of the run with NUL; strings with no
   entry in --texts keep their Japanese bytes (moved like the others);
3. writes a translation JSON with one `bytes` patch for the run and one per
   `addiu` (the immediate only: the high half stays valid because the run
   doesn't cross a 64 KB boundary of the address space; checked).

--texts maps "0x28b20" (file offset) or a Japanese string (every copy)
to English. --max-len refuses English longer than N letters: the strcpy
destination is a fixed buffer, so stay within the longest original
(20 bytes for DATE's banners) unless the buffer is known to be larger.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "legacy_scripts" / "tools"))
from tokipatch import font  # noqa: E402


def address_builds(words):
    """Same as code_strings.address_builds, without the capstone import."""
    found = {}
    for i, w in enumerate(words):
        if w >> 26 != 0x0F:
            continue
        rt, hi = (w >> 16) & 31, w & 0xFFFF
        for j in range(i + 1, min(i + 16, len(words))):
            v = words[j]
            op, rs = v >> 26, (v >> 21) & 31
            if rs == rt and op in (0x09, 0x0D):
                lo = v & 0xFFFF
                if op == 0x09 and lo & 0x8000:
                    lo -= 0x10000
                found.setdefault(((hi << 16) + lo) & 0xFFFFFFFF, []).append((i, j))
            if op in (0x09, 0x0D, 0x0F, 0x23) and (v >> 16) & 31 == rt and j != i:
                break
    return found


def strings_in(data, start, end):
    out, o = [], start
    while o < end:
        if data[o] == 0:
            o += 1
            continue
        e = data.index(b"\0", o)
        out.append((o, bytes(data[o:e])))
        o = e + 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--region", nargs=2, required=True)
    ap.add_argument("--texts", required=True)
    ap.add_argument("--base", default="0x80132000")
    ap.add_argument("--max-len", type=int, default=20)
    ap.add_argument("--comment", default="")
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    disc = a.file.upper().lstrip("/")
    data = (ROOT / "extracted" / disc).read_bytes()
    base = int(a.base, 0)
    start, end = (int(x, 0) for x in a.region)
    hi = lambda addr: (addr + 0x8000) >> 16   # the lui half for a signed addiu
    if hi(base + start) != hi(base + end - 1):
        sys.exit("the run crosses a lui boundary; this tool only rewrites addiu immediates")
    words = struct.unpack_from(f"<{len(data) // 4}I", data)
    builds = address_builds(words)

    strs = strings_in(data, start, end)
    starts = {o for o, _ in strs}
    readers = {}
    for addr, pairs in builds.items():
        o = addr - base
        if start <= o < end:
            if o not in starts:
                sys.exit(f"an address {addr:#x} built at {base + 4 * pairs[0][1]:#x} "
                         f"points inside a string, not at its start")
            readers[o] = pairs
    for k, w in enumerate(words):
        if base + start <= w < base + end:
            sys.exit(f"data word at {4 * k:#x} points into the run ({w:#x})")
    for o, raw in strs:
        if o not in readers:
            sys.exit(f"string at {o:#x} ({raw.decode('shift_jis', 'replace')}) has no lui/addiu reader")

    table = json.loads(Path(a.texts).read_text(encoding="utf-8"))
    pairs_enc = font.PairEncoder()
    layout, placed, cursor = bytearray(), {}, 0
    entries, patches = [], []
    for o, raw in strs:
        jp = raw.decode("shift_jis")
        en = table.get(f"{o:#x}", table.get(f"{o:#X}", table.get(jp)))
        if en is not None and len(en) > a.max_len:
            sys.exit(f"{o:#x} {jp}: {en!r} is longer than {a.max_len} letters")
        blob = pairs_enc.encode(en) if en is not None else raw
        if blob not in placed:
            placed[blob] = start + len(layout)
            layout += blob + b"\0"
            if len(layout) % 2:
                layout += b"\0"
        new = placed[blob]
        entries.append((o, jp, en, new))
        for lui_i, add_i in readers[o]:
            w = words[add_i]
            lo = (base + new) & 0xFFFF
            neww = (w & 0xFFFF0000) | lo
            if neww != w:
                patches.append({"file": disc, "offset": f"{4 * add_i:#X}",
                                "original": struct.pack("<I", w).hex(),
                                "replacement": struct.pack("<I", neww).hex(),
                                "comment": f"addiu -> {jp} -> {en or jp!r} at {new:#x}"})
    if len(layout) > end - start:
        sys.exit(f"the English needs {len(layout)} bytes, the run has {end - start}")
    region = bytes(layout).ljust(end - start, b"\0")
    run = {"file": disc, "offset": f"{start:#X}", "original": data[start:end].hex(),
           "replacement": region.hex(),
           "comment": f"{len(strs)} strings repacked ({len(placed)} distinct), "
                      f"{len(layout)} of {end - start} bytes; readers repointed below"}
    doc = {"description": a.comment or "DRAFT", "bytes": [run] + patches}
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for o, jp, en, new in entries:
        print(f"{o:#07x} -> {new:#07x}  {jp:<12} {en if en is not None else '(kept)'}")
    print(f"{len(strs)} strings, {len(placed)} distinct, {len(layout)}/{end - start} bytes, "
          f"{len(patches)} addiu patched -> {out}")


if __name__ == "__main__":
    main()
