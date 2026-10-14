"""Translate in place the prefixed text lines an overlay reaches by pointer.

Usage:
  python tools/prefixed_lines.py CDROM/EXEDIR/BUNKA_SD.EXN --region 0x7900 0x9670
      --texts extracted/tables/BUNKA_SD.json [--prefixes " gE"]
      [--description "..."] -o translation/extra/stage_shows.json

BUNKA_SD.EXN (the festival's stage shows, game-internals 6ab) keeps each
displayed line as its own string: one prefix byte, ' ' (more lines follow
on this page), 'g' (end of page) or 'E' (end of the show), then the text,
often padded with full-width spaces that seem to pace the display. Speaker
labels are separate unprefixed strings. A `strings` patch can't carry the
raw prefix byte (the encoder would turn 'g' into a letter), so this tool
writes one `bytes` patch per line:

- the prefix byte is kept as it is;
- the English is pair-encoded (tokipatch.script.encode_english); full-width
  characters such as 「」 pass through;
- the original's trailing full-width spaces are kept as far as they fit;
- the line may use the original's bytes plus the NUL padding up to the next
  non-zero byte, minus one NUL terminator; anything longer is refused.

--texts maps a file offset ("0x7910") or a Japanese string (every copy in
the region, for labels) to English. Lines without an entry stay Japanese.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tokipatch import font, script  # noqa: E402

FW_SPACE = b"\x81\x40"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--region", nargs=2, required=True)
    ap.add_argument("--texts", required=True)
    ap.add_argument("--prefixes", default=" gE")
    ap.add_argument("--description", default="DRAFT")
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()

    data = (ROOT / "extracted" / a.file).read_bytes()
    start, end = int(a.region[0], 16), int(a.region[1], 16)
    texts = json.loads(Path(a.texts).read_text(encoding="utf-8"))
    prefixes = a.prefixes.encode("ascii")
    pairs = font.PairEncoder()

    # Strings found by scanning, plus every offset key: a line can follow
    # binary data (a jump table) with no NUL in between, so the scan alone
    # would read it as part of that data.
    starts, i = set(), start
    while i < end:
        if data[i]:
            starts.add(i)
            i = data.index(b"\0", i)
        i += 1
    starts |= {int(k, 16) for k in texts if k.startswith("0x") and start <= int(k, 16) < end}

    patches, bad, todo = [], 0, 0
    for i in sorted(starts):
        e = data.index(b"\0", i)
        raw = data[i:e]
        pre = raw[:1] if raw[0] in prefixes else b""
        body = raw[len(pre):]
        try:
            jp = body.decode("cp932")
        except UnicodeDecodeError:
            continue           # binary data between the text runs
        en = texts.get(f"{i:#x}", texts.get(jp))
        if en is None:
            todo += 1
            continue
        nxt = e + 1
        while nxt < len(data) and data[nxt] == 0:
            nxt += 1
        room = nxt - i - 1     # leave one NUL before the next non-zero byte
        new = pre + script.encode_english(en, pairs)[0]
        pad = (len(body) - len(body.rstrip(FW_SPACE))) // 2 if body.endswith(FW_SPACE) else 0
        while pad and len(new) + 2 * pad > room:
            pad -= 1
        new += FW_SPACE * pad
        if len(new) > room:
            print(f"{i:#07x}: {len(new) - room} byte(s) too long: {en!r}")
            bad += 1
            continue
        old = data[i:i + len(new) + 1]
        rep = new + b"\0"
        if len(raw) + 1 > len(rep):
            old = data[i:e + 1]
            rep = rep + b"\0" * (len(old) - len(rep))
        patches.append({"file": a.file, "offset": f"{i:#x}", "original": old.hex(),
                        "replacement": rep.hex(), "comment": f"{jp} -> {en}"})

    print(f"{len(patches)} line(s), {bad} too long, {todo} left in Japanese")
    if bad:
        sys.exit(1)
    Path(a.output).write_text(json.dumps({"description": a.description, "bytes": patches},
                                         ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
