"""List the in-place Japanese strings of an overlay (or the EXE) and how much room each has.

Usage:
  python tools/exn_words.py EXEDIR/BUNKASAI.EXN [--todo] [--json OUT]
  python tools/exn_words.py --all            (a summary line per overlay)

For every Japanese string the code addresses (a `lui` + `addiu`/`ori`
pair, the pattern tools/code_strings.py lists in detail) or a data word
points at, it prints: file offset, the room for English in letters (the
string's bytes, its NUL and the padding to the next 4-byte boundary, minus
the NUL, rounded down to even: pair encoding is one byte per letter and an
odd count is padded with a space),
how it's reached (code/data), whether a translation/*.json already covers
it, and the text.

--json OUT writes a skeleton {"strings": [...]} with every untranslated
entry ("text": "") for a draft: fill the texts, keep each within its room
(the patcher refuses longer ones, docs/PS1_BUILD_SAFETY.md, in-place-string budget rule) and test on screen;
strings drawn by add_text (0x8004E788) or used as banners are the usual
cases (game-internals 6p, 6y, 6z). Names that don't fit can sometimes use
NUL padding that nothing else points into, through a `bytes` patch
(translation-guide "Repacking strings the code addresses directly").
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tokipatch import script  # noqa: E402

EX = ROOT / "extracted"
JP = re.compile("[ぁ-んァ-ン一-龯]")


def base_of(name: str) -> int:
    return 0x80040800 if name.endswith("SLPM_86.053") else 0x80132000


def done_offsets(disc: str):
    out = {}
    for p in (ROOT / "translation").glob("*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        for s in d.get("strings", []):
            if s["file"].upper().endswith(disc.upper()):
                out[int(s["offset"], 16)] = s["text"]
        for b in d.get("bytes", []):
            if b["file"].upper().endswith(disc.upper()):
                o = int(b["offset"], 16)
                for k in range(o, o + len(b["original"]) // 2):
                    out.setdefault(k, "(bytes patch)")
        for b in d.get("dialogue", []):
            if b["file"].upper().endswith(disc.upper()):
                for l in b["lines"]:
                    out[int(l["offset"], 16)] = l["text"]
    return out


def strings(name: str):
    path = EX / ("SLPM_86.053" if name == "SLPM_86.053" else "CDROM/" + name)
    x = path.read_bytes()
    base = base_of(name)
    refs = {}
    hi = {}
    for o in range(0, len(x) - 3, 4):
        w = struct.unpack_from("<I", x, o)[0]
        op, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        if op == 0x0F:
            hi[rt] = (imm << 16, o)
            continue
        if op in (0x09, 0x0D) and rs in hi and o - hi[rs][1] < 64:
            v = (hi[rs][0] + (imm - 0x10000 if op == 0x09 and imm & 0x8000 else imm)) & 0xFFFFFFFF
            refs.setdefault(v - base, set()).add("code")
        elif base <= w < base + len(x):
            refs.setdefault(w - base, set()).add("data")
    out = []
    for off, how in sorted(refs.items()):
        if not 0 <= off < len(x) or x[off] == 0:
            continue
        try:
            raw = script.read_string(x, off)
            text = script.decode(raw)
        except Exception:  # noqa: BLE001
            continue
        if not JP.search(text) or any(ord(c) < 0x20 and c != "\n" for c in text):
            continue
        n = len(raw)
        end = off + n + 1
        while end % 4 and end < len(x) and x[end] == 0:
            end += 1
        # Pair encoding: 2 bytes per 2 letters (an odd count pads a space),
        # then the NUL.
        room = (end - off - 1) // 2 * 2
        out.append((off, room, "+".join(sorted(how)), text))
    return out


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("--todo", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    if a.all:
        names = ["SLPM_86.053"] + ["EXEDIR/" + p.name for p in sorted((EX / "CDROM/EXEDIR").glob("*.EXN"))]
        for n in names:
            s = strings(n)
            done = done_offsets(n)
            todo = [t for t in s if t[0] not in done]
            print(f"{n:24} {len(s):4d} strings, {len(todo):4d} untranslated, "
                  f"{sum(len(t[3]) for t in todo):6d} characters left")
        return
    if not a.file:
        sys.exit(__doc__)
    done = done_offsets(a.file)
    rows = strings(a.file)
    skel = []
    for off, room, how, text in rows:
        d = done.get(off)
        if a.todo and d is not None:
            continue
        print(f"{off:#07x} room {room:3d} {how:9} {'DONE ' + repr(d) if d is not None else 'todo'}  {text!r}")
        if d is None:
            skel.append({"file": "CDROM/" + a.file if a.file != "SLPM_86.053" else a.file,
                         "offset": f"{off:#X}".replace("0X", "0x"), "original": text, "text": "",
                         "room": room})
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        with open(a.json, "w", encoding="utf-8", newline="\n") as f:
            f.write("{\n  \"description\": \"DRAFT\",\n  \"strings\": [\n")
            f.write(",\n".join("    " + json.dumps(s, ensure_ascii=False) for s in skel))
            f.write("\n  ]\n}\n")
        print(f"{len(skel)} untranslated -> {a.json} (drop the \"room\" keys' entries you don't translate)")


if __name__ == "__main__":
    main()
