"""List the strings an overlay's code refers to, and what the code does with them.

Usage (needs capstone):
  uv run --with capstone python tools/code_strings.py FILE [--base 0x80132000]
      [--range START END] [--json OUT]

Some overlays (e.g. TEL.EXN, game-internals 6m) don't keep all their text in
pointer tables: the code builds a string's address with `lui` + `addiu`/`ori`
and passes it straight to a print, `strcpy` or `strcat` call. Such strings
can't be relocated (only translated in place), and a fragment's English has
to fit how the code assembles the line, so this tool prints, for every
Japanese string the code addresses:

  offset, the text, and each use: the call it feeds (named when known),
  the argument register it lands in, and the constant a1/a2 at the call.

Known EXE functions (game-internals 6e, 6m):
  0x80051010 line(text, line_no, speaker)   one display line
  0x80050E8C box(text, ?, speaker)          a whole multi-line string
  0x800AE0F0 strcpy(dst, src)   0x800AE100 strcat(dst, src)
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import progress  # noqa: E402

KNOWN = {
    0x80051010: "line",
    0x80050E8C: "box",
    0x800AE0F0: "strcpy",
    0x800AE100: "strcat",
    0x80050DFC: "label?",
}
ARG_REGS = ("a0", "a1", "a2", "a3")


def address_builds(words, base):
    """{target address: [instruction index of the addiu/ori]} from lui pairs.

    Follows each `lui rX` to the first later instruction (within 16) that
    adds a low half to rX, which also catches a `lui` in a branch delay slot.
    """
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
                found.setdefault(((hi << 16) + lo) & 0xFFFFFFFF, []).append(j)
            if op in (0x09, 0x0D, 0x0F, 0x23) and (v >> 16) & 31 == rt and j != i:
                break   # rX overwritten
    return found


def use_of(md, data, base, index):
    """Describe the call that consumes the address built at instruction `index`."""
    start = index * 4
    insns = list(md.disasm(data[start:start + 4 * 12], base + start))
    if not insns:
        return "?"
    dest = insns[0].op_str.split(",")[0].strip().lstrip("$")
    consts = {}
    for k, ins in enumerate(insns[1:], 1):
        if ins.mnemonic == "jal":
            target = int(ins.op_str, 16)
            # the delay slot executes before the call
            if k + 1 < len(insns):
                d = insns[k + 1]
                parts = [p.strip().lstrip("$") for p in d.op_str.split(",")]
                if d.mnemonic == "addiu" and len(parts) == 3 and parts[1] == "zero":
                    consts[parts[0]] = int(parts[2], 0)
                elif d.mnemonic == "move" and len(parts) == 2 and parts[1] == "zero":
                    consts[parts[0]] = 0
            name = KNOWN.get(target, f"{target:#x}")
            extra = ",".join(f"{r}={consts[r]}" for r in ("a1", "a2") if r in consts)
            return f"{name}({dest}{';' + extra if extra else ''})"
        parts = [p.strip().lstrip("$") for p in ins.op_str.split(",")]
        if ins.mnemonic == "addiu" and len(parts) == 3 and parts[1] == "zero":
            consts[parts[0]] = int(parts[2], 0)
        elif ins.mnemonic == "move" and len(parts) == 2 and parts[1] == "zero":
            consts[parts[0]] = 0
        if ins.mnemonic in ("jr", "j", "b", "beq", "bne"):
            pass
    return f"no call ({dest})"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--base", default="0x80132000")
    ap.add_argument("--range", nargs=2)
    ap.add_argument("--json", help="write [{offset, original, uses}] here")
    args = ap.parse_args()
    data = Path(args.file).read_bytes()
    base = int(args.base, 0)
    lo, hi = (int(x, 0) for x in args.range) if args.range else (0, len(data))
    words = struct.unpack_from(f"<{len(data) // 4}I", data)
    builds = address_builds(words, base)
    md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
    out = []
    for m in progress.STRING.finditer(data, lo, hi):
        start, end = m.start(), m.end()
        if start and data[start - 1] and data[start - 1] >= 0x40:
            continue   # not a string start
        if not progress.SJIS_CHAR.search(m.group()):
            continue
        # A string may also be addressed one byte early (after a separator).
        refs = builds.get(base + start, [])
        text = data[start:end].decode("shift_jis", "replace").replace(" ", "/")
        uses = [f"{base + 4 * j:#x}:{use_of(md, data, base, j)}" for j in refs]
        out.append({"offset": f"{start:#x}", "original": text, "uses": uses})
        print(f"{start:#07x}  {text[:34]:<34}  {' '.join(uses) or '(no lui/addiu reference)'}")
    if args.json:
        Path(args.json).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
