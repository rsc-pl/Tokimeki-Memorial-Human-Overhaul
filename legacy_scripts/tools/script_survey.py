"""Survey an untranslated script file: who loads it, its base, its section tables.

Usage:
  python tools/script_survey.py CDROM/BUNKA/KT_S61.BIN [--base 0x801E8000] [--strings] [-v]
  python tools/script_survey.py --all [--dir SERIFU]       (one line per untranslated file)

What it reports (the manual steps of game-internals 6j-6z, automated):
- loaders: every overlay (EXEDIR/*.EXN) and the EXE whose code holds the
  file's LBA as an `ori`/`addiu` immediate (the overlay loader passes the
  LBA to the CD read; game-internals 6j "Loading"), or an overlay holding
  it as a data word (an LBA table), with the address;
- base: the load address the file's own pointers fit (as dump_dialogue.py);
- tables: runs of words that point into the file, found in the loaders
  and in the file itself. A section table in these games is three
  parallel arrays (masters, code-byte lists, third pointers; EVENT_FU
  layout). Each run is tried as masters with the next run of the same
  length as code lists, walked like tools/geko_sections.py, and the
  strings reached are compared with dump_dialogue.py's list: "covers
  N/M" tells how much of the file that table explains.

The output is a starting point for the per-file investigation in
file-level translation work, not a final answer: always confirm on screen.
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
sys.path.insert(0, str(ROOT / "legacy_scripts" / "tools"))
from tokipatch import script  # noqa: E402
import dump_dialogue  # noqa: E402

EX = ROOT / "extracted"
EXE_BASE = 0x80040800        # SLPM_86.053 file offset 0 (0x800-byte header)
EXN_BASE = 0x80132000


def files_tsv():
    out = {}
    for line in (EX / "files.tsv").read_text(encoding="utf-8").splitlines():
        lba, size, name = line.split("\t")
        out[name.strip()] = (int(lba), int(size))
    return out


def binaries():
    yield "SLPM_86.053", EXE_BASE, (EX / "SLPM_86.053").read_bytes()
    for p in sorted((EX / "CDROM/EXEDIR").glob("*.EXN")):
        yield "EXEDIR/" + p.name, EXN_BASE, p.read_bytes()


def loaders(lba: int):
    """Code that puts the LBA in a register (ori/addiu rt, zero, LBA)."""
    hits = []
    for name, base, data in binaries():
        for o in range(0, len(data) - 3, 4):
            w = struct.unpack_from("<I", data, o)[0]
            if w >> 26 in (0x09, 0x0D) and (w >> 21) & 31 == 0 and w & 0xFFFF == lba:
                hits.append((name, base + o))
            elif w == lba and name != "SLPM_86.053":
                # An LBA table (BUNKAKEN.EXN lists the festival invitations
                # this way, game-internals 6aa).
                hits.append((name, base + o))
    return hits


def pointer_runs(data: bytes, lo: int, hi: int, min_len: int = 2):
    """[(offset, [words])]: runs of consecutive words inside [lo, hi)."""
    runs, start, cur = [], None, []
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from("<I", data, o)[0]
        if lo <= w < hi:
            if start is None:
                start, cur = o, []
            cur.append(w)
        else:
            if start is not None and len(cur) >= min_len:
                runs.append((start, cur))
            start = None
    if start is not None and len(cur) >= min_len:
        runs.append((start, cur))
    return runs


def walk(x: bytes, base: int, master: int, codes: int, with_codes: bool = False, strict: bool = True):
    """Parts of one section (EVENT_FU layout): [[offset, ...], ...], or with
    with_codes [[(offset, code byte), ...], ...]."""
    inside = lambda w: base <= w < base + len(x)
    word = lambda o: struct.unpack_from("<I", x, o)[0] if 0 <= o <= len(x) - 4 else 0
    m, c = master - base, codes - base
    parts, k = [], 0
    while inside(word(m + 4 * k)) and inside(word(c + 4 * k)):
        lst, cl = word(m + 4 * k) - base, word(c + 4 * k) - base
        st, t = [], 0
        while 0 <= cl + t < len(x) and x[cl + t] != 0xFF:
            p = word(lst + 4 * t)
            if not inside(p):
                break
            st.append((p - base, x[cl + t]) if with_codes else p - base)
            t += 1
        if not st:
            break
        if strict and not (0 <= cl + t < len(x) and x[cl + t] == 0xFF):
            return []           # code list and string list don't line up
        parts.append(st)
        k += 1
    return parts


def survey(disc_path: str, base=None, verbose=False, show_strings=False):
    tsv = files_tsv()
    lba, size = tsv[disc_path]
    x = (EX / disc_path).read_bytes()
    lines, base = dump_dialogue_lines(x, base)
    dumped = {int(l["offset"], 16) for l in lines}
    chars = sum(len(l["original"]) for l in lines)
    res = {"file": disc_path, "lba": lba, "size": size, "base": base, "strings": len(lines),
           "chars": chars, "loaders": loaders(lba), "tables": []}
    hi = base + len(x)
    cache = {}

    pairs_used = {}
    kind = ["static"]

    def reach(m, c):
        if (m, c) not in cache:
            parts = walk(x, base, m, c, with_codes=True)
            # Speaker codes are small (game-internals 6j); anything else
            # means m/c aren't a real master/code-list pair.
            ok = parts and all(b <= 0x1F for st in parts for _, b in st)
            cache[(m, c)] = {o for st in parts for o, _ in st} if ok else set()

        return cache[(m, c)]

    sources = [("(self)", base, x)] + [(n, b, d) for n, b, d in binaries()
                                       if any(n == ln for ln, _ in res["loaders"])]
    for name, sbase, data in sources:
        kind[0] = "static"
        # Static tables: a run of words into the file, masters then code lists.
        # Tables shared by several files (the 79-entry event table, 6j/6z)
        # hold pointers into the other files too: accept any pointer into
        # the load region when finding the run.
        for off, words in pointer_runs(data, base, base + max(len(x), 0x20000)):
            best = None
            for cnt in range(1, min(len(words) // 2, 300) + 1):
                got = set()
                for m, c in zip(words[:cnt], words[cnt:2 * cnt]):
                    got |= reach(m, c)
                if best is None or len(got & dumped) > len(best[1] & dumped):
                    best = (cnt, got)
            if best and len(best[1] & dumped) >= 3:
                for m, c in zip(words[:best[0]], words[best[0]:2 * best[0]]):
                    if cache[(m, c)]:
                        pairs_used.setdefault((m, c), "static")
                res["tables"].append({"in": name, "at": sbase + off, "count": best[0], "kind": "static",
                                      "covers": len(best[1] & dumped), "extra": len(best[1] - dumped),
                                      "reached": best[1]})
        if name == "(self)":
            continue
        kind[0] = "code"
        # Tables built by code: lui/ori or lui/addiu constants into the file.
        consts, hireg = [], {}
        for o in range(0, len(data) - 3, 4):
            w = struct.unpack_from("<I", data, o)[0]
            op, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
            if op == 0x0F:
                hireg[rt] = (imm << 16, o)
            elif op in (0x09, 0x0D) and rs in hireg and o - hireg[rs][1] < 64:
                v = hireg[rs][0] + (imm - 0x10000 if op == 0x09 and imm & 0x8000 else imm)
                v &= 0xFFFFFFFF
                if base <= v < hi:
                    consts.append((o, v))
        got = set()
        for i, (o, m) in enumerate(consts):
            for _, c in consts[i + 1:i + 8]:
                r = reach(m, c)
                if r:
                    got |= r
                    pairs_used.setdefault((m, c), "code")
        if len(got & dumped) >= 3:
            res["tables"].append({"in": name, "at": sbase + consts[0][0], "count": len(consts), "kind": "code",
                                  "covers": len(got & dumped), "extra": len(got - dumped), "reached": got})
    allr = set().union(*[t["reached"] for t in res["tables"]]) if res["tables"] else set()
    res["covered"] = len(allr & dumped)
    codes = {}
    seen = {"static": {}, "code": {}}
    for (m, c), k in pairs_used.items():
        for st in walk(x, base, m, c, with_codes=True):
            for o, b in st:
                seen[k].setdefault(o, set()).add(b)
    # Static tables are the reliable source; code-built pairs are guesses
    # (consecutive constants) and only fill offsets no static table
    # reaches. Conflicting codes mean a pair was read against the wrong
    # file (the shared event table, game-internals 6z): unknown.
    for k in ("static", "code"):
        for o, bs in seen[k].items():
            if o not in codes:
                codes[o] = next(iter(bs)) if len(bs) == 1 else None
    # DATE_*.BIN: DATE.EXN builds each girl's 27-section table in code
    # (game-internals 6k); tools/date_sections.py simulates it exactly.
    m = re.search(r"SERIFU/DATE_(\w\w)\.BIN$", disc_path)
    if m:
        import date_sections
        if m.group(1) in date_sections.GIRL_FILES:
            exn = (EX / "CDROM/EXEDIR/DATE.EXN").read_bytes()
            words = date_sections.girl_table(exn, date_sections.GIRL_FILES.index(m.group(1)))
            exact = {}
            for mst, cod in zip(words[:27], words[27:54]):
                for st in walk(x, base, mst, cod, with_codes=True, strict=False):
                    for o, b in st:
                        exact.setdefault(o, b)
            codes.update(exact)
            res["exact_codes"] = len(exact)
            res["covered"] = len((allr | set(exact)) & dumped)
            res["tables"].append({"in": "EXEDIR/DATE.EXN", "at": date_sections.TABLE, "count": 27,
                                  "kind": "date_sections", "covers": len(set(exact) & dumped),
                                  "extra": len(set(exact) - dumped), "reached": set(exact)})
    res["codes"] = codes
    res["reached"] = set().union(*[t["reached"] for t in res["tables"]]) if res["tables"] else set()
    res["certain"] = set(seen["static"]) | set(res.get("exact_codes") and exact or ())
    res["tables"].sort(key=lambda t: -t["covers"])
    if show_strings:
        for l in lines:
            print(f"  {l['offset']:>8} {l['original'][:60]!r}")
    return res


def dump_dialogue_lines(x: bytes, base=None):
    """dump_dialogue.py's string list for this file: (lines, base)."""
    base = base if base is not None else dump_dialogue.guess_base(x)
    lines = [{"offset": f"{o:#x}", "original": t} for o, t in sorted(dump_dialogue.targets(x, base).items())]
    return lines, base


def translated_files():
    done = set()
    for p in (ROOT / "translation").glob("*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        for b in d.get("dialogue", []):
            done.add(b["file"].upper())
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("--base", type=lambda s: int(s, 0))
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--dir")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    if a.all:
        done = translated_files()
        for name, (lba, size) in sorted(files_tsv().items()):
            if not name.endswith(".BIN") or name.startswith("CDROM/SPEAKTST") or name in done:
                continue
            if a.dir and f"/{a.dir}/" not in name:
                continue
            try:
                r = survey(name)
            except Exception as ex:  # noqa: BLE001
                print(f"{name}: error {ex}")
                continue
            if r["strings"] < 3:
                continue
            ld = ",".join(sorted({n.split('/')[-1] for n, _ in r["loaders"]})) or "-"
            t = r["tables"][0] if r["tables"] else None
            ts = (f"{t['kind']} {t['in'].split('/')[-1]}@{t['at']:#x} x{t['count']}; all cover {r['covered']}/{r['strings']}"
                  if t else "no table")
            print(f"{name:32} {r['strings']:5d} str {r['chars']:6d} ch base {r['base']:#x} loaders {ld:24} {ts}", flush=True)
        return
    if not a.file:
        sys.exit(__doc__)
    r = survey(a.file, a.base, a.v, a.strings)
    print(f"{r['file']}: LBA {r['lba']}, {r['size']} bytes, base {r['base']:#x}, "
          f"{r['strings']} strings, {r['chars']} characters")
    for n, addr in r["loaders"]:
        print(f"  loader: {n} at {addr:#x}")
    print(f"  all tables together cover {r['covered']}/{r['strings']} dumped strings")
    for t in r["tables"][:8]:
        print(f"  {t['kind']} table in {t['in']} at {t['at']:#x}: {t['count']} entries, covers "
              f"{t['covers']}/{r['strings']} dumped strings (+{t['extra']} not dumped)")


if __name__ == "__main__":
    main()
