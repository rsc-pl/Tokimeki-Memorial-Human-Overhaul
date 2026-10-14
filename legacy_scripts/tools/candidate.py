"""Build the test candidate and show exactly what it changes.

Usage:
  python tools/candidate.py [translation/extra/foo.json ...] [--out review_dates]
                            [--reference default_now] [--rebuild-reference]

1. Stops the isolated emulator (it locks the review disc's BIN).
2. Builds the reference: every translation/*.json, the normal build
   (cached in .emu/<reference>/ unless --rebuild-reference or a
   translation/*.json is newer than it).
3. Builds the candidate into .emu/<out>/ (default review_dates, the folder
   the Sunday test state reopens): every translation/*.json plus the
   given drafts.
4. Diffs the two Track 1 images sector by sector, names the file owning
   each changed sector (extracted/files.tsv), and checks the checksum
   trailer of every changed file.

Expect only the drafts' files to change. Anything else is a bug to find
before testing on screen (docs/PS1_BUILD_SAFETY.md checklist). With no drafts, the
candidate equals the normal build: use it after promoting a file to
confirm the promotion changed nothing (byte-identical).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tokipatch.cd import Track  # noqa: E402
from tokipatch.patcher import has_checksum  # noqa: E402

NAME = "Tokimeki Memorial - Forever with You (Japan) (PlayStation the Best)"
CUE = ROOT / NAME / f"{NAME}.cue"
TRACK1 = f"{NAME} (Track 1).bin"


def stop_emulator():
    if os.name == "nt":
        subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                        "Get-Process duckstation* -ErrorAction SilentlyContinue | Where-Object "
                        "{ $_.Path -like '*\\.emu\\duckstation\\*' } | Stop-Process -Force"],
                       capture_output=True)


def build(out: Path, extra, log: Path):
    cmd = [sys.executable, "-m", "tokipatch", str(CUE), "-o", str(out), "--force"]
    if extra:
        for f in sorted((ROOT / "translation").glob("*.json")) + [Path(e) for e in extra]:
            cmd += ["-t", str(f)]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    with open(log, "w", encoding="utf-8") as f:
        r = subprocess.run(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT, env=env)
    if r.returncode:
        print(log.read_text(encoding="utf-8")[-3000:])
        sys.exit(f"build failed: {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("drafts", nargs="*")
    ap.add_argument("--out", default="review_dates")
    ap.add_argument("--reference", default="default_now")
    ap.add_argument("--rebuild-reference", action="store_true")
    a = ap.parse_args()
    emu = ROOT / ".emu"
    stop_emulator()

    ref = emu / a.reference
    newest = max(p.stat().st_mtime for p in (ROOT / "translation").glob("*.json"))
    if a.rebuild_reference or not (ref / TRACK1).exists() or (ref / TRACK1).stat().st_mtime < newest:
        print(f"building reference {ref} ...", flush=True)
        build(ref, [], emu / f"{a.reference}.log")
    out = emu / a.out
    print(f"building candidate {out} ...", flush=True)
    build(out, a.drafts, emu / f"{a.out}.log")

    files = []
    for line in (ROOT / "extracted/files.tsv").read_text(encoding="utf-8").splitlines():
        lba, size, name = line.split("\t")
        files.append((int(lba), int(size), name.strip()))

    def owner(sector):
        for lba, size, name in files:
            if lba <= sector < lba + (size + 2047) // 2048:
                return name, lba, size
        return ("?", 0, 0)

    sa, sb = ref / TRACK1, out / TRACK1
    changed = {}
    with open(sa, "rb") as fa, open(sb, "rb") as fb:
        sector = 0
        while True:
            x, y = fa.read(2352 * 64), fb.read(2352 * 64)
            if not x and not y:
                break
            if x != y:
                for k in range(0, max(len(x), len(y)), 2352):
                    if x[k:k + 2352] != y[k:k + 2352]:
                        o = owner(sector + k // 2352)
                        changed.setdefault(o, []).append(sector + k // 2352)
            sector += 64
    if not changed:
        print("candidate is byte-identical to the reference")
        return
    with Track(sb) as t:
        for (name, lba, size), sectors in sorted(changed.items()):
            ok = has_checksum(t.read_file(lba, size)) if name.endswith((".BIN", ".EXN")) else None
            print(f"  {name}: {len(sectors)} sector(s) changed"
                  + ("" if ok is None else f", checksum {'valid' if ok else 'INVALID or none'}"))


if __name__ == "__main__":
    main()
