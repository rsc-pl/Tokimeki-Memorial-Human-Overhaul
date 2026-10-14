"""Log which code reads a RAM address, via a GDB read watchpoint.

Usage:  python tools/emu/watch_reads.py ADDR SECONDS [--skip LO-HI ...]

Arms a read watchpoint on ADDR in the isolated DuckStation and keeps the game
running, printing pc/ra and a few registers each time ADDR is read, until
SECONDS have passed. Use --skip to ignore known readers by pc range, e.g. the
overlay checksum loop:  --skip 0x8004636C-0x800463E8

Drive the game into the screen of interest with drive.ps1 while this runs.
Text that's drawn once (into VRAM, when a screen opens) only shows up if the
watch is armed before the screen opens.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("addr", type=lambda s: int(s, 0))
    ap.add_argument("seconds", type=float)
    ap.add_argument("--skip", action="append", default=[], help="pc range LO-HI to ignore")
    ap.add_argument("--max", type=int, default=40, help="stop after this many reported hits")
    args = ap.parse_args()
    skips = [tuple(int(x, 0) for x in s.split("-")) for s in args.skip]

    g = Gdb()
    g.cmd(f"Z3,{args.addr:x},1")
    t0, reported, skipped = time.time(), 0, 0
    try:
        while reported < args.max and (left := args.seconds - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                break
            r = g.regs()
            if any(lo <= r["pc"] < hi for lo, hi in skips):
                skipped += 1
                continue
            reported += 1
            print(f"{time.time() - t0:6.1f}s pc={r['pc']:08x} ra={r['ra']:08x} "
                  f"a0={r['a0']:08x} a1={r['a1']:08x} a2={r['a2']:08x} "
                  f"v0={r['v0']:08x} v1={r['v1']:08x} sp={r['sp']:08x}", flush=True)
    finally:
        g.cmd(f"z3,{args.addr:x},1")
        g.detach()
        print(f"done: {reported} reported, {skipped} skipped", flush=True)


if __name__ == "__main__":
    main()
