"""Log whether code at given addresses ever runs, via GDB breakpoints.

Usage:  python tools/emu/watch_exec.py SECONDS ADDR [ADDR ...] [--stack N] [--max N]

Sets an execution breakpoint on each ADDR in the isolated DuckStation and
keeps the game running, printing pc/ra each time one is hit, until SECONDS
have passed. Drive the game with drive.ps1 while this runs. --stack N also
prints the first N stack words (arguments 5+ live at sp+0x10...); --max stops
after N hits.

Used to check that the functions the renderer hook overwrites are never
called (game-internals §6f): no output except "done: 0 hit(s)" is the
expected result.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402


def main() -> None:
    args = sys.argv[1:]
    stack = maxhits = 0
    for opt in ("--stack", "--max"):
        if opt in args:
            i = args.index(opt)
            value = int(args[i + 1], 0)
            del args[i:i + 2]
            if opt == "--stack":
                stack = value
            else:
                maxhits = value
    if len(args) < 2:
        sys.exit(__doc__)
    seconds = float(args[0])
    addrs = [int(a, 0) for a in args[1:]]

    g = Gdb()
    for a in addrs:
        g.break_at(a)
    print(f"armed {', '.join(f'{a:08x}' for a in addrs)} for {seconds:.0f}s", flush=True)
    t0, hits = time.time(), 0
    try:
        while (left := seconds - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                break
            r = g.regs()
            hits += 1
            line = (f"{time.time() - t0:6.1f}s HIT pc={r['pc']:08x} ra={r['ra']:08x} "
                    f"a0={r['a0']:08x} a1={r['a1']:08x} a2={r['a2']:08x} a3={r['a3']:08x}")
            if stack:
                words = struct.unpack(f"<{stack}I", g.mem(r["sp"], 4 * stack))
                line += " sp: " + " ".join(f"{w:08x}" for w in words)
            print(line, flush=True)
            if maxhits and hits >= maxhits:
                break
    finally:
        for a in addrs:
            g.clear_break(a)
        g.detach()
        print(f"done: {hits} hit(s)", flush=True)


if __name__ == "__main__":
    main()
