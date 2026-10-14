"""Log the main loop's girl events while the game runs, via GDB breakpoints.

Usage:  python tools/emu/watch_events.py SECONDS [--states]

Breaks where the EXE starts a girl's scene from the daily event queue
(game-internals §6j) and prints the date, the girl id and the queue, so
you can see which events a stretch of play produced:

  0x800721b0  queue record -> CD4 = girl, CD0 = scene (special events)
  0x80072210  queue record -> girl id, then state 0x5B (meeting scenes)
  0x800732ac  the injury follow-up event (CD4 = 0x0B, CD0 = 2)

--states also logs every main-loop state change (0x80042878, a0 = new state).
Drive the game with drive.ps1 in parallel. Breakpoints slow the emulator.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402

SCENE_CASES = (0x800721B0, 0x80072210)
INJURY_EVENT = 0x800732AC
SET_STATE = 0x80042878
DATE = 0x800E62BE          # year, month, day, weekday (0 = Monday)
QUEUE = 0x800E6918         # day records from 0x800E691C: type, girl, scene, flags
QUEUE_INDEX = 0x800E699C


def main() -> None:
    args = sys.argv[1:]
    states = "--states" in args
    args = [a for a in args if a != "--states"]
    if len(args) != 1:
        sys.exit(__doc__)
    seconds = float(args[0])

    addrs = [*SCENE_CASES, INJURY_EVENT] + ([SET_STATE] if states else [])
    g = Gdb()
    for a in addrs:
        g.break_at(a)
    print("armed", " ".join(f"{a:08x}" for a in addrs), flush=True)
    t0, last_queue = time.time(), None
    try:
        while (left := seconds - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                break
            r = g.regs()
            pc = r["pc"]
            y, m, d, wd = g.mem(DATE, 4)
            when = f"{time.time() - t0:6.1f}s {y}/{m}/{d} wd{wd}"
            if pc == SET_STATE:
                print(f"{when} state {r['a0']:#x} ra={r['ra']:08x}", flush=True)
                continue
            line = f"{when} HIT {pc:08x} ra={r['ra']:08x}"
            if pc in SCENE_CASES:
                # a1 = 0x800E6280 + 4 * index; the record's girl byte is at a1 + 0x69D
                rec = g.mem(r["a1"] + 0x69C, 4)
                line += f" record type={rec[0]:#x} girl={rec[1]} scene={rec[2]}"
            print(line, f"index={g.mem(QUEUE_INDEX, 1)[0]}", flush=True)
            queue = g.mem(QUEUE, 0x88)
            if queue != last_queue:
                print("   queue:", queue.hex(" "), flush=True)
                last_queue = queue
    finally:
        for a in addrs:
            g.clear_break(a)
        g.detach()
        print("done", flush=True)


if __name__ == "__main__":
    main()
