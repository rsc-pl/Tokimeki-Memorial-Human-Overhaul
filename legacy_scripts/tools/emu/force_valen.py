"""Force Valentine's Day (SERIFU/VALEN.BIN) in the isolated emulator (test cards only).

Usage:  python tools/emu/force_valen.py [--girls G,...] [--parts P,...]
            [--intro] [--year N] [--timeout S]

Start it on the Sunday-night planning screen, then pick a weekly command.
Where the main loop reads the next day record (0x80071DD0, as
force_event.py) it writes a Valentine record `31 00 00 00` over the first
ordinary one: that day runs VALEN.EXN (state 0x54; game-internals 6v),
Ijuin in the hallway, then each girl who gives the player chocolate, then
the player's count of the day.

Then it polls RAM for VALEN.EXN's code (the overlay area holds other code
before it loads) and arms:
  --year N     Ijuin's lines for the Nth Valentine's Day (0-2): his part is
               4*year - 0x180 from the year byte the code reads at
               0x80132720, which in February is 96-98. Always set (default
               0): forced in April 1995 the part would be negative.
  --girls G,.. the girls who give chocolate, in order: the list at
               0x80134524 (a byte every 2) and its count 0x8013453C, written
               when the per-girl step 0x80132D0C first runs. Up to four
               worked; a six-girl list played Shiori six times (not traced).
               The forced list bypasses the ranking 0x80134540-42, so each
               giver's part 2 (her later scene, e.g. Mio's poem) doesn't play.
  --parts P,.. each girl's part (0x80134498, at 0x80132E10 once the game
               has chosen it): 0 obligation chocolate, 1 heartfelt, and for
               Shiori 3/5 her "sorry about earlier" versions.
  --intro      the flag 0x80134544 that Megumi is introduced (by Shiori, at
               the back of the school) and Shiori apologizes later; it
               normally needs Megumi unmet with 0x800E6636 >= 20.

This changes game state (RAM and registers only): use it on test cards.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import REG_NAMES, Gdb  # noqa: E402

READ_RECORD = 0x80071DD0
QUEUE = 0x800E691C
QUEUE_INDEX = 0x800E699C
STEP = 0x80132D0C                        # per-girl step; polled for VALEN's code
CODE = bytes.fromhex("1380023c13800e3c")
YEAR = 0x80132720                        # t7 = year byte, Ijuin's part
PART = 0x80132E10                        # the girl's part is in 0x80134498
LIST, COUNT, INDEX, INTRO = 0x80134524, 0x8013453C, 0x80134520, 0x80134544


def setreg(g: Gdb, name: str, value: int) -> None:
    g.cmd(f"P{REG_NAMES.index(name):x}=" + struct.pack("<I", value).hex())


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--girls", "--parts", "--year", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    intro = "--intro" in args
    args = [a for a in args if a != "--intro"]
    if args:
        sys.exit(__doc__)
    timeout = float(opts.get("--timeout", "300"))
    girls = [int(x, 0) for x in opts["--girls"].split(",")] if "--girls" in opts else []
    parts = [int(x, 0) for x in opts["--parts"].split(",")] if "--parts" in opts else []

    g = Gdb()
    g.break_at(READ_RECORD)
    t0 = time.time()
    try:
        while True:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                sys.exit("timed out before a day record")
            index = g.mem(QUEUE_INDEX, 1)[0]
            addr = QUEUE + 4 * index
            record = g.mem(addr, 4)
            if record[0] == 0x00:
                g.cmd(f"M{addr:x},4:31000000")
                print(f"Valentine record at {addr:#x} (was {record.hex(' ')})", flush=True)
                break
    finally:
        g.clear_break(READ_RECORD)
        g.detach()

    while True:
        time.sleep(0.2)
        g = Gdb()
        if g.mem(STEP, 8) == CODE:
            break
        g.detach()
        if time.time() - t0 > timeout:
            sys.exit("VALEN.EXN never loaded")
    print(f"VALEN loaded after {time.time() - t0:.1f}s", flush=True)
    armed = [YEAR] + ([STEP] if girls or intro else []) + ([PART] if parts else [])
    for a in armed:
        g.break_at(a)
    try:
        while armed:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                print(f"timed out; still armed: {[hex(a) for a in armed]}", flush=True)
                return
            pc = g.regs()["pc"]
            if pc == YEAR:
                year = int(opts.get("--year", "0"), 0)
                setreg(g, "t7", 0x60 + year)
                print(f"Ijuin's year {year}", flush=True)
            elif pc == STEP:
                if girls:
                    data = b"".join(bytes([x, 0]) for x in girls)
                    g.cmd(f"M{LIST:x},{len(data)}:{data.hex()}")
                    g.cmd(f"M{COUNT:x},2:" + struct.pack("<h", len(girls)).hex())
                    g.cmd(f"M{INDEX:x},2:0000")
                if intro:
                    g.cmd(f"M{INTRO:x},1:01")
                print(f"girls {girls}, intro {intro}", flush=True)
            elif pc == PART:
                part = parts.pop(0)
                g.cmd("M80134498,2:" + struct.pack("<h", part).hex())
                print(f"girl {g.regs()['a1']} part {part}", flush=True)
                if parts:
                    continue
            else:
                continue
            g.clear_break(pc)
            armed.remove(pc)
    finally:
        for a in (YEAR, STEP, PART):
            g.clear_break(a)
        g.detach()


if __name__ == "__main__":
    main()
