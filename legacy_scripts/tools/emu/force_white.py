"""Force White Day (SERIFU/WHITE.BIN) in the isolated emulator (test cards only).

Usage:  python tools/emu/force_white.py [--gave G,...] [--pick G] [--mood M]
            [--year97] [--timeout S]

Start it on the Sunday-night planning screen, then pick a weekly command.
It marks the girls in --gave as having given the player chocolate on
Valentine's Day (bit 0 of 0x800E6449 + 0x38*girl; game-internals 6u) and,
where the main loop reads the next day record (0x80071DD0, as
force_event.py), writes a White Day record `30 00 00 00` over the first
ordinary one, so that day runs SHOUGATU.EXN's White Day flow (state 0x55):
Ijuin in the hallway, then the player's special return to one girl.

Then it polls RAM for SHOUGATU's White Day code (the overlay area holds
other code before it loads, so a breakpoint armed early would fire on the
wrong code) and arms:
  --pick G     the girl the return goes to (0x800E71DF, set at 0x8013BCFC,
               where the game copies the menu's choice), whatever the menu
               shows; she should be one of --gave.
  --mood M     what her mood call (0x80051A68, returning at 0x8013BD44)
               gives: 0-1 parts 1-2, 2 parts 3-4, 3 parts 5-6, 4 parts 7-8.
  --year97     Ijuin's 1997 lines (section 3 parts 4-7): the year byte the
               code reads at 0x8013B90C is made 97.
Without --gave nobody gave chocolate: Ijuin's "I don't" branch, no return.

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
CODE_AT = 0x8013B900                     # SHOUGATU's White Day code, polled
CODE = bytes.fromhex("0e800f3cbe62ef91")
YEAR = 0x8013B90C                        # sltiu t8, t7(year), 0x61
PICK = 0x8013BCFC                        # jal; delay slot stores t6 -> 0x800E71DF
MOOD = 0x8013BD44                        # move v1, v0 after the mood call


def setreg(g: Gdb, name: str, value: int) -> None:
    g.cmd(f"P{REG_NAMES.index(name):x}=" + struct.pack("<I", value).hex())


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--gave", "--pick", "--mood", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    year97 = "--year97" in args
    args = [a for a in args if a != "--year97"]
    if args:
        sys.exit(__doc__)
    timeout = float(opts.get("--timeout", "300"))
    gave = [int(x, 0) for x in opts["--gave"].split(",")] if "--gave" in opts else []

    g = Gdb()
    for girl in gave:
        addr = 0x800E6449 + 0x38 * girl
        g.cmd(f"M{addr:x},1:{g.mem(addr, 1)[0] | 1:02x}")
    if gave:
        print(f"chocolate from {gave}", flush=True)
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
                g.cmd(f"M{addr:x},4:30000000")
                print(f"White Day record at {addr:#x} (was {record.hex(' ')})", flush=True)
                break
    finally:
        g.clear_break(READ_RECORD)
        g.detach()

    armed = ([YEAR] if year97 else []) + ([PICK] if "--pick" in opts else []) + \
            ([MOOD] if "--mood" in opts else [])
    if not armed:
        return
    while True:
        time.sleep(0.2)
        g = Gdb()
        if g.mem(CODE_AT, 8) == CODE:
            break
        g.detach()
        if time.time() - t0 > timeout:
            sys.exit("SHOUGATU.EXN never loaded")
    print(f"SHOUGATU loaded after {time.time() - t0:.1f}s", flush=True)
    for a in armed:
        g.break_at(a)
    try:
        while armed:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                print(f"timed out; not reached: {[hex(a) for a in armed]}", flush=True)
                return
            pc = g.regs()["pc"]
            if pc == YEAR:
                setreg(g, "t7", 0x61)
                print("year -> 97 for Ijuin", flush=True)
            elif pc == PICK:
                setreg(g, "t6", int(opts["--pick"], 0))
                print(f"return goes to girl {opts['--pick']}", flush=True)
            elif pc == MOOD:
                setreg(g, "v0", int(opts["--mood"], 0))
                print(f"mood {opts['--mood']}", flush=True)
            else:
                continue
            g.clear_break(pc)
            armed.remove(pc)
    finally:
        for a in (YEAR, PICK, MOOD):
            g.clear_break(a)
        g.detach()


if __name__ == "__main__":
    main()
