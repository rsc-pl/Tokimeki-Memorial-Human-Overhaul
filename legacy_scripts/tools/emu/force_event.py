"""Force one girl special event in the isolated emulator (test cards only).

Usage:  python tools/emu/force_event.py GIRL SCENE [--type T] [--first] [--clear-flag ADDR]
            [--club C] [--timeout S]

Breaks where the main loop is about to read the next day record from its
event queue (0x80071DD0, game-internals §6j) and, at the first ordinary
record (type 0x00), writes a special-event record `45 GIRL SCENE 00` in its
place, so that day runs the girl's scene instead of the chosen command.
--type changes the record type (0x30 White Day; 0x48 the meeting scenes run
by SHOUGATU.EXN, which with girl 0 returns the game to the title screen).
--first also makes the week's first record (0x800E691C) that type: multi-day
events (the camp, the trip, game-internals 6x/6y) check it to go on.
--clear-flag zeroes a one-shot "seen" byte first (Shiori's scene 2 uses
0x800E67ED). --club sets the player's club first (top 4 bits of the u16
at 0x800E6374, as force_festival.py: 0 Literature ... 5 Band, 6-10 sports,
11 none); MASTER.EXN's contest day (--type 0x25) loads the club's contest
file from it (game-internals 6ad). Then it detaches and the game continues
on its own.

Start it on the Sunday-night planning screen, then pick a weekly command.
This changes game state: use it only on the harness's test cards and do the
same forcing on the unpatched game for the comparison run.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402

READ_RECORD = 0x80071DD0   # index already advanced; next insn reads the record
QUEUE = 0x800E691C         # records: type, girl, scene, flags
QUEUE_INDEX = 0x800E699C
DATE = 0x800E62BE
CLUB = 0x800E6374


def main() -> None:
    args = sys.argv[1:]
    first = "--first" in args
    if first:
        args.remove("--first")
    flag = None
    timeout = 300.0
    rtype = 0x45
    club = None
    for opt in ("--clear-flag", "--timeout", "--type", "--club"):
        if opt in args:
            i = args.index(opt)
            value = args[i + 1]
            del args[i:i + 2]
            if opt == "--clear-flag":
                flag = int(value, 0)
            elif opt == "--type":
                rtype = int(value, 0)
            elif opt == "--club":
                club = int(value, 0)
            else:
                timeout = float(value)
    if len(args) != 2:
        sys.exit(__doc__)
    girl, scene = int(args[0], 0), int(args[1], 0)

    g = Gdb()
    if flag is not None:
        print(f"flag {flag:#x} was {g.mem(flag, 1).hex()}, clearing", flush=True)
        g.cmd(f"M{flag:x},1:00")
    if club is not None:
        v = (int.from_bytes(g.mem(CLUB, 2), "little") & 0x0FFF) | (club << 12)
        g.cmd(f"M{CLUB:x},2:{v.to_bytes(2, 'little').hex()}")
    g.break_at(READ_RECORD)
    t0 = time.time()
    try:
        while (left := timeout - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                print("timed out without forcing", flush=True)
                return
            index = g.mem(QUEUE_INDEX, 1)[0]
            addr = QUEUE + 4 * index
            record = g.mem(addr, 4)
            y, m, d, wd = g.mem(DATE, 4)
            print(f"{y}/{m}/{d} wd{wd} index {index} record {record.hex(' ')}", flush=True)
            if record[0] == 0x00:
                new = bytes([rtype, girl, scene, 0])
                g.cmd(f"M{addr:x},4:{new.hex()}")
                if first:
                    g.cmd(f"M{QUEUE:x},1:{rtype:02x}")
                print(f"forced {new.hex(' ')} at {addr:#x} (was {record.hex(' ')})", flush=True)
                return
    finally:
        g.clear_break(READ_RECORD)
        g.detach()


if __name__ == "__main__":
    main()
