"""Force a walk home from school with a girl (GEKO.BIN), in the isolated emulator.

Usage:
  python tools/emu/force_walk.py GIRL [--rank R] [--topic PART] [--timeout S]
      [-- BREAK_SET_RULES]

Start it on the Sunday-night planning screen (e.g. the 95/4/23 state), then
pick a weekly command. It marks GIRL as met (bit 1 of 0x800E6448 + 0x38*GIRL;
the walk needs it), and turns Monday's day record into the walk-home record
`44 GIRL 00 00` (game-internals 6n). Then, while GEKO.EXN is loaded:

--rank R    makes every rank call in the walk-home steps return R (0-4):
            0/1 she waits and asks you, 2 you call out and she agrees,
            3 she has other plans, 4 she runs off (game-internals 6n).
--topic P   makes the walk end with the talk after "And then..." and picks
            its part P (23-38: exams, culture fest, sports day, school trip,
            New Year, birthday, holidays, moving up a year, graduation; see
            `python tools/geko_sections.py --strings --girl S`) by writing
            the pending topic id 0x80144C50 = P - 22.

Anything after `--` is more tools/emu/break_set.py rules (--at PC ...).
This changes game state (RAM and registers): use it on test cards only.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import break_set  # noqa: E402
from gdbstub import Gdb  # noqa: E402

READ_RECORD = 0x80071DD0   # force_event.py: next day record about to be read
QUEUE = 0x800E691C
QUEUE_INDEX = 0x800E699C
GIRL_FLAGS = 0x800E6448    # + 0x38 * girl; bit 1 = met
GEKO_EXN_LBA = 37994
# Return addresses of the rank calls (0x80051A68) in GEKO.EXN's walk-home steps.
RANK_RETURNS = [0x80132960, 0x80132D20, 0x801331B8, 0x80133268, 0x80133338,
                0x801335B0, 0x80133774, 0x80133D3C]
PART = 0x80144C3C
TOPIC = 0x80144C50


def main() -> None:
    args = sys.argv[1:]
    extra = []
    if "--" in args:
        i = args.index("--")
        args, extra = args[:i], args[i + 1:]
    rank = topic = None
    timeout = 400.0
    for opt in ("--rank", "--topic", "--timeout"):
        if opt in args:
            i = args.index(opt)
            value = args[i + 1]
            del args[i:i + 2]
            if opt == "--rank":
                rank = int(value, 0)
            elif opt == "--topic":
                topic = int(value, 0)
            else:
                timeout = float(value)
    if len(args) != 1:
        sys.exit(__doc__)
    girl = int(args[0], 0)

    g = Gdb()
    flags = GIRL_FLAGS + 0x38 * girl
    old = g.mem(flags, 1)[0]
    g.cmd(f"M{flags:x},1:{old | 2:02x}")
    print(f"girl {girl} flags {old:#04x} -> {old | 2:#04x}", flush=True)
    g.break_at(READ_RECORD)
    t0 = time.time()
    forced = False
    try:
        while not forced and (left := timeout - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                print("timed out without forcing", flush=True)
                g.detach()
                return
            addr = QUEUE + 4 * g.mem(QUEUE_INDEX, 1)[0]
            record = g.mem(addr, 4)
            if record[0] == 0x00:
                new = bytes([0x44, girl, 0, 0])
                g.cmd(f"M{addr:x},4:{new.hex()}")
                print(f"forced {new.hex(' ')} at {addr:#x} (was {record.hex(' ')})", flush=True)
                forced = True
    finally:
        g.clear_break(READ_RECORD)
    rules = break_set.parse(extra + ["--timeout", str(timeout)])[2] if extra else []
    if rank is not None:
        for pc in RANK_RETURNS:
            rules.append({"pc": pc, "actions": [("reg", "v0", rank)], "times": 0, "hits": 0})
    if topic is not None:
        # The talk after the walk only runs when a topic is pending
        # (0x80144C50 != 0, normally proposed from the calendar); its part is
        # 22 + the topic id (0x80133F94). Set the id at the first rank call.
        rules.append({"pc": 0x801331B8, "actions": [("mem8", TOPIC, topic - 22)], "times": 1, "hits": 0})
    merged = {}
    for r in rules:
        if r["pc"] in merged:
            merged[r["pc"]]["actions"] += r["actions"]
            merged[r["pc"]]["times"] = 0 if 0 in (merged[r["pc"]]["times"], r["times"]) else merged[r["pc"]]["times"]
        else:
            merged[r["pc"]] = r
    rules = list(merged.values())
    if rules:
        break_set.run(g, rules, GEKO_EXN_LBA, timeout - (time.time() - t0))
    else:
        g.detach()


if __name__ == "__main__":
    main()
