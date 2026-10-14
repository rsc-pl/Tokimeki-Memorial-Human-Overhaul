"""Force the culture festival day (CDROM/BUNKA/*.BIN) in the isolated emulator.

Usage:  python tools/emu/force_festival.py [--only G | --met G,...] [--club C]
            [--year N] [--timeout S]

Start it on the Sunday-night planning screen of a test card, then pick a
weekly command. It sets up who the festival can involve, then writes a
festival day record `24 00 00 00` over the next ordinary one and the week's
first record (0x800E691C), as force_event.py --type 0x24 --first does: that
day enters main state 0x70 (BUNKASAI.EXN), which plays the whole day
(game-internals 6aa, "The festival day").

--only G marks girl G as met and every other girl as not met (bit 1 of
0x800E6448 + 0x38*girl, as force_trip.py), so the "who shall I invite?"
menu lists only her and the first item picks her. --met G,... only adds
girls. Girl ids: 0 Shiori, 1 Mio, 2 Yuina, 3 Ayako, 4 Saki, 5 Yukari,
6 Nozomi, 7 Mira, 8 Yuko, 9 Megumi, 10 Yumi.

--club C sets the player's club (top 4 bits of the u16 at 0x800E6374, as
force_club_welcome.py): 0 Literature, 1 Drama, 2 Science, 3 Computer,
4 Art, 5 Band (the six exhibiting clubs), 6-10 sports, 11 none.

--year N sets the year byte 0x800E62BE to 95+N (N = 0, 1, 2).

Then drive the day's menus with xmas_run.ps1 -KeyList. This changes game
state (RAM only): use it on the harness's test cards, and force the
unpatched game the same way for comparisons.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402

READ_RECORD = 0x80071DD0   # day handler: index advanced, next insn reads the record
QUEUE = 0x800E691C
QUEUE_INDEX = 0x800E699C
MET = 0x800E6448           # + 0x38 * girl, bit 1
CLUB = 0x800E6374          # u16, club in the top 4 bits
YEAR = 0x800E62BE
GIRLS = 11


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--only", "--met", "--club", "--year", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    if args or ("--only" in opts and "--met" in opts):
        sys.exit(__doc__)
    timeout = float(opts.get("--timeout", "300"))

    g = Gdb()
    if "--only" in opts:
        only = int(opts["--only"], 0)
        for girl in range(GIRLS):
            addr = MET + 0x38 * girl
            v = g.mem(addr, 1)[0]
            v = v | 2 if girl == only else v & ~2 & 0xFF
            g.cmd(f"M{addr:x},1:{v:02x}")
    for girl in (int(x, 0) for x in opts.get("--met", "").split(",") if x):
        addr = MET + 0x38 * girl
        g.cmd(f"M{addr:x},1:{g.mem(addr, 1)[0] | 2:02x}")
    if "--club" in opts:
        club = int(opts["--club"], 0)
        v = int.from_bytes(g.mem(CLUB, 2), "little")
        v = (v & 0x0FFF) | (club << 12)
        g.cmd(f"M{CLUB:x},2:{v.to_bytes(2, 'little').hex()}")
    if "--year" in opts:
        g.cmd(f"M{YEAR:x},1:{0x5F + int(opts['--year'], 0):02x}")
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
                g.cmd(f"M{addr:x},4:24000000")
                g.cmd(f"M{QUEUE:x},1:24")
                club = int.from_bytes(g.mem(CLUB, 2), "little") >> 12
                print(f"festival record at {addr:#x} (was {record.hex(' ')}), club {club}", flush=True)
                break
    finally:
        g.clear_break(READ_RECORD)
        g.detach()


if __name__ == "__main__":
    main()
