"""Force the "welcome to the club" scene (SERIFU/NYUBU.BIN) with a girl.

Usage:  python tools/emu/force_club_welcome.py GIRL [--club C] [--part N] [--timeout S]

Start it on the Sunday-night planning screen of a test card, then pick a
weekly command. The scene is main state 0x60 (KANGEI.EXN, entry 0x80132000;
game-internals 6q), which the game enters from 0x80077908 on a club day
when a girl shares the player's club. This tool stops where the day handler
is about to read the next ordinary day record (0x80071DD0, as
force_event.py does), stores GIRL in the scene's girl byte 0x800E69DD and
makes the handler call set_state(0x60) (0x80042878) and return through its
own epilogue (0x800722B4). GIRL: 0 Shiori, 1 Mio, 2 Yuina, 3 Ayako, 4 Saki,
5 Yukari, 6 Nozomi; 7 and up get NYUBU section 7.

--club C sets the player's club (top 4 bits of the u16 at 0x800E6374: 0
Literature ... 6 Baseball, 7 Soccer ... 10 Basketball, 11 none). The scene's
background is looked up by club for some girls; with no club (11, the
95/4/23 test save) Shiori's lookup reads past its table and the scene
hangs on an empty box waiting for a CD read, so give her a club.

--part N overrides the part the scene computes from the player's club and
the girl's flags (s16 0x800CA148, written by the selection ending at
0x80132C0C in KANGEI.EXN).

This changes game state (RAM and registers only): use it on test cards.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import break_set  # noqa: E402
from gdbstub import REG_NAMES, Gdb  # noqa: E402

READ_RECORD = 0x80071DD0    # day handler, record index already advanced
EPILOGUE = 0x800722B4       # the day handler's own return path
SET_STATE = 0x80042878
QUEUE, QUEUE_INDEX, DATE = 0x800E691C, 0x800E699C, 0x800E62BE
GIRL_BYTE = 0x800E69DD
CLUB = 0x800E6374
KANGEI_LBA = 38186
PART_DONE = 0x80132C0C


def setreg(g: Gdb, name: str, value: int) -> None:
    g.cmd(f"P{REG_NAMES.index(name):x}=" + struct.pack("<I", value).hex())


def main() -> None:
    args = sys.argv[1:]
    part, club, timeout = None, None, 300.0
    for opt in ("--part", "--club", "--timeout"):
        if opt in args:
            i = args.index(opt)
            value = args[i + 1]
            del args[i:i + 2]
            if opt == "--part":
                part = int(value, 0)
            elif opt == "--club":
                club = int(value, 0)
            else:
                timeout = float(value)
    if len(args) != 1:
        sys.exit(__doc__)
    girl = int(args[0], 0)

    g = Gdb()
    g.break_at(READ_RECORD)
    t0 = time.time()
    forced = False
    try:
        while (left := timeout - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                print("timed out without forcing", flush=True)
                return
            index = g.mem(QUEUE_INDEX, 1)[0]
            record = g.mem(QUEUE + 4 * index, 4)
            y, m, d, wd = g.mem(DATE, 4)
            print(f"{y}/{m}/{d} wd{wd} index {index} record {record.hex(' ')}", flush=True)
            if record[0] == 0x00:
                g.cmd(f"M{GIRL_BYTE:x},1:{girl:02x}")
                if club is not None:
                    old = struct.unpack("<H", g.mem(CLUB, 2))[0]
                    new = (old & 0x0FFF) | club << 12
                    g.cmd(f"M{CLUB:x},2:" + struct.pack("<H", new).hex())
                setreg(g, "a0", 0x60)
                setreg(g, "ra", EPILOGUE)
                setreg(g, "pc", SET_STATE)
                print(f"state 0x60 (club welcome), girl {girl}, club {club}", flush=True)
                forced = True
                break
    finally:
        g.clear_break(READ_RECORD)
        if not (forced and part is not None):
            g.detach()
    if forced and part is not None:
        rule = {"pc": PART_DONE, "times": 1, "hits": 0,
                "actions": [("mem16", 0x800CA148, part)]}
        break_set.run(g, [rule], KANGEI_LBA, timeout)


if __name__ == "__main__":
    main()
