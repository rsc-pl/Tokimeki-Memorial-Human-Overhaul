"""Force the summer training camp (SERIFU/GASSHUKU.BIN, GASSH_FU.BIN) in the isolated emulator.

Usage:  python tools/emu/force_camp.py [--club C] [--met G,...] [--girl G]
            [--parts P,...] [--year N] [--week N] [--timeout S]

Start it on the Sunday-night planning screen, then pick a weekly command.
It sets the player's club (top 4 bits of the u16 0x800E6374: 0 Literature,
1 Drama, 2 Science, 3 Computer, 4 Art, 5 Band, 6 Baseball, 7 Soccer,
8 Tennis, 9 Swimming, 10 Basketball; game-internals 6q/6x), marks the
--met girls as met (bit 1 of 0x800E6448 + 0x38*girl), optionally sets the
year byte 0x800E62BE to 95+N, and writes a camp day record `42 00 00 00`
over the next ordinary one (main loop 0x80071DD0, as force_event.py) and
makes the week's first record (0x800E691C) a camp day too, which the camp
checks before going on: that day enters state 0x5F, KANGEI.EXN's training
camp (game-internals 6x).

The camp then runs one stage per day by itself (game-internals 6x). Its
girl is the first girl in the player's club (club nibble of 0x800E644A +
0x38*girl, chosen at 0x80133DC8); --girl G puts G in the club (and any
lower-numbered girl in it out, to "none"). Her scene plays in stage 9: a
chat when she's met (--met), else her first-meeting scenes (0x80134DB0;
not for Yumi, 10, or in 1997). Her chat goes through 0x801349B4, where
the part has been computed (0x80139ADC) and her section (switch
0x801349EC: 0 Shiori -> GASSH_FU, 1 Mio, 2 Yuina, 3 Ayako, 4 Saki,
5 Yukari, 6 Nozomi, others Yumi's section 7) is about to load; the tool
polls RAM for KANGEI's code there and sets
  --parts P,.. the part, one per pass (the last repeats).
--week N also makes the week's records after this one, up to index N-1,
camp days.

This changes game state (RAM only): use it on the harness's test cards.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402

READ_RECORD = 0x80071DD0
QUEUE = 0x800E691C
QUEUE_INDEX = 0x800E699C
SCENE = 0x801349B4                       # jal 0x801349D4: load the girl's section
SCENE_CODE = bytes.fromhex("75d2040c00000000")
PART = 0x80139ADC


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--club", "--met", "--girl", "--parts", "--year", "--week", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    if args:
        sys.exit(__doc__)
    timeout = float(opts.get("--timeout", "300"))
    parts = [int(x, 0) for x in opts["--parts"].split(",")] if "--parts" in opts else []

    g = Gdb()
    if "--club" in opts:
        word = struct.unpack("<H", g.mem(0x800E6374, 2))[0]
        word = (word & 0x0FFF) | (int(opts["--club"], 0) & 0xF) << 12
        g.cmd("M800e6374,2:" + struct.pack("<H", word).hex())
    for girl in (int(x, 0) for x in opts.get("--met", "").split(",") if x):
        addr = 0x800E6448 + 0x38 * girl
        g.cmd(f"M{addr:x},1:{g.mem(addr, 1)[0] | 2:02x}")
    if "--girl" in opts:
        club = struct.unpack("<H", g.mem(0x800E6374, 2))[0] >> 12
        girl = int(opts["--girl"], 0)
        for k in range(girl + 1):
            addr = 0x800E644A + 0x38 * k
            b = g.mem(addr, 1)[0]
            if k == girl:
                b = (b & 0x0F) | club << 4
            elif b >> 4 == club:
                b = (b & 0x0F) | 0xB0
            g.cmd(f"M{addr:x},1:{b:02x}")
    if "--year" in opts:
        g.cmd(f"M800e62be,1:{0x5F + int(opts['--year'], 0):02x}")
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
                g.cmd(f"M{addr:x},4:42000000")
                # The camp goes on only while the week's first record is a
                # camp day too (EXE 0x800752DC); otherwise set_stage(1)
                # replays the arrival forever (game-internals 6x).
                g.cmd(f"M{QUEUE:x},1:42")
                if "--week" in opts:
                    # every later day of the week a camp day too
                    for k in range(index + 1, int(opts["--week"], 0)):
                        g.cmd(f"M{QUEUE + 4 * k:x},4:42000000")
                print(f"camp record at {addr:#x} (was {record.hex(' ')}), club "
                      f"{struct.unpack('<H', g.mem(0x800E6374, 2))[0] >> 12}", flush=True)
                break
    finally:
        g.clear_break(READ_RECORD)
        g.detach()
    if not parts:
        return

    while True:
        time.sleep(0.2)
        g = Gdb()
        if g.mem(SCENE, 8) == SCENE_CODE:
            break
        g.detach()
        if time.time() - t0 > timeout:
            sys.exit("KANGEI.EXN never loaded")
    print(f"KANGEI loaded after {time.time() - t0:.1f}s", flush=True)
    g.break_at(SCENE)
    try:
        while time.time() - t0 < timeout:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                print("timed out", flush=True)
                return
            was = (g.mem(0x800E71DF, 1)[0], struct.unpack("<h", g.mem(PART, 2))[0])
            if parts:
                part = parts.pop(0) if len(parts) > 1 else parts[0]
                g.cmd(f"M{PART:x},2:" + struct.pack("<h", part).hex())
            print(f"scene: girl/part was {was}, now {g.mem(0x800E71DF, 1)[0]}/"
                  f"{struct.unpack('<h', g.mem(PART, 2))[0]}", flush=True)
    finally:
        g.clear_break(SCENE)
        g.detach()


if __name__ == "__main__":
    main()
