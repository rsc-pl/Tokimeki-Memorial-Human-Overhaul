"""Make the player's birthday happen, optionally with a girl's present.

Usage:  python tools/emu/force_birthday.py [GIRL] [--date M/D] [--timeout S]
        python tools/emu/force_birthday.py --her GIRL [--as OTHER] [--date M/D]

Run it on the Sunday-night planning screen of a test card, then pick a
weekly command. It writes the player's birthday (bits 0-3 month, 4-8 day of
the u32 at 0x800E6378; game-internals 6r) as M/D (default 4/25, the Monday
after the 95/4/23 test save), so the birthday scene (SERIFU/P_BIRTH.BIN)
plays that day by itself. On that save nobody brings a present, so it is
the "nobody gave me a present" lines.

With GIRL (0 Shiori ... 10 Yumi) the tool also waits for the overlay that
runs the scene: on a school day GEKO.EXN (state 0x56), in other flows
KANGEI.EXN; each has its own copy of the selector, which takes the met girl
with the best rank and gives the present only if that rank is below 2. It
polls RAM for the overlay's code at its selector (both addresses are other
code in the main-screen overlay, so a breakpoint armed early would fire
constantly), then breaks there and sets the girl and her rank to 0.

--her GIRL instead sets that girl's birthday (same format, u32 at
0x800E644C + 0x38*GIRL) to M/D and marks her as met (bit 1 of
0x800E6448 + 0x38*GIRL), so her birthday scene (SERIFU/G_BIRTH.BIN) plays
that day: the player decides whether to give a present and which.
Only a girl the save has really met gets one: setting the met bit on the
95/4/23 save (only Shiori met) queued first-meeting scenes instead. So
--as OTHER takes Shiori's birthday (--her 0) and, when GEKO.EXN's G_BIRTH
section switch runs (0x801361D4, polled by its code bytes as above), sets
the scene's girl 0x800E71DF to OTHER: her section, label and lines play.

This changes game state (RAM and registers only): use it on test cards.
"""

from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import REG_NAMES, Gdb  # noqa: E402

BIRTHDAY = 0x800E6378
# overlay: (selector pc, its code bytes, girl register, rank register)
SELECTORS = {
    "GEKO": (0x80134930, "0200e12d08002010", "fp", "t7"),
    "KANGEI": (0x8013907C, "0200a12d07002010", "s7", "t5"),
}


def setreg(g: Gdb, name: str, value: int) -> None:
    g.cmd(f"P{REG_NAMES.index(name):x}=" + struct.pack("<I", value).hex())


GBIRTH_SWITCH = 0x801361D4      # GEKO.EXN, reads the girl id for G_BIRTH
GBIRTH_CODE = bytes.fromhex("0e800c3cdf718c91")


def swap_girl(other: int, timeout: float) -> None:
    t0 = time.time()
    while True:
        time.sleep(0.2)
        g = Gdb()
        if g.mem(GBIRTH_SWITCH, 8) == GBIRTH_CODE:
            break
        g.detach()
        if time.time() - t0 > timeout:
            sys.exit("GEKO.EXN never loaded")
    g.break_at(GBIRTH_SWITCH)
    try:
        g.cont(timeout=timeout)
        g.cmd(f"M{0x800E71DF:x},1:{other:02x}")
        print(f"G_BIRTH scene girl -> {other}", flush=True)
    finally:
        g.clear_break(GBIRTH_SWITCH)
        g.detach()


def main() -> None:
    args = sys.argv[1:]
    month, day, timeout = 4, 25, 300.0
    her, other = None, None
    for opt in ("--date", "--timeout", "--her", "--as"):
        if opt in args:
            i = args.index(opt)
            value = args[i + 1]
            del args[i:i + 2]
            if opt == "--her":
                her = int(value, 0)
            elif opt == "--as":
                other = int(value, 0)
            elif opt == "--date":
                month, day = (int(x) for x in value.split("/"))
            else:
                timeout = float(value)
    if len(args) > 1:
        sys.exit(__doc__)
    girl = int(args[0], 0) if args else None

    g = Gdb()
    if her is not None:
        field = 0x800E644C + 0x38 * her
        old = struct.unpack("<I", g.mem(field, 4))[0]
        new = (old & ~0x1FF) | day << 4 | month
        g.cmd(f"M{field:x},4:" + struct.pack("<I", new).hex())
        if other is None:
            met = 0x800E6448 + 0x38 * her
            flags = g.mem(met, 1)[0] | 2
            g.cmd(f"M{met:x},1:{flags:02x}")
        print(f"girl {her} birthday {old:#x} -> {new:#x} ({month}/{day})", flush=True)
        g.detach()
        if other is not None:
            swap_girl(other, timeout)
        return
    old = struct.unpack("<I", g.mem(BIRTHDAY, 4))[0]
    new = (old & ~0x1FF) | day << 4 | month
    g.cmd(f"M{BIRTHDAY:x},4:" + struct.pack("<I", new).hex())
    print(f"player birthday {old:#x} -> {new:#x} ({month}/{day})", flush=True)
    g.detach()
    if girl is None:
        return

    t0 = time.time()
    found = None
    while found is None:
        time.sleep(0.2)
        g = Gdb()
        for name, (pc, code, _, _) in SELECTORS.items():
            if g.mem(pc, 8) == bytes.fromhex(code):
                found = name
                break
        else:
            g.detach()
            if time.time() - t0 > timeout:
                sys.exit("no birthday overlay loaded")
    pc, _, girl_reg, rank_reg = SELECTORS[found]
    print(f"{found}.EXN loaded after {time.time() - t0:.1f}s", flush=True)
    g.break_at(pc)
    try:
        g.cont(timeout=timeout)
        setreg(g, girl_reg, girl)
        setreg(g, rank_reg, 0)
        print(f"girl {girl} brings a present ({girl_reg}, {rank_reg})", flush=True)
    finally:
        g.clear_break(pc)
        g.detach()


if __name__ == "__main__":
    main()
