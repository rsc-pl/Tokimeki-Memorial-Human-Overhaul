"""Force New Year's Day (SERIFU/SHOGATU.BIN) in the isolated emulator (test cards only).

Usage:  python tools/emu/force_newyear.py [--visit G | --call G] [--year N]
            [--met G,...] [--timeout S]

Start it on the Sunday-night planning screen, then pick a weekly command.
At the next ordinary weekday state change (state 0x40) it swaps the state
for 0x53, SHOUGATU.EXN's New Year flow (game-internals 6w): a girl may
come to the door, or the player goes to the shrine alone or calls a girl.

Then it polls RAM for SHOUGATU's New Year code (the overlay area holds
other code before it loads) and arms:
  --visit G    girl G comes to the door (section part 0-5): at
               0x8013296C the best-ranked girl (fp, 0xFF for none) becomes
               G, and her mood call returns 0 (she visits when it's < 2).
  --call G     the player phones G (part 9 on): the menu's choice, stored
               to 0x800E71DF in the delay slot at 0x80133830, becomes G.
               Take "go with a girl" and any name in the menu.
  --year N     the year byte 0x800E62BE (95-97 = 1st-3rd New Year, written
               as 95+N right after the state swap); the date is otherwise
               the test card's.
  --met G,...  mark these girls met (bit 1 of 0x800E6448 + 0x38*girl).

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

SET_STATE = 0x80042878
SWITCH = 0x80132A34                      # New Year girl switch (lbu 0x800E71DF)
SWITCH_CODE = bytes.fromhex("0e800e3cdf71ce91")
VISIT = 0x8013296C                       # jal mood(fp); fp = the visiting girl
VISIT_MOOD = 0x80132974                  # mood call returned
CALL = 0x8013382C                        # jal switch; delay slot stores v0 -> 0x800E71DF


def setreg(g: Gdb, name: str, value: int) -> None:
    g.cmd(f"P{REG_NAMES.index(name):x}=" + struct.pack("<I", value).hex())


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--visit", "--call", "--year", "--met", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    if args:
        sys.exit(__doc__)
    timeout = float(opts.get("--timeout", "300"))

    g = Gdb()
    for girl in (int(x, 0) for x in opts.get("--met", "").split(",") if x):
        addr = 0x800E6448 + 0x38 * girl
        g.cmd(f"M{addr:x},1:{g.mem(addr, 1)[0] | 2:02x}")
    g.break_at(SET_STATE)
    t0 = time.time()
    try:
        while True:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                sys.exit("timed out before a weekday")
            r = g.regs()
            if r["a0"] == 0x40:
                setreg(g, "a0", 0x53)
                if "--year" in opts:
                    g.cmd(f"M800e62be,1:{0x5F + int(opts['--year'], 0):02x}")
                print(f"state 0x40 -> 0x53, date {list(g.mem(0x800E62BE, 4))}", flush=True)
                break
    finally:
        g.clear_break(SET_STATE)
        g.detach()

    armed = ([VISIT, VISIT_MOOD] if "--visit" in opts else []) + ([CALL] if "--call" in opts else [])
    if not armed:
        return
    while True:
        time.sleep(0.2)
        g = Gdb()
        if g.mem(SWITCH, 8) == SWITCH_CODE:
            break
        g.detach()
        if time.time() - t0 > timeout:
            sys.exit("SHOUGATU.EXN never loaded")
    print(f"SHOUGATU loaded after {time.time() - t0:.1f}s", flush=True)
    for a in armed:
        g.break_at(a)
    try:
        while time.time() - t0 < timeout:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                print("timed out", flush=True)
                return
            pc = g.regs()["pc"]
            if pc == VISIT:
                setreg(g, "fp", int(opts["--visit"], 0))
                setreg(g, "a0", int(opts["--visit"], 0))
                print(f"visiting girl -> {opts['--visit']}", flush=True)
            elif pc == VISIT_MOOD:
                setreg(g, "v0", 0)
                print("her mood -> 0", flush=True)
            elif pc == CALL:
                setreg(g, "v0", int(opts["--call"], 0))
                print(f"call goes to girl {opts['--call']}", flush=True)
            else:
                continue
            g.clear_break(pc)
            armed.remove(pc)
            if not armed:
                return
    finally:
        for a in (VISIT, VISIT_MOOD, CALL):
            g.clear_break(a)
        g.detach()


if __name__ == "__main__":
    main()
