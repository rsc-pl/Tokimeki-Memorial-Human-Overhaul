"""Force the graduation ending (ENDING.EXN, main state 0x63) with a chosen girl.

Usage:  python tools/emu/force_ending.py GIRL [--set ADDR=VALUE ...] [--timeout S]

Start it on the Sunday-night planning screen of a test card (xmas_run.ps1
-Tool "tools/emu/force_ending.py 0" ...). Like force_state.py 0x63, it
changes the argument of the next set_state(0x40) call to 0x63, so that day
runs the ending. ENDING.EXN then picks who waits at the tree
(game-internals 6ac): 0x800E71DF starts at 13 (nobody), becomes 12 in a
special case, or the met girl with the highest score above 499; the
result is read back at 0x80133224. This stops there, after the choice,
and overwrites 0x800E71DF with GIRL (0 Shiori ... 10 Yumi, 12, 13; see
6ac for the sections). The breakpoint is only acted on while the main
state 0x800E7388 is 0x63 (another overlay may run code at that address).

--set writes any byte at the same moment (e.g. a flag the ending reads).
--trace S then logs, for S seconds, every distinct string handed to
add_text (0x8004E788, a3 = string), to see what the ending draws.
This changes game state: only on the harness's test cards.
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
STATE = 0x800E7388
CHOSEN = 0x80133224      # ENDING.EXN: lbu of 0x800E71DF right after the choice
GIRL = 0x800E71DF
ADD_TEXT = 0x8004E788


def main() -> None:
    args = sys.argv[1:]
    sets, timeout = [], 300.0
    while "--set" in args:
        i = args.index("--set")
        a, v = args[i + 1].split("=")
        sets.append((int(a, 0), int(v, 0)))
        del args[i:i + 2]
    trace = 0.0
    if "--trace" in args:
        i = args.index("--trace")
        trace = float(args[i + 1])
        del args[i:i + 2]
    if "--timeout" in args:
        i = args.index("--timeout")
        timeout = float(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    girl = int(args[0], 0)
    sys.stdout.reconfigure(encoding="utf-8")

    g = Gdb()
    t0 = time.time()
    g.break_at(SET_STATE)
    try:
        while True:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                sys.exit("timed out before the state change")
            if g.regs()["a0"] == 0x40:
                g.cmd(f"P{REG_NAMES.index('a0'):x}=" + struct.pack("<I", 0x63).hex())
                print("state 0x40 -> 0x63", flush=True)
                break
    finally:
        g.clear_break(SET_STATE)

    g.break_at(CHOSEN)
    try:
        while True:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                sys.exit("timed out before the ending chose a girl")
            if g.mem(STATE, 1)[0] != 0x63:
                continue
            was = g.mem(GIRL, 1)[0]
            g.cmd(f"M{GIRL:x},1:{girl:02x}")
            for a, v in sets:
                g.cmd(f"M{a:x},1:{v:02x}")
            print(f"ending girl {was} -> {girl}", flush=True)
            break
    finally:
        g.clear_break(CHOSEN)
    if trace:
        seen, t1 = set(), time.time()
        g.break_at(ADD_TEXT)
        try:
            while time.time() - t1 < trace:
                try:
                    g.cont(timeout=trace - (time.time() - t1))
                except socket.timeout:
                    g.interrupt()
                    break
                a3 = g.regs()["a3"]
                raw = g.mem(a3, 64).split(b"\0")[0]
                if raw not in seen:
                    seen.add(raw)
                    text = "".join(chr(c & 0x7F) if 0xA0 <= c < 0xFF else "." for c in raw)
                    try:
                        text = raw.decode("cp932")
                    except UnicodeDecodeError:
                        pass
                    print(f"add_text {a3:#x}: {raw.hex()}", flush=True)
        finally:
            g.clear_break(ADD_TEXT)
    g.detach()


if __name__ == "__main__":
    main()
