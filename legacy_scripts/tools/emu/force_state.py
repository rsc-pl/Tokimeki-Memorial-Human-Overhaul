"""Enter any main state (overlay) at any stage, in the isolated emulator.

Usage:  python tools/emu/force_state.py STATE [--from 0x40] [--stage N] [--step N]
            [--girl G] [--scene S] [--set ADDR=VALUE ...] [--timeout S]

Generic version of the swaps force_christmas.py and force_newyear.py do.
At the next set_state(FROM) call (0x80042878; default 0x40, the weekday
study state the Sunday test state reaches first), it changes the argument
to STATE, so that day runs the overlay the overlay-load table gives STATE
(game-internals 6j "Overlay selection"; the full state -> overlay map is in
docs/game-internals.md §6aa). Then it waits until the main state byte
0x800E7388 holds STATE and sets, before the overlay's dispatcher reads
them:
  --stage N / --step N   the stage byte 0x800E7389 / step byte 0x800E738A
  --girl G               0x800E71DF (the scene's girl) and 0x80122CD4
  --scene S              0x80122CD0 (the scene id overlays switch on)
  --set ADDR=VALUE       any byte (repeatable), e.g. a year or flag
Stage and step are written once, right after the state changes; the
overlay's first frame then starts there.

Start it on the Sunday-night planning screen (xmas_run.ps1 -Tool
"tools/emu/force_state.py 0x63 --stage 2" ...). This changes game state:
only on the harness's test cards, and compare with the unpatched game.
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


def main() -> None:
    args = sys.argv[1:]
    opts, sets = {}, []
    while "--set" in args:
        i = args.index("--set")
        a, v = args[i + 1].split("=")
        sets.append((int(a, 0), int(v, 0)))
        del args[i:i + 2]
    for opt in ("--from", "--stage", "--step", "--girl", "--scene", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = int(args[i + 1], 0) if opt != "--timeout" else float(args[i + 1])
            del args[i:i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    want = int(args[0], 0)
    frm = opts.get("--from", 0x40)
    timeout = opts.get("--timeout", 300.0)

    g = Gdb()
    g.break_at(SET_STATE)
    t0 = time.time()
    try:
        while (left := timeout - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                sys.exit("timed out before the state change")
            r = g.regs()
            if r["a0"] == frm:
                g.cmd(f"P{REG_NAMES.index('a0'):x}=" + struct.pack("<I", want).hex())
                print(f"state {frm:#x} -> {want:#x} on {list(g.mem(0x800E62BE, 4))}", flush=True)
                break
    finally:
        g.clear_break(SET_STATE)
    # Let set_state run, then write the stage bytes before the next frame.
    g.detach()
    if not any(k in opts for k in ("--stage", "--step", "--girl", "--scene")) and not sets:
        return
    while time.time() - t0 < timeout:
        time.sleep(0.05)
        g = Gdb()
        if g.mem(STATE, 1)[0] == want:
            if "--stage" in opts:
                g.cmd(f"M800e7389,1:{opts['--stage']:02x}")
            if "--step" in opts:
                g.cmd(f"M800e738a,1:{opts['--step']:02x}")
            if "--girl" in opts:
                g.cmd(f"M800e71df,1:{opts['--girl']:02x}")
                g.cmd("M80122cd4,4:" + struct.pack("<I", opts["--girl"]).hex())
            if "--scene" in opts:
                g.cmd("M80122cd0,4:" + struct.pack("<I", opts["--scene"]).hex())
            for a, v in sets:
                g.cmd(f"M{a:x},1:{v:02x}")
            print(f"set {opts} {[(hex(a), v) for a, v in sets]}", flush=True)
            g.detach()
            return
        g.detach()
    sys.exit("state never became current")


if __name__ == "__main__":
    main()
