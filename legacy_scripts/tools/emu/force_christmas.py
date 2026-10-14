"""Force the Christmas party in the isolated emulator (test cards only).

Usage:  python tools/emu/force_christmas.py [--girl 0|7|9] [--timeout S]
        python tools/emu/force_christmas.py --party [--visits N] [--looks V]
            [--physique V] [--sotoi N] [--visit] [--girls A,B] [--met G,...]
            [--mood M] [--intro] [--present P] [--timeout S]

At the next ordinary weekday state change (state 0x40, a study day), swaps
the requested state for 0x52, which runs SHOUGATU.EXN's Christmas-party
flow. When that flow's stage dispatcher (0x8013D180, stopped at 0x8013D190
before it reads the stage byte) first runs, the tool sets the stage.

Without --party it writes what the party's girl selector (0x80140030)
would: stage 6 with girl 0 / scene id 7, Shiori's walk home after the
party (EVENT_FU, game-internals 6j); --girl 7 gives stage 7, Mira's walk
(EVENT_KG), --girl 9 stage 8, Megumi's (EVENT_MI; game-internals 6z).

--party starts at stage 0 instead: the whole party (SERIFU/XMAS.BIN,
game-internals 6t). Stage 0 is the arrival at Ijuin's house, stage 1
Ijuin's speech, stage 2 the mingling (Shiori, then two random girls 1-10),
stage 3 the present exchange, stage 4 the evening at home after being
turned away. Options, all written to RAM or registers:
  --visits N   earlier parties attended (bits 9-11 of 0x800E66E8): picks
               Ijuin's speech (part 9 + 3N of section 11) and the door checks.
  --looks V    0x800E6396 (probably Looks): at least 70 + 30N (-10 from the
               third party) and the butler lets the player in politely.
  --physique V 0x800E638E: otherwise, at least 150 + 25N and Sotoi lets him
               in for his physique; below both, he's turned away.
  --sotoi N    times Sotoi has done that (bits 9-11 of 0x800E6758): from 1
               on, he says "you've come again" instead.
  --visit      on the turned-away evening, Megumi visits with a present
               (Megumi's field 0x800E6636 = 50 at 0x80140AD8 and the coin
               flip forced at 0x80140B10; she must be unmet).
  --girls A,B  the two girls met after Shiori (0x800E71DF at 0x8013E8A0 and
               0x8013EC7C, before the game reads her mood and section).
  --met G,...  mark these girls as met (bit 1 of 0x800E6448 + 0x38*girl)
               when they're picked, so they chat instead of playing their
               first meeting (Yumi, 10, has no first meeting here).
  --mood M     the value the girl-mood call (0x80051A68) returns for Shiori
               and both girls (4: she brushes the player off).
  --intro      Shiori introduces a friend (0x80146050 = 1, normally needs
               Megumi unmet with 20+ in her field and a coin flip): the
               first girl becomes Megumi (9).
  --present P  the present exchange's part (0x80145F2C at 0x8013FEC0):
               3*girl + year + 2 (girl 11 is Ijuin; year 0-2), which box
               the player opens no longer matters.

Graphics left over from the weekday screen show behind the scene; the text
boxes are unaffected. Use it only on the harness's test cards, and do the
same forcing on the unpatched game for the comparison run.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import REG_NAMES, Gdb  # noqa: E402

SET_STATE = 0x80042878       # set_state(a0)
DISPATCH = 0x8013D190        # SHOUGATU stage dispatcher, before it reads 0x800E7389
DISPATCH_CODE = bytes.fromhex("0e800e3c8973ce91")
# girl -> (stage, scene id written to 0x80122CD0): the walks home after the
# party read event-table entries 12 (Shiori, stage 6 0x801419D0), 36 (Mira,
# stage 7 0x80142500) and 60 (Megumi, stage 8 0x801430A0); game-internals 6z.
STAGES = {0: (6, 7), 7: (7, 7), 9: (8, 7)}
PICK = (0x8013E8A0, 0x8013EC7C)            # 0x800E71DF read after each random pick
MOOD = (0x8013E5C8, 0x8013E8B8, 0x8013EC94)  # just after each 0x80051A68 call
INTRO = 0x8013E5B8           # Shiori's step stores 0x800E71DF; 0x80146050 decided
PRESENT = 0x8013FEC0         # just after the present part is stored at 0x80145F2C
VISIT = (0x80140AD8, 0x80140B10)  # stage 4: Megumi's visit checks (her field, coin flip)


def setreg(g: Gdb, name: str, value: int) -> None:
    g.cmd(f"P{REG_NAMES.index(name):x}=" + struct.pack("<I", value).hex())


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--girl", "--timeout", "--visits", "--looks", "--physique", "--sotoi", "--girls",
                "--mood", "--present", "--met"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    flags = {f for f in ("--party", "--intro", "--visit") if f in args}
    args = [a for a in args if a not in flags]
    girl = int(opts.get("--girl", "0"), 0)
    timeout = float(opts.get("--timeout", "300"))
    party = "--party" in flags
    if args or (not party and girl not in STAGES):
        sys.exit(__doc__)
    girls = [int(x, 0) for x in opts["--girls"].split(",")] if "--girls" in opts else []

    g = Gdb()
    g.break_at(SET_STATE)
    armed: list[int] = []
    t0 = time.time()
    try:
        while (left := timeout - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                print("timed out", flush=True)
                return
            r = g.regs()
            pc = r["pc"]
            if pc == SET_STATE:
                if r["a0"] != 0x40:
                    continue
                setreg(g, "a0", 0x52)
                print(f"state 0x40 -> 0x52 on {list(g.mem(0x800E62BE, 4))}", flush=True)
                g.clear_break(SET_STATE)
                g.break_at(DISPATCH)
                continue
            if pc == DISPATCH:
                if g.mem(DISPATCH, 8) != DISPATCH_CODE:
                    continue
                g.clear_break(DISPATCH)
                if not party:
                    stage, scene = STAGES[girl]
                    g.cmd("M800e7389,2:" + bytes([stage, 0]).hex())
                    g.cmd("M80122cd4,4:" + struct.pack("<I", girl).hex())
                    g.cmd("M80122cd0,4:" + struct.pack("<I", scene).hex())
                    g.cmd(f"M800e71df,1:{girl:02x}")
                    print(f"stage {stage}, girl {girl}, scene id {scene}", flush=True)
                    return
                g.cmd("M800e7389,2:0000")
                if "--visits" in opts:
                    word = struct.unpack("<I", g.mem(0x800E66E8, 4))[0]
                    word = (word & ~0xE00) | (int(opts["--visits"], 0) & 7) << 9
                    g.cmd("M800e66e8,4:" + struct.pack("<I", word).hex())
                if "--sotoi" in opts:
                    word = struct.unpack("<I", g.mem(0x800E6758, 4))[0]
                    word = (word & ~0xE00) | (int(opts["--sotoi"], 0) & 7) << 9
                    g.cmd("M800e6758,4:" + struct.pack("<I", word).hex())
                for opt, addr in (("--physique", 0x800E638E), ("--looks", 0x800E6396)):
                    if opt in opts:
                        g.cmd(f"M{addr:x},2:" + struct.pack("<h", int(opts[opt], 0)).hex())
                print("party from stage 0, " + ", ".join(f"{k} {v}" for k, v in opts.items()),
                      flush=True)
                armed = list(PICK[:len(girls)])
                if "--mood" in opts:
                    armed += MOOD
                if "--intro" in flags:
                    armed.append(INTRO)
                if "--present" in opts:
                    armed.append(PRESENT)
                if "--visit" in flags:
                    armed += VISIT
                if not armed:
                    return
                for a in armed:
                    g.break_at(a)
                continue
            if pc in PICK:
                k = PICK.index(pc)
                gl = girls[k]
                g.cmd(f"M800e71df,1:{gl:02x}")
                if str(gl) in opts.get("--met", "").split(","):
                    met = 0x800E6448 + 0x38 * gl
                    g.cmd(f"M{met:x},1:{g.mem(met, 1)[0] | 2:02x}")
                print(f"girl {k + 1} -> {gl}", flush=True)
            elif pc in MOOD:
                setreg(g, "v0", int(opts["--mood"], 0))
                print(f"mood {opts['--mood']} at {pc:#x}", flush=True)
            elif pc == INTRO:
                g.cmd("M80146050,1:01")
                print("Shiori introduces a friend", flush=True)
            elif pc == VISIT[0]:
                g.cmd("M800e6636,2:" + struct.pack("<h", 50).hex())
                print("Megumi's field -> 50", flush=True)
            elif pc == VISIT[1]:
                setreg(g, "t0", 1)
                print("Megumi visits", flush=True)
            elif pc == PRESENT:
                g.cmd("M80145f2c,2:" + struct.pack("<h", int(opts["--present"], 0)).hex())
                print(f"present part {opts['--present']}", flush=True)
            else:
                continue
            # each armed address runs once per party
            g.clear_break(pc)
            armed.remove(pc)
            if not armed:
                return
    finally:
        for a in (SET_STATE, DISPATCH, *PICK, *MOOD, INTRO, PRESENT, *VISIT):
            g.clear_break(a)
        g.detach()


if __name__ == "__main__":
    main()
