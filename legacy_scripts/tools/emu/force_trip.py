"""Force the school trip (SERIFU/SHUGAKU.BIN) in the isolated emulator.

Usage:  python tools/emu/force_trip.py [--met G,...] [--year N] [--week N]
            [--girl G] [--mood M] [--invite G] [--sick] [--event-mood] [--timeout S]

Start it on the Sunday-night planning screen, then pick a weekly command.
It marks the --met girls as met (bit 1 of 0x800E6448 + 0x38*girl),
optionally sets the year byte 0x800E62BE to 95+N, and writes a trip day
record `41 00 00 00` over the next ordinary one (main loop 0x80071DD0, as
force_event.py) and the week's first record (0x800E691C): that day enters
main state 0x51, SHUGAKU.EXN (game-internals 6y). The whole six-day trip
then plays from that one record and the week goes on. --week N also makes
the week's records after this one, up to index N-1, trip days: the trip
then starts over after day 6 (useful only to see it twice).

--sick sets the low nibble of 0x800E6375 (nonzero when the player is
ill; SHUGAKU's step 0x8013799C then blanks the first line and draws
"I feel awful, but it's the trip" with add_text).

--girl G: when the player's pick from the girl menu is stored
(0x801399C8: a0 -> 0x800E71DF, then set_girl 0x800847B8 and the section
switch 0x801399F4), make it G instead, so her name, portrait and section
all follow. The menu only lists met girls (--met). G is a girl id:
0 Shiori, 1 Mio, 2 Yuina, 3 Ayako, 4 Saki, 5 Yukari, 6 Nozomi, 7 Mira,
8 Yuko, 9 Megumi.

--mood M: her answer when the player asks her (0x80139628, the mood call
0x80051A68 & 0x7F): 0-1 glad (part 15), 2 part 18, 3 part 21, 4 and more
she turns him down (part 24).

--invite G: on the first free day, before the player chooses, the girl
with the best mood below 4 (loop 0x80139164, ties by two stat calls) asks
him herself when her mood is below 2 (parts 7-9). Makes it G with mood 0.

--event-mood makes the mood calls of the trip's special-event checks
return 0, so the girls' trip events (EVENT_* entries 19, 29, 48, 66)
can start: Yuina's (stage 8) needs Hokkaido, Ayako's (9) Okinawa, Saki's
(10) and Yukari's (11) a mood below 2 (game-internals 6z).

This changes game state (RAM only): use it on the harness's test cards.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import REG_NAMES, Gdb  # noqa: E402

READ_RECORD = 0x80071DD0
QUEUE = 0x800E691C
QUEUE_INDEX = 0x800E699C
SECTION = 0x801399F4                     # load the girl's section (switch on 0x800E71DF)
SECTION_CODE = bytes.fromhex("0e800e3cdf71ce91")
PICK = 0x801399C8                        # a0 = the girl picked from the menu
ANSWER = 0x80139628                      # v0 = her mood when the player asks
INVITE = 0x80139200                      # jal mood(s7 = the girl who may invite him)
INVITE_MOOD = 0x80139208                 # v0 = her mood (< 2: she invites him)
# After the mood calls of the special-event checks (0x80133358, 0x80138750,
# 0x801388E8): mood < 2 lets Yukari's (stage 11) and Saki's (stage 10)
# trip events start (game-internals 6z).
EVENT_MOODS = (0x80133360, 0x80138758, 0x801388F0)
GIRL = 0x800E71DF


def main() -> None:
    args = sys.argv[1:]
    opts = {}
    for opt in ("--met", "--year", "--week", "--girl", "--mood", "--invite", "--timeout"):
        if opt in args:
            i = args.index(opt)
            opts[opt] = args[i + 1]
            del args[i:i + 2]
    sick = "--sick" in args
    if sick:
        args.remove("--sick")
    event_mood = "--event-mood" in args
    if event_mood:
        args.remove("--event-mood")
    if args:
        sys.exit(__doc__)
    timeout = float(opts.get("--timeout", "300"))

    g = Gdb()
    for girl in (int(x, 0) for x in opts.get("--met", "").split(",") if x):
        addr = 0x800E6448 + 0x38 * girl
        g.cmd(f"M{addr:x},1:{g.mem(addr, 1)[0] | 2:02x}")
    if "--year" in opts:
        g.cmd(f"M800e62be,1:{0x5F + int(opts['--year'], 0):02x}")
    if sick:
        g.cmd(f"M800e6375,1:{g.mem(0x800E6375, 1)[0] & 0xF0 | 1:02x}")
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
                g.cmd(f"M{addr:x},4:41000000")
                g.cmd(f"M{QUEUE:x},1:41")
                if "--week" in opts:
                    for k in range(index + 1, int(opts["--week"], 0)):
                        g.cmd(f"M{QUEUE + 4 * k:x},4:41000000")
                print(f"trip record at {addr:#x} (was {record.hex(' ')})", flush=True)
                break
    finally:
        g.clear_break(READ_RECORD)
        g.detach()
    rules = {}
    if "--girl" in opts:
        rules[PICK] = [("a0", int(opts["--girl"], 0))]
    if "--mood" in opts:
        rules[ANSWER] = [("v0", int(opts["--mood"], 0))]
    if "--invite" in opts:
        rules[INVITE] = [("s7", int(opts["--invite"], 0))]
        rules[INVITE_MOOD] = [("v0", 0)]
    if event_mood:
        for pc in EVENT_MOODS:
            rules[pc] = [("v0", 0)]
    if not rules:
        return

    while True:
        time.sleep(0.2)
        g = Gdb()
        if g.mem(SECTION, 8) == SECTION_CODE:
            break
        g.detach()
        if time.time() - t0 > timeout:
            sys.exit("SHUGAKU.EXN never loaded")
    print(f"SHUGAKU loaded after {time.time() - t0:.1f}s", flush=True)
    for addr in rules:
        g.break_at(addr)
    try:
        while time.time() - t0 < timeout:
            try:
                g.cont(timeout=timeout - (time.time() - t0))
            except socket.timeout:
                g.interrupt()
                print("timed out", flush=True)
                return
            pc = g.regs()["pc"]
            for reg, value in rules.get(pc, []):
                was = g.regs()[reg]
                g.cmd(f"P{REG_NAMES.index(reg):x}=" + struct.pack("<I", value).hex())
                print(f"{pc:#x}: {reg} was {was}, now {value}", flush=True)
    finally:
        for addr in rules:
            g.clear_break(addr)
        g.detach()


if __name__ == "__main__":
    main()
