"""List the sections of a girl's DATE_*.BIN as a translation/test checklist.

Usage:
  python tools/date_sections.py [--girl N] [--file ...] [--exn ...] [--strings]

Reads DATE.EXN's section tables (game-internals §6k) and the place switch,
then prints, per section: the place it belongs to, its file range, string
and part counts, how many parts are choices (03/08) and replies (02), the
parts-per-version byte its setup stores, and the address where the setup
first reads the version byte 0x800CA2FC. Pass that address to
`tools/emu/force_date.py ... --set-at ADDR 0x800CA2FC N` to force version N.

--strings also lists each part's string offsets and speaker codes. Nothing
here prints game text, so the output can go into docs.

--girl N (0-10, default 0 Shiori) picks the girl: DATE.EXN's switch at
0x8013E7B0 (girl byte 0x800E69DD, jump table 0x8015AFE4) calls one fill
function per girl that writes the 81 table words, then reads her file by
LBA (game-internals 6k). This tool simulates that girl's fill function and
opens her file (DATE_FU/KI/HI/KA/NI/KO/KY/KG/AS/MI/SA.BIN).
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

EXN_BASE = 0x80132000
FILE_BASE = 0x80198000
TABLE = 0x8015BDC0          # 27 masters, then 27 byte lists, then 27 thirds
GIRL_JUMPS = 0x8015AFE4     # girl 0-9 -> case (girl 10 is the default case)
GIRL_DEFAULT = 0x8013E94C
GIRL_FILES = ["FU", "KI", "HI", "KA", "NI", "KO", "KY", "KG", "AS", "MI", "SA"]


def girl_table(exn: bytes, girl: int) -> list:
    """The 81 section-table words girl's fill function writes."""
    words = struct.unpack_from(f"<{len(exn) // 4}I", exn)
    case = GIRL_DEFAULT if girl == 10 else words[(GIRL_JUMPS - EXN_BASE) // 4 + girl]
    jal = words[(case - EXN_BASE) // 4]
    fill = ((jal & 0x3FFFFFF) << 2) | 0x80000000
    regs, table, i, end = {}, [0] * 81, (fill - EXN_BASE) // 4, None
    while True:
        w = words[i]
        op, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        if op == 0x0F:
            regs[rt] = imm << 16
        elif op == 0x0D:
            regs[rt] = regs.get(rs, 0) | imm
        elif op == 0x09:
            regs[rt] = (regs.get(rs, 0) + simm) & 0xFFFFFFFF
        elif op == 0x2B:
            addr = (regs.get(rs, 0) + simm) & 0xFFFFFFFF
            if TABLE <= addr < TABLE + 81 * 4:
                table[(addr - TABLE) // 4] = regs.get(rt, 0)
        if i == end:
            return table
        if w == 0x03E00008:     # jr ra: one more for the delay slot
            end = i + 1
        i += 1
SECTIONS = 27
PLACE_JUMPS = 0x8015B060    # place - 1 -> case storing the setup function
PLACES = 20
# The date's step list; its placeholder entry (step 9) is the place-0 setup:
# the runner (0x801449D4) replaces it with the place's setup for places 1-20.
STEP_LIST = 0x8015BF50
PLACE0_STEP = 9
VERSION_LO = 0xA2FC         # *(u8*)0x800CA2FC, the section's version
PARTS_PER_VERSION_LO = 0xB658   # *(u8*)0x8015B658
CODES = {0x00: "player", 0x01: "girl", 0x02: "reply", 0x03: "choice", 0x04: "narration",
         0x06: "thought", 0x07: "sound/narration", 0x08: "action choice"}
# Sections not reached through the place switch (game-internals §6k).
SHARED = {9: "Theme Park parade (sub-scene)", 22: "end of the date",
          23: "meeting", 24: "seasonal small talk", 25: "hobby notes", 26: "going home"}

ROOT = Path(__file__).resolve().parents[2]


def place_names() -> list:
    doc = json.loads((ROOT / "translation" / "outings.json").read_text(encoding="utf-8"))
    names = [line["text"] for block in doc["dialogue"] for line in block["lines"]
             if line["offset"].upper() >= "0X72B4C"]
    return names[:PLACES]


def scan_places(exn: bytes) -> dict:
    """{place: {place, setup, slot, load, ppv}} from DATE.EXN's place switch.

    `load` is where the setup first reads the version byte 0x800CA2FC (None
    if it never does); `ppv` the parts-per-version values it stores.
    """
    def xw(addr):
        return struct.unpack_from("<I", exn, addr - EXN_BASE)[0]

    places = {}
    for i in range(-1, PLACES):
        if i < 0:
            setup = xw(STEP_LIST + 4 * PLACE0_STEP)
        else:
            # Each case is `lui t, hi; addiu t, t, lo; b ...; sw t, (v0)`.
            case = xw(PLACE_JUMPS + 4 * i)
            hi, lo = xw(case) & 0xFFFF, xw(case + 4) & 0xFFFF
            setup = ((hi << 16) + struct.unpack("<h", struct.pack("<H", lo))[0]) & 0xFFFFFFFF
        info = {"place": i + 1, "setup": setup, "ppv": [], "load": None}
        addr = setup
        while xw(addr) != 0x03E00008:                       # up to `jr ra`
            w = xw(addr)
            op, imm = w >> 26, w & 0xFFFF
            if op == 0x23 and 0xBDC0 <= imm < 0xBDC0 + 4 * SECTIONS and "slot" not in info:
                info["slot"] = (imm - 0xBDC0) // 4          # lw of its master entry
            if op == 0x24 and imm == VERSION_LO and info["load"] is None:
                info["load"] = addr                         # first lbu of the version
            if op == 0x28 and imm == PARTS_PER_VERSION_LO:   # sb of parts per version
                rt = (w >> 16) & 31
                for back in range(addr - 4, addr - 40, -4):
                    v = xw(back)
                    if v >> 26 == 9 and (v >> 21) & 31 == 0 and (v >> 16) & 31 == rt:
                        info["ppv"].append(v & 0xFFFF)
                        break
            addr += 4
        places[i + 1] = info
    return places


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--girl", type=int, default=0)
    ap.add_argument("--file")
    ap.add_argument("--exn", default=str(ROOT / "extracted/CDROM/EXEDIR/DATE.EXN"))
    ap.add_argument("--strings", action="store_true")
    args = ap.parse_args()
    data = Path(args.file or ROOT / f"extracted/CDROM/SERIFU/DATE_{GIRL_FILES[args.girl]}.BIN").read_bytes()
    exn = Path(args.exn).read_bytes()
    table = girl_table(exn, args.girl)

    def xw(addr):
        return struct.unpack_from("<I", exn, addr - EXN_BASE)[0]

    def fw(off):
        return struct.unpack_from("<I", data, off)[0]

    in_file = lambda w: FILE_BASE <= w < FILE_BASE + len(data)

    by_slot = {info["slot"]: info for info in scan_places(exn).values()}
    names = ["Neighborhood park"] + place_names()
    for info in by_slot.values():
        info["name"] = names[info["place"]]

    total = 0
    for s in range(SECTIONS):
        master, blists = table[s] - FILE_BASE, table[SECTIONS + s] - FILE_BASE
        if not (in_file(table[s]) and in_file(table[SECTIONS + s])):
            # Mio, Yuina, Ayako and Megumi: section 16 (the Ski Resort) is a
            # null entry in their fill function; they have no ski date.
            print(f"section {s:2}  master {table[s]:#010x}, code lists "
                  f"{table[SECTIONS + s]:#010x}: outside the file, not read")
            continue
        parts = []
        while in_file(fw(master + 4 * len(parts))) and fw(master + 4 * len(parts)) - FILE_BASE < master:
            p = len(parts)
            lst, bl = fw(master + 4 * p) - FILE_BASE, fw(blists + 4 * p) - FILE_BASE
            codes = []
            while data[bl + len(codes)] != 0xFF:
                codes.append(data[bl + len(codes)])
            parts.append([(fw(lst + 4 * k) - FILE_BASE, c) for k, c in enumerate(codes)])
        strings = [o for part in parts for o, _ in part]
        total += len(strings)
        choices = sum(any(c in (3, 8) for _, c in part) for part in parts)
        replies = sum(any(c == 2 for _, c in part) for part in parts)
        info = by_slot.get(s)
        if info:
            what = f"place {info['place']} {info['name']}"
            even = [v for v in info["ppv"] if len(parts) % v == 0]
            if info["load"] is None:
                force = "no version byte: branches on choices"
            else:
                if even:
                    versions = f"{len(parts) // even[0]} versions of {even[0]} parts"
                elif info["ppv"]:
                    versions = f"{info['ppv'][0]} parts per version, irregular tail"
                else:
                    versions = "parts per version not set by the setup"
                force = f"{versions}; --set-at {info['load']:#x} 0x800CA2FC N"
        else:
            what, force = SHARED.get(s, "?"), "shared; see game-internals §6k"
        print(f"section {s:2}  {what:28} {min(strings):#07x}-{max(strings):#07x}  "
              f"{len(strings):3} strings  {len(parts):2} parts  {choices:2} choices  "
              f"{replies:2} replies  {force}")
        if args.strings:
            for p, part in enumerate(parts):
                print(f"    part {p:2}: " + "  ".join(f"{o:#06x}:{CODES.get(c, hex(c))}" for o, c in part))
    print(f"{total} strings in {SECTIONS} sections")


if __name__ == "__main__":
    main()
