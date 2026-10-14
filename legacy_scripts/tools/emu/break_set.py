"""Break at code addresses and change registers or memory there (testing aid).

Usage:
  python tools/emu/break_set.py [--lba 37418] [--timeout S]
      --at PC [--times N] [--reg R=V] [--mem8 ADDR=V] [--mem16 ADDR=V] [--sp16 OFF=V]
      [--pc NEWPC] [--at PC ...]

Each --at starts a rule; the options after it belong to that rule. All
breakpoints are armed at once; a rule fires when its PC is hit while the
overlay with LBA --lba is loaded (default DATE.EXN 37418; the loaded
overlay's LBA is at 0x800B6D40), --times N times (default 1; 0 = every hit
until the timeout), then its breakpoint is removed. Use --times 0 for code
that recomputes the value every frame. Actions run in the order given. The
tool exits when every rule is done or after --timeout seconds.

Examples (Shiori's dates, game-internals §6k):
  meeting, she's on time, best mood:  --at 0x80132570 --reg v0=0 --mem8 0x8015B654=1
  ending part 7 (recomputed per frame): --at 0x8013B6F8 --times 0 --sp16 0x3a=7
  going home, band 3:                 --at 0x8013B810 --mem16 0x8015BF14=3
  small talk part 0 on any day:       --at 0x8013B0D4 --mem16 0x8015BF0C=0 --pc 0x8013B0E4

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

LOADED_LBA = 0x800B6D40


def parse(argv):
    lba, timeout, rules = 37418, 400.0, []
    it = iter(argv)
    for arg in it:
        if arg in ("-h", "--help"):
            sys.exit(__doc__)
        value = next(it, None)
        if value is None:
            sys.exit(f"{arg} needs a value\n{__doc__}")
        if arg == "--lba":
            lba = int(value, 0)
        elif arg == "--timeout":
            timeout = float(value)
        elif arg == "--at":
            rules.append({"pc": int(value, 0), "actions": [], "times": 1, "hits": 0})
        elif arg == "--times":
            if not rules:
                sys.exit(f"{arg} must follow --at")
            rules[-1]["times"] = int(value, 0)
        elif arg in ("--reg", "--mem8", "--mem16", "--sp16", "--pc"):
            if not rules:
                sys.exit(f"{arg} must follow --at")
            if arg == "--pc":
                rules[-1]["actions"].append(("pc", None, int(value, 0)))
            else:
                key, val = value.split("=")
                if arg == "--reg" and key not in REG_NAMES:
                    sys.exit(f"unknown register {key}")
                target = key if arg == "--reg" else int(key, 0)
                rules[-1]["actions"].append((arg[2:], target, int(val, 0)))
        else:
            sys.exit(f"unknown option {arg}\n{__doc__}")
    if not rules:
        sys.exit(__doc__)
    return lba, timeout, rules


def apply(g: Gdb, rule) -> str:
    done = []
    regs = None
    for kind, target, value in rule["actions"]:
        if kind == "reg":
            g.cmd(f"P{REG_NAMES.index(target):x}=" + struct.pack("<I", value & 0xFFFFFFFF).hex())
            done.append(f"{target}={value:#x}")
        elif kind in ("mem8", "mem16"):
            size = 1 if kind == "mem8" else 2
            g.cmd(f"M{target:x},{size}:" + value.to_bytes(size, "little").hex())
            done.append(f"[{target:#x}]={value:#x}")
        elif kind == "sp16":
            regs = regs or g.regs()
            addr = regs["sp"] + target
            g.cmd(f"M{addr:x},2:" + value.to_bytes(2, "little").hex())
            done.append(f"[sp+{target:#x}]={value:#x}")
        elif kind == "pc":
            g.cmd(f"P{REG_NAMES.index('pc'):x}=" + struct.pack("<I", value).hex())
            done.append(f"pc={value:#x}")
    return ", ".join(done)


def run(g: Gdb, rules, lba: int = 37418, timeout: float = 400.0) -> None:
    """Arm every rule's breakpoint, apply each as asked, then detach."""
    pending = {r["pc"]: r for r in rules}
    for pc in pending:
        g.break_at(pc)
    t0 = time.time()
    try:
        while pending and (left := timeout - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                break
            pc = g.regs()["pc"]
            if pc not in pending or struct.unpack("<I", g.mem(LOADED_LBA, 4))[0] != lba:
                continue
            rule = pending[pc]
            rule["hits"] += 1
            done = apply(g, rule)
            if rule["hits"] <= 3 or rule["hits"] % 100 == 0:
                print(f"{time.time() - t0:6.1f}s at {pc:#x} (hit {rule['hits']}): {done}", flush=True)
            if rule["times"] and rule["hits"] >= rule["times"]:
                del pending[pc]
                g.clear_break(pc)
        for pc, rule in pending.items():
            if rule["times"] and rule["hits"] < rule["times"]:
                print(f"not hit {rule['times'] - rule['hits']} more time(s): {pc:#x}", flush=True)
    finally:
        for pc in pending:
            g.clear_break(pc)
        g.detach()


def main() -> None:
    lba, timeout, rules = parse(sys.argv[1:])
    run(Gdb(), rules, lba, timeout)


if __name__ == "__main__":
    main()
