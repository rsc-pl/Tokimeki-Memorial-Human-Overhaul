"""Log every file the game loads, via a breakpoint on its CD read routine.

Usage:  python tools/emu/trace_reads.py path/to/game.cue SECONDS

Start the game in the isolated DuckStation first. This connects to the GDB
stub, breaks on 0x80046318 (a0=sector count, a1=RAM buffer, a2=LBA) and prints
which disc file each read hits, until SECONDS have passed. The game runs slower
while being traced.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from gdbstub import Gdb  # noqa: E402
from tokipatch.__main__ import parse_cue  # noqa: E402
from tokipatch.cd import Track  # noqa: E402
from tokipatch.iso9660 import list_files  # noqa: E402

CD_READ = 0x80046318


def main() -> None:
    cue, seconds = Path(sys.argv[1]), float(sys.argv[2])
    _, data_name = parse_cue(cue)
    with Track(cue.parent / Path(data_name).name) as track:
        files = sorted((e for e in list_files(track).values() if not e.is_dir), key=lambda e: e.lba)

    def name(lba: int) -> str:
        for e in files:
            if e.lba <= lba < e.lba + max(1, (e.size + 2047) // 2048):
                return f"{e.path}+{lba - e.lba}"
        return "?"

    g = Gdb()
    g.break_at(CD_READ)
    t0 = time.time()
    try:
        while (left := seconds - (time.time() - t0)) > 0:
            try:
                g.cont(timeout=left)
            except socket.timeout:
                g.interrupt()
                break
            r = g.regs()
            print(f"{time.time() - t0:6.1f}s  lba={r['a2']:6d}  sectors={r['a0']:3d}  "
                  f"buf={r['a1']:08x}  {name(r['a2'])}  (ra={r['ra']:08x})", flush=True)
    finally:
        g.clear_break(CD_READ)
        g.detach()


if __name__ == "__main__":
    main()
