"""Copy a byte range of a disc file into the running game's RAM (GDB stub).

Usage:
  python tools/emu/poke_file.py FILE BASE START END

FILE is a local copy of a disc file (e.g. extracted/CDROM/EXEDIR/NAME_ENT.EXN
for the original, or a file read from a patched build), BASE its load address
(0x80132000 for overlays). Bytes [START, END) of the file are written to
BASE + START.

Use it with a save state (testing.md, "Save states") to swap text in an
already-loaded file without replaying the game: e.g. restore the original
Japanese strings for an unpatched comparison at the exact same point, or
load newly patched strings without rebooting. The checksum isn't involved:
the game only verifies a file right after reading it from the disc.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gdbstub import Gdb  # noqa: E402


def main() -> None:
    path, base, start, end = sys.argv[1], *(int(a, 0) for a in sys.argv[2:5])
    data = Path(path).read_bytes()[start:end]
    g = Gdb()
    for off in range(0, len(data), 0x200):
        chunk = data[off:off + 0x200]
        reply = g.cmd(f"M{base + start + off:x},{len(chunk):x}:{chunk.hex()}")
        if reply != "OK":
            raise RuntimeError(f"write failed at {base + start + off:#x}: {reply}")
    if g.mem(base + start, len(data)) != data:
        raise RuntimeError("read-back mismatch")
    g.detach()
    print(f"wrote {len(data)} bytes to {base + start:#x}")


if __name__ == "__main__":
    main()
