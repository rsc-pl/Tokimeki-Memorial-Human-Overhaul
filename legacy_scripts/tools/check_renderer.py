"""Run the renderer hook in a tiny MIPS interpreter and check its glyphs.

Usage:  python tools/check_renderer.py

Assembles the hook (tokipatch/renderer.py), then for every pair of supported
characters runs it from the hook site the way layout_string would, and checks
that it:
  - calls render_glyph with an index whose glyph address is the scratch glyph,
  - leaves the scratch glyph byte-identical to pairfont.render_pair(),
  - returns to the layout loop with v0 = s1;
and that a Japanese code goes back to the game's own lookup unchanged.

Run it after any change to the hook source or the narrow font. It only
models the instructions the hook uses (and the R3000 load delay slot); it
doesn't replace a check in the emulator.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tokipatch import pairfont, renderer  # noqa: E402


class Cpu:
    def __init__(self, mem: dict):
        self.mem = mem
        self.r = [0] * 32

    def read(self, addr: int, n: int) -> int:
        return int.from_bytes(bytes(self.mem.get(addr + i, 0) for i in range(n)), "little")

    def run(self, pc: int, stops, calls, limit: int = 5000) -> int:
        """Execute from pc until it reaches an address in `stops`.

        A jal to an address in `calls` (a dict addr -> list) records a0 and
        returns immediately, as if the callee did nothing."""
        r, npc, pending = self.r, pc + 4, None
        for _ in range(limit):
            w = self.read(pc, 4)
            op, rs, rt, rd = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
            sa, fn, imm = (w >> 6) & 31, w & 63, w & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            target, load = None, None
            if op == 0 and fn == 0x00:
                r[rd] = (r[rt] << sa) & 0xFFFFFFFF
            elif op == 0 and fn == 0x02:
                r[rd] = r[rt] >> sa
            elif op == 0 and fn == 0x21:
                r[rd] = (r[rs] + r[rt]) & 0xFFFFFFFF
            elif op == 0 and fn == 0x25:
                r[rd] = r[rs] | r[rt]
            elif op == 0x09:
                r[rt] = (r[rs] + simm) & 0xFFFFFFFF
            elif op == 0x0B:
                r[rt] = int(r[rs] < (simm & 0xFFFFFFFF))
            elif op == 0x0C:
                r[rt] = r[rs] & imm
            elif op == 0x0F:
                r[rt] = imm << 16
            elif op in (0x23, 0x25):
                load = (rt, self.read((r[rs] + simm) & 0xFFFFFFFF, 4 if op == 0x23 else 2))
            elif op == 0x28:
                self.mem[(r[rs] + simm) & 0xFFFFFFFF] = r[rt] & 0xFF
            elif op in (0x04, 0x05):
                if (r[rs] == r[rt]) == (op == 0x04):
                    target = (npc + (simm << 2)) & 0xFFFFFFFF
            elif op in (0x02, 0x03):
                target = (npc & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
                if op == 0x03:
                    r[31] = npc + 4
            else:
                raise NotImplementedError(f"{pc:08x}: {w:08x}")
            r[0] = 0
            if pending:                  # a load lands one instruction late
                r[pending[0]] = pending[1]
            pending = load
            pc, npc = npc, target if target is not None else npc + 4
            if pc in calls:
                calls[pc].append(r[4])
                pc, npc = r[31], r[31] + 4
            if pc in stops:
                if pending:
                    r[pending[0]] = pending[1]
                return pc
        raise RuntimeError("hook didn't finish")


def main() -> int:
    site, code, scratch = renderer.build()
    mem = {}
    for addr, data in ((renderer.HOOK_SITE, site), (renderer.CODE_ADDR, code),
                       (renderer.NARROW_ADDR, renderer.narrow_font())):
        mem.update((addr + i, b) for i, b in enumerate(data))
    stops = (renderer.HOOK_RESUME, renderer.LAYOUT_LOOP)

    cpu = Cpu(mem)
    cpu.r[3] = 0x889F                       # v1 = 亜, the first kanji
    calls = {renderer.RENDER_GLYPH: []}
    assert cpu.run(renderer.HOOK_SITE, stops, calls) == renderer.HOOK_RESUME
    assert cpu.r[8] == 0x889F and not calls[renderer.RENDER_GLYPH], "Japanese path changed"

    chars = [chr(c) for c in range(0x20, 0x7F) if pairfont.supported(chr(c))]
    for a, b in itertools.product(chars, chars):
        cpu = Cpu(mem)
        cpu.r[3] = renderer.encode_char(a) << 8 | renderer.encode_char(b)
        cpu.r[17] = 0x1234                  # s1, the string pointer
        calls = {renderer.RENDER_GLYPH: []}
        assert cpu.run(renderer.HOOK_SITE, stops, calls) == renderer.LAYOUT_LOOP
        (index,) = calls[renderer.RENDER_GLYPH]
        assert (renderer.FONT_ADDR + index * renderer.GLYPH_BYTES) & 0xFFFFFFFF == scratch
        glyph = bytes(mem.get(scratch + i, 0) for i in range(renderer.GLYPH_BYTES))
        assert glyph == pairfont.render_pair(a + b), f"pair {a + b!r}"
        assert cpu.r[2] == 0x1234, "v0 != s1 on exit"
    print(f"ok: {len(chars) ** 2} pairs, {len(code)} bytes of hook code, scratch glyph {scratch:#010x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
