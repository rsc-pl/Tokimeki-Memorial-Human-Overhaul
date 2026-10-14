"""Renderer hook: draws English letter pairs on the fly.

The game's text path (docs/game-internals.md §6a) is add_text ->
layout_string (0x8004F268) -> render_glyph(index) (0x8004F364), which expands
the 18-byte 12x12 1bpp glyph at FONT + index*18 into a VRAM glyph-cache slot.
layout_string reads 2 bytes per character and is the only code that reads the
font, so one hook there covers every screen.

English is encoded 1 byte per letter: ASCII with the top bit set (0x20-0x7E
-> 0xA0-0xFE). Every 2-byte code is then 0xA0A0-0xFEFE. No Japanese text uses
a lead byte >= 0xA0 (the font stops at 0x9872), and no byte >= 0x80 is a
dialogue control code, so these codes are free.

The hook (patched over 0x8004F2CC in layout_string, just after the code is
read) sends codes below 0xA000 back to the game's own lookup. For the others
it composes the pair into a scratch glyph from a 5x12 font (letter 1 in
columns 0-4, letter 2 in columns 7-11, as tokipatch/pairfont.py draws them)
and calls render_glyph with the index that points at the scratch glyph.

Code and data go into two functions of the EXE that nothing calls (no jal,
j, or pointer to them in the EXE, any overlay, or any file on the disc; and
an execution breakpoint never fired while playing; game-internals §6f):
  0x8004443C (708 bytes):  the hook, then the scratch glyph
  0x8004B778 (948 bytes):  the 5x12 font, 96 characters x 8 bytes
"""

from __future__ import annotations

import struct
import zlib
from typing import List

from . import mips, pairfont

EXE_RAM_BASE = 0x80040800
FONT_ADDR = 0x800B6D50              # the game font (font.FONT_ADDR)
GLYPH_BYTES = 18

LAYOUT_LOOP = 0x8004F294            # layout_string: top of the per-character loop
HOOK_SITE = 0x8004F2CC              # layout_string: first instruction after the code is read
HOOK_RESUME = 0x8004F2D8            # layout_string: `sltu at, t0, t1` (code < first range?)
RENDER_GLYPH = 0x8004F364
# What's at HOOK_SITE in the original:  lui t1, 0x800b ; lhu t1, 0x402c(t1)
HOOK_SITE_ORIGINAL = bytes.fromhex("0b80093c2c402995")

CODE_ADDR, CODE_SIZE, CODE_CRC32 = 0x8004443C, 708, 0x95CF8D48
NARROW_ADDR, NARROW_SIZE, NARROW_CRC32 = 0x8004B778, 948, 0xC57F80EA

FIRST_CHAR = 0x20                   # narrow font covers ASCII 0x20-0x7F
CHAR_COUNT = 96
ENTRY_BYTES = 8                     # 12 rows x 5 bits, as two little-endian words


def encode_char(ch: str) -> int:
    """The byte for one English character."""
    return ord(ch) | 0x80


def narrow_font() -> bytes:
    """The 5x12 font table: per character, rows 0-5 then rows 6-11, each row
    5 bits (bit 4 = leftmost pixel) at bit 5*r of its word."""
    out = bytearray()
    for code in range(FIRST_CHAR, FIRST_CHAR + CHAR_COUNT):
        ch = chr(code)
        rows = pairfont.letter_rows(ch) if pairfont.supported(ch) else [0] * 12
        words = [0, 0]
        for y, bits in enumerate(rows):
            words[y // 6] |= bits << (5 * (y % 6))
        out += struct.pack("<II", *words)
    return bytes(out)


HOOK_SOURCE = """
hook:                           ; t0 = character code (from the delay slot at HOOK_SITE)
    srl   t2, t0, 8
    sltiu at, t2, 0xA0
    beqz  at, pair
    nop
    lui   t1, 0x800b            ; not a pair: the two instructions we replaced,
    lhu   t1, 0x402c(t1)        ; then back into the game's range lookup
    j     HOOK_RESUME
    nop                         ; (load delay for t1)
pair:
    addiu a1, t2, -0xA0         ; left character index
    andi  a2, t0, 0xFF
    addiu a2, a2, -0xA0         ; right character index
    lui   t9, %hi(NARROW)
    addiu t9, t9, %lo(NARROW)
    sll   a1, a1, 3
    addu  a1, a1, t9
    sll   a2, a2, 3
    addu  a2, a2, t9
    lui   t8, %hi(SCRATCH)
    addiu t8, t8, %lo(SCRATCH)
    addiu t7, zero, 2           ; two words per character
half:
    lw    t3, 0(a1)
    lw    t4, 0(a2)
    addiu t6, zero, 3           ; three row pairs per word
rows:
    andi  t1, t3, 31            ; row A = left << 7 | right
    sll   t1, t1, 7
    andi  t2, t4, 31
    or    t1, t1, t2
    srl   t3, t3, 5
    srl   t4, t4, 5
    andi  t2, t3, 31            ; row B
    sll   t2, t2, 7
    andi  t5, t4, 31
    or    t2, t2, t5
    srl   t3, t3, 5
    srl   t4, t4, 5
    sll   t1, t1, 12            ; two 12-bit rows -> 3 bytes, MSB first
    or    t1, t1, t2
    srl   t2, t1, 16
    sb    t2, 0(t8)
    srl   t2, t1, 8
    sb    t2, 1(t8)
    sb    t1, 2(t8)
    addiu t6, t6, -1
    bnez  t6, rows
    addiu t8, t8, 3
    addiu a1, a1, 4
    addiu t7, t7, -1
    bnez  t7, half
    addiu a2, a2, 4
    lui   a0, %hi(SCRATCH_INDEX)
    jal   RENDER_GLYPH
    addiu a0, a0, %lo(SCRATCH_INDEX)
    j     LAYOUT_LOOP           ; same exit as the game's own glyph path
    move  v0, s1
"""


def _scratch_after(code_end: int) -> int:
    """First address >= code_end that is a whole number of glyphs from FONT_ADDR."""
    addr = code_end
    while (addr - FONT_ADDR) % GLYPH_BYTES:
        addr += 1
    return addr


def build():
    """Return (hook_site_bytes, code_bytes, scratch_address)."""
    symbols = {"HOOK_RESUME": HOOK_RESUME, "LAYOUT_LOOP": LAYOUT_LOOP,
               "RENDER_GLYPH": RENDER_GLYPH, "NARROW": NARROW_ADDR,
               "SCRATCH": 0, "SCRATCH_INDEX": 0}
    size = len(mips.assemble(HOOK_SOURCE, CODE_ADDR, symbols))
    scratch = _scratch_after(CODE_ADDR + size)
    # A negative index is fine: render_glyph computes FONT + index*18 in
    # 32-bit arithmetic, so it lands on the scratch glyph.
    symbols["SCRATCH"] = scratch
    symbols["SCRATCH_INDEX"] = ((scratch - FONT_ADDR) // GLYPH_BYTES) & 0xFFFFFFFF
    code = mips.assemble(HOOK_SOURCE, CODE_ADDR, symbols)
    site = mips.assemble("""
        j     hook
        andi  t0, v1, 0xffff        ; the code, as the game computes it at 0x8004F2D4
    """, HOOK_SITE, {"hook": CODE_ADDR})
    if scratch + GLYPH_BYTES > CODE_ADDR + CODE_SIZE:
        raise AssertionError("renderer hook doesn't fit")
    return site, code, scratch


def _region(exe: bytearray, addr: int, size: int) -> slice:
    start = addr - EXE_RAM_BASE
    return slice(start, start + size)


def install(exe: bytearray) -> List[str]:
    """Patch the hook into SLPM_86.053. Returns log lines."""
    site_at = _region(exe, HOOK_SITE, len(HOOK_SITE_ORIGINAL))
    code_at = _region(exe, CODE_ADDR, CODE_SIZE)
    narrow_at = _region(exe, NARROW_ADDR, NARROW_SIZE)
    checks = [("layout_string hook site", bytes(exe[site_at]) == HOOK_SITE_ORIGINAL),
              ("unused function at 0x8004443C", zlib.crc32(exe[code_at]) == CODE_CRC32),
              ("unused function at 0x8004B778", zlib.crc32(exe[narrow_at]) == NARROW_CRC32)]
    for name, ok in checks:
        if not ok:
            raise ValueError(f"SLPM_86.053: {name} doesn't hold the expected original code; "
                             "is this the PlayStation the Best (SLPM-86053) executable?")
    site, code, scratch = build()
    narrow = narrow_font()
    exe[site_at] = site
    exe[code_at] = code.ljust(CODE_SIZE, b"\0")
    exe[narrow_at] = narrow.ljust(NARROW_SIZE, b"\0")
    return [f"renderer hook: layout_string {HOOK_SITE:#010x} -> {CODE_ADDR:#010x} "
            f"({len(code)} bytes of code, scratch glyph {scratch:#010x}), "
            f"5x12 font at {NARROW_ADDR:#010x} ({len(narrow)} bytes)"]
