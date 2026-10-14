"""The game font (in SLPM_86.053) and the English letter-pair encoding.

Facts (docs/game-internals.md, "Font"):
  - Font: 3418 glyphs of 12x12 1bpp, 18 bytes each, at RAM 0x800B6D50.
  - Codes map to glyphs via a range table at RAM 0x800B402C: (first code,
    first glyph index) u16 pairs. Codes below 0x8140 are rejected, which is
    why plain ASCII doesn't display.
  - The renderer reads 2 bytes per character and draws glyphs 14 px apart.

English is encoded as letter pairs, 1 byte per letter: ASCII with the top
bit set, so each 2-byte code holds two letters (0xA0A0-0xFEFE). The renderer
hook (tokipatch/renderer.py) composes the glyph for such a code on the fly
from a narrow 5x12 font (tokipatch/pairfont.py). Every pair is available, so
there's no glyph pool to run out of.
"""

from __future__ import annotations

import struct
import zlib

from . import pairfont, renderer

EXE = "SLPM_86.053"
EXE_RAM_BASE = 0x80040800            # RAM address = file offset + this
FONT_ADDR = 0x800B6D50
GLYPH_BYTES = 18
GLYPH_COUNT = 3418
RANGE_TABLE_ADDR, RANGE_TABLE_END = 0x800B402C, 0x800B40E4
RANGE_TABLE_CRC32 = 0x3CC19FF3       # guards against a different executable
BLANK_CODE = 0x8140                  # ideographic space: an existing blank glyph


def _ranges(exe: bytes):
    start = RANGE_TABLE_ADDR - EXE_RAM_BASE
    table = exe[start:RANGE_TABLE_END - EXE_RAM_BASE]
    if zlib.crc32(table) != RANGE_TABLE_CRC32:
        raise ValueError(f"{EXE}: font range table isn't where expected; "
                         "is this the PlayStation the Best (SLPM-86053) executable?")
    return [struct.unpack_from("<HH", table, o) for o in range(0, len(table), 4)]


def glyph_index(exe: bytes, code: int) -> int:
    """Map a Shift-JIS code to its glyph index, exactly like the game does."""
    index = None
    for first, base in _ranges(exe):
        if code >= first:
            index = base + (code - first)
    if index is None or not 0 <= index < GLYPH_COUNT:
        raise ValueError(f"code {code:#06x} has no glyph in the game font")
    return index


def glyph_offset(exe: bytes, code: int) -> int:
    """File offset in SLPM_86.053 of a code's 18-byte glyph."""
    return FONT_ADDR - EXE_RAM_BASE + glyph_index(exe, code) * GLYPH_BYTES


class PairEncoder:
    """Encodes English text as letter-pair codes for the renderer hook."""

    def __init__(self):
        self.used = False   # whether any text needs the renderer hook

    def encode(self, text: str) -> bytes:
        for ch in text:
            if not pairfont.supported(ch):
                raise ValueError(f"{text!r}: character {ch!r} isn't in the English pair font")
        if len(text) % 2:
            text += " "
        out = bytearray()
        for i in range(0, len(text), 2):
            out += self.code_for(text[i:i + 2]).to_bytes(2, "big")
        return bytes(out)

    def code_for(self, pair: str) -> int:
        if pair == "  ":
            # The font's own blank. Icons the game draws over blank cells
            # (the ○/× on Yes/No lines) were lined up with this glyph.
            return BLANK_CODE
        self.used = True
        return renderer.encode_char(pair[0]) << 8 | renderer.encode_char(pair[1])
