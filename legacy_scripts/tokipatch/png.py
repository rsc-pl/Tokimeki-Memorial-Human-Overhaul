"""Minimal reader/writer for 8-bit indexed PNGs (stdlib only).

Graphics are stored as indexed PNGs whose palette is the game's own CLUT, so
pixel values map 1:1 to the palette indices the game uses. Any editor that
preserves indices (Aseprite, GIMP in Indexed mode, Pro Motion) can edit them.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import List, Tuple

_SIG = b"\x89PNG\r\n\x1a\n"


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


def write_indexed(path: Path, width: int, height: int, pixels: bytes,
                  palette: List[Tuple[int, int, int]]) -> None:
    raw = b"".join(b"\0" + pixels[y * width:(y + 1) * width] for y in range(height))
    plte = b"".join(bytes(c) for c in palette)
    Path(path).write_bytes(
        _SIG
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 3, 0, 0, 0))
        + _chunk(b"PLTE", plte)
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b""))


def read_indexed(path: Path) -> Tuple[int, int, bytes]:
    """Return (width, height, one palette index per pixel)."""
    data = Path(path).read_bytes()
    if not data.startswith(_SIG):
        raise ValueError(f"{path}: not a PNG")
    pos, idat, header = 8, b"", None
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
    width, height, depth, color_type, _, _, interlace = header
    if (depth, color_type, interlace) != (8, 3, 0):
        raise ValueError(f"{path}: must be an 8-bit indexed (palette) PNG, non-interlaced")

    raw = zlib.decompress(idat)
    out = bytearray()
    prev = bytearray(width)
    for y in range(height):
        f = raw[y * (width + 1)]
        line = bytearray(raw[y * (width + 1) + 1:(y + 1) * (width + 1)])
        for x in range(width):
            a = line[x - 1] if x else 0
            b = prev[x]
            c = prev[x - 1] if x else 0
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + b) & 255
            elif f == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        out += line
        prev = line
    return width, height, bytes(out)
