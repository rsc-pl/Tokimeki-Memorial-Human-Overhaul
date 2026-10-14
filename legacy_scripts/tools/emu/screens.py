"""Recognise known game screens in a DuckStation screenshot (stdlib only).

Usage:  python tools/emu/screens.py NAME screenshot.png
Exit code 0 if the screenshot shows screen NAME, 1 otherwise. drive.ps1's
`until:NAME:ms` step uses this to wait for a screen without fixed delays.

Detectors are deliberately simple colour statistics, tuned on real
screenshots. Add new ones to DETECTORS as you need them.
"""

from __future__ import annotations

import struct
import sys
import zlib


def read_rgb(path):
    """Decode an 8-bit RGB/RGBA PNG. Returns (width, height, bytes per pixel, rows)."""
    data = open(path, "rb").read()
    pos, idat = 8, b""
    while pos < len(data):
        n, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        pos += 12 + n
        if kind == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
        elif kind == b"IDAT":
            idat += body
    bpp = {2: 3, 6: 4}[ctype]
    raw = zlib.decompress(idat)
    stride = w * bpp
    rows, prev, p = [], bytearray(stride), 0
    for _ in range(h):
        f = raw[p]
        line = bytearray(raw[p + 1:p + 1 + stride])
        p += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + b) & 255
            elif f == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line)
        prev = line
    return w, h, bpp, rows


def colour_stats(path):
    """Fractions of near-white and logo-pink pixels in the central area."""
    w, h, bpp, rows = read_rgb(path)
    white = pink = n = 0
    for y in range(0, h, 8):
        row = rows[y]
        for x in range(w // 6, w * 5 // 6, 8):
            r, g, b = row[x * bpp], row[x * bpp + 1], row[x * bpp + 2]
            n += 1
            white += r > 230 and g > 230 and b > 230
            pink += r > 200 and g < 120 and b > 120
    return white / n, pink / n


def is_title(path) -> bool:
    # White background with the pink メモリアル logo. The blank white fade
    # before it has no pink, and the intro scenes aren't mostly white.
    white, pink = colour_stats(path)
    return white > 0.5 and pink > 0.01


DETECTORS = {"title": is_title}

if __name__ == "__main__":
    name, path = sys.argv[1], sys.argv[2]
    sys.exit(0 if DETECTORS[name](path) else 1)
