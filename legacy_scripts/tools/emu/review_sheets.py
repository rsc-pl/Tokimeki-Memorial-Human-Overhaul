"""Put a run's contact sheets side by side for review: two 15-box columns per image.

Usage:  python tools/emu/review_sheets.py PREFIX [PREFIX ...]

Reads .emu/shots/<PREFIX>_sheet*.png (xmas_run.ps1) or <PREFIX>_sheet.png
(date_run.ps1, cut into 15-box columns) and writes
.emu/shots/R_<PREFIX>_0.png, _1.png, ...: 30 boxes per image, which is
what one review step can read at once. Prints the files written.
"""

from __future__ import annotations

import glob
import sys
from pathlib import Path

from PIL import Image

SHOTS = Path(__file__).resolve().parents[3] / ".emu" / "shots"
COLUMN = 2550          # 15 boxes of 170 px, contact_sheet.py's layout


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for prefix in sys.argv[1:]:
        cols = []
        for s in sorted(glob.glob(str(SHOTS / f"{prefix}_sheet*.png"))):
            im = Image.open(s)
            for y in range(0, im.height, COLUMN):
                cols.append(im.crop((0, y, im.width, min(im.height, y + COLUMN))))
        for i in range(0, len(cols), 2):
            grp = cols[i:i + 2]
            out = Image.new("RGB", (sum(c.width for c in grp), max(c.height for c in grp)))
            x = 0
            for c in grp:
                out.paste(c, (x, 0))
                x += c.width
            path = SHOTS / f"R_{prefix}_{i // 2}.png"
            out.save(path)
            print(path)


if __name__ == "__main__":
    main()
