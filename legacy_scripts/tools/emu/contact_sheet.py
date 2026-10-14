"""Stack the dialogue box of several screenshots into one image.

Usage (needs Pillow):  python tools/emu/contact_sheet.py OUT.png NAME [NAME ...]

NAME is a screenshot in .emu/shots/ without ".png". Each box is cropped,
scaled to 700x170 and labelled, so a whole scene can be reviewed in one
image. Keep OUT outside the repo or under .emu/ (screenshots are game data).
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw

SHOTS = Path(__file__).resolve().parents[3] / ".emu" / "shots"


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out, names = sys.argv[1], sys.argv[2:]
    crops = []
    for name in names:
        path = SHOTS / f"{name}.png"
        if not path.exists():
            print(f"missing {path}", file=sys.stderr)
            continue
        im = Image.open(path).convert("RGB")
        w, h = im.size
        box = im.crop((int(w * 0.08), int(h * 0.68), int(w * 0.92), int(h * 0.97))).resize((700, 170))
        draw = ImageDraw.Draw(box)
        draw.rectangle((0, 0, 7 * len(name) + 4, 14), fill=(0, 0, 0))
        draw.text((2, 1), name, fill=(255, 255, 0))
        crops.append(box)
    sheet = Image.new("RGB", (700, 170 * max(1, len(crops))))
    for i, box in enumerate(crops):
        sheet.paste(box, (0, 170 * i))
    sheet.save(out)


if __name__ == "__main__":
    main()
