"""Compare existing indexed images and synthetic bitmap edits with the Go tool."""
import hashlib
import json
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace

from tokipatch import png, patcher


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    out = []
    for probe in json.load(sys.stdin):
        path = Path(probe['png'])
        w, h, pixels = png.read_indexed(path)
        bpp, stride = probe['bpp'], probe['stride']
        size = stride * (probe['y'] + h + 2)
        data = bytearray((i * 73 + probe['seed'] * 19 + 31) & 255 for i in range(size))
        before = bytearray()
        for rx, ry, rw, rh in probe['rects']:
            for row in range(ry, ry + rh):
                for col in range(rx, rx + rw):
                    x, y = probe['x'] + col, probe['y'] + row
                    offset = y * stride + (x if bpp == 8 else x // 2)
                    before.append(data[offset] if bpp == 8 else (data[offset] >> (4 * (x & 1))) & 15)
        p = SimpleNamespace(file='SYNTHETIC', png=path, pixels=0, stride=stride,
                            x=probe['x'], y=probe['y'], rects=probe['rects'],
                            bpp=bpp, original_crc32=zlib.crc32(before), source='graphics-check')
        edit = SimpleNamespace(data=data, log=[])
        patcher.apply_image(p, edit)
        out.append({'width': w, 'height': h, 'pixels_sha256': sha(pixels),
                    'output_sha256': sha(data)})
    json.dump(out, sys.stdout)


if __name__ == '__main__':
    main()
