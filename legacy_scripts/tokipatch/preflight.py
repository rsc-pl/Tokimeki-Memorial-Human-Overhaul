"""Read-only proof that all translation edits can be planned against a disc.

No output directory, sectors or other game files are modified. This invokes
exactly the validation/packing path that normal builds use before copying.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from . import patcher
from .__main__ import parse_cue, TRANSLATION_DIR
from .cd import Track

def main():
    ap=argparse.ArgumentParser(description="Validate patch against original game without writing")
    ap.add_argument("input",type=Path)
    ap.add_argument("-t","--translation",type=Path,action="append")
    args=ap.parse_args()
    source=args.input.resolve()
    if not source.is_file(): ap.error("input does not exist")
    if source.suffix.lower()==".cue":
        files,data=parse_cue(source)
        if data is None: ap.error("MODE2/2352 track missing")
        source=source.parent / data
    trans=args.translation or sorted(TRANSLATION_DIR.glob("*.json"))
    strings,images,byte_patches,dialogue=patcher.load_translations(trans)
    print(f"Read-only preflight: {len(trans)} translation files, {sum(len(d.lines) for d in dialogue)} dialogue lines",flush=True)
    try:
        with Track(source) as track:
            edits=patcher.plan(track,strings,images,byte_patches,dialogue,log=print)
    except (ValueError, OSError) as exc:
        print(f"FAIL: preflight rejected source image: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {len(edits)} disc files can be patched; source untouched")
    return 0

if __name__=="__main__": sys.exit(main())
