"""Command-line entry point:  python -m tokipatch <game.cue> [-o OUTPUT_DIR]"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from . import patcher
from .cd import Track

TRANSLATION_DIR = Path(__file__).resolve().parents[2] / "translation"


def parse_cue(cue: Path) -> Tuple[List[str], Optional[str]]:
    """Return (all FILE names in the cue, the FILE holding the MODE2/2352 track)."""
    files: List[str] = []
    data_file = None
    for line in cue.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r'\s*FILE\s+"(.+)"\s+\w+', line) or re.match(r"\s*FILE\s+(\S+)\s+\w+", line)
        if m:
            files.append(m.group(1))
        elif re.match(r"\s*TRACK\s+\d+\s+MODE2/2352", line, re.I) and data_file is None:
            data_file = files[-1] if files else None
    return files, data_file


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="tokipatch",
        description="Apply the English translation to Tokimeki Memorial: Forever with You (PS1).")
    ap.add_argument("input", type=Path, help="the game's .cue file (or its Track 1 .bin)")
    ap.add_argument("-o", "--output", type=Path,
                    help="folder for the patched game (default: '<input folder> [English]' next to it)")
    ap.add_argument("-t", "--translation", type=Path, action="append",
                    help="translation JSON file(s) to apply (default: everything in translation/)")
    ap.add_argument("-f", "--force", action="store_true", help="overwrite an existing output folder")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every patched string, not just a summary per file")
    ap.add_argument("--all-errors", action="store_true",
                    help="report all independent patch planning errors before aborting (no output is written)")
    args = ap.parse_args(argv)
    # The log contains Japanese and English; a console or file that can't show
    # a character must not stop the patcher halfway through writing the copy.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

    src: Path = args.input.resolve()
    if not src.is_file():
        ap.error(f"{src} not found")

    if src.suffix.lower() == ".cue":
        cue_files, data_name = parse_cue(src)
        if data_name is None:
            ap.error("no MODE2/2352 data track in the .cue")
        to_copy = [src] + [src.parent / name for name in cue_files]
        data_name = Path(data_name).name
    else:
        to_copy = [src]
        data_name = src.name

    out: Path = (args.output or src.parent.with_name(src.parent.name + " [English]")).resolve()
    if out == src.parent:
        ap.error("output folder must differ from the input folder")
    if out.exists() and any(out.iterdir()) and not args.force:
        ap.error(f"{out} already exists and isn't empty (use --force to overwrite)")

    started = time.monotonic()
    translations = args.translation or sorted(TRANSLATION_DIR.glob("*.json"))
    progress = Progress()
    try:
        strings, images, byte_patches, dialogue = patcher.load_translations(translations)
        print(f"Loaded {len(strings)} string(s), "
              f"{sum(len(d.lines) for d in dialogue)} dialogue line(s), {len(images)} image(s) "
              f"and {len(byte_patches)} byte patch(es) from {len(translations)} translation file(s).")
        print("Step 1/3: checking the translation against your disc (nothing is written yet)")
        data_src = next(f for f in to_copy if f.name == data_name)
        with Track(data_src) as track:
            edits = patcher.plan(track, strings, images, byte_patches, dialogue,
                                 log=progress.line, progress=progress.status,
                                 collect_errors=args.all_errors)
    except (ValueError, OSError) as e:
        progress.clear()
        print(f"error: {e}", file=sys.stderr)
        return 1

    for f in to_copy:
        if not f.is_file():
            ap.error(f"{f} (referenced by the .cue) not found")
    print(f"Step 2/3: copying the game to {out}")
    out.mkdir(parents=True, exist_ok=True)
    for f in to_copy:
        size = f.stat().st_size
        print(f"  {f.name}" + (f" ({size / 2**20:.0f} MB)" if size >= 2**20 else ""))
        shutil.copyfile(f, out / f.name)

    print(f"Step 3/3: writing {len(edits)} patched file(s)"
          + ("" if args.verbose else " (-v lists every string)"))
    with Track(out / data_name, writable=True) as track:
        patcher.apply(track, edits, verbose=args.verbose)

    seconds = time.monotonic() - started
    took = f"{int(seconds // 60)}m {seconds % 60:.0f}s" if seconds >= 60 else f"{seconds:.0f}s"
    print(f"Done in {took}. Patched game written to:\n  {out}")
    if src.suffix.lower() == ".cue":
        print("Open the .cue file in that folder with your emulator.")
    return 0


class Progress:
    """Prints stage lines, and per-block status in place on a terminal.

    Redirected to a file, a status is printed as its own line instead.
    """

    def __init__(self, stream=sys.stdout):
        self.stream = stream
        self.tty = stream.isatty()
        self.width = 0

    def line(self, message: str) -> None:
        self.clear()
        print(message, file=self.stream, flush=True)

    def status(self, message: str) -> None:
        if not self.tty:
            print(f"    {message}", file=self.stream, flush=True)
            return
        message = f"    {message}"[:shutil.get_terminal_size().columns - 1]
        self.stream.write("\r" + message.ljust(self.width))
        self.stream.flush()
        self.width = len(message)

    def clear(self) -> None:
        if self.width:
            self.stream.write("\r" + " " * self.width + "\r")
            self.stream.flush()
            self.width = 0


if __name__ == "__main__":
    sys.exit(main())
