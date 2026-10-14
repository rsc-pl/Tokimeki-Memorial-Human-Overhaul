"""Extract every file from the disc, and write a listing with LBAs.

Usage:  python tools/extract.py path/to/game.cue OUTPUT_DIR

Writes OUTPUT_DIR/<path on disc> for each file, plus OUTPUT_DIR/files.tsv
(lba, size, path). Audio (TR02.DA) and the FMV .STR files are skipped.
Don't commit the output; it's copyrighted game data.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tokipatch.__main__ import parse_cue  # noqa: E402
from tokipatch.cd import Track  # noqa: E402
from tokipatch.iso9660 import list_files  # noqa: E402


def main() -> None:
    cue, out = Path(sys.argv[1]), Path(sys.argv[2])
    _, data_name = parse_cue(cue)
    with Track(cue.parent / Path(data_name).name) as track:
        files = list_files(track)
        listing = []
        for entry in sorted(files.values(), key=lambda e: e.lba):
            listing.append(f"{entry.lba}\t{entry.size}\t{entry.path}{'/' if entry.is_dir else ''}")
            if entry.is_dir or entry.lba >= track.sector_count or entry.path.endswith(".STR"):
                continue
            dst = out / entry.path
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(track.read_file(entry.lba, entry.size))
    (out / "files.tsv").write_text("\n".join(listing) + "\n", encoding="utf-8")
    print(f"extracted {len(files)} entries to {out}")


if __name__ == "__main__":
    main()
