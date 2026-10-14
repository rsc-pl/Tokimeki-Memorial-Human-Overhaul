"""Minimal ISO 9660 directory reader, enough to locate files on the disc."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict

from .cd import Track

PVD_LBA = 16


@dataclass
class Entry:
    path: str
    lba: int
    size: int
    is_dir: bool


def list_files(track: Track) -> Dict[str, Entry]:
    """Return every file and directory keyed by upper-case path without ';1'."""
    pvd = track.read_data(PVD_LBA)
    if pvd[1:6] != b"CD001":
        raise ValueError("No ISO 9660 volume descriptor found - is this a PS1 data track?")
    root_lba, root_size = struct.unpack_from("<I", pvd, 158)[0], struct.unpack_from("<I", pvd, 166)[0]

    entries: Dict[str, Entry] = {}

    def walk(lba: int, size: int, prefix: str) -> None:
        buf = track.read_file(lba, size)
        i = 0
        while i < len(buf):
            length = buf[i]
            if length == 0:  # records never cross sectors; skip padding
                i = (i // 2048 + 1) * 2048
                continue
            rec = buf[i:i + length]
            i += length
            if length < 34:
                continue
            name_len = rec[32]
            raw_name = rec[33:33 + name_len]
            if raw_name in (b"\0", b"\1"):
                continue
            name = raw_name.decode("ascii", "replace").split(";")[0].upper()
            entry = Entry(
                path=f"{prefix}{name}",
                lba=struct.unpack_from("<I", rec, 2)[0],
                size=struct.unpack_from("<I", rec, 10)[0],
                is_dir=bool(rec[25] & 2),
            )
            entries[entry.path] = entry
            if entry.is_dir:
                walk(entry.lba, entry.size, entry.path + "/")

    walk(root_lba, root_size, "")
    return entries
