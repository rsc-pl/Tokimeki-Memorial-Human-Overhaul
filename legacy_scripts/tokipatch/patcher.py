"""Applies translation files (JSON) to the data track.

A translation file can contain:

  "strings": in-place text replacements
      {"file", "offset", "original", "text", "encoding"?, "slot"?}
      `encoding` is "pairs" (default: English letter pairs, 1 byte per letter,
      composed on the fly by the renderer hook; see font.py, renderer.py) or
      "fullwidth" (each letter as a full-width Shift-JIS character, 2 bytes
      and 12 px per letter). As in dialogue, "\n" stands for the 0x20 line
      break and "{G}"-style tokens for control bytes, in both "original" and
      "text" (overlay strings the dialogue renderer draws contain them), and
      a "pairs" text may contain full-width characters ("○", "『").
      `slot` (optional) is the size of a fixed-size record the string starts
      (e.g. 33 for the DATE.EXN place-name table, game-internals 6l). Only
      for tables whose record size is proven from the code that reads them.
      Every byte from the original's end to the slot's end must be NUL; the
      English (plus its NUL) may then use the whole slot.

  "images":  pixels copied from an 8-bit indexed PNG into a 4/8bpp bitmap
      {"file", "png", "pixels", "stride", "x", "y", "rects", "original_crc32", "bpp"?}
      `pixels` is the file offset of the bitmap, `stride` its width in bytes,
      (x, y) where the PNG's top-left lands, and `rects` the [x, y, w, h] areas
      of the PNG to copy (everything else is left alone). `bpp` is 8 (default)
      or 4 (two pixels per byte, low nibble first). `original_crc32` is the
      CRC32 of the replaced pixel values, one byte per pixel, row by row.

  "bytes":   raw byte replacements, for code/data hacks
      {"file", "offset", "original", "replacement", "comment"}
      `original` and `replacement` are hex strings of equal length; the
      patcher refuses to run unless the file holds exactly `original`.

  "dialogue": blocks of script strings that are repacked, not fitted in place
      {"file", "base", "max_cells"?, "share_identical"?,
       "lines": [{"offset", "original", "text"}]}
      `base` is the RAM address the file is loaded to (its string pointers
      are absolute). The space of every translated string is pooled, the
      English is packed into it, and every pointer is updated (script.py).
      The English must keep the original's line breaks, choices and name
      codes (scene scripts time events to display lines). A line with an
      empty "text" is left untouched. With "share_identical": true, movable
      strings whose English encodes to the same bytes are stored once and
      all their pointers point at that copy (safe because the game copies a
      string before cutting it up; game-internals §6k).
"""

from __future__ import annotations

import json
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import font, png, renderer, script, text
from .cd import Track
from .iso9660 import Entry, list_files

EXPECTED_BOOT = b"cdrom:SLPM_86.053"
CHECKSUM_MARKER = b"\x12\x10"
ENCODINGS = ("pairs", "fullwidth")


@dataclass
class StringPatch:
    file: str
    offset: int
    original: str
    text: str
    source: str  # translation file it came from, for error messages
    encoding: str = "pairs"
    slot: Optional[int] = None


@dataclass
class ImagePatch:
    file: str
    png: Path
    pixels: int
    stride: int
    x: int
    y: int
    rects: List[List[int]]
    original_crc32: int
    source: str
    bpp: int = 8


@dataclass
class BytePatch:
    file: str
    offset: int
    original: bytes
    replacement: bytes
    comment: str
    source: str


@dataclass
class DialogueLine:
    offset: int
    original: str
    text: str


@dataclass
class DialogueBlock:
    file: str
    base: int
    lines: List[DialogueLine]
    source: str
    max_cells: int = script.MAX_CELLS
    share_identical: bool = False


@dataclass
class FileEdit:
    entry: Entry
    original: bytes
    data: bytearray
    log: List[str] = field(default_factory=list)


def load_translations(paths: List[Path]):
    """Return (strings, images, byte_patches, dialogue) from the given JSON files."""
    strings, images, byte_patches, dialogue = [], [], [], []
    for path in paths:
        path = Path(path)
        doc = json.loads(path.read_text(encoding="utf-8"))
        for item in doc.get("strings", []):
            encoding = item.get("encoding", "pairs")
            if encoding not in ENCODINGS:
                raise ValueError(f"{path.name}: unknown encoding {encoding!r} (use {ENCODINGS})")
            strings.append(StringPatch(
                file=item["file"].upper().lstrip("/"),
                offset=int(item["offset"], 0),
                original=item["original"],
                text=item["text"],
                source=path.name,
                encoding=encoding,
                slot=item.get("slot"),
            ))
            slot = strings[-1].slot
            if slot is not None and (not isinstance(slot, int) or slot < 2):
                raise ValueError(f"{path.name}: {item['offset']}: slot must be an integer >= 2")
        for item in doc.get("images", []):
            images.append(ImagePatch(
                file=item["file"].upper().lstrip("/"),
                png=path.parent / item["png"],
                pixels=int(item["pixels"], 0),
                stride=item["stride"],
                x=item["x"],
                y=item["y"],
                rects=item["rects"],
                original_crc32=int(item["original_crc32"], 0),
                source=path.name,
                bpp=item.get("bpp", 8),
            ))
            if images[-1].bpp not in (4, 8):
                raise ValueError(f"{path.name}: images support bpp 4 or 8, not {images[-1].bpp}")
        for item in doc.get("bytes", []):
            original = bytes.fromhex(item["original"])
            replacement = bytes.fromhex(item["replacement"])
            if len(original) != len(replacement):
                raise ValueError(f"{path.name}: bytes patch at {item['offset']} changes length")
            byte_patches.append(BytePatch(
                file=item["file"].upper().lstrip("/"),
                offset=int(item["offset"], 0),
                original=original,
                replacement=replacement,
                comment=item.get("comment", ""),
                source=path.name,
            ))
        for item in doc.get("dialogue", []):
            dialogue.append(DialogueBlock(
                file=item["file"].upper().lstrip("/"),
                base=int(item["base"], 0),
                lines=[DialogueLine(int(line["offset"], 0), line["original"], line["text"])
                       for line in item["lines"]],
                source=path.name,
                max_cells=item.get("max_cells", script.MAX_CELLS),
                share_identical=bool(item.get("share_identical", False)),
            ))
    return strings, images, byte_patches, dialogue


def check_disc(files: Dict[str, Entry], track: Track) -> None:
    cnf = files.get("SYSTEM.CNF")
    if cnf is None or EXPECTED_BOOT not in track.read_file(cnf.lba, cnf.size):
        raise ValueError("This doesn't look like Tokimeki Memorial: Forever with You "
                         "(PlayStation the Best, SLPM-86053).")


def has_checksum(data: bytes) -> bool:
    """Most data files end with a big-endian 16-bit byte sum + 12 10.

    The game verifies it after every load and silently retries forever on a
    mismatch (which shows up as a hang on a white or black screen).
    """
    return (len(data) >= 4 and data[-2:] == CHECKSUM_MARKER
            and sum(data[:-4]) & 0xFFFF == int.from_bytes(data[-4:-2], "big"))


def fix_checksum(data: bytearray) -> None:
    data[-4:-2] = (sum(data[:-4]) & 0xFFFF).to_bytes(2, "big")


def apply_string(patch: StringPatch, edit: FileEdit, pairs: font.PairEncoder) -> None:
    where = f"{patch.source}: {patch.file} @ {patch.offset:#x}"
    data = edit.data
    # Written like dialogue: "\n" is the 0x20 line break and "{G}"-style
    # tokens are control bytes (overlay strings drawn by the dialogue
    # renderer use both); plain text encodes exactly as Shift-JIS.
    original = script.encode_original(patch.original)
    end = patch.offset + len(original)
    if bytes(data[patch.offset:end]) != original or data[end:end + 1] != b"\0":
        found = script.decode(bytes(data[patch.offset:end]))
        raise ValueError(f"{where}: expected {patch.original!r}, found {found!r}")

    if patch.slot is not None:
        # A fixed-size record: the string may fill it, but only if everything
        # after the original up to the record's end is NUL (nothing else is
        # stored there).
        if len(original) + 1 > patch.slot:
            raise ValueError(f"{where}: the original doesn't fit a {patch.slot}-byte slot")
        if patch.offset + patch.slot > len(data) or any(data[end:patch.offset + patch.slot]):
            raise ValueError(f"{where}: bytes after the original aren't all NUL up to "
                             f"the {patch.slot}-byte slot's end")
        capacity = patch.slot
    else:
        # The string owns its terminator plus any zero padding up to the next
        # 4-byte boundary (the compiler aligns string literals to 4 bytes).
        capacity = len(original) + 1
        while (patch.offset + capacity) % 4 and data[patch.offset + capacity] == 0:
            capacity += 1

    if patch.encoding == "pairs":
        # Same bytes as pairs.encode for plain ASCII; also takes "\n",
        # control tokens and full-width characters, as dialogue does.
        new = script.encode_english(patch.text, pairs)[0]
        max_letters = (capacity - 1) // 2 * 2
    else:
        new = text.encode(patch.text)
        max_letters = (capacity - 1) // 2
    if len(new) + 1 > capacity:
        raise ValueError(f"{where}: {patch.text!r} needs {len(new) + 1} bytes "
                         f"but only {capacity} are available "
                         f"(max {max_letters} characters with {patch.encoding} encoding)")
    data[patch.offset:patch.offset + capacity] = new.ljust(capacity, b"\0")
    edit.log.append(f"{patch.offset:#07x}: {patch.original}  ->  {patch.text}")
    # Japanese is 12 px per 2 bytes and pair/full-width English is 12 px per 2
    # bytes too, so anything longer than the original bytes draws wider.
    if len(new) > len(original):
        edit.log.append(f"    note: {len(new) * 6} px wide vs {len(original) * 6} px originally; "
                        "check it fits on screen")


def apply_dialogue(block: DialogueBlock, edit: FileEdit, pairs: font.PairEncoder) -> None:
    """Repack a block's translated strings into the space they occupied.

    Each string's slot is its bytes + NUL + zero padding to the next 4-byte
    boundary (as for in-place strings). All slots are pooled, the English is
    packed into the pool, and every pointer to a moved string is rewritten.
    Strings referenced from code, or by no pointer we can find, must fit in
    their own slot.
    """
    data, orig = edit.data, edit.original
    index = script.WordIndex(orig)
    jobs, slots = [], {}
    for line in sorted((x for x in block.lines if x.text), key=lambda x: x.offset):
        where = f"{block.source}: {block.file} @ {line.offset:#x}"
        raw = script.encode_original(line.original)
        end = line.offset + len(raw)
        if bytes(data[line.offset:end]) != raw or data[end:end + 1] != b"\0":
            found = script.decode(script.read_string(orig, line.offset))
            raise ValueError(f"{where}: expected {line.original!r}, found {found!r}")
        capacity = len(raw) + 1
        while (line.offset + capacity) % 4 and data[line.offset + capacity] == 0:
            capacity += 1
        new, widths = script.encode_english(line.text, pairs)
        if script.structure(line.text) != script.structure(line.original):
            raise ValueError(f"{where}: the English must have the same line breaks, choices "
                             f"and name codes as the original ({script.structure(line.original)}), "
                             f"has {script.structure(line.text)}: {line.text!r}")
        # Thought lines: the game draws "（" itself, and in some scripts "）" too
        # (EVENT_FU.BIN's thoughts don't contain it). Only close with ")" where
        # the Japanese does, or the bracket is drawn twice.
        if line.original.rstrip("\n").endswith("）") != line.text.rstrip("\n ").endswith(")"):
            raise ValueError(f"{where}: the English must end with ')' exactly when the original "
                             f"ends with '）' (the game draws the other brackets): {line.text!r}")
        for n, cells in enumerate(widths):
            if cells > block.max_cells:
                raise ValueError(f"{where}: display line {n + 1} is {cells} cells wide "
                                 f"(max {block.max_cells}; a letter is 1 cell, a name "
                                 f"code counts as its longest name): {line.text!r}")
        pointers = script.find_pointers(orig, block.base, line.offset)
        movable = bool(pointers) and not index.code_references(block.base, line.offset)
        jobs.append((line, new, pointers, movable, where))
        slots[line.offset] = line.offset + capacity

    # Merge adjacent slots into spans and clear them.
    spans: List[List[int]] = []
    for start, stop in sorted(slots.items()):
        if spans and spans[-1][1] == start:
            spans[-1][1] = stop
        else:
            spans.append([start, stop])
    for start, stop in spans:
        for pos, target in index.pointers_into(block.base, start, stop):
            if target not in slots:
                raise ValueError(f"{block.source}: {block.file}: word at {pos:#x} points into "
                                 f"translated text at {target:#x}, not at a string start")
        data[start:stop] = bytes(stop - start)

    def take(free: List[List[int]], start: int, size: int) -> None:
        for span in free:
            if span[0] <= start and start + size <= span[1]:
                free.remove(span)
                free.extend(x for x in ([span[0], start], [start + size, span[1]]) if x[1] > x[0])
                free.sort()
                return
        raise AssertionError(f"{start:#x} isn't free")

    # Strings that can't move keep their own slot.
    fixed = [list(span) for span in spans]
    pinned = {}
    for line, new, pointers, movable, where in jobs:
        if not movable:
            capacity = slots[line.offset] - line.offset
            if len(new) + 1 > capacity:
                reason = "is referenced from code" if pointers else "has no pointer to it"
                raise ValueError(f"{where}: the string {reason}, so it can't move, and the "
                                 f"English needs {len(new) + 1} bytes but only {capacity} "
                                 f"are available")
            take(fixed, line.offset, len(new) + 1)
            pinned[line.offset] = line.offset
    total = sum(stop - start for start, stop in spans)
    if block.share_identical:
        unique = {job[1] for job in jobs if job[3]}
        needed = (sum(len(new) + 1 for new in unique)
                  + sum(len(job[1]) + 1 for job in jobs if not job[3]))
    else:
        needed = sum(len(job[1]) + 1 for job in jobs)

    def pack(order, best_fit: bool):
        """Place the movable strings; None if one doesn't fit anywhere."""
        free = [list(span) for span in fixed]
        placed, shared = dict(pinned), {}       # shared: English bytes -> its copy
        for line, new, pointers, movable, where in order:
            if not movable:
                continue
            if block.share_identical and new in shared:
                placed[line.offset] = shared[new]
                continue
            fits = [x for x in free if x[1] - x[0] >= len(new) + 1]
            if not fits:
                return None
            span = min(fits, key=lambda x: (x[1] - x[0], x[0])) if best_fit else fits[0]
            placed[line.offset] = shared[new] = span[0]
            take(free, span[0], len(new) + 1)
        return placed

    # First fit in file order. The pool is often split into small gaps
    # between pointer lists (DATE_FU.BIN), where that can strand a long
    # string; then place the longest strings first, each in the tightest gap.
    # The fallback only runs when first fit fails, so blocks that already fit
    # keep their exact layout.
    placed = pack(jobs, best_fit=False)
    if placed is None:
        placed = pack(sorted(jobs, key=lambda job: (-len(job[1]), job[0].offset)), best_fit=True)
    if placed is None:
        raise ValueError(f"{block.source}: {block.file}: the English doesn't fit in the "
                         f"space of the original strings ({needed} bytes needed, "
                         f"{total} available)")

    for line, new, pointers, movable, where in jobs:
        at = placed[line.offset]
        data[at:at + len(new)] = new
        for p in pointers:
            data[p:p + 4] = (block.base + at).to_bytes(4, "little")
        edit.log.append(f"{line.offset:#07x} -> {at:#07x}: {line.text!r}")
    copies = len(set(placed.values()))
    note = f", {len(jobs) - copies} sharing an identical copy" if copies < len(jobs) else ""
    edit.log.append(f"dialogue: {len(jobs)} string(s){note}, {needed} of {total} bytes used")


def _rect_pixels(patch: ImagePatch, rect: List[int]):
    """Yield (png row, png column, bitmap byte offset, nibble shift or None)."""
    rx, ry, rw, rh = rect
    for row in range(ry, ry + rh):
        for col in range(rx, rx + rw):
            x, y = patch.x + col, patch.y + row
            if patch.bpp == 8:
                yield row, col, patch.pixels + y * patch.stride + x, None
            else:
                yield row, col, patch.pixels + y * patch.stride + x // 2, 4 * (x & 1)


def apply_image(patch: ImagePatch, edit: FileEdit) -> None:
    where = f"{patch.source}: {patch.file} <- {patch.png.name}"
    width, height, pixels = png.read_indexed(patch.png)
    data = edit.data
    row_pixels = patch.stride * 8 // patch.bpp

    original = bytearray()
    for rect in patch.rects:
        rx, ry, rw, rh = rect
        if rx + rw > width or ry + rh > height or patch.x + rx + rw > row_pixels:
            raise ValueError(f"{where}: rect {rect} is out of bounds")
        for _, _, off, shift in _rect_pixels(patch, rect):
            original.append(data[off] if shift is None else (data[off] >> shift) & 15)
    crc = zlib.crc32(original)
    if crc != patch.original_crc32:
        raise ValueError(f"{where}: target pixels don't match the expected original "
                         f"(crc32 {crc:#010x}, expected {patch.original_crc32:#010x})")

    for rect in patch.rects:
        for row, col, off, shift in _rect_pixels(patch, rect):
            value = pixels[row * width + col]
            if shift is None:
                data[off] = value
            elif value > 15:
                raise ValueError(f"{where}: pixel ({col}, {row}) is index {value}; "
                                 "a 4bpp image only has indices 0-15")
            else:
                data[off] = (data[off] & ~(15 << shift)) | (value << shift)
    edit.log.append(f"{patch.pixels:#07x}: image {patch.png.name}")


def apply_bytes(patch: BytePatch, edit: FileEdit) -> None:
    where = f"{patch.source}: {patch.file} @ {patch.offset:#x}"
    end = patch.offset + len(patch.original)
    found = bytes(edit.data[patch.offset:end])
    if found != patch.original:
        raise ValueError(f"{where}: expected bytes {patch.original.hex()}, found {found.hex()}")
    edit.data[patch.offset:end] = patch.replacement
    edit.log.append(f"{patch.offset:#07x}: bytes {patch.original.hex()} -> {patch.replacement.hex()}"
                    + (f"  ({patch.comment})" if patch.comment else ""))


def _quiet(message: str) -> None:
    pass


def plan(track: Track, strings: List[StringPatch], images: List[ImagePatch],
         byte_patches: List[BytePatch] = (),
         dialogue: List[DialogueBlock] = (),
         log: Callable[[str], None] = _quiet,
         progress: Callable[[str], None] = _quiet) -> List[FileEdit]:
    """Validate and apply every patch in memory, against the unmodified disc.

    `log` gets a line per stage; `progress` gets a short status for each
    dialogue block (the slow part), meant to be shown in place.
    """
    log("  Reading the disc's file list")
    files = list_files(track)
    check_disc(files, track)
    log("  Found Tokimeki Memorial: Forever with You (SLPM-86053)")

    edits: Dict[str, FileEdit] = {}

    def edit_for(path: str, source: str) -> FileEdit:
        if path not in edits:
            entry = files.get(path)
            if entry is None or entry.is_dir:
                raise ValueError(f"{source}: no file {path!r} on the disc")
            data = track.read_file(entry.lba, entry.size)
            edits[path] = FileEdit(entry, data, bytearray(data))
        return edits[path]

    pairs = font.PairEncoder()
    if strings:
        log(f"  Checking {len(strings)} menu and screen string(s)")
    for s in strings:
        apply_string(s, edit_for(s.file, s.source), pairs)
    if images:
        log(f"  Checking {len(images)} image(s)")
    for i in images:
        apply_image(i, edit_for(i.file, i.source))
    if byte_patches:
        log(f"  Checking {len(byte_patches)} code and data patch(es)")
    for b in byte_patches:
        apply_bytes(b, edit_for(b.file, b.source))
    if dialogue:
        lines = sum(1 for d in dialogue for x in d.lines if x.text)
        log(f"  Repacking {lines} dialogue line(s) in {len(dialogue)} block(s)")
    for n, d in enumerate(dialogue, 1):
        progress(f"[{n}/{len(dialogue)}] {d.file} ({d.source})")
        apply_dialogue(d, edit_for(d.file, d.source), pairs)

    if pairs.used:
        log("  Installing the English text renderer")
        exe = edit_for(font.EXE, "renderer")
        exe.log.extend(renderer.install(exe.data))

    for path, edit in edits.items():
        if has_checksum(edit.original):
            if edit.data[-4:] != edit.original[-4:]:
                raise ValueError(f"{path}: a patch overwrote the file's checksum trailer")
            fix_checksum(edit.data)
            edit.log.append("checksum updated")
    log(f"  All checks passed: {len(edits)} file(s) to rewrite")
    return list(edits.values())


def apply(track: Track, edits: List[FileEdit], log=print, verbose: bool = True) -> None:
    """Write the planned edits. Without `verbose`, each file's per-string
    lines (those starting with an offset) are summed up as a count."""
    for n, edit in enumerate(edits, 1):
        sectors = track.write_file(edit.entry.lba, edit.original, bytes(edit.data))
        if verbose:
            log(f"  {edit.entry.path} ({sectors} sector(s))")
            for line in edit.log:
                log(f"    {line}")
            continue
        changes = sum(1 for line in edit.log if line.startswith("0x"))
        details = [f"{changes} change(s)"] if changes else []
        blocks = [line for line in edit.log if line.startswith("dialogue:")]
        if len(blocks) > 1:
            details.append(f"{len(blocks)} dialogue blocks repacked")
        details.extend(blocks[:len(blocks) == 1])
        if any(line.startswith("renderer hook") for line in edit.log):
            details.append("English text renderer installed")
        if "checksum updated" in edit.log:
            details.append("checksum updated")
        log(f"  [{n}/{len(edits)}] {edit.entry.path} ({sectors} sector(s)): " + "; ".join(details))
