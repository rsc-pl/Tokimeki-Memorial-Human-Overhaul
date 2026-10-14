"""Dialogue (script) strings: decoding, encoding and pointer relocation.

Facts (docs/game-internals.md, "Dialogue"):
  - Dialogue lines are NUL-terminated strings, drawn by the EXE's dialogue
    renderer (0x80081190). It walks a string byte by byte: a control byte
    (below) takes 1 byte, anything else is a 2-byte Shift-JIS character.
  - 0x20 ends a display line, 'q' (0x71) ends a choice option. Letters
    m M A W O F Y S P p G insert a name or word kept in RAM (the player's
    name, the girl's name, ...), always as full-width Shift-JIS.
  - 'n' (0x6E) marks an empty option: the option picker (EXE 0x80081024)
    skips an option that starts with it. It occurs only as a run ending an
    option ("...nn" or "qnn" in the DATE_* yukata lines, game-internals 6k),
    and is only accepted there.
  - A narration/sound line (speaker code 07) may start with a speaker label:
    one ASCII prefix byte, then a fixed number of label bytes, then the text
    (EXE 0x8007F174...: '>' 4 bytes and '<' 4 bytes in （）, '-' 6 bytes,
    '+' 2 bytes). The label is drawn on its own before the bracket, so it
    takes no room on the text's line (game-internals 6p).
  - Strings are reached through tables of absolute RAM pointers, stored in the
    same file (base = the file's load address). So a translated string can
    be moved anywhere inside the space freed by the strings being replaced,
    as long as every pointer to it is updated.

In translation files a dialogue string is written with "\\n" for a line break
and "{X}" for control byte X ("{P}", "{G}", "{q}", ...). A speaker label is
written "{>部長}" at the very start of the string; in English "{>Capt}",
padded with spaces to the label's byte count (one byte per letter).
"""

from __future__ import annotations

import bisect
import re
import struct
from typing import Dict, List, Tuple

from . import pairfont

LINE_BREAK = 0x20
CHOICE = ord("q")
# Every byte the renderer treats as a 1-byte control code (0x80081430...).
CONTROL = frozenset(b" qmMAWOFYSPpG")
# Empty-option marker; not a renderer code (see the module docstring).
SKIP = ord("n")
# Speaker-label prefix byte -> label length in bytes (code-07 lines only).
LABELS: Dict[int, int] = {ord(">"): 4, ord("<"): 4, ord("-"): 6, ord("+"): 2}
_LABEL = re.compile(r"\{([><+-])([^{}\n]*)\}")

# Widest display line, in 7 px cells (one cell per English letter, two per
# full-width character). The dialogue box fits about 29 letters after the
# speaker's name (measured on screen); 28 leaves a margin.
MAX_CELLS = 28

# How wide each inserted word can get, in 7 px cells (2 cells = one
# full-width character). Used for line-width checks only, so these are
# deliberately generous estimates where the real maximum isn't known yet.
# {G} is filled only by 0x80051438 (short-name table + suffix, or the fixed
# Shiori/Yumi/Ijuin names) and three overlay strcpy's (館林さん, 伊集院):
# 10 cells at most, Japanese or English (game-internals 6e).
TOKEN_CELLS: Dict[str, int] = {
    "P": 12, "p": 6, "m": 6, "F": 12, "G": 10, "Y": 6, "S": 18,
    "O": 18, "W": 18, "A": 18, "M": 18, "n": 0,
}

_TOKEN = re.compile(r"\{([A-Za-z])\}|\n")


def _is_lead(b: int) -> bool:
    return 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEA


def _label_len(raw: bytes) -> int:
    """Length of a speaker-label prefix at the start of raw (0 if none)."""
    if not raw or raw[0] not in LABELS:
        return 0
    n = LABELS[raw[0]]
    label = raw[1:1 + n]
    if len(label) < n or len(raw) == 1 + n:
        return 0
    try:
        label.decode("shift_jis")
    except UnicodeDecodeError:
        return 0
    return 1 + n


def _take_label(text: str):
    """"{>部長}rest" -> (">", "部長", "rest"); (None, "", text) without one."""
    m = _LABEL.match(text)
    if not m:
        return None, "", text
    return m.group(1), m.group(2), text[m.end():]


def decode(raw: bytes) -> str:
    """Bytes of one dialogue string (without NUL) -> readable text."""
    out, i = [], _label_len(raw)
    if i:
        out.append("{%s%s}" % (chr(raw[0]), raw[1:i].decode("shift_jis")))
    while i < len(raw):
        b = raw[i]
        if b == LINE_BREAK:
            out.append("\n")
            i += 1
        elif b in CONTROL:
            out.append("{%s}" % chr(b))
            i += 1
        elif b == SKIP and _ends_option(raw, i):
            out.append("{n}")
            i += 1
        elif _is_lead(b) and i + 1 < len(raw):
            out.append(raw[i:i + 2].decode("shift_jis"))
            i += 2
        else:
            raise ValueError(f"byte {b:#04x} at +{i} isn't dialogue text")
    return "".join(out)


def _ends_option(raw: bytes, i: int) -> bool:
    """Whether raw[i:] up to the next 'q' (or the end) is all 'n' bytes."""
    end = raw.find(b"q", i)
    run = raw[i:end if end >= 0 else len(raw)]
    return len(run) > 0 and set(run) == {SKIP}


def read_string(data: bytes, offset: int) -> bytes:
    end = data.index(b"\0", offset)
    return bytes(data[offset:end])


def encode_original(text: str) -> bytes:
    """Readable Japanese text (as written in a translation file) -> bytes."""
    out = bytearray()
    prefix, label, text = _take_label(text)
    if prefix:
        out += prefix.encode() + label.encode("shift_jis")
    for piece, token in _split(text):
        out += piece.encode("shift_jis") if token is None else token
    return bytes(out)


def _split(text: str):
    """Yield (text, None) runs and ("", control byte) tokens."""
    pos = 0
    for m in _TOKEN.finditer(text):
        if m.start() > pos:
            yield text[pos:m.start()], None
        if m.group(0) == "\n":
            yield "", bytes([LINE_BREAK])
        else:
            code = ord(m.group(1))
            if (code not in CONTROL and code != SKIP) or code == LINE_BREAK:
                raise ValueError(f"{text!r}: unknown control code {m.group(0)}")
            yield "", bytes([code])
        pos = m.end()
    if pos < len(text):
        yield text[pos:], None


def encode_english(text: str, pairs) -> Tuple[bytes, List[int]]:
    """English dialogue -> (bytes, width of each display line in 7 px cells).

    ASCII runs are letter-pair encoded (`pairs` is a font.PairEncoder); an odd
    run is padded with a space, so it costs one empty cell. Non-ASCII
    characters (e.g. "…", "♪") are written as full-width Shift-JIS.
    """
    out = bytearray()
    widths = [0]
    prefix, label, text = _take_label(text)
    if prefix:
        # Drawn on its own before the bracket: a fixed size and no width on
        # the text's line. ASCII letters are padded with spaces.
        size = LABELS[ord(prefix)]
        if label and all(c < "\x7f" for c in label):
            if len(label) > size:
                raise ValueError(f"{text!r}: speaker label {label!r} is longer than {size} letters")
            encoded = pairs.encode(label.ljust(size))
        else:
            encoded = label.encode("shift_jis")
        if len(encoded) != size:
            raise ValueError(f"{text!r}: speaker label {label!r} must take exactly {size} bytes")
        out += prefix.encode() + encoded
    for piece, token in _split(text):
        if token is not None:
            out += token
            if token[0] in (LINE_BREAK, CHOICE):
                widths.append(0)
            else:
                widths[-1] += TOKEN_CELLS[chr(token[0])]
            continue
        for run in re.findall(r"[\x20-\x7e]+|[^\x20-\x7e]+", piece):
            if run[0] < "\x7f":
                for ch in run:
                    if not pairfont.supported(ch):
                        raise ValueError(f"{text!r}: character {ch!r} isn't in the English pair font")
                encoded = pairs.encode(run)
            else:
                encoded = run.encode("shift_jis")
                if any(not _is_lead(encoded[i]) for i in range(0, len(encoded), 2)):
                    raise ValueError(f"{text!r}: {run!r} isn't full-width Shift-JIS")
            out += encoded
            widths[-1] += len(encoded)  # 2 bytes = one glyph = 2 cells
    return bytes(out), widths


def structure(text: str) -> str:
    """A string's line layout and codes, which a translation must keep.

    Scene scripts time events to display lines (e.g. the prologue waits for
    the 4th line of Rei's introduction before playing his animation), so the
    English needs the same number of lines, the same choices, and the same
    name codes in each line (their order within a line may change).
    """
    lines = []
    prefix, _, text = _take_label(text)
    if prefix:
        lines.append("label" + prefix)
    for line in text.split("\n"):
        parts = []
        for option in line.split("{q}"):
            # Empty-option markers ({n}) must stay a run at the option's end.
            body = option
            while body.endswith("{n}"):
                body = body[:-3]
            codes = sorted(re.findall(r"\{[A-Za-z]\}", body))
            if "{n}" in codes:
                codes.append("<n not at the end>")
            tail = (len(option) - len(body)) // 3
            parts.append("".join(codes) + (f"$n{tail}" if tail else ""))
        lines.append("|".join(parts))
    return "/".join(lines)


def find_pointers(data: bytes, base: int, offset: int) -> List[int]:
    """File offsets of every aligned 32-bit word equal to base + offset."""
    needle = struct.pack("<I", base + offset)
    hits, pos = [], data.find(needle)
    while pos != -1:
        if pos % 4 == 0:
            hits.append(pos)
        pos = data.find(needle, pos + 1)
    return hits


class WordIndex:
    """A file's aligned 32-bit words, indexed once for the pointer searches.

    A dialogue block asks about every one of its strings (thousands in the
    big SERIFU files); scanning the whole file each time made a full build
    take minutes.
    """

    def __init__(self, data: bytes):
        self.words = struct.unpack_from(f"<{len(data) // 4}I", data, 0)
        self.lui: Dict[int, List[int]] = {}       # lui immediate -> word indices
        for i, w in enumerate(self.words):
            if w >> 26 == 0x0F:
                self.lui.setdefault(w & 0xFFFF, []).append(i)
        order = sorted(range(len(self.words)), key=self.words.__getitem__)
        self._by_value = [self.words[i] for i in order]
        self._order = order

    def pointers_into(self, base: int, start: int, end: int) -> List[Tuple[int, int]]:
        """(word offset, target offset) of aligned words pointing into [start, end)."""
        lo = bisect.bisect_left(self._by_value, base + start)
        hi = bisect.bisect_left(self._by_value, base + end)
        return [(i * 4, self.words[i] - base) for i in sorted(self._order[lo:hi])]

    def code_references(self, base: int, target: int, window: int = 8) -> List[int]:
        """File offsets of `lui` + `addiu/ori` pairs that build address base+target.

        Strings referenced from code can't be relocated by rewriting pointer
        tables, so the patcher refuses to move them.
        """
        addr = base + target
        lo = addr & 0xFFFF
        hi_addiu = ((addr + 0x8000) >> 16) & 0xFFFF   # addiu sign-extends its immediate
        hi_ori = (addr >> 16) & 0xFFFF
        hits = []
        for i in sorted(set(self.lui.get(hi_addiu, ())) | set(self.lui.get(hi_ori, ()))):
            w = self.words[i]
            rt, imm = (w >> 16) & 31, w & 0xFFFF
            for w2 in self.words[i + 1:i + 1 + window]:
                op, rs = w2 >> 26, (w2 >> 21) & 31
                # addiu, ori, or a load straight from the address (lb/lh/lw/lbu/lhu)
                if rs == rt and (w2 & 0xFFFF) == lo and (
                        (op in (0x09, 0x20, 0x21, 0x23, 0x24, 0x25) and imm == hi_addiu)
                        or (op == 0x0D and imm == hi_ori)):
                    hits.append(i * 4)
                    break
        return hits


def pointers_into(data: bytes, base: int, start: int, end: int) -> List[Tuple[int, int]]:
    """(word offset, target offset) of aligned words pointing into [start, end)."""
    return WordIndex(data).pointers_into(base, start, end)


def code_references(data: bytes, base: int, target: int, window: int = 8) -> List[int]:
    """File offsets of `lui` + `addiu/ori` pairs that build address base+target."""
    return WordIndex(data).code_references(base, target, window)
