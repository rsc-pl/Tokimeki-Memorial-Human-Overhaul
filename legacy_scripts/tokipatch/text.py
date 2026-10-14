"""Converting English script text into bytes the game can display.

The game prints Shift-JIS with a 16x16 full-width font and has no half-width
(ASCII) glyphs, so for now English is written with full-width Latin letters
(Ａ-Ｚ, ａ-ｚ). A variable-width font hack would replace this module later.
"""

from __future__ import annotations

# ASCII characters whose obvious full-width form isn't in JIS X 0208.
_SPECIAL = {
    " ": "　",   # ideographic space
    "'": "’",   # ’
    '"': "”",   # ”
    "-": "−",   # −
    "~": "〜",   # 〜
    "\\": "＼",  # ＼
}


def to_fullwidth(text: str) -> str:
    out = []
    for ch in text:
        if ch in _SPECIAL:
            out.append(_SPECIAL[ch])
        elif "!" <= ch <= "~":
            out.append(chr(ord(ch) + 0xFEE0))
        else:
            out.append(ch)  # already Japanese / full-width
    return "".join(out)


def _is_jis_x0208(lead: int) -> bool:
    return 0x81 <= lead <= 0x84 or 0x88 <= lead <= 0x9F or 0xE0 <= lead <= 0xEA


def encode(text: str) -> bytes:
    """Encode script text as 2-byte Shift-JIS, rejecting anything the font lacks."""
    data = to_fullwidth(text).encode("shift_jis")
    for i in range(0, len(data), 2):
        if i + 1 >= len(data) or not _is_jis_x0208(data[i]):
            raise ValueError(f"{text!r}: character {data[i:i+2]!r} can't be displayed by the game font")
    return data
