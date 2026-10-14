"""Regression tests for finding dialogue strings in script files.

The fixtures are synthetic: they reproduce the layouts seen in the game's
SERIFU files (strings after a NUL, strings directly after a pointer table,
pointers into the middle of a string) without containing any game data.

Run with: python -m unittest discover tests
"""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "legacy_scripts"))
sys.path.insert(0, str(ROOT / "legacy_scripts" / "tools"))

import dump_dialogue  # noqa: E402
from tokipatch import font, patcher, script  # noqa: E402

BASE = 0x80198000


class Script:
    """Builds a script file: strings and pointer words, with known offsets."""

    def __init__(self, base: int = BASE):
        self.base = base
        self.data = bytearray()
        self.fixups = []        # (word offset, label, delta)
        self.labels = {}

    def string(self, label: str, raw: bytes, align: bool = True):
        self.labels[label] = len(self.data)
        self.data += raw + b"\0"
        while align and len(self.data) % 4:
            self.data += b"\0"

    def text(self, label: str, text: str):
        self.string(label, script.encode_original(text))

    def pointer(self, label: str, delta: int = 0):
        self.fixups.append((len(self.data), label, delta))
        self.data += bytes(4)

    def word(self, value: int):
        self.data += struct.pack("<I", value)

    def build(self) -> bytes:
        for pos, label, delta in self.fixups:
            struct.pack_into("<I", self.data, pos, self.base + self.labels[label] + delta)
        return bytes(self.data)


def layout(base: int = BASE):
    s = Script(base)
    s.text("after_nul", "あいう")                 # file start, then NUL-padded
    s.pointer("after_nul")                        # a scene's pointer table...
    s.pointer("after_table")
    s.text("after_table", "かきく\nけこ")         # ...directly followed by a string
    s.pointer("after_table", 2)                   # pointer into the middle (unaligned)
    s.text("long", "さしすせそたち")
    s.pointer("long")
    s.pointer("long", 4)                          # aligned pointer into the middle
    s.word(0x80010000)                            # a pointer word outside this file
    s.text("after_foreign", "なにぬ")
    s.pointer("after_foreign")
    s.string("ascii", b"PP")                      # control codes only, no Japanese
    s.pointer("ascii")
    s.string("binary", b"\x01\x02")               # not text at all
    s.pointer("binary")
    s.word(base + 0x100000)                       # points past the end of the file
    return s, s.build()


class StartsString(unittest.TestCase):
    def setUp(self):
        self.s, self.data = layout()
        self.at = self.s.labels

    def test_file_start_and_after_nul(self):
        self.assertTrue(dump_dialogue.starts_string(self.data, BASE, 0))
        self.assertTrue(dump_dialogue.starts_string(self.data, BASE, self.at["long"]))

    def test_after_pointer_table(self):
        off = self.at["after_table"]
        self.assertEqual(self.data[off - 1], 0x80)   # the case the old check rejected
        self.assertTrue(dump_dialogue.starts_string(self.data, BASE, off))

    def test_interior_offsets_rejected(self):
        self.assertFalse(dump_dialogue.starts_string(self.data, BASE, self.at["after_table"] + 2))
        self.assertFalse(dump_dialogue.starts_string(self.data, BASE, self.at["long"] + 4))

    def test_after_record_table(self):
        # TEL.EXN: strings follow tables of 4-byte records like 27 00 00 03,
        # or 5a 00 00 20 (the last byte equals the line-break code).
        text = "あっ…。".encode("shift_jis") + b"\0"
        for record in (b"\x27\x00\x00\x03", b"\x5a\x00\x00\x20"):
            data = b"\0" * 8 + record + text
            self.assertTrue(dump_dialogue.starts_string(data, BASE, 12), record.hex())
        # ...but a line break inside a string is not a start.
        data = b"\0" * 4 + "あいう".encode("shift_jis") + b" " + "えお".encode("shift_jis") + b"\0"
        self.assertFalse(dump_dialogue.starts_string(data, BASE, 11))

    def test_after_word_pointing_outside_the_file_rejected(self):
        self.assertFalse(dump_dialogue.starts_string(self.data, BASE, self.at["after_foreign"]))

    def test_after_pointer_with_wrong_base_rejected(self):
        # With another base the preceding words are no longer in-file pointers.
        self.assertFalse(dump_dialogue.starts_string(self.data, BASE + 0x800, self.at["after_table"]))


class Targets(unittest.TestCase):
    def setUp(self):
        self.s, self.data = layout()
        self.at = self.s.labels
        self.rejected = {}
        self.found = dump_dialogue.targets(self.data, BASE, self.rejected)

    def test_finds_strings_after_nul_and_after_pointer_table(self):
        self.assertEqual(self.found, {
            self.at["after_nul"]: "あいう",
            self.at["after_table"]: "かきく\nけこ",
            self.at["long"]: "さしすせそたち",
        })

    def test_reports_interior_and_unproven_targets(self):
        interior = "not at a string start (interior pointer?)"
        self.assertEqual(self.rejected, {
            self.at["after_table"] + 2: interior,
            self.at["long"] + 4: interior,
            self.at["after_foreign"]: interior,
            self.at["ascii"]: "no Japanese text",
        })

    def test_undecodable_and_out_of_file_targets_ignored(self):
        self.assertNotIn(self.at["binary"], self.found)
        self.assertNotIn(self.at["binary"], self.rejected)

    def test_rejected_is_optional(self):
        self.assertEqual(dump_dialogue.targets(self.data, BASE), self.found)

    def test_guess_base(self):
        self.assertEqual(dump_dialogue.guess_base(self.data), BASE)

    def test_guess_base_off_the_0x800_grid(self):
        # GASSH_FU.BIN loads at 0x801B4400; a 0x800-step search can't find it.
        _, data = layout(0x801B4400)
        self.assertEqual(dump_dialogue.guess_base(data), 0x801B4400)


class Edit:
    def __init__(self, data: bytes):
        self.original = data
        self.data = bytearray(data)
        self.log = []


def block(lines):
    return patcher.DialogueBlock("SERIFU/TEST.BIN", BASE, [
        patcher.DialogueLine(off, original, text) for off, original, text in lines], "test")


class RepackAfterPointerTable(unittest.TestCase):
    """The patcher already handles strings after a table; keep it that way."""

    def setUp(self):
        s = Script()
        s.text("first", "あいう")
        s.pointer("first")
        s.pointer("second")
        s.text("second", "かきく\nけこ")
        s.pointer("second")
        self.s, self.data = s, s.build()

    def word(self, data, pos):
        return struct.unpack_from("<I", data, pos)[0]

    def test_pointers_rewritten_and_table_kept(self):
        first, second = self.s.labels["first"], self.s.labels["second"]
        table = first + 8
        edit = Edit(self.data)
        patcher.apply_dialogue(block([
            (first, "あいう", "Hi"),
            (second, "かきく\nけこ", "Hello th\nyo"),
        ]), edit, font.PairEncoder())
        out = bytes(edit.data)
        self.assertEqual(len(out), len(self.data))
        english = {text: script.encode_english(text, font.PairEncoder())[0]
                   for text in ("Hi", "Hello th\nyo")}
        # Every pointer lands on its string's English.
        self.assertEqual(script.read_string(out, self.word(out, table) - BASE), english["Hi"])
        for pos in (table + 4, second + 12):
            self.assertEqual(script.read_string(out, self.word(out, pos) - BASE),
                             english["Hello th\nyo"])
        # Each string fits back in its own slot, so the table between them is
        # byte-identical: nothing was packed over it.
        self.assertEqual(out[table:table + 8], self.data[table:table + 8])

    def test_closing_bracket_must_match_original(self):
        # The game draws a thought's "）" itself unless the string contains it.
        first = self.s.labels["first"]
        with self.assertRaisesRegex(ValueError, "end with '\\)'"):
            patcher.apply_dialogue(block([(first, "あいう", "Hi.)")]),
                                   Edit(self.data), font.PairEncoder())
        s = Script()
        s.text("thought", "あいう）")
        s.pointer("thought")
        data = s.build()
        with self.assertRaisesRegex(ValueError, "end with '\\)'"):
            patcher.apply_dialogue(block([(0, "あいう）", "Hi.")]), Edit(data), font.PairEncoder())
        patcher.apply_dialogue(block([(0, "あいう）", "Hi.)")]), Edit(data), font.PairEncoder())

    def test_interior_pointer_still_refused(self):
        s = Script()
        s.text("first", "あいう")
        s.pointer("second")
        s.text("second", "かきく\nけこ")
        s.pointer("second", 2)
        data = s.build()
        with self.assertRaisesRegex(ValueError, "not at a string start"):
            patcher.apply_dialogue(block([(s.labels["second"], "かきく\nけこ", "Hello th\nyo")]),
                                   Edit(data), font.PairEncoder())


class EmptyOptionMarker(unittest.TestCase):
    """'n' runs ending an option (DATE_* yukata lines) decode as {n}."""

    def test_round_trip(self):
        for raw in (b"\x82\xa0\x20\x82\xa2nn", b"\x82\xa0\x82\xa2qnn"):
            text = script.decode(raw)
            self.assertIn("{n}{n}", text)
            self.assertEqual(script.encode_original(text), raw)

    def test_only_at_the_end_of_an_option(self):
        for raw in (b"\x82\xa0n\x82\xa0", b"nn\x82\xa0", b"\x82\xa0nnq\x82\xa0n\x82\xa0"):
            with self.assertRaises(ValueError):
                script.decode(raw)

    def test_structure_keeps_the_run_at_the_end(self):
        original = "あいう\nえお{n}{n}"
        self.assertEqual(script.structure("Hi\nthere.{n}{n}"), script.structure(original))
        self.assertNotEqual(script.structure("Hi\n{n}{n}there."), script.structure(original))
        self.assertNotEqual(script.structure("Hi\nthere.{n}"), script.structure(original))
        self.assertEqual(script.structure("Thanks.{q}{n}{n}"), script.structure("あ{q}{n}{n}"))

    def test_english_keeps_the_bytes(self):
        new, widths = script.encode_english("Thanks.{q}{n}{n}", font.PairEncoder())
        self.assertTrue(new.endswith(b"qnn"))
        self.assertEqual(widths[-1], 0)


class PackFallback(unittest.TestCase):
    """Gaps split by pointer lists: first fit can strand a long string."""

    def setUp(self):
        s = Script()
        s.text("a", "あいうえおかきくけこさ")   # 22 bytes + NUL: a 24-byte gap
        s.pointer("a")
        s.pointer("b")
        s.text("b", "あいうえお")               # 10 bytes + NUL: a 12-byte gap
        self.s, self.data = s, s.build()

    def test_longest_first_when_first_fit_fails(self):
        a, b = self.s.labels["a"], self.s.labels["b"]
        long_line = "Hello there, everyone!"   # 22 letters: 23 bytes, only fits gap a
        edit = Edit(self.data)
        patcher.apply_dialogue(block([(a, "あいうえおかきくけこさ", "Hi"),
                                      (b, "あいうえお", long_line)]),
                               edit, font.PairEncoder())
        out = bytes(edit.data)
        ptr = lambda pos: struct.unpack_from("<I", out, pos)[0] - BASE
        self.assertEqual(ptr(24), b)     # "Hi" moved into b's small gap
        self.assertEqual(ptr(28), a)     # the long line took a's big gap
        self.assertEqual(script.read_string(out, a),
                         script.encode_english(long_line, font.PairEncoder())[0])

    def test_first_fit_layout_kept_when_it_works(self):
        a, b = self.s.labels["a"], self.s.labels["b"]
        edit = Edit(self.data)
        patcher.apply_dialogue(block([(a, "あいうえおかきくけこさ", "Hi"),
                                      (b, "あいうえお", "Bye")]),
                               edit, font.PairEncoder())
        out = bytes(edit.data)
        # Both go into the first gap in file order, as before the fallback.
        self.assertEqual(struct.unpack_from("<I", out, 24)[0] - BASE, a)
        self.assertEqual(struct.unpack_from("<I", out, 28)[0] - BASE, a + 3)


class ShareIdentical(unittest.TestCase):
    """Repeated lines (DATE_FU.BIN has 31 copies of one) can share one copy."""

    def setUp(self):
        s = Script()
        for label in ("a", "b", "c"):
            s.text(label, "あいうえお")
        for label in ("a", "b", "c"):
            s.pointer(label)
        self.s, self.data = s, s.build()
        self.table = s.labels["c"] + 12

    def lines(self, third="Hello there"):
        return [(self.s.labels["a"], "あいうえお", "Hello there"),
                (self.s.labels["b"], "あいうえお", "Hello there"),
                (self.s.labels["c"], "あいうえお", third)]

    def targets(self, out):
        return [struct.unpack_from("<I", out, self.table + 4 * i)[0] - BASE for i in range(3)]

    def test_too_big_without_sharing(self):
        line = "Hello there, how are"     # 20 bytes + NUL > one 12-byte slot each
        with self.assertRaisesRegex(ValueError, "doesn't fit"):
            patcher.apply_dialogue(block([(o, j, line) for o, j, _ in self.lines()]),
                                   Edit(self.data), font.PairEncoder())

    def test_identical_strings_share_one_copy(self):
        line = "Hello there, how are"
        b = block([(o, j, line) for o, j, _ in self.lines()])
        b.share_identical = True
        edit = Edit(self.data)
        patcher.apply_dialogue(b, edit, font.PairEncoder())
        out = bytes(edit.data)
        targets = self.targets(out)
        self.assertEqual(len(set(targets)), 1)
        self.assertEqual(script.read_string(out, targets[0]),
                         script.encode_english(line, font.PairEncoder())[0])
        self.assertIn("2 sharing an identical copy", edit.log[-1])

    def test_different_strings_still_get_their_own_copy(self):
        b = block(self.lines("Bye now"))
        b.share_identical = True
        edit = Edit(self.data)
        patcher.apply_dialogue(b, edit, font.PairEncoder())
        out = bytes(edit.data)
        a, b2, c = self.targets(out)
        self.assertEqual(a, b2)
        self.assertNotEqual(a, c)
        self.assertEqual(script.read_string(out, c),
                         script.encode_english("Bye now", font.PairEncoder())[0])


class SpeakerLabels(unittest.TestCase):
    """A code-07 line may start with a prefix byte and a fixed-size label."""

    RAW = b">" + "部長".encode("shift_jis") + "はい".encode("shift_jis")

    def test_decode_and_reencode(self):
        text = script.decode(self.RAW)
        self.assertEqual(text, "{>部長}はい")
        self.assertEqual(script.encode_original(text), self.RAW)

    def test_english_label_is_padded_and_takes_no_line_width(self):
        raw, widths = script.encode_english("{-???}Hi", font.PairEncoder())
        self.assertEqual(raw[:1], b"-")
        self.assertEqual(len(raw), 1 + 6 + 2)
        self.assertEqual(widths, [2])

    def test_label_too_long_rejected(self):
        with self.assertRaises(ValueError):
            script.encode_english("{>Captain}Hi", font.PairEncoder())

    def test_structure_keeps_the_prefix(self):
        self.assertEqual(script.structure("{>Capt}Hi"), script.structure("{>部長}はい"))
        self.assertNotEqual(script.structure("Hi"), script.structure("{>部長}はい"))

    def test_lone_prefix_byte_is_not_a_label(self):
        with self.assertRaises(ValueError):
            script.decode(b">" + "部長".encode("shift_jis"))


if __name__ == "__main__":
    unittest.main()
