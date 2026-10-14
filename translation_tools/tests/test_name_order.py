"""Check name order and text layout."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import name_order as names


class NameOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs, cls.script = names._encoder()

    def test_full_name_swapped(self):
        jp = "私、片桐彩子。"
        en = "I'm Ayako Katagiri."
        after, matched = names._replace(jp, en)
        self.assertEqual(after, "I'm Katagiri Ayako.")
        self.assertEqual(matched, ["片桐彩子"])
        names._validate_change(jp, en, after, self.pairs, self.script)

    def test_abbreviated_labels_keep_size(self):
        for japanese, before, after in (
            ("藤崎詩織", "S. Fujisaki", "Fujisaki S."),
            ("片桐彩子", "A Katagiri", "Katagiri A"),
            ("早乙女優美", "Y. Saotome", "Saotome Y."),
            ("早乙女好雄", "Y. Saotome", "Saotome Y."),
        ):
            with self.subTest(before=before, japanese=japanese):
                actual, matched = names._replace(japanese, before)
                self.assertEqual(actual, after)
                self.assertEqual(matched, [japanese])
                names._validate_change(japanese, before, actual, self.pairs, self.script)

    def test_does_not_guess_shared_surname(self):
        self.assertEqual(names._replace("早乙女さん", "Y. Saotome"), ("Y. Saotome", []))

    def test_keeps_single_names(self):
        self.assertEqual(names._replace("片桐さんだ。", "Ayako really came through."),
                         ("Ayako really came through.", []))

    def test_does_not_modify_honorifics_or_tokens(self):
        old = "Meet Ayako Katagiri-san.\nAsk {G} later."
        new, _ = names._replace("片桐彩子さん、{G}", old)
        self.assertEqual(new, "Meet Katagiri Ayako-san.\nAsk {G} later.")
        names._validate_change("片桐彩子さん、{G}", old, new, self.pairs, self.script)

    def test_does_not_touch_other_characters_or_japanese(self):
        self.assertEqual(names._replace("由美", "I'm Yumi Saotome."), ("I'm Yumi Saotome.", []))
        self.assertEqual(names._replace("虹野沙希", "I'm Nijino Saki."), ("I'm Nijino Saki.", []))

    def test_all_name_changes_idempotent(self):
        for japanese, given, surname in ((n.japanese, n.given, n.surname) for n in names.NAMES):
            before = f"I'm {given} {surname}."
            after, _ = names._replace(japanese, before)
            self.assertEqual(names._replace(japanese, after), (after, []))

    def test_repository_contains_no_remaining_safe_candidates(self):
        remaining = names.run("audit")
        self.assertEqual(remaining, [], remaining[:5])


if __name__ == "__main__":
    unittest.main()
