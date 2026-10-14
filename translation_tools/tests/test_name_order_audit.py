"""Verify full-name order and the edited text records."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import name_order_audit as audit


class FullNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads(audit.RULES.read_text(encoding="utf-8"))
        cls.pairs, cls.script = audit._encoder()

    def test_multiline_detection(self):
        self.assertEqual(list(audit.western_name_matches("虹野沙希", "Saki\nNijino")),
                         [("Nijino", "Saki\nNijino")])

    def test_uppercase_detection(self):
        self.assertEqual(list(audit.western_name_matches("ヒモオ ユイナ サマ", "LADY YUINA HIMOO")),
                         [("Himoo", "YUINA HIMOO")])

    def test_reversed_initial_detection(self):
        self.assertEqual(list(audit.western_name_matches("虹野沙希", "S. Nijino")),
                         [("Nijino", "S. Nijino")])

    def test_punctuation_and_case(self):
        examples = ("YUINA / HIMOO", "Yuina, Himoo", "yuina\nHIMOO", "YuinaHimoo", "Y. HIMOO", "y. himoo")
        for english in examples:
            with self.subTest(english=english):
                self.assertTrue(list(audit.western_name_matches("紐緒結奈", english)))

    def test_alternative_long_vowel_spellings(self):
        self.assertTrue(list(audit.western_name_matches("朝日奈夕子", "Yuuko Asahina")))
        self.assertTrue(list(audit.western_name_matches("外井雪之丞", "Yukinojou Sotoi")))

    def test_separate_phrases_not_a_full_name(self):
        english = "A present from Mira!\nA Kagami Mira promo video?"
        self.assertEqual(list(audit.western_name_matches("鏡魅羅", english)), [])

    def test_correct_order_not_flagged(self):
        self.assertEqual(list(audit.western_name_matches("虹野沙希", "Nijino Saki")), [])

    def test_no_partial_word_matches(self):
        self.assertEqual(list(audit.western_name_matches("虹野沙希", "XSaki NijinoY")), [])

    def test_sources_match(self):
        for rule in self.rules:
            with self.subTest(file=rule['file'], offset=rule['offset']):
                data = json.loads((audit.TRANSLATION / rule['file']).read_text(encoding="utf-8"))
                rows = [r for block in data.get('dialogue', []) for r in block['lines']]
                hits = [r for r in rows if r['offset'] == rule['offset']]
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['original'], rule['original'])
                self.assertEqual(hits[0]['text'], rule['after'])

    def test_encoded_sizes_and_width(self):
        for rule in self.rules:
            with self.subTest(file=rule['file'], offset=rule['offset']):
                before, after, widths = audit.check(rule['original'], rule['before'], rule['after'],
                                                    self.pairs, self.script)
                self.assertLessEqual(after, before)
                self.assertEqual(len(widths), rule['original'].count('\n') + 1)

    def test_global_search_and_reapply(self):
        self.assertEqual(audit.inspect(), [])
        self.assertEqual(audit.apply_rules('verify'), [])


if __name__ == '__main__':
    unittest.main()
