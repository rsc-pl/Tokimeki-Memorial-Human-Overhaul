"""Test repeated surname substitutions and source constraints."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import surname_phrases as tool


class SurnamePhraseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs, cls.script = tool._encoder()

    def test_gift(self):
        result = tool.propose('如月さんのプレゼントだ！\nゲーテの詩集か…\n彼女らしいな。',
                              "A present from Mio!\nPoems by Goethe...\nThat's so like her.")
        self.assertEqual(result[0], "From Kisaragi!\nPoems by Goethe...\nThat's so like her.")
        self.assertEqual(result[2], 'gift')

    def test_phone(self):
        result = tool.propose('お前って、\n鏡さんに嫌われてるぜ\n',
                              "You know,\nMira can't stand you.\n")
        self.assertEqual(result[0], "Look,\nKagami doesn't like you.\n")
        old = "You know,\nMira can't stand you.\n"
        new = result[0]
        enc, widths = self.script.encode_english(new, self.pairs)
        self.assertLessEqual(len(enc), len(self.script.encode_original('お前って、\n鏡さんに嫌われてるぜ\n')))
        self.assertEqual(self.script.structure(old), self.script.structure(new))
        self.assertLessEqual(widths[1], 26)

    def test_given_name_stays_when_source_uses_it(self):
        self.assertIsNone(tool.propose('如月未緒のプレゼントだ！\n素敵。', 'A present from Mio!\nHow nice.'))

    def test_different_phrase_is_not_rewritten(self):
        self.assertIsNone(tool.propose('鏡さんは大丈夫？\n', "You know,\nMira can't stand you.\n"))

    def test_ambiguous_family_is_untouched(self):
        self.assertIsNone(tool.propose('早乙女さんのプレゼントだ！\n', 'A present from Yumi!\n'))

    def test_repository_has_no_pending_matches(self):
        self.assertEqual(tool.run('verify'), [])


if __name__ == '__main__':
    unittest.main()
