"""Check surname substitutions and their technical limits."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import surname_names as tool


class SurnameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs, cls.script = tool._encoder()

    def options(self, jp, en, kind='dialogue', slot=None):
        return tool.candidates(jp, en, kind, slot, 0, self.pairs, self.script)

    def test_direct_surname(self):
        result = self.options('紐緒さんのプレゼントだ！', 'A present from Yuina!')
        self.assertEqual([(x[0].surname, x[1], x[2]) for x in result],
                         [('Himoo', 'A present from Himoo!', 'READY')])

    def test_given_name_remains_given(self):
        self.assertEqual(self.options('優美ちゃんは元気？', 'Is Yumi doing okay?'), [])

    def test_full_name_needs_review(self):
        result = self.options('紐緒結奈', 'Yuina')
        self.assertEqual(result[0][2], 'REVIEW')

    def test_shared_surname_needs_review(self):
        result = self.options('早乙女は来た？', 'Is Yumi here?')
        self.assertEqual(result[0][2], 'REVIEW')

    def test_mirror_word_needs_review(self):
        result = self.options('鏡を見て', 'Mira?')
        self.assertEqual(result[0][2], 'REVIEW')

    def test_inplace_string_capacity(self):
        result = self.options('藤崎', 'Shiori', 'strings')
        self.assertEqual(result[0][2], 'TECHNICAL')

    def test_slotted_string(self):
        result = self.options('虹野さんの１／８フィギュア', '1/8 scale Saki', 'strings', 33)
        self.assertEqual(result[0][1], '1/8 scale Nijino')
        self.assertEqual(result[0][2], 'READY')

    def test_line_mismatch(self):
        result = self.options('紐緒さんと公園へ行った\nだよ', 'I saw Yuina\nyesterday')
        self.assertEqual(result[0][2], 'READY')
        result = self.options('紐緒さんと公園へ行った\nだよ', 'Yesterday\nI saw Yuina')
        self.assertEqual(result[0][2], 'REVIEW')

    def test_runtime_table_limit(self):
        result = self.options('館林', 'Miharu', 'dialogue')
        self.assertEqual(result[0][2], 'TECHNICAL')

    def test_repository_has_no_pending_safe_changes(self):
        rows = tool.run('verify')
        self.assertFalse([r for r in rows if r['status'] == 'READY'])


if __name__ == '__main__':
    unittest.main()
