"""Regression: the public Go builder's authoritative Python planner lists all
independent patch failures and never writes a partial disc image.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tokipatch import patcher, script


class FakeTrack:
    def __init__(self, contents):
        self.contents = contents
        self.reads = 0

    def read_file(self, lba, size):
        self.reads += 1
        return self.contents[:size]


class CollectionTests(unittest.TestCase):
    def setUp(self):
        # Three nonoverlapping fixed strings with room only for one simple
        # character apiece. All bytes are authentic for the synthetic source.
        self.original = bytearray(48)
        for pos, kana in ((0, 'あ'), (12, 'い'), (24, 'う')):
            encoded = script.encode_original(kana)
            self.original[pos:pos + len(encoded)] = encoded
        self.track = FakeTrack(bytes(self.original))
        self.entry = SimpleNamespace(is_dir=False, size=len(self.original), lba=0,
                                     path='TEST.EXN')
        self.entries = {'TEST.EXN': self.entry}

    def string(self, offset, kana, english):
        return patcher.StringPatch(file='TEST.EXN', offset=offset, original=kana,
                                   text=english, source='multi.json', slot=4)

    def run_plan(self, strings, *, collect_errors):
        with patch.object(patcher, 'list_files', return_value=self.entries), \
             patch.object(patcher, 'check_disc', return_value=None), \
             patch.object(patcher, 'has_checksum', return_value=False):
            return patcher.plan(self.track, strings, [], [], [],
                                collect_errors=collect_errors)

    def test_reports_both_oversize_strings_with_offsets(self):
        jobs = [self.string(0, 'あ', 'OVERLONG'),
                self.string(12, 'い', 'ALSO OVERLONG')]
        with self.assertRaises(patcher.PlanErrors) as cm:
            self.run_plan(jobs, collect_errors=True)
        problems = cm.exception.problems
        self.assertEqual(len(problems), 2)
        self.assertIn('0x0', problems[0])
        self.assertIn('0xc', problems[1])
        self.assertIn('2 patch error(s)', str(cm.exception))

    def test_default_python_backend_still_fails_fast(self):
        jobs = [self.string(0, 'あ', 'OVERLONG'),
                self.string(12, 'い', 'ALSO OVERLONG')]
        with self.assertRaises(ValueError) as cm:
            self.run_plan(jobs, collect_errors=False)
        self.assertNotIsInstance(cm.exception, patcher.PlanErrors)
        self.assertIn('0x0', str(cm.exception))

    def test_failed_mutation_does_not_poison_next_patch(self):
        # A failed operation mutates its scratch copy. Another operation on
        # the exact same offset must still see the original bytes.
        first = self.string(0, 'あ', 'XXX')
        second = self.string(0, 'あ', 'OK')
        seen = []
        genuine = patcher.apply_string

        def patched_apply(p, e, pairs):
            if p is first:
                e.data[:4] = b'bad!'
                e.log.append('should not escape')
                raise ValueError('first write failed after partial mutation')
            seen.append(bytes(e.data[:4]))
            return genuine(p, e, pairs)

        with patch.object(patcher, 'apply_string', side_effect=patched_apply), \
             self.assertRaises(patcher.PlanErrors) as cm:
            self.run_plan([first, second], collect_errors=True)
        self.assertEqual(len(cm.exception.problems), 1)
        self.assertEqual(seen[0], bytes(self.original[:4]))

    def test_successful_plan_is_byte_identical_to_legacy(self):
        patch_item = self.string(0, 'あ', 'A')
        patch_item.encoding = 'fullwidth'  # no renderer required
        original = self.run_plan([patch_item], collect_errors=False)
        collecting = self.run_plan([patch_item], collect_errors=True)
        self.assertEqual(len(original), 1)
        self.assertEqual(len(collecting), 1)
        self.assertEqual(original[0].data, collecting[0].data)
        self.assertEqual(original[0].log, collecting[0].log)

    def test_multiple_operation_types_reported(self):
        bad_string = self.string(0, 'あ', 'OVERLONG')
        bad_bytes = patcher.BytePatch(file='TEST.EXN', offset=32,
                                      original=b'WRONG', replacement=b'RIGHT',
                                      comment='', source='binary.json')
        with patch.object(patcher, 'list_files', return_value=self.entries), \
             patch.object(patcher, 'check_disc', return_value=None), \
             patch.object(patcher, 'has_checksum', return_value=False), \
             self.assertRaises(patcher.PlanErrors) as cm:
            patcher.plan(self.track, [bad_string], [], [bad_bytes], [],
                         collect_errors=True)
        self.assertEqual(len(cm.exception.problems), 2)
        self.assertIn('binary.json', cm.exception.problems[1])


if __name__ == '__main__':
    unittest.main()
