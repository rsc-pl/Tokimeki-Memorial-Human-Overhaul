"""Check source-anchored name corrections and encoding limits."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import surname_context as tool


class SurnameContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads(tool.RULES.read_text(encoding='utf-8'))
        cls.pairs, cls.script = tool._encoder()

    def test_all_changes_fit(self):
        self.assertEqual(len(self.rules), 15)
        for rule in self.rules:
            with self.subTest(file=rule['file'], offset=rule['offset']):
                path = tool.TRANSLATION / rule['file']
                data = json.loads(path.read_text(encoding='utf-8'))
                strings = [('strings', x) for x in data.get('strings', [])]
                dialogues = [('dialogue', x) for block in data.get('dialogue', []) for x in block.get('lines', [])]
                matches = [(kind, x) for kind, x in strings + dialogues if x['offset'] == rule['offset']]
                self.assertEqual(len(matches), 1)
                kind, record = matches[0]
                self.assertEqual(record['original'], rule['original'])
                self.assertEqual(record['text'], rule['after'])
                tool.validate(record['original'], rule['before'], rule['after'], kind, record.get('slot'), self.pairs, self.script)

    def test_name_and_speaker_remain_distinct(self):
        rule = next(x for x in self.rules if x['file'] == 'trip_battles.json' and x['offset'] == '0x2AC30')
        self.assertEqual(rule['after'], "Saotome: Yumi's bored!")

    def test_direct_address_is_not_third_person(self):
        rule = next(x for x in self.rules if x['file'] == 'new_year.json' and x['offset'] == '0x744c')
        self.assertEqual(rule['after'], 'Close to what?\nWhat did you get,\nKatagiri?')

    def test_reapplication_finds_no_changes(self):
        self.assertEqual(tool.run('verify'), [])


if __name__ == '__main__':
    unittest.main()
