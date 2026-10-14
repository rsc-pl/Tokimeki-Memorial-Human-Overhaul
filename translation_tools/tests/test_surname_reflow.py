"""Check dialogue replacements against the existing text encoder."""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import surname_reflow as tool

class SurnameReflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules=json.loads(tool.RULES.read_text(encoding='utf-8'))
        cls.pairs,cls.script=tool._encoder()

    def test_dialogue_structure_and_widths(self):
        for rule in self.rules:
            with self.subTest(file=rule['file'], offset=rule['offset']):
                old,new,widths=tool.check(rule['original'],rule['before'],rule['after'],self.pairs,self.script)
                self.assertEqual(len(widths),rule['original'].count('\n')+1)
                self.assertTrue(all(w <= (28 if i==0 else 26) for i,w in enumerate(widths)))
                self.assertGreater(old,0)
                self.assertGreater(new,0)

    def test_correct_japanese_and_current_english(self):
        for rule in self.rules:
            doc=json.loads((tool.TRANSLATION/rule['file']).read_text(encoding='utf-8'))
            hits=[row for block in doc['dialogue'] for row in block['lines'] if row['offset']==rule['offset']]
            self.assertEqual(len(hits),1)
            self.assertEqual(hits[0]['original'],rule['original'])
            self.assertEqual(hits[0]['text'],rule['after'])

    def test_overflow_rejected(self):
        r=self.rules[0]
        with self.assertRaisesRegex(ValueError,'display overflow'):
            tool.check(r['original'],r['before'],r['after'].replace('Katagiri','KatagiriXXXXXXXX'),self.pairs,self.script)

    def test_repeat_is_clean(self):
        self.assertEqual(tool.run('verify'),[])

if __name__=='__main__':
    unittest.main()
