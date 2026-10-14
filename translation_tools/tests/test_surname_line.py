"""Test source-aligned surname corrections."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import surname_line


class SurnameLineTests(unittest.TestCase):
    def test_rules_are_applied(self):
        for rule in json.loads(surname_line.RULES.read_text(encoding="utf-8")):
            path = surname_line.TRANSLATION / rule["file"]
            found = [r for r in surname_line.records(path) if r["offset"] == rule["offset"]]
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["original"], rule["original"])
            self.assertEqual(found[0]["text"], rule["after"])

    def test_no_unknown_line_mismatches(self):
        self.assertEqual(surname_line.apply("verify"), [])


if __name__ == "__main__":
    unittest.main()
