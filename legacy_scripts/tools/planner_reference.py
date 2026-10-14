"""Read-only Python planner oracle for synthetic PS1 dialogue relocations.

JSON list on stdin; each item contains synthetic byte-array as base64 plus
DialogueBlock JSON fields. Returns status, SHA-256 and placements, never game
content or translation strings. Only used by tests, never production builds.
"""
import base64
import hashlib
import json
import re
import sys
from types import SimpleNamespace
from tokipatch import font, patcher

PATTERN = re.compile(r"^(0x[0-9a-f]+) -> (0x[0-9a-f]+):")


def run(item):
    original = base64.b64decode(item["data"])
    edit = SimpleNamespace(original=original, data=bytearray(original), log=[])
    kind = item.get("kind", "dialogue")
    block = item.get("block", {})
    if kind == "dialogue":
        instance = patcher.DialogueBlock(
        file=block.get("file", "SYNTHETIC.BIN"),
        source=block.get("source", "G04"),
        base=block["base"],
        lines=[patcher.DialogueLine(x["offset"], x["original"], x["text"])
               for x in block["lines"]],
        max_cells=block.get("max_cells", 28),
        share_identical=block.get("share_identical", False),
    )
    try:
        if kind == "dialogue":
            patcher.apply_dialogue(instance, edit, font.PairEncoder())
        elif kind == "string":
            patch = patcher.StringPatch(file="SYNTHETIC.BIN", source="G04", offset=item["offset"],
                                       original=item["original"], text=item["text"],
                                       encoding=item.get("encoding", "pairs"), slot=item.get("slot"))
            patcher.apply_string(patch, edit, font.PairEncoder())
        elif kind == "bytes":
            patch = patcher.BytePatch(file="SYNTHETIC.BIN", source="G04", offset=item["offset"],
                                      original=bytes.fromhex(item["original"]),
                                      replacement=bytes.fromhex(item["replacement"]), comment="")
            if len(patch.original) != len(patch.replacement):
                raise ValueError("raw bytes patch changes length (validated by load_translations)")
            patcher.apply_bytes(patch, edit)
        else:
            raise ValueError("unknown patch kind")
    except (ValueError, IndexError, AssertionError) as exc:
        return {"ok": False, "error": str(exc)}
    placements = [[int(x.group(1), 16), int(x.group(2), 16)]
                  for line in edit.log if (x := PATTERN.match(line))]
    return {"ok": True, "sha256": hashlib.sha256(edit.data).hexdigest(),
            "placements": placements, "summary": edit.log[-1] if edit.log else ""}


def main():
    cases = json.load(sys.stdin)
    json.dump([run(item) for item in cases], sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
