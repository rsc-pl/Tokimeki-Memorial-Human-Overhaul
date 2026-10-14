#!/usr/bin/env python3
"""Check translated surname references against Japanese dialogue lines."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from name_order import NAMES, RECORD, ROOT, TRANSLATION, _encoder

RULES = Path(__file__).with_name("surname_line_rules.json")
REPORT = ROOT / ".local/translation/reports/N07/SURNAME_LINE_CHANGES.tsv"
BLOCKED = ROOT / ".local/translation/reports/N05/SURNAME_UNRESOLVED.tsv"


def records(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("strings", []) + [r for b in data.get("dialogue", []) for r in b["lines"]]


def inspect():
    hits = []
    for path in sorted(TRANSLATION.glob("*.json")):
        for row in records(path):
            for number, (jp, en) in enumerate(zip(row["original"].split("\n"), row["text"].split("\n"))):
                for name in NAMES:
                    if name.japanese_surname not in jp or name.japanese_given in jp:
                        continue
                    given = rf"(?<![A-Za-z]){re.escape(name.given)}(?![A-Za-z])"
                    surname = rf"(?<![A-Za-z]){re.escape(name.surname)}(?![A-Za-z])"
                    if re.search(given, en, re.IGNORECASE) and not re.search(surname, en, re.IGNORECASE):
                        hits.append(("translation/" + path.name, row["offset"], number, name.surname))
    return hits


def apply(mode):
    definitions = json.loads(RULES.read_text(encoding="utf-8"))
    pairs, script = _encoder()
    updates = []
    edits = []
    for rule in definitions:
        path = TRANSLATION / rule["file"]
        content = path.read_text(encoding="utf-8")
        row = [r for r in records(path) if r["offset"] == rule["offset"]]
        if len(row) != 1 or row[0]["original"] != rule["original"] or row[0]["text"] not in (rule["before"], rule["after"]):
            raise ValueError("unexpected source at " + rule["file"] + ":" + rule["offset"])
        if script.structure(rule["original"]) != script.structure(rule["after"]):
            raise ValueError("line or control-code structure changed")
        old, _ = script.encode_english(rule["before"], pairs)
        new, widths = script.encode_english(rule["after"], pairs)
        if any(width > (28 if i == 0 else 26) for i, width in enumerate(widths)):
            raise ValueError("screen width exceeded")
        if row[0]["text"] == rule["after"]:
            continue
        if mode == "verify":
            raise ValueError("unapplied correction at " + rule["file"] + ":" + rule["offset"])
        replacement = [0]
        def edit(match):
            if (match.group("offset"), json.loads(match.group("jp")), json.loads(match.group("en"))) != (rule["offset"], rule["original"], rule["before"]):
                return match.group(0)
            replacement[0] += 1
            return match.group("head") + json.dumps(rule["after"], ensure_ascii=False)
        updated = RECORD.sub(edit, content)
        if replacement[0] != 1:
            raise ValueError("record replacement failed")
        edits.append((rule, len(old), len(new), widths))
        updates.append((path, updated))
    if mode == "apply":
        for path, content in updates:
            path.write_text(content, encoding="utf-8")
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        with REPORT.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file, delimiter="\t")
            writer.writerow(("file", "offset", "jp", "before", "after", "old_bytes", "new_bytes", "widths"))
            for rule, old, new, widths in edits:
                writer.writerow((rule["file"], rule["offset"], rule["original"].replace("\n", "\\n"), rule["before"].replace("\n", "\\n"), rule["after"].replace("\n", "\\n"), old, new, "/".join(map(str, widths))))
    with BLOCKED.open(encoding="utf-8", newline="") as file:
        unresolved = {(r["file"], r["offset"]) for r in csv.DictReader(file, delimiter="\t") if r["status"] == "TECHNICAL"}
    hits = inspect()
    unexpected = [(f, o, n, name) for f, o, n, name in hits if (f, o) not in unresolved]
    if mode == "verify" and unexpected:
        raise ValueError(f"{len(unexpected)} surname substitutions not in the known inventory: {unexpected[:4]}")
    print(f"{mode.upper()}: {len(edits)} corrections, {len(hits)} remaining line-local substitutions, {len(unexpected)} new findings")
    if mode == "audit":
        for f, o, n, name in unexpected:
            print(f"  {f}:{o} line {n+1}: {name}")
    return edits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ("audit", "apply", "verify"):
        group.add_argument("--"+mode, action="store_true")
    args = parser.parse_args()
    try:
        apply("apply" if args.apply else "verify" if args.verify else "audit")
        return 0
    except (ValueError, OSError) as error:
        print("FAIL:", error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
