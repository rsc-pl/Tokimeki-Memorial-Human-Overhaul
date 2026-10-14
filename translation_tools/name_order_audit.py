#!/usr/bin/env python3
"""Check full-name order and apply source-checked corrections."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from name_order import NAMES, RECORD, ROOT, TRANSLATION, _encoder

RULES = Path(__file__).with_name("name_order_extra_rules.json")
REPORT = ROOT / ".local/translation/reports/N06/NAME_ORDER_CHANGES.tsv"
COLUMNS = ("file", "offset", "jp", "before", "after", "old_bytes", "new_bytes", "widths")


ALIASES = {"Yuko": ("Yuuko",), "Yukinojo": ("Yukinojou",)}


def western_name_matches(japanese: str, english: str):
    """Find reversed names with different spacing, case and punctuation."""
    separators = r"[\s.,:;!?/\-\'\"()\[\]]{1,8}"
    for name in NAMES:
        for given in (name.given, *ALIASES.get(name.given, ())):
            surname = re.escape(name.surname)
            escaped = re.escape(given)
            variants = (
                (rf"(?<![A-Za-z]){escaped}{separators}{surname}(?![A-Za-z])", re.IGNORECASE),
                (rf"(?<![A-Za-z]){escaped}{surname}(?![A-Za-z])", re.IGNORECASE),
                (rf"(?<![A-Za-z']){re.escape(given[0])}\.{separators}?{surname}(?![A-Za-z])", re.IGNORECASE),
            )
            if name.japanese in japanese or name.japanese_surname in japanese:
                variants += ((rf"(?<![A-Za-z']){re.escape(given[0].upper())}{separators}{surname}(?![A-Za-z])", 0),)
            yielded = set()
            for regex, flags in variants:
                for match in re.finditer(regex, english, flags=flags):
                    marker = (match.start(), match.end())
                    if marker not in yielded:
                        yielded.add(marker)
                        yield name.surname, match.group(0)


def inspect(root: Path = ROOT):
    results = []
    for path in sorted((root / "translation").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        records = data.get("strings", []) + [entry for block in data.get("dialogue", []) for entry in block["lines"]]
        for item in records:
            for surname, value in western_name_matches(item["original"], item["text"]):
                results.append((path.name, item["offset"], surname, value, item["original"], item["text"]))
    return results


def check(jp, before, after, pairs, script):
    if script.structure(jp) != script.structure(after) or script.structure(before) != script.structure(after):
        raise ValueError("line or token structure changed")
    old, _ = script.encode_english(before, pairs)
    new, widths = script.encode_english(after, pairs)
    if len(new) > len(old):
        raise ValueError("encoded length increased")
    if any(width > (28 if i == 0 else 26) for i, width in enumerate(widths)):
        raise ValueError(f"display width exceeded: {widths}")
    return len(old), len(new), widths


def apply_rules(mode: str):
    pairs, script = _encoder()
    rules = json.loads(RULES.read_text(encoding="utf-8"))
    by_file = {}
    for rule in rules:
        key = rule["offset"]
        if key in by_file.setdefault(rule["file"], {}):
            raise ValueError(f"duplicate offset: {rule['file']} {key}")
        by_file[rule["file"]][key] = rule
    changes = []
    updates = []
    for name, lookup in by_file.items():
        path = TRANSLATION / name
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        entries = [entry for block in data.get("dialogue", []) for entry in block["lines"]]
        entries += data.get("strings", [])
        offsets = {item["offset"]: item for item in entries if item["offset"] in lookup}
        if len(offsets) != len(lookup):
            raise ValueError(f"missing or duplicated records in {name}")
        replacements = {}
        for offset, rule in lookup.items():
            item = offsets[offset]
            if item["original"] != rule["original"] or item["text"] not in (rule["before"], rule["after"]):
                raise ValueError(f"unexpected source: {name} {offset}")
            old_size, new_size, widths = check(rule["original"], rule["before"], rule["after"], pairs, script)
            if item["text"] != rule["after"]:
                replacements[(offset, rule["original"], rule["before"])] = rule["after"]
                changes.append({"file": "translation/"+name, "offset": offset, "jp": rule["original"],
                                "before": rule["before"], "after": rule["after"],
                                "old_bytes": str(old_size), "new_bytes": str(new_size),
                                "widths": "/".join(map(str, widths))})
        count = [0]
        def edit(match):
            key = (match.group("offset"), json.loads(match.group("jp")), json.loads(match.group("en")))
            replacement = replacements.get(key)
            if replacement is None:
                return match.group(0)
            count[0] += 1
            return match.group("head") + json.dumps(replacement, ensure_ascii=False)
        modified = RECORD.sub(edit, content)
        if count[0] != len(replacements):
            raise ValueError(f"JSON records not matched in {name}")
        def without_text(obj):
            if isinstance(obj, dict):
                return {k: without_text(v) for k, v in obj.items() if k != "text"}
            if isinstance(obj, list):
                return [without_text(v) for v in obj]
            return obj
        if without_text(json.loads(content)) != without_text(json.loads(modified)):
            raise ValueError(f"non-English data changed in {name}")
        if modified != content:
            updates.append((path, modified))
    if mode == "verify" and changes:
        raise ValueError(f"{len(changes)} source-checked changes remain")
    if mode == "apply":
        for path, content in updates:
            path.write_text(content, encoding="utf-8")
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        with REPORT.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=COLUMNS, delimiter="\t")
            writer.writeheader()
            writer.writerows({k: v.replace("\n", "\\n") for k, v in row.items()} for row in changes)
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ("audit", "apply", "verify"):
        group.add_argument("--" + mode, action="store_true")
    args = parser.parse_args()
    mode = "apply" if args.apply else "verify" if args.verify else "audit"
    try:
        outstanding = inspect()
        changes = apply_rules(mode)
        if mode == "verify":
            outstanding = inspect()
            if outstanding:
                raise ValueError(f"{len(outstanding)} Western-order full names remain")
        print(f"{mode.upper()}: {len(changes)} changes; {len(outstanding)} reversed full names or initials")
        if mode == "audit":
            for filename, offset, surname, value, *_ in outstanding:
                print(f"  {filename}:{offset} {surname} {value!r}")
    except (OSError, ValueError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
