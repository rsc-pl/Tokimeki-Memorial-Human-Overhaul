#!/usr/bin/env python3
"""Restore surnames in repeated gift and telephone dialogue patterns."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from name_order import NAMES, RECORD, ROOT, TRANSLATION, _encoder

REPORT = ROOT / '.local' / 'translation' / 'reports' / 'N03' / 'SURNAME_PHRASES.tsv'
COLUMNS = ('file', 'offset', 'name', 'original', 'before', 'after', 'rule', 'source_bytes', 'result_bytes')


def propose(jp: str, english: str):
    lines = jp.split('\n')
    for name in NAMES:
        if name.japanese_given in jp or name.japanese_surname == '早乙女':
            continue
        if (len(lines) > 1 and
                re.fullmatch(rf'{re.escape(name.japanese_surname)}さんのプレゼントだ[！!]', lines[0]) and
                english.startswith(f'A present from {name.given}!\n')):
            return english.replace(f'A present from {name.given}!\n', f'From {name.surname}!\n', 1), name.surname, 'gift'
        if (len(lines) == 3 and
                lines[0] == 'お前って、' and
                lines[1] == f'{name.japanese_surname}さんに嫌われてるぜ' and
                lines[2] == '' and
                english == f"You know,\n{name.given} can't stand you.\n"):
            return f"Look,\n{name.surname} doesn't like you.\n", name.surname, 'telephone'
    return None


def inspect_file(path: Path, pairs, script):
    before_file = path.read_text(encoding='utf-8')
    rows = []
    def edit(match):
        jp = json.loads(match.group('jp'))
        old = json.loads(match.group('en'))
        candidate = propose(jp, old)
        if candidate is None:
            return match.group(0)
        new, name, rule = candidate
        old_bytes, _ = script.encode_english(old, pairs)
        new_bytes, widths = script.encode_english(new, pairs)
        source_bytes = script.encode_original(jp)
        if script.structure(old) != script.structure(new):
            raise ValueError(f'{path.name}:{match.group("offset")} changes control codes or line layout')
        if len(new_bytes) > len(source_bytes):
            raise ValueError(f'{path.name}:{match.group("offset")} exceeds source allocation')
        if any(w > (26 if i in (1, 2) else 28) for i, w in enumerate(widths)):
            raise ValueError(f'{path.name}:{match.group("offset")} exceeds display width')
        if old == new:
            return match.group(0)
        rows.append(dict(file=path.relative_to(ROOT).as_posix(), offset=match.group('offset'),
                         name=name, original=jp, before=old, after=new, rule=rule,
                         source_bytes=len(source_bytes), result_bytes=len(new_bytes)))
        return match.group('head') + json.dumps(new, ensure_ascii=False)
    after_file = RECORD.sub(edit, before_file)
    def fixed_fields(v):
        if isinstance(v, dict):
            return {k: fixed_fields(w) for k, w in v.items() if k != 'text'}
        if isinstance(v, list):
            return [fixed_fields(w) for w in v]
        return v
    if fixed_fields(json.loads(before_file)) != fixed_fields(json.loads(after_file)):
        raise ValueError(f'{path}: non-translation fields changed')
    return after_file, rows


def run(mode: str, report: Path = REPORT):
    pairs, script = _encoder()
    patches, changes = [], []
    for path in sorted(TRANSLATION.glob('*.json')):
        after, rows = inspect_file(path, pairs, script)
        if rows:
            patches.append((path, after))
            changes.extend(rows)
    if mode == 'verify' and changes:
        raise ValueError(f'{len(changes)} source-matched surname phrases remain')
    if mode == 'apply':
        for path, content in patches:
            path.write_text(content, encoding='utf-8')
        report.parent.mkdir(parents=True, exist_ok=True)
        with report.open('w', encoding='utf-8', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=COLUMNS, delimiter='\t')
            writer.writeheader()
            for row in changes:
                writer.writerow({k: str(row[k]).replace('\n', '\\n').replace('\t', '\\t') for k in COLUMNS})
    print(f'{mode.upper()}: {len(changes)} records in {len(patches)} files')
    if mode == 'audit':
        for r in changes:
            print(f"{r['file']}:{r['offset']} {r['rule']} {r['before']!r} -> {r['after']!r}")
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--audit', action='store_true')
    group.add_argument('--apply', action='store_true')
    group.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    try:
        run('apply' if args.apply else 'verify' if args.verify else 'audit')
    except (OSError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
