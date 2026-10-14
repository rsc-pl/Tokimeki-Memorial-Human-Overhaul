#!/usr/bin/env python3
"""Restore Japanese surnames where a translated line uses a given name instead."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from name_order import NAMES, RECORD, ROOT, TRANSLATION, _encoder

REPORT_DIR = ROOT / '.local' / 'translation' / 'reports' / 'N02'
FIELDS = ('file', 'offset', 'kind', 'name', 'original', 'before', 'after', 'status', 'reason')


def candidates(original: str, english: str, kind: str, slot: int | None, offset: int, pairs, script):
    found = []
    for name in NAMES:
        pattern = re.compile(rf'(?<![A-Za-z]){re.escape(name.given)}(?![A-Za-z])')
        if not pattern.search(english) or name.japanese_surname not in original:
            continue
        if name.surname in english:
            continue
        new = pattern.sub(name.surname, english)
        status = 'READY'
        reason = ''
        if kind == 'dialogue' and offset in (0x72DB0, 0x72DC4) and original in ('鏡', '早乙女'):
            status, reason = 'TECHNICAL', 'Name-table surname requires allocation and runtime-reference checks'
        elif name.japanese_given in original:
            status, reason = 'REVIEW', 'Japanese gives a full name'
        elif name.japanese_surname == '早乙女':
            status, reason = 'REVIEW', 'Surname belongs to two characters'
        elif name.japanese_surname == '鏡' and not re.search(r'鏡(?:さん|様|ちゃん|君|くん|「|『)', original):
            status, reason = 'REVIEW', 'Surname also occurs as an ordinary word'
        elif any(other != name and other.japanese_surname in original for other in NAMES):
            status, reason = 'REVIEW', 'Several names occur in Japanese'
        else:
            src_lines, en_lines = original.split('\n'), english.split('\n')
            src_positions = [i for i, s in enumerate(src_lines) if name.japanese_surname in s]
            en_positions = [i for i, s in enumerate(en_lines) if pattern.search(s)]
            if src_positions != en_positions or len(en_positions) != 1:
                status, reason = 'REVIEW', 'Name is on a different or repeated display line'
        if status == 'READY':
            try:
                before_bytes, before_widths = script.encode_english(english, pairs)
                after_bytes, after_widths = script.encode_english(new, pairs)
                original_bytes = script.encode_original(original)
                if script.structure(english) != script.structure(new):
                    status, reason = 'REVIEW', 'Control-code structure changed'
                elif any(w > (26 if i in (1, 2) else 28) for i, w in enumerate(after_widths)):
                    status, reason = 'REVIEW', 'Display width exceeds the current limit'
                elif kind == 'strings':
                    capacity = slot if slot is not None else len(original_bytes) + 1
                    if len(after_bytes) + 1 > capacity and len(after_bytes) > len(before_bytes):
                        status, reason = 'TECHNICAL', 'In-place string needs a larger slot'
                elif len(after_bytes) > len(original_bytes):
                    status, reason = 'TECHNICAL', 'Check shared dialogue pool and pointers; individual Japanese bytes are not a strict limit'
                if status == 'READY':
                    for oldline, newline in zip(english.split('\n'), new.split('\n')):
                        for m in re.finditer(r'\{[A-Za-z]\}', oldline):
                            oldrun = re.split(r'\{[A-Za-z]\}', oldline[:m.start()])[-1]
                            newrun = re.split(r'\{[A-Za-z]\}', newline[:m.start() + len(newline)-len(oldline)])[-1]
                            if len(oldrun) % 2 != len(newrun) % 2:
                                status, reason = 'REVIEW', 'Pair padding before a control code may change'
                                break
                        if status != 'READY':
                            break
            except (ValueError, UnicodeError) as e:
                status, reason = 'REVIEW', 'Encoding error: ' + str(e)
        found.append((name, new, status, reason))
    return found


def inspect_file(path: Path, pairs, script):
    text = path.read_text(encoding='utf-8')
    data = json.loads(text)
    records = []
    patches = {}
    for kind in ('strings', 'dialogue'):
        entries = data.get('strings', []) if kind == 'strings' else [entry for block in data.get('dialogue', []) for entry in block.get('lines', [])]
        for entry in entries:
            original, old = entry['original'], entry['text']
            offset = entry['offset']
            results = candidates(original, old, kind, entry.get('slot'), int(offset, 0), pairs, script)
            if not results:
                continue
            for name, new, status, reason in results:
                records.append(dict(file=path.relative_to(ROOT).as_posix(), offset=offset, kind=kind,
                                    name=name.surname, original=original, before=old, after=new,
                                    status=status, reason=reason))
            if len(results) == 1 and results[0][2] == 'READY':
                patches[(offset, original, old)] = results[0][1]
    edited = 0
    def substitute(m):
        nonlocal edited
        key = (m.group('offset'), json.loads(m.group('jp')), json.loads(m.group('en')))
        if key not in patches:
            return m.group(0)
        edited += 1
        return m.group('head') + json.dumps(patches[key], ensure_ascii=False)
    new_text = RECORD.sub(substitute, text)
    applied = [row for row in records if row['status'] == 'READY']
    if edited != len(applied):
        raise ValueError(f'{path}: expected {len(applied)} changes, found {edited}')
    old_data, new_data = json.loads(text), json.loads(new_text)
    def without_english(value):
        if isinstance(value, dict):
            return {k: without_english(v) for k, v in value.items() if k != 'text'}
        if isinstance(value, list):
            return [without_english(v) for v in value]
        return value
    if without_english(old_data) != without_english(new_data):
        raise ValueError(f'{path}: fields other than text changed')
    return new_text, records


def write_tsv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS, delimiter='\t')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: str(row[k]).replace('\n', '\\n').replace('\t', '\\t') for k in FIELDS})


def run(mode: str, report_dir: Path = REPORT_DIR):
    pairs, script = _encoder()
    rows, updates = [], []
    for path in sorted(TRANSLATION.glob('*.json')):
        changed, entries = inspect_file(path, pairs, script)
        rows += entries
        if changed != path.read_text(encoding='utf-8'):
            updates.append((path, changed))
    if mode == 'verify' and updates:
        raise ValueError(f'{len(updates)} files still contain eligible surname replacements')
    if mode == 'apply':
        for path, content in updates:
            path.write_text(content, encoding='utf-8')
        write_tsv(report_dir / 'SURNAME_CHANGES.tsv', [r for r in rows if r['status'] == 'READY'])
        write_tsv(report_dir / 'SURNAME_REVIEW.tsv', [r for r in rows if r['status'] != 'READY'])
    from collections import Counter
    counts = Counter(r['status'] for r in rows)
    print(f"{mode.upper()}: " + ', '.join(f'{key}={counts[key]}' for key in ('READY','TECHNICAL','REVIEW')))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--audit', action='store_true')
    choice.add_argument('--apply', action='store_true')
    choice.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    try:
        run('apply' if args.apply else 'verify' if args.verify else 'audit')
    except (ValueError, OSError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
