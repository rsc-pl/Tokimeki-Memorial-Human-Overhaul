#!/usr/bin/env python3
"""Apply source-checked surname corrections without changing script layout."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from name_order import RECORD, ROOT, TRANSLATION, _encoder

RULES = Path(__file__).with_name('surname_context_rules.json')
REPORT = ROOT / '.local/translation/reports/N04/SURNAME_CONTEXT.tsv'
COLUMNS = ('file', 'offset', 'original', 'before', 'after', 'description', 'source_bytes', 'result_bytes')


def validate(original, old, new, kind, slot, pairs, script):
    before_bytes, _ = script.encode_english(old, pairs)
    after_bytes, widths = script.encode_english(new, pairs)
    budget = len(script.encode_original(original))
    if script.structure(old) != script.structure(new):
        raise ValueError('line layout or control codes differ')
    if any(w > (26 if i in (1, 2) else 28) for i, w in enumerate(widths)):
        raise ValueError('screen width exceeded')
    if kind == 'strings':
        if len(after_bytes) + 1 > (slot if slot is not None else budget + 1):
            raise ValueError('in-place string exceeds its slot')
    return budget, len(after_bytes)


def run(mode, report=REPORT):
    pairs, script = _encoder()
    definitions = json.loads(RULES.read_text(encoding='utf-8'))
    keys = set()
    by_file = {}
    for rule in definitions:
        key = (rule['file'], rule['offset'])
        if key in keys:
            raise ValueError(f'duplicate record: {key}')
        keys.add(key)
        by_file.setdefault(rule['file'], {})[rule['offset']] = rule
    changed, updates, inspected = [], [], set()
    for fname, rules in by_file.items():
        path = TRANSLATION / fname
        data = json.loads(path.read_text(encoding='utf-8'))
        indexed = {}
        for kind in ('strings', 'dialogue'):
            entries = data.get('strings', []) if kind == 'strings' else [e for block in data.get('dialogue', []) for e in block.get('lines', [])]
            for entry in entries:
                if entry['offset'] in rules:
                    key = entry['offset']
                    if key in indexed:
                        raise ValueError(f'{fname}:{key}: duplicate offset')
                    indexed[key] = (kind, entry)
        substitutions = {}
        for offset, rule in rules.items():
            if offset not in indexed:
                raise ValueError(f'{fname}:{offset}: record missing')
            kind, entry = indexed[offset]
            if entry['original'] != rule['original']:
                raise ValueError(f'{fname}:{offset}: Japanese source differs')
            if entry['text'] not in (rule['before'], rule['after']):
                raise ValueError(f'{fname}:{offset}: unexpected English text')
            budget, size = validate(entry['original'], rule['before'], rule['after'], kind, entry.get('slot'), pairs, script)
            inspected.add((fname, offset))
            if entry['text'] == rule['before']:
                substitutions[(offset, entry['original'], entry['text'])] = rule['after']
                changed.append(dict(file=f'translation/{fname}', offset=offset, original=entry['original'],
                                    before=rule['before'], after=rule['after'], description=rule['description'],
                                    source_bytes=budget, result_bytes=size))
        source = path.read_text(encoding='utf-8')
        replacements = [0]
        def edit(match):
            key = (match.group('offset'), json.loads(match.group('jp')), json.loads(match.group('en')))
            if key not in substitutions:
                return match.group(0)
            replacements[0] += 1
            return match.group('head') + json.dumps(substitutions[key], ensure_ascii=False)
        result = RECORD.sub(edit, source)
        if replacements[0] != len(substitutions):
            raise ValueError(f'{fname}: replacement count differs')
        def without_text(value):
            if isinstance(value, dict):
                return {k: without_text(v) for k, v in value.items() if k != 'text'}
            if isinstance(value, list):
                return [without_text(x) for x in value]
            return value
        if without_text(json.loads(source)) != without_text(json.loads(result)):
            raise ValueError(f'{fname}: non-English fields changed')
        if result != source:
            updates.append((path, result))
    if inspected != keys:
        raise ValueError('not all records were inspected')
    if mode == 'verify' and changed:
        raise ValueError(f'{len(changed)} surname corrections remain')
    if mode == 'apply':
        for path, content in updates:
            path.write_text(content, encoding='utf-8')
        report.parent.mkdir(parents=True, exist_ok=True)
        with report.open('w', encoding='utf-8', newline='') as fh:
            writer = csv.DictWriter(fh, fieldnames=COLUMNS, delimiter='\t')
            writer.writeheader()
            for row in changed:
                writer.writerow({k: str(v).replace('\n', '\\n').replace('\t', '\\t') for k, v in row.items()})
    print(f'{mode.upper()}: {len(changed)} source-checked records across {len(updates)} files')
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    for name in ('audit', 'apply', 'verify'):
        action.add_argument(f'--{name}', action='store_true')
    args = parser.parse_args()
    try:
        run('apply' if args.apply else 'verify' if args.verify else 'audit')
    except (OSError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
