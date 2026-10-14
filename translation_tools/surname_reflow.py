#!/usr/bin/env python3
"""Apply verified dialogue replacements while preserving line and control layout."""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path
from name_order import RECORD, ROOT, TRANSLATION, _encoder

RULES = Path(__file__).with_name('surname_reflow_rules.json')
REPORT = ROOT / '.local/translation/reports/N05/SURNAME_REFLOW.tsv'
COLUMNS = ('file', 'offset', 'jp', 'before', 'after', 'reason', 'old_bytes', 'new_bytes', 'widths')


def check(original, before, after, pairs, script):
    if script.structure(original) != script.structure(after):
        raise ValueError('script structure changed')
    if script.structure(before) != script.structure(after):
        raise ValueError('dialogue line or token placement changed')
    old, _ = script.encode_english(before, pairs)
    new, widths = script.encode_english(after, pairs)
    if any(w > (28 if i == 0 else 26) for i, w in enumerate(widths)):
        raise ValueError(f'display overflow: {widths}')
    return len(old), len(new), widths


def run(mode):
    pairs, script = _encoder()
    rules = json.loads(RULES.read_text(encoding='utf-8'))
    keyed = {}
    for rule in rules:
        key = (rule['file'], rule['offset'])
        if key in keyed:
            raise ValueError(f'duplicate source {key}')
        keyed[key] = rule
    files = {}
    for key, rule in keyed.items():
        files.setdefault(key[0], {})[key[1]] = rule
    changed, updated, seen = [], [], set()
    for file, lookup in files.items():
        path = TRANSLATION / file
        content = path.read_text(encoding='utf-8')
        doc = json.loads(content)
        rows = [row for block in doc.get('dialogue', []) for row in block['lines']]
        found = {}
        for row in rows:
            if row['offset'] in lookup:
                if row['offset'] in found:
                    raise ValueError(f'duplicate record {file} {row["offset"]}')
                found[row['offset']] = row
        replacements = {}
        for offset, rule in lookup.items():
            row = found.get(offset)
            if row is None or row['original'] != rule['original']:
                raise ValueError(f'Japanese source does not match {file} {offset}')
            if row['text'] not in (rule['before'], rule['after']):
                raise ValueError(f'English source does not match {file} {offset}')
            old_bytes, new_bytes, widths = check(rule['original'], rule['before'], rule['after'], pairs, script)
            seen.add((file, offset))
            if row['text'] == rule['before']:
                changed.append(dict(file='translation/'+file, offset=offset, jp=rule['original'],
                                    before=rule['before'], after=rule['after'], reason=rule['reason'],
                                    old_bytes=str(old_bytes), new_bytes=str(new_bytes), widths='/'.join(map(str,widths))))
                replacements[(offset,rule['original'],rule['before'])] = rule['after']
        count = [0]
        def edit(match):
            key = (match.group('offset'),json.loads(match.group('jp')),json.loads(match.group('en')))
            value = replacements.get(key)
            if value is None:
                return match.group(0)
            count[0] += 1
            return match.group('head') + json.dumps(value,ensure_ascii=False)
        result = RECORD.sub(edit, content)
        if count[0] != len(replacements):
            raise ValueError(f'file layout not recognized: {file}')
        if result != content:
            updated.append((path, result))
    if seen != set(keyed):
        raise ValueError('uninspected records')
    if mode == 'verify' and changed:
        raise ValueError(f'{len(changed)} corrections still pending')
    if mode == 'apply':
        for path, result in updated:
            path.write_text(result,encoding='utf-8')
        REPORT.parent.mkdir(parents=True,exist_ok=True)
        with REPORT.open('w', encoding='utf-8', newline='') as fh:
            writer=csv.DictWriter(fh,delimiter='\t',fieldnames=COLUMNS)
            writer.writeheader()
            for row in changed:
                writer.writerow({k:v.replace('\n','\\n').replace('\t','\\t') for k,v in row.items()})
    print(f'{mode.upper()}: {len(changed)} replacements, {len(updated)} files')
    return changed


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_mutually_exclusive_group(required=True)
    for action in ('audit','apply','verify'):
        actions.add_argument('--'+action,action='store_true')
    args=parser.parse_args()
    try:
        run('apply' if args.apply else 'verify' if args.verify else 'audit')
    except (ValueError,OSError) as error:
        print('FAIL:',error,file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
