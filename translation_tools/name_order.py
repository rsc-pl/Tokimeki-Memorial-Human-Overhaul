#!/usr/bin/env python3
"""Reorder unambiguous Japanese character names in the existing English JSON.

This only changes Western given-name/surname order. It does not add or remove
honorifics, expand initials, normalize long vowels, or change dynamic names.

    python3 translation_tools/name_order.py --audit
    python3 translation_tools/name_order.py --apply
    python3 translation_tools/name_order.py --verify

The JSON's original formatting is kept, so Git shows only changed records.
The script can be rerun safely. It requires only the Python standard library
and the existing legacy PS1 encoder for capacity comparisons.
"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TRANSLATION = ROOT / "translation"
DEFAULT_REPORT = ROOT / ".local" / "translation" / "reports" / "N01" / "NAME_ORDER_CHANGES.tsv"

# All entries in JP surname/given-name order. Romanization is deliberately
# identical to upstream: long-vowel spelling belongs to another checkpoint.
@dataclass(frozen=True)
class Name:
    japanese: str
    japanese_surname: str
    japanese_given: str
    given: str
    surname: str


NAMES = (
    Name('藤崎詩織', '藤崎', '詩織', 'Shiori', 'Fujisaki'),
    Name('如月未緒', '如月', '未緒', 'Mio', 'Kisaragi'),
    Name('紐緒結奈', '紐緒', '結奈', 'Yuina', 'Himoo'),
    Name('片桐彩子', '片桐', '彩子', 'Ayako', 'Katagiri'),
    Name('虹野沙希', '虹野', '沙希', 'Saki', 'Nijino'),
    Name('古式ゆかり', '古式', 'ゆかり', 'Yukari', 'Koshiki'),
    Name('清川望', '清川', '望', 'Nozomi', 'Kiyokawa'),
    Name('鏡魅羅', '鏡', '魅羅', 'Mira', 'Kagami'),
    Name('朝日奈夕子', '朝日奈', '夕子', 'Yuko', 'Asahina'),
    Name('美樹原愛', '美樹原', '愛', 'Megumi', 'Mikihara'),
    Name('早乙女優美', '早乙女', '優美', 'Yumi', 'Saotome'),
    Name('館林見晴', '館林', '見晴', 'Miharu', 'Tatebayashi'),
    Name('伊集院レイ', '伊集院', 'レイ', 'Rei', 'Ijuin'),
    Name('早乙女好雄', '早乙女', '好雄', 'Yoshio', 'Saotome'),
    Name('外井雪之丞', '外井', '雪之丞', 'Yukinojo', 'Sotoi'),
)

# Record matcher permits both indented and one-line records, but never reads
# or writes a description, source JP string, executable mapping or control code.
RECORD = re.compile(
    r'(?P<head>"offset"\s*:\s*"(?P<offset>[^"\\]+)"\s*,\s*'
    r'"original"\s*:\s*(?P<jp>"(?:\\.|[^"\\])*")\s*,\s*'
    r'"text"\s*:\s*)(?P<en>"(?:\\.|[^"\\])*")'
)


def _encoder():
    sys.path.insert(0, str(ROOT / "legacy_scripts"))
    from tokipatch import font, script
    return font.PairEncoder(), script


def _replace(jp: str, english: str) -> tuple[str, list[str]]:
    """Return transformed string and full names changed, without case guessing."""
    updated = english
    matched = []
    for name in NAMES:
        given, surname = re.escape(name.given), re.escape(name.surname)
        # Restrict swaps to names attested in the same Japanese record.
        # A shared surname is not enough for an abbreviated initial.
        jp_attests_person = name.japanese in jp or (
            name.japanese_surname in jp and
            (name.japanese_given in jp or name.surname != "Saotome")
        ) or name.japanese_given in jp
        if not jp_attests_person:
            continue
        full = re.compile(rf"(?<![A-Za-z]){given} {surname}(?![A-Za-z])")
        updated, n = full.subn(f"{name.surname} {name.given}", updated)
        if n:
            matched.extend([name.japanese] * n)
        # Abbreviations are only safe where JP supplies the exact full name.
        # In particular, Y. Saotome can refer to TWO different people.
        if name.japanese in jp:
            abbreviated = re.compile(rf"(?<![A-Za-z]){re.escape(name.given[0])}(\.?) {surname}(?![A-Za-z])")
            def swap(m: re.Match[str]) -> str:
                return f"{name.surname} {name.given[0]}{m.group(1)}"
            updated, n = abbreviated.subn(swap, updated)
            if n:
                matched.extend([name.japanese] * n)
    return updated, matched


def _validate_change(jp: str, before: str, after: str, pairs, script) -> None:
    if len(before) != len(after):
        raise ValueError("name reorder changed character budget")
    if before.count("\n") != after.count("\n"):
        raise ValueError("name reorder changed line count")
    if [len(x) for x in before.split("\n")] != [len(x) for x in after.split("\n")]:
        raise ValueError("name reorder changed line widths")
    if script.structure(before) != script.structure(after):
        raise ValueError("name reorder changed control/choice structure")
    old_bytes, old_widths = script.encode_english(before, pairs)
    new_bytes, new_widths = script.encode_english(after, pairs)
    if len(old_bytes) != len(new_bytes) or old_widths != new_widths:
        raise ValueError("name reorder changed encoded size or layout")
    # The JP structure is not changed; pre-existing upstream mismatches are
    # deliberately outside the scope of this name-order-only checkpoint.


def _entries(path: Path, pairs, script) -> tuple[str, str, list[dict]]:
    content = path.read_text(encoding="utf-8")
    records = []

    def handle(m: re.Match[str]) -> str:
        jp = json.loads(m.group("jp"))
        before = json.loads(m.group("en"))
        after, names = _replace(jp, before)
        if not names:
            return m.group(0)
        _validate_change(jp, before, after, pairs, script)
        records.append({
            "file": path.relative_to(ROOT).as_posix(),
            "offset": m.group("offset"), "jp": jp,
            "before": before, "after": after,
            "names": ",".join(dict.fromkeys(names)),
        })
        return m.group("head") + json.dumps(after, ensure_ascii=False)

    changed = RECORD.sub(handle, content)
    before_doc, after_doc = json.loads(content), json.loads(changed)
    if before_doc.keys() != after_doc.keys():
        raise ValueError(f"document schema changed: {path}")
    # No fields beyond the EN `text` values should differ.
    def without_text(obj):
        if isinstance(obj, dict):
            return {k: without_text(v) for k, v in obj.items() if k != "text"}
        if isinstance(obj, list):
            return [without_text(v) for v in obj]
        return obj
    if without_text(before_doc) != without_text(after_doc):
        raise ValueError(f"non-translation source data changed: {path}")
    return content, changed, records


def run(mode: str, root: Path = ROOT, report: Path | None = None) -> list[dict]:
    if root.resolve() != ROOT.resolve():
        raise ValueError("root override not supported; execute a copied script from the target tree")
    pairs, script = _encoder()
    outcomes = []
    updated = []
    for path in sorted(TRANSLATION.glob("*.json")):
        old, new, records = _entries(path, pairs, script)
        if records:
            outcomes.extend(records)
            updated.append((path, new))
    if mode == "verify":
        if outcomes:
            raise ValueError(f"{len(outcomes)} Western-order names still present")
    if mode == "apply":
        # All changes are validated before writing any file.
        for path, new in updated:
            path.write_text(new, encoding="utf-8")
        if report is not None:
            report.parent.mkdir(parents=True, exist_ok=True)
            with report.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, delimiter="\t", fieldnames=("file", "offset", "names", "jp", "before", "after"))
                writer.writeheader()
                for row in outcomes:
                    writer.writerow({k: v.replace("\n", "\\n") for k, v in row.items()})
    return outcomes


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    choice = p.add_mutually_exclusive_group(required=True)
    choice.add_argument("--audit", action="store_true")
    choice.add_argument("--apply", action="store_true")
    choice.add_argument("--verify", action="store_true")
    p.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = p.parse_args()
    mode = "audit" if args.audit else "apply" if args.apply else "verify"
    try:
        changes = run(mode, report=args.report if mode == "apply" else None)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"{mode.upper()}: {len(changes)} name-order records across {len(set(r['file'] for r in changes))} files")
    if mode == "audit":
        for r in changes:
            print(f"  {r['file']}:{r['offset']} {r['before']!r} -> {r['after']!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
