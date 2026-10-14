"""Read-only whole-file hash oracle using the production Python patch planner."""
import argparse
import base64
from types import SimpleNamespace
import hashlib
import json
from pathlib import Path
from tokipatch import patcher
from tokipatch.cd import Track


def run():
    ap = argparse.ArgumentParser()
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument('--track', type=Path)
    source.add_argument('--fixture', type=Path)
    ap.add_argument('--translation', action='append', type=Path)
    args = ap.parse_args()
    paths = args.translation or sorted((Path(__file__).resolve().parents[2] / 'translation').glob('*.json'))
    strings, images, raw, blocks = patcher.load_translations(paths)
    if args.fixture is not None:
        decoded = {k: base64.b64decode(v) for k, v in json.loads(args.fixture.read_text()).items()}
        entries = {k: SimpleNamespace(path=k, lba=i+30, size=len(v), is_dir=False)
                   for i, (k,v) in enumerate(decoded.items())}
        by_lba = {v.lba: decoded[k] for k,v in entries.items()}
        class TrackFixture:
            def read_file(self, lba, size):
                return by_lba[lba][:size]
        previous_files, previous_check = patcher.list_files, patcher.check_disc
        try:
            patcher.list_files = lambda _: entries
            patcher.check_disc = lambda *_: None
            files = patcher.plan(TrackFixture(), strings, images, raw, blocks)
        finally:
            patcher.list_files, patcher.check_disc = previous_files, previous_check
    else:
        with Track(args.track) as track:
            files = patcher.plan(track, strings, images, raw, blocks)
    records = []
    for edit in files:
        a, b = edit.original, edit.data
        records.append({
            'path': edit.entry.path,
            'size': len(b),
            'original_sha256': hashlib.sha256(a).hexdigest(),
            'patched_sha256': hashlib.sha256(b).hexdigest(),
            'changed_bytes': sum(x != y for x, y in zip(a, b)),
            'checksum_updated': patcher.has_checksum(a),
        })
    print(json.dumps({
        'files': records,
        'renderer_installed': any('renderer hook' in line for e in files for line in e.log),
        'strings': len(strings), 'images': len(images), 'bytes': len(raw), 'blocks': len(blocks)
    }, sort_keys=True))

if __name__ == '__main__':
    run()
