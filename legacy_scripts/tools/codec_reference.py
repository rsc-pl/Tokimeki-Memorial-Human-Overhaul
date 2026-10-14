"""Read-only regression oracle for the Go text codec.

Input: JSON list of {kind, original, text, encoding} over stdin.
Output: JSON list of [original digest or ERR, target digest or ERR,
                     width list or null, original structure, target structure].
No game data is modified; no disc image is required.
"""
import hashlib
import json
import sys
from tokipatch import script, text, font


def encode_hash(fn):
    try:
        raw = fn()
        if isinstance(raw, tuple):
            return hashlib.sha256(raw[0]).hexdigest(), raw[1]
        return hashlib.sha256(raw).hexdigest(), None
    except (ValueError, UnicodeError, KeyError, IndexError) as exc:
        return "ERR", None


def run(row):
    orig, _ = encode_hash(lambda: script.encode_original(row["original"]))
    pairs = font.PairEncoder()
    if row["kind"] == "dialogue" or row.get("encoding", "pairs") == "pairs":
        target, widths = encode_hash(lambda: script.encode_english(row["text"], pairs))
    else:
        target, widths = encode_hash(lambda: text.encode(row["text"]))
    if row["kind"] == "dialogue":
        return [orig, target, widths, script.structure(row["original"]), script.structure(row["text"])]
    return [orig, target, widths, "", ""]


def main():
    rows = json.load(sys.stdin)
    json.dump([run(row) for row in rows], sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
