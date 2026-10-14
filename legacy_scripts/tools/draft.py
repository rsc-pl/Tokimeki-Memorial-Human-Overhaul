"""Make, fill and check a dialogue translation draft for one script file.

Usage:
  python tools/draft.py CDROM/BUNKA/KT_S61.BIN -o translation/extra/ayako_festival.json
        [--table extracted/tables/KT_S61.json ...] [--name Ayako] [--base 0x801E8000]
        [--description "..."] [--todo extracted/todo/KT_S61.txt]
  python tools/draft.py --check translation/foo.json [--name Yuina]

The original per-file translation workflow used it as follows:

1. It lists every string of the file (dump_dialogue.py's scan) and keeps
   the pure-punctuation pauses Japanese (game-internals 6e).
2. It fills each line from, in order: a per-offset entry "@0x1c" in a
   --table, the --table's plain Japanese -> English entries, then the
   translation memory: every (original, text) pair already in
   translation/*.json, when that original always got the same English.
   So shared lines (e.g. the festival's closing narration, the date lines
   every girl shares) are translated once.
3. It writes the remaining distinct Japanese strings to --todo (default
   extracted/todo/<FILE>.txt), one JSON string per line with its speaker
   code and offsets: the work list. Tables and todo files hold Japanese
   script, so keep them in extracted/ (docs/PS1_BUILD_SAFETY.md, no-game-data rule).
4. It writes the draft JSON (one dialogue block, share_identical) and runs
   the checks below on it, plus the patcher's real packing.

Checks (all printed with the offset and the English):
- structure: same lines, choices and name codes as the Japanese (the
  patcher refuses otherwise);
- width: a line over 28 cells (a name code counts as its longest name,
  script.TOKEN_CELLS); lines 2-3 over 26 (they run into the page icon);
- odd runs: an odd number of letters right before a name code shows a
  double space;
- odd name: with --name NAME of odd length, any text after {G} on the
  same line shows NAME's pair padding before it ("Yuina ,");
- thoughts (code 06) and notes (04): the last run must be even unless the
  Japanese ends with "）" (the game adds the closing bracket);
- choices (codes 03/08 or {q}): each option's last run must be even
  (otherwise a space shows before 』);
- "）" kept: the English ends with ")" exactly when the Japanese does;
- budget: the block must pack into the file's string space; when it
  doesn't, the lines longer than their own original slot are listed (the
  pool can be split into small gaps, BUNKA/*.BIN: shorten those first).
"""

from __future__ import annotations

import argparse
import collections
import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "legacy_scripts" / "tools"))
from tokipatch import font, patcher, script  # noqa: E402
import dump_dialogue  # noqa: E402
import script_survey  # noqa: E402

PUNCT = re.compile(r"^[‥…。・？！\s　\n]*$")
NAME_CODE = re.compile(r"\{[GPMSOWAYFpm]\}")


def translation_memory(exclude: str = None):
    """{original: text} for originals that always got the same English."""
    seen = collections.defaultdict(set)
    for p in sorted((ROOT / "translation").glob("*.json")):
        if exclude and p.resolve() == Path(exclude).resolve():
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        for b in doc.get("dialogue", []):
            for line in b["lines"]:
                if line.get("text"):
                    seen[line["original"]].add(line["text"])
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def check_line(jp: str, en: str, code=None, name=None, pairs=None, certain=True):
    pairs = pairs or font.PairEncoder()
    msg = []
    if script.structure(en) != script.structure(jp):
        msg.append(f"structure {script.structure(jp)} vs {script.structure(en)}")
    try:
        _, widths = script.encode_english(en, pairs)
        if max(widths) > script.MAX_CELLS:
            msg.append(f"width {max(widths)}")
        body = re.sub(r"^\{[><+-][^}]*\}", "", en)
        for alt in body.split("{q}"):
            for i, ln in enumerate(alt.split("\n")):
                if i in (1, 2):
                    _, w = script.encode_english(ln, pairs)
                    if max(w) > 26:
                        msg.append(f"warn: line {i + 1} width {max(w)} (may touch the page icon)")
    except Exception as ex:  # noqa: BLE001
        msg.append(str(ex))
    body = re.sub(r"^\{[><+-][^}]*\}", "", en)
    for m in re.finditer(r"([^{}\n]*)\{[GPMSOWAYFpm]\}", body):
        if len(m.group(1)) % 2:
            msg.append(f"odd run before name: {m.group(1)!r}")
    if name and len(name) % 2 and re.search(r"\{G\}(?!\{q\}|\n|$|\)$)", en):
        msg.append(f"text after odd-length name {name}")
    elif name and len(name) % 2 and re.search(r"\{G\}\)$", en):
        msg.append(f"warn: closing ')' right after odd-length {name}: a space shows before it")
    elif name and len(name) % 2 and re.search(r"\{G\}(\{q\}|$)", en) and code in (3, 8):
        # An option ending on the name: its pair padding shows before the
        # game's closing bracket ("Go with Yuina 』"), like the thoughts below.
        msg.append(f"warn: option ends on odd-length {name}: a space shows before the bracket")
    if code in (4, 6) and name and len(name) % 2 and en.rstrip().endswith("{G}"):
        # The game's closing bracket follows the name's pair padding
        # ("Crying? Mio )"); unavoidable when the name must end the box.
        msg.append(f"warn: thought ends on odd-length {name}: a space shows before ')'")
    soft = "" if certain else "warn: "     # code guessed from code-built tables
    if code in (4, 6):
        last = re.split(r"\{[A-Za-z]\}|\n", en)[-1]
        if len(last) % 2 and not jp.rstrip("\n").endswith("）"):
            msg.append(f"{soft}odd thought end {last!r}")
    if jp.rstrip("\n").endswith("）") != en.rstrip("\n ").endswith(")"):
        msg.append("closing paren mismatch")
    # Menu options (03 choice, 08 action; or {q} where the code is unknown).
    # 02 replies also use {q}, but those alternatives are ordinary lines.
    if code in (3, 8) or (code is None and "{q}" in en):
        opts = en.split("{q}") if "{q}" in en else en.split("\n")
        for opt in opts:
            tail = re.split(r"\{[A-Za-z]\}", opt)[-1]
            if len(tail) % 2:
                msg.append(("warn: " if code is None else soft) + f"odd option end {opt!r}"
                           + (" (if this is a menu)" if code is None else ""))
    return msg


def budget(doc_path: Path):
    """The patcher's packing of each block: (ok, message)."""
    out = []
    doc = json.loads(doc_path.read_text(encoding="utf-8"))
    pairs = font.PairEncoder()
    for item in doc.get("dialogue", []):
        data = (ROOT / "extracted" / item["file"]).read_bytes()
        block = patcher.DialogueBlock(
            file=item["file"], base=int(item["base"], 0),
            lines=[patcher.DialogueLine(int(x["offset"], 0), x["original"], x["text"])
                   for x in item["lines"] if x["text"]],
            source=doc_path.name, share_identical=bool(item.get("share_identical")))
        try:
            edit = patcher.FileEdit(entry=None, original=data, data=bytearray(data))
            with redirect_stdout(io.StringIO()):
                patcher.apply_dialogue(block, edit, pairs)
            out.append((True, f"{item['file']}: " + "; ".join(edit.log[-1:]) if edit.log else "packs"))
        except Exception as ex:  # noqa: BLE001
            out.append((False, f"{item['file']}: DOES NOT PACK: {ex}"))
            # The pool is often split into small gaps (pointer lists between
            # the strings, BUNKA/*.BIN): list the lines longer than their own
            # original slot, the ones to shorten first.
            for x in item["lines"]:
                if not x["text"]:
                    continue
                o = int(x["offset"], 16)
                cap = data.index(b"\0", o) - o + 1
                while (o + cap) % 4 and data[o + cap] == 0:
                    cap += 1
                try:
                    need = len(script.encode_english(x["text"], pairs)[0]) + 1
                except Exception:  # noqa: BLE001
                    continue
                if need > cap:
                    out.append((True, f"    {o:#07x} over its own slot by {need - cap}: {x['text']!r}"))
    return out


def check_doc(path: Path, name=None, codes=None, certain=None):
    doc = json.loads(path.read_text(encoding="utf-8"))
    pairs = font.PairEncoder()
    problems = 0
    for item in doc.get("dialogue", []):
        if codes is None:
            try:
                r = script_survey.survey(item["file"], int(item["base"], 0))
                codes, certain = r["codes"], r["certain"]
            except Exception:  # noqa: BLE001
                codes, certain = {}, set()
        for x in item["lines"]:
            if not x["text"]:
                continue
            o = int(x["offset"], 16)
            for m in check_line(x["original"], x["text"], codes.get(o), name, pairs,
                                certain=certain is None or o in certain):
                problems += not m.startswith("warn:")
                print(f"  {o:#07x} c{codes.get(o) if codes.get(o) is not None else -1:02x}: {m}  {x['text']!r}")
    for ok, m in budget(path):
        print("  " + m)
        problems += 0 if ok else 1
    return problems


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("-o", "--output")
    ap.add_argument("--table", action="append", default=[])
    ap.add_argument("--name")
    ap.add_argument("--base", type=lambda s: int(s, 0))
    ap.add_argument("--description")
    ap.add_argument("--todo")
    ap.add_argument("--no-tm", action="store_true")
    ap.add_argument("--check")
    a = ap.parse_args()
    if a.check:
        n = check_doc(Path(a.check), a.name)
        print(f"{a.check}: {n} problem(s)")
        sys.exit(1 if n else 0)
    if not a.file or not a.output:
        sys.exit(__doc__)

    disc = a.file.upper().lstrip("/")
    r = script_survey.survey(disc, a.base)
    base, codes, certain = r["base"], r["codes"], r["certain"]
    x = (ROOT / "extracted" / disc).read_bytes()
    lines = dict(dump_dialogue.targets(x, base))
    # Strings the section tables reach but the dumper's scan misses
    # (game-internals 6k: some date files have 4-9).
    extra = []
    for o in sorted(r["reached"] - set(lines)):
        try:
            t = script.decode(script.read_string(x, o))
        except Exception:  # noqa: BLE001
            continue
        if t and any(ord(ch) > 0x7F for ch in t):
            lines[o] = t
            extra.append(o)
    if extra:
        print(f"{len(extra)} string(s) reached by tables but missed by the dumper, included: "
              + " ".join(hex(o) for o in extra))
    lines = sorted(lines.items())

    table, per_off = {}, {}
    for t in a.table:
        for k, v in json.loads(Path(t).read_text(encoding="utf-8")).items():
            if k.startswith("@"):
                per_off[int(k[1:], 16)] = v
            else:
                table[k] = v
    tm = {} if a.no_tm else translation_memory(exclude=a.output)

    out, todo, src = [], collections.OrderedDict(), collections.Counter()
    for o, jp in lines:
        if PUNCT.match(jp):
            continue
        if o in per_off:
            en, s = per_off[o], "offset"
        elif jp in table:
            en, s = table[jp], "table"
        elif jp in tm:
            en, s = tm[jp], "memory"
        else:
            en, s = "", "todo"
            todo.setdefault(jp, []).append(o)
        src[s] += 1
        out.append({"offset": f"{o:#x}", "original": jp, "text": en})

    outp = Path(a.output)
    desc = a.description
    if desc is None and outp.exists():
        desc = json.loads(outp.read_text(encoding="utf-8")).get("description")
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8", newline="\n") as f:
        f.write("{\n  \"description\": " + json.dumps(desc or "DRAFT", ensure_ascii=False) + ",\n")
        f.write(f"  \"dialogue\": [{{\n    \"file\": \"{disc}\",\n    \"base\": \"{base:#x}\",\n"
                "    \"share_identical\": true,\n    \"lines\": [\n")
        f.write(",\n".join("      " + json.dumps(l, ensure_ascii=False) for l in out))
        f.write("\n    ]\n  }]\n}\n")

    todo_path = Path(a.todo or ROOT / "extracted" / "todo" / (Path(disc).stem + ".txt"))
    todo_path.parent.mkdir(parents=True, exist_ok=True)
    with open(todo_path, "w", encoding="utf-8", newline="\n") as f:
        for jp, offs in todo.items():
            c = codes.get(offs[0])
            f.write(f"{json.dumps(jp, ensure_ascii=False)}  # c{c if c is not None else -1:02x} "
                    f"{' '.join(hex(o) for o in offs[:4])}\n")
    print(f"{disc}: {len(out)} lines ({dict(src)}), {len(todo)} distinct to translate -> {todo_path}")
    print(f"tables cover {r['covered']}/{r['strings']} strings")
    n = check_doc(outp, a.name, codes, certain)
    print(f"{outp}: {n} problem(s)")


if __name__ == "__main__":
    main()
