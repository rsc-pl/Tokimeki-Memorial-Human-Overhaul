# Translation guide

How to add English to the patch. Read [game-internals.md](game-internals.md)
for the formats, and the safety rules in [PS1_BUILD_SAFETY.md](PS1_BUILD_SAFETY.md) first.

## Translation files

`./tokimemo build GAME.cue` calls the preserved backend and applies every `translation/*.json` (not subfolders).
Put work that isn't ready in `translation/extra/`, and apply it on purpose
with `-t translation/extra/<file>.json` (`-t` replaces the default set, so
list every file you want).

**After testing, promote the translation into normal builds.** This is the
user's standing preference: once the relevant on-screen checks pass, move the
tested JSON from `translation/extra/` into `translation/`, update its references
and verification status, and build without `-t` to check default inclusion.
Do not leave a successfully tested translation opt-in. Retain specific notes
about untested conditional paths; a known failure blocking promotion must be
reported explicitly. For a path-only promotion, compare the normal build's
game files with the tested candidate to confirm the output is unchanged.

One JSON file per screen or feature. It can have a `strings` list, an
`images` list, or both:

```json
{
  "description": "What this file covers.",
  "strings": [ ... ],
  "images":  [ ... ]
}
```

## Text (`strings`)

```json
{
  "file": "CDROM/EXEDIR/OPTION.EXN",
  "offset": "0xA880",
  "original": "文字表示速度",
  "text": "Text Speed"
}
```

- `file`: path on the disc (case-insensitive, no `;1`).
- `offset`: file offset of the first byte of the string (hex string).
- `original`: the exact Japanese currently there. The patcher refuses to run
  if it doesn't match and isn't NUL-terminated.
- `text`: plain English.
- `encoding` (optional): `"pairs"` (default) or `"fullwidth"`.

### Encodings

**`pairs` (default, use this).** The game can't draw ASCII (game-internals
§6b), so English is written as *letter pairs*: each 2-byte character code
holds two letters (ASCII with the top bit set), and a hook in the game's text
renderer draws the pair from a narrow font as it lays the text out
(game-internals §6f). On screen that's 7 px per letter; on disc it's 1 byte
per letter (odd lengths are padded with a space).
- Supported characters: `A–Z a–z 0–9`, space, and `. , ! ? ' " - : ; ( ) / & + %`.
  Anything else is rejected with an error. To add a character, draw it in
  `tokipatch/pairfont.py` (5 px wide, same metrics as the rest); the hook's
  font table covers all of ASCII 0x20–0x7F, so no code change is needed.
- Every pair is available, so there's no glyph budget: vocabulary costs
  nothing, only bytes do.
- The hook is in the EXE's shared renderer, so pair-encoded text works on any
  screen that draws through it (every text screen seen so far). Graphics
  baked into images (like the title menu) still need image patches.

**`fullwidth`.** Each letter becomes a full-width Shift-JIS character
(`Name?` → `Ｎａｍｅ？`): 2 bytes and 12 px per letter, using the font's
original Latin glyphs. Space → ideographic space, `'` → `’`, `"` → `”`,
`-` → `−`, `~` → `〜`. Only use it where pair glyphs can't be used.

### Space budget
Original bytes + 1 (NUL) + NUL padding up to the next 4-byte boundary.
With `pairs` that's `budget - 1` letters (rounded down to even); with
`fullwidth`, `(budget - 1) // 2` letters. Too-long text is rejected with the
limit in the error. Shorten the English; don't touch the rule.

**Fixed-size records (`slot`).** Some tables store each string in a
fixed-size record, read with a fixed stride, e.g. the 33-byte place names in
`DATE.EXN` (game-internals §6l). There a string may use its whole record:

```json
{"file": "CDROM/EXEDIR/DATE.EXN", "offset": "0x29C0D", "original": "海",
 "text": "the beach", "slot": 33}
```

The patcher checks that every byte from the original's end to the record's
end is NUL, and allows English up to `slot - 1` bytes. Only use it where
the record size is proven from the code that reads the table (a copy loop,
a stride multiply) and documented in game-internals. A wrong slot size
usually runs into the next record and is refused.

Screen width matters too: menus are sized for the Japanese. With `pairs`,
English that uses **no more letters than the original had bytes** is never
wider than the Japanese was. The patch log (`-v`) prints a `note:` for any string
that goes beyond that (using the padding), so check those on screen. For
multi-line text (description boxes), keep every line within its original
width.

**Line breaks and codes in in-place strings.** Overlay strings drawn by
the dialogue renderer can contain its 0x20 line break and name codes
(ETC.EXN's exam thoughts, ENDING.EXN's `{M}残念ながら`). Write them as in
dialogue, `\n` and `{G}`/`{M}`, in both `original` (as `exn_words.py`
prints them) and `text`; `text` may also hold full-width characters such
as `○` or `『』`. Plain strings encode exactly as before (the normal build
stayed byte-identical when this was added, 2026-10-10). The room is the
encoded size: every odd run of letters is padded with a space, once per
line, so a three-line string can need up to three bytes more than its
letter count.

### Drafting a whole file

`tools/draft.py` builds a file's
draft: it lists every string, fills the ones any committed translation
already has (the translation memory: same Japanese, same English), keeps
punctuation-only pauses, and writes the rest to a todo list in
`extracted/todo/`. Translations go in a table in `extracted/tables/`
(Japanese keys, so not committed; `"@0x1c"` keys override one offset).
`python tools/draft.py --check translation/<file>.json` runs the same
checks on any file: structure, widths, odd runs before names, odd
names followed by text, thought and menu-option endings, `)` kept, and
the patcher's packing.

### Code and data patches (`bytes`)

```json
{"file": "CDROM/EXEDIR/NAME_ENT.EXN", "offset": "0x1B8",
 "original": "10000424", "replacement": "0e000424",
 "comment": "set_glyph_advance(16) -> 14"}
```
These are raw bytes, verified against `original` before patching. Keep
general code changes in `translation/code.json`; patches that only serve
one translation file live in that file (`new_year.json`'s `%s` formats,
`school_trip.json`'s place names). Give each one a comment saying what the
instruction is, and document the reasoning in game-internals.

**Repacking strings the code addresses directly.** When a few in-place
words can't fit their slots but sit next to each other, and nothing else
points into that stretch (search the overlay for data words and
`lui`/`addiu` immediates aimed at it), one `bytes` patch can rewrite the
whole stretch with the English laid out freely, and one more per `addiu`
points each reader at its new string (game-internals §6y: Okinawa,
Hokkaido, Sapporo in SHUGAKU.EXN). Strings that keep their place still go
in `strings` with their `original`. `tools/repack_words.py FILE --region
START END --texts TABLE -o OUT` does the whole job for a run: it checks
that only `lui`/`addiu` pairs reach the run (each at a string start, no
data words pointing in, every string read somewhere), lays the English out
from START (identical English stored once), and writes the `bytes`
patches: one for the run, one per `addiu` immediate. `--max-len` (default
20) guards the strcpy destination. First used for DATE.EXN's 73 place
banners (game-internals §6k).

### Patterns to watch for
- **Icons and numbers drawn over text cells.** The game draws ○/× icons and
  numbers at fixed character cells, over blank characters in the string. Keep
  a blank glyph (`"  "`, i.e. two spaces, which maps to the font's blank
  0x8140) in exactly those cells, and arrange the English around them.
  Examples: the Yes/No lines (`"    Yes...       No...  "` keeps "Yes..."
  ending at cell 4 and "No..." at cell 10). A leading full-width space before
  an icon becomes a leading `"  "`. Strings after a game-drawn number (3番…)
  start with `": "`.
- **Messages split into pieces.** Some messages are several adjacent strings
  (e.g. `メニュー設定を` + `マウスライク` + `にしました`). You can't always tell
  whether the pieces share a line. Inspect the consumers before settling the
  wording: they may concatenate, draw on separate rows, or use fixed x positions.
  The in-game Menu Mode confirmations are now mapped to three separate rows
  (§6i in game-internals): `"Menu mode:"` / `"Mouse-like"` / `"selected."`.
  Concatenated field labels instead need their own trailing separators, e.g.
  `"Name: "` before a saved name. Do not remove dialogue display lines when
  adapting pieces; dialogue's structural checks still apply.
  For example, the Club Day notice (§6h in game-internals) has only 56 px
  between its last two fragments: the first must fit eight pair-font letters,
  even though its disc slot can hold ten. Preserve intentional padding and
  verify the combined result; fitting each byte slot alone cannot catch overlap.
- **Bounded appends.** A whole string literal may be present on disc while its
  consumer copies only the first glyph. The Save/Load panel appends two bytes
  from its slot-number and date suffixes (§6i). Its slot suffix must fit one
  pair, `": "`; writing `": Album"` cannot make the unused tail appear.
  Check the destination buffer as well as each literal's in-place budget.
- **The same words as graphics.** A screen can show text that isn't a string
  at all (Options ▸ Text Speed / Icon Mode / Cursor Speed / Voice Mode use
  pre-drawn glyph cells). If a translated string doesn't change the screen,
  dump RAM via the GDB stub and search for the Japanese. No hit means it's
  graphics (testing.md).
- **Pointers into the middle of a string.** Possible in principle (code can
  point past a prefix), so if an on-screen label is a suffix of a string you
  translated, check it. (The suspected case on the Voice screen turned out to
  be graphics.)

**Finding strings:**

```bash
python tools/extract.py path/to/game.cue extracted
python tools/find_text.py extracted/CDROM/EXEDIR --grep "名前"
```

Columns: file, offset, budget in bytes (`-` = not NUL-terminated, usually
script bytecode: **don't patch** until the script format is understood), text.
`find_text.py` is pure Python and slow over the whole `extracted/` tree
(minutes), so point it at a directory or file. To find where a known on-screen
phrase lives, search for its Shift-JIS bytes directly (`data.find(text.encode("shift_jis"))`),
which is instant.

A string often exists in **more than one file**. The Options items appear
both in `OPTION.EXN` (title Options page) and in `SLPM_86.053` (in-game
settings). Translate each copy that a screen uses, and check which screen
you're looking at.

Strings with capacity `-` are usually dialogue: use the `dialogue` format
below, not `strings`.

## Dialogue (`dialogue`)

Dialogue strings are repacked instead of fitted one by one: the space of every
translated string in a block is pooled, the English is packed into it, and
every pointer to a moved string is rewritten (game-internals §6e). Example:
[translation/prologue.json](../translation/prologue.json).

```json
{
  "dialogue": [{
    "file": "CDROM/EXEDIR/NAME_ENT.EXN",
    "base": "0x80132000",
    "lines": [
      {"offset": "0x1b1d0",
       "original": "俺の名前は{P}。\nここ、私立きらめき高校の\n新入生だ。",
       "text": "My name's {P}.\nI'm a freshman at\nKirameki High."}
    ]
  }]
}
```

- `base`: the file's load address (its pointers are absolute). Overlays are
  0x80132000; SERIFU bases are listed in game-internals §6e.
- `\n` is a line break; `{P}`, `{G}`, ... insert names; `{q}` separates choice
  options (game-internals §6e has the full list).
- A line with `"text": ""` is left alone, so a file can be translated a bit at
  a time.
- Start from a dump: `python tools/dump_dialogue.py extracted/CDROM/SERIFU/EVENT_KI.BIN -o extracted/dumps/EVENT_KI.json`
  (it finds the base). **Keep dumps out of the repo** (they're the Japanese
  script; PS1_BUILD_SAFETY.md: no game data in the repository). Only commit lines you've translated.
- The dumper prints how many pointer targets decode as text but were left
  out; `--rejected` lists them. "No Japanese text" entries seen so far are
  binary records. A Japanese target reported as "not at a string start"
  means a pointer into the middle of a string or a wrong base: work out which
  before translating that file (game-internals §6e). Dumps made before
  2026-10-07 missed every string that follows a pointer table; regenerate them.
- After changing the dumper or `script.py`, run `python -m unittest discover tests`.

**Rules the patcher enforces:**
- **Same number of display lines and choices as the Japanese, with the same
  name codes on each line.** Scene code can wait for a specific line to start
  typing (Rei's introduction plays his animation on its 4th line). With
  fewer lines the game waits forever. Reflow the English to the original's
  line count.
- **At most 28 letters per line** (`max_cells`, default 28). A name code
  counts as its longest name (`script.TOKEN_CELLS`, e.g. `{P}` = 12).
- **The English must fit in the space of the strings it replaces.** It's
  about 1 byte per letter, the same as the Japanese bytes for a typical
  translation, so write tightly. The log line `dialogue: N string(s),
  X of Y bytes used` shows the margin.
- **The pool is in pieces.** Script files interleave strings with pointer
  lists, so the free space is many small gaps, and a string must fit one gap.
  The patcher packs in file order first; if that strands a string it retries
  longest-first, each in the tightest gap (blocks that already fit keep their
  exact layout). If it still fails with plenty of bytes free, the longest
  strings are too long for any gap: keep each long reply near its own
  original size. (The museum pilot failed at 1322 of 1624 bytes until two
  122/124-byte replies were cut below the largest gap.) Check while
  translating with `python tools/dialogue_budget.py FILE.json`: it lists
  each string's own slot, its gap and the English bytes, flags strings that
  can't fit (`OVER-GAP`) or must borrow (`over-slot`), and runs the real
  packing. On a dump, `--all --range START END` shows a section's budgets
  before anything is written. In `DATE_FU.BIN` 57 strings over 100 bytes
  sit alone in their gap, so those replies get roughly their own size.
- **Plan a `DATE_FU` batch with `python tools/date_sections.py`**: section
  ranges, parts, choices/replies and how to force each version (§6k of
  game-internals; testing.md "Testing date conversations").

**Strings the code addresses directly** (overlays like `TEL.EXN`,
game-internals §6m) can go in a `dialogue` block too: the patcher finds
their `lui`/`addiu` references and keeps each in its own slot (original
bytes + NUL + padding) instead of moving it; `dialogue_budget.py` reports
the space. Use a separate block for them. Many are fragments the code
glues together with `strcpy`/`strcat` (a name or date goes between them),
so translate them as pieces of one sentence and check the joined result on
screen. `python tools/code_strings.py FILE --range A B` (needs capstone)
lists each such string with the call it feeds.

**`"share_identical": true`** (per `dialogue` block): strings whose English
encodes to the same bytes are stored once and all their pointers point at
that copy. `DATE_FU.BIN` repeats "shall we go inside?" 31 times; sharing
saves about a fifth of its pool. Safe because the game copies a string
before cutting it up (game-internals §6k). Translate repeated lines
identically so they can share.

**Choices (`{q}`).** A string with `{q}` is either a set of options
(code `03`/`08`: the game lists them, in shuffled order, each in `『』`) or
a reply with one option per choice (code `02`: the game shows only the one
matching the chosen option, game-internals §6k). Keep the option count and
order. Give every **option** an even number of letters, or the pair padding
shows as a space before the game's `』` ("lovely? 』"). Replies don't need
that.

**Empty options (`{n}`).** In the `DATE_*` yukata exchange a line ends in
`{n}{n}` and a reply's second option is just `{n}{n}`: the game skips an
option starting with `n`. Keep each `{n}` run exactly where it is (the
patcher's structure check enforces it); write the English before it.
Not every girl's date file has this exchange (game-internals §6k).

**Speaker labels in a string (`{>部長}`, `{-？？？}`).** A narration line
(code `07`) can carry its own speaker label: a prefix byte and a fixed
number of label bytes before the text (`>` and `<` 4, `-` 6, `+` 2;
game-internals §6p). Keep the token at the start and write an English label
of at most that many letters (`{>Capt}`, `{-???}`); the patcher pads it
with spaces. The label isn't counted in the line width.

**Lines near the page icon.** The "next" hand icon sits at the right end of
the box's lower lines; 27–28-letter lines on lines 2–3 touch it. The
patcher allows 28, but keep those lines at 26 or less where it's easy.

**Style notes (from the prologue):**
- The box shows 3 lines at a time; 4–5 line strings scroll, which is fine.
- The game draws the speaker label and the opening bracket (`「`, `『`, or `（`
  for thoughts). Never write an opening `(`. End a line with `)` **only if
  the Japanese ends with `）`**: prologue thoughts do, but `EVENT_FU.BIN`'s
  don't, because the game draws both brackets there. The patcher enforces
  this. Keep the run before the game's bracket an even number of letters,
  or the pair padding shows as a space before it ("So true." not "How true.").
- A text run with an odd number of letters before a name code wastes a cell,
  showing as a double space (`"My name is {P}"` → "is  Name"). Prefer an even
  run (`"My name's {P}"`).

`TOKEN_CELLS` must cover the widest text a control code can insert after name
tables are translated, not merely the width of the original Japanese value.
The current conservative widths are 18 cells for `{S}`, `{O}`, `{W}`,
`{A}` and `{M}`, 10 for `{G}` (its writers are all known, game-internals
§6e), 6 for `{Y}`, and 12 for `{P}`. If an inserted-name table is
changed, update these limits and revalidate every translated line containing
the affected code; otherwise the static width check can accept a line that
overruns the dialogue box.

Only UI strings with a numeric budget go through `strings`. Pair encoding
halves the bytes English needs, which makes many more UI strings fit in place
than full-width did.

## Graphics (`images`)

```json
{
  "file": "CDROM/FUKUTEST/TITLE.NBN",
  "png": "graphics/title_menu.png",
  "pixels": "0x60000",
  "stride": 128,
  "x": 0,
  "y": 68,
  "rects": [[0, 0, 128, 32], [0, 32, 48, 16]],
  "original_crc32": "0xe7038d68"
}
```

- `pixels`: file offset of the 8bpp bitmap. `stride`: bytes per row.
- `x`, `y`: where the PNG's top-left pixel lands in that bitmap.
- `rects`: `[x, y, w, h]` areas *of the PNG* that are written. Everything else
  in the PNG is ignored, so it can contain the surrounding original art for
  context.
- `original_crc32`: CRC32 of the original pixel values under all `rects`
  (one byte per pixel), row by row, rect by rect. The patcher refuses to run
  on a mismatch.
- `bpp` (optional): 8 (default) or 4. For 4bpp, `stride` is still bytes per
  row, `x`/`y` are pixels, and two pixels share a byte (low nibble = left
  pixel). The PNG may only use indices 0–15.
- `png`: path relative to the JSON file. It must be an **8-bit indexed PNG**
  whose pixel values are the game's palette indices.

**Editing PNGs:** use an editor that keeps palette indices (Aseprite, GIMP in
Indexed mode with the embedded palette, Pro Motion). RGB PNGs are rejected.
The embedded palette is the game's CLUT for that graphic, so what you see is
what the game shows.

**Generated art:** `tools/make_title_menu.py <cue>` regenerates
`translation/graphics/title_menu.png` and `title_menu_options_selected.png`
from a built-in pixel font, using the original outline and gradient indices,
and prints each `original_crc32`. Follow that pattern for new menus: export
the original region with the right CLUT, draw, record the CRC of the replaced
cells.

**Sprite cells shared by two meanings.** UI sprites are built from frame
definitions that point at cells of a sheet (game-internals §7, "Sprite
frames"). One cell can serve two purposes: on the main screen 月 is both the
month suffix and Monday, and 日 both the day suffix and Sunday. Don't redraw
such a cell for one meaning. Redraw a cell only one frame uses, and repoint
the other frame's part with a `bytes` patch on its `cell` field. Example:
`tools/make_main_screen.py` turns 年 into "/" and `main_screen.json` points
the 月/日 suffix parts at it, so the weekday cells can become Mo…Su. Search
the frame table for every use of a cell before changing it.

**Every state of a graphic is separate art.** Menus usually have a highlighted
and an unselected version, and they may live in different places in the file.
The title menu's highlighted OPTIONS was a separate strip, missed the first
time. When you replace a graphic, check every state on screen (highlight each
item). To find the other versions, shape-match the cells you already know
(zero/non-zero masks) across the file; matching colour indices isn't enough.

**Finding a graphic and its palette:** see
[testing.md](testing.md#finding-graphics-vram-dumps). In short:
dump CPU→VRAM uploads in the isolated emulator, identify the block, then find
those bytes in the file that was loaded (`trace_reads.py`), and match the CLUT
by 5-bit colour values.

## Before you call it done
Run the checklist in [PS1_BUILD_SAFETY.md](PS1_BUILD_SAFETY.md#checklist-for-any-change-that-affects-the-output).
At minimum, build to a scratch folder, boot it, look at the changed screen, and
continue past it.

After adding or promoting translations, refresh the progress bar in the README with `python tools/progress.py --update-readme` (needs
`extracted/`; `--by-file` lists every file's share). It counts Japanese
characters in NUL-terminated strings with kana, skipping the `SPEAKTST/`
voice-test copies, so kanji-only labels and pre-drawn graphics aren't in it.
