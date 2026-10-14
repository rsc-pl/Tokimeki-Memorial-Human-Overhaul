> **Historical upstream research.** Paths in older examples referring to `tools/`, `tokipatch/` or PowerShell are from the original Windows-oriented layout. Source files now reside under `legacy_scripts/`; for supported Linux commands use [Native tooling](NATIVE_TOOLING.md) and see [Legacy migration](LEGACY_MIGRATION.md). Do not run archived `.ps1` examples as current project commands.

# Game internals — Tokimeki Memorial: forever with you (PS1, SLPM-86053)

Everything here was found on the *PlayStation the Best* disc (SLPM-86053),
using `tools/extract.py`, `tools/find_text.py`, `tools/mipsdis.py` and the
emulator tools in `tools/emu/` (see [testing.md](testing.md)). Addresses are
KSEG0 RAM addresses unless noted. "File offset" means an offset inside a file
on the disc.

Each section says how a fact was established, so it can be re-checked.

---

## 1. Disc image

| | |
|---|---|
| Track 1 | MODE2/2352 data, 298,500 sectors (702,072,000 bytes) |
| Track 2 | CD-DA audio, 45,151,344 bytes, INDEX 00 at 00:00:00, INDEX 01 at 00:02:00 |
| Volume ID | `VX009J2` (system ID `PLAYSTATION`) |
| SYSTEM.CNF | `BOOT = cdrom:SLPM_86.053;1`, `TCB = 8`, `EVENT = 32`, `STACK = 801FFF00` |

Sector layout (MODE2/2352): 12 sync, 4 header (BCD MSF + mode 02), 8 subheader
(4 bytes repeated), 2048 data, 4 EDC, 276 ECC. The patcher only touches Form 1
sectors and regenerates EDC/ECC (`tokipatch/cd.py`). Our EDC/ECC code
reproduces the stored values on untouched sectors byte for byte, so it's
known correct.

**Quirk:** LBA 14515, the first sector of the `/CDROM` directory, has a mangled
subheader (`30 00 80 38 00 00 80 00`), and its directory records start at byte
0x10 instead of 0x18. The game never reads it (it uses hard-coded LBAs), but
our ISO walker does. `Track.read_data` falls back to offset 0x10 when the two
subheader copies differ.

Filesystem: ISO 9660, root holds `SYSTEM.CNF` (LBA 23), `SLPM_86.053` (LBA 24),
`KONAMIC3.STR` (LBA 400), `OPENXA.STR` (LBA 2080) and `/CDROM/` with 31
subdirectories (~1,370 files). `CDROM/DADIR/TR02.DA` points at LBA 298650,
which is the audio track (track 1 length + 150-sector pregap).
`tools/extract.py` writes a full LBA listing to `files.tsv`.

## 2. Main executable `SLPM_86.053`

| | |
|---|---|
| Header | PS-X EXE, 0x800 bytes |
| Load address | `0x80041000` (t_size `0xA2800`) |
| Entry point | `0x800420D0` |
| File offset → RAM | `RAM = offset + 0x80040800` |

It contains system/UI text (see §6), the CD loader, and the overlay loader.

## 3. Code overlays (`CDROM/EXEDIR/*.EXN`)

- 27 files, each exactly 196,608 bytes (96 sectors). They're MIPS code plus data,
  uncompressed (the first bytes are instructions).
- Loaded to **`0x80132000`** (pointer stored at `*(0x800B6D3C)`).
  `RAM = 0x80132000 + file offset`. Confirmed by a pointer table in
  `NAME_ENT.EXN` at 0x1AD28, whose pointers (`0x8014B150`…) land on strings at
  0x19150.
- Each game mode has its own overlay. `NAME_ENT.EXN` holds the new-game flow:
  memory card prompts, prologue narration and script, name/birthday entry.
  It's loaded as the title screen comes up. When its checksum failed, the game
  stuck on the white transition before the title menu appeared.

### Overlay loader (in `SLPM_86.053`)

A switch around `0x80078DC0`–`0x80078F84` picks a hard-coded LBA per mode, then:

```
a2 = LBA ; *(u8*)0x800B6D38 = 0x60 (sectors)
if (current == a2) state = 3            ; already loaded
else { *(u32*)0x800B6D40 = a2; CdRead(0x60, *(0x800B6D3C), a2); state = 1 }
```

Loader state lives at `0x800B6D34` (u8): 0 = idle, 1 = reading, 2 = read done
(set by `0x80078FE0` when the sync function `0x800460CC` returns bit 0),
3 = loaded and verified. The current LBA is at `0x800B6D40`.

`0x80079014` verifies the read with the checksum routine (§4):
on success state = 3 and it calls `0x80042458`. On failure it sets state = 0 and
LBA = 0, so the load is requested again: **an infinite reload loop**.

Hard-coded overlay LBAs (instruction address → LBA → file):

| Insn | LBA | File | | Insn | LBA | File |
|---|---|---|---|---|---|---|
| 80078dc0 | 38570 | OLH.EXN | | 80078e9c | 39434 | TEL.EXN |
| 80078dd4 | 37706 | EN_NICHI.EXN | | 80078eb0 | 37610 | ENDING.EXN |
| 80078de8 | 38282 | MASTER.EXN | | 80078ec4 | 37802 | ETC.EXN |
| 80078dfc | 38954 | RPG_BAT.EXN | | 80078ed8 | 37418 | DATE.EXN |
| 80078e10 | 37322 | BUNKA_SD.EXN | | 80078eec | 37514 | DATE2.EXN |
| 80078e24 | 39338 | TAIIKU.EXN | | 80078f00 | 38666 | OMIMAI.EXN |
| 80078e38 | 38186 | KANGEI.EXN | | 80078f14 | 37994 | GEKO.EXN |
| 80078e4c | 38858 | RENSYU.EXN | | 80078f28 | 39146 | SHUGAKU.EXN |
| 80078e60 | 37226 | BUNKASAI.EXN | | 80078f3c | 39626 | VALEN.EXN |
| 80078e74 | 37130 | BUNKAKEN.EXN | | 80078f50 | 39050 | SHOUGATU.EXN |
| 80078e88 | 38378 | NAME_ENT.EXN | | 80078f64 | 38762 | OPTION.EXN |
| | | | | 80078f74 | 39530 | TT.EXN |
| | | | | 80078f84 | 39242 | TACO.EXN |

Not in this switch: `EVENT.EXN`, `GYOZI.EXN`, `O.BIN`. Checked 2026-10-11: no
instruction in the EXE or any overlay builds their LBA (37898, 38090,
38474), no data word holds it and no code names them, so they're **never
loaded**: old copies (a gift table, date banners, the help menu header).
They're left untranslated and `tools/progress.py` skips them.

**Consequence:** files can't be moved or resized without patching these
constants (and any other LBA tables for data files) as well as the ISO 9660
directory.

## 4. CD read and file checksum

| Address | Function |
|---|---|
| `0x80046318` | `read(a0 = sector count, a1 = RAM buffer, a2 = LBA)`, used for every file load seen so far |
| `0x800460CC` | returns the read status byte at `0x8012512A` |
| `0x8004636C` | `checksum_ok(a0 = sector count, a1 = buffer)` |

`checksum_ok` sums every byte of the first `count*2048 - 4` bytes into a
16-bit total, then compares it with the **big-endian u16** at
`buffer + count*2048 - 4`. The two bytes after it are always `12 10`.

So a file's last 4 bytes are `[sum16 hi][sum16 lo][0x12][0x10]`, where the sum
covers everything before them. This holds for every file whose size is a
whole number of sectors. All files with a valid trailer were.

Files with a valid trailer, by directory (from a scan of the extracted disc):
all 27 `EXEDIR` overlays, all 45 `SERIFU` dialogue files, 45/46 `BUNKA`,
all 164 `BUSTUP`, 76/78 `EVENT`, 12/12 `SPEAKTST`, most of `TACO`, `TAIIKU`,
`TARA_OBJ`, `FUKUTEST` (incl. `TITLE.NBN`), `END_OBJ`, `PROLODIR`, `*_SD`,
`MASTER`, `LASTPHOT`, `STAFF2`. None in `BS` (MDEC stills), `VAB_SE`, `VAB_SEQ`.

Only the overlay loader's call to the check has been confirmed. Assume
every file with a trailer is checked: the patcher fixes any trailer that
was valid in the original (`patcher.has_checksum`).

## 5. Boot sequence

From `tools/emu/trace_reads.py` (breakpoint on `0x80046318`), unpatched game:

| Order | File | Sectors | Buffer |
|---|---|---|---|
| 1 | `FUKUTEST/MAINROM.NBN` | 53 | 0x80180000 |
| 2 | `TMD/DUM.TMD` | 1 | 0x801F0000 |
| 3 | `FUKUTEST/TITLE.NBN` (title logo, menu, CLUTs) | 214 | 0x80180000 |
| 4 | `EXEDIR/NAME_ENT.EXN` | 96 | 0x80132000 |
| 5+ | `FUKUTEST/O_31_*.NBN` (opening/prologue images) | 33–65 | 0x80180000 / 0x801B0000 |

The opening movie plays from `OPENXA.STR`. Pressing Start skips to a white
fade, then the title. Left idle, the title returns to the attract loop
within roughly 10 seconds (not measured exactly).

**Controls follow the Japanese convention: ○ (Circle) confirms, × (Cross)
cancels/goes back.** This applies on the title menu and elsewhere. In the test
harness, ○ is the `C` key and × is the `X` key. (Confirmed by the user playing
the game.)

## 6. Text

- **Encoding:** plain Shift-JIS (JIS X 0208 double-byte), uncompressed,
  NUL-terminated.
- **In the EXE and overlays:** C string literals, 4-byte aligned, padded with NULs,
  reached through pointer tables (e.g. `NAME_ENT.EXN` 0x1AD28).
  An in-place replacement may use the original's bytes + NUL + padding to the
  next 4-byte boundary.
- **In dialogue** (`SERIFU/*.BIN`, the prologue in `NAME_ENT.EXN` 0x1B1D0–, and
  probably `BUNKA/`, `SPEAKTST/`, `EVENT/`): NUL-terminated strings with
  1-byte ASCII control codes mixed in (`0x20` = line break, `P` = player's
  name, ...), reached through tables of absolute RAM pointers. There is no
  separate bytecode for the text itself. `find_text.py` shows these as capacity
  `-` because the control bytes break its runs; use `tools/dump_dialogue.py`.
  Full details in §6e.
- **Where things are:**

| Location | Content |
|---|---|
| `SLPM_86.053` 0x6EB40–0x76000 | system/UI: memory card, save/load, options screen, calendar, places, weekday/holiday command prompts, club names |
| `EXEDIR/NAME_ENT.EXN` 0x19150– | kana tables for name entry, memory-card/album prompts, prologue narration, name-entry questions (0x1ACE4 surname, 0x1AD04 name, 0x1AD10 nickname), default nicknames, prologue script |
| `EXEDIR/OPTION.EXN` 0xA880–0xA8EF | Options page items (title ▸ OPTIONS), one string per item |
| `SLPM_86.053` 0x6FA08–0x70290 | in-game system settings screen: item list, choices, help lines and confirmation messages (`translation/system_settings.json`, included in normal builds). The user reports all submenus translated; main list and Text Speed choices/help are screenshot-verified. Individual confirmation/conditional-path coverage is not itemized (§6i). **Not** used by the title Options sub-screens. |
| `EXEDIR/*.EXN` | per-mode UI text |
| `SERIFU/`, `BUNKA/`, `SPEAKTST/`, `EVENT/` | dialogue (thousands of lines) |

- The title menu text is **not** text. It's graphics (§7).
- **Strings aren't always referenced by data pointers.** No 32-bit pointer to
  the `OPTION.EXN` items exists, so the code builds their addresses in
  instructions. Relocating such strings means patching code, not a table.

### 6c. Options page sub-screens (title ▸ OPTIONS ▸ item)

`OPTION.EXN` runs the page and loads `FUKUTEST/OPTION.NBN` (61 sectors →
0x801B0000, checksum trailer) for its graphics. The sub-screens split into
**text** (drawn with the game font via `add_text`, translatable now) and
**graphics** (pre-drawn glyph cells, not yet translatable):

| Item | Contents | Source | Status |
|---|---|---|---|
| Text Speed | 遅い / 普通 / 速い | **graphics** (OPTION.NBN frames) | English (Slow / Norm / Fast) |
| Icon Mode | ＴＹＰＥ‐Ａ / ＴＹＰＥ‐Ｂ / フリー + icon preview | **graphics** | English (Free; Init/Edit) |
| Mouse | (disabled without a PlayStation Mouse) | ? | not reachable in testing |
| Menu Mode | 4 choices + 3-line description box | text: `OPTION.EXN` 0xB30C– (choices), 0xA8F0–0xAA6B (descriptions, 3 lines per choice) | English, verified |
| Cursor Speed | 超遅い / 遅い / 普通 / 速い / 超速い | **graphics** | English (V.Slow … V.Fast) |
| Voice Mode | ＯＮ / ＯＦＦ / ×ボタンでカット | **graphics** | English (Skip X) |
| Extras | フリートーク / エンディング (`OPTION.EXN` 0xAA6C/0xAA7C) | text | translated, box is empty until unlocked |

- `OPTION.EXN` 0xAC10–0xAFFF holds a debug menu's strings (XA/VAB/SEQ test
  calls, "設定メニュー１…Ｆ"). It's not reachable normally and isn't translated.
- **The OPTION.NBN glyph sheet:** 8bpp, 128 px wide rows, 16×16 cells, 8 per
  row, starting at file offset **0xC000** (row 0 = the yellow highlight bar).
  It's a *deduplicated* character set (Y T P E A B ビ O / 左 右 初 期 状 態 N F / …)
  covering every character used by the graphical labels, apparently
  pre-rendered from the game font with outline + gradient. Labels are drawn
  as one 16×16 sprite per character, 14 px apart, twice (shadow at +1,+1 with
  CLUT 0x7E10, text with 0x7E11; the highlighted item uses 0x7E50/0x7E51).
- **The labels are sprite frames in OPTION.NBN** (found 2026-10-11 by
  reading the live sprite objects, stride 0x44 from `0x80120650`: offset
  0x0C points at a frame table, 0x18 holds the frame number). The table is
  at file `0x132D8` (RAM `0x801C32D8`), 130 frames of `s16 parts, x, y, 0`
  + 14-byte parts `x, y, cell, attr, 0, w, h`, the same layout as the EXE's
  frames (§7). `cell` counts 8×8 tiles of a 128 px wide 8bpp strip: rows
  0–127 are file `0x0000`–`0x3FFF`, rows 128–255 file `0xC000`–`0xFFFF`.
  Label frames come in pairs (attr 0x2000 normal, 0x2100 highlighted): 11/12
  超遅い, 13 遅い, 15 普通, 17 速い, 19 超速い, 21/23 TYPE-A/B, 25 フリー,
  27–39 the Mouse sub-screen, 41 初期状態, 43 変更, 45/47 ON/OFF, 49 ×ボタン
  でカット, 51–61 and 117 the graphic Extras entries, 63–115 and 122–129
  Extras name lists.
- **Translated** (`translation/option_labels.json`, generated by
  `tools/make_option_labels.py`): the Text Speed, Cursor Speed, Icon Mode
  and Voice Mode words, drawn with the pair font in the sheet's style
  (index 0x37→0x31 by row, shadow 0xE2) into the tiles of the replaced glyphs
  and blank tiles, each frame's parts rewritten; V.Slow/V.Fast share the
  Slow/Fast strips as 超遅い shares 遅い. **Don't reuse glyph cells no frame
  references:** the Icon Mode screen draws cell 36 from code, under the
  フリー label; overwriting it put a stray line there. Runs must start on
  even tile rows (two 16 px runs mustn't share a tile row). The strip has
  only ~1 tile column left, so the Mouse sub-screen and the graphic Extras
  entries stay Japanese.

### 6d. New game: album screen and name entry (`NAME_ENT.EXN`)

After GAME START, about 15 s pass, then the **album (save slot) screen**:
- **Message box: text.** `NAME_ENT.EXN` 0x197B4–0x1A14B, ~88 strings
  (memory-card checks, create/copy/erase/restart album, system-file prompts).
  - Lines starting with a full-width space leave room for an icon (○ before
    ボタン…) or for indentation.
  - `番アルバム…` lines follow an album number that the game draws in front.
- **Yes/No.** The no-save prompt uses `NAME_ENT.EXN` 0x19A0C (○ at cell 5,
  × at cell 11). Other prompts use the shared lines in `SLPM_86.053` 0x73470 /
  0x73488 (`　はい……　　ボタン`; ○/× drawn at cell 6).
- **Graphics: `FUKUTEST/FILESEL.NBN`** (loaded to 0x80180000, 8bpp,
  uploaded in 128×128 px blocks; found 2026-10-11 by logging the upload
  routine 0x8004435C): the panel is file `0x24000`/`0x28000`/`0x2C000` (VRAM
  x 640/704/768, y 0) over `0x30000`/`0x34000`/`0x38000` (y 128): buttons
  コピー/ニュー/クリア/ロード (fill 0xA6, outline 0x3A on a gradient), システム
  (ink 0xDB, shadow 0x86), 年 月 日, 名前, あだ名, 所属部, クリア人数, 人 (ink 2
  on row-striped backgrounds). The sprite strip is `0x1A000`/`0x3C000`/
  `0x1E000`/`0x40550` (VRAM x 320–512): the highlighted buttons (fill 0xB1,
  outline 0xB2), the parameter page's stat names, the girls' ratings page's
  13 surnames, パラメータ/女の子の評価/クリア回数 titles (ink 0xDB) and the
  有/無 system-file badges (ink 0xE3). The slot number's 番 is text
  (`NAME_ENT.EXN` 0x19660/0x19664). Translated in `album_screen.json`
  (`tools/redraw_labels.py`, which redraws a label in place: erase its ink to
  the row background, draw the pair font in the same ink) and `album.json`.
  `SLPM_86.053` 0x70790–0x70853 holds similar labels (名前…, あだ名…), but
  changing them does not affect this screen.
- **Navigation:** the default Mouse-like menu mode moves the hand freely with
  the D-pad. To pick album 1 from the "Which album" prompt, hold ←, ↑, then
  nudge ↓/→ (see testing.md for exact timings).

Then **name entry**:
- **Questions: text.** `NAME_ENT.EXN` 0x1ACE4 / 0x1AD04 / 0x1AD10, then
  birthday/blood type 0x194C0, 0x19510, 0x19534, 0x1955C.
- **Graphics:** the side buttons かな/カナ/記号/漢字/終了 and the birthday
  page's labels are 4bpp cells in `NAME_ENT/NAME_ENT.NBN` (256 px wide, two
  copies side by side; frame table at file `0x1AF58`, frames 16–25 the
  buttons, normal/highlighted by CLUT). The pink 名前:/あだ名: captions are
  neither text (the text list holds only the empty name fields there) nor
  those cells (a probe overwriting the sheet's 名 changed nothing); probably
  the `NAME_SAK.BS` background (MDEC), not handled.
- **Kana grid:** strings at 0x19150– (rows like あいうえお) plus conversion
  tables (0x192D8–). These are the characters the player can type on the
  かな/カナ pages.
- **English names already work, no patch needed.** The **記号** page isn't a
  table: it lists font characters in Shift-JIS order from 0x8140, with
  scroll arrows. Three clicks of the ▼ arrow reach ０–９, **Ａ–Ｚ and ａ–ｚ**.
  Fields hold 3 (family) + 3 (given) + ~6 (nickname) characters. A typed
  letter is a full-width character (2 bytes, drawn with the font's own wide
  Latin glyph). × moves the input cursor back a slot.
  - Decision (with the user): short English names via 記号 are acceptable.
    The kana pages stay as they are (they keep the hidden cheat names
    reachable).
  - Longer or narrower names would need the ASCII/narrow-letter renderer
    change (open question 2).
- **Data, not UI:** the default names 藤崎/詩織 (0x1956C/0x19574) and the
  cheat-name list (0x19590–).
- This screen sets glyph advance 16 at init; it's patched to 14. The typed
  name characters still line up with their underscores (checked).

### 6e. Dialogue

Found by dumping the prologue strings, disassembling the EXE code that compares
bytes against them, and stepping through the prologue in the emulator
(testing.md, "Reaching the prologue"). Everything here was checked on screen
with English text unless marked otherwise.

**String format.** NUL-terminated. A byte that is one of the control codes
below takes 1 byte; anything else is a 2-byte Shift-JIS character (the
renderer doesn't check lead-byte ranges, it just skips 2). The patcher writes
these as `\n` and `{X}` in translation files (`tokipatch/script.py`).

| Byte | Meaning |
|---|---|
| `0x20` | end of display line |
| `q` (0x71) | end of a choice option (also ends the line) |
| `P` | player's full name, family + given with no space (on screen: "My name's みみ.") |
| `G` | the girl's name (RAM 0x800CA190). Written only by `0x80051438(buf, girl)` (girl 0: the fixed 詩織 `0x800AFB7C`; 10: 優美 + ちゃん; 12: 伊集院; others: the short-name table `0x800B35F4` + さん), called from set_girl `0x80084838` and SHUGAKU `0x801397F8`, and by literal strcpy's in GEKO (`0x80141488`: 館林さん, Miharu) and SHOUGATU (`0x8013DFA8`: 伊集院). So at most 10 cells, Japanese or English (longest English: "Yukinojo", 8; the suffixes are empty in English): `TOKEN_CELLS["G"]` = 10 (was a guessed 18; changed 2026-10-10) |
| `p`, `m` | RAM 0x800CA16C / 0x800CA174 (likely family / given name; unverified) |
| `F` | `sprintf("%s%s", p-buffer, 0x800CA174)` (unverified) |
| `Y` | the fixed string 好雄 (Yoshio) at 0x800B2240; a parallel expansion path uses 0x800B2250 |
| `S`, `O`, `W`, `A`, `M` | RAM 0x800CA23C / 0x800CA248 / 0x800CA250 / 0x800CA25C / 0x800CA280 (place, item, ...? unverified) |

Unpatched dynamic names are inserted as full-width Shift-JIS, 14 px per
character. Fixed names and name-table entries translated with `pairs` retain
their pair encoding when the renderer inserts them.

**Renderer:** `0x80081190` (EXE), called with (x, y, attr, string, ...). It
copies the string to a 512-byte stack buffer, splits it at `0x20`/`q`, copies
each line into a 64-byte buffer (`strncpy`, so a line must stay under 64 bytes
after name expansion), expands the name codes, and draws each line with
`add_text` (§6a) at 16 px line spacing. So dialogue uses the same font, glyph
cache and 14 px advance as the UI, and **letter-pair English works unchanged**.
- The speaker label and an opening bracket are drawn by the game before the
  first line: `「` for other characters, `『` for the player, `（` for the
  player's thoughts. In the prologue, thought strings end with `）` but never
  start with `（`; in English, end them with `)` only. In `EVENT_FU.BIN`
  the game draws **both** brackets: its thought strings contain neither, and
  an English `)` showed up doubled on screen (§6j). The patcher therefore
  requires the English to end with `)` exactly when the original ends with
  `）`.
- **Speaker-label source:** EXE function `0x80051438` constructs the normal
  character label. Character 0 copies Shiori from `0x800AFB7C`; the other
  character IDs select a pointer from the 16-entry table at `0x800B35F4`.
  It then appends `ちゃん` from `0x800AFB84` for its special case, or `さん`
  from `0x800AFB8C` normally. `translation/character_names.json` replaces the
  short-name strings and blanks both suffixes, because English uses bare given
  names here. This was found by statically following the string references and
  table loads in `SLPM_86.053`; EXE RAM addresses convert to file offsets by
  subtracting `0x80040800` (§2).
- **Name tables:** the adjacent full-name strings occupy file offsets
  `0x72C80`–`0x72D37` (Shiori's at `0x72C80`), with their 16-entry pointer table
  beginning at `0x72D38`.
  The 16 short speaker names occupy `0x72D78`–`0x72DF3`, followed immediately
  by their pointer table at `0x72DF4` (`0x800B35F4` in RAM). Both string areas
  are pooled and repointed by the dialogue patcher. The English full-name pool
  uses all 184 available bytes (with Shiori's "S. Fujisaki", §6m), so several given names have to be initials;
  the short-name pool uses 100 of 124 bytes.
- Four special Shiori literals and four special Yoshio literals live at file
  offsets `0x71980`–`0x719DC` (RAM `0x800B2180`–`0x800B21DC`) and bypass the
  normal short-name table. The fixed `{Y}` expansions are at file offsets
  `0x71A40` and `0x71A50` (RAM `0x800B2240`/`0x800B2250`). These all need to be
  translated along with the two name tables for names to be consistent across
  normal dialogue and special paths.
- Lines that start with `（` are outdented by 14 px.
- A first pass (0x800812D4) sets `*(u32*)0x80122D1C = 0` unless every
  character is one of `…‥「。、`. Purpose unknown (silent lines?). English
  never matches, like normal Japanese text. Keep pure-punctuation lines in
  Japanese punctuation to be safe.
- String helpers it uses are BIOS A-functions (`0x800AE0F0` strcpy,
  `0x800AE090` strncpy, `0x800AE0E0` strlen), all byte-wise, so **strings need
  no alignment**.

**Text box:** shows **3 lines**. Strings with 4 or 5 lines (both occur) scroll
up one line at a time as the typewriter reaches them. Width: measured ≈29
letters after the speaker label, so the patcher limits a line to **28 cells**
(1 per letter, 2 per full-width character; `script.MAX_CELLS`).
"Hey, she just looked at you!" (28) reaches the right edge.

**Typewriter** (EXE, used by the prologue; probably by all dialogue):
`0x800B3F60` text-list entry count, `0x3F62` total glyphs, `0x3F64` first
dialogue entry, `0x3F66` speed, `0x3F68` glyphs revealed. `0x8004EC24` reveals
one glyph every speed+1 frames and returns 1 when all are shown;
`0x8004ECF0` returns the text-list entry (display line) currently being typed.

**Scene scripts time events to display lines.** The prologue is hand-written
code in `NAME_ENT.EXN`: step machines indexed by `0x800E738D`, each step
calling *start line* `0x80144B44` (line index in `*(u8*)0x8014D180`) and
*run line* `0x80144C8C` every frame. Rei's step (0x80148380) waits until
`0x8004ECF0() == 0x800E71E1 + 3`, i.e. until his **4th** display line starts,
then plays his entrance. With a 3-line translation it waited forever (a clean
hang with no error, the box just stays up). **Rule: a translation must keep
the original's number of display lines and choices.** The patcher enforces it
(`script.structure`).

**Voiced lines advance by themselves** (`0x80144E34`–): once the XA clip
reaches its end sector and the text is fully typed, a counter at
`0x800E7384` runs to 61 frames (~1 s) and the scene moves on. Pressing ○
also advances. Per prologue line `i`: speaker/voice byte at
`NAME_ENT.EXN` 0x1BA04+i (low nibble 0xF = no voice), XA position at
0x1BA30+8i, a second table at 0x1BB88+8i.

**Pointers and relocation.** Every dialogue string found so far is reached
only through 32-bit pointers in its own file, as absolute RAM addresses
(file offset + load address). So strings can be repacked freely inside the
space of the strings they replace, if every pointer is updated
(`patcher.apply_dialogue`). The patcher refuses strings that code builds
addresses for (`lui`/`addiu`), and pointers into the middle of a string.

| File | Load address (from its pointers) |
|---|---|
| `EXEDIR/NAME_ENT.EXN` prologue | 0x80132000 (overlay); 43 strings 0x1B1D0–0x1B957, table 0x1B958 |
| `SERIFU/DATE_*`, `EVENT_*` | 0x80198000 (`DATE_FU` and `EVENT_FU` confirmed at runtime; §6j, §6k) |
| `SERIFU/SERIFU, G_APPEAR, G_INVITE, GASSHUKU, GEKO, GROUP_D, HAGEMASI, NYUBU, OMIMAI, SHOGATU, SHUGAKU, VALEN, WHITE, XMAS` | 0x80197000 |
| `SERIFU/G_BIRTH, KARADATA, P_BIRTH, ZAKOSEN` | 0x801B0000 |
| `SERIFU/GASSH_FU` | 0x801B4400 (not on the 0x800 grid; see below) |
| `SERIFU/EPILOG` | 0x80180000 |
| `SERIFU/ENDING` | 0x801F0000 |
| `BUNKA/*` (46 files) | 0x801E8000 |
| `SPEAKTST/TEST_*` (12 files) | 0x80180000 |

(The table is from a scan for the base that makes the most pointers land on
string starts. Only the prologue has been verified in the game.) Sizes, from
`tools/dump_dialogue.py` after the 2026-10-07 extraction fix below (Japanese
bytes, excluding NULs): `SERIFU/` 16,727 strings / ~652 KB, `BUNKA/` 12,898 /
~454 KB, `SPEAKTST/` 16,340 / ~629 KB. The earlier figures (~9,000 / ~9,100
strings) missed every string that follows a pointer table. `EVENT/` has no
dialogue strings.
A few strings (mostly `SPEAKTST`) also contain bytes such as `<`, `>`, `-`,
`n` that the renderer doesn't treat as control codes; `script.decode`
rejects them, so `dump_dialogue.py` leaves them out. Find out what reads them
before translating those files.

**Strings directly after pointer tables (extraction fix, 2026-10-07).** Script
files interleave short pointer lists with the strings they list, so many
strings start right after an aligned pointer word, not after a NUL. In
`SERIFU/EVENT_FU.BIN` the word at `0x648` points at `0x62C` and is
immediately followed by the string at `0x64C`; `0x69C`–`0x6A7` holds three
pointers followed by the string at `0x6A8`. Some words point at other lists
rather than at strings (`0x6F4` → the list at `0x648`, `0x6F8` → the list at
`0x69C`), so scene mapping has to decode a nested table structure; that
structure isn't understood yet.

The old dumper accepted a pointer target only if the byte before it was NUL,
which dropped all of these. `dump_dialogue.starts_string()` now also accepts
an aligned target preceded by a word that points into the same file. That is
a safe boundary: such a word's third byte is below 0x20 for every base in the
table above (0x13–0x1F), which is neither a Shift-JIS byte nor a control
code, so no decodable string can run through it. Effect: `DATE_FU` 186 → 474 strings,
`EVENT_FU` 119 → 157, `GEKO` 615 → 1,011, `TEST_FU` 2,473 → 2,474. All the
pilot offsets below are now dumped. Synthetic regression tests are in
`tests/test_dialogue_extraction.py`.

Method: for every aligned word, take the target `word − base`; if it decodes
as dialogue, classify the byte before it. Across all SERIFU, SPEAKTST and
BUNKA files, 10,658 targets with a non-NUL preceding byte follow an in-file
pointer word. Apart from `GASSH_FU` (wrong base, next paragraph), **no
Japanese-text target is rejected as an interior pointer**. The dumper still
reports left-out targets on stderr (`--rejected` lists them): 691, all
"no Japanese text". The sampled ones are 4-byte binary records
(`code, 0, 0, n`, e.g. `DATE_FU.BIN` `0x548C`, `0x6E38`, `0x6FA0`) whose first
byte happens to be a name-code letter (`A`, `P`, `p`); they are data, not lines.
The patcher's guard against pointers into the middle of translated text is
unchanged and tested.

**`GASSH_FU.BIN` loads at `0x801B4400`**, not `0x801BE000`. Its first pointer
list (file `0x4C`) holds `0x801B4400` and `0x801B441C`, matching the strings at
file offsets 0 and `0x1C`. At that base it has 1,207 strings and no rejected
Japanese targets; at the old base, 183 strings and 969 Japanese targets
that land mid-string. The old search only tried 0x800-aligned bases; `guess_base()` now
also votes on candidates from pointer value minus string start. Every other
SERIFU, SPEAKTST and BUNKA file keeps the base it had before. Static only;
the load address hasn't been traced in the game.

**Character-pack planning inventory (2026-10-07).** With the fixed dumper,
`SERIFU/DATE_FU.BIN` (47,104 file bytes) has 474 pointer-target strings
(25,417 Japanese bytes), `SERIFU/EVENT_FU.BIN` (12,288 bytes) has 157
(4,831 bytes), both at inferred base `0x80198000`; `SPEAKTST/TEST_FU.BIN`
(186,368 bytes) has 2,474 (94,496 bytes) at `0x80180000`. There are 11
`SERIFU/DATE_*` files. These are string counts, including choices and player
replies, not display-line or scene counts. Japanese bytes approximate the
repack pool only for the strings actually translated (each slot also gets its
NUL and alignment padding). The user has selected Shiori for the first pack;
per-scene consumers and runtime load addresses still need tracing. The historical research plan has been retired; this inventory doesn't establish full-file or
full-route coverage.

**Early Shiori pilot candidates (2026-10-07, static inspection only).**
`SERIFU/EVENT_FU.BIN` contains a short early-morning school-walk exchange:
file offsets `0x62C`, `0x64C`, `0x668`, `0x6A8` (inferred RAM `0x8019862C`,
`0x8019864C`, `0x80198668`, `0x801986A8`). The entries cover getting up early,
a greeting, the player addressing Shiori, and a thought after walking to
school; they have 2/2/3/3 display lines with no choices or name codes.
Each has exactly one pointer, at file `0x648`, `0x6A0`, `0x6A4`, `0x6F0`
respectively, and no code references. A dry run of `patcher.apply_dialogue`
with placeholder English on the extracted file accepted all four, rewrote
only those pointers, and reported a 180-byte pool for those four; with the
scene's fifth string `0x2AA8` (§6j) the pool is **188 bytes**. This is a
compact candidate, but **not an early-game event**: §6j decodes its trigger
(Shiori affection ≥ 61 plus another score ≥ 50, nonzero interaction counters,
about a 1% roll per check, once per game). The scene also includes the string
at `0x2AA8`.

A fallback is the shared `SERIFU/GEKO.BIN` Shiori walk-home dialogue (inferred
base `0x80197000`): candidate clusters start at file `0x1A24` (her invitation),
`0x1B50` (accepting a player invitation), `0x1C54` (declining it). The last
contains the two-choice prompt at `0x1C9C` and response at `0x1CD0`. Some of
these strings follow pointer tables; the fixed dumper now includes all five.
Ownership is supported by explicit Shiori references in the exchange, not
just a filename. Actual early-game availability, relationship thresholds,
scene boundaries and shared consumers remain unverified. These candidates
were found by enumerating aligned pointer values in the inferred file range,
decoding their targets and inspecting the local text; no script dumps or
screenshots are committed. Prefer whichever scene is naturally encountered
and replayable near the start, then trace its real loader and scene driver.

**Budgets: the two limits for translating the whole script.**
1. **Space.** English pair text costs 1 byte per letter, Japanese 2 bytes per
   character, and English needs ~2× the characters, so a translation uses
   about as many bytes as the original. The prologue fits (1912 of 1928
   bytes) only after tightening the English. The zero tail of `NAME_ENT.EXN`
   (0x1BCD0–) is **not** free: code references reach 0x253A4 (BSS). Other
   files may have slack; check each.
2. **Pair glyphs: solved.** Pre-drawn pair glyphs needed one free kanji per
   distinct pair (the UI plus the prologue used 383 of 993; prose passes
   ~1,000 distinct pairs after ~80,000 letters). The renderer now composes
   every pair on the fly (§6f), so vocabulary no longer costs anything.

### 6a. Text renderer (all in `SLPM_86.053`, shared by every screen seen so far)

Found by arming a GDB read watchpoint on an Options string *before* opening
the page (`tools/emu/watch_reads.py`). The text is laid out once, when the
screen opens, not every frame.

| Address | Role |
|---|---|
| `0x8004E788` | `add_text(a0 = x, a1 = y, a2 = colour/attr byte, a3 = string, [sp+0x38] = extra byte)`. Appends an 8-byte entry to the text list at `0x800B3DC0` (x s16, y s16, attr u8, glyph count u8, extra u8, 1). Entry count is at `0x800B3F60` (max 52 = 0x34). Called e.g. from `OPTION.EXN` at `0x80132CF0`. |
| `0x8004F268` | `layout_string(string)`. Reads **2 bytes per character, always**, combining them into a 16-bit code; stops at a NUL in either byte. Codes `< 0x8140` go to an error routine (`0x800AE0B0`) and the rest of the string is dropped. Other codes go through the range table to a glyph index. Returns the number of glyphs used. **Patched:** codes ≥ 0xA000 are English letter pairs, composed by the renderer hook (§6f). |
| `0x8004F364` | `render_glyph(index)`. Decodes the glyph (`0x8004F4F0`) into 16×12 4bpp and uploads it to a VRAM glyph-cache slot: x = 0x320 + (slot & 7)·4, y = 0x100 + (slot & 0x78)·2, 4×12 halfwords (`0x8004435C` = LoadImage). The slot counter is at `0x800B3F62`. |
| `0x8004F4F0` | Expands one 18-byte 1bpp glyph into nibbles. |

**Glyph advance:** cached glyphs are placed `index × advance` px apart (the
`multu` at `0x8004EF30` / `0x8004F030`). The advance is a global byte at
**`0x800B3F6A`**, set by `0x8004E750(a0)` to 16 if a0 == 16, else 14. The
text-system reset at `0x8004E708` forces anything other than 14/16 back to 14.
Calls seen: `OPTION.EXN` 0x80132CA0 (14), `NAME_ENT.EXN` 0x801321B4 (**16**,
patched to 14 by `translation/code.json`), 0x80139724 (14), 0x8013BCFC (14).
Pair glyphs are laid out for a 14 px advance (letters at columns 0–4 and
7–11 → an even 7 px per letter). At 16 px they show a gap after every second
letter, so screens that use 16 get patched to 14.

`add_text`'s fifth argument (entry byte 6) is 0 at every call site seen; its
purpose is unknown.

### 6b. Font

- **There is no BIOS font use.** No `Krom2RawAdd` (B0:51) stub exists among the
  EXE's 208 BIOS call stubs. The font is the game's own data.
- **Location:** RAM `0x800B6D50` = `SLPM_86.053` file offset `0x76550`.
  3,418 glyphs × 18 bytes (to `0x855A4`).
- **Format:** 12×12 pixels, 1 bpp, MSB first, rows packed back to back
  (12 bits per row). Latin letters use rows 1–9 for capitals (baseline row 9),
  rows 4–9 for lowercase x-height, and row 10+ for descenders.
- **Code → glyph range table:** RAM `0x800B402C`–`0x800B40E3`, 46 × (u16 first
  code, u16 first glyph index), sorted. Glyph = base + (code − first) of the
  last range with first ≤ code (CRC32 of the table: `0x3CC19FF3`).

  | Codes | Glyphs | Content |
  |---|---|---|
  | 0x8140–0x84BE | 0–452 | punctuation, digits, Ａ–Ｚ, ａ–ｚ, hiragana, katakana, Greek, Cyrillic |
  | 0x889F–0x9872 | 453–3417 | JIS level-1 kanji (亜 … 蓮) |
  | ≥ 0x9873 | none | JIS level-2 kanji aren't in the font; not drawn |

- **ASCII is not supported:** plain ASCII bytes produce codes < 0x8140 and draw
  nothing (tested: the Options item rendered blank). Full-width Ａ–Ｚ works but
  takes 2 bytes and 12 px per letter.
- **English solution in use: letter pairs composed by a renderer hook** (§6f).
  English costs 1 byte and 7 px per letter, any pair of letters is available,
  and the font itself is left untouched.
- **Unused kanji.** `tools/find_free_glyphs.py` → `translation/font/free_glyphs.txt`
  lists 993 level-1 kanji that never appear in the game's text (the heuristic
  is described in that tool). Earlier builds redrew them as pre-drawn letter
  pairs; that pool ran out after a few scenes, which is why the hook replaced
  it. The list isn't used by the patcher any more. It's kept as spare font
  slots (18 bytes each, in runs of at most 11) for future renderer work.

### 6f. Renderer hook: letter pairs composed on the fly (`tokipatch/renderer.py`)

**Why one hook is enough.** A scan of the EXE and every overlay for calls and
address constants found exactly one path into the font: `add_text`
(`jal` at 0x8004E82C) → `layout_string` → `render_glyph` (`jal` at
0x8004F32C) → glyph expander (`jal` at 0x8004F390), which is the only code
that builds the font address (0x8004F4FC) or the range table address
(0x8004F2CC, 0x8004F304). Dialogue goes through the same path (§6e).

**Encoding.** English is ASCII with the top bit set (0x20–0x7E → 0xA0–0xFE),
1 byte per letter, read by `layout_string` two at a time as a code
0xA0A0–0xFEFE. These codes are free:
- No game text uses a lead byte ≥ 0xA0. The font ends at 0x9872 and the
  original lookup draws nothing for higher codes (the range loop at
  0x8004F30C falls off the end of the table without calling `render_glyph`).
- The dialogue renderer (0x80081190) only compares bytes against its ASCII
  control codes (0x20, `q`, `P`, ...) and specific `0x81xx` punctuation;
  every other lead byte is a 2-byte character. Bytes ≥ 0x80 never match.
- `"  "` (two spaces) is still written as 0x8140, the font's own blank, so the
  icon cells on Yes/No lines are unchanged (translation-guide, patterns).

**The hook.** In `layout_string`, 0x8004F2CC/0x8004F2D0 (`lui t1,0x800b;
lhu t1,0x402c(t1)`, the start of the range lookup) become
`j 0x8004443C; andi t0,v1,0xffff` (t0 = the code, as the game computes it at
0x8004F2D4). The hook:
1. Code < 0xA000: runs the two replaced instructions and jumps back to
   0x8004F2D8, so Japanese takes exactly the original path.
2. Otherwise: builds the 18-byte glyph from two 5×12 letters (letter 1 in
   columns 0–4, letter 2 in columns 7–11, the same layout the pre-drawn pairs
   had, so text looks identical), stores it in a scratch glyph, calls
   `render_glyph(index)` with an index that points at the scratch glyph, and
   continues at the loop top 0x8004F294 with `v0 = s1`, exactly like the
   game's own glyph path. It only uses t/a registers; s0/s1/ra are untouched.

The scratch glyph lies *before* the font, so its index is negative
(0xFFFF9A36 = −26058): the expander computes `FONT + index·18` in 32-bit
arithmetic, which wraps to the scratch address 0x8004451C. The scratch only
has to live until the expander has run (it copies the glyph into the 4bpp
upload buffer at 0x801255F0 straight away), so one buffer serves every glyph.

**Where it lives.** Two functions in the EXE that nothing calls:

| Address | Size | Was | Now holds |
|---|---|---|---|
| `0x8004443C` | 708 | a leaf-ish routine reading 0x800B3D10– (GPU state?) | hook code (216 bytes), scratch glyph at 0x8004451C |
| `0x8004B778` | 948 | a leaf routine masking bytes at stride 0x40 | 5×12 font: 96 characters (ASCII 0x20–0x7F) × 8 bytes = 768 bytes |

Font entry format: two little-endian words, rows 0–5 then rows 6–11, row `r`
at bits `5r…5r+4`, bit 4 = leftmost pixel (`renderer.narrow_font()`).

**How "unused" was established** (redo this before using any other region):
- *Static:* no `jal`/`j` to either address in the EXE or any `EXEDIR/*.EXN`;
  no 32-bit word equal to either address in **any file on the disc**; no
  `lui`+`addiu/ori/load` pair building either address, even with the low half
  up to 200 instructions after the `lui`.
- *Runtime:* `tools/emu/watch_exec.py` with execution breakpoints on both
  entry points (and 0x80044700) for 15 minutes of the **unpatched** game:
  boot, title, Options page and sub-screens, album load, name entry, the whole
  prologue, several weeks of the main loop, and a SERIFU dialogue event
  (meeting 如月). 0 hits.
- *Patched:* the patched game ran from boot to the first in-game screen.
  A call into either region would now run hook code or font data and crash.

Other unreferenced functions in the game's own code (static scan only, not
checked at runtime): 0x80049140 (616 bytes, non-leaf), 0x80054C74 (504),
0x8008EFE4 (368), 0x8008D8A0 (364), 0x8005A410 (336), 0x8008F934 (280),
0x80058DA0 (272). The scan treats each `jr ra` + delay slot as a function end
and each `jal` target as a start; 0x8009xxxx and above looks like PsyQ
library code and was left alone.

**Checks.** `renderer.install` refuses to patch unless the hook site holds
the original two instructions and both regions match their original CRC32
(0x95CF8D48, 0xC57F80EA). `tokipatch/mips.py` is a small assembler for the
hook source; capstone disassembles its output back to the same instructions.
`tools/check_renderer.py` runs the hook in a minimal MIPS interpreter (load
delay slots modelled): it produces byte-identical glyphs to
`pairfont.render_pair` for all 6,084 supported pairs and leaves Japanese
codes on the original path. Run it after changing the hook or the font.

**Verified on screen:** title Options page and Menu Mode descriptions, album
prompts with the ○/× icons, all name-entry questions, the whole prologue
(including Rei's line-timed entrance), then the first in-game screen.

### 6g. Main game loop screen (`translation/main_screen.json`)

The weekly command screen: stat panel, vertical calendar, command icons and
the player's thought line in the message box.

- **What's text:** only the speaker name and the thought line (the live
  `add_text` list had 3 entries: a hidden 8-glyph one, the name, the
  13-glyph line). The stat labels, numbers, calendar and icons are sprites
  (§7, "Sprite frames" and `MAINROM.NBN`). A read watchpoint on the 体調
  string at `SLPM_86.053` 0x72AD0 never fired while the panel redrew, so the
  stat-name strings there are used elsewhere (now translated in `outings.json`,
  but their consuming screens remain unverified).
- **Thought lines** are EXE strings reached from code (`lui`/`addiu`), so each
  must fit its own slot. They contain `0x20` line breaks and go through the
  dialogue renderer. The game draws `（`, so they end with `）` and the English
  ends with `)`:
  - **Weekday screen** (Sunday night, "plans for the week"):
    `SLPM_86.053` 0x6F624–0x6F754 (明日から何をしようかな？） and the variants
    for exams, the baseball tournament, summer camp, the school festival,
    the school trip, make-up classes, illness).
  - **Holiday screen** (Sundays and holidays during the day): 0x70DA4–0x70EF8
    (今日は何をしようかな？）, date day, club practice, meeting place, phone).
    Some lines are built from pieces with a name in between, e.g.
    今日は、 + girl + とデートだ）, and それじゃ、⏎ + place + で、⏎ + girl +
    を待つか。）. The English keeps each piece's line breaks and reads with
    the inserted word at the same spot ("Well then," / "<place> it is" /
    "<girl> will come.)").
  - 0x6F610 平日コマンド画面 / 0x70D90 休日コマンド画面 look like debug labels
    and aren't translated.
- **In-game Save/Load (memory card icon, Sunday night only):** 0x6F76C–0x6F9E4.
  The slot panel's labels (名前…, あだ名…, 所属部‥, クリア人数‥) are
  `translation/album_panel_exe.json` (included in normal builds). The user has
  verified English labels, dates and values on populated Load slots 1/2
  (None/Soccer); Save-mode and empty/error/System branches remain unverified (§6i).
- **Date in RAM:** 0x800E62BE year (95), 0x800E62BF month, 0x800E62C0 day,
  0x800E62C1 weekday (0 = Monday … 6 = Sunday). Found by diffing RAM dumps
  of two Sundays. The calendar code at 0x80064CA0– sets the weekday sprite's
  frame to `0x52 + weekday`, and its colour byte to 0x43 (Saturday) or 0x44
  (Sunday or a holiday from the table at 0x800E62C4 + day).

### 6h. Main-loop EXE text tables

The remaining main-loop text in `SLPM_86.053` is not one screen-sized block.
It includes ordinary in-place strings plus several contiguous, pointer-backed
string pools. The latter are declared as `dialogue` blocks even when they are
short labels, so all pointers can be relocated within the original pool:

| File offsets | Contents | Translation |
|---|---|---|
| `0x6F3FC`–`0x71A50` | system title fragments; recurring club, term/holiday, health, Christmas/New Year and sound-effect text; phone/news labels; special name paths | `main_events.json`, `character_names.json` |
| `0x72AD0`–`0x72B1B` | nine textual stat names (not the sprite-based main stat panel) | `outings.json` |
| `0x72B4C`–`0x72C2B` | 20 outing-place names | `outings.json` |
| `0x72C8C`–`0x72DF3` | full and short character-name pools (§6e) | `character_names.json` |
| `0x730A4`–`0x73107` | 11 clubs plus None, including Literature at the start | `clubs.json` |
| `0x751F8`–`0x75FFC` | memory-card check, concert/movie listings, town-news copy and magazine reactions | `town_news.json` |

The stat-name strings at `0x72AD0` still do not drive the main screen's stat
panel: that panel is graphics (§6g/§7). Their exact consumer remains to be
confirmed on screen. Likewise, the place and club tables are identified by
their contents and pointer structure, but every screen that consumes them has
not yet been reached.

The club-list screen is a confirmed consumer of the pool at
`0x730A4`–`0x73107`. The user's original screenshots show ten translated club
names, untranslated Literature, Cancel, a successful Soccer selection and the
“Soccer club joined.” result. Literature at `0x730A4` was omitted when the
pool started at `0x730AC`; it is now included. The complete pool uses 94/100
bytes, and all 12 relocated pointers were checked against the encoded text.
Disassembly of `0x8006B648` confirms that the menu draws only the first eleven
entries from the pointer table at `0x800B3908` (file `0x73108`); None is the
twelfth table entry and Cancel is a separate literal at file `0x70860`.

**Club Day notice: fixed coordinates, not concatenation.** Disassembling
`0x800607E0`–`0x800608B4` shows six separate calls to `add_text` with these
positions (game pixels relative to the text origin):

| String file offset | x | y | Current English |
|---|---:|---:|---|
| `0x7029C` | -86 | 50 | ` Each ` |
| `0x702A4` | -44 | 50 | `3rd Sunday` |
| `0x702B0` | 26 | 50 | ` is` |
| `0x702B8` | -72 | 66 | ` Club Day, so` |
| `0x702CC` | -72 | 82 | `don't   ` (three trailing spaces) |
| `0x702D8` | -16 | 82 | `miss it.` |

At 7 px per English letter, the last two fragments have only eight letters
between their starting positions. The previous `don't miss` used ten encoded
cells including padding, so the final fragment overprinted it. Repartitioning
the words respects that eight-cell limit. The speaker label is drawn through
`0x80050DFC`; a six-byte name starts at x = -128 and ends at -86, immediately
before the first fragment. `Capt.` plus the leading space in ` Each ` gives
the label a visible gap. The old claim that a leading pair-space was dropped
was not established; fixed-position overlap explains the screenshot.

The user's follow-up screenshots and play test verify both corrections:
Literature fits its list column and joining Soccer reaches the captain's
notice without overlapping text. The Literature label extends slightly beyond
the green selector rectangle; the fixed-position notice retains a wide gap
between “don't” and “miss it.”. The user accepts these cosmetic issues for now
and explicitly requests leaving both unchanged. This verifies the corrected
list and notice, not every other consumer of the club-name table.

Not every Shift-JIS-looking run in these regions is player-facing text. The
main-loop translation deliberately leaves the debug labels at `0x6F610`,
`0x70940`, `0x709AC` and `0x70D90`, obsolete album fragments at
`0x6EB40`–`0x6EB67`, renderer punctuation/control literals around
`0x71804`–`0x71A3F`, fixed-width blank town-news rows, and unreferenced
single-kanji data unchanged. These exclusions are also recorded in the JSON
descriptions so a later audit does not repeatedly rediscover them.

### 6i. Save/Load panel and in-game settings (review and user verification, 2026-10-07)

These are `translation/album_panel_exe.json` and `system_settings.json`, now
included in normal builds after testing in the combined `.emu/review_settings/`
candidate. The user reports successful translation of the panel and all
in-game settings submenus. Screenshots show
the main settings list, Text Speed choices/help, and populated Load slots 1/2
with dates and None/Soccer club values. No overlap or clipping was reported.
Detailed coverage and remaining checks are in `testing.md` under the settings
handoff. Promotion changes file discovery only, not the tested patch contents.
The static findings below come from string-reference searches and Capstone
disassembly of the original `extracted/SLPM_86.053`, mapped at `0x80040800`.
They do not establish untested branch behavior or unlock title Options graphics.

**Save/Load panel (`album_panel_exe.json`, 21 strings).** The two literal
groups at file `0x70790`–`0x707F7` and `0x707F8`–`0x70853` are consumed by
the panel code around RAM `0x80069758`–`0x80069F94`. The first branch reads
card metadata indexed by `*(u8*)0x800E7D36`; the second uses the index at
`0x800E7397` into records at `0x80123120`, stride `0xF00`.

- Names and labels are **concatenated**, not independently positioned.
  `strcpy` (`0x800AE0F0`) copies a label into a stack buffer, followed by
  `strncat` (`0x800AE110`) or `strcat` for the value. The buffers are 32 bytes
  apart: date `sp+0xC8`, name `sp+0xA8`, nickname `sp+0x88`, club `sp+0x68`,
  cleared count `sp+0x48`. Name appends are bounded at 6 + 6 bytes, nickname
  at 13; clubs come from the table at `0x800B3908` (current English maximum
  10 bytes), cleared count uses one or two full-width digits (up to 4 bytes).
  `Name: ` / `Nickname: ` / `Club: ` / `Cleared: ` therefore preserve a visible
  separator while using at most 19 / 24 / 17 / 15 bytes including NUL.
  These byte bounds do not prove the fields fit their on-screen panel.
- The number heading appends **only two bytes** from file `0x70790` or
  `0x7080C`. See RAM `0x80069770`–`0x80069784` and
  `0x80069C48`–`0x80069C58`: the latter calls `strncat` with `a2 = 2`.
  The former draft `: Album` would show only `: `; the translation now
  explicitly stores that suffix. The heading is the existing full-width
  slot number plus a colon, not a promised full English "Album" heading.
- Year/month/day suffixes are also two-byte appends, in the date builders
  around `0x80069848` onward and `0x80069CB0`–`0x80069E30`.
  The year/month replacements `/` each encode as one two-byte `/ ` pair;
  the empty day replacement starts with NUL, so it appends nothing.
  No copy lengths, date digits or code instructions are changed.
- The fields share an x origin and draw at y = -64 (date), -48 (name),
  -32 (nickname), -16 (club), 0 (cleared count); the heading is at y = -80,
  x = field origin + 12. Empty/error slots and the System entry use separate
  paths. Test both Save and Load: two copies do not imply both were exercised.

**In-game settings (`system_settings.json`, 114 strings).** Initialization
at RAM `0x8005DC4C` uses file `0x6FA08`–`0x70290`; the main title is passed
to `0x8006612C`. Choices, help and confirmations use the shared text drawer
`0x8004E788`, not title Options' pre-rendered choice graphics.

- Icon Mode confirmations use two distinct rows, x = -128, y = 50 and 66
  (Type A references at `0x8005E660` and `0x8005E67C`; B/Free follow the
  same layout). Cursor Speed and Voice Mode confirmations likewise use
  separate rows (around `0x8005FABC`–`0x8005FD90`, and `0x80060000` onward).
  Their drafts already read correctly across those rows.
- Menu Mode descriptions occupy three rows at y = 50, 66, 82 (around
  `0x8005F380`). Its confirmations also occupy three rows, not a concatenated
  sentence: first x = -128, second x = -86 with color attribute 1, third
  x = -128. The first choice's references are `0x8005F518`, `0x8005F534`,
  `0x8005F550`; the other choices repeat the arrangement. All four now use
  `Menu mode:` / `<mode>` / `selected.`, preserving all three visible pieces.
  The longest mode, `Mouse-like + Menu A`, is 18 bytes / 126 px and fits the
  row's static bounds. The user reports submenu translation success, but
  individual confirmation states and selection rectangles were not itemized.
- Menu Mode confirmation code writes values 0–3 to `0x800E7312`, corresponding
  to Mouse-like, Menu A, Menu B, and Mouse-like + Menu A. This is a static
  mapping, not a runtime identification of the old 95/4/23 test card's mode.
- Cursor Speed has **two label sets**, file `0x6FFEC`–`0x7000C` and
  `0x70014`–`0x7003C`. The branch around `0x8005F7FC` checks bytes at
  `0x800E7D2C` (threshold 9) and `0x800E67C4` (threshold 2) to choose a set.
  The meaning of those input/device conditions remains unverified; do not
  assume one set is dead because only the other appears with a controller.
- Help/confirmation lines retain their separate draws and fit within a
  256 px row at the normal 14 px pair-cell advance. Padding-using labels
  are screenshot-verified for Text Speed (`Normal` fits) and the main list
  with Icon Mode highlighted. Every highlight state was not individually
  documented; the user's broader report covers all submenus' translations.
  No navigation, settings values, selector sizes or coordinates were patched.

### 6j. Girl special events (`SERIFU/EVENT_*.BIN`) and how they're triggered

Found 2026-10-07 by static disassembly (capstone, `tools/mipsdis.py`) of the
original `SLPM_86.053` and overlays, then a GDB run of the **unpatched** game
from the 95/4/23 test card to 95/5/17 (`tools/emu/watch_events.py`). Shiori
is girl id 0 throughout. Nothing here has been patched.

**Scene data in an EVENT file.** A scene is a *master* list of pointers to
string lists, one list per part; a parallel list points at one byte list per
part (one byte per string, `FF`-terminated; probably speaker/expression codes,
not decoded), and a third pointer per scene leads to further per-scene records
(not decoded). In `EVENT_FU.BIN`, scene 2 (the early-morning walk) is master
`0x6F4` → lists `0x648` {`0x62C`}, `0x69C` {`0x2AA8`, `0x64C`, `0x668`},
`0x6F0` {`0x6A8`}; byte lists via `0x70C` → `06` / `0C 0D 00` / `06`. The
string at `0x2AA8` lies far from the rest and is part of the scene too.
Scene 1 is master `0x390`, byte lists via `0x3C0`.

**Event table.** GEKO, DATE, GYOZI, SHOUGATU and SHUGAKU each contain the
same 237-word table (GEKO: `0x80145EC0`, written by code at
`0x8013799C`–`0x80138828`): 79 masters, then 79 byte-list pointers, then 79
third pointers. Shiori's events are entries **6–13**. Each event has a setup
function that copies entry k of the three tables to the current-event slots
`0x80146274/78/7C`; entry 7 (scene 2) is set up at `0x8013AA1C`, which also
sets girl id `0x800E71DF = 0`. `EVENT.EXN` contains a similar per-girl table,
but its offsets don't match the disc's `EVENT_FU.BIN` (e.g. `0x6F8` for
`0x6F4`) and its code calls addresses outside the main EXE, so it looks like
a stale build; the overlay loader never loads it (§3).

**Loading.** GEKO's `0x80138F7C` switches on girl id `*(u8*)0x800E71DF`
(14 cases) and reads that girl's EVENT file: Shiori's case reads LBA 44581
(`EVENT_FU.BIN`), 6 sectors, to `0x80198000`. This confirms the
`0x80198000` base statically; DATE, SHOUGATU and SHUGAKU have the same loader
(immediates `0x8014C840`, `0x8013D3F8`, `0x80137744`).

**Dispatch.** `*(u32*)0x80122CD4` = girl id, `*(u32*)0x80122CD0` = scene.
GEKO's `0x80138840` jumps through `0x80144910` on the girl id; Shiori's
handler `0x80139A8C` runs scene 1 → `0x80139B08`, scene 2 → `0x8013A144`,
scene 8 → `0x8013A230`. Each scene is a step machine: a copied list of
function pointers indexed by the step byte `0x800E738A` (scene 2's list is at
`0x801464BC`, starting with the setup above and later the EVENT loader).

**Main-loop event queue.** The EXE's main state is set by `0x80042878(state)`
(`0x800E7388`). Each day's event is a 4-byte record `type, girl, scene, flags`
in a queue starting at `0x800E691C`, current index `0x800E699C`. The day
handler around `0x800714D0`–`0x800722B8` switches on the record type: case
`0x800721B0` copies girl/scene into `0x80122CD4/CD0` (special events), case
`0x80072210` sets the girl id and enters state `0x5B` (meeting scenes). In
the test run, type-`0x48` records produced meetings with girl 1 (95/5/10) and
girl 8 (95/5/17); no Shiori special event occurred.

**Why the walk is rare: `0x8006FB4C`.** The queue builder (`0x80070B80`)
asks this selector for a (girl, scene) pair and writes it as a type-`0x45`
record. The selector loops over girls 0–10 and, for each, requires:
the met flag (bit 1 of `0x800E6448 + 0x38·g`), rank `0x80051B48(g) < 2`,
a nonzero sum of 20 per-girl counters (`0x800E6451 + 0x38·g`; all were 0 at
95/5/17), and `rand() & 15 < 5`, then jumps through `0x800B1314` by girl.
Shiori's case `0x8006FC70` requires `rand() % 100 < 3`; then if bit 0 of
`0x800E7378` is 1 it may pick scene 1 (needs `0x80066ACC() == 1`,
`0x80051A68(0) & 0x7F < 2` and flag `0x800E67EC == 0`), otherwise **scene 2,
once, if flag `0x800E67ED == 0`** (the flag is then set).

The rank function returns 4 if A < 10, 3 if A < 50, 2 if B < 50, 1 if
B < 80, else 0, with A = `0x80052C88(g)` = weight × affection / 100, clamped
to 0–100 (weight byte at `0x800B41A0 + g`, Shiori 83; affection = s16 at
`0x800E6442 + 0x38·g`) and B = `0x80052648(g)` (another score, not decoded).
So scene 2 needs **A ≥ 50 (Shiori's affection ≥ 61) and B ≥ 50**, the
counters above, and a roll of about 1% per check. On the test card at 95/5/17
her affection was 47 (A = 39). **The walk is not an early-game event.**

Other Shiori scenes found on the way: scene 8 is chosen by the EXE directly
(`0x80075628`) when `0x800754C0()` returns 1: two packed month/day fields
(`0x800E6378` vs `0x800E644C`, probably birthdays) must match, in March or
early April, among other checks. The injury message step machine
(`0x80073198`, string file `0x709D0`) can start a one-shot event for girl
`0x0B` scene 2 when `0x800E7378 & 0xFF < 0x19`, flag `0x800E6837 == 0` and
`0x800E62BD == 0`.

**Forced in the emulator (2026-10-07, unpatched).** The day handler's
record-type switch is the jump table at `0x800B1340`, indexed by the type
itself (`type < 0x4B`): type `0x45` → `0x800721B0`, type `0x48` →
`0x80072210`. `tools/emu/force_event.py 0 2 --clear-flag 0x800E67ED` stops
at `0x80071DD0` (index already advanced, record about to be read) and turns
the next type-`0x00` record into `45 00 02 00`. From the 95/4/23 test card
that was Tuesday 95/4/25; the scene played in full and the rest of the week
ran normally, twice. `trace_reads.py` during the replay showed
`EVENT_FU.BIN` (LBA 44581, 6 sectors) read to **`0x80198000`** from
`ra = 0x80138FC4` (the GEKO loader above), then Shiori's portrait
`BUSTUP/HU02.BIN` to `0x80180000`. That confirms the load address at
runtime. What the screen showed, in order:
1. `0x62C`: the player's thought (`（`), 2 lines, over a morning street.
2. `0x2AA8` + `0x64C` **in one box**: label 藤崎 and `「`, then
   "あっ、{P}" as line 1 and the two-line greeting as lines 2–3. The part's
   byte list gives these two strings `0C` and `0D`.
3. `0x668`: the player speaking (`『`, code `00`), 3 lines.
4. `0x6A8`: the player's thought (code `06`), 3 lines.
With this test save `{P}` displayed as ま君 in both the unpatched and the
English build; whether the 君 comes from a name field or the code isn't
established. A translation of `0x2AA8` + `0x64C` must still fit
the 3-line box together, since they share it.

**All of `EVENT_FU.BIN` (2026-10-07, static).** Every one of the file's
157 strings belongs to exactly one of Shiori's eight table entries; a part's
string count is the length of its `FF`-terminated byte list (string lists
can be back to back). Per-string codes: `00` player (『), `01` Shiori (「),
`06` thought (both brackets drawn by the game), `0C` + `0D` two Shiori
strings sharing one box, `07` and `10` sound-effect lines (a click, a phone
ringing). Short one-word strings are stored together at `0x2AA8`–`0x2AF0`;
each still belongs to one scene. Who runs each entry (setup function found by its table
loads, then its scene step list, then the dispatcher):

| Entry | Master | Overlay, selector | Strings | Content | Trigger (static) |
|---|---|---|---:|---|---|
| 6 | `0x390` | GEKO, scene 1 | 21 | sudden rain on the way home, Shiori without an umbrella | selector `0x8006FB4C` (bit 0 of `0x800E7378` set): `0x80066ACC() == 1` (a date-window check), rank `0x80051A68(0) & 0x7F < 2`, flag `0x800E67EC` |
| 7 | `0x6F4` | GEKO, scene 2 | 5 | morning walk (translated) | see above |
| 8 | `0xA78` | DATE, scene 3 | 19 | "do you remember this place?" | `0x800CA2F8 == 0`, months 9–11, both ranks best, flag `0x800E67EE`, date step `0x800E7389/738A == 1/1` |
| 9 | `0xFFC` | DATE, scene 4 | 18 | park date in spring | place 1 (Kirameki Park), months 3–5, flag `0x800E67EF`, date step `0x738A == 13` |
| 10 | `0x14DC` | DATE, scene 5 | 15 | theme park in winter, stuck on the Ferris wheel | place 12 (Theme Park), months 12–2, both ranks best plus bit `0x80` of `0x80051A68`, flag `0x800E67F0`, `*(u32*)0x80122CDC == 2`, step `1/0x23` |
| 11 | `0x18FC` | DATE, scene 6 | 16 | pool in summer, Shiori goes missing | place 16 (Pool), year ≥ 96, months 6–8, `0x80051A68 & 0x7F < 3`, rank < 2, flag `0x800E67F1`, girl byte `0x800E646D`, step `1/10` |
| 12 | `0x1D78` | SHOUGATU, Christmas party stage 6 | 21 | walking home after the Christmas party, white Christmas | Christmas-party flow (state `0x52`); stage 3's girl selector `0x80140030` picks stage 6 when `*(u8*)0x80145FE4 == 0` (set in stage 2), writes girl 0 / scene id 7 and counts up flag `0x800E67F2` |
| 13 | `0x2584` | GEKO, scene 8 | 42 | Shiori phones the player | EXE `0x800754C0` (two packed month/day fields equal, March or early April) |

DATE's top-level switch (`0x8014C0C8`, table `0x8015B3D0`) is on the girl id
in `0x80122CD4` too; case 0 runs Shiori's dispatcher `0x8014F370`, which maps
scene ids 3/4/5/6 to step machines `0x8014FAE0`/`FBA0`/`FC80`/`FE90`. Date
events are chosen by `0x8013272C` (girl id first) through the helper
`0x801326B0(scene, one_shot, flag_index)`, which sets `0x80122CD0`, sets the
one-shot byte `0x800E67EC + flag_index` and enters state `0x5E`. Flags come
in blocks of 7 per girl; Shiori's are indices 0–6 (`0x800E67EC`–`F2`).
**Place ids are 1-based** indexes of the outing-name table (file
`0x72C30`): the scene texts match (park, Ferris wheel, swimming). Place 0
(entry 8) is the neighborhood park (近所の公園, seen on screen); its name isn't in the outing table. GYOZI.EXN does not run any Shiori event: its
read at `0x80135BC8` takes index 8 of its own scene tables, and the third
word only coincides with the event table.

**On screen (2026-10-07, forced, unpatched and English).** Sound lines
(codes `07`, `10`) are drawn at the box's left edge in light blue with no
label or bracket. Strings with 4 lines scroll and the label scrolls away
with the first line; a `0C` + `0D` pair longer than 3 lines scrolls the same
way. In the English build `{G}` showed "Shiori" in the player's line, so it
expands from the translated name table; `{p}` showed the test save's ま and
Shiori's `{P}` showed ま君. The rain scene starts in the classroom, the phone
call moves to Shiori's room.

**Dates and the other event flows (2026-10-07, traced and forced).**
- **Appointments.** Eight slots at `0x800E67CC + 4·i`: bits 0–4 place
  (1-based; 0 = neighborhood park), 12–15 month, 16–20 day, 24 a flag,
  25–28 girl, 29 active. `0x8006AEC4(year, month, day)` checks the slots
  against today's date; on a match the holiday screen says "today I have a
  date with <girl>" and the heart icon starts it. The launcher `0x80076DA0`
  copies slot 0's girl/place into a `[0x80, girl, place]` queue record and
  enters state `0x50` (DATE.EXN). Writing slot 0 on the 95/4/23 test save
  (`tools/emu/force_date.py`) gives a real date with Shiori on 4/30.
- **Date-event chooser.** DATE.EXN calls `0x8013272C` at each date step
  (`0x800E7389`/`738A`); the steps seen were 0/15, 0/41, then 1/x. A park
  date reached 1/13 and picked scene 4 by itself. The other three need a
  season and affection ranks the test save lacks, so the tool jumps to the
  scene's call (PC write through the GDB stub) at its step: 1/1 (scene 3,
  place 0), 1/35 (scene 5, theme park), 1/10 (scene 6, pool). The scene
  plays and the date ends normally. The theme-park date asks which ride
  first (DATE_FU text); the forced Ferris-wheel scene doesn't follow that
  choice.
- **SHOUGATU flows.** State `0x52` runs the Christmas-party flow through
  the stage dispatcher `0x8013D180` (stage in `0x800E7389`; stages 6/7/8 are
  Shiori/KG/MI's after-party scenes, their entries 12/36/60). The day-record
  type `0x30` runs White Day (state `0x55`; Ijuin in the hallway, then a
  reply event when a girl gave chocolate; §6u), and type `0x31`
  Valentine's Day (state `0x54`, VALEN.EXN, §6v). A forced type-`0x48` record
  (meeting) with girl 0 returned the game to the title screen: don't force
  it for Shiori. `tools/emu/force_christmas.py` swaps the next weekday's
  state `0x40` for `0x52` and sets stage 6 / girl 0 / scene id 7; with
  `--party` it starts the party itself (stages 0–4, XMAS.BIN, §6t).
- **Overlay entry points** (GEKO `0x8013882C`, DATE `0x8014C0A0`,
  SHOUGATU `0x8013D180`) aren't referenced by any `jal`, data word or
  `lui`/`addiu` pair in the EXE or overlays; how the EXE calls them isn't
  known yet.

**Overlay selection.** The loader switch (§3) is indexed by
`*(u8*)0x800E738E − 0x11` through the jump table at `0x800B19E8`
(0x81 entries). GEKO.EXN is loaded for values `0x45`, `0x46`, `0x48`, `0x49`,
`0x4C` of that index (mapped by following each case to its LBA constant;
cases falling through to a shared default weren't separated).

### 6k. Regular dates (`SERIFU/DATE_FU.BIN`) and choices

Found 2026-10-07 by static disassembly of `DATE.EXN` and the EXE, then forced
museum dates in DuckStation (unpatched and English; testing.md "Testing date
conversations"). All 27 sections are translated in
`translation/shiori_dates.json` (2026-10-08; 471 of 476 strings, the five
pure-punctuation pause lines stay Japanese). Yuko's `DATE_AS.BIN` is in
`translation/yuko_dates.json` (456 of 460; see "Other girls' date files").

**Section table.** `DATE.EXN` holds three parallel 27-entry tables at
`0x8015BDC0` (masters), `0x8015BE2C` (byte lists) and `0x8015BE98` (third
pointers), statically holding Shiori's `DATE_FU.BIN` offsets (code from
`0x80141050` on rewrites them for other girls, like GEKO's event table).
Each section has the EVENT_FU layout (§6j): master → one string list per
part, a parallel `FF`-terminated code byte per string. **All 474 strings are
reached from these 27 sections, each exactly once, and each string has
exactly one pointer.** A section's setup copies its entry to
`0x800CA160/164/168`.

**Places.** The date setup switches on the place `*(u8*)0x800CA2F8` − 1
through the jump table at `0x8015B060` (20 cases, `0x80144A70`–`0x80144BA0`),
each storing one setup function. Place ids are the 1-based outing ids (§6j):

| Section | File range | Strings | Place / use | Setup |
|---:|---|---:|---|---|
| 0 | `0x0`–`0x6A8` | 30 | 7 Art Museum | `0x80134C64` |
| 1 | `0xB48`–`0xD50` | 10 | 10 Bowling Alley | `0x80135620` |
| 2 | `0xF44`–`0x1168` | 8 | 15 Concert Hall | `0x80136340` |
| 3 | `0x1330`–`0x166C` | 15 | 4 Zoo | `0x801344C8` |
| 4 | `0x2414`–`0x26AC` | 17 | 18 Shrine (festival, yukata) | `0x80136A74` |
| 5 | `0x2A78`–`0x2E44` | 15 | 9 Arcade | `0x801353F8` |
| 6 | `0x3B10`–`0x3D38` | 10 | 11 Karaoke | `0x80135804` |
| 7 | `0x3F40`–`0x4178` | 12 | 0 Neighborhood park: talk, ask about her hobbies or favorite places | `0x80133DE8` |
| 8 | `0x4B0C`–`0x4D68` | 8 | 14 Cinema | `0x80135E7C` |
| 9 | `0x4F40`–`0x5020` | 6 | parade invitation, inside the Theme Park date's flow | `0x8013BBF0` |
| 10 | `0x5130`–`0x5324` | 10 | 16 Pool | `0x801366A4` |
| 11 | `0x5514`–`0x5984` | 16 | 6 Planetarium | `0x801349A0` |
| 12 | `0x5E08`–`0x5FB4` | 8 | 17 Beach | `0x80136870` |
| 13 | `0x6170`–`0x6354` | 10 | 5 Botanical Garden | `0x801347B8` |
| 14 | `0x6534`–`0x6C9C` | 30 | 2 Shopping | `0x80135B4C` |
| 15 | `0x71A0`–`0x73BC` | 10 | 19 Skating Rink | `0x80136B70` |
| 16 | `0x7594`–`0x7764` | 10 | 20 Ski Resort | `0x80136D3C` |
| 17 | `0x7958`–`0x7E60` | 21 | 13 Stadium | `0x80135C14` |
| 18 | `0x81F0`–`0x84F0` | 15 | 3 Aquarium | `0x8013426C` |
| 19 | `0x8774`–`0x8964` | 10 | 8 Library | `0x8013518C` |
| 20 | `0x8B4C`–`0xA25C` | 85 | 12 Theme Park | `0x80135A34` |
| 21 | `0xAF94`–`0xB348` | 18 | 1 Kirameki Park (walk) | `0x80133EA0` |
| 22 | `0x18F4`–`0x1EDC` | 36 | end of every date (her verdict, the player's answer) | `0x8013B488`, `0x80140CE0` |
| 23 | `0x3104`–`0x3630` | 35 | meeting at the place (waiting, her being late) | `0x8013AE5C` |
| 24 | `0x4368`–`0x449C` | 10 | seasonal small talk | `0x8013AF1C` |
| 25 | `0x461C`–`0x4900` | 13 | "found out that her hobby is ..." notes (code `04`) | `0x8013B884` |
| 26 | `0x5CCC`–`0x5D3C` | 4 | "let's go home, {P}" | `0x8013B7B0` |

(The place switch, sections 0, 4, 7, 21 and 17, and the part selection of
22, 23, 24 and 26 below were confirmed by forcing them; 9 and 25 statically.) A date runs 23 → 24 (on
certain days) → the place's section → 22 → 26, with an impression thought
after each choice (below). `tools/date_sections.py` prints this table with
part/choice counts and each place's forcing address.

**The date's step machine.** DATE.EXN runs a date as a list of step
functions indexed by the step byte `0x800E738A` (`0x8004284C` advances it;
`0x8007C784` waits for a CD read, then advances). The runner `0x801449D4`
copies the list for the place — jump table `0x8015B0B0` on the place byte
`0x800CA2F8` (0–20) picks one of 21 lists; place 0's is at `0x8015BF50`,
the Theme Park's (104 steps) at `0x8015C738` — and replaces the placeholder
entry `0x80133DE8` with the place's setup for places 1–20. Place 0 keeps it,
so **section 7 is the neighborhood-park date**. The first steps load the
files: step 3 `SERIFU.BIN` (LBA 44870) to `0x80197000`, step 5 the girl's
`DATE_xx.BIN` (`DATE_FU` LBA 44329, 23 sectors) to `0x80198000` and fills the
section tables (`0x80141004` for Shiori), step 7 `TAKU3.BIN` (LBA 44969) to
`0x801A4000` (the impression tables at `0x801A427C`/`0x801A4D2C` are in
it). The parade setup `0x8013BBF0` sits at steps 61, 72 and 74 of the Theme
Park list, so **section 9 is a Theme Park sub-scene** (not forced yet).

**Kirameki Park in spring.** On 4/30 a Kirameki Park date reaches date step
13 right after the "let's go" exchange and plays EVENT_FU scene 4 instead
of the version's remark and choice. Setting its one-shot flag
`*(u8*)0x800E67EF` = 1 before then lets the section-21 part play (seen with
the pond version). **Shopping (section 14)** with the clothes option ran:
part 0 → reply → part 4 ("can I go look?") → pause (part 5) → part 6
(sorry + waiting choice) → reply → ending; which of the later parts
(carrying, cute item, necklace, junk shop) follow other first choices
wasn't traced.

**Arcade and Theme Park, seen 2026-10-08.** The Arcade's version byte picks
its part directly (version 0 → part 2, the "I don't come here much" choice;
1 → part 4, which games); the video/medal action choice (part 1) did not
come up with either. A forced Theme Park date on 4/30 went straight to
"where to next?" (part 9: roller coaster / Ghost House / Ferris wheel), one
ride with its remark, choice and reply, then the ending; the hero show
(parts 1–8) and the parade (section 9) did not come up, and their
conditions weren't traced.

**Neighborhood park (section 7, place 0).** Seen on screen: Shiori's
remark, an unlabelled narration line (`07`), a two-option action choice
(`08`: ask about her hobbies / find out places she likes), a centered
"・・・" pause (`07`), then the hobby note (`04`) as a thought with brackets
drawn by the game, then the ending. The part is 2·mood, set by
`0x8013A898` (a step of the park list): force with
`--at 0x8013A8B0 --reg v0=RANK`.

**Versions of a place.** Fifteen places pick a version byte `0x800CA2FC` in
their setup and the parts-per-version byte `0x8015B658`; `0x801324DC` then
adds version × parts-per-version to the part index `*(s16*)0x800CA148`. The
first read of `0x800CA2FC` in each setup is where `force_date.py --version N`
writes it (`date_sections.py` lists the addresses; checked for places 7, 1
and 13). Shopping, Theme Park, Cinema, Concert Hall and Shrine have no
version byte: they branch on choices.

**Shared sections: which part plays** (found statically, then forced on
screen with `tools/emu/break_set.py` rules; mood = `(r ≥ 2) + (r ≥ 3)` and
band = `(r ≥ 2) + (r ≥ 3) + (r ≥ 4)` for `r = 0x80051A68(girl) & 0x7F`,
lower is better):
- **23 meeting.** At date start `0x801447C4` sets the arrival byte
  `*(u8*)0x8015B654` = 1 (both on time), or 0 (she's late) when
  `*(u32*)0x800E7378 & 3 == 0` and the girl isn't 2; the flow at
  `0x8013F214` sets 2 (the player is late) when the meeting place doesn't
  match (`0x800E69A4`/`69A5`; not traced further). `0x80132564` computes the
  part into `*(s16*)0x8015BF04`: arrival 0 → 2·mood (player waits) then +1
  (her apology); arrival 1 → 6 + mood; arrival 2 → 9 + mood. If the s16 at
  `0x800E6396` (probably the player's Looks) is below 30 (35 for girl 7),
  `0x8013F544` uses part 12 (silence) then 13 (she runs off, the player goes
  home) and the date ends. Forced: arrival 2 / mood 1 → part 10, arrival 0 /
  mood 2 → parts 4–5, `0x800E6396` = 10 → parts 12–13.
- **24 small talk.** `0x8013AF1C`, at the date's first step, by calendar
  day only: part 0 on 3/21 (3/20 in 96), part 1 on 7/23 (95), 7/28 (96) or
  7/27 (97), part 2 or 3 at random on 9/23 (9/22 in 96), part 4 on 12/23;
  other days have none (`0x8013B0D4`). Forced part 0 by jumping from
  `0x8013B0D4` to `0x8013B0E4` with `0x8015BF0C` = 0.
- **22 ending.** `0x8013B488`: part = 3·band + the date's result (s16 at
  `0x800CA234 + 2·*(u32*)0x80122CDC`, 0–2, from the choices) via
  `0x800CA158`; special cases set 10 (`0x800E69DC` ≠ 0), 11 (a repeat of the
  last place), 18/19 (girl 6). The value lives at `sp+0x3A` and is
  recomputed every frame up to `0x8013B6F8`. Parts 12–17 (thanks for the
  anthology the player gave her) come from `0x80140C84`: 12 + mood + 3 if
  year ≥ 96. Forced part 9 (rewriting `sp+0x3A` at every hit).
- **26 going home.** `0x8013B7B0`: part = band (0–3) in `0x8015BF14`.
  Forced band 3 and band 1.
- **25 hobby notes.** Shown after section 7's choice: part = the choice
  (`*(u32*)0x80122CDC` → `0x8015BF1C`), line = `rand % count` in
  `0x8015BF20` (`0x8013AA4C`–); part 4 (she likes a boy) needs the best
  rank and bit 5 of the girl's byte at `+0x1C8`. Seen after a park date
  (place 0) choosing "ask about her hobbies": a part-0 note.

**Code bytes** (per string, as in EVENT_FU): `00` player (『), `01` Shiori
(「), `02` Shiori's reply to the last choice, `03` player choice (a spoken
line), `04` narration, `06` thought, `07` sound or narration line, `08`
action choice (e.g. "praise her yukata / don't"). **`n` marks an empty
option**: in section 4 the player's compliment `0x2450` ends in `nn` and
Shiori's reply `0x2478` is "thanks{q}nn". Seen on screen at the Shrine:
choosing to praise shows the compliment (no trace of `nn`) and her thanks;
choosing not to skips both lines. The picker skips an option that starts
with `n` (`0x80081024`); the renderer drops `nn` as an invalid code. Seven of
the eleven DATE files have the same pair (FU, KA, KG, KI, KY, MI, NI, and
their SPEAKTST copies); AS, HI, KO and SA have no yukata exchange and no
`n` at all (checked 2026-10-08 by searching for 浴衣 and `nn`). No other
script uses `n`. `script.py` decodes it as `{n}` only as a run ending an option,
and the structure check keeps it there.

**Speaking a part: EXE `0x8007EF48(string, code, option, ...)`.** It
`strcpy`s the string to a stack buffer (`sp+0x7C`) and switches on the code
through `0x800B22A8` (20 cases). For a reply (`02`) the loop at
`0x80080F48`–`0x80081020` walks the copy, stepping 1 byte over control codes
(space, `m M A W O F Y p G P S`) and 2 bytes over anything else, and cuts it
at the option-th `q` (or NUL); an option whose first byte is `n` is skipped
(`0x80081024`). The chosen option is then drawn with the label and bracket
by the dialogue renderer `0x80081190`. **The script string itself is never
written**, so several pointers may share one copy of identical text
(`share_identical`, translation-guide). Pair-encoded English is 2 bytes per
pair, both ≥ `0xA0`, so the walk stays in step.

**Choices on screen.** A `03` string's options are shown in a full-width box
without a label, each wrapped in `『』` drawn by the game, **in a shuffled
order** (seen 3-1-2, 1-2-3, ...). The reply is the option *chosen*, not its
position. Option widths: Japanese uses up to 17 characters; the box is about
33 letters wide, so the 28-cell dialogue limit is safe. An option with an
odd letter count shows its pair padding as a space before `』`, so keep
options even.

**Museum (section 0) flow.** 19 parts: five exhibitions × (`01 00` going in,
`01 03` remark + choice, `02` reply), then variant 5 (part 15 going in, then
one of parts 16–18). Setup `0x80134C64` sets the exhibition byte
`0x800CA2FC`: year 97 (`0x800E62BE == 0x61`) months 9–11 → 2, year 97
months 3–5 → 3, year 95 months 9–11 → 4, otherwise 0 or 1 by bit 0 of
`0x800E645B + 0x38·girl`; 2–4 become 5 if that girl's per-exhibition seen
byte (`0x800E645C/D/E + 0x38·girl`) is set. `0x801324DC` adds
variant × parts-per-variant (byte `0x8015B658`, 3 here) to the part index
`*(s16*)0x800CA148`. Variant 5's line is part 16 + mood, added at `0x801392F0` (rank call just
before): affection 48 → `0x6A8`, 200 → `0x688`; forcing `v0 = 0` at
`0x801392F0` showed `0x660`. (`0x80132570` is the meeting's mood, not
this.) The talk runner is EXE `0x80082764`. The
tables `*(0x8015B520)` = `0x801A427C` and `*(0x8015B524)` = `0x801A4D2C`
(15 bytes per girl, loaded from another file) give each choice's
impression level, copied to `0x800CA21C`–`0x800CA230`.

**Other girls' date files (checked 2026-10-08, static).** DATE.EXN's step
that loads the girl's file (`0x8013E7B0`) switches on the date's girl byte
`*(u8*)0x800E69DD` (jump table `0x8015AFE4`, girls 0–9; girl 10 is the
default case `0x8013E94C`). Each case calls a **fill function** that writes
all 81 section-table words as `lui`/`ori` immediates (`0x80141004`
Shiori, `0x80141518` Mio, `0x801419FC` Yuina, `0x80141EE0` Ayako,
`0x801423C4` Saki, `0x801428D8` Yukari, `0x80142DEC` Nozomi, `0x80143300`
Mira, `0x80143814` Yuko, `0x80143D28` Megumi, `0x8014420C` Yumi), then
reads her `DATE_xx.BIN` (FU, KI, HI, KA, NI, KO, KY, KG, AS, MI, SA) to
`0x80198000` by LBA. All files use the same 27-section layout and the same
place setups; `tools/date_sections.py --girl N` simulates the fill
function and lists that girl's sections.

- **Yuko (`DATE_AS.BIN`, girl 8):** all 27 sections valid; they reach
  exactly the 460 strings `dump_dialogue.py` finds, each once. Part counts
  match Shiori's except the Shrine (13 parts vs 15; no yukata pair),
  Shopping (11 vs 20), Library (5 vs 6) and Theme Park (55 vs 57).
  Translated 2026-10-08 (`translation/yuko_dates.json`).
  - **Library version 1 reads past her list.** The setup still assumes 2
    versions of 3 parts. Seen on screen, unpatched and English alike
    (`--version 1`): part 3 (going in), part 4 ("I'm done with the
    library, I'm going home"), then "part 5", which is the word after her
    5-entry master (`0x00FF0001`, code bytes at `0x7798`) with byte list
    `0x1700001C`: an **empty choice box**; ○ on it gives the bad-impression
    thought and the date ends normally. Those words are code-list and table
    bytes the translation never changes, so the English build behaves the
    same. Not checked on real hardware, where such a read could fault.
  - **Her date events (EVENT_AS)** are picked in the date-event chooser
    (`0x8013272C`, Yuko's block at `0x80133618`, girl `0x800E71DF` = 8);
    each fires once at its date step (`0x800E738A`) and sub-step 1:
    Arcade (place 9) in months 3–5, flag `0x800E6823`, step 12 → scene 2
    (a crane-game scene; it took over a forced 4/30 Arcade date, and
    setting the flag to 1 in the meeting rule let the regular part play);
    Theme Park (12) months 6–8 with `*(u8*)0x8015B680` = 1, flag `0x6824`,
    step `0x3C` → scene 3; Concert Hall (15) months 9–11 with
    `*(u8*)0x8015B688` = 10, flag `0x6825`, step `0x11` → scene 4; Skating
    Rink (19) in months 12, 1, 2, flag `0x6826`, step 8 → scene 5; Library
    (8) on 95/12/10, 96/12/8 or 97/12/7 with bit 17 of `0x800E6374`, step
    0 → scene 6. The Arcade case also checks `*(u8*)0x8015B670` and
    `*(u32*)0x80122CDC`; the rank values (`sp+0x31`/`0x33`) some cases test
    weren't decoded. (Shiori's flags are `0x800E67EE`–`0x800E67F1`.)
    The Library's one-shot flag is index `0x3B` (`0x800E6827`). The
    chooser's call sites (each loads the scene into `a0`, then calls
    `0x801326B0`): scene 2 `0x80133684`, 3 `0x801336FC`, 4 `0x80133760`,
    5 `0x801337BC`, 6 `0x80133860`; `force_date.py 8 PLACE … --scene N`
    jumps there. A Theme Park date that takes one ride ends at step
    `0x38` without reaching `0x3C` (the parade steps follow later rides),
    so the parade scene was forced with `--any-step`.
  - **EVENT_AS.BIN** (LBA 44577, 4 sectors, base `0x80198000`, checksum
    trailer, 89 strings) is entries **0–5** of the shared event table (§6j;
    Shiori's are 6–13). Entries 1–5 are scenes 2–6 above (DATE reads them
    at `0x8014D0A4` ff.); entry 0, the staff room, is GEKO's girl-8 scene 1
    (handler `0x80139470`, setup `0x80139640`; a `45 08 01 00` day record
    plays it). SHOUGATU and SHUGAKU load EVENT_AS with their generic
    per-girl loader but read none of entries 0–5 (they use 12/36/60 and
    19/29/48/66). Entry 0 has the in-string label `{>先生}` (§6p).
    Translated in `translation/yuko_events.json` (2026-10-08).
- **The other nine girls** (checked while translating them, 2026-10-10).
  Mio, Yuina, Ayako and Megumi have no Ski Resort date: section 16 is a
  null entry (master and code lists 0) in their fill functions
  (`date_sections.py` reports it as "outside the file, not read"). The 4–9
  strings per girl that the tables reach but `dump_dialogue.py` misses (Mio,
  Yuina, Nozomi, Mira, Megumi, Yumi) are empty placeholder strings: there is
  nothing to translate in them. Their place banners are DATE.EXN's own
  strings (below). Translated in `translation/{mio,yuina,ayako,saki,yukari,
  nozomi,mira,megumi,yumi}_dates.json`; the few pure-punctuation pause
  lines stay Japanese, as in Shiori's and Yuko's files.
- **Location banners** during dates (the spot inside a place, e.g. 並木道
  "Tree-lined Path"; not the 21 place names of §6l, which `date_shared.json`
  patches in their slots): 73 strings, 47 distinct, in DATE.EXN
  `0x28B20`–`0x28E90`, each built once by a `lui`/`addiu` pair and
  `strcpy`'d into a buffer of about 20 bytes. They are too
  short in place, so `tools/repack_words.py` lays the English out again in
  the same region (pair-encoded, NUL-terminated, 2-byte aligned, identical
  names shared) and rewrites each `addiu` immediate: one `bytes` patch for
  the region plus one per reference (`translation/date_banners.json`). The
  tool refuses a region that a data word points into, a string with no
  reader, an address in the middle of a string, or a region crossing a
  `lui` boundary.

**Impression thoughts** after each choice (the player's thought, in levels
from a great impression to a bad one) are not in `DATE_FU`: they are in the
shared `SERIFU/SERIFU.BIN` (§6l), with copies in `SPEAKTST/TEST_OT.BIN`.

### 6l. Shared date lines (`SERIFU/SERIFU.BIN`)

Found 2026-10-08 by dumping the file and statically tracing `DATE.EXN`,
then forced in DuckStation (testing.md, "SERIFU.BIN"). Translated in
`translation/date_shared.json`.

**File.** 4,096 bytes (2 sectors, LBA 44870), checksum trailer, loaded by
DATE step 3 to `0x80197000` for every girl's date (§6k). 48 strings, each
with exactly one pointer; 2,324 bytes of string space in 12 gaps. The rest
is section lists, code bytes and zeroed work areas (`0x300`–`0x44F`,
`0x79C`–`0x9B7`, `0xB14`–`0xBDB`, `0xEB8`–`0xFFB`: 24-byte records filled at
run time; the pointer runs at `0x420`, `0x94C`, `0xBBC`, `0xFC0` point into
them, not at text). Other `SERIFU` files load at the same address, so words
in other overlays that point into `0x80197xxx` belong to those files.

**Section table.** `DATE.EXN` holds three parallel 4-entry tables at
`0x8015BD90` (masters), `0x8015BDA0` (code-byte lists) and `0x8015BDB0`
(third pointers, into the work areas), the same layout as DATE_FU's (§6k):

| Sec | Strings (file) | Count | Codes | Content | Setup / selector |
|---:|---|---:|---|---|---|
| 0 | `0x0`–`0x260` | 12 | `06` | concert blurbs ("X is a ... band"), one per concert, in the order of the EXE concert-name table (`town_news.json`: KNM Symphony, Chisa Morita, Chage & Aska, WIZARD, Riko Kodama, XeXeX, KNM Symphony, Bees, SNACK, KNM Symphony, prf, Rinsu) | `0x8013BAD4`: line = byte `0x8015B688`, set by the Concert Hall setup `0x80136340` (by date); confirmed by forcing 0 and 11 |
| 1 | `0x454`–`0x6EC` | 18 | `00 06 08 03 07` | the player alone at the meeting place: she's late, "did I get the place wrong?", the choice of where to go, or she never comes | `0x8013EFA0` (below); part in s16 `0x8015BF3C` |
| 2 | `0x9B8`–`0xAA8` | 7 | `04` | impression thoughts after a choice, levels 0–4 (great → bad), then two "but my lie was exposed: I can't really swim / skate" lines | `0x8013B174`: line = s16 at `0x800CA22C + 2·choice` (the impression level copied from `TAKU3.BIN`, §6k); forcing all three to N there once shows level N (seen 0 and 1). The swim lie line followed the Pool boast option on screen; `0x8013B208` is a second caller, presumably the lie lines (not traced) |
| 3 | `0xBDC`–`0xE40` | 11 | `06` | movie blurbs, one per film, in the order of the EXE movie-name table (`town_news.json`: I'm Doing It, Forrest Gump, Summer Saw, Fungaa, Kanpanman, Sleep Fist II, Love Melody, Speed King, BANPO, The Mask, Love and Youth) | `0x8013B964`: line = byte `0x8015B684`, set by the Cinema setup `0x80135E7C` (by date); confirmed by forcing 3 and 6 |

Codes `04` and `06` are drawn as the player's thought with **both brackets
drawn by the game** (seen on screen in the English dates: `（…。）` around
strings that contain neither), so English gets no parentheses. An odd
letter count on the last line shows its pair padding as a space before the
game's `）` ("a bad impression. )", seen), so thoughts end on an even run. Each blurb
and impression section is a single part whose line is chosen by the value
above; all four go through the talk runner `0x80082764`, which copies the
string before cutting it (`share_identical` is safe, as in §6k).

**Section 1, the missed meeting** (`0x8013EFA0`, a step of every date).
Parts and codes:

| Part | Strings | Content |
|---:|---|---|
| 0 | `0x454` `00`, `0x474` `06`, `0x4A4` `08` | "{G} isn't here yet" / "late… did I get the place wrong?" / action choice: "it was here" or `{A}` |
| 1 | `0x4D4` `00` | "no, it was here; I'll wait" |
| 2 | `0x508` `00` | "let's go to `{A}`" |
| 3 | `0x520` `00`, `0x540` `06`, `0x570` `03` | as part 0 with three options: here, `{A}`, `{M}` |
| 4–6 | `0x5B0`, `0x5E4`, `0x5FC` `00` | wait here / go to `{A}` / go to `{M}` |
| 7 | `0x614` `06`, `0x630` `00` | "{G} never came" / "oh well, home" |
| 8 | `0x650` `00`, `0x670` `06`, `0x694` `07`, `0x6D0` `06`, `0x6EC` `00` | stood up: waiting, the centered "・・・" pause, she never came, home |

The function copies a 21 × 33-byte place-name table from `DATE.EXN`
`0x8015B9DC` (file offset `0x299DC`; index = place id 0–20 as in §6k:
近所の公園 … スキー場) to the stack (the `0x2D6`-byte loop at `0x8013EFB8`),
then:
- If the girl's rank (`0x80051A68(girl) & 0x7F`, read at `0x8013F008`) is
  4, part 8 plays (stood up) and the step skips ahead (`0x738A` += `0x24`).
- Otherwise it reads the meeting bytes: `0x800E69A4` = **where the player
  went**, `0x800E69A5` = **the agreed place**, `0x800E69A6`/`69A7` = the
  other places the player half-remembers (`0xFF` = none; the main loop asks
  "where were we meeting?" on the date day, `main_screen.json`). If the
  player is at the agreed place (and the arrival byte `0x8015B654` is 1),
  or `69A6` is `0xFF`, the normal meeting runs (`0x738A` += `0x11`).
- On a mismatch, `{A}` (`0x800CA25C`) gets `69A6`'s name and, when `69A7`
  isn't `0xFF`, `{M}` (`0x800CA280`) gets `69A7`'s and part 3 (three
  options) replaces part 0. A candidate equal to where the player stands is
  replaced by the agreed place, so the right answer is always offered.
  Names are `strcpy`'d from the table (stride 33, `0x8013F0C0`).

Forced on screen (2026-10-08, testing.md "SERIFU.BIN"; this corrects the
first, static reading, which had `69A4`/`69A5` swapped): staying ("it was
here") or a wrong place leads to part 1/4 or 2/5/6, then part 7 ("she never
came"). Back home **an answering-machine message** from the girl follows
("ひどい事するのね…"); it is in `EXEDIR/TEL.EXN` (§6m), not here. Being stood up (part 8) ends the same way.
Choosing the agreed place goes there and continues as the player-late
meeting (§6k arrival 2), and **the date then takes place at the agreed
place**, not the appointment's original one (a forced museum date became a
Kirameki Park walk).

**The place-name table is the only source of `{A}`/`{M}` here.** It's read
only by this function (the one reference to `0x8015B9DC`). Every slot is the
Japanese name followed by NULs up to 33 bytes, so the in-place budget
(original + NUL + padding to 4 bytes, AGENTS rule 5) is often below the
English: 海 allows 2 letters, 神社 4, 遊園地/図書館/動物園/プール 6. Fitting
"Beach" or "Theme Park" needs the whole 33-byte record (the bytes after each
name are NUL up to the next record, and `strcpy` stops at the first NUL):
`date_shared.json` writes them with `"slot": 33` (translation-guide). The same function family at `0x80149D04` copies a second
93 × 33-byte table at `0x8015D108`: birthday-present item names, a separate
job.

`{A}` and `{M}` are inserted by the renderer from those buffers; a
pair-encoded name keeps its pairs (§6e), and an odd-length name ends in its
padding space.

### 6m. Phone calls (`EXEDIR/TEL.EXN`)

Found 2026-10-08 by dumping the overlay, listing its code's string
references (`tools/code_strings.py`), and calling Shiori, Yoshio and Ijuin
in DuckStation. Translated in `translation/phone_calls.json`.

**File.** Overlay, 196,608 bytes at LBA 39434, base `0x80132000`, checksum
trailer. Opened from the main loop's phone icon (holiday screen; Down
×8 from the first icon). Its text sits in two areas that work differently:

- **Data area `0xE5F0`–`0x14F0C`** (470 strings): the call scripts. Strings
  are followed by lists of pointers to them, one list per exchange; a
  12-entry list is indexed by girl (Shiori, Mio, Yuina, Ayako, Saki, Yukari,
  Nozomi, Mira, Yuko, Megumi, Yumi, then Ijuin), an 11-entry list by girl
  without Ijuin, and 13-entry lists probably by mood or day. Between the
  lists are tables of 4-byte records (`xx 0x 00 yy`, e.g. `5a 00 00 02`),
  and some strings start right after such a record, without a NUL.
  `dump_dialogue.py` treats a byte below `0x40` (other than the `0x20` line
  break), or an aligned word ending `00 00 xx`, as a string start for this
  reason. Every one of these strings has a pointer and none is addressed by
  code, so the block is repacked like a SERIFU file; 8 strings have two
  pointers (shared answers).
- **Code area `0xC430`–`0xE4F4`** (219 strings): addressed directly by the
  code (`lui` + `addiu`), so they stay in their own slots (the patcher keeps
  code-referenced strings in place). They're printed one line at a time
  (`0x80051010(text, line, speaker)`; speaker `13` = the callee, `15` the
  player, `31` a thought, `47` a sound, `10` Yumi), a whole box at a time
  (`0x80050E8C`), or are **fragments the code concatenates** with
  `strcpy`/`strcat` (`0x800AE0F0`/`0x800AE100`) into a stack buffer:
  - the player's greeting to Yoshio: "もしもし、" + player name + "ですけど。";
    Yoshio's reply "おっ、" + name + "か。";
  - the invitation (`0x80136A80`–): month digits (EXE table `0x800B3288`,
    full-width) + 月 + day digits + 日 + "に、 " + place name (EXE table
    `0x800B342C`, already English via `outings.json`) + "へ 行かない？";
    the confirmation adds "の前で 待ち合わせということで。" and the
    player's "やったー。 " + date + "が、楽しみだぜ。 ";
  - Yoshio's girl info: name + "、" + name + "‥‥と。"; the request
    name + "の" + "ことについて"; the missed-date thoughts
    "しまった！！今日は、 " + name + "と デートの約束があったんだ。）" and
    "そうかっ！ " + name + "は、 怒って来なかったのか。）".

  In English the fragments are written as pieces of one sentence ("4／30, would
  ⏎Theme Park⏎work for you?"). 月 became "／" and 日 ", ".
- `0x80050DFC(text)` sets a custom speaker label: 留さん (Tome, the
  fireworks man), 部長 (the club captain), and Yoshio's label for his own
  lines. 自宅 ("Home") is a location banner.
- The Yoshio menu ("ask about the girls / date spots") is drawn by
  `0x80050D78`; the girl-info card labels (`0xE478`–`0xE4BC`) by
  `0x8004E788` at fixed x positions. The card's label column is narrow:
  "BWH." and "Notes" overlapped the colon the game draws, so they became
  "B W H" and "Memo". The card's values (sign, blood type, club, notes) come
  from `FUKUTEST/JOHO.NBN` and are still Japanese.
- `0xCED4` ("くそ、次こそ絶対 誘ってみせるぜ。）") has no reference
  anywhere: unused, translated anyway.

**The phone book** lists full names from the EXE table at `0x72C80`
(§6e). That table's first entry, 藤崎詩織 at `0x72C80`, wasn't in
`character_names.json` (the pointer table at `0x72D38` starts one entry
earlier than documented before); it's now "S. Fujisaki", and the full-name
pool is 184 of 184 bytes. Only a fresh boot shows EXE changes: a save state
keeps the EXE it was made with in RAM.

**Calls seen** (2026-10-08): Shiori answers, the player introduces himself
("Um...⏎This is {P}."), her greeting by mood, then the date picker ("Choose
a day / place for the date.", the date-spot book), the assembled
invitation, her answer, the confirmation and goodbye, "Click.", then the
player's thoughts. A missed date (§6l) is followed at home by the
answering-machine message (data area, one list per girl × 3 moods) and
the player's realization.

### 6n. Walking home from school (`SERIFU/GEKO.BIN`)

Found 2026-10-08 by tracing `GEKO.EXN` and the EXE's day handler, then
forced in DuckStation (`tools/emu/force_walk.py`, testing.md "Walking
home"). Translated in `translation/walk_home.json`.

**Trigger.** Day record type `0x44` (`44 GIRL 00 00`, the girl in byte 1)
in the event queue (§6j): the handler `0x80072030` enters state `0x59`
(GEKO.EXN) if the girl has been met (bit 1 of `0x800E6448 + 0x38·girl`),
unless the previous record was type `0x28`/`0x47` or `0x800E6375 & 0xF ==
3`. GEKO.EXN serves several states: `0x5A` (record type `0x46`) is a girl
asking the player out for Sunday, from `SERIFU/G_INVITE.BIN` (§6o); `0x5D` (type `0x45`) the special events (§6j). The weekly picker
`0x80070850` writes the type-`0x46` records; who writes type `0x44` wasn't
traced. The walk's entry is `0x80132244`: substate `0x800E7389` 0 runs the
step list `0x80144C5C` (the walk), 1 the list `0x80144D40` (the talk on the
way).

**File.** 73,728 bytes at LBA 44744 (36 sectors), base `0x80197000`,
checksum trailer. 1,011 strings (492 distinct texts: the same lines recur
across girls), all reached from 12 sections. Three parallel 12-entry tables
in GEKO.EXN at `0x80144BA0` (masters), `0x80144BD0` (code-byte lists),
`0x80144C00` (third pointers), the EVENT_FU layout (§6j). The section isn't
the girl id: the switch at `0x801327AC` (jump table `0x80144724`) maps
girls 0–10 to sections **1, 5, 2, 3, 9, 6, 7, 4, 0, 8, 11** (Shiori, Mio,
Yuina, Ayako, Saki, Yukari, Nozomi, Mira, Yuko, Megumi, Yumi), and section
10 is the player's own thoughts (set up for every walk at `0x801326D4`).
`tools/geko_sections.py --strings [--girl S]` lists them.

**Parts** (each girl's section, ~40 parts; s16 part index at `0x80144C3C`,
read through `0x800CA134` like DATE's):

| Parts | Content |
|---|---|
| 0 | (section 10) "Phew, what a long day" thought |
| 1–5 | she waited for the player: invitation + action choice (`08`), accepted (2, 3 "{G} and I had a nice walk home"), turned down (4, 5 / section 10 regret thoughts) |
| 6–11 | the player spots her and calls out; `0C`+`0D` "Oh, {P}." + "Heading home?" share one box; his choice; she agrees (8) |
| 12–17 | same, but she has other plans (14) |
| 18–21 | she runs off ("‥‥‥‥‥。"), the player wonders if he hurt her |
| 22 | "And then..." (code `07`) |
| 23–38 | the talk on the way, one per topic: exams, culture festival (24–27 by club), sports day, school trip (29–30), New Year, her birthday, summer/winter/spring break, moving up to 2nd/3rd year, graduation |
| 39 | "We talked about things like that on our walk home" |
| 40–42 | Saki only: Koshien / National Stadium / future (club manager lines), Mira only: she parts at a corner (40–41) |

The opening is chosen by the girl's rank (`0x80051A68`, §6j) at
`0x801331A0`: base part 0 for rank 0/1, +6 for rank 2, +12 for rank 3,
+18 for rank 4 (or flag byte `0x80144C58`). The talk on the way only runs
when a topic is pending: byte `0x80144C50` (0 = none) is proposed from the
calendar by `0x80132A4C(topic)`; the talk's part is 22 + the topic id
(`0x80133F94`). Forced: ranks 0, 2, 3, 4 and topics 1 (exams) and 12
(winter break) by `force_walk.py --rank R --topic P`.

Code bytes as in EVENT_FU: `00` player, `01` girl, `03`/`08` choices, `06`
thought (the game draws both brackets), `07` narration, `0C`/`0D` two girl
strings in one box, `09` and some empty strings (`0x11CC8`–`0x11EB8`) are
placeholders. `{M}` in the culture-festival lines is the player's club.
Oddities: Mira's part-7 choice (`0x68F0`) separates its two options with a
line break instead of `{q}`; on screen it shows as two normal options like
the others (the choice box splits on line breaks too), so the English keeps
the line break. Shiori's lines use 詩織 instead of `{G}` in three places.

### 6o. A girl asks the player out (`SERIFU/G_INVITE.BIN`)

Found 2026-10-08 the same way as §6n. Translated in
`translation/invitations.json`.

**Trigger.** Day record type `0x46` (`46 GIRL ...`): the handler
`0x80072164` enters state `0x5A` (GEKO.EXN) unless appointment slot 0
(`0x800E67CC`) is already active. The weekly picker `0x80070850` writes
these records (once a week at most). `force_event.py GIRL 0 --type 0x46`
forces one; no met check was seen.

**File.** 32,768 bytes at LBA 44835 (16 sectors), base `0x80197000`,
checksum trailer, 351 strings in 13 sections from GEKO.EXN's three
parallel 13-entry tables at `0x80147630` (masters), `0x80147664` (code
bytes), `0x80147698` (third pointers). The switch at `0x80143804` (jump
table `0x80144B68`) maps girls 0–10 to sections **1, 5, 2, 3, 10, 6, 8, 4,
0, 9, 12** (note Saki 10, Nozomi 8, Megumi 9, unlike GEKO.BIN); section 11
is the player's thoughts after turning her down (loaded at `0x80143FB0`),
and section 7 isn't selected by any girl id (its strings are mostly shared;
translated anyway). `tools/geko_sections.py --invite` lists them.

**Parts** (each girl): 0 her greeting, "are you free this Sunday?" and the
player's choice (free / busy); 1–19 her invitation for place 2–20 (the
outing ids of §6j: shopping, aquarium, zoo, botanical garden, planetarium,
art museum, library, arcade, bowling, karaoke, theme park, baseball,
wrestling, cinema, concert, pool, beach, skating, skiing); 20 the
player's yes/no; 21 her reply and "Meet at {M}?"; 22 the player's "this
Sunday" thought; 23 her reaction when refused. Some girls have no line for
some places (they don't invite there). Yukari's parts 16 and 17 are the
beach and the pool, swapped against everyone else's (original data, left
as is).

**`{M}` here is the meeting place**, from a 19 × 33-byte table in GEKO.EXN
at `0x80147988` (file `0x15988`: ショッピング街, 水族館の前 … スキー場の前,
place 2–20), copied whole (`0x273` = 19 × 33 bytes) at `0x80142E0C`.
Translated with `"slot": 33` ("the zoo gate", "the arcade", ...).

### 6p. First meetings (`SERIFU/G_APPEAR.BIN`)

Found 2026-10-08 by static tracing of `SHOUGATU.EXN` and the EXE, then
forced in DuckStation (`tools/emu/meet_run.ps1`, testing.md "First
meetings"). Translated in `translation/meetings.json`.

**Trigger.** Day record type `0x48` (`48 GIRL SCENE 00`): the EXE's handler
`0x80072210` enters state `0x5B`, served by **SHOUGATU.EXN**. Its loaders
`0x80137A04`/`0x80137A5C` read `G_APPEAR.BIN` (LBA 44797, 16 sectors,
32,768 bytes, checksum trailer) to `0x80197000` and store the record's girl
in `*(u8*)0x80144E10`; the scene byte (`*(u32*)0x80122CD0`) is copied to
`*(u8*)0x80144E14` (`0x801376F8`) and picks the girl's **variant**.
`force_event.py GIRL SCENE --type 0x48` forces one. The switch at
`0x80137204` (jump table `0x80143730`) maps girl ids 1–8 and 10 to a
handler (`0x801398F0` Mio, `0x80137FF0` Yuina, `0x80138B40` Ayako,
`0x8013A950` Saki, `0x8013A190` Yukari, `0x8013A500` Nozomi, `0x801391D4`
Mira, `0x80137BB0` Yuko, `0x8013AF10` Yumi); Shiori (0) and Megumi (9) go to
a stub (`0x80046500`), and a forced Shiori meeting returns to the title
(§6j). Yuko's handler: variants 0–2 run one step list with part =
variant × 3 (the three collisions, `0x80137F70`), variant ≥ 3 another (Yoshio
introduces her). Other girls' variant logic wasn't traced; in the forced
runs Ayako's variant 0 played parts 6–7 and Yuina's variant 2 the lab with
the Computer Club branch (presumably by the player's club).

**Sections.** A fill function (`0x80136F90`, the same values as the static
table) writes three parallel 9-entry tables at `0x80144D90` (masters),
`0x80144DB4` (code-byte lists), `0x80144DD8` (third pointers), the EVENT_FU
layout (§6j). Section = 0 Yuko, 1 Yuina, 2 Ayako, 3 Mira, 4 Mio, 5 Yukari,
6 Nozomi, 7 Saki, 8 Yumi (each confirmed by a forced meeting). The nine
sections reach 416 strings, each once; `dump_dialogue.py` used to find 408
(below). `tools/geko_sections.py --appear [--strings]` lists them. No
choices in this file. Codes: `00` player, `01` girl, `06` thought (both
brackets drawn by the game), `07` narration or sound, `09` the collision
sound (ドン), `0A` Yoshio (his own label), `0C`/`0D` two girl strings in one
box. `{F}` is the player's full name (まま for the test save), `{p}` the
short name and `{P}` the name with a suffix; in Yumi's scene `{P}` uses
SHOUGATU's format `%sさん` (`0x11890`, `sprintf` at `0x8013B0C0`), elsewhere
君. `{m}` (Yoshio to the player) showed ま.

**Speaker labels inside a code-07 string.** The EXE's speak function
(`0x8007EF48`, code-07 case `0x8007F030`) checks the string's first byte:
`>` copies the next 4 bytes as a label (`sprintf "%s "`, drawn by
`0x8004E788` at x −0x78), draws 「 at −0x56 and the text from byte 5 at
−0x48; `<` the same with （ and ）(`0x800B2034`); `-` takes 6 bytes (label
at −0x80, text from byte 7); `+` takes 2 bytes (label at −0x70). G_APPEAR
uses `>部長` (the drama-club captain, Mio's section) and `-？？？` (Yumi
before she gives her name). `dump_dialogue.py` rejected these 8 strings
until `script.py` learned the prefix (2026-10-08): it's written `{>部長}` /
`{-？？？}` at the start of the string, and the English label is padded to
the same byte count (`{>Capt}`, `{-???}`, one byte per letter); the label
takes no room on the text's line. Other files may have the same prefixes
(EVENT_OT.BIN has `-女生徒`); re-dump before translating them.

**Fixed sound strings.** After the prefixes, the code-07 case compares the
whole text with fixed strings: そして… and ピンポーン are drawn lower and
indented (x −0x28); ガチャ, カチャ, ガラッ, ごそごそ get colour argument 2,
ジロジロ and ドン colour 1; anything else the caller's colour at the same
x. The code-09 case (`0x8007F6A8`) does the same for ドン. So a translated
sound keeps its place but may change colour (on screen "Bonk!" showed in
the default pink; the original ボカ isn't special either). Earlier files
already translate these sounds ("Click.", "And then...").

**Words in SHOUGATU.EXN.** The meeting code `strcpy`s a speaker label and
a **location banner** (shown top left as the scene opens; the box sizes to
the text) from in-place strings at file `0x11760`–`0x118A0`: 女生徒 (Yuko's
label before her introduction, to `0x800CA188`) and 廊下, 教室, 実験室, 中庭,
美術室, 音楽室, 図書室, 演劇部, グランド, 近所の公園, プール, 学校前 (to
`0x800CA19C`), one copy per use. Translated in place in `meetings.json`
(4- and 6-byte originals allow 6 letters, グランド and 近所の公園 10).
`tools/code_strings.py SHOUGATU.EXN --range 0x11600 0x11a00` lists them
with their callers.

### 6q. A girl welcomes the player to her club (`SERIFU/NYUBU.BIN`)

Found 2026-10-08 by static tracing of `KANGEI.EXN` and the EXE, then forced
in DuckStation (`tools/emu/force_club_welcome.py`, testing.md "Club
welcome"). Translated in `translation/club_welcome.json`.

**KANGEI.EXN serves three main states** with different entry points (the
EXE's overlay-entry switch, jump table `0x800B1BEC` indexed by state −
0x11): `0x60` → `0x80132000` (this scene), `0x5F` → `0x80132FF8` (the
training camp: GASSHUKU.BIN / GASSH_FU.BIN and the NOZOKI peeking event),
`0x72` → `0x80141280`. The day handler enters `0x5F` for record type
`0x42` (a forced one on 4/25 started the camp: "合宿所に着いたぞ") and
`0x72` for type `0x20` (a forced one started the sports day, 体育祭).
KANGEI also has loaders for G_BIRTH.BIN and P_BIRTH.BIN (`0x80138CE4`,
`0x80138D1C`), not traced to a state. (The older "loader switch at
`0x800B19E8`", §3, is the overlay-load table; the entry table is separate.)

**Trigger.** State `0x60` is set in `0x80077908` (reached through a
function table at `0x80076FAC`, not by `jal`): on a weekly club day with
the player in a club (`*(u16*)0x800E6374 >> 12` ≠ 11), `0x80053564(club)`
returns the girl in that club, stored as the scene's girl `0x800E69DD`, and
her byte `0x800E6280 + 0x38·girl + 0x1CA` gets bit 2 (seen once). Other
conditions there (a byte `0x800E62C1` = 6, a day-record girl of 4, the
day count `0x800E62C2` < `0x2DA`) weren't decoded.

**File and sections.** 6,144 bytes at LBA 44860 (3 sectors), base
`0x80197000`, checksum trailer, 93 strings, no choices. The step list at
`0x801399B0` (21 steps) loads it at step 3 (`0x801324D8`), and `0x80132090`
fills three parallel 8-entry tables at `0x80139950` (masters, code lists,
third pointers; the EVENT_FU layout, §6j). `0x8013260C` picks the entry by
girl (jump table `0x80139668`): girls 0–6 (Shiori, Mio, Yuina, Ayako, Saki,
Yukari, Nozomi) → sections 0, 3, 1, 2, 6, 4, 5; any other girl → section 7,
a basketball-team line ("バスケ部に入部してくれたんですね"). Which girl, if
any, reaches section 7 in normal play wasn't found; forced with girl 10 the
label showed Yumi. `tools/geko_sections.py --nyubu` lists the sections.
The part (`*(s16*)0x800CA148`) is chosen at `0x80132A00`–`0x80132C0C` from
the player's club and the girl's flags (`0x800E6448 + 0x38·girl` bit 2:
whether he already knew she was in the club, giving "so you joined" vs.
"so you're in this club").

**Backgrounds by club.** Step 9 (`0x80132C24`) picks the background's LBA
for the girl; Shiori's and three other cases index a table by the
player's club. With no club (11) Shiori's lookup reads past her 11-entry
table, step 10 waits forever for a CD read, and the box stays empty
(unpatched too). Natural play can't reach that (the scene needs a club),
so the forcer has `--club`.

**Codes.** `00` player, `01` girl, `0C`/`0D` "Oh, {P}" and her greeting in
one box. `{P}` is the name plus the girl's suffix (君 or さん).

### 6r. The player's birthday (`SERIFU/P_BIRTH.BIN`)

Found 2026-10-08 by static tracing and a natural trigger in DuckStation
(`tools/emu/force_birthday.py`, testing.md "The player's birthday").
Translated in `translation/birthday.json`.

**Trigger.** The player's birthday is bits 0–3 (month) and 4–8 (day) of
the u32 at `0x800E6378` (1/1 on the test save; Shiori's is the same format
at `0x800E644C`, §6j). Writing 4/25 on the Sunday 95/4/23 state makes the
scene play by itself on Monday, in **GEKO.EXN** (main state `0x56`). It is
not only KANGEI's: GEKO, KANGEI, DATE and SHOUGATU each contain a P_BIRTH
loader (GEKO `0x8013448C`, KANGEI `0x80138D08`) and their own copy of the
section tables (filled by GEKO `0x80134F84`, KANGEI `0x80137B90`), so the
scene runs in whichever overlay serves that day. All copies point into the
same file; the translation only moves strings inside it.

**File.** 6,144 bytes at LBA 44867 (3 sectors), loaded to **`0x801B0000`**
(G_BIRTH.BIN loads to the same address), checksum trailer, 79 strings.
13 sections: 13 masters, 13 code lists and 12 third pointers. Girl →
section through each overlay's switch (KANGEI's jump table `0x80139928`):
0 Shiori → 1, 1 Mio → 6, 2 Yuina → 3, 3 Ayako → 4, 4 Saki → 10, 5 Yukari
→ 7, 6 Nozomi → 8, 7 Mira → 5, 8 Yuko → 0, 9 Megumi → 9, any other girl
→ 12 (Yumi's lines); section 11 is "nobody gave me a present". Section 2,
a classmate calling "おーい、{p}、女の子が来てるぜ" (code `07`), is read
only by KANGEI's flow (`0x801389AC`), probably a birthday during the
training camp; not seen.

**Who brings a present.** The selector (GEKO `0x80134840`–`0x80134950`,
KANGEI `0x80138F88`) loops over met girls (bit 1 of `0x800E6448 +
0x38·girl`) and keeps the one with the best rank (`0x80051A68(g) & 0x7F`,
ties by the scores `0x80052C88`/`0x80052648`); she comes only if that rank
is below 2 (GEKO also needs bit 3 of `0x800E699E` clear), else section 11.
The forcer sets the girl and rank at the check (GEKO `0x80134930`: `fp`,
`t7`; KANGEI `0x8013907C`: `s7`, `t5`). Both addresses are other code in
the main-screen overlay, so it polls RAM for the overlay's code bytes
before arming the breakpoint. Note: `0x800B6D40` is the LBA of the **last
CD read**, not of the loaded overlay; right after an overlay loads a data
file it no longer identifies the overlay.

### 6s. The girls' birthdays (`SERIFU/G_BIRTH.BIN`) and the gift names

Found 2026-10-08 by static tracing and DuckStation runs
(`force_birthday.py --her/--as`, testing.md "The girls' birthdays").
Translated in `translation/girl_birthdays.json`.

**Trigger.** A girl's birthday (u32 at `0x800E644C + 0x38·girl`, bits 0–3
month, 4–8 day; Shiori 2/3 on the test save, `0xE2`) set to an upcoming
school day makes her birthday scene play that day in GEKO.EXN, for a girl
the save has met. Setting only the met bit (bit 1 of `0x800E6448 +
0x38·girl`) for an unmet girl didn't: the game queued her first-meeting
scene (G_APPEAR, §6p) instead, and no birthday. The birthday check isn't in
GEKO (no read of `0x644C` there); the EXE, DATE, KANGEI, SHOUGATU and
SHUGAKU read the field (`0x80052DA4(who, month, day)` is the EXE's
"is it this person's birthday" test, who 0xF = the player). Not traced.

**File.** 45,056 bytes at LBA 44813 (22 sectors), base `0x801B0000` (same
as P_BIRTH, §6r), checksum trailer. 13 sections from GEKO's fill
`0x80134D10` (tables `0x80144F10`: 13 masters, 13 code lists, 12 third
pointers); they reach 584 pointers, 582 strings the dumper finds plus two
empty `09` placeholders (`0xAC60`, `0xAC64`, parts 27 and 30 of section 11).
GEKO's switch `0x801361D4` (jump table `0x801448A0`): girl 0 Shiori → 1,
1 Mio → 5, 2 Yuina → 2, 3 Ayako → 3, 4 Saki → 10, 5 Yukari → 6, 6 Nozomi →
8, 7 Mira → 4, 8 Yuko → 0, 9 Megumi → 9, 10 Yumi → 12; section 11 is the
gift choice lists and section 7 a copy of Nozomi's (no girl id maps to it).
Each girl's parts: 0 "today is {G}'s birthday", the give/skip action choice
(`08`); 1 skip; 2–3 "what should I get her?" and "I'll go with {A}"; 4–12
the meeting by rank (four greetings); 13/15/17 her reaction (loved / fine /
disliked) with 14/16/18 the player's thought; Shiori, Yuina and Nozomi
also have 19–35: calling her out on a holiday (no number known, three
answers by rank, "Click.", meeting at home or the park, the hand-over), the
phone greeting by rank, and "she's not home". The gift choice is one part
of section 11 (three options, shown shuffled; which part each girl gets
wasn't traced: Shiori's run listed CD/handkerchief/earrings, part 0, and
Yuina's perfume/CPU book/whip, part 6).

**`{A}` is the chosen gift's name**, from a 99-record × 33-byte table
(`クラシックのＣＤ`, `ハンカチ` …; records 90–92 empty) that six overlays
carry identically: DATE `0x2B108`, DATE2 `0x8878`, GEKO `0x131FC`, KANGEI
`0x8570`, SHOUGATU `0x120C0`, SHUGAKU `0x91AC` (file offsets). All six are
translated with `"slot": 33`, using the same English as the gift options.
BUNKAKEN, BUNKASAI and GYOZI have **different** tables at the same layout
(only the first 9 or 42 records match; e.g. GYOZI's 料理の鉄人ビデオ全４巻
without お); they belong to other events and are left for those files.

**Location banners** in GEKO (`0x12710`–`0x12864`, strcpy'd like
SHOUGATU's, §6p): 校門前, 近所の公園, 玄関, 廊下, 自宅前, the club rooms,
グランド, プール, 体育館, and two プルルルルル (phone ringing) strings
drawn by `0x8004E788`. Translated in place in `girl_birthdays.json`; they
also show in walk-home and other GEKO scenes.

### 6t. The Christmas party (`SERIFU/XMAS.BIN`)

Found 2026-10-08/09 by static disassembly of SHOUGATU.EXN and forced
parties in DuckStation (`force_christmas.py --party`, testing.md "The
Christmas party"). Translated in `translation/christmas.json`.

**File.** 28,672 bytes at LBA 44988 (14 sectors), base `0x80197000`,
checksum trailer. SHOUGATU loads it at `0x8013D7BC` (`0x80046318(0xE,
0x80197000, 44988)`) and fills the section tables at `0x8013C070`: 13
masters at `0x80145AD0`, 13 code lists at `0x80145B04`, 13 third pointers
at `0x80145B38` (the dumper's six rejected "no Japanese text" targets are
those third records). Sections (EVENT_FU layout, §6j): 0 Yuko, 1 Shiori,
2 Yuina, 3 Ayako, 4 Mira, 5 Mio, 6 Yukari, 7 Nozomi, 8 Megumi, 9 Saki, 10
the present exchange, 11 the arrival, Ijuin's speeches and the lonely
evening at home, 12 Yumi (`tools/geko_sections.py --xmas`). They reach 359
pointers: the 358 dumped strings plus an empty string at `0x6C44`
(section 10 part 32, Yumi's 1995 present: she isn't at school yet).

**Flow.** Main state `0x52`; SHOUGATU's stage dispatcher `0x8013D180`
(jump table `0x801438E0`, stage `0x800E7389`, step `0x800E738A`):
- **Stage 0, arrival** (`0x8013D660`; section 11 parts 0–8). The count of
  earlier parties is bits 9–11 of `0x800E66E8`. The butler (label 黒服,
  the first year; 外井 Sotoi later, strcpy'd from SHOUGATU `0x1194C` /
  `0x11954` into the label buffer `0x800CA188`, girl id 12) lets the player
  in politely when `0x800E6396` (probably Looks, §6k) ≥ 70 + 30·count
  (−10 from the third party). Otherwise, when the stat `0x800E638E` ≥
  150 + 25·count, Sotoi is "dazzled by the physique" (parts 4–5, the first
  time) or "you've come again" (part 7, when bits 9–11 of `0x800E6758`,
  the times he did this, are nonzero; `0x8013D92C` counts them up).
  Otherwise the player is turned away (part 3) and spends the evening
  alone (parts 19–21).
- **Stage 1, Ijuin's speech** (`0x8013DDD0`): part 9 + 3·count of
  section 11 (welcome, "did you say something?", the cocktail glass). The
  label 伊集院 comes from SHOUGATU `0x11960`/`0x11968`; the banners
  伊集院邸 (`0x11940`) and パーティー会場 (`0x11970`) go to `0x800CA19C` /
  `0x800CA1DC`.
- **Stage 2, mingling** (`0x8013E330`): Shiori first (section 1; part 0,
  or 4 when the mood call `0x80051A68` returns 4), then two random girls
  1–10 (`(*(u32*)0x800E7378 + i) % 10 + 1`, written to `0x800E71DF` and
  kept at `0x80146054` / `0x80146058`; unmet girls only while fewer than
  two/three are met; Mio needs `0x800E644A >> 4 != 8`, Yukari `!= 9`).
  The girl switch `0x8013EE30` (table `0x80143990`) maps girls 1 Mio → 5,
  2 Yuina → 2, 3 Ayako → 3, 4 Saki → 9, 5 Yukari → 6, 6 Nozomi → 7, 7 Mira
  → 4, 8 Yuko → 0, 9 Megumi → 8, 10 Yumi → 12. Part 0 is the chat ("talked
  to {G}"), part 1 her brush-off (mood 4; Nozomi: mood ≥ 2 → part 1, 4 →
  part 2), then "we haven't even talked"; an unmet girl plays her first
  meeting instead (later parts) and is marked met (bit 1 of `0x800E6448 +
  0x38·girl`). When `0x80146050` is set (Megumi unmet, her `+0x1BE` field ≥
  20, and a coin flip) Shiori says she'll introduce a friend (section 1
  parts 2–3) and the first girl is Megumi.
- **Stage 3, present exchange** (`0x8013F224`; section 10): four boxes
  hold Shiori, Ijuin (11) and the two girls; the opened box gives part
  3·girl + (year − 1995) + 2 (`0x80145F2C`, stored at `0x8013FEBC`). Parts
  with two strings are alternatives (Shiori's score: "I can't read it"
  when `0x800E638A` < 100). Then the closing thought (part 38, or 39 after
  Ijuin's present) and the girl selector `0x80140030` for stages 6–8.
- **Stage 4, turned away** (`0x801407C0`; also loads file `0xD` to
  `0x801B0000`, LBA 48315): the evening at home, section 11 parts 19–21.
  Before it, at `0x80140AD8`, Megumi visits with a present (section 8
  parts 5–7, she's marked met) under the same conditions as Shiori's
  introduction: Megumi unmet, `0x800E6636` ≥ 20, `*(u32*)0x800E7378`
  odd.
- **Stages 6–8**: a girl's walk home after the party (EVENT_FU etc., §6j).

In the forced runs the player's "we haven't even talked" part after a
brush-off (e.g. section 0 part 2) didn't play; it's reached some other
way, not traced.

### 6u. White Day (`SERIFU/WHITE.BIN`)

Found 2026-10-09 by static disassembly of SHOUGATU.EXN and forced White
Days in DuckStation (`force_white.py`, testing.md "White Day and
Valentine's Day"). Translated in `translation/white_day.json`.

**Trigger.** Day-record type `0x30` (EXE record switch: jump table
`0x800B1340` indexed by the type, case `0x80071FC8`) enters main state
`0x55`, which loads SHOUGATU.EXN. Writing `30 00 00 00` over an ordinary
record (`force_event.py --type 0x30`, or `force_white.py`) gives White Day
the next school day, from any date.

**File.** 18,432 bytes at LBA 44979 (9 sectors), base `0x80197000`,
checksum trailer. SHOUGATU loads it at `0x8013B71C` (`0x80046318(9,
0x80197000, 44979)`) and fills the tables at `0x8013B210`: 13 masters at
`0x80145960`, 13 code lists at `0x80145994`, 13 third pointers at
`0x801459C8`; the current section's three pointers go to `0x801459FC`–
`0x80145A04`, the part to `0x80145A08`. 251 strings, all reached (the
dumper's 3 rejected targets are third records). Sections
(`tools/geko_sections.py --white`): 0 Yuko, 1 Shiori, 2 Yuina, 3 Ijuin,
4 Ayako, 5 Mira, 6 Mio, 7 Yukari, 8 Nozomi, 9 Megumi, 10 Saki, 11 the
player's thoughts, 12 Yumi.

**Flow.** The hallway banner is SHOUGATU's 廊下 (`0x118A0`, already
"Hall", §6p). Ijuin (section 3, label from the EXE's name table, girl id
12) talks first: parts 0–3, or 4–7 when the year byte `0x800E62BE` is 97
(`0x8013B900`). The player's answer is part 1 ("of course") when any girl
has bit 0 of `0x800E6449 + 0x38·girl` set (she gave him chocolate on
Valentine's Day; the flag is collected into `0x80145A10` at `0x8013B85C`),
otherwise part 2 ("no") and Ijuin's jab; part 3 is the player's grumble.
Then section 11 part 0 ("I splurged on one special gift; who gets it?")
and a menu of the girls with the flag (flags copied to `0x800CA2B0`, names
from the EXE's table). The chosen girl goes to `0x800E71DF` at
`0x8013BD00` (delay slot of `0x8013BCFC`); part 1 of section 11 ("there's
{G}") and the girl switch `0x8013BDE0` (jump table `0x801438B0`): girls
0 Shiori → 1, 1 Mio → 6, 2 Yuina → 2, 3 Ayako → 4, 4 Saki → 10, 5 Yukari →
7, 6 Nozomi → 8, 7 Mira → 5, 8 Yuko → 0, 9 Megumi → 9, 10 Yumi → 12. Her
part comes from her mood (`0x80051A68`, returning at `0x8013BD44`): mood
0–1 parts 1–2 (delighted), 2 → 3–4, 3 → 5–6, 4 → 7–8 (cold); part 0 is the
player greeting her. Afterwards every flagged girl's bit is cleared and
her `+0x1C2` field goes up by 1; the chosen one also gets `+0x1BE` +8,
`+0x1C2` +8 and `+0x1C6` −10 (`0x8013BB24`).

### 6v. Valentine's Day (`SERIFU/VALEN.BIN`, `EXEDIR/VALEN.EXN`)

Found 2026-10-09 the same way (`force_valen.py`). Translated in
`translation/valentine.json`.

**Trigger.** Day-record type `0x31` (case `0x80071FB8`) enters main state
`0x54`, which loads VALEN.EXN (LBA 39626, at `0x80132000`).

**File.** 14,336 bytes at LBA 44972 (7 sectors), base `0x80197000`,
checksum trailer. VALEN.EXN loads it at `0x8013253C` (`0x80046318(7,
0x80197000, 44972)`) and fills its tables at `0x80132000`: masters
`0x801343F0`, code lists `0x80134424`, third pointers `0x80134458`;
current section `0x8013448C`–`0x80134494`, part `0x80134498`. 187
strings plus an empty placeholder at `0x362C` (section 2 part 6, code 09).
Sections (`geko_sections.py --valen`): 0 Yuko, 1 the player's count, 2
Shiori, 3 Yuina, 4 Ijuin, 5 Ayako, 6 Mira, 7 Mio, 8 Yukari, 9 Nozomi, 10
Megumi, 11 Saki, 12 Yumi. Speaker code **`0B`** is a second girl in the
scene: Shiori's lines inside Megumi's section (shown with Shiori's label).
Several girls' boxes are a `0C` "あっ、" plus a `0D` string starting
with `{P}`.

**Flow.**
- **Ijuin** (section 4): part 4·year − 0x180 + base, from the year byte
  read at `0x80132718`; in February that's 96–98, giving parts 0–3, 4–7
  and 8–12 for the first, second and third Valentine's Day. Forced on
  another date (April 1995) the part would be negative, so
  `force_valen.py` always sets the year.
- **Who gives chocolate** (`0x80132834`): a list of girl ids at
  `0x80134524` (a byte every 2), count `0x8013453C`, index `0x80134520`,
  built from met girls (bit 1 of `+0x1C8`) whose `0x80052648(girl)` is at
  least 70, ranked by `+0x1BE` + `+0x1C2` (the top three kept in
  `0x80134540`–`0x80134542`; not traced further). The per-girl step
  `0x80132D0C` takes the next one into `0x800E71DF`; her part
  (`0x80134498`, `0x80132D68`–`0x80132E0C`) is 1 (heartfelt) when
  `0x80052648(girl)` ≥ 70, else 0 (courtesy); for Shiori the test is her
  `0x800E643E` ≥ 70. The girl switch `0x80132E10` (jump table
  `0x8013437C`) maps 0 Shiori → 2, 1 Mio → 7, 2 Yuina → 3, 3 Ayako → 5,
  4 Saki → 11, 5 Yukari → 8, 6 Nozomi → 9, 7 Mira → 6, 8 Yuko → 0, 9 Megumi
  → 10, 10 Yumi → 12.
- **Megumi's introduction**: the flag `0x80134544` is set (at
  `0x801328A4`) when Megumi is unmet and `0x800E6636` ≥ 20. Then Megumi's
  part is 3 (Shiori calls the player behind the school and introduces her,
  sections 10 parts 3–12, Shiori speaking with code `0B`) and Shiori's own
  part is 3 (heartfelt, "sorry about earlier, my friend asked me") or 5
  (courtesy, sorry).
- **Banners** VALEN.EXN strcpy's into `0x800CA1DC` (`0x2320`–`0x23B8`):
  廊下, 教室, 校舎裏, 屋上, 校門前, 自宅前 (one string per scene place).
- **The count** (section 1): the closing thought by how many chocolates
  the player got (5 parts, "so many" … "not a single one").
- **Part 2 of each girl** (the player's afterthought: Yuko's "I'm really
  happy", Mio's poem found in the box, Saki's "until morning", …) never
  played in the forced runs, where the girl list is written directly and
  the ranking `0x80134540`–`0x80134542` stays `0xFF`. They're probably the
  later scene for the top-ranked giver (the 自宅前 "Home" banners are
  copied at `0x80133A5C`/`0x80133A84`); not traced.

### 6w. New Year's Day (`SERIFU/SHOGATU.BIN`)

Found 2026-10-09 by static disassembly of SHOUGATU.EXN and forced New
Year's Days in DuckStation (`force_newyear.py`, testing.md "New Year's
Day"). Translated in `translation/new_year.json`.

**Trigger.** Main state `0x53` (entered by the calendar code at
`0x80061100` / `0x801615FC`), one of the four SHOUGATU states (loader case
`0x80078F40`: `0x52` party, `0x53` New Year, `0x55` White Day, `0x5B`
meetings). Swapping a weekday's `set_state(0x40)` for `0x53` plays it on
any date; the year byte `0x800E62BE` (95–97) picks the year's lines.

**File.** 106,496 bytes at LBA 44872 (52 sectors), base `0x80197000`,
checksum trailer; loaded at `0x801326BC` (`0x80046318(0x34, 0x80197000,
44872)`). The fill `0x80132000` writes three 15-entry tables: masters
`0x80143A40`, code lists `0x80143A7C`, third pointers `0x80143AB8`
(current section `0x80143AF4`–`0x80143AFC`, part `0x80143B00`). 1,483
strings (638 distinct); 8 more table slots are empty `09` placeholders
(`0x1967C`–`0x19694`, `0x196D8`), and the dumper's 64 rejected targets are
all non-text. Sections (`geko_sections.py --newyear`): 0 going alone, 1
Yuko, 2 Shiori, 3 Yuina, 4 Ayako, 5 Mira, 6 Mio, 7 Yukari, 8 and 9 Nozomi
(near-identical copies), 10 Megumi, 11 Saki, 12 "something else?", 13
Yumi, 14 "I don't know her number". The girl switch `0x80132A34` (jump
table `0x80143568`) maps girls 0 Shiori → 2, 1 Mio → 6, 2 Yuina → 3, 3
Ayako → 4, 4 Saki → 11, 5 Yukari → 7, 6 Nozomi → **9**, 7 Mira → 5, 8 Yuko →
1, 9 Megumi → 10, 10 Yumi → 13: **section 8 is never selected** (like
G_BIRTH's spare Nozomi copy, §6s); it's translated with section 9's
English.

**Flow (each girl's section).** Part 0–5: she rings the doorbell, the
invitation (`08` choice) and her answer, the regret thought. The visit
happens when the met girl with the best mood (`0x80051A68` < 2, ties
broken by `0x80052C88` + `0x80052648`; loop `0x801328D4`) exists:
`0x8013296C`. Otherwise (or after refusing) part 6: "what now?", go with
a girl or alone; part 7 the girl menu (choice at `0x80122CDC`, 0xB =
Stop; the girl's phone number needs bit 3 of her flags `0x800E6448 +
0x38·girl`, else section 14), part 8 "I just turned her down", part 9 the
call, 10 nobody home, 11 she answers, 12–14 her three phone answers (by
mood), 15 "she isn't here yet", 16 her arrival, 17 going in, 18–22 the
wish (`03` choice; the wish names come from SHOUGATU `0x11D88`, 9-byte
slots, and `{W}` inserts the chosen one), 23–26 "what did you wish for?",
27–30 the fortune and the player's reaction, 31–34 hers by result, 35–38
going home (35/37 the usual endings, 36/38 the "we graduate this year"
ones; forcing the year byte to 97 still gave 37, so the third-year choice
reads something else, not traced), and
for some girls extra parts (Shiori 39–46: the kimono at her door; Yukari
the kimono compliment, `02` reply).

**Fortune drawing** (`0x801350F8`): an in-place announcement in SHOUGATU
(おみくじを引きます。 `0x11640`, うおりゃあああ〜・・・ `0x11658`, こ、これは！！
`0x11670`) then one of three sprintf formats around the result name:
`%sだ・・・` (`0x11680`, bad), `おっ、%sだ。` (`0x1168C`, middling),
`ラッキー！%sだ！！` (`0x1169C`, good). The names are two 7-entry tables of
5-byte slots (`0x11E5C`, `0x11E80`): 大吉, 中吉, 吉, 凶, 大凶, 小吉, 末吉;
`{O}` inserts the drawn one. The formats are patched with `bytes` entries:
pair-encoded English around the raw `%s` (`0x25 0x73`), which works
because every English name is exactly 4 letters (Best, Good, Fair, Poor,
Doom, Okay, Late), so the name's pairs line up with the text around it.

**Banners**: 正月 (four copies, strcpy'd at `0x80132744`, `0x80132DC0`,
`0x80133620`, `0x801336BC`), 初詣 (`0x11630`), and the narration
それじゃ、神社に行くか。 (`0x11600`).

### 6x. The summer training camp (`SERIFU/GASSHUKU.BIN`, `GASSH_FU.BIN`)

Found 2026-10-09 by static disassembly of KANGEI.EXN and forced camps in
DuckStation (`force_camp.py`, testing.md "The training camp"). Translated
in `translation/training_camp.json`.

**Trigger.** Day-record type `0x42` enters main state `0x5F`, KANGEI.EXN's
camp entry `0x80132FF8` (§6q). The camp runs one stage per camp day
(stage `0x800E7389`, 33 stages, jump table `0x801396F0`; the trace of a
forced camp: arrival, then day after day 4/25–4/30 with the date advancing,
then the last day). It goes on only while **the week's first record**
(`0x800E691C`) is a camp day too: the EXE's day-advance step
(`0x800752DC`) calls `next_stage` when that byte is `0x42`, else
`set_stage(1)`, which replays the arrival forever (the first forcing
attempts sat on 合宿所に着いたぞ). `force_camp.py` writes both records.

**Files.** GASSHUKU.BIN: 120,832 bytes at LBA 44640, base `0x80197000`,
loaded at `0x80133CB0`; 8 sections, tables filled at `0x80132E74`
(masters `0x80139A5C`, code lists `0x80139A7C`, third pointers
`0x80139A9C`). GASSH_FU.BIN: 92,160 bytes at LBA 44699, base
**`0x801B4400`**, loaded at `0x80133CEC`; one section (Shiori, 195
parts), tables at `0x80132E40` (`0x80139A50`/`54`/`58`). Current section
`0x80139AD0`–`D8`, part `0x80139ADC`. 1,587 + 1,207 strings, all reached
(GASSHUKU has 3 more empty placeholders, `0x1D2C8`–`0x1D2D8`); the dumper's
rejected targets are all non-text.

**Sections** (switch `0x801349EC` on `0x800E71DF`, jump table
`0x8013984C`): girl 0 Shiori → GASSH_FU, 1 Mio → 2, 2 Yuina → 0, 3 Ayako →
1, 4 Saki → 5, 5 Yukari → 3, 6 Nozomi → 4, others → 7 (Yumi). Section 6
is shared: the arrival line, the last day's bath (peek or not; the three
windows: a girl's scream, the boys' bath, Ijuin's tacky statue) and the
technique box. Each girl's section covers both of her clubs (Yuina:
Science/Computer, Ayako: Art/Band, Mio: Literature/Drama, Saki:
Baseball/Soccer), Shiori's every club.

**The camp's girl** is the first girl (by id) whose club nibble
(`0x800E644A + 0x38·girl`, high 4 bits) equals the player's club
(`0x800E6374 >> 12`), chosen at `0x80133DC8` into `0x800E71DF` (and
`0x800E69DD`); for Basketball from 1996 it can be Yumi. Stage 9
(`0x80134120`) plays her scene: a chat when she's met, else her first
meeting (`0x80134DB0`: food poisoning, the test of courage with lot No.
15, fainting at practice; not for Yumi or in 1997). The chat's part
(`0x80134724`–`0x801349B0`) comes from her mood (`0x80051A68`) and the
club stat `0x800E68EC + 4·club` (< 100, < 200, < 356, more), so it
follows the player's progress through the years.

**Technique box** (section 6 parts 13): `{A}奥義` / `{M}` / `をマスターした。`
— `{A}` and `{M}` are filled from two fixed-record tables KANGEI copies
to the stack at `0x8013769C`: club names, 11 × 20 bytes at file `0x7FAC`
(→ `0x800CA25C`), and technique names, 11 × 21 bytes at `0x8088` (→
`0x800CA280`), indexed by club. Both are translated with `"slot"` 20/21.

**Banners** strcpy'd by the camp: 合宿所 (`0x7780`), the club rooms
(`0x7790`–`0x77F0`), ロビー (`0x77F8`, `0x78B0`), グランド (`0x7800`),
肝試し (`0x780C`), のぞき (`0x78E0`). The club-name strings at
`0x7600`–`0x765C` are copied by code near the club welcome
(`0x80132834`…) and were left alone (8-byte slots: "Baseball" doesn't
fit; not seen on screen).

### 6y. The school trip (`SERIFU/SHUGAKU.BIN`, `EXEDIR/SHUGAKU.EXN`)

Found 2026-10-09 by static disassembly of SHUGAKU.EXN and forced trips in
DuckStation (`force_trip.py`, testing.md "The school trip"). Translated in
`translation/school_trip.json`.

**Trigger.** Day-record type `0x41` (the EXE's switch, case `0x80071FF0`)
enters main state `0x51`; the overlay-load table maps `0x51` to
SHUGAKU.EXN (LBA 39146, case `0x80078F18`) and the entry table to
`0x80137490`. Stage dispatcher there (stage `0x800E7389`, 12 stages, jump
table `0x8013ADB0`). The trip lasts six days (the date advances). One
forced `0x41` record, with the week's first record also `0x41` as for the
camp (§6x), played the whole trip; then the week went on normally (a
meeting scene, then the holiday and weekly prompts). Making the following
records `0x41` too (`--week`) replays the trip from the start after day
6. Where the game writes the real records wasn't traced.

**File.** 92,160 bytes at LBA 44924, base `0x80197000`, 1,111 strings
(1,236 reached: the rest are empty placeholders `0x163F4`–`0x16690`; the
dumper's 8 rejected targets are non-text). Thirteen sections, static
tables at `0x8013C420` (masters), `0x8013C454` (code lists), `0x8013C488`
(third pointers), also written by `0x80136380`; current section
`0x800CA2D0`/`D4`/`D8`, part `0x800CA2DC` (u16). After them, at
`0x8013C4BC`, the 237-word event table GEKO/DATE/SHOUGATU share (§6j):
the trip plays girls' special events from their `EVENT_*.BIN` (Ayako's
Okinawa day ended in her EVENT_KA scene: lost, asking a foreigner the way,
label 外国人 from SHUGAKU `0x8D70` → `0x800CA188`). Those scenes and the
label belong to the EVENT files and are still Japanese.

**Sections** (switch `0x801399F4` on `0x800E71DF`, jump table
`0x8013AF38`): girl 0 Shiori → 1, 1 Mio → 5, 2 Yuina → 2, 3 Ayako → 3,
4 Saki → 10, 5 Yukari → 6, 6 Nozomi → 8 (7 when `0x80051A68(6)` & 0x7F <
2: a softer Nozomi), 7 Mira → 4, 8 Yuko → 0, 9 Megumi → 9. Section 11 is
the default (no girl yet; the opening, destination choice and day
narration), 12 Yoshio (girl `0x0D`). Yumi (a year below) has none.
`tools/geko_sections.py --trip` lists them. Each girl's section has the
same 46 parts: 7–9 she invites the player, 11 go with a girl or alone,
13–25 asking her (15, 18, 21 by mood; 24–25 she refuses), 26/27/28 the
first free day in Kyoto/Okinawa/Sapporo, 29 the way back and the promise,
33–34 the second free day, 35/36/37 the danger (deer, habu, bear) with
"run together / leave this to me", 38 escaped, 39–40 after the fight,
41–45 the last day.

**Flow** (as forced; stage numbers not mapped one by one): day 1
destination choice (京都・奈良 / 沖縄 / 北海道, a three-line choice; the
index goes to `0x800CA2CC`) and arrival; day 2 group tour; day 3 free
time: a girl with mood < 2 may ask him first (loop `0x80139164` over girls
0–9: the best mood below 4, ties by two stat calls; `0x80139200`), else he
chooses: a girl from the menu of met girls (pick in a0 at `0x801399C8`) or
alone (Yoshio, section 12). Her answer follows her mood at `0x80139628`:
0–1 → part +0, 2 → +3, 3 → +6, else +9 (refusal). Day 4 group tour; day 5
the promised free time, the danger choice; "leave this to me" starts an
RPG-style battle (`EXEDIR/RPG_BAT.EXN`, its own text, e.g. ハブ・ロード;
not part of this file); day 6 home. When the player is ill (low nibble of
`0x800E6375`), step `0x8013799C` blanks the opening line and draws four
add_text lines (くぅー、/体の調子が、最悪だぜ。/…).

**Words in SHUGAKU.EXN** (`code_strings.py SHUGAKU.EXN`), translated in
place: banners ホテル・廊下 (`0x8D80`–`0x8DA0`), 修学旅行 (`0x8E78`,
`0x8E84`), ホテル・ロビー (`0x8EF0`, `0x8F60`), 社寺巡り, 守礼門, 時計台前,
土産屋, 浜辺, クラーク像前 (to `0x800CA19C`); the destination as banner
(`0x8E9C`/`0x8EB0`/`0x8EC0` → `0x800CA1DC`) and as `{S}` (`0x800CA23C`:
`0x8E90`… on day 1, 京都/沖縄/北海道 `0x8EC8`–`0x8ED8` after arriving, the
cities 京都/那覇/札幌 `0x8F20`–`0x8F30` on day 3, `0x8FB0`–`0x8FC0`
later); 【団体行動中】 (`0x8EE0`, add_text) and the four sick-day lines
(`0x8E24`–`0x8E60`, add_text).

**Repacked destination names.** "Okinawa", "Hokkaido" and "Sapporo" need
9 bytes with the NUL; their slots hold 8. The 56 bytes `0x8EA8`–`0x8EDF`
(only these strcpy sources use them: no data word or other immediate
points there) are rewritten as Okinawa `0x8EA8`, Hokkaido `0x8EB4`, Kyoto
`0x8EC0`, Sapporo `0x8EC8`, and the `addiu $a1` of each strcpy that read
them (`0x80138240`, `…258`, `…26C`, `…2CC`, `…2E4`, `…2FC`, `0x8013AB40`,
`…B58`, and 札幌's `0x80139474`) points at the new place: ten `bytes`
patches, each checking the original instruction. The old 札幌/沖縄/北海道
at `0x8F30`/`0x8FB8`/`0x8FC0` are then unused and left as they were.
`{S}` counts 18 cells in the width check; an odd-length place name ends in
its padding space, so the dialogue ends a line on `{S}`.

### 6z. The other girls' special events (`SERIFU/EVENT_*.BIN`)

Found 2026-10-10 by walking the shared event table (§6j) against each
file and tracing its readers in GEKO, DATE, SHOUGATU and SHUGAKU; forced
in DuckStation (testing.md "The other girls' special events"). Translated
in `translation/<girl>_events.json` (Yuina, Ayako, Mira, Mio, Yukari,
Nozomi, Megumi, Saki, Yumi, `other_events.json`) and the overlays'
in-place words in `event_words.json`.

**Files and entries.** All load at `0x80198000` (§6j "Loading": GEKO's
loader `0x80138F7C` maps girl ids 0–13 to FU, KI, HI, KA, NI, KO, KY, KG,
AS, MI, SA, then OT for 11–13; DATE, SHOUGATU and SHUGAKU have the same
loader). Each file's strings are reached exactly by one block of the
79-entry table, and every string of every file is reached:

| File | Girl id | Entries | Strings | Readers |
|---|---|---|---:|---|
| EVENT_HI (Yuina) | 2 | 14–20 | 98 | GEKO 14, 20; DATE 15–18; SHUGAKU 19 (Hokkaido, trip stage 8) |
| EVENT_KA (Ayako) | 3 | 24–29 | 108 | GEKO 24; DATE 25–28; SHUGAKU 29 (Okinawa, stage 9) |
| EVENT_KG (Mira) | 7 | 30–36 | 116 | GEKO 30, 36; DATE 31–35; SHOUGATU 36 (walk after the Christmas party, stage 7) |
| EVENT_KI (Mio) | 1 | 37–41 | 75 | GEKO 37; DATE 38–41 |
| EVENT_KO (Yukari) | 5 | 42–48 | 118 | GEKO 42, 43; DATE 44–47; SHUGAKU 48 (trip stage 11) |
| EVENT_KY (Nozomi) | 6 | 49–53 | 147 | GEKO 49; DATE 50–53 |
| EVENT_MI (Megumi) | 9 | 54–60 | 140 | GEKO 54, 55; DATE 56–59; SHOUGATU 60 (walk after the party, stage 8) |
| EVENT_NI (Saki) | 4 | 61–66 | 169 | GEKO 61; DATE 62–65; SHUGAKU 66 (trip stage 10) |
| EVENT_SA (Yumi) | 10 | 67–73 | 160 | GEKO 67, 68, 73; DATE 69–72 |
| EVENT_OT | 11 Miharu, 12 Ijuin, 13 Yoshio | 21–23, 74–78 | 190 | GEKO 21–23 (Ijuin), 74, 75, 77 (Miharu), 78 (Yoshio); DATE 76 (Miharu's mix-up) |

A few other entries' pointers also land inside these files when read with
the wrong file (12, 18, 20, 1, 39, 23 overlap strings by chance); they
belong to the files in the table.
Nozomi's entries carry two versions of most scenes (soft and tomboyish
parts in the same entry, picked by her mood).

**Where each kind plays.**
- **GEKO (school days):** a day record `45 GIRL SCENE 00`
  (`force_event.py GIRL SCENE`). Handler table `0x80144910` (girl id →
  scene switch): Yuina scenes 1, 7; Ayako 1; Nozomi 1, 8; Mio 1; Yukari
  1, 2; Megumi 1, 2; Saki 1; Mira 1; Yumi 1, 2, 7; Miharu (11) 1, 2, 4;
  Ijuin (12) 1–3; Yoshio (13) one scene. Miharu's scenes set the `{G}`
  buffer to 館林さん and the label to 館林 (GEKO `0x12B1C`/`0x12B24`).
- **DATE (dates):** the date-event chooser (`0x8013272C`, §6k) calls
  `0x801326B0(scene, flag?, flag index)`, which stores the scene in
  `0x80122CD0` and enters main state `0x5E`; DATE then reads the date
  girl's entry for that scene (scene 2 = her first DATE entry, …) at
  `0x8014D0A4` ff., whatever the place. `force_date.py --event N` jumps
  there with a0 = N. The place's banner still shows the date's place.
  Miharu's mix-up (entry 76) belongs to girl 11 inside a date with another
  girl (`--event 3 --event-girl 11`, not run).
- **SHOUGATU (Christmas party):** stages 7 and 8 of the party flow
  (`0x80142500` Mira, `0x801430A0` Megumi) are the walks home, like
  Shiori's stage 6; `force_christmas.py --girl 7|9`.
- **SHUGAKU (school trip):** stages 8–11 (§6y). The checks after the free
  days pick them: stage 8 Yuina when the destination is Hokkaido, 9 Ayako
  for Okinawa (both at `0x80138828` ff. with the girl in `0x800E71DF`),
  11 Yukari and 10 Saki when their mood (`0x80051A68`) is below 2; Saki's
  also needs `0x800E69DD` = 4, set in `0x801388D8` only when a birthday
  check (`0x800E62BF`/`0x800E62C0` against her record) passes, so the
  forcer didn't reach it. `force_trip.py --event-mood` sets the moods.
  Yuina's crop-circle scene ends in an RPG battle (`RPG_BAT.EXN`, an
  "alien" 宇宙人, still Japanese).

**Speaker labels.** In-string labels as in §6p: `{>先生}` → `{>Tchr}`,
`{>幹部}` → `{>Boss}`, `{>迷子}` → `{>Tyke}`, `{-戦闘員}` → `{-Minion}`,
`{-女生徒}` → `{-Girl}`, `{-謎の女}` → `{-???}`, and the 2-byte `{+犬}`
(Megumi's dog) → `{+Mu}` (Muku; two letters is all a `+` label holds).
The overlays' own labels: 外国人 (SHUGAKU `0x8D70` → "Expat"), 男子１/２,
先生, 謎の女 (GEKO, DATE).

**Words in the overlays** (`event_words.json`): GEKO's banners and labels
`0x12984`–`0x12B60` (only those the event code uses; Shiori's room is
"Her Room"); DATE's event words at `0x29440`–`0x29510`. Three DATE words
are 4–6 bytes with 8–10 bytes of NUL after them up to the next string or
pointer (観覧車 `0x29470`, 遊園地 `0x294F0`, 池 `0x29500`); only the one
`addiu` that reads each points into that stretch, so `bytes` patches use
the padding for "Ferris Wheel", "Theme Park", "Pond". DATE's place banners
for regular dates (`0x28B20`–`0x28E84`) are still Japanese (out of scope;
they show on every date).

**`{G}` width.** Every writer of the `{G}` buffer `0x800CA190` is known
(§6e table): its longest English value is 8 letters, so the width check now
counts `{G}` as 10 cells, not 18. Text after an odd-length name shows its
pair padding ("Yuina ,"), so these files end lines on `{G}` for Yuina, Mio,
Rei (Ijuin) and the other odd names.

### 6aa. Map of the remaining script files, states and day records

Surveyed 2026-10-10 with `tools/script_survey.py --all` (loaders, base,
section tables of every untranslated script file) and
`tools/exn_words.py --all` (in-place overlay words), as part of the upstream whole-game survey. All of these follow the layouts of §6j/§6k: one
`dialogue` block per file, sections in the EVENT_FU layout.

**Main state → overlay** (overlay-load table `0x800B19E8`, indexed by
state − 0x11; each case loads one EXN by LBA):

| Overlay | States | What |
|---|---|---|
| BUNKASAI.EXN | 0x70 | culture festival day (girl's exhibit, own club) |
| BUNKAKEN.EXN | 0x71 | festival tour with a girl, invitations |
| BUNKA_SD.EXN | 0x80 | festival stage shows (BUNKASD/*.BIN) |
| ENDING.EXN | 0x63 | graduation: confession (ENDING.BIN), epilogue (EPILOG.BIN) |
| MASTER.EXN | 0x74, 0x75, 0x76 | club contests and tournaments (MASTER/*.BIN) |
| OMIMAI.EXN | 0x61, 0x62 | sickbed visits (OMIMAI.BIN), encouragement (HAGEMASI.BIN) |
| DATE2.EXN | 0x58, 0x5C | group dates (GROUP_D.BIN, KARADATA.BIN) |
| RENSYU.EXN | 0x73 | practice matches (SHIAI/SIAI_TX.BIN) |
| TAIIKU.EXN | 0x72 | sports day (TAIIKU/*.BIN) |
| RPG_BAT.EXN | 0x81 | the trip's battles (BATTLE/*.BIN) |
| ETC.EXN | 0x35–0x37, 0x91 | exams and other one-day screens |
| OLH.EXN | 0x3A | (not identified yet) |
| EN_NICHI.EXN | 0x82 | the shrine fair minigames |
| DATE.EXN 0x50/0x5E, GEKO 0x56/57/59/5A/5D, KANGEI 0x5F/60, SHOUGATU 0x52/53/55/5B, SHUGAKU 0x51, TEL 0x43/45, VALEN 0x54, NAME_ENT 0x11/13–15, OPTION 0x20–22 | | translated areas |

**Day-record type → state** (the main loop's switch `0x800B1340`, §6j;
`tools/emu/force_event.py G S --type T [--first]` writes one): 0x10 →
0x46, 0x20 → 0x72 (sports day), 0x24 → 0x70 (culture festival: forced on
4/25 it played the whole day, BUN_PC.BIN's lines, the girl menu, the club
menu, Shiori's exhibit, and the week went on), 0x25/0x26/0x27 → 0x74/0x75/
0x76 (MASTER; 0x25 with the test card's club played the baseball
tournament, MASTER/KOSIEN.BIN, and its technique box; 0x26 and 0x27 went
back to the title screen on the 95/4 card, so they need more set-up),
0x28 → 0x42, 0x2C → 0x41 (it played New Year's Day), 0x30 → 0x55 (White
Day), 0x31 → 0x54 (Valentine), 0x32 → 0x57, 0x33 → 0x56, 0x40 → 0x35
(nothing visible on the test card), 0x41 → 0x51 (trip), 0x42 → 0x5F
(camp), 0x43 → 0x36 (the third year's start and the career counselling:
ETC.EXN's own text, a 先生 label), 0x45 → 0x5D (special events), 0x47 →
0x61 (a girl's encouragement, HAGEMASI.BIN, girl in the record; state 0x62 is
the sickbed visit, OMIMAI.BIN, 2026-10-11),
0x48 meetings (§6p), 0x49 → 0x58 (Yoshio's group date at the theme park:
GROUP_D.BIN, with ride choices between two girls), 0x4A → 0x37 (the
university exam day: ETC.EXN's text and menus), 0x20 → 0x72 (sports day:
an event menu, then a spoon-race minigame that needs input), 0x10 → 0x46
(nothing visible). Probes `pb1`–`pb12` (testing.md). `force_state.py
0x63` from the Sunday state played the ending with nobody waiting
(graduation-day lines with Yoshio, then the epilogue narration over the
room and the bad-ending song's lyrics on a black screen): run `fs1`. Main states
without a record (the ending 0x63, BUNKAKEN 0x71, ...) can be entered with
`tools/emu/force_state.py STATE [--stage N]`.

**Files** (load base; who loads them; tables `script_survey.py` found,
covering every dumped string unless noted):
- **Festival, `BUNKA/` (base 0x801E8000):** per girl `XX_S6` (at her
  exhibit) and `XX_S6B`, `XX_S6O` (her exhibit, other versions), the club
  variants `KT_S61–63` (Ayako), `KS_S61–62` (Mio), `XX_S6W` (touring the
  festival with her), `XX_S6S`/`XX_S6I` (her invitation to the festival /
  to her club); `BUN_PC` (the player), `BUN_FU` (a birthday on the
  festival), `TWINBEE`, `URANAI`. XX: AS Yuko, FU Shiori, HI Yuina, KG Mira,
  KO Yukari, KY Nozomi, MI Megumi, NI Saki, SA Yumi, KT Ayako
  (Katagiri), KS Mio (Kisaragi). S6/S6B/S61–63 are loaded by BUNKASAI,
  S6O/S6W and the invitations by BUNKAKEN (the invitations through an LBA
  table at BUNKAKEN `0x80155F0C`); all section tables are built by code
  (`lui`/`ori` pairs) in those overlays. 217,000 characters, very
  repetitive: the translation memory (`tools/draft.py`) fills shared lines.
- **Dates, `SERIFU/DATE_*` (0x80198000, DATE.EXN):** the code-built
  tables reach 85–98% of each file; the rest are the strings §6k lists as
  missed or out-of-file (check with `tools/date_sections.py`).
- **Ending:** ENDING.BIN (0x801F0000; ENDING.EXN table `0x8013C280`, 17
  sections, all 410 strings), EPILOG.BIN (0x80180000; table `0x8013CAC0`,
  15 sections).
- **SERIFU, other:** GROUP_D (DATE2 `0x8013A380`, 11), KARADATA
  (0x801B0000, DATE2 `0x8013B540`, 11), OMIMAI (OMIMAI.EXN `0x80134A60`,
  12), HAGEMASI (`0x80134C30`, 13), ZAKOSEN (0x801B0000, DATE.EXN
  `0x8015B644`, 2).
- **Club contests:** `MASTER/*.BIN` (0x801E8000, MASTER.EXN code-built
  tables): TAI_MAS (309 strings), SUI_CON, EN_GP, G_CON, MOKUTEN, NOBEL,
  UEKI, KOSIEN; `SHIAI/SIAI_TX.BIN` (RENSYU.EXN).
- **Sports day:** `TAIIKU/` F_DANCE, KISA23, KIYOTAI, TAI_TX, KARI
  (TAIIKU.EXN).
- **Not text** (the scan's false positives in `progress.py`): `CLUB_SD/`,
  `MAIN_SD/` (animation data), `BS/`, `XA_G/`, `VAB_SEQ/`, most of
  `BATTLE/` and `TAIIKU/` (graphics), `FUKUTEST/NAME_KAN.NBN` (the
  name-entry kanji grid). `TARA_OBJ/KARAKASI.BIN` is song lyrics (rule 9:
  not reproduced, left alone). `FUKUTEST/JOHO.NBN` holds the girls' info
  card values (sizes, birthdays).

**Overlay words** (`exn_words.py --all`, untranslated in-place strings):
RPG_BAT 319, OLH 290, ETC 200, BUNKA_SD 207, NAME_ENT 126, DATE 76 (the
date place banners), BUNKAKEN 55, BUNKASAI 46, MASTER 36, the EXE 34,
TAIIKU 28, ENDING 25, OPTION 20, OMIMAI 16, a few elsewhere.

### 6ab. The culture festival (`BUNKA/*.BIN`, BUNKASAI.EXN, BUNKAKEN.EXN)

Found 2026-10-10 by forcing the day with `tools/emu/force_festival.py`
(day record `24 00 00 00`, main state 0x70) from the Sunday state.

**Flow without an exhibiting club** (club 11): BUN_PC's opening ("Festival
day!"), "ask a girl / go alone", the girl menu (only girls whose met bit,
bit 1 of `0x800E6448 + 0x38·girl`, is set, then Stop), the meeting and
"Look around with me?", then her answer from her invitation file.
BUNKAKEN loads it through the LBA table at `0x80155F0C` (12 words) indexed
by the girl byte `0x80122EBC` (readers `0x8013B5F0`, `0x801440D8`; the
sector counts are bytes at `0x80155F00`): entries 0–3 are the club girls'
`FU/KS/HI/KT_S6I` (Shiori, Mio, Yuina, Ayako: she's busy with her club
and asks him to visit it), 4–10 the other girls' `XX_S6S` (she comes
along), 11 Shiori's `FU_S6S`. The club menu follows (Literature, Drama,
Science, Computers, Art, Band; the cursor moves **linearly**, any arrow
key is +1). With a girl along, her tour file `XX_S6W` plays the chosen
exhibit and the way home. Alone, Yoshio stops by, and at a club girl's
exhibit her `XX_S6O` file plays (Mio after the Drama play, in the
dressing room); at another exhibit, "Nobody I know here" and the show.

**Flow with an exhibiting club** (clubs 0–5): BUN_PC names the club's
exhibit, Shiori visits (`FU_S6`), the club's own scene (the Science
explosion, the Art portrait, the Computer Club's PC fortune), then the
festival ends and Shiori is met on the way home (GEKO). The Drama play,
the Band concert and the Literature speech contest are BUNKA_SD.EXN's
stage shows (state 0x80, phase B13), still Japanese.

**PC fortune** (BUNKASAI `0x8015B308`, BUNKAKEN `0x80152A18`): draws
the girl's family name from the EXE table `0x800B35F4` and then her given
name from a stack table. `character_names.json` maps that table to given
names, so the screen read "Shiori Shiori"; the second `jal 0x8004E788`
(BUNKASAI file `0x29388`, BUNKAKEN `0x20A98`) is replaced by a `nop` in
the festival word files. The player's line takes the family name and the
name the player typed.

**Stage shows** (BUNKA_SD.EXN, state 0x80; translated in
`stage_shows.json`): the text is file `0x7910`–`0x9670`, one string per
displayed line, each starting with a prefix byte: `' '` (more lines
follow), `'g'` (end of page: wait for a press) or `'E'` (end of the show),
padded with full-width spaces that pace the scroll. Ten pointer tables at
`0x9670`–`0xB140` reach the 286 lines and speaker labels (one label
string per use, unprefixed); code-built addresses reach the speech
titles, the 題目 "Topic" header, the speakers' names and the 「 drawn
before each line. Jump tables sit inside the text run (`0x7FD8`,
`0x8994`, `0x8A40`, `0x8D94`, `0x9524`, `0x95F0`), and two lines follow
one with no NUL in between (`0x8090`, `0x8AD0`). The box is wider than
a dialogue box (28+ letters per line fit) and scrolls line by line.
Which show plays: the Drama Club's by year (95 Kintaro Samurai, 96
Cultman, 97 Romeo and Julietta), the Literature Club's speech contest in
97 (95 poems, 96 essays), the Band's concert (no text). `tools/
prefixed_lines.py` writes one `bytes` patch per line, keeping the prefix.

**Megumi's tour** returns to the title screen right after the club menu,
in the unpatched game too (run `fu09b`, Japanese text): her `MI_S6W` is
never reached from this forcing. Not investigated further.

`FU_S6.BIN`'s checksum trailer doesn't match its contents in the
original disc (sum `0x9467`, trailer `0x9584`), so `has_checksum` is
false and the patcher leaves the trailer alone; the game loads the
patched file fine (runs `fb0`–`fb5`).

### 6ac. The ending (ENDING.EXN, ENDING.BIN, EPILOG.BIN)

Found 2026-10-11 with `tools/emu/force_ending.py` (state 0x63 from the
Sunday state).

**Who waits.** ENDING.EXN sets the girl byte `0x800E71DF` to 13 (nobody),
then 12 in a special case (a score at `sp+0x58` under 500, `0x800E66EB`
≥ 70 and `0x800E683B` == 2), else the met girl (bit of `0x800E6448 +
0x38·g + 0x1C8`) with the highest score above 499 (`0x801331B0`–). The
result is read back at `0x80133224`; `force_ending.py` overwrites it
there. 13 plays Yoshio's "shall we go home?" and the bad epilogue over the
player's room, then the song (title in place at `0xA260`, lyrics from
`0xAC48` and `TARA_OBJ/KARAKASI.BIN`, left in Japanese), the credits and
ETC.EXN's save prompt.

**What is drawn.** The classroom part uses the normal dialogue box. At
the tree, text is drawn straight over the art and **only the player's
lines appear**; the girls' confessions (codes `0C`/`0D`/`0F`, up to 20
full-width characters a line) play as voice only, unpatched as well
(voice mode `0x800E62BC` makes no difference: ENDING.EXN never reads it).
Their English is kept within 28 cells anyway. ENDING.BIN is also loaded
by OPTION.EXN (`0x8013878C`, the Extras "Ending" replay).

**Epilogue** (EPILOG.BIN): a narrow column (about 22 cells) scrolling
over the tree art, with the girl's name and ENDING.EXN's career words
(`{M}`) inserted.

### 6ad. Club contests (MASTER.EXN, MASTER/*.BIN)

Found 2026-10-11 by forcing the day records (`force_event.py 0 0 --type T
--club C`, club in the top 4 bits of the u16 `0x800E6374`):
- **0x25** → state 0x74: the baseball tournament, KOSIEN.BIN (whatever
  the club), with its secret-move box.
- **0x26** → 0x75: a sports club's nationals final, TAI_MAS.BIN (soccer,
  swimming, basketball seen; the "Caster" label); with a culture club it
  returns to the title screen.
- **0x27** → 0x76: a culture club's contest; MASTER.EXN switches on the
  club (`0x80132478`, jump table `0x8013BA68`): 0 Literature UEKI, 1
  Drama EN_GP, 2 Science NOBEL, 3 Computers G_CON (then its shoot-'em-up
  minigame), 4 Art MOKUTEN (目展, the game's Nitten parody: "Meten"), 5
  Band SUI_CON. With a sports club it returns to the title screen.

Practice matches (RENSYU.EXN, state 0x73, `SHIAI/SIAI_TX.BIN`): forcing
the state alone returns to the title; their record isn't found yet, so
`practice_matches.json` was promoted unverified.

## 7. Graphics

### General
- Most graphics are **raw pixel data with separate palettes**, not TIM files.
- Uploads go through `0x8004435C(x, y, w, h, [sp+0x10] = source)` (x and w
  in halfwords). `TITLE.NBN` comes in 64×128-halfword blocks (16 KiB: 128 px
  at 8bpp, 256 px at 4bpp); `MAINROM.NBN` in **32×128-halfword chunks**
  (8 KiB, 64-byte rows). Palettes are uploaded as 256×1 (256-colour CLUTs).
  Log the uploads to learn a file's layout (testing.md, "Does this code ever
  run?", `--stack 6`).
- **Get the row width right before reading anything into the art.** Rendering
  64-byte rows as 128-byte rows interleaves two rows: every glyph looks half
  height and the sheet looks like two copies side by side.
- To tell 8bpp from 4bpp: render a region as 4bpp. If shapes show vertical
  1-pixel striping, it's really 8bpp.
- `BS/*.BS` and `*.STR` are MDEC-compressed stills and movies (different tooling,
  not yet handled).

### Sprite frames (`SLPM_86.053`)

Most UI sprites (the main-screen stat panel, calendar, ...) aren't drawn
from coordinates in code. Sprite objects (e.g. at 0x8011F2xx) hold a **frame
number**, and the renderer (`0x80047804`–) looks the frame up in a pointer
table at **`0x800C975C`** (190 entries, static data in the EXE, file offset
= address − 0x80040800). Found with a read watchpoint on an object's frame
field while the screen was showing.

Frame data: `s16 part count, x offset, y offset, 0`, then one 14-byte part
each: `s16 x, y, cell, attr, 0, w, h`. `cell` counts 8×8 tiles in a 128 px
wide strip: tile `c` is at x = (c % 16)·8, y = (c / 16)·8. For the main-screen
sheet the strip is `MAINROM.NBN` chunk 4 (rows 0–127) followed by chunk 9
(rows 128–255). `attr` selects texture page/CLUT (0x3100 for the calendar
characters and labels, 0x3080/0x308D/0x30Fx for frame art); not decoded
further.

Changing a part's `cell` is a 2-byte patch (`translation/main_screen.json`),
which is how cells shared by two meanings get separated.

| Frame | What |
|---|---|
| `0x3C` | vertical calendar: parts 3/4/5 = 年/月/日 suffixes (cells 44/14/42), part 6 = the `( )` around the weekday (cell 98), plus borders |
| `0x3D` | stat panel: parts 25/26/27 = the three 32×40 label columns (cells 268/348/428), parts 14–24 the dashes (cell 100) and borders |
| `0x44`–`0x4D` | digits 0–9 (8×16) |
| `0x52`–`0x58` | weekday Monday…Sunday (cells 14, 32, 34, 36, 38, 40, 42). Monday **shares** the 月 cell and Sunday the 日 cell with the calendar suffixes |

### `FUKUTEST/MAINROM.NBN` (108,544 bytes, no checksum trailer)

Main-screen and command-screen art: command icons, stat panel, calendar
characters, girl-info labels, town-news banners. Loaded at boot to
0x80180000 (53 sectors, before the title) and uploaded once, so a change
needs a reboot to show (a save state keeps the old VRAM). 4bpp, 13 chunks of
8 KiB = 128×128 px, **64 bytes per row**. Uploads (file offset → VRAM
halfword x, y): 0x00000 → (0x380,0x180), 0x04000 → (0x380,0x100),
0x06000 → (0x2C0,0x100), 0x08000 → (0x300,0x180), 0x0A000 → (0x3C0,0x180),
0x0C000 → (0x3E0,0x180), 0x0E000 → (0x340,0x100), 0x10000 → (0x2C0,0x180),
0x12000 → (0x340,0x180), 0x16000 → (0x3C0,0x100), 0x18000 → (0x300,0x100).

- **Chunk 4 (0x8000):** row 0: digits 0–9 (8 px each), ● × ▲ ?, 月 (x112);
  row 16: 火 水 木 金 土 日 年 (16 px cells, x 0–96); row 48: the `( )`
  weekday bracket cell (x16) and the stat dash (x32). Glyph fill index 9,
  drop shadow index 10 at (+1,+1).
- **Chunk 9 (0x12000):** x 96–127, rows 0–119: the stat labels, one 40-row
  block per panel column (体調 芸術 容姿 / 文系 運動 根性 / 理系 雑学 ストレス),
  a label every 14 rows. The dash sprite starts ~27 px into the label, so
  that's the usable width. x < 96: panel frame art.
- Chunk 0 is the command icons, chunk 1 girl-info labels (星座, B.W.H, 電話,
  血液型). **The info card doesn't use them**: checked on screen 2026-10-11
  (Yoshio, "Ask girls' views", Shiori). Its labels are add_text strings
  (`phone_calls.json`) and its values come from JOHO.NBN (`info_card.json`).
  No screen showing these cells has been found, so they're left as they
  are. Chunk 11 the date-spot magazine art (メモリアルスポット masthead and
  issue labels; left as they are, like the title logo).
- **Town News headlines** (found 2026-10-11): EXE frames 126–133 (table
  `0x800C975C`) draw the eight banners 中央公園紹介 … プラネタリウム特集, each a
  24-row strip: part 1 up to 128 px plus a tail part. Their cells use one
  texture page: cells 2048–2303 = chunk 2, 2304–2559 = chunk 7, 1792–2047 =
  chunk 11 (confirmed by rendering the frames). Headlines 1–5 are chunk 2
  rows 0/24/48/72/96 (widths 128/120/112/128/112), 6–8 chunk 7 rows 0/24/48;
  the tails sit at chunk 2 x 120–127 y 24–47 and x 112–127 y 48–71 and
  96–119, and chunk 11 x 0–47 y 104–127. Each banner has its own colours
  (ink 2/7/12 with shadow 4/9/14). Translated in `town_news_banners.json`
  (`tools/redraw_labels.py`, big bold letters, tails cleared).

`FUKUTEST/EXAMINE.NBN` (loaded by ETC.EXN for the end-of-term exam
results) is 4bpp with 64-byte rows: file `0x0000`–`0x1FFF` and `0x2000`–
`0x3FFF` are byte-identical copies of MAINROM chunks 4 and 9, so
`exam_results.json` applies the same image patches there; rows 314–325
hold the board title 期末試験結果発表 (ink 9, shadow 0xA down-right).
`NAME_ENT/NAME_ENT.NBN` is the same 4bpp/64-byte layout (render it at
128-byte rows and it looks like two half-height copies).

`CALROM.NBN` (loaded at 0x801A0000 on the main screen) holds the Calendar
command's month pages, which are already in English (MON TUE …).

### `FUKUTEST/TITLE.NBN` (438,272 bytes, checksum trailer)
- Holds the title logo, copyright line, the GAME START/OPTIONS menu cells,
  character art and 16 CLUTs. Loaded to 0x80180000 and uploaded from there.
- Pixel data in 16 KiB blocks, 128 bytes per row (8bpp). The layout of every
  block isn't fully mapped. The parts used so far:
  - **Menu cells:** block at file offset **0x60000**, rows 68–115, 16×16 cells:

    | Row y | Cells (x=0…127) |
    |---|---|
    | 68 | ゲームスタート *selected* (x 0–111), オ (x 112–127) |
    | 84 | ゲームスタート *unselected* (x 0–111), プ (x 112–127) |
    | 100 | シ (0–15) ョ (16–31) ン (32–47); x ≥ 48 is unrelated art, **don't touch** |

    The game draws each item's cells next to each other on screen, so a word
    drawn as one strip and sliced into the same cells displays seamlessly.
    The オプション cells here are the **unselected** (grey) version only.
  - **Highlighted OPTIONS:** a separate, contiguous 80×16 strip in the block
    at file offset **0x5C000**, rows 52–67, x 48–127 (オ プ シ ョ ン at x = 48,
    64, 80, 96, 112), in the blue selected style. On those rows **x < 48 is the
    pointing-hand cursor; don't touch it.** Found by shape-matching the grey
    オ/プ/シ cells (zero/non-zero pixel masks) against every 16×16 window of
    the file. A colour-index search missed it.
  - **Styles in the menu CLUT:** selected = outline index 8, fill gradient
    2,3,4,5,6,7,7,6,5,4,3,2 on cell rows 2–13. Unselected = outline 24, gradient
    18–23 the same way. Indices 10–15 and 25–31 are anti-aliasing blends.
  - **CLUTs:** 16 × 512 bytes in 0x4C000–0x4E1FF, **not stored in upload order**.
    VRAM upload # → file offset: 0→0x4C400, 1→0x4C600, 2→0x4C800, 3→0x4CA00,
    4→0x4CC00, 5→0x4CE00, 6→0x4D000, 7→0x4D200, 8→0x4D400, 9→0x4D600,
    10→0x4D800, 11→0x4DA00, 12→0x4DC00, **13→0x4E000 (menu)**, 14→0x4DE00,
    15→0x4C000.
- Colours are 15-bit BGR (`r = c & 31`, `g = c>>5 & 31`, `b = c>>10 & 31`; bit 15 = STP).
  Index 0 / colour 0x0000 is transparent.

### `BATTLE/*.BIN` (school-trip RPG battles, `RPG_BAT.EXN`)
- RPG_BAT loads one file per battle at 0x80180000 (e.g. `VS_HABU.BIN`, LBA
  14934, file name list at `0x8013A074`–`0x8013DCD0`). The file carries its own
  sprite frame table (VS_HABU: `0x801B576C` = file 0x3576C; frames as in
  the EXE: `s16 parts,x,y,0` + 14-byte parts `x,y,cell,attr,0,w,h`) and its
  pixel chunks. Sprite objects are the usual 0x44-byte ones from 0x80120650.
- **Frame cells count 8×8 tiles of 128×128 8bpp chunks**: cells 0–255 are
  the UI chunk, 256+ the background (frame 0, 320×168) and the rest.
- **The UI chunk isn't 0x4000-aligned.** VS_HABU's starts at **0x20A10**
  (128-byte rows from there): checked against the window gradient (cell 48),
  the highlight bar (cell 144) and the digits (cells 224–233). Every battle
  file with a command menu has a copy: PARK, UTYU, VS_PARK, VS_UTYU at 0x80;
  VS_KUMA 0x188F0, VS_SIKA 0x188D8, VS_ROBO 0x2B258, VS_UFO 0x2D35C. They
  differ by 0–177 pixels outside the labels. The other `VS_*.BIN` (sports
  and club versus screens) have no such chunk.
- **Command menu** (frames 4–7): 32×16 cells. The bright versions are cell 60
  攻撃 (96,24), cell 92 防御 (96,40) and cell 12 奥義 (96,0), in ink 0x18 with
  a 0x1A shade. They sit on a 40×16 bar (cell 144) that the CLUT turns red
  when highlighted. The dim versions are cells 151 (32×32, 攻撃+防御 at
  (56,72)) and 234 (奥義 at (80,112)), in 0x10/0x12. ミス (miss) is cell 149
  (40,72), 16×8 in 0x10/0x12, and cell 165 (40,80) in 0xEE/0xEF (frames 64/65).
  All of these are redrawn as Fight/Guard/Skill/Miss in `battle_menu.json`
  (`tools/redraw_labels.py`). "Attack" is 32 px and leaves no room for the
  shadow inside a 32 px cell; Miss is a hand-drawn 6-row bitmap.
- The menu words aren't text, so a search of RAM for 攻撃 finds nothing.
  The battle's names and lines are RPG_BAT's own text (`trip_battles.json`).

### Sports day instruction cards (`TAIIKU/*SETU.BIN`, `TAIIKU.EXN`)
- Each event opens with a parchment card explaining the controls, drawn by
  the font-less **tile picture** system of the EXE, not by text: SPSETU
  (spoon relay), KASETU (borrowing race), TASETU (ball rolling), NINSETU
  (three-legged race, two pictures: a casual and a polite version). The
  file loads at 0x8018F000. The card is a full screen, 320×256 8bpp,
  uploaded to VRAM (0x140, 0) in 1280 8×8 pieces.
- **Format** (all little-endian):
  - CLUT at file 0.
  - Tile header `u32 pages, u8 8,8,4,4, u32 0x400, u32 blocks`. Its offset
    varies: SPSETU 0xE000, KASETU 0xE008, TASETU 0x12008, NINSETU 0x1E008
    and 0x1F020.
  - Then `blocks` block maps of 4×4 u32 entries, row-major. Entry byte 0
    holds the flips (bit 0 vertical, bit 1 horizontal), byte 2 the tile
    index within its page (16 per row), byte 3 the page.
  - Then a 20-byte screen header (`03 03 00 00 20 20 04 04 01 S 08 08 ...`),
    followed by 8 rows of 10 u32 block numbers. The row stride is S×0x20
    (0x800 or 0x40).
  - Pages are 128×128 8bpp (16 KiB). The file doesn't say where they are;
    they were found by decoding: 0x2000/0x6000, and for NINSETU 0xE000/0x12000
    (casual) and 0x16000/0x1A000 (polite). The loader fills in a page
    pointer table; SPSETU's file even contains one (0x129CC), saved from RAM.
- **Code:** the layer descriptors are at 0x801217A0 (20 bytes each: tile
  table pointer, map pointer, type, w, h, cell size).
  - **0x8004D1C8–0x8004D2C0** walks the screen map. It **skips entries
    whose low 16 bits are 0**: block 0 means "nothing here", and reusing it
    leaves VRAM garbage on screen.
  - **0x8004D3C8**(layer, block, …) draws one block.
  - **0x8004D6B8** copies a tile with its flips, then **0x8004435C**
    uploads it (`ra` 0x8004D64C).
- `tools/make_sports_cards.py` decodes each card, draws the English and
  re-encodes it with minimal changes (`sports_day_cards.json`). The changes:
  the Japanese glyph tiles are reused, blocks no longer on screen are
  renumbered (never block 0), and the decode is checked against the
  intended picture. The cards' text area (x 50–270, y 36–172) is plain
  colour 0x17. Ink is 0x11, red 0x2A, and the title uses hollow letters.
- The girl standing by the card and the pointing hand are sprites that the
  original also shows. The three-legged race's ひだり/みぎ (left/right)
  speech bubbles are separate minigame sprites, still Japanese.

## 8. Open questions / next research targets

1. **Dialogue beyond the prologue** (§6e): confirm the SERIFU load addresses
   in the game, find which scene code drives each file (and any line-timed
   events like Rei's), and where the remaining name codes (`S O W A M p m F`)
   come from. The ordinary speaker-label source and `{Y}` are now mapped.
   Check `BUNKA/`, `SPEAKTST/`, `EVENT/`.
2. **Text renderer leftovers:** the sprite drawer that places cached glyphs (for
   a true variable-width font later). Dialogue does go through
   `add_text`/`layout_string` (§6e).
3. **Pointer tables:** systematically map them in the EXE and overlays, so strings
   can be relocated into free space instead of only fitting in place.
4. **Data-file LBA tables:** how non-overlay files (e.g. `TITLE.NBN`, `SERIFU/*`) are
   located (hard-coded constants like the overlays?). Needed before files can grow.
5. Where `GYOZI.EXN` and `O.BIN` are loaded from. `EVENT.EXN` looks like a
   stale build that is never loaded (§6j).
6. Which title-menu graphics remain: the logo (ときめきメモリアル) is Japanese art
   in the same file and hasn't been touched.
7. **More room for code.** The renderer hook (§6f) uses two unused EXE
   functions. Anything bigger (a variable-width font, relocation helpers)
   needs more: the dead-code scan in §6f lists further candidates, each to be
   checked the same way before use.
8. **The rest of the main loop** (§6g): what each command icon opens (study
   choices, outing places at 0x72B40–, club commands, phone list, the
   stat-result messages after a week), where the stat-name strings at
   0x72AD0 are used, and the `MAINROM.NBN` art not translated yet (girl-info
   labels, town-news banners, date-spot art). The command grid's hand
   doesn't respond predictably to the test driver's key holds (testing.md),
   so reaching each command needs a better input method first.
9. **Regular dates** (§6k): the other places' flows (step lists) and how to
   reach the Theme Park parade (section 9) without walking every ride.
   Resolved 2026-10-07: section 7 is place 0, the `n` marker, the museum's
   variant-5 selector, and DATE2.EXN, which loads `GROUP_D.BIN` (group
   dates; its table at `0x8013A384` holds `GROUP_D` offsets at base
   `0x80197000`), `G_BIRTH`/`P_BIRTH`/`KARADATA.BIN` to `0x801B0000` and
   `TARA_OBJ` files, and never reads `DATE_FU.BIN`.
