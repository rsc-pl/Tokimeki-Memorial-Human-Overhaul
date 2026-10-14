> **Historical upstream research.** Paths in older examples referring to `tools/`, `tokipatch/` or PowerShell are from the original Windows-oriented layout. Source files now reside under `legacy_scripts/`; for supported Linux commands use [Native tooling](NATIVE_TOOLING.md) and see [Legacy migration](LEGACY_MIGRATION.md). Do not run archived `.ps1` examples as current project commands.

# Testing a patch in an emulator

A patch that builds cleanly can still break the game. The first build passed
every static check (strings matched, EDC/ECC valid, one sector changed) and
still hung, because of the file checksum. **Always boot the result.**

The tools in `tools/emu/` drive DuckStation on Windows without touching the
user's own install, settings, memory cards or focused window.

## One-time setup

```bash
python tools/emu/setup_duckstation.py --bios "D:\Emulation\PS1 BIOS"
```

This copies the installed DuckStation (default
`%LOCALAPPDATA%\Programs\DuckStation`, override with `--source`) to
`.emu/duckstation/` as a **portable** install (`portable.txt`), so all its data
stays in that folder. It seeds settings from the user's `settings.ini` and
then sets:
- keyboard controls: arrows, `C`=Circle (**confirm**), `X`=Cross (**back**),
  `Z`=Square, `S`=Triangle,
  `Enter`=Start, `Backspace`=Select
- GDB stub on port 2345
- no power-off confirmation, no save state on exit
- RetroAchievements **off**. The user's `[Cheevos]` section is not copied, so
  their login token never ends up in `.emu/`. With achievements on, a login
  prompt appears every boot, and hardcore mode disables save states.
- **Memory cards in `.emu/duckstation/memcards`.** Portable mode does *not*
  redirect absolute paths inherited from the user's settings. An early harness
  version kept the user's `[MemoryCards] Directory` (`G:\Emulation\PS1_MEM`),
  and a test run created an album + system file on the user's real
  Tokimeki card. After setup, check that the only absolute path left in
  `settings.ini` is the BIOS folder.

Hotkeys inherited from DuckStation defaults: `F10` screenshot, `F2` save
state, `F1` load state.

The current dev box only has a PAL BIOS (SCPH-1002) and the unpatched game
runs fine with it, so BIOS region isn't a factor in the bugs seen so far.

## Build, boot, look

```bash
python -m tokipatch "<game>.cue" -o .emu/build --force
```

```powershell
Start-Process .emu\duckstation\duckstation-qt-x64-ReleaseLTCG.exe -ArgumentList '-batch','-fastboot','".emu\build\<game>.cue"'
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\emu\drive.ps1 -Seq "wait:26000,Return,until:title:60000,shot:title,Down,wait:500,shot:options_highlighted"
```

Screenshots land in `.emu/shots/<name>.png`.

`drive.ps1` steps: `KEY[:holdms]`, `wait:ms`, `shot:name`, `until:screen:ms`.
Keys go to the emulator window with `PostMessage`, so the window doesn't need
focus and no other window ever receives input.

The driver also accepts a hidden game window and matches its title (including
the Japanese title's `forever with you` suffix). It stops if no matching window
exists. Screenshots must be newly created after F10; a timeout is an error,
not permission to reuse the previous file. These checks fixed a test run that
previously continued after null-window input errors and falsely reported a
screen match from a stale screenshot. Launch an isolated test with
`Start-Process -WindowStyle Hidden` and wait for the game window to exist.

### Getting to screens reliably
- **Don't rely on fixed delays.** Boot time varies between runs, so a sequence
  that hit the title once lands in the attract movie the next time.
- **Use `until:<screen>:<ms>`.** It screenshots in a loop until
  `tools/emu/screens.py` recognises the screen (currently `title`: mostly white
  plus the pink logo), then continues immediately. Add detectors to
  `screens.py` for other screens you need to reach.
- **Do the whole interaction in one `drive.ps1` call.** Each launch of
  `drive.ps1` costs ~3 s (PowerShell start + `Add-Type` compile). Detecting the
  title in one call and pressing keys in the next was slow enough for the
  title to time out (~10 s idle) back into the attract loop.
- **Timing reference (DuckStation, fast boot):** the opening movie is playing
  ~25 s after launch. `Start` skips to a white fade, then the title.
- **Always compare with the unpatched game** at the same point before blaming
  the patch.

### Save states
- **`F2` saves** to `savestates/SLPM-86053_1.sav`. **`F1` (hotkey load) doesn't
  work** through the driver (black screen, then the attract movie). Not
  investigated.
- **Loading at launch works:** pass `-statefile` on the command line.
  ```powershell
  Start-Process .emu\duckstation\duckstation-qt-x64-ReleaseLTCG.exe -ArgumentList '-batch','-statefile','"<abs path>\SLPM-86053_1.sav"','"<abs path>\game.cue"'
  ```
  Wait ~8 s before driving it.
- A state holds RAM, so files already loaded (e.g. the `NAME_ENT.EXN`
  overlay, the EXE's font) are whatever build made the state. To test new
  text without replaying, **poke it in** with `tools/emu/poke_file.py`:
  ```bash
  python tools/emu/poke_file.py .emu/b2/NAME_ENT.EXN 0x80132000 0x1B1D0 0x1BA04   # prologue strings + pointer table
  python tools/emu/poke_file.py .emu/b2/SLPM_86.053 0x80040800 0x3C3C 0x3F00    # renderer hook code + scratch
  python tools/emu/poke_file.py .emu/b2/SLPM_86.053 0x80040800 0xAF78 0xB32C    # hook's 5x12 font
  python tools/emu/poke_file.py .emu/b2/SLPM_86.053 0x80040800 0xEACC 0xEAD4    # jump into the hook
  ```
  A state made with a build that already has the renderer hook only needs
  the text poked; the hook code doesn't change with the translation. Poking
  the hook itself into a state from an older build is **untested** (the
  emulator's recompiler may keep stale code), so prefer a state from a hook
  build. If you do poke it, write the jump last, as above.
  (read the patched files out of a build with `Track.read_file`). Poking the
  *original* bytes instead gives an exact unpatched comparison at the same
  point; that's how the Rei hang was pinned on the translation.
  Always finish with one real boot of the build.
- The patcher can't overwrite a build the emulator has open. Build into a
  second folder (`-o .emu/build2`).

### New-game flow (album screen → name entry)
On a blank test card (`rm -rf .emu/duckstation/memcards/*` first):

```
Return,until:title:60000,C,wait:18000,            # GAME START → "no save data" prompt
C,wait:3000,                                       # Yes → "Which album?"
Down,wait:300,Left:1500,wait:300,Up:900,wait:300,  # steer the free hand cursor...
Down:290,wait:300,Right:80,wait:600,               # ...onto album slot 1
C,wait:2500,C,wait:2500,                           # pick slot 1, system-file explanation
C,wait:9000                                        # "Make a system file?" Yes → name entry
```
At normal emulator speed, the hand moved at roughly 0.8 screenshot px per ms
of key hold (≈ 4.8 per game px) in one calibration. On the initial family-name
screen, `Right:150` selected み and `Down:540` reached the Exit button; a
screenshot after the move and another after `C` confirmed that the next name
field opened. Treat these as starting values, not fixed coordinates.

Directional holds are timed in host wall-clock milliseconds, while cursor
movement advances in emulated frames. GDB read/watch/execution breakpoints
slow the emulator enough that the same hold covers fewer game frames and
therefore **undershoots**. Navigate and verify the cursor at normal speed
before arming a watchpoint whenever possible. If the watchpoint must already
be armed, recalibrate the hold under that exact tracing load; adding only a
longer `wait:` after the hold does not recover the missed movement.

With an album already on the test card, GAME START opens the album screen
in Load mode with the hand on slot 1. Pressing `C` twice loads it; an album
whose name was never finished goes straight back to name entry. From name
entry: `Down:180,Left:130,C` opens the 記号 page. Then `Right:1450,Right:110`
puts the hand on the ▼ scroll arrow; each `C` scrolls one row-block.

### Reaching the prologue (dialogue)
From name entry (hand on the かな page), type one kana in each name field and
accept the default birthdays. This worked from boot, as one `drive.ps1` call:

```
$name = "Up:540,wait:200,Right:230,wait:300,C,wait:600,Down:540,wait:200,Left:230,wait:300,C,wait:1500"
wait:22000,Return,until:title:60000,C,wait:16000,C,wait:2500,C,wait:9000,  # title → album 1 → name entry
Right:130,wait:300,C,wait:800,Down:540,wait:200,Left:230,wait:300,C,wait:1500,  # family name, 終了
$name,$name,wait:500,                                                       # given name, nickname
C,wait:1500,C,wait:1500,C,wait:3500,                                        # birthday/blood: 終了 ×3
Right:640,wait:300,C,wait:8000,                                             # "Is this OK?" → はい (save a state here: F2)
Left:700,wait:300,C,wait:1500,C,wait:1500,C,wait:3500,                      # Shiori's birthday: 終了 ×3
Right:670,wait:300,C,wait:12000                                             # はい → prologue starts
```
Then `C,wait:4500,shot:...` per line. Text types out letter by letter and
voiced lines also advance by themselves, so a shot can catch a line
half-typed or skip one; that's normal. To review many lines, crop the text
box (screenshot y 700–1000) from each shot into one contact sheet.

**Keep your hands off the emulator during a scripted run.** Input from the
user mid-run (they were also playing) made one comparison misleading.

### The main game loop (weekly command screen)
- **Making an in-game save:** saving is only possible on the **Sunday-night
  planning screen** ((明日から何をしようかな？) with the night view). The
  memory-card icon at the bottom right of the command grid is then lit
  instead of grey; select it → セーブ → slot → ○ to overwrite. (Told by the
  user; done once.) After that, a boot with that card goes title → GAME START
  → `C,wait:3000,C` straight to the main screen, about a minute.
- `.emu/memcard_backup/mainloop_*.mcd` is a card with such a save (album 1,
  95/4/23). Copy it over the card in `.emu/duckstation/memcards/` to use it;
  back up whatever is there first.
- From the planning screen, `C` on the first icon (study) runs a week and
  lands on the next Sunday, either the holiday screen (今日は…) or, after a
  day off, the planning screen again.
- **Check the loaded save's menu behavior before calibrating.** In the review
  run using the backed-up 95/4/23 card, `Down:300` advanced one item in list
  order (book → science → art → fitness → school icon), even across a row;
  `Up:300` reversed it. This is discrete selection, not free cursor movement.
  The exact saved Menu Mode value has not been traced. Don't interpret every
  sideways move as a timing error, or reuse name-entry free-hand timings here.
  Take screenshots after moves; short holds and behavior in other modes still
  need calibration.
- **Graphics live in VRAM from boot.** `MAINROM.NBN` is uploaded once at boot,
  so a save state shows the art of the build that made it. Test graphics
  changes with a real boot and the save card.

### Controls: ○ confirms, × goes back
This is a Japanese game: **○ (Circle, key `C`) confirms and × (Cross, key `X`)
cancels/goes back.** Use `C` to select menu items and advance text. Early test
runs pressed `X` to "confirm", which explains some of the confusing results
(e.g. landing back in the attract loop). Treat any old note that says `X`
selected something as unverified.

### What failure looks like
- **Hang on a white or black screen during a transition:** almost certainly a
  file checksum mismatch. The loader retries forever (game-internals §3/§4).
  Confirm with the GDB stub: loader state `*(u8*)0x800B6D34 == 1` and LBA at
  `0x800B6D40` stuck on the patched file.
- **Garbage or missing glyphs:** wrong encoding, or a character the font
  doesn't have.
- **A dialogue line that never advances** (text fully shown, ○ does nothing,
  no CD error): the scene is waiting for a display line that doesn't exist,
  because the translation has fewer lines than the Japanese (game-internals
  §6e). The patcher now rejects this. To diagnose another case, set GDB
  breakpoints on the scene's *run line* routine to see whether it's still
  called, and compare `0x8004ECF0`'s result with what the scene step waits
  for.

## Debugging with the GDB stub

`tools/emu/gdbstub.py` is a minimal client. **Connecting halts the emulator**;
call `detach()` to resume it.

```python
import sys; sys.path.insert(0, "tools/emu")
from gdbstub import Gdb
g = Gdb()
print(hex(g.regs()["pc"]))
print(g.mem(0x800B6D34, 1).hex())          # overlay loader state
open(".emu/ram.bin", "wb").write(g.mem(0x80000000, 0x200000))
g.detach()
```

Register replies contain `xxxxxxxx` for unavailable registers; they're read as 0.

### Which files does the game load?

```bash
python tools/emu/trace_reads.py "<game>.cue" 60
```

This breaks on the CD read routine `0x80046318` and prints LBA, sector count,
buffer and the matching disc file for each read. The game runs slower while
traced. Run it in the background and drive the game with `drive.ps1` at the
same time.

### Which code reads a string? (read watchpoints)

```bash
python tools/emu/watch_reads.py 0x8013C880 60 --skip 0x8004636C-0x800463E8
```

This arms a GDB read watchpoint (`Z3`) on an address and logs pc/ra/args for
each read while the game keeps running. Drive the game with `drive.ps1` in
parallel. Tips:
- **Arm it before the screen opens.** Menu text is laid out once when a screen
  opens, so a watchpoint set while the screen is already showing never fires.
  Go back to the previous screen, arm, then re-enter.
- RAM address of a string in an overlay = `0x80132000 + file offset`. In the
  EXE it's `0x80040800 + file offset`.
- `--skip` the checksum loop (`0x8004636C`–`0x800463E8`), which reads every
  byte of a freshly loaded overlay.
- This is how the text renderer was found: the first hit was `add_text`
  (`0x8004E788`), the second `layout_string` (`0x8004F268`).

### Does this code ever run? (execution breakpoints)

```bash
python tools/emu/watch_exec.py 900 0x8004443C 0x8004B778
```

This sets execution breakpoints and logs every hit (pc, ra, a0–a3) while
the game keeps running. `--stack N` also prints N stack words (arguments 5+),
`--max N` stops after N hits. `watch_exec.py 80 0x8004435c --stack 6 --max 120`
during a boot logs every VRAM upload (x, y, w, h, source address): that's how
`MAINROM.NBN`'s chunk layout was found. Drive the game in parallel. It's how the two EXE
functions the renderer hook reuses were shown to be unused (game-internals
§6f): run it on the **unpatched** game and play through as much as you can.
- The emulator runs noticeably slower while breakpoints are armed (a page
  fade took ~10 s instead of ~4 s), so give `drive.ps1` steps longer waits.
  Free-moving cursors also travel less during a fixed directional hold; see
  the calibration warning under "New-game flow" above.
- The Options page and the in-game command grid use the free-moving hand
  (Mouse-like menu mode), so a short `Down` doesn't step one item. `X` on the
  Options page jumps the hand to オプション終了; `C` there returns to the title.
- Pressing `C` repeatedly on the first in-game screen picks the first command
  (study) each week and advances the calendar. It reached a SERIFU event
  (meeting 如月) after ~30 presses, a handy way to exercise dialogue files.

### Which girl events happen? (event watcher)

```bash
python tools/emu/watch_events.py 420 --states > .emu/events.log
```

Breaks where the main loop starts a girl's scene from the daily event queue
and logs the date, record (type, girl, scene) and the queue (game-internals
§6j). `--states` also logs every main-loop state change. Drive the game in
parallel, e.g. `C,wait:2500` repeated to study through the weeks.

First run (2026-10-07, **unpatched** original, 95/4/23 test card, 45 presses
of `C`, about 2 minutes): reached 95/5/17. Two meeting events (type `0x48`,
girl 1 on 5/10 and girl 8 on 5/17), no Shiori special event. Replay
assets from that run:
- `.emu/savestates_backup/shiori_0423_unpatched.sav`: unpatched, 95/4/23
  Sunday night, hand on Study. Only for unpatched comparisons; it holds the
  original EXE and text.
- `.emu/memcard_backup/pre_shiori_<timestamp>_*.mcd`: the harness card from
  before this run (it had the user's 95/4/9 and 95/4/16 saves). The
  95/4/23 test card is installed in its place.

The unpatched original is in the repo folder
`Tokimeki Memorial - Forever with You (Japan) (PlayStation the Best)/`
(gitignored; checked byte-identical to `extracted/` for the EXE, GEKO.EXN and
EVENT_FU.BIN).

### Forcing a girl event (Shiori's morning walk)

Rare special events can be forced on a test card, with the user's agreement
(given 2026-10-07 for Shiori's walk). Do the same forcing on the unpatched
game for the comparison. Recipe, about one minute:

```powershell
Start-Process -WindowStyle Hidden .emu\duckstation\duckstation-qt-x64-ReleaseLTCG.exe -ArgumentList '-batch','-statefile','"<abs>\.emu\savestates_backup\shiori_0423_unpatched.sav"','"<abs>\<game>.cue"'
```

Wait ~9 s, then start the forcer and choose Study:

```bash
python tools/emu/force_event.py 0 2 --clear-flag 0x800E67ED --timeout 120
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\emu\drive.ps1 -Seq "C,wait:4000,shot:walk_01,wait:3000,shot:walk_02,wait:3000,shot:walk_03,C,wait:2500,shot:walk_04,wait:2500,shot:walk_05,C,wait:2500,shot:walk_06,C,wait:2500,shot:walk_07,C,wait:2500,shot:walk_08"
```

The forcer prints `forced 45 00 02 00 at 0x800e6924` (Tuesday 95/4/25). The
first line appears about 10 s after `C`; each later `C` advances one box
(4 boxes, game-internals §6j), and the week then continues to the weekend
command screen. Done twice on the unpatched game, once with
`trace_reads.py` chained after the forcer (`EVENT_FU.BIN` → `0x80198000`).

**English test (2026-10-07).** Candidate `.emu/review_shiori/` (15 default
files plus the draft; log `.emu/review_shiori.log`): only LBAs 44581 and
44586 (EVENT_FU's first and last sectors) differ from the default build,
with valid EDC/ECC and headers; the file keeps its size and checksum; all
five pointers resolve to their English. Real boot, card save loaded, walk
forced on 95/4/25, every box screenshotted (`.emu/shots/q_*.png`) and
compared with the unpatched run (`f_*.png`). The first attempt showed the
thought lines' `)` doubled, because these strings don't contain `）`; fixed,
rebuilt, retested: all four boxes correct, Shiori's label and her 3-line box
fit, and the game returns to the day command screen as in the unpatched run.
After promotion, the normal build (no `-t`, `.emu/default_shiori/`) is
byte-identical to the tested candidate. Not tested: the natural trigger
(needs mid-game affection), other names in `{P}`.

**Rain and phone call (2026-10-07).** Same recipe with `force_event.py 0 1
--clear-flag 0x800E67EC` (rain) and `force_event.py 0 8` (phone call; no
flag needed). Forcers can be chained in one week:
`force 0 1 && force 0 8 && force 0 2 --clear-flag 0x800E67ED` puts the three
scenes on Tuesday, Wednesday and Thursday. Unpatched references:
`.emu/shots/r_*.png` (rain), `h_*.png` (phone). Candidate
`.emu/review_shiori2/` (15 defaults minus the promoted `shiori_events.json`,
plus the revised draft): only EVENT_FU's sectors 44581, 44585, 44586 differ
from the default build, EDC/ECC and headers valid, checksum valid, all 68
strings' pointers resolve, and no byte outside the string slots and their
pointers changed. First on-screen pass showed "happy. )": two thought lines
ended in an odd-length run, padded with a space before the game's bracket;
fixed to even lengths, rebuilt, retested. Every box of the three scenes was
then seen (`ex_*`, plus `fz_*`/`fw_*` for two boxes whose screenshots had
caught them mid-typing). Screenshots need at least ~1.5 s between them;
0.7 s makes `drive.ps1` fail. Promoted; the normal build
`.emu/default_shiori2/` is byte-identical to the candidate.

### Forcing a date with Shiori, and her date events

On the Sunday-night screen of the 95/4/23 test save (state or card save):

```bash
python tools/emu/force_date.py 0 PLACE 4 30 [--scene N] --timeout 400
```

then drive `C,wait:12000,C,wait:12000,C,wait:7000` (Study for the week,
Study on the 4/29 holiday, then the heart icon on 4/30 starts the date) and
step through with `C,wait:2800`. Places are 1-based outing ids (1 Kirameki
Park, 12 Theme Park, 16 Pool), 0 is the neighborhood park. `--scene` jumps to
Shiori's date event when the date reaches its step: 3 (place 0), 4 (place 1;
also happens by itself), 5 (place 12), 6 (place 16). One date per boot; the
event appears about 15–20 presses in, and the date ends back home.

### Forcing the walk home after the Christmas party

```bash
python tools/emu/force_christmas.py --timeout 400
```

Start it on Sunday night and choose Study; at the next weekday it switches to
the Christmas-party flow at Shiori's stage. It can follow a
`force_event.py` chain (it waits for the next weekday). Leftover weekday
graphics show behind the scene.

**All of EVENT_FU (2026-10-07).** Unpatched references: `d3_*`, `dg_*`
(park), `tp_*` (theme park), `d6_*` (pool), `ny_*` (Christmas). Candidate
`.emu/review_shiori3/`: only EVENT_FU's six sectors differ from the default
build, EDC/ECC and headers valid, checksum valid, all 157 strings' pointers
resolve, nothing else in the file changed. Real boots of the candidate:
boot 1 chained rain (4/25), phone (4/26), walk (4/27) and Christmas (4/28),
`p1_*`; boots 2–5 one date event each, `p3_* p4_* p5_* p6_*`. Every box was
English and fit; first lines of 4-/5-line strings scroll away before a
screenshot. Promoted; the normal build `.emu/default_shiori3/` is
byte-identical to the candidate.

Card note: the harness card's frame 63 of block 0 (`0x1F80`, the memory
card write-test frame) changes during these runs; no save data changes.

**For a patched build** the save state can't be used: it holds the original
EXE and text. Boot the patched CUE, load the 95/4/23 card save
(title → GAME START → `C,wait:3000,C`), then run the forcer and the same
drive sequence. The forcer only writes RAM; nothing is saved unless you save
in the game, and a forced run must not be saved over the test card.

### Testing date conversations (`DATE_FU.BIN`, 2026-10-07)

**A save state reopens the disc it was made with**, whatever CUE is passed
on the command line. A state made from `.emu/review_dates/` always reads
`.emu/review_dates/`, so rebuild candidates **into that same folder** (with
the emulator closed) and keep reusing the state. Building to a second folder
and passing its CUE silently tests the old text. The EXE in the state must
come from a build with the renderer hook; DATE files are read from disc when
the date starts, so they always come from the state's disc.

Recipe used for the museum pilot:
1. Boot the candidate from `.emu/review_dates/`, load the 95/4/23 card save
   (`wait:22000,Return,until:title:60000,C,wait:16000,C,wait:3000,C,wait:20000`),
   then `F2` on the Sunday screen. Backed up as
   `.emu/savestates_backup/dates_sunday_0423_candidate.sav`.
2. Per run: launch that state (`-batch -statefile`), wait ~9 s, start
   `python tools/emu/force_date.py 0 7 4 30 --set-at 0x80134F74 0x800CA2FC N`
   (museum, exhibition N = 0–5; game-internals §6k), then drive
   `C,wait:12000,C,wait:12000,C,wait:7000` and `C,wait:3200` per box. The
   meeting before the place is random (4–8 boxes), so screenshot each box.
3. On the choice screen press `F2` and copy the state; relaunch it and press
   `C`, `Down,C` or `Down,Down,C` to see each reply. The options' screen
   order is shuffled per date but fixed in the state; the reply follows the
   option, not its position.
4. Variant 5's other lines: raising Shiori's affection in RAM (s16 at
   `0x800E6442`, 48 → 200) on the Sunday state gave `0x688`; `0x660` was
   shown by writing master entry 16's value over entry 18
   (`0x80198718` ← `*(u32*)0x80198710`) once DATE_FU was loaded.

`watch_reads.py` on DATE_FU's master entries is swamped by an unrelated
reader (`pc 0x80082B3C`) before the file loads; prefer static tracing.

**Tools (2026-10-07).** All run from the repo root with `powershell.exe`
(5.1) and the isolated emulator; they change RAM only.
- `tools/emu/launch_state.ps1 -State X.sav [-Build review_dates|orig]`:
  restart the emulator (visible) from a state. It stops only the isolated
  `.emu\duckstation` instance, never another DuckStation.
- `tools/emu/date_run.ps1 -Place P [-Version N] [-Girl G] [-Presses K]
  [-Prefix name] [-Break "rules"]`: launch the Sunday state, force a 4/30
  date with girl G (default 0, Shiori) at place P
  (and version N), drive into it and screenshot K boxes; contact sheet in
  `.emu/shots/<prefix>_sheet.png`, forcer log in `.emu/date_run.log` (the
  forcer runs detached so late rules still fire).
- `tools/emu/date_choices.ps1 -Prefix name [-Pre keys]`: from just before a
  choice, save a state there and try every option (sheet
  `<prefix>_choices.png`, state `.emu/savestates_backup/<prefix>_choice.sav`).
- `tools/emu/break_set.py --at PC [--times N] [--reg R=V] [--mem8 A=V]
  [--mem16 A=V] [--sp16 OFF=V] [--pc NEWPC] ...`: breakpoint rules, also
  accepted by `force_date.py` after `--`. Rules used (game-internals §6k):
  meeting `--at 0x80132570 --reg v0=RANK --mem8 0x8015B654=ARRIVAL`
  (RANK 0/2/3 → mood 0/1/2), run-away meeting `--at 0x80132570 --mem16
  0x800E6396=10`, small talk `--at 0x8013B0D4 --mem16 0x8015BF0C=N --pc
  0x8013B0E4`, ending `--at 0x8013B6F8 --times 0 --sp16 0x3a=N` (the value
  is recomputed every frame, so rewrite it at every hit), going home
  `--at 0x8013B810 --mem16 0x8015BF14=BAND`, park (place 0) talk
  `--at 0x8013A8B0 --reg v0=RANK`, museum "seen before" line
  `--at 0x801392F0 --reg v0=RANK` (with `--version 5`).
- `tools/emu/contact_sheet.py OUT NAME...`: stack screenshots' text boxes.
- `tools/date_sections.py`: the section/place checklist and forcing
  addresses; `tools/dialogue_budget.py FILE.json [--all] [--range A B]`:
  per-string space (own slot, gap, English) and a dry-run pack.

Example, every shared selector in one unpatched-section date (checked on
screen: meeting part 4–5, small talk part 0, ending part 9, going home
band 1):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\emu\date_run.ps1 -Place 7 -Version 0 -Presses 20 -Prefix sh2 -Break "--at 0x80132570 --reg v0=3 --mem8 0x8015B654=0 --at 0x8013B0D4 --mem16 0x8015BF0C=0 --pc 0x8013B0E4 --at 0x8013B6F8 --times 0 --sp16 0x3a=9 --at 0x8013B810 --mem16 0x8015BF14=1"
```

`--version` was also checked on Kirameki Park (version 2: the cherry-blossom
lines; afterwards Shiori's spring park event from EVENT_FU starts by itself
on 4/30) and the Stadium (version 3: wrestling). Also seen: a place-0
(neighborhood park) date with its hobby choice and note, the Shrine's yukata
choice with both options (the `{n}` empty option), and museum version 5
with `v0 = 0` at `0x801392F0` (line `0x660`). A forcer left waiting on a
rule keeps the GDB connection; `launch_state.ps1` restarting the emulator
ends it.

**Museum pilot results.** Unpatched reference `mu_*` (exhibition 0, the top
option chosen). Candidate `.emu/review_dates/` (16 default files plus the
draft): only DATE_FU's first and last sectors (LBA 44329, 44351) differ from
the default build; checksum and EDC/ECC valid; 30/30 pointers resolve; file
bytes change only in `0x0`–`0x6CD` and the trailer. On screen (`m0_*`–`m5_*`,
`v1_*`, `h5_*`, `p5_*`): all five exhibitions' going-in, remark, choice list
and all three replies each, English, within the box; variant 5's three
lines (two of them caught while typing); dates end normally and the week
continues. Fixed on the way: odd-length options showed a space before `』`.
Not tested: the natural trigger of each exhibition (by year/month and
whether it was seen) and variant 5's natural selection by standing. After
promotion the normal build `.emu/default_dates/` is byte-identical to the
candidate.

**Batch 1 (shared sections 22, 23, 24, 26).** Candidate in
`.emu/review_dates/` (all default files plus the draft): only six DATE_FU
sectors in LBA 44329–44351 differ from the default build. Three forced
museum dates with `-Break` rules (sheets `b1a`, `b1b`, `b1c`): meeting
arrival 0 / mood 2 (parts 4–5), arrival 2 / mood 0 (part 9 with its
thought), the run-away (parts 12–13, the date ends and the week goes on);
small talk parts 0 and 4; ending parts 15 (anthology thanks, last line
caught while typing) and 9 (the `‥‥‥‥。` line with an English thought on
its second line); going home bands 0 (`{P}` inserted) and 3. All English,
within the box, no stalls, the week continues. The other parts were checked
only statically (structure, width, packing). After promotion the normal
build is byte-identical to the candidate.

**Batch 2 (section 7, neighborhood park; section 25, hobby notes).** Only
DATE_FU sectors differ from the default build. One forced place-0 date
(`date_run.ps1 -Place 0` with `--at 0x80132570 --reg v0=0 --mem8
0x8015B654=1` for a fixed 3-box meeting and `--at 0x8013A8B0 --reg v0=3`
for park part 4), then `date_choices.ps1 -Options 2` (sheets `b2a`, `b2`,
`b2_nar`, `b2e`): meeting part 6, her part-4 remark, the narration, the
action choice, both options each followed by the centered pause and a note
(part 0 "listening to music", part 1 "watching sports"), ending part 6 and
going home band 1–2; the week continues. Parts 0 and 2 and the other notes
were checked only statically. Normal build byte-identical to the candidate.

**Batch 3 (section 21, Kirameki Park; section 14, Shopping).** Only DATE_FU
sectors differ. In April a Kirameki Park date plays Shiori's spring park
event (EVENT_FU scene 4) right after the walk starts, in place of the
version's remark and choice; setting its one-shot flag in the meeting rule
(`--mem8 0x800E67EF=1`) skips it. Seen (sheets `b3k`, `b3kc`, `b3s`): the
pond version (`-Version 1`) going in, remark, all three options and
replies; a Shopping date choosing clothes, then "can I go look?", the
pause, the waiting choice (three options listed, one taken) and its reply,
ending and going home. Not seen: Kirameki Park versions 0 and 2 on this
build, Shopping's other first choices and its carrying, cute-item, necklace
and junk-shop branches (static checks only). Normal build byte-identical to
the candidate.

**Batch 4 (sections 1, 6, 10, 12, 13, 15, 16, 19: the two-version
places).** Only DATE_FU sectors differ. With the on-time meeting rule:
Bowling version 0 and Beach version 1 driven through to the end (one option
each; sheets `b4bo`, `b4be`), and Karaoke version 1 with all three
requests and replies (`b4kc`). Pool, Botanical Garden, Skating Rink, Ski
Resort and Library, and the other version of each place, were checked only
statically. Normal build byte-identical to the candidate.

**Batch 5 (sections 3 Zoo, 18 Aquarium, 11 Planetarium, 5 Arcade, 17
Stadium).** Only DATE_FU sectors differ. Forced with the on-time meeting
rule and driven through one option each: Zoo version 2 (koala), Aquarium
1 (sharks), Planetarium 1 (which picked the Cygnus choice, part 12),
Stadium 3 (wrestling), Arcade versions 0 and 1 (sheets `b5zs`, `b5ap`,
`b5arc`, `b5ar1`). On the Arcade, `date_choices.ps1` was started too early
(on the remark), so its two runs saw the version-0 choice list in two
shuffles and two different replies. The Arcade's version picks the part
directly (version 0 → part 2, 1 → part 4); the video/medal action choice
(part 1) did not come up in either and is checked only statically, like
the other versions of every place in this batch. Normal build
byte-identical to the candidate.

**Batch 6 (sections 2 Concert Hall, 8 Cinema, 4 Shrine).** Only DATE_FU
sectors differ. Forced with the on-time meeting rule (sheets `b6cc`,
`b6coe`, `b6shc`): the Cinema up to its `07` announcement (full-width 「
and indent kept, renders in place); the Concert Hall's seat exchange,
choice and the part-3 reply, then the ending; the Shrine's remark and
yukata action choice with both options (praise → compliment and thanks;
say nothing → both skipped, straight to the goldfish offer). The goldfish
minigame then needs real input (its instruction banner is a graphic) and
was not played, so the reactions after the minigames (parts 7–11), the
shooting gallery and the fireworks choice, and the Cinema's choice and
replies, were checked only statically. The film and concert description
thoughts shown in these dates come from another file and are still
Japanese. Normal build byte-identical to the candidate.

**Batch 7 (section 20 Theme Park, section 9 parade).** Only DATE_FU sectors
differ. A forced Theme Park date (on-time meeting rule) went to "where to
next?", the Ghost House and the ending (sheets `b7a`); then a state saved
on that choice (`.emu/savestates_backup/b7w_choice.sav`) was replayed for
each ride (`b7w`): Ferris wheel, Ghost House and roller coaster, each with
its going-in line, remark, choice list and the reply to the first-listed
option. The hero show (parts 1–8), the later ride rounds (parts 25–56),
the Virtual Ship and the parade did not come up and were checked only
statically. Careful: pressing on past the end of a date runs the next
week's commands (here a library event) in RAM; nothing was saved. The
normal build (all of DATE_FU) is byte-identical to the candidate.

### SERIFU.BIN, the shared date lines (2026-10-08)

Candidate `.emu/review_dates/` (all default files plus the draft): only
SERIFU.BIN (LBA 44870–44871) and DATE.EXN's place-name sector and trailer
(LBA 37501, 37513) differed from the default build. Forced dates from the
Sunday state (sheets `s1p`, `s1m0`, `s1m1`, `s2`, `s3st`, `s3w`, `s3x`):
- **Impressions.** A Pool version-1 date replayed for all three options
  (state `.emu/savestates_backup/s1p_choice.sav`): levels 2, 3 and 4 after
  the replies, and after the boast ("Swimming's my specialty.") the swim lie
  line, then level 3. Levels 0 and 1 forced on museum dates with
  `--at 0x8013B174 --mem16 0x800CA22C=N --mem16 0x800CA22E=N --mem16
  0x800CA230=N`. Use a single hit: with `--times 0` the forcer stops the
  game every frame and the screenshots missed the thought. Levels 3 and 4
  showed a space before `)` (odd last line); fixed, but the new wording
  wasn't re-shot.
- **Blurbs.** `--at 0x8013BAD4 --mem8 0x8015B688=N` on Concert Hall dates
  (N = 11, the 5-line Rinsu blurb, scrolls; N = 0) and `--at 0x8013B964
  --mem8 0x8015B684=N` on Cinema dates (N = 3, 6): the forced blurb shows.
- **Missed meeting.** Stood up: `--at 0x8013F008 --reg v0=4`. Wrong place:
  `--at 0x8013F03C --mem8 0x800E69A4=4 --mem8 0x800E69A5=1 --mem8
  0x800E69A6=12 --mem8 0x800E69A7=4` (three options: here, the theme park,
  Kirameki Park, which is the agreed place) and `69A4=1 69A5=4 69A6=12
  69A7=255` (two options). Every option replayed from a state on the
  choice: waiting or a wrong place lead to "never showed up" and the
  answering-machine message (TEL.EXN, Japanese); the agreed place leads to
  the late arrival, and the date continues at Kirameki Park.
- Odd-length names ("Kirameki Park") show a padding space before the
  option's `』`, as expected.

Not seen: the other ten concert and nine movie blurbs, the skate lie line,
the other place names, natural triggers, other girls' dates.

The same odd-ending space also affected nine DATE_FU notes and thoughts
(hobby notes, the parade and hero-show thoughts); their endings were made
even in `shiori_dates.json`. That repacks the whole of DATE_FU, so a park
date was replayed on the new build (both action options and notes, one of
them an edited note, the ending, the week continuing). EVENT_FU's 157
strings were checked statically: all its `04`/`06` thoughts already end
evenly. The normal build is byte-identical to the candidate.

### Phone calls (TEL.EXN, 2026-10-08)

No forcer needed: the phone works from any holiday screen. State
`.emu/savestates_backup/phone_sat0429.sav` (Saturday 95/4/29, made from
`.emu/review_dates/` by pressing `C` on the Sunday state, so a week of
study runs) has the cursor on the first command icon. From it:
- phone book: `Down` ×8 (one icon per press, waits of ~900 ms; faster
  presses get dropped), `C`. In the book `Down` goes Yoshio → Shiori; from
  Yoshio, `Down`,`Down` reaches Rei Ijuin.
- **Shiori**: `Down`, `C`, then `C` through her greeting, the day picker
  (the first offered day, 4/30), the place book (`Down`, `C`: Theme Park),
  the invitation, her yes, the confirmation, "Click.", the thoughts.
- **Yoshio**: `C` through the greeting to the two-item menu (`Down` is
  "date spots", the cursor starts there), then the girl list (the cursor
  starts on an empty row; `Up` reaches Shiori) and her info card.
- **Ijuin**: the full call, then back to the holiday screen.
- **Missed date**: the SERIFU wrong-place state
  `.emu/savestates_backup/s3w_choice.sav`, `C` and on: waiting, going home,
  the answering-machine message and the thoughts.

Results (candidate in `.emu/review_dates/`; only TEL.EXN's text sectors and
trailer and one EXE sector, the full-name table, changed): all of the above
in English and within the boxes, including the composed lines (the
greeting "Hi, it's / ま.", the invitation "4／30, would / Theme Park / work
for you?", the date confirmation). On the info card "BWH." and "Notes"
overlapped the game's colon (compared with the unpatched card from
`shiori_0423_unpatched.sav` on the same path); shortened to "B W H" and
"Memo" and re-checked. A fresh boot of the candidate (load the card save,
a week of study, phone book) shows "S. Fujisaki"; the save states still
show 藤崎詩織 because they keep the old EXE in RAM. The normal build is
byte-identical to the candidate.

Not seen: other girls' calls (only Shiori is in this save's book), a
declined date, cold or stood-up calls, Yoshio's warnings and Yumi
answering, Miharu's wrong numbers, the anthology thanks, Tome, the club
captain, the girl-ratings screen.

### Walking home (GEKO.BIN, 2026-10-08)

`tools/emu/force_walk.py GIRL [--rank R] [--topic P]` (game-internals §6n)
marks the girl as met, turns Monday's day record into a walk-home record
`44 GIRL 00 00`, and with `--rank` makes every rank call in the walk return
R (0/1 she waited for you, 2 you call out and she agrees, 3 she has plans,
4 she runs off); `--topic P` makes the walk end with the talk on the way,
part P (23-38). `tools/emu/walk_run.ps1 -Girl G [-Rank R] [-Topic P]
[-Presses K]` launches the Sunday state, runs it detached (log
`.emu/walk_run.log`), picks the first weekly command and screenshots K
boxes (`C` also takes the first option of each choice). The walk plays
on Monday 4/25, straight after the week starts.

Results on the candidate in `.emu/review_dates/` (only GEKO.BIN's sectors,
LBA 44744-44779, changed): Shiori rank 0 (she waits and asks, the choice,
accepting, "Shiori and I had a nice walk home") and with topic 23 (exams:
"And then...", her question, his answers, the closing thought); Yuko rank 2
(he calls out, the shared `0C`/`0D` box "Oh, {P}. / Heading home?", the
choice, "grab a drink", topic 34: the four-line winter-plans string
scrolls); Mira rank 3 (plans with another boy); Megumi rank 4 (she runs
off); Mira rank 2 (her line-break choice shows as two options). Before the translation, an unpatched-text run of Shiori (`gw`) showed
the same flow in Japanese (she declined). The section-10 thought
"Phew, what a long day" opens every walk.

Not seen: the other girls' sections (Mio, Yuina, Ayako, Saki, Yukari,
Nozomi, Yumi), the declined-invitation paths and regret thoughts, the
other topics, Saki's and Mira's extra parts, natural triggers.

### A girl asks the player out (G_INVITE.BIN, 2026-10-08)

`force_event.py GIRL 0 --type 0x46` on the Sunday state, then pick a
weekly command: on Monday 4/25 the girl asks about Sunday. Boxes: greeting
(two boxes), "are you free?", the choice (`Down` for "busy"), her
invitation for a place, the yes/no choice, her reply, "Meet at {M}?", her
goodbye, the player's thought. Give each press ~3.5 s and screenshot
before pressing `Down`; early presses get eaten.

Results on the candidate (only G_INVITE.BIN's sectors and GEKO.EXN's
place-name sector and trailer changed): Shiori accepted (zoo invitation,
"Meet at {M}", the thought) and refused (her "it can't be helped" and the
player's "Was I a little too cold...?"); Yuko accepted (arcade, "Meet at
the arcade," with the English place name), after which the Sunday date
with her starts (her date file is still Japanese). Not seen: the other
nine girls, the other places and meeting-place names, natural triggers.

### Yuko's dates (DATE_AS.BIN, 2026-10-08)

`date_run.ps1 -Girl 8` forces a Yuko date (the forcer's first argument).
Checked first: the date's girl byte `0x800E69DD` reads 8 during and after
the date, the label says Yuko, and the lines come from `DATE_AS.BIN` (her
Library lines exist only there). Same rules as Shiori's; the on-time
meeting rule `--at 0x80132570 --reg v0=0 --mem8 0x8015B654=1` gives a fixed
3-box meeting, then 7 presses reach most places' first choice.
`date_choices.ps1` now waits 2 s after relaunching its state: right after a
state loads, early presses were dropped (a Bowling run "chose" nothing).

- **Library version 1, unpatched first** (`yl1`): going in, "図書館はもういいよ"
  (she gives up), then an empty choice box (the part read past her list,
  game-internals §6k), the bad-impression thought, the ending. The English
  build (`y4l`) does exactly the same.
- **Her Arcade event.** A forced 4/30 Arcade date played EVENT_AS's crane
  game scene instead of the section-5 part (spring, game-internals §6k);
  `--mem8 0x800E6823=1` in the meeting rule suppresses it.
- Candidate in `.emu/review_dates/` (all default files plus the draft):
  only DATE_AS's sectors (LBA 44309–44328) differed from a default build,
  checksum valid, after every batch.
- Batch 1 (sheets `y1a`, `y1b`, `y1c`, `y2e`): meeting arrival 0 / mood 2
  (parts 4–5), arrival 2 / mood 0 (part 9, the "(Truth is...)" thought),
  arrival 0 / mood 0 (part 1 with her late-arrival thought); small talk 0,
  1, 4; ending parts 12 (poetry book) and 3, plus the player's replies;
  going home bands 0 (`{P}` shows as the name + 君), 1–2 and 3. In runs
  forcing a poor ending her line passed during a screen fade; a slower
  replay (`y2e`) caught part 3.
- Batch 2 (`y2m`, `y2p`): museum exhibition 0 with every option; a park-0
  date (`--at 0x8013A8B0 --reg v0=3`) with both actions, the pause and two
  notes.
- Batch 3 (`y3k`, `y3s`, `y3a`): Kirameki Park version 2 (cherry blossoms;
  no spring event for Yuko) with every option; Shopping's first choice with
  every option, then the accessories list and one reply.
- Batch 4 (`y4l`, `y4b`, `y4e`): Library version 1; Bowling version 0 and
  Beach version 1 with every option (the kept "‥‥‥‥‥。" option shows as
  is).
- Batch 5 (`y5s`, `y5z`, `y5a`, `y5p`, `y5q`): Stadium version 1 (the
  "(Explain it to her.)" option) and Arcade version 1 with every option, the
  Zoo with two of three, Planetarium and Aquarium driven through.
- Batch 6 (`y6c`, `y6s`, `y6m`): Concert Hall and Cinema choices with every
  reply; the Shrine up to the goldfish minigame (needs real input).
- Batch 7 (`y7a`, `y7w`): the Theme Park's ride choice, then each ride from
  a state on it (`.emu/savestates_backup/y7w_choice.sav`): going in, the
  remark, the choice and a reply.

Every forced date ended normally. Not seen: other versions and moods, the
Shrine after the minigames, the hero show, later ride rounds, the parade,
the Arcade's medal branch, natural triggers. After promotion the normal
build (`.emu/default_yuko/`, 22 files, no `-t`) is byte-identical to the
candidate.

### Running the emulator hidden

When the user is working on the same desktop, start the isolated emulator
with a hidden window so their input can't reach it:
`launch_state.ps1 -Hidden`, `meet_run.ps1 -Hidden`, or set
`$env:TOKI_EMU_HIDDEN = "1"` for scripts that call `launch_state.ps1`
(`date_run.ps1`, `walk_run.ps1`, `date_choices.ps1`). `drive.ps1` posts
keys to the hidden window and F10 screenshots still work; every G_APPEAR
test below ran this way. The default stays visible.

### First meetings (G_APPEAR.BIN, 2026-10-08)

`tools/emu/meet_run.ps1 -Girl G [-Scene V] [-Presses K] [-Hidden]`
launches the Sunday state, writes a type-`0x48` record `48 G V 00` for the
next weekday (`force_event.py G V --type 0x48`, log `.emu/meet_run.log`),
picks the first weekly command and screenshots K boxes. The meeting plays
on Tuesday 4/25 straight after the week starts. V is the girl's variant
(game-internals §6p). The location banner shows only in the first ~3 s of
the scene: to see it, screenshot every 0.6 s right after `C` (`bn_*`).

Unpatched-text runs first (`gy0`: Yuko variant 0 with the 女生徒 label;
`gm10`: Yumi with the ？？？ labels and `{P}` = まさん; `gb_*`: the 学校前
banner). Candidate in `.emu/review_dates/` (all default files plus the
draft): only G_APPEAR (LBA 44797–44812) and SHOUGATU.EXN's banner sector
and trailer (LBA 39084, 39085, 39145) differ from the default build, both
checksums valid. The default build itself was unchanged by the new
speaker-label code in `script.py`.

Seen in English (sheets `e8a`, `e8d`, `e2c`, `e3a`, `e7a`, `e1d`, `e5a`,
`e6a`, `e4a`, `e10`, `bn_sheet`): Yuko's first collision ("Girl" label) and
her whole introduction by Yoshio (girl 8, variants 0 and 3); Yuina's lab
scene (girl 2 variant 2, Computer Club branch); Ayako painting outside
(girl 3 variant 0, parts 6–7); Mira (girl 7); Mio's drama-club scene with
the "Capt" labels (girl 1 variant 4); Yukari's tennis ball (girl 5); Nozomi's
morning run (girl 6); Saki's baseball recruiting (girl 4); Yumi's whole
scene with the "???" labels (girl 10); banners Hall, Local Park, Drama.
Lines of 27–28 letters on the box's lower lines touched the page icon and
were shortened. "(It's Mio )" shows the odd-length name's pair padding.
Not seen: the other variants (Yuko's 2nd/3rd collision, Yuina's other
scenes, Ayako's band and art-club scenes, Mio's library/book/literature
scenes, Yukari's doubles, Nozomi's swim-team scenes, Saki's soccer and
manager scenes), the other banners, natural triggers. Normal build
(`.emu/default_meet/`, 23 files) byte-identical to the candidate.

### Club welcome (NYUBU.BIN, 2026-10-08)

`meet_run.ps1 -Girl G -Welcome [-Club C] [-Part N] -Hidden` runs
`tools/emu/force_club_welcome.py`: at the next weekday's day record it
sets the scene's girl (`0x800E69DD`) and makes the day handler enter main
state `0x60` (KANGEI.EXN's club-welcome entry), optionally setting the
player's club and the part (game-internals §6q). The scene plays on Monday
4/25 right after the week starts. A first attempt with a forced day
record type `0x42` reached the training camp instead (same overlay,
other entry), and type `0x20` the sports day.

**Give Shiori a club.** On the 95/4/23 save the player has none (11);
Shiori's background is looked up by club, and her scene sat on an empty
box forever. The same happened with the untranslated NYUBU (an unpatched
build swapped into `.emu/review_dates/`), so it's the forcing, not the
patch; with `-Club 6` / `7` / `0` it plays.

Candidate in `.emu/review_dates/`: only NYUBU's three sectors (LBA
44860–44862) differ from the default build; checksum valid. Seen in
English (sheets `w*`, `x*`): Shiori's baseball (club 6, part 2), soccer
(club 7, part 5) and general (part 0) welcomes; Yuina; Ayako's Art Club
and Band; Mio; Yukari; Nozomi; Saki's soccer part; section 7 (girl 10,
label Yumi). The player's "{G}," lines showed a space before the comma
for Mio, Yuina and Ayako; reworded to end on the name ("Hi, {G}" /
"Oh, {G}") and re-checked. Not seen: the other parts, the natural trigger.
Normal build (`.emu/default_nyubu/`, 24 files) byte-identical to the
candidate.

### Yuko's special events (EVENT_AS.BIN, 2026-10-08)

All six scenes, emulator hidden (`$env:TOKI_EMU_HIDDEN = "1"` for
`date_run.ps1`), from the Sunday state:
- **Staff room:** `meet_run.ps1 -Girl 8 -Scene 1 -Type 0x45` (a `45 08 01
  00` record; plays on Monday 4/25). Sheets `ev0`, `ev0b`: the "Tchr" label,
  the centered pause, and the whole talk.
- **Crane game:** `date_run.ps1 -Girl 8 -Place 9` with no flag rule; the
  event plays by itself on the 4/30 date (`ev1`).
- **Concert, skating, library:** `date_run.ps1 -Girl 8 -Place 15/19/8
  -Extra "--scene 4/5/6"` (`ev3`, `ev4`, `ev5`; `force_date.py --scene` now
  takes Yuko's scenes 2–6; don't add `-Break` rules, which make
  `force_date.py` skip `--scene`). Each forcer stopped at its step (1/0x11, 1/8,
  1/0) and the date ended normally.
- **Parade:** `-Place 12 -Extra "--scene 3"` didn't fire: the date took
  the Ferris wheel and ended at step 1/0x38, before 0x3C. With
  `--scene 3 --any-step` it played at the date's first step (`ev2b`) and
  the date ended normally.

Candidate in `.emu/review_dates/`: only EVENT_AS's 4 sectors (LBA
44577–44580) differ from the default build; checksum valid. The first
draft didn't pack (2,827 of 2,704 bytes): sixteen lines were shortened,
with `dialogue_budget.py`'s per-string overrun list as the guide. Normal
build (`.emu/default_evas/`, 25 files) byte-identical to the candidate.
Not tested: natural triggers, the parade at its own step.

### The player's birthday (P_BIRTH.BIN, 2026-10-08)

`meet_run.ps1 -Girl G -Birthday -Hidden` (or `-Girl -1` for nobody) runs
`tools/emu/force_birthday.py`: it sets the player's birthday to 4/25 on
the Sunday state, so the scene plays by itself on Monday after the first
weekly command (game-internals §6r), and with a girl it sets her as the
one bringing a present. First attempts broke at KANGEI's selector and
watched `0x800B6D40` for KANGEI's LBA; neither worked, because the scene
ran in GEKO and that address holds the last CD read's LBA. The forcer now
polls for GEKO's or KANGEI's code at the selector.

Untranslated reference: nobody (`pb1`), Shiori (`pbs`). Candidate in
`.emu/review_dates/`: only P_BIRTH's 3 sectors (LBA 44867–44869) differ
from the default build; checksum valid. Seen in English (sheets `pbx_*`,
`pbA`–`pbD`): nobody, and every girl's present (girls 0–10; Yumi's via the
default section). "Yuina , for me?" and "(Yuina  gave me" showed the
odd-length name's padding; both reworded to end the line on the name and
re-checked (`pbz`). Not seen: section 2 (KANGEI's flow). Normal build
(`.emu/default_pbirth/`, 26 files) byte-identical to the candidate.

### The girls' birthdays (G_BIRTH.BIN, 2026-10-08)

`meet_run.ps1 -Girl G -GirlBirthday [-Date M/D] -Hidden` runs
`force_birthday.py --her 0 [--as G]`: Shiori's birthday (u32 at
`0x800E644C`) is set to 4/25, so her birthday scene plays on Monday by
itself; for another girl, the scene's girl byte is switched to G at GEKO's
G_BIRTH section switch (game-internals §6s). That plays G's section (her
gift list, lines and reactions), but the speaker label and `{G}` keep
Shiori's name, set before the switch. Setting an unmet girl's birthday and
met bit instead (first attempt, `gbg_*`) played her first-meeting scene,
not a birthday. `C` takes the first option of each choice; `-Date 4/29`
puts the birthday on the Saturday holiday, which plays the phone version.

Candidate in `.emu/review_dates/`: G_BIRTH's sectors, GEKO's banner and
gift-table sectors, and the gift-table sectors of DATE, DATE2, KANGEI,
SHOUGATU and SHUGAKU changed (42 sectors), checksums valid. Seen in
English (`gbs`, `gbh0`, `gbt2`, `gbt3b`, `gbA`–`gbC`): Shiori's school-day
birthday (gift list, `{A}` gift name, greeting, thanks, "fine" reaction)
and her holiday phone version in full (the call, "Click.", meeting at the
front door, the present); every other girl's section with the swap. Mio's,
Saki's, Yuko's, Megumi's and Yumi's lists etc. read fine; **Megumi's and
Yumi's 1995 gift lists are empty boxes**: part 3·girl + (year − 1995) of
section 11 hits the original's two empty placeholder strings (parts 27,
30), so the same would happen unpatched; Yumi only starts school in 1996.
Not seen: other ranks' greetings and reactions, Yuina's and Nozomi's
phone versions, the 1996/97 lists. Normal build (`.emu/default_gbirth/`,
27 files) byte-identical to the candidate.

### The Christmas party (XMAS.BIN, 2026-10-09)

`xmas_run.ps1 -Opts "..." [-Presses N] [-Wait 4000] [-Prefix p]` launches
the Sunday state, runs `force_christmas.py --party` with the options
(game-internals §6t; the tool's docstring lists them), picks the first
weekly command, and screenshots every box, in sheets of 15. The next
weekday becomes the party: arrival, Ijuin's speech, Shiori, two girls,
the present exchange, then the week goes on. Runs used (unpatched first,
`x0`/`x1`, then the English candidate):
- default stats: turned away, evening at home (`x0`); `--visit`: Megumi
  visits with a present first (`f1`); `--looks 999`: let in politely
  (`f2`); `--physique 999`: Sotoi's "physique" lines (`e1`–`e9`);
  `--physique 999 --sotoi 1 --visits 1`: "you've come again" (`f3`);
- `--girls A,B` for first meetings (`e1` Yuko/Mio, `e2` Yuina/Ayako, `e3`
  Mira/Yukari, `e4` Nozomi/Saki); `--intro --girls 9,10 --met 10`:
  Shiori introduces Megumi, then Yumi chats (`e5`); `--met` chats and
  `--mood 4` brush-offs, `--visits 1`/`2` for the later speeches (`e6`–`e9`);
- `--present P` for each run's present (it overrides the opened box's
  part; the closing thought still follows the real box, so a forced
  girl's present can be followed by the "a girl's present would've been
  nicer" thought).

Use `-Wait 4000` or more: the present-exchange announcement types slowly
and at 3.5 s its second line is still half drawn (the Japanese too).
Sound lines (`Thud`) advance by themselves between screenshots. The first
`--intro` run stalled the emulator once at stage 2 (no breakpoint hit, the
driver's screenshots stopped); the same run passed on a retry.

Candidate in `.emu/review_dates/`: XMAS's 14 sectors and SHOUGATU's word
sector + checksum changed (16 sectors), checksums valid. Seen in English:
see the corresponding row in UPSTREAM_VERIFICATION.md. Normal build (`.emu/default_xmas/`, 28 files)
byte-identical to the candidate.

### White Day and Valentine's Day (WHITE.BIN, VALEN.BIN, 2026-10-09)

Both are forced with `xmas_run.ps1 -Tool <forcer> -Opts "..." -Hidden`
from the Sunday state (game-internals §6u/§6v; options in each tool's
docstring). The forcer writes a White Day (`30`) or Valentine (`31`) day
record over the next ordinary one, then polls for the overlay's code
before arming its breakpoints.
- `force_white.py --gave G,... --pick G --mood M [--year97]`: `w1` Yuko
  mood 0 with Shiori also in the menu, `w2` nobody (Ijuin's "no" branch),
  `w3` Yuina mood 2 with Ijuin's 1997 lines, `w4` Mira mood 3, `w5` Yumi
  mood 4 ("give it to my brother"), `w6` Mio and `w7`/`w8` Saki mood 0.
  The girl menu lists the `--gave` girls with their English names.
- `force_valen.py --girls G,... --parts P,... [--intro] [--year N]`: `v1`
  Yuko heartfelt, Shiori and Megumi courtesy; `v2` Shiori, Yuina, Mio
  heartfelt; `v3` year 1, Megumi's introduction by Shiori and Shiori's
  apology; `v4` year 2, Ayako, Mira, Yukari, Nozomi heartfelt; `v5` Saki,
  Yumi heartfelt, Mio, Ayako courtesy; `v7`/`v8`/`v9` the other courtesy
  versions and Megumi's heartfelt one (`v8` stalled the emulator once
  after Ijuin; the retry passed). A six-girl list (`v6`) played Shiori's courtesy scene six
  times: keep to four girls.

The forced list skips the ranking that seems to pick the later
"part 2" scenes (game-internals §6v), so those weren't seen. Each forced
day ends normally and the week continues (Mio's library meeting followed
in several runs). Candidate in `.emu/review_dates/`: WHITE's 9, VALEN's 7
and VALEN.EXN's 2 sectors changed (18), checksums valid.

### New Year's Day (SHOGATU.BIN, 2026-10-09)

`xmas_run.ps1 -Tool tools/emu/force_newyear.py -Opts "..." -Hidden` from
the Sunday state: the next weekday's state `0x40` becomes `0x53`
(game-internals §6w). `--visit G --met G` makes G ring the doorbell
(best-mood girl forced at `0x8013296C`); `--call G --met G` makes the
phone menu's choice G (the menu shows Shiori and the met girls; any
entry works). `--year 1`/`2` writes the year byte for the second and third
New Year's lines. With the default `-Keys C` every choice takes its first
option (accept, Grades); `-Keys "Down,wait:600,C"` takes the second
(refuse, then go alone, Health).
- English runs: `n1` calling Shiori (her kimono at the door, the fortune
  "Lucky me! Best!!"), `n2` Yuko visits, `n3` calling Yuina (third year),
  `n5` calling Mira ("Uh, Doom..."), `n6` Mio visits (second year), `n7`
  calling Yukari (her kimono choice, "Oh, Fair."), `n8` Nozomi visits,
  `n9` calling Megumi, `n10` Saki visits ("Uh, Poor...", the UFO trick),
  `n11` calling Yumi (second year), `n12` Shiori visits (third year), and
  the re-runs `m1`–`m5` (Ayako, Shiori's and Saki's third-year endings,
  Mio, refusing Yuko and going alone).
- Not reached: the third-year "we graduate" endings (year 97 alone still
  plays the usual one), Nozomi's unused section 8, the phone answers for
  other moods, refusing and then picking the same girl (part 8), a girl
  with no known number (section 14).
- After the shrine the week continues normally (Mio's library meeting
  followed in several runs).

**Harness stalls.** Five of the twelve runs (`n4`, `n6`, `n10`, `n11`,
`n12`) ended early with `drive.ps1`'s "DuckStation did not produce a new
screenshot": the hidden emulator stopped writing screenshot files, while
the forcer's log shows the game had already been forced normally. The
same happened once each in the party and Valentine runs. It's the
harness, not the patch: re-running the same options worked. Check a
run's shot count (`ls .emu/shots | grep -c ^PREFIX_`) before reading its
sheets. Since the camp work (2026-10-09) `drive.ps1` re-presses F10 up to
four times before giving up and `gdbstub.Gdb.detach()` waits for the
stub's reply; the 9 camp runs and the re-check after it all completed.

### The training camp (GASSHUKU.BIN, GASSH_FU.BIN, 2026-10-09)

`xmas_run.ps1 -Tool tools/emu/force_camp.py -Opts "--club C --girl G
[--met G] [--year N]" -Presses 45 -Hidden` from the Sunday state
(game-internals §6x). The forcer sets the player's club and puts G in it,
then writes a camp day record and makes the week's first record a camp
day too; the camp then runs by itself (arrival, G's scene in stage 9, the
other days without text, the last day's bath with its choices) and the
week continues (Mio's library meeting followed in every run). Without
`--met` G plays her first meeting, with it her chat.
- English runs: `k1` Yuina chat (Science) and the girls'-bath window,
  `k2` Ayako's test of courage (Art), `k3` Mio chat (Literature), `k4`
  Yukari fainting at practice (Tennis; `k4b` re-checked a shortened line),
  `k5` Nozomi's first meeting (Swimming), `k6` Saki chat (Baseball) and the
  boys'-bath window, `k7` Yumi chat (Basketball, 1996), `k8`/`k9` Shiori
  (GASSH_FU: Drama, Soccer) and Ijuin's statue window.
- Not reached: the technique box (`{A}` secret / `{M}` / mastered, probably
  at a high club level), later years' chat levels, the rumors, Saki's
  missed-Koshien lines.

Two harness traps found here:
- A forcer that waits on a breakpoint holds the GDB connection: a second
  script can't attach until it exits.
- The camp replays its arrival forever if only the forced day is a camp
  day (game-internals §6x), which first looked like a hang on the
  unpatched disc too.

### The school trip (SHUGAKU.BIN, 2026-10-09)

`xmas_run.ps1 -Tool "tools/emu/force_trip.py --year 1" -Opts "--met G
--girl G [--mood M]" -Presses 50 -KeyList ";Down+C" -Hidden` from the
Sunday state (game-internals §6y). The forcer writes one trip day record
(plus the week's first record, as for the camp); the six days then play by
themselves and the week continues. `-KeyList` (new in `xmas_run.ps1`,
";"-separated presses, "+" between keys of one press) picks the
destination on the second press: `C` Kyoto/Nara, `Down+C` Okinawa,
`Down+Down+C` Hokkaido. At the "ask a girl / go alone" choice `C` asks a
girl; the menu lists only met girls, so `--met G --girl G` swaps the pick.
- English runs (`t1`–`t12`, `u1`–`u6`): Shiori (all three destinations),
  Yuko, Yuina, Ayako, Mira, Mio, Yukari, Nozomi, Megumi and Saki, each
  through both free days, the danger and the escape; `u1` Yuina with
  "leave this to me" (the habu RPG battle, then her after-fight lines);
  `u2` Yuina inviting him herself (`--invite 2`); `u3` Mio refusing
  (`--mood 4`); `u4` Yoshio (go alone), the three-way choice and the bear
  battle; `u5` the sick-day start (`--sick`); `u6` a single record: the
  trip ends and the week goes on.
- Fixed on the way: Yuina's and Mio's odd-length names showed their pair
  padding before punctuation ("Yuina ," / "Mio !"): their sections' lines
  end on `{G}` or put no punctuation after it (per-offset overrides, since
  the shared lines are fine for even names). `{S}` lines end on the place
  name for the same reason ("Okinawa " is odd). "Right, I remember now."
  first ran to 34 cells with `{S}`.
- Odd, but from files this patch doesn't touch: Ayako's Okinawa run ended in her
  EVENT_KA special event (Japanese: lost, asking a foreigner); the
  battles are `RPG_BAT.EXN`'s own Japanese text (ハブ・ロード, キラーヒグマ,
  攻撃/防御); a blank box between scenes; the first sick-day line
  (くぅー → "Ugh...") wasn't captured.
- `--week N` makes later records trip days too; the trip then restarts
  from day 1 after the last day (not a hang; the real game queues one
  record).
- Not reached: the other moods' answers (parts 18/21) for most girls,
  most girls' invitations and refusals, the softer Nozomi section 7, other
  battle outcomes.

### The other girls' special events (EVENT_*.BIN, 2026-10-10)

All from the Sunday state, emulator hidden, batch script
`.emu/ev_runs.sh` (local). Four ways in (game-internals §6z):
- **GEKO scenes:** `xmas_run.ps1 -Tool "tools/emu/force_event.py GIRL
  SCENE" -Presses 30` (runs `g01`–`g22`): Yuina 1, 7; Ayako 1; Nozomi 1,
  8; Mio 1; Yukari 1, 2; Megumi 1, 2; Saki 1; Mira 1; Yumi 1, 2, 7;
  Ijuin 1–3; Miharu 1, 2, 4; Yoshio's.
- **Christmas walks:** `force_christmas.py --girl 7` / `--girl 9` (`s01`
  Mira, `s02` Megumi; new stages in the forcer).
- **Date events:** `date_run.ps1 -Girl G -Place P -Extra "--event N"
  -Presses 32` (new `force_date.py --event`, `d01`–`d37`): every DATE
  entry of all nine girls. The scene plays after the meeting whatever the
  place, then the date ends; the end-of-date lines and the
  answering-machine messages that follow are other files (still Japanese
  where they belong to other girls' DATE_* files).
- **School-trip events:** `force_trip.py --event-mood` (`t21`/`t25`
  Yuina, Hokkaido, through the crop circle into the alien battle; `t22`
  Ayako, Okinawa, the expat; `t24` Yukari's bath). Saki's cold (`t23`)
  didn't start: it needs a birthday-dependent flag (§6z).
- Seen in English: every scene above, labels Tchr/Boss/Minion/Tyke/Mu/
  Expat/Girl/???, the event banners. Fixed before the runs: Yuina's file
  needed 78 bytes more than the original had; 18 long lines shortened.
  The trip's Ayako lines (school_trip.json) got the same odd-name fix as
  Yuina's and Mio's (§6y).
- Odd but not caused by this patch: forced date events end with the date
  girl's Japanese goodbye lines (her DATE_* file, not translated yet), and
  the standing-up message then plays because the forced jump skips the
  date's normal end; "Mio  and I had" in that message (phone_calls.json)
  shows the double space of an odd name before " and".
- Not reached: Saki's trip cold, Miharu's mix-up (DATE entry 76), Nozomi's
  soft/tomboy alternatives beyond one each, the battles' outcomes.

### The other girls' dates (DATE_*.BIN, 2026-10-10)

Nine files, one forced date per place, all from the Sunday state with the
emulator hidden: `date_run.ps1 -Girl G -Place P -Version -1 -Presses 30
-Prefix X` (the game picks the version). Batch scripts `.emu/ky_runs.sh`
and `.emu/dt_runs.sh` (local), logs `ky_runs.txt` / `dt_runs.txt`. To keep
the runs down (one per variant family), each girl got a third of the
places, rotating so every place was seen with three girls:
- `k00`–`k20`: Nozomi, every place 0–20.
- `mi00`…`mi18` Megumi and `ko00`…`ko18` Yukari: places 0, 3, 6 … 18
  (neighborhood park, Aquarium, Planetarium, Arcade, Theme Park, Concert
  Hall, Shrine).
- `hi01`…`hi19` Yuina, `ni01`…`ni19` Saki, `kg01`…`kg19` Mira: places
  1, 4 … 19 (Kirameki Park, Zoo, Art Museum, Bowling, Stadium, Pool,
  Skating Rink).
- `sa02`…`sa20` Yumi, `ka02`…`ka20` Ayako, `ki02`…`ki20` Mio: places
  2, 5 … 20 (Shopping, Botanical Garden, Library, Karaoke, Cinema, Beach,
  Ski Resort).

Each run shows the meeting, the place's first choice with the pick the
driver makes (the first option), her reply, the impression thought, her
verdict, the player's answer and the way home, then the week resumes.
Review with `review_sheets.py` or a side-by-side of two prefixes. The
location banner is visible only in each run's second screenshot, still
sliding in from the top left, so its first letter is cut off by the screen
edge there; the meeting runs (`bn_*`) show the settled box whole.

- **Null ski sections.** Mio, Yuina, Ayako and Megumi have no ski date
  (section 16 is a null entry in their fill function, game-internals §6k).
  Forcing place 20 for them (`ka20`, `ki20`) plays the meeting and then
  returns to the title screen; reloading continues normally. That's the
  forcer reaching a date the game never offers, not the patch.
- **Odd-length names in options** (Mio, Yuina, Ayako): an option ending on
  `{G}` shows a space before 』 ("You can get it, Yuina 』"), accepted as
  for Mio's cinema line above.
- Fixed after the runs (wording only, then re-checked with `draft.py
  --check`): Mira's bowling "Your turn. Let's see you manage it, then.",
  Ayako's "there are free seats", Megumi's horror-film note, Saki's and
  Yuina's skating replies, Yuko's goldfish line ("wanna scoop some goldfish?"). The
  promoted build differs from the tested candidate only in those strings
  (and the repacked bytes after them).
- `tools/date_sections.py` now skips a section whose table entries point
  outside the file (the null ski sections) instead of reading garbage.

### The culture festival (BUNKA/*.BIN, 2026-10-10)

`xmas_run.ps1 -Tool "tools/emu/force_festival.py --only G --club C"
-Presses 60 -Hidden` from the Sunday state: the forcer marks only girl G
as met (so the first menu item is her) and sets the player's club, then
writes the festival day record. Batch scripts `.emu/fest_runs*.sh`
(local), game-internals §6ab for the flow.
- `fa00`–`fa10`: each girl invited with no exhibiting club (11); the club
  menu then defaults to Literature. Club girls (Shiori, Mio, Yuina, Ayako)
  decline and the player tours alone; the others come along (S6S, S6W).
- `fb0`–`fb5`: the player in each exhibiting club; Shiori visits.
- `fc01b`, `fc02c`, `fc03c`: Mio, Yuina, Ayako's own exhibits, choosing
  Drama / Computers / Band. `-KeyList` with **one key per press** after
  16 empty entries ("Right+C" in one press lost the move); the club menu
  moves linearly, so Computers is three Downs and Band five.
- `fu09b`: Megumi's tour with the festival drafts left out, to compare
  with `fa09`: both go back to the title after the club menu. Since the
  save state reopens its own disc, the comparison build has to be
  rebuilt into `review_dates` (`python tools/candidate.py` with no
  drafts).
- Fixed after the runs: the PC fortune's doubled name (a nop per overlay),
  "if you'll have me" (Saki, Yukari, and Saki's line in
  school_trip.json), Mira's "You expect me to do it?", Yuko's "All that
  text..." and her missing "?", the gym announcements. `fb3b` re-checked
  the PC fortune.
- Stage shows (`stage_shows.json`, `.emu/fest_runs5.sh`): `sd10`, `sd11`,
  `sd12` with `--club 1 --year 0/1/2` (Kintaro Samurai, Cultman, Romeo and
  Julietta), `sd02` with `--club 0 --year 2` (the speech contest: Shiori's
  speech); `sd01` (`--year 1`) is the essays exhibit, no show. Each run is
  70 presses. Labels match the unpatched `fb1`. Short labels put the 「
  right after the name ("Shiori「"): the label slots have no room for a
  space.

### The ending (ENDING.BIN, EPILOG.BIN, 2026-10-11)

`xmas_run.ps1 -Tool "tools/emu/force_ending.py G" -Presses 90 -Wait 1500
-Keys Up -KeyList "C;C;C;C;C;C" -Hidden` (`.emu/end_runs3.sh`, runs
`en00`–`en10`, `en12`, `en13`): six presses through the classroom, then
`Up` (which advances nothing) with a shot every 1.5 s, because the tree
scene and the epilogue advance by themselves. The review sheets crop to
the dialogue box, so these runs are reviewed with full screenshots
(scratchpad `endsheet.py`: drops near-identical frames, three per row).
`eu00`/`eut` were the unpatched Shiori run and an `add_text` trace
(`--trace`): the girls' lines at the tree are never drawn.

### Sickbed, encouragement, group date (OMIMAI, HAGEMASI, GROUP_D, 2026-10-11)

`.emu/d_runs.sh` (local), Sunday state, hidden:
- `om00`, `om01`, `om05`, `om08`, `om10`: `force_event.py G 0 --type
  0x47`. Despite the NEXT_STEPS guess, record 0x47 plays **HAGEMASI**
  (a girl's short encouragement, "Please don't push yourself too hard")
  on the next weekday, not the sickbed visit.
- `hg0`: `force_state.py 0x62` plays **OMIMAI**, the sickbed visit
  (Shiori's here: "Shiori's come to visit you. Come on, get up.").
- `gd0`–`gd2`: `force_event.py 0 S --type 0x49` (scene 0–2 make no
  difference): Yoshio's call, the theme park with Shiori and Mio, the
  Ferris wheel, roller coaster and haunted-house choices. "Ride with Mio
  』" shows the accepted odd-name space.
- `kd0`: `force_state.py 0x5c` jumps straight to a karaoke song (its
  on-screen lyrics are song data, left Japanese) and then back to the
  title screen; KARADATA's chatter needs the real karaoke date. Not found
  yet, like ZAKOSEN's thugs (DATE.EXN `0x8013CADC`): both files were
  later promoted without comprehensive on-screen verification upstream (UPSTREAM_VERIFICATION.md).

### Club contests (MASTER/*.BIN, 2026-10-11)

`.emu/e_runs.sh`, `.emu/e_runs2.sh` (local), Sunday state, hidden,
`xmas_run.ps1 -Tool "tools/emu/force_event.py 0 0 --type T --club C"
-Presses 40`: `mc0` (0x25, baseball), `m27c0`–`m27c5` (0x27, each
culture club), `mt7`, `m26c9`, `m26c10` (0x26, soccer, swimming,
basketball). `m26c0` and `mu8` (0x26 with a culture club, 0x27 with a
sports club) and `rs7` (state 0x73) went back to the title screen.

### Overlay words and small files (2026-10-11)

`.emu/f_runs.sh` (local), hidden:
- `fb1`: Yuina's Okinawa trip with "leave this to me" (as `u1`): the habu
  battle in English (Habu Lord, Mongoose, "220 damage dealt", "Loot:
  Habu"). The run showed the player's "No good! I'm done for!" glued to
  his name: the English had dropped the original's opening 「; restored on
  seven lines (two shortened to fit) after the run, statically checked.
- `fe43` (record 0x43): career counselling; `fe4a` (0x4A): the
  university exam day. "I want college." became "College for me." (it is
  both the option and the spoken line).
- `fol` (state 0x3A): OLH.EXN is the in-game help (Q&A) screen.
- `fta` (record 0x20): sports day prompt and event menu, then the spoon
  relay minigame (needs input; its caption bubble is graphics).
- `fn13`/`fn14` (states 0x13/0x14): the album panel and the family-name
  entry; neither plays the opening narration, which needs a real new
  game (`opening_words.json` was promoted unverified).
- `fic*`: Yoshio's info card from `phone_sat0429.sav` with `drive.ps1`.
  Presses sent while text is still typing get dropped, so the fixed
  sequences drifted (ratings path, date spots) and never opened the card;
  `info_card.json` was promoted unverified. The phone book in that old state still
  shows 藤崎詩織 (RAM from before the name patch; a fresh boot shows the
  English name).

### Tools for the whole-game loop (2026-10-10)

The upstream per-file translation process used these (details in each docstring):
- `tools/script_survey.py FILE` / `--all`: loaders, base, section tables
  and their coverage, each string's speaker code (game-internals §6aa).
- `tools/draft.py FILE -o DRAFT [--table T] [--name GIRL]`: the draft with
  the translation memory filled in, the todo list, and the checks;
  `tools/draft.py --check JSON` checks any translation file. Its "code"
  per line comes from the tables; where a string is reached with
  conflicting codes it's unknown, and the option checks become `warn:`.
- `tools/candidate.py [DRAFT ...]`: reference + candidate builds, changed
  files with checksums; with no drafts it confirms a promotion is
  byte-identical.
- `tools/exn_words.py EXN`: an overlay's in-place strings with their room.
- `tools/emu/force_state.py STATE [--stage N] [--girl G] [--scene S]`:
  any overlay at any stage; `force_event.py ... --type T --first` for day
  records (the map is in game-internals §6aa).
- `tools/emu/review_sheets.py PREFIX...`: 30 boxes per review image.

Probes `pb1`–`pb12` (2026-10-10, unpatched text in the normal build):
day-record types 0x24, 0x25, 0x26, 0x27, 0x47, 0x49, 0x20, 0x40, 0x43,
0x4A, 0x10, 0x2C forced from the Sunday state; what each showed is in
game-internals §6aa. `d17b` re-checked Mio's cinema menu after its options
were made even ("Yep. You're pretty anyway." / "Nah, not at all.");
"Crying? Mio )" in the same scene is the odd name before the game's
bracket and can't be avoided (the name must end the box).
`draft.py --check` over every committed file then found one real bug the
earlier checks missed: the trip's destination menu showed "『Okinawa 』"
(an odd option). Now "Kyoto/Nara / Naha/Okinawa / Sapporo/Hokkaido",
re-checked on screen (`tr2`).

### Disassembly

```bash
uv run --with capstone python tools/mipsdis.py .emu/ram.bin 0x80000000 0x8004636C 40
uv run --with capstone python tools/mipsdis.py extracted/SLPM_86.053 0x80040800 0x80078DC0 80
```

Don't name a script `dis.py`: it shadows the stdlib module that capstone imports.
When scanning a whole binary with capstone, set `md.skipdata = True`.
Otherwise it stops at the first data word and silently returns a fraction of
the code (an early search for BIOS calls found nothing because of this).

## Finding graphics (VRAM dumps)

1. In `.emu/duckstation/settings.ini` set `[Debug] DumpCPUToVRAMCopies = true`.
2. Boot and get to the screen. Every CPU→VRAM upload is saved as
   `.emu/duckstation/cpu_to_vram_copy_<n>.png`. Movies produce thousands of
   these, so stop soon after the screen appears.
3. Group by size: 24×240 are movie slices, 64×128 are 16 KiB pixel blocks,
   256×1 are 256-colour CLUTs, 16×1 are 16-colour CLUTs. The blocks and CLUTs
   that arrive together belong to the file just loaded (`trace_reads.py`).
4. Render the file's bytes as 8bpp with 128-byte rows (or 4bpp, 256 px) to find
   the art. 4bpp rendering of 8bpp data shows vertical striping.
5. **Matching CLUTs:** DuckStation's PNGs expand 5-bit colour to 8-bit, so
   don't compare with `c<<3`. Convert the dump back with `round(v*31/255)` and
   search the file for the 15-bit words (ignore bit 15). The CLUTs in
   `TITLE.NBN` are stored out of upload order (game-internals §7).
6. Set `DumpCPUToVRAMCopies = false` again afterwards.

## Windows-specific gotchas
- Run `drive.ps1` with **Windows PowerShell 5.1** (`powershell.exe`). In pwsh 7,
  its `Add-Type` code doesn't compile without extra assembly references.
- `SetForegroundWindow` is blocked for background processes (foreground lock),
  and sending real keystrokes risks typing into the user's windows. That's why
  the driver uses `PostMessage`.
- `PrintWindow` returns black for DuckStation's GPU-rendered area. Use
  DuckStation's own screenshot hotkey (what `shot:` does).
- DuckStation keeps the screenshot file locked briefly after writing it. The
  driver waits 1.2 s before moving it.
- Kill only the isolated instance:
  `Get-Process | ? { $_.Path -like "*\.emu\duckstation\*" } | Stop-Process`.

## Club correction handoff (2026-10-07)

The current test image is `.emu/review_clubs/` (open its CUE), built from the
default 13 translation files; `.emu/review_clubs.log` is the build log.
It includes Literature and the revised Club Day fragments. Real boot and
loading the 95/4/23 test card succeeded, and play continued to the 4/29 holiday.
The first News issue also displayed its English introduction, Movie “Closed”,
Concert “KNM Symphony” and event announcement; later issues are unverified.
No unpatched comparison at the corrected club screens has been completed.

Final static checks passed: a full raw-track comparison found exactly the 37
sectors predicted by the patch plan, with valid regenerated EDC/ECC on each.
Every patched file retained its size, and all files that originally had valid
checksum trailers still validate. `SLPM_86.053` and `MAINROM.NBN` do not have
those trailers; earlier session claims of an EXE checksum update were mistaken.
All 12 club-table pointers resolve to their expected English strings, and the
three adjacent notice-fragment pairs fit their fixed x-coordinate gaps.
The driver passes PowerShell syntax validation. The isolated emulator was
stopped after the review.

Follow-up user verification (screenshots and play test):

1. Club List: Literature replaces 文芸 and fits the column. Its selected state
   extends slightly beyond the green selector rectangle; the user accepts this
   for now. The first screenshot shows Literature highlighted.
2. Joining Soccer: the user confirms successful joining and the second
   screenshot shows the corrected captain's notice: “Capt. Each 3rd Sunday is”
   / “Club Day, so” / “don't   miss it.”. There is no text overlap. The wide
   gap before “miss it.” is noticeable but accepted by the user for now.

Leave both cosmetic issues unchanged, as requested. Continuation after this
corrected notice was not explicitly reported; the earlier build's club flow
had already been checked for continuation. For future text tests, boot the CUE
and load a memory-card save: older emulator states retain old EXE strings and
pointer tables.

The test harness's previous card was backed up under
`.emu/memcard_backup/review_before_*` before the main-loop test card was copied
in. This run did not operate the user's DuckStation installation or cards.

## Save/Load panel and settings handoff (2026-10-07)

Candidate: `.emu/review_settings/` (open its CUE); log:
`.emu/review_settings.log`. It originally included the 13 default translation
files plus the two drafts, now at `translation/album_panel_exe.json` and
`translation/system_settings.json`: 397
in-place strings, 173 pooled dialogue entries, 4 images and 3 byte patches
from 15 JSON files. The user has now reported successful visual verification
of populated Load panels and all settings submenus (details below). Both
translations have now been promoted into normal builds at the user's request.
This candidate preserves the user-accepted club selector overhang and notice
gap. It does not translate the title Options' graphics-based choices or the
new-game album panel's graphics.

Changes from the drafts:

- Both Save/Load panel copies now use `Name: `, `Nickname: `, `Club: ` and
  `Cleared: ` before their saved values. Their destination buffers were checked
  as well as the literal byte budgets. Slot headings intentionally use a colon
  after the number: the game only appends two bytes, so `: Album` was misleading.
- All four Menu Mode confirmations now read `Menu mode:` / `<mode>` /
  `selected.` on the original three rows. Other settings translations remain
  as drafted; no coordinates, selector sizes or settings logic were changed.
- Consumer addresses, fixed copy limits, row coordinates and the two Cursor
  Speed label sets are documented in game-internals §6i. The translation guide
  now explains these patterns rather than recommending empty trailing pieces
  without first checking their layout.

Static checks completed on the candidate:

- The normal patcher planned against the original disc and built successfully;
  all 135 extra strings passed original-byte checks and in-place budgets.
- Every output file matched the planned bytes and retained its original size;
  all files with original valid checksum trailers still validate. The EXE and
  `MAINROM.NBN` do not have those trailers.
- A full raw Track 1 comparison found exactly the 37 planned changed sectors;
  every changed sector is Mode 2 Form 1 with valid regenerated EDC/ECC and an
  unchanged header/subheader. Compared with `.emu/review_clubs/`, only EXE
  sectors 247, 248 and 249 differ. The CUE and audio track are identical to
  the originals. All 1,981 incremental EXE byte differences are confined to
  the two documented literal blocks (`0x6FA08`–`0x7028F` and
  `0x70790`–`0x70853`); no code or other default translations changed.
- Slot/date appends obey their two-byte limits. The panel's maximum current
  label/value lengths stay inside their 32-byte stack buffers, including NUL.

### Follow-up user verification

The user supplied four screenshots and reported that these screens were
successfully translated, adding that **all system settings submenus were
visually verified**, although not all were photographed. Record that report
as visual evidence without treating it as an exhaustive per-string test.

1. Settings main screen: `System Settings`, Text Speed, Icon Mode, Mouse,
   Menu Mode, Cursor Speed, Voice Mode and Exit render in English. Icon Mode
   is highlighted; the help reads `Change system settings.`. Mascot is not
   visible in this screenshot, so no unlock-condition conclusion follows.
2. Text Speed submenu: `Text Spd`, Slow (highlighted), Normal, Fast and
   `Change the text display speed.` are legible, without apparent clipping.
   In particular, the padding-using `Normal` label fits.
3. Load slot 1: number/colon heading, date 95/4/9, Name/Nickname/Club/Cleared
   labels and saved values render correctly; the club is None and cleared
   count is 0. The prompt is `Choose a file to load.`. Japanese player-entered
   names remain intact; these are saved user values, not missing translations.
4. Populated slot 2: heading and date change to 2 and 95/4/16, and the club
   changes to Soccer. Labels and values remain readable with separators and
   no apparent overlap. The blank prompt in this screenshot is not evidence
   of Save mode; the screenshots explicitly establish populated Load panels.

The other settings submenus are user-reported visually verified, not individually
screenshot-verified. Individual setting-change confirmations (including the
three-row Menu Mode messages), every highlighted state, which Cursor Speed
label set appeared, and mouse-accessory/unlock-dependent paths were not
separately itemized. Do not infer their detailed coverage from the general
submenu report. The panel's Save-mode copy, empty/error/System entries,
longest club values and nonzero cleared counts also remain unverified.
An unpatched comparison and continuation after these particular screens
were not explicitly reported. No emulator instance, settings or memory cards
were operated by the agent during this documentation update; no screenshots
or game data were added to the repository.

Original test checklist (retain for remaining branch checks; the visual
coverage above has already been completed and should not be discarded):

1. Boot the candidate CUE fresh and load a **memory-card save**, not an old
   emulator save state. Old states preserve old EXE strings and pointer tables.
2. On Sunday night, open the memory-card command. Check populated and empty
   slots in **both Save and Load**, without overwriting a valued save just to
   test. Look at the slot number, date, name, nickname, club and cleared count:
   there should be visible separators, intact values, and no clipping or
   overlap. A saved club such as Literature/Basketball is a useful width test.
   The full-width digits and spaces around date slashes are expected for now.
3. Open **in-game System Settings**, not title OPTIONS. Check the item list,
   highlighted/unselected choices, help text and confirmation for Text Speed,
   Icon Mode, all four Menu Modes, all five Cursor Speeds, Voice Mode and
   available Mascot choices. In particular check `Normal` and the longest
   Menu Mode; its confirmation should have three readable rows. Note which
   Cursor Speed label set appears; both sets exist but may require different
   input/device conditions. Mouse settings need the mouse accessory and can
   remain explicitly unverified without one.
4. Restore preferred settings, exit to the game and play through the next
   transition. Do not force memory-card errors or corrupt saves to exercise
   `Bad data`; leave unseen error branches unverified. If a problem appears,
   compare the original game at the same point before blaming the patch.

The historical verification table in `UPSTREAM_VERIFICATION.md` records upstream reports. Both JSONs
have now been moved into `translation/`, so the normal command includes them.
Unverified-path notes are retained; inaccessible mouse/error paths are not
marked as seen. The user's standing preference is to promote tested new
translation files into normal builds after testing, not leave them opt-in.

### Normal-build promotion verification

Built `.emu/default_promoted_settings/` from the original CUE with
`python -m tokipatch <original cue> -o .emu/default_promoted_settings --force`,
**without any `-t` options**. Log: `.emu/default_promoted_settings.log`.
Default discovery loaded all 15 JSON files (397 strings, 173 pooled dialogue
entries, 4 images and 3 byte patches). The two old `extra/` paths no longer
exist; their patch entries are unchanged, with only description metadata
updated alongside the moves.

SHA-256 comparisons confirmed that the CUE and both BIN tracks are identical
to `.emu/review_settings/`, the candidate the user tested. An independent
check against the original confirmed exact planned output bytes, unchanged
file sizes, valid applicable checksum trailers, exactly 37 expected changed
sectors and valid EDC/ECC on every changed sector. The original source files
were only read. No new emulator run was performed for this path-only promotion;
the user's candidate verification applies to the byte-identical output, with
the same branch-coverage limitations recorded above.

Rebuild recipe after promotion (PowerShell; no `-t` flags are needed):

```powershell
$env:PYTHONIOENCODING = 'utf-8'
python -m tokipatch '<original game.cue>' -o .emu/review_settings --force
```

### Sports day cards (2026-10-11)

- Force the sports day with `force_event.py 0 0 --type 0x20` while the first
  weekly command runs (start it in the background, then press C). After
  "Which event to enter?" the menu is Spoon relay / Borrowing race / Other
  events. "Other events" switches to 3-leg race / Ball rolling / Other
  events, **with the cursor staying on the third line**, so one Down picks
  the 3-leg race and two pick Ball rolling. The card shows about 20 s after
  the pick.
- **The Sunday state reopens `.emu/review_dates` whatever `-Build` says**
  (DuckStation takes the disc from the save state). To compare with an
  unpatched card, build without the JSON into review_dates
  (`candidate.py`), then rebuild.
- A VRAM upload trace (`watch_exec.py ... 0x8004435c --max 4000`) counts
  1280 uploads (ra 0x8004D64C) per card. A lower count means a block was
  skipped (block number 0, game-internals 7).

### The info card (2026-10-11)

From `phone_sat0429.sav`, sending the presses one at a time with a
screenshot after each worked where the fixed `fic*` sequences drifted:
`Down` ×8 at 900 ms, `C` (phone book, Yoshio), `C` ×5 through the
greeting, `Up` to "Ask girls' views", `C`, `C` ×2 (the ratings page),
`C` (the thought), `C` on Shiori in the girl list, then `C` ×4 to the card.

