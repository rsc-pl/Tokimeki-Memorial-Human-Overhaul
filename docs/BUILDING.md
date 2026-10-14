# Building the PS1 patch

You need Go 1.23 or newer, Python 3.8 or newer, and your own Japanese *Tokimeki Memorial: forever with you* PlayStation the Best disc image (SLPM-86053). The image must be a two-track BIN/CUE dump with a MODE2/2352 data track. You don't need PowerShell, Windows or Pillow to build the patch.

The Go launcher compiles itself on first run. From the repository root:

```sh
./tokimemo doctor
./tokimemo test
./tokimemo inspect "/path/to/game.cue"
./tokimemo preflight "/path/to/game.cue"
./tokimemo build --output "/path/to/output-folder" "/path/to/game.cue"
```

`inspect` checks that the CUE and its tracks can be read; it does **not** confirm the game's edition. `preflight` checks the game's bytes against the patch before writing anything. `build` makes a separate, patched BIN/CUE copy. The original files must not be modified. Open the **patched CUE** in DuckStation to play.

Without a game image, `./tokimemo status` and `./tokimemo test` still check the repository's translation data and code. The numbered menu is available with `./tokimemo`.

### Source files

`translation/` holds the current translation and graphics. `cmd/tokimemo/` is the Go frontend; `legacy_scripts/tokipatch/` contains the Python disc-writing backend still used by `build`. The older research scripts remain in `legacy_scripts/tools/`. Detailed reverse-engineering notes from the original project are in `legacy_documentation/`.

The game images, extracted files, emulator saves and local build results do not belong in commits.
