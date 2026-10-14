# Tokimeki Memorial: Human Overhaul

The 2026 PlayStation English patch finally made *Tokimeki Memorial: forever with you* playable in English. This fork is an effort to improve its translation, working from the Japanese script rather than treating the existing English as settled.

The original patch was made with AI translation, and its author has been open about not knowing Japanese. An initial spot check of lines from different parts of the game suggests that much of the English is worth keeping. At the same time, there are quite a few problems to address, including lost nuances, changes in how characters address each other, and awkward phrasing. It doesn't look as though we'll need to rewrite the entire script from scratch, but that's only an early impression, not an assessment of the whole translation. We want the English to read naturally while preserving the game's Japanese setting, name order, honorifics and character relationships.

The review is being carried out by **rsc-pl, kyuubo, Mblack, KonataHoshi, and WhiteCatty**. The translation is still largely the original draft; this is work in progress, not a finished revision.

## Playing and building

There is no new release to download yet. The existing PS1 patcher and English assets are included, along with a Go command-line tool for Linux. It currently uses the original Python patcher for writing the disc image.

The patcher requires the Japanese **PlayStation the Best** release (**SLPM-86053**) in two-track BIN/CUE format. The original game is not included.

See [Building](docs/BUILDING.md) for the commands and requirements.

## What comes next

First we'll review the PS1 text and address the restrictions imposed by its dialogue boxes. The existing tools will gradually be replaced with Go code, without trading away the checks that keep a patched disc playable.

We also intend to bring the reviewed translation to **Tokimeki Memorial: Forever with You Emotional** on Nintendo Switch. That will require separate work on the Switch game's files, menus and text display. It is not a Switch patch yet, and we won't assume that every line is identical between versions.

## Credits

This is a fork of [gothamor's PS1 English patch](https://github.com/gothamor/tokimeki-memorial-english-patch). The original author did the reverse engineering, initial English translation, renderer changes and patching tools that made this work possible. The historical technical notes are retained in [`legacy_documentation/`](legacy_documentation/).

*Tokimeki Memorial* belongs to Konami. No game images or extracted game data are distributed here.
