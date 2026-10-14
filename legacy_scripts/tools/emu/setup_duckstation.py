"""Create an isolated, scriptable DuckStation copy in .emu/duckstation (Windows).

Usage:  python tools/emu/setup_duckstation.py [--source DIR] [--bios DIR]

Copies an installed DuckStation into the repo's .emu/ folder and turns it into
a *portable* install (portable.txt), so its settings, memory cards, save states
and screenshots live there. The user's own DuckStation install and config are
never touched. Settings are seeded from the user's settings.ini when present,
then changed to:
  - keyboard bindings for pad 1 (arrows, C=Circle, X=Cross, Z=Square,
    S=Triangle, Enter=Start, Backspace=Select). In this game Circle
    confirms and Cross goes back.
  - GDB stub on 127.0.0.1:2345
  - no power-off confirmation, no save-state-on-exit, no game-list scanning
  - RetroAchievements off and the user's [Cheevos] section (incl. login token)
    not copied. Otherwise it prompts for login on every boot, and hardcore
    mode blocks save states.
  - memory cards in .emu/duckstation/memcards. The user's settings may point
    at their real card folder (an absolute path, which portable mode does NOT
    redirect); tests create albums/system files and must never touch it.

After running, grep the new settings.ini for absolute paths ("= X:\\"):
anything other than the BIOS folder is a bug.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
DEST = REPO / ".emu" / "duckstation"
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))

PAD1 = """[Pad1]
Type = AnalogController
Up = Keyboard/Up
Down = Keyboard/Down
Left = Keyboard/Left
Right = Keyboard/Right
Cross = Keyboard/X
Circle = Keyboard/C
Square = Keyboard/Z
Triangle = Keyboard/S
Start = Keyboard/Return
Select = Keyboard/Backspace
L1 = Keyboard/Q
R1 = Keyboard/W
"""


def set_key(ini: str, section: str, key: str, value: str) -> str:
    sec = re.search(rf"^\[{re.escape(section)}\]\n(.*?)(?=^\[|\Z)", ini, re.M | re.S)
    if not sec:
        return ini.rstrip("\n") + f"\n\n[{section}]\n{key} = {value}\n"
    body = sec.group(1)
    if re.search(rf"^{re.escape(key)} = .*$", body, re.M):
        body = re.sub(rf"^{re.escape(key)} = .*$", lambda _: f"{key} = {value}", body, flags=re.M)
    else:
        body = f"{key} = {value}\n" + body
    return ini[:sec.start(1)] + body + ini[sec.end(1):]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, default=LOCAL / "Programs" / "DuckStation",
                    help="installed DuckStation folder to copy")
    ap.add_argument("--bios", help="folder containing PS1 BIOS images")
    args = ap.parse_args()

    if not (args.source / "duckstation-qt-x64-ReleaseLTCG.exe").exists():
        raise SystemExit(f"DuckStation not found in {args.source} (use --source)")
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(args.source, DEST)
    (DEST / "portable.txt").write_text("")

    user_ini = LOCAL / "DuckStation" / "settings.ini"
    ini = user_ini.read_text(encoding="utf-8") if user_ini.exists() else ""
    # Drop the user's RetroAchievements section entirely: it holds their login
    # token, and hardcore mode blocks save states and debugging.
    ini = re.sub(r"^\[Cheevos\]\n.*?(?=^\[|\Z)", "", ini, flags=re.M | re.S)
    ini = re.sub(r"^\[Pad1\]\n.*?(?=^\[|\Z)", "", ini, flags=re.M | re.S).rstrip("\n") + "\n\n" + PAD1
    ini = re.sub(r"^RecursivePaths = .*\n?", "", ini, flags=re.M)
    for section, key, value in [
        ("Main", "ConfirmPowerOff", "false"),
        ("Main", "SaveStateOnExit", "false"),
        ("Main", "PauseOnFocusLoss", "false"),
        ("Main", "SetupWizardIncomplete", "false"),
        ("Cheevos", "Enabled", "false"),
        ("Cheevos", "ChallengeMode", "false"),
        ("Debug", "EnableGDBServer", "true"),
        ("Debug", "GDBServerPort", "2345"),
        ("Debug", "DumpCPUToVRAMCopies", "false"),
        # Never inherit the user's memory card folder: test runs create albums
        # and system files, which would land on the user's real cards.
        ("MemoryCards", "Directory", str(DEST / "memcards")),
    ]:
        ini = set_key(ini, section, key, value)
    if args.bios:
        ini = set_key(ini, "BIOS", "SearchDirectory", args.bios)
    (DEST / "settings.ini").write_text(ini, encoding="utf-8")
    print(f"isolated DuckStation ready in {DEST}")


if __name__ == "__main__":
    main()
