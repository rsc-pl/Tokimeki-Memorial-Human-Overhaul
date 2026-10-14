# Start a forced date from a Sunday-night state and screenshot the first
# boxes.
#
#   powershell.exe -File tools\emu\date_run.ps1 -Place 7 -Version 2 [-Girl 0] [-Presses 6] [-Prefix p7v2]
#       [-State .emu\savestates_backup\dates_sunday_0423_candidate.sav] [-Build review_dates]
#       [-Extra "--set-at ..."] [-Break "--at 0x8013B6F8 --sp16 0x3a=7"]
#
# -Break passes tools/emu/break_set.py rules (after `--`) to force_date.py, so
# the meeting, ending or going-home part can be chosen in the same session.
# Launches the state, runs tools/emu/force_date.py (date with -Girl, default 0
# Shiori, 8 Yuko, on 4/30 at PLACE;
# -Version N forces the place's version, -Version -1 leaves it alone), then
# drives Study, Study, the heart icon, and -Presses boxes with a screenshot
# each (<Prefix>_01 ...). The meeting before the place is random (4-8 boxes),
# so look at the sheet (.emu/shots/<Prefix>_sheet.png) and continue by hand
# or with date_choices.ps1. The forcer's log is .emu\date_run.log. Keep your
# hands off the emulator meanwhile.
param([Parameter(Mandatory)][int]$Place, [int]$Version = -1, [int]$Girl = 0, [int]$Presses = 6, [string]$Prefix = "",
      [string]$State = ".emu\savestates_backup\dates_sunday_0423_candidate.sav",
      [string]$Build = "review_dates", [string]$Extra = "", [string]$Break = "")
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Prefix) { $Prefix = "p${Place}v${Version}" }
& "$here\launch_state.ps1" -State $State -Build $Build
$forceArgs = @("tools/emu/force_date.py", "$Girl", "$Place", "4", "30", "--timeout", "400")
if ($Version -ge 0) { $forceArgs += @("--version", "$Version") }
if ($Extra) { $forceArgs += $Extra.Split(" ") }
if ($Break) { $forceArgs += @("--") + $Break.Split(" ") }
# A detached process, so rules that fire late in the date (ending, going
# home) outlive this script; its output goes to .emu\date_run.log.
$quoted = $forceArgs | ForEach-Object { if ($_ -match " ") { "`"$_`"" } else { $_ } }
Start-Process python -ArgumentList $quoted -WindowStyle Hidden -RedirectStandardOutput .emu\date_run.log -RedirectStandardError .emu\date_run.err | Out-Null
Start-Sleep -Seconds 3
$seq = "C,wait:12000,C,wait:12000,C,wait:7000"
$names = @()
for ($i = 1; $i -le $Presses; $i++) { $n = "{0}_{1:D2}" -f $Prefix, $i; $seq += ",C,wait:3200,shot:$n"; $names += $n }
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$here\drive.ps1" -Seq $seq | Out-Null
Get-Content .emu\date_run.log, .emu\date_run.err -ErrorAction SilentlyContinue
python "$here\contact_sheet.py" ".emu\shots\${Prefix}_sheet.png" @names
"sheet: .emu\shots\${Prefix}_sheet.png"
