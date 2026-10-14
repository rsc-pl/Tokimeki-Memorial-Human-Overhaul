# Restart the isolated DuckStation from a save state, visible by default.
#
#   powershell.exe -File tools\emu\launch_state.ps1 -State .emu\savestates_backup\X.sav [-Build review_dates] [-Hidden]
#
# -Hidden (or the environment variable TOKI_EMU_HIDDEN=1, which reaches the
# scripts that call this one) starts it with a hidden window, so someone
# working on the same desktop can't send it input; drive.ps1 still finds it.
#
# -Build names a folder under .emu holding a patched CUE, or "orig" for the
# unpatched disc. NOTE: DuckStation reopens the disc the state was made with,
# whatever CUE is passed, so rebuild candidates into the state's own folder
# (docs/testing.md, "Testing date conversations").
param([Parameter(Mandatory)][string]$State, [string]$Build = "review_dates", [int]$Wait = 9, [switch]$Hidden)
# Only the isolated instance, never the user's own DuckStation.
Get-Process duckstation* -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*\.emu\duckstation\*" } | Stop-Process -Force -Confirm:$false
Start-Sleep -Seconds 2
$root = (Get-Location).Path
$name = "Tokimeki Memorial - Forever with You (Japan) (PlayStation the Best).cue"
$cue = if ($Build -eq "orig") { "$root\Tokimeki Memorial - Forever with You (Japan) (PlayStation the Best)\$name" } else { "$root\.emu\$Build\$name" }
$statePath = (Resolve-Path $State).Path
$style = if ($Hidden -or $env:TOKI_EMU_HIDDEN -eq "1") { "Hidden" } else { "Normal" }
Start-Process .emu\duckstation\duckstation-qt-x64-ReleaseLTCG.exe -WindowStyle $style -ArgumentList '-batch','-statefile',"`"$statePath`"","`"$cue`""
Start-Sleep -Seconds $Wait
"launched $State ($Build)"
