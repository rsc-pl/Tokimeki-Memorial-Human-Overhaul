# Force a walk home from school with a girl and screenshot the boxes.
#
#   powershell.exe -File tools\emu\walk_run.ps1 -Girl 0 [-Rank 0] [-Topic 33] [-Presses 14]
#       [-Prefix name] [-Keys "C"] [-State ...] [-Build review_dates]
#
# Launches the Sunday-night state, runs tools/emu/force_walk.py detached
# (log .emu\walk_run.log), picks the first weekly command, then presses
# -Keys (default C, which also takes the first option of any choice) with a
# screenshot per box. Contact sheet: .emu\shots\<Prefix>_sheet.png.
param([Parameter(Mandatory)][int]$Girl, [int]$Rank = -1, [int]$Topic = -1, [int]$Presses = 14,
      [string]$Prefix = "", [string]$Keys = "C",
      [string]$State = ".emu\savestates_backup\dates_sunday_0423_candidate.sav",
      [string]$Build = "review_dates")
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Prefix) { $Prefix = "w${Girl}r${Rank}" }
& "$here\launch_state.ps1" -State $State -Build $Build | Out-Null
$a = @("tools/emu/force_walk.py", "$Girl", "--timeout", "300")
if ($Rank -ge 0) { $a += @("--rank", "$Rank") }
if ($Topic -ge 0) { $a += @("--topic", "$Topic") }
Start-Process python -ArgumentList $a -WindowStyle Hidden -RedirectStandardOutput .emu\walk_run.log -RedirectStandardError .emu\walk_run.err | Out-Null
Start-Sleep -Seconds 3
$seq = "C,wait:10000"
$names = @()
for ($i = 1; $i -le $Presses; $i++) { $n = "{0}_{1:D2}" -f $Prefix, $i; $seq += ",shot:$n,$Keys,wait:3500"; $names += $n }
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$here\drive.ps1" -Seq $seq | Out-Null
Get-Content .emu\walk_run.log, .emu\walk_run.err -ErrorAction SilentlyContinue | Select-Object -First 12
python "$here\contact_sheet.py" ".emu\shots\${Prefix}_sheet.png" @names
"sheet: .emu\shots\${Prefix}_sheet.png"
