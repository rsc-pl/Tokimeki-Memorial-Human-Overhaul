# At (or just before) a choice: save a state there, then try every option.
#
#   powershell.exe -File tools\emu\date_choices.ps1 -Prefix p7v2 [-Pre "C,wait:6000,shot:p7v2_rem,C,wait:3000"]
#       [-Options 3] [-Build review_dates]
#
# Runs -Pre (keys that reach the choice list), screenshots the list, presses
# F2 and copies the state to .emu/savestates_backup/<Prefix>_choice.sav, then
# for each option relaunches that state, moves down k times, confirms and
# screenshots the reply (<Prefix>_r<k>) and the box after it. The screen
# order of options is shuffled per date but fixed in the state; the reply
# follows the option chosen, not its position.
param([Parameter(Mandatory)][string]$Prefix, [string]$Pre = "wait:500", [int]$Options = 3,
      [string]$Build = "review_dates")
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$drive = "$here\drive.ps1"
$state = ".emu\savestates_backup\${Prefix}_choice.sav"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $drive -Seq "$Pre,shot:${Prefix}_ch,F2,wait:3000" | Out-Null
Copy-Item .emu\duckstation\savestates\SLPM-86053_1.sav $state -Force
$names = @("${Prefix}_ch")
for ($k = 0; $k -lt $Options; $k++) {
    if ($k -gt 0) { & "$here\launch_state.ps1" -State $state -Build $Build | Out-Null }
    # A freshly loaded state drops presses for a moment.
    $seq = if ($k -gt 0) { "wait:2000," } else { "" }
    for ($d = 0; $d -lt $k; $d++) { $seq += "Down,wait:600," }
    $seq += "shot:${Prefix}_d$k,C,wait:5000,shot:${Prefix}_r$k,C,wait:3200,shot:${Prefix}_r${k}b"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $drive -Seq $seq | Out-Null
    $names += @("${Prefix}_d$k", "${Prefix}_r$k", "${Prefix}_r${k}b")
}
python "$here\contact_sheet.py" ".emu\shots\${Prefix}_choices.png" @names
"sheet: .emu\shots\${Prefix}_choices.png"
