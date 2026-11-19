<#
    TATAR Triage Toolkit - autostart target unit tests (Windows edition).

    Get-RiskyAutostartFolder decides whether an autostart entry (Run key, Startup
    folder, scheduled task) points into a folder a standard user can write to and
    that ordinary software does not autostart from. The rule is narrow on purpose:
    AppData and ProgramData are left out because OneDrive, Teams, updaters and game
    launchers autostart from there, so these tests pin the quiet cases as hard as
    the loud ones.

    The function is lifted out of the collector by text; dot sourcing Tatar.ps1
    would run a collection.

    Run from the repo root:
        powershell -NoProfile -File tests\Test-AutostartTarget.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param([string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'))

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$src   = [IO.File]::ReadAllText($Collector)
$start = $src.IndexOf('function Get-RiskyAutostartFolder')
if ($start -lt 0) { Write-Host 'FAIL  Get-RiskyAutostartFolder not found in the collector' -ForegroundColor Red; exit 1 }
$depth = 0; $i = $src.IndexOf('{', $start)
while ($i -lt $src.Length) {
    if     ($src[$i] -eq '{') { $depth++ }
    elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
    $i++
}
Invoke-Expression $src.Substring($start, $i - $start + 1)

$cases = @(
    # loud: a standard user can write here and nothing legitimate autostarts from it
    @('"C:\Users\Public\x.exe"',                                  'Users\Public'),
    @('C:\Users\Public\Documents\x.exe -s',                       'Users\Public'),
    @('C:\Windows\Temp\a.exe',                                    'Windows\Temp'),
    @('C:\Users\bob\AppData\Local\Temp\x.exe',                    'a user Temp folder'),
    @('%TEMP%\x.exe',                                             'a user Temp folder'),
    @('C:\Users\bob\Downloads\setup.exe',                         'a Downloads folder'),
    @('C:\$Recycle.Bin\S-1-5-21\x.exe',                           'the Recycle Bin'),
    @('powershell.exe -File C:\Users\Public\r.ps1',               'Users\Public'),
    @('c:\users\public\x.exe',                                    'Users\Public'),
    # quiet: ordinary software, and near misses that must not match
    @('C:\Program Files\App\app.exe',                             ''),
    @('C:\Windows\System32\cmd.exe',                              ''),
    @('C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background', ''),
    @('C:\Users\bob\AppData\Roaming\Microsoft\Teams\Update.exe',  ''),
    @('C:\ProgramData\Wargaming.net\GameCenter\wgc.exe',          ''),
    @('C:\ProgramData\Microsoft\Windows Defender\x.exe',          ''),
    @('C:\Users\Publication\x.exe',                               ''),
    @('C:\Users\bob\Downloadsx\a.exe',                            ''),
    @('C:\Users\bob\Downloads',                                   ''),
    @('',                                                         '')
)
foreach ($c in $cases) {
    $got = Get-RiskyAutostartFolder $c[0]
    if ($got -eq $c[1]) { $pass++; Write-Host ("  PASS  [{0}] -> '{1}'" -f $c[0], $got) -ForegroundColor Green }
    else                { $fail++; Write-Host ("  FAIL  [{0}] expected '{1}', got '{2}'" -f $c[0], $c[1], $got) -ForegroundColor Red }
}
Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}" -f $pass, $fail)
if ($fail -gt 0) { exit 1 } else { exit 0 }
