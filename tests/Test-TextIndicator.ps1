<#
    TATAR Triage Toolkit - text indicator and Office macro marker unit tests
    (Windows edition).

    Get-TextIndicator flags a credential dump by another program, or a URL
    written in hex or base64, in text the run collected (command lines, the
    PowerShell history, event 4688). The case table is shared with
    tests/test-text-indicator.sh. Get-OfficeMacroMarker says whether an Office
    file carries a VBA project from its bytes alone; it is tested here with
    synthetic bytes, so no document with a macro is stored in the repository.

    The functions and the rule table are lifted out of the collector by text:
    dot sourcing Tatar.ps1 would run a collection.

    Run from the repo root: powershell -NoProfile -File tests\Test-TextIndicator.ps1
    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\text-indicator-cases.tsv')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$src = [IO.File]::ReadAllText($Collector)
function Get-Block { param([string]$Start, [char]$Open, [char]$Close)
    $st = $src.IndexOf($Start)
    if ($st -lt 0) { Write-Host "FAIL  '$Start' not found" -ForegroundColor Red; exit 1 }
    $d = 0; $i = $src.IndexOf($Open, $st)
    while ($i -lt $src.Length) { if ($src[$i] -eq $Open) { $d++ } elseif ($src[$i] -eq $Close) { $d--; if ($d -eq 0) { break } }; $i++ }
    $src.Substring($st, $i - $st + 1) }
Invoke-Expression (Get-Block '$script:CredDumpRules = @(' '(' ')')
foreach ($fn in 'function Get-TextIndicator', 'function Get-OfficeMacroMarker') { Invoke-Expression (Get-Block $fn '{' '}') }
Write-Host ("Lifted the rule table, Get-TextIndicator and Get-OfficeMacroMarker from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''
function Check { param([string]$L, [bool]$Ok, [string]$D = '')
    if ($Ok) { $script:pass++; Write-Host "  PASS  $L" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $L  $D" -ForegroundColor Red } }

foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $c = $line -split "`t"
    if ($c.Count -lt 3) { continue }
    $ti = Get-TextIndicator $c[0]
    $got = if (-not $ti) { 'none' } elseif ($ti.Kind -eq 'credential dump') { 'credential' } elseif ($ti.Kind -match 'hex') { 'hex' } else { 'base64' }
    $note = if ($c.Count -gt 3) { $c[3] } else { '' }
    Check ("{0,-10} {1}" -f $c[1], $note) ($got -eq $c[1]) "got $got"
}
Check 'empty text is no indicator' (-not (Get-TextIndicator ''))
Check 'a credential dump outranks an encoded URL on the same line' ((Get-TextIndicator 'rundll32 comsvcs.dll MiniDump aHR0cHM6Ly').Kind -eq 'credential dump')

# Office macro marker, from synthetic bytes only
$latin = [Text.Encoding]::GetEncoding(28591)
function B { param([string]$S) $latin.GetBytes($S) }
$zipWith    = B ("PK" + [char]3 + [char]4 + ('x' * 40) + 'word/vbaProject.bin' + ('y' * 40))
$zipWithout = B ("PK" + [char]3 + [char]4 + ('x' * 40) + 'word/document.xml' + ('y' * 40))
$oleWith    = B ([string][char]0xD0 + [char]0xCF + [char]0x11 + [char]0xE0 + ('z' * 40) + "_`0V`0B`0A`0_`0P`0R`0O`0J`0E`0C`0T`0" + ('z' * 40))
$oleAscii   = B ([string][char]0xD0 + [char]0xCF + [char]0x11 + [char]0xE0 + ('z' * 40) + '_VBA_PROJECT written as plain text' + ('z' * 40))
Check 'OOXML with vbaProject.bin carries a macro'      ((Get-OfficeMacroMarker $zipWith) -eq 'vbaProject.bin')
Check 'OOXML without vbaProject.bin carries none'      ((Get-OfficeMacroMarker $zipWithout) -eq '')
Check 'OLE with the UTF-16 _VBA_PROJECT stream name'    ((Get-OfficeMacroMarker $oleWith) -eq '_VBA_PROJECT')
Check 'the ASCII text _VBA_PROJECT is not a stream name' ((Get-OfficeMacroMarker $oleAscii) -eq '')
Check 'an empty file carries none'                     ((Get-OfficeMacroMarker ([byte[]]@())) -eq '')

Write-Host ''
Write-Host ("text indicators: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
