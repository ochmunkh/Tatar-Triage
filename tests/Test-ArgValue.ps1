<#
    TATAR Triage Toolkit - Read-ArgValue unit tests (Windows edition).

    Read-ArgValue is the gate every value-taking flag passes through. It had one
    job already - reject a flag with no value, so '-OutputPath -CaseId IR-1'
    cannot create a directory called '-CaseId' - and one blind spot:

    PowerShell parses 'a,b' in ARGUMENT mode as an array. So the README's own
    example, '.\Tatar.ps1 -Modules network,process', arrives here as a two
    element array when the script is launched from a PowerShell prompt, and
    [string] on an array joins with a SPACE. '-Modules network,process' became
    the single module name 'network process', and the run died with "No valid
    modules were run". Launched from cmd.exe the same flag arrives as a literal
    string and always worked, which is how it survived to 1.4.0.

    Run from the repo root:
        powershell -NoProfile -File tests\Test-ArgValue.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param([string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'))

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

$src   = [IO.File]::ReadAllText($Collector)
$start = $src.IndexOf('function Read-ArgValue')
if ($start -lt 0) { Write-Host 'FAIL  Read-ArgValue not found in the collector' -ForegroundColor Red; exit 1 }
$depth = 0; $i = $src.IndexOf('{', $start)
while ($i -lt $src.Length) {
    if     ($src[$i] -eq '{') { $depth++ }
    elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
    $i++
}
Invoke-Expression $src.Substring($start, $i - $start + 1)
Write-Host ("Lifted Read-ArgValue from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host "  ok   $Label"; $script:pass++ }
    else {
        Write-Host "  FAIL $Label" -ForegroundColor Red
        if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkYellow }
        $script:fail++
    }
}

# the shape that was broken: PowerShell hands over an ARRAY
$r = Read-ArgValue '-Modules' @('network','process')
Check 'T1 : an array value is rejoined with commas, not spaces' ($r -eq 'network,process') "got '$r'"
Check 'T2 : and therefore splits back into the right module names' `
      ((($r -split ',').Count -eq 2) -and (($r -split ',')[1] -eq 'process')) "got '$r'"

$r = Read-ArgValue '-Modules' @('network')
Check 'T3 : a single-element array is just the element' ($r -eq 'network') "got '$r'"

# the shape that always worked: cmd.exe hands over a literal string
$r = Read-ArgValue '-Modules' 'network,process'
Check 'T4 : a literal string is unchanged' ($r -eq 'network,process') "got '$r'"

$r = Read-ArgValue '-OutputPath' 'E:\Evidence'
Check 'T5 : a path with no comma is unchanged' ($r -eq 'E:\Evidence') "got '$r'"

$r = Read-ArgValue '-CaseId' 'IR-2026-001'
Check 'T6 : a value may contain a hyphen as long as it does not START with one' `
      ($r -eq 'IR-2026-001') "got '$r'"

Write-Host ''
Write-Host '-------------------------------------------'
Write-Host ("passed: {0}   failed: {1}" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
