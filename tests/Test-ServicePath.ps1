<#
    TATAR Triage Toolkit - service ImagePath unit tests (Windows edition).

    A service ImagePath is a COMMAND LINE, not a path:
    'C:\Windows\system32\svchost.exe -k netsvcs' is the normal form. Three
    checks depend on pulling the executable back out of it - the SHA-256 feed
    in `hashes`, and the unquoted-path and user-writable-location findings in
    `privesc` - and all three were wrong in the same way, because stripping
    surrounding quotes leaves the arguments attached.

    The contract tests in Invoke-Tests.ps1 cannot see this: the modules that
    use it need Win32_Service and so never run off Windows. These tests call
    the parser itself against a table, so a regression names the exact case.

    Get-ServiceImagePath is lifted out of the collector by text rather than dot
    sourcing it: dot sourcing Tatar.ps1 would run a collection.

    Run from the repo root:
        pwsh -NoProfile -File tests/Test-ServicePath.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\service-path-cases.tsv')
)

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

# ---- lift Get-ServiceImagePath out of the collector -------------------------
$src   = [IO.File]::ReadAllText($Collector)
$start = $src.IndexOf('function Get-ServiceImagePath')
if ($start -lt 0) { Write-Host 'FAIL  Get-ServiceImagePath not found in the collector' -ForegroundColor Red; exit 1 }

$depth = 0; $i = $src.IndexOf('{', $start); $open = $i
while ($i -lt $src.Length) {
    if     ($src[$i] -eq '{') { $depth++ }
    elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
    $i++
}
if ($depth -ne 0) { Write-Host 'FAIL  could not delimit Get-ServiceImagePath' -ForegroundColor Red; exit 1 }
Invoke-Expression $src.Substring($start, $i - $start + 1)
Write-Host ("Lifted Get-ServiceImagePath from {0} ({1} chars)" -f (Split-Path $Collector -Leaf), ($i - $open))
Write-Host ''

# ---- run the case table -----------------------------------------------------
foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $f = $line -split "`t"
    if ($f.Count -lt 2) { continue }
    $pathName = $f[0]; $expect = $f[1]
    $note     = if ($f.Count -gt 2) { $f[2] } else { '' }

    $got = Get-ServiceImagePath $pathName
    $shown = if ($null -eq $got) { '(none)' } else { $got }

    if ($shown -ceq $expect) {
        $pass++
        Write-Host ("  PASS  {0}" -f $pathName) -ForegroundColor Green
    } else {
        $fail++
        Write-Host ("  FAIL  {0}" -f $pathName) -ForegroundColor Red
        Write-Host ("        expected [{0}], got [{1}]  --  {2}" -f $expect, $shown, $note) -ForegroundColor Red
    }
}

# ---- degenerate input the table cannot express ------------------------------
# Win32_Service.PathName is null for a service whose registration is damaged,
# and the callers pipe it in unguarded.
foreach ($case in @(@{ N = 'null PathName'; V = $null }, @{ N = 'empty PathName'; V = '' }, @{ N = 'whitespace PathName'; V = '   ' })) {
    $got = Get-ServiceImagePath $case.V
    if ($null -eq $got) {
        $pass++
        Write-Host ("  PASS  {0} returns null" -f $case.N) -ForegroundColor Green
    } else {
        $fail++
        Write-Host ("  FAIL  {0} returns null  got [{1}]" -f $case.N, $got) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host ("Service ImagePath: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
