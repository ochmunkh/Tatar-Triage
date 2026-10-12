<#
    TATAR Triage Toolkit - allowlist path-extraction unit tests (Windows edition).

    The allowlist, Authenticode-publisher and hash passes can only ever match
    files the extractor found in a finding's message + detail. So whatever
    Get-PathCandidate returns IS the set of files an operator's allowlist can
    reach: a finding whose paths are not extracted is structurally
    unsuppressible, no matter what the allowlist says.

    Get-PathCandidate is lifted out of the collector by text rather than dot
    sourcing it: dot sourcing Tatar.ps1 would run a collection. Same technique
    and the same shared case table shape as tests\Test-IocBoundary.ps1.

    Run from the repo root:
        powershell -NoProfile -File tests\Test-AllowlistPath.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\allowlist-path-cases.tsv')
)

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

# ---- lift Get-PathCandidate out of the collector -----------------------------
$src   = [IO.File]::ReadAllText($Collector)
$start = $src.IndexOf('function Get-PathCandidate')
if ($start -lt 0) { Write-Host 'FAIL  Get-PathCandidate not found in the collector' -ForegroundColor Red; exit 1 }

$depth = 0; $i = $src.IndexOf('{', $start); $open = $i
while ($i -lt $src.Length) {
    if     ($src[$i] -eq '{') { $depth++ }
    elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
    $i++
}
if ($depth -ne 0) { Write-Host 'FAIL  could not delimit Get-PathCandidate' -ForegroundColor Red; exit 1 }
Invoke-Expression $src.Substring($start, $i - $start + 1)
Write-Host ("Lifted Get-PathCandidate from {0} ({1} chars)" -f (Split-Path $Collector -Leaf), ($i - $open))
Write-Host ''

# ---- run the shared case table -----------------------------------------------
foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $f = $line -split "`t"
    if ($f.Count -lt 4) { continue }
    if ($f[0] -ne 'windows') { continue }

    $message   = $f[1]
    $detail    = if ($f[2] -eq '-') { '' } else { $f[2] }   # "-" is the empty-column placeholder
    $expectAll = $f[3]
    $note      = if ($f.Count -gt 5) { $f[5] } else { '' }

    # exactly the blob the collector builds for a finding
    $got = @(Get-PathCandidate "$message $detail")
    $gotStr = if ($got.Count) { $got -join ' ' } else { '-' }

    if ($gotStr -eq $expectAll) {
        $pass++
        Write-Host ("  PASS  {0}" -f $message) -ForegroundColor Green
    } else {
        $fail++
        Write-Host ("  FAIL  {0}" -f $message) -ForegroundColor Red
        Write-Host ("        expected [{0}], got [{1}]  --  {2}" -f $expectAll, $gotStr, $note) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host ("Allowlist path extraction: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
