<#
    TATAR Triage Toolkit - public address unit tests (Windows edition).

    external_ips.txt lists the public addresses of established connections, for
    the analyst to look up afterwards. A private, documentation or loopback
    address in it is noise; a public one missing from it is a lead lost. This
    runs Test-PublicAddress against the case table the Linux tests use, so both
    editions hold the same rule. The function is lifted out of the collector by
    text: dot sourcing Tatar.ps1 would run a collection.

    Run from the repo root: powershell -NoProfile -File tests\Test-PublicAddress.ps1
    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\public-address-cases.tsv')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$src = [IO.File]::ReadAllText($Collector)
$fn = 'function Test-PublicAddress'
$st = $src.IndexOf($fn)
if ($st -lt 0) { Write-Host "FAIL  $fn not found" -ForegroundColor Red; exit 1 }
$d = 0; $i = $src.IndexOf('{', $st)
while ($i -lt $src.Length) { if ($src[$i] -eq '{') { $d++ } elseif ($src[$i] -eq '}') { $d--; if ($d -eq 0) { break } }; $i++ }
Invoke-Expression $src.Substring($st, $i - $st + 1)
Write-Host ("Lifted Test-PublicAddress from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''
foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $c = $line -split "`t"
    if ($c.Count -lt 2) { continue }
    $got = if (Test-PublicAddress $c[0]) { 'public' } else { 'not' }
    $note = if ($c.Count -gt 2) { $c[2] } else { '' }
    if ($got -eq $c[1]) { $pass++; Write-Host ("  PASS  {0,-28} {1}" -f $c[0], $note) -ForegroundColor Green }
    else { $fail++; Write-Host ("  FAIL  {0,-28} expected {1}, got {2}  --  {3}" -f $c[0], $c[1], $got, $note) -ForegroundColor Red }
}
foreach ($x in @('', '   ')) {
    if (-not (Test-PublicAddress $x)) { $pass++; Write-Host "  PASS  [$x] is not an address" -ForegroundColor Green }
    else { $fail++; Write-Host "  FAIL  [$x] was taken for a public address" -ForegroundColor Red }
}
Write-Host ''
Write-Host ("public addresses: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
