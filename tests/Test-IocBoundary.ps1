<#
    TATAR Triage Toolkit - IOC boundary unit tests (Windows edition).

    The contract tests in Invoke-Tests.ps1 prove end to end that a truncated
    indicator does not raise a finding. They cannot say WHICH rule rejected it,
    and they are slow because each case runs a collection. These tests call the
    matcher itself against a table shared with the Linux edition, so both
    platforms are held to the same rule and a regression names the exact case.

    Get-IocPattern is lifted out of the collector by text rather than dot
    sourcing it: dot sourcing Tatar.ps1 would run a collection.

    Run from the repo root:
        powershell -NoProfile -File tests\Test-IocBoundary.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\ioc-boundary-cases.tsv')
)

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

# ---- lift the matcher out of the collector ----------------------------------
# Get-IocPattern is the rule. New-IocIndex and Find-IocInText are how a whole
# feed is matched in one pass; they must give the same answer as the rule for
# every case, alone and in a crowded feed.
$src = [IO.File]::ReadAllText($Collector)
foreach ($fn in 'Get-IocPattern', 'New-IocIndex', 'Find-IocInText') {
    $start = $src.IndexOf("function $fn")
    if ($start -lt 0) { Write-Host "FAIL  $fn not found in the collector" -ForegroundColor Red; exit 1 }
    $depth = 0; $i = $src.IndexOf('{', $start)
    while ($i -lt $src.Length) {
        if     ($src[$i] -eq '{') { $depth++ }
        elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
        $i++
    }
    if ($depth -ne 0) { Write-Host "FAIL  could not delimit $fn" -ForegroundColor Red; exit 1 }
    Invoke-Expression $src.Substring($start, $i - $start + 1)
    Write-Host ("Lifted {0} from {1}" -f $fn, (Split-Path $Collector -Leaf))
}

# Decoys of every shape, none of which occurs in any case text.
$decoys = New-Object System.Collections.Generic.List[string]
$rng = New-Object System.Random 7
for ($k = 0; $k -lt 1000; $k++) {
    $decoys.Add(('decoy{0}.example.invalid' -f $k))
    $decoys.Add(('198.18.{0}.{1}' -f [int]($k / 250), ($k % 250)))
    $b = New-Object byte[] 32; $rng.NextBytes($b)
    $decoys.Add((($b | ForEach-Object { $_.ToString('x2') }) -join ''))
}
Write-Host ''

# ---- run the shared case table ----------------------------------------------
foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $f = $line -split "`t"
    if ($f.Count -lt 3) { continue }
    $token = $f[0]; $text = $f[1]; $expect = $f[2]
    $note  = if ($f.Count -gt 3) { $f[3] } else { '' }

    $hit  = [regex]::IsMatch($text, (Get-IocPattern $token), 'IgnoreCase')
    $want = ($expect -eq 'match')

    # The one-pass matcher, with the token alone and among the decoys.
    $alone   = @(Find-IocInText -Text $text -Index (New-IocIndex -Indicators @($token))) -contains $token
    $crowd   = @($decoys) + @($token)
    $crowded = @(Find-IocInText -Text $text -Index (New-IocIndex -Indicators $crowd)) -contains $token
    if ($alone -ne $want -or $crowded -ne $want) {
        $fail++
        Write-Host ("  FAIL  {0,-18} in {1}" -f $token, $text) -ForegroundColor Red
        Write-Host ("        one-pass matcher: alone={0} crowded={1}, expected {2}" -f $alone, $crowded, $expect) -ForegroundColor Red
        continue
    }

    if ($hit -eq $want) {
        $pass++
        Write-Host ("  PASS  {0,-18} in {1}" -f $token, $text) -ForegroundColor Green
    } else {
        $fail++
        Write-Host ("  FAIL  {0,-18} in {1}" -f $token, $text) -ForegroundColor Red
        Write-Host ("        expected {0}, got {1}  --  {2}" -f $expect, $(if ($hit) { 'match' } else { 'nomatch' }), $note) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host ("IOC boundary: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
