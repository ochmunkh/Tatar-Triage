<#
    TATAR Triage Toolkit - -EncodedCommand pattern unit tests.

    Two collectors look for powershell.exe's -EncodedCommand. They used to do it
    two different ways and were wrong in opposite directions: Collect-Process
    matched the regex '-enc ' and missed every abbreviation, while Collect-ObfScan
    matched the literal '-enc' with -SimpleMatch and flagged every '-Encoding utf8'
    in every ordinary script it read. Both now use one pattern, and this file is
    what keeps that pattern honest in both directions at once.

    The pattern is lifted out of the collector by text rather than dot sourcing
    it: dot sourcing Tatar.ps1 would run a collection.

    Run from the repo root:
        powershell -NoProfile -File tests\Test-EncodedArg.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\encodedarg-cases.tsv')
)

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

$src = [IO.File]::ReadAllText($Collector)
$m = [regex]::Match($src, "(?m)^\s*\`$script:EncArgPattern\s*=\s*'([^']+)'")
if (-not $m.Success) {
    Write-Host 'FAIL  $script:EncArgPattern not found in the collector' -ForegroundColor Red
    exit 1
}
$pattern = $m.Groups[1].Value
Write-Host ("Lifted EncArgPattern from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''

foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $f = $line -split "`t"
    if ($f.Count -lt 2) { continue }
    $text = $f[0]; $expect = $f[1]
    $note = if ($f.Count -gt 2) { $f[2] } else { '' }

    $hit  = [regex]::IsMatch($text, $pattern, 'IgnoreCase')
    $want = ($expect -eq 'match')

    if ($hit -eq $want) {
        $pass++
        Write-Host ("  PASS  {0}" -f $text) -ForegroundColor Green
    } else {
        $fail++
        Write-Host ("  FAIL  {0}" -f $text) -ForegroundColor Red
        Write-Host ("        expected {0}, got {1}  --  {2}" -f $expect, $(if ($hit) { 'match' } else { 'nomatch' }), $note) -ForegroundColor Red
    }
}

# The finding text shows what a pattern means, not the expression behind it.
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
$fn  = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ObfPatternLabel' }, $true)
if (-not $fn) {
    $fail++; Write-Host '  FAIL  Get-ObfPatternLabel not found in the collector' -ForegroundColor Red
} else {
    $script:EncArgPattern = $pattern
    . ([scriptblock]::Create($fn.Extent.Text))
    $labelCases = @(
        @($pattern,         'encoded command argument (-enc / -EncodedCommand)'),
        @('-w\s+hidden',    'hidden window flag (-w hidden)'),
        @('eval\(',         'eval('),
        @('WScript\.Shell', 'WScript.Shell'),
        @('IEX',            'IEX')
    )
    foreach ($c in $labelCases) {
        $got = Get-ObfPatternLabel $c[0]
        if ($got -ceq $c[1]) { $pass++; Write-Host ("  PASS  label for {0}" -f $c[1]) -ForegroundColor Green }
        else { $fail++; Write-Host ("  FAIL  label for {0}: got '{1}'" -f $c[1], $got) -ForegroundColor Red }
    }
    $raw = ([regex]::Matches($src, "Suspicious pattern '\{0\}' in") | Measure-Object).Count
    $used = ([regex]::Matches($src, 'Get-ObfPatternLabel \$first\.Pattern') | Measure-Object).Count
    if ($used -ge 2) { $pass++; Write-Host '  PASS  both obfscan findings use the label' -ForegroundColor Green }
    else { $fail++; Write-Host '  FAIL  an obfscan finding still prints the raw pattern' -ForegroundColor Red }
}
if ($src.Contains('top-level folder(s), the largest: {1}')) { $pass++; Write-Host '  PASS  temp-executable finding names where the files are' -ForegroundColor Green }
else { $fail++; Write-Host '  FAIL  temp-executable finding does not say where the files are' -ForegroundColor Red }
Write-Host ''
Write-Host ("EncodedCommand pattern: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
