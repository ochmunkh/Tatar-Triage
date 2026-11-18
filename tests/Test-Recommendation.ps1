<#
    TATAR Triage Toolkit - recommendation tests (Windows edition, schema 1.8).
    Get-Recommendation is lifted from Tatar.ps1 with the parser and compared with
    tests/fixtures/recommendations.tsv, the reference shared with
    test-recommendation.sh. Source is ASCII only.

        pwsh -NoProfile -File tests/Test-Recommendation.ps1
    Exit code: 0 = all passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param([string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'))
$ErrorActionPreference = 'Continue'
$script:Pass = 0; $script:Fail = 0
function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { $script:Pass++; Write-Host ('  PASS  ' + $Name) -ForegroundColor Green }
    else { $script:Fail++; Write-Host ('  FAIL  ' + $Name + '  ' + $Detail) -ForegroundColor Red }
}
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Collector).Path, [ref]$tokens, [ref]$errs)
$def = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Get-Recommendation' }, $true)
if (-not $def) { Write-Host 'FAIL  Get-Recommendation not found'; exit 1 }
. ([scriptblock]::Create($def.Extent.Text))
Write-Host "`nR1  shared reference"
$ref = Join-Path $PSScriptRoot 'fixtures\recommendations.tsv'
foreach ($line in [IO.File]::ReadAllLines($ref, [Text.Encoding]::UTF8)) {
    if (-not $line) { continue }
    $f = $line.Split("`t")
    $probe = $f[0]; if ($probe -eq '*') { $probe = 'no-such-category' }
    $got = Get-Recommendation -Category $probe
    Check ('R1 : category ' + $f[0]) ($got -ceq $f[1]) ('got ' + $got)
    Check ('R2 : text for ' + $f[0] + ' is clean') (($f[1].Length -le 400) -and ($f[1] -cmatch '^[ -~]+$') -and ($f[1] -notmatch '["''\\$`]')) ''
}
Write-Host "`nR3  the finding record carries it"
$src = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Collector).Path)
Check 'R3 : Add-Finding sets recommendation' ($src -match 'recommendation\s*=\s*\(Get-Recommendation -Category \$Category\)') ''
Check 'R3 : the IOC finding sets recommendation' ($src -match "recommendation\s*=\s*\(Get-Recommendation -Category 'ioc'\)") ''
Write-Host ("`nrecommendation tests: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 }
