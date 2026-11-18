<#
    TATAR Triage Toolkit - finding identity tests (Windows edition, schema 1.7).
    Functions are lifted from Tatar.ps1 with the parser. The golden vectors in
    tests/fixtures/identity-vectors.tsv are shared with test-identity.sh and
    tests/identity_ref.py. Source is ASCII only.

        pwsh -NoProfile -File tests/Test-Identity.ps1
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
foreach ($n in @('Get-HashText', 'Get-FindingIdentity', 'Get-EvidenceSection', 'Set-FindingIdentity')) {
    $def = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true)
    if (-not $def) { Write-Host ('FAIL  ' + $n + ' not found'); exit 1 }
    . ([scriptblock]::Create($def.Extent.Text))
}
Write-Host "`nI1  golden vectors"
$vec = Join-Path $PSScriptRoot 'fixtures\identity-vectors.tsv'
foreach ($line in [IO.File]::ReadAllLines($vec, [Text.Encoding]::UTF8)) {
    if (-not $line -or $line.StartsWith('#')) { continue }
    $f = $line.Split("`t")
    $paths = if ($f[7]) { @($f[7] -split ';;') } else { @() }
    $r = Get-FindingIdentity -Module $f[0] -ArtifactClass $f[1] -Category $f[2] -Message $f[3] -Detail $f[4] -Severity $f[5] -Confidence $f[6] -Paths $paths
    $tag = $f[3]; if ($tag.Length -gt 48) { $tag = $tag.Substring(0, 48) }
    Check "I1 : fingerprint  $tag" ($r.fingerprint -eq $f[8]) "expected $($f[8]) got $($r.fingerprint)"
    Check "I1 : contentHash  $tag" ($r.contentHash -eq $f[9]) "expected $($f[9]) got $($r.contentHash)"
}
Write-Host "`nI2  properties"
function Fp { param($Msg, $Paths = @('/a'), $Mod = 'm') (Get-FindingIdentity -Module $Mod -ArtifactClass 'c' -Category 'k' -Message $Msg -Detail '' -Severity 'High' -Confidence '0.7' -Paths $Paths).fingerprint }
Check 'I2 : a PID does not change the fingerprint' ((Fp 'Process PID 1 started') -eq (Fp 'Process PID 99999 started'))
Check 'I2 : a port number is NOT masked' ((Fp 'Listener 8080') -ne (Fp 'Listener 8081'))
Check 'I2 : path order does not matter' ((Fp 'x' @('/a', '/b')) -eq (Fp 'x' @('/b', '/a')))
Check 'I2 : module is part of the identity' ((Fp 'x' @('/a') 'm') -ne (Fp 'x' @('/a') 'm2'))
Write-Host "`nI3  Set-FindingIdentity"
$script:ReportFile = 'C:\o\TATAR_Report_h.txt'
$f = [pscustomobject]@{ module = 'process'; artifactClass = 'process'; category = 'Process'; message = 'Suspicious process PID 4 in temp'; detail = 'd'; severity = 'High'; confidence = 0.7; paths = @('C:\x.exe') }
Set-FindingIdentity -Findings @($f)
Check 'I3 : fingerprint and contentHash are 16 hex' (($f.fingerprint -match '^[0-9a-f]{16}$') -and ($f.contentHash -match '^[0-9a-f]{16}$'))
Check 'I3 : evidence names the report and section' ((@($f.evidence).Count -eq 1) -and ($f.evidence[0].file -eq 'TATAR_Report_h.txt') -and ($f.evidence[0].section -like '03 Processes*'))
Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
