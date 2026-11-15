<#
    TATAR Triage Toolkit - artifact-class mapping unit tests (Windows edition).

    artifactClass is the axis a suppression or IOC rule aims at. `category` is
    module-grained - persistence covers Run keys, IFEO, Winlogon, scheduled
    tasks and COM hijacks at once - so a finding filed under the wrong class is
    a finding the right rule will never match. A silent miss, which is the
    failure shape this project keeps correcting for.

    The case table is shared with tests/test-artifact-class.sh, so both editions
    are held to one vocabulary and the rows common to both are asserted twice.

    Get-ArtifactClass and the vocabulary are lifted out of the collector by
    text: dot sourcing Tatar.ps1 would run a collection, and a harness carrying
    its own copy of the list would pass while the shipped one was broken.

    Run from the repo root:  powershell -NoProfile -File tests\Test-ArtifactClass.ps1
    Exit: 0 all passed, 1 at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\artifact-class-cases.tsv')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

$src = [IO.File]::ReadAllText($Collector)
$start = $src.IndexOf('function Get-ArtifactClass')
if ($start -lt 0) { Write-Host 'FAIL  Get-ArtifactClass not found' -ForegroundColor Red; exit 1 }
$depth = 0; $i = $src.IndexOf('{', $start)
while ($i -lt $src.Length) {
    if     ($src[$i] -eq '{') { $depth++ }
    elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
    $i++
}
Invoke-Expression $src.Substring($start, $i - $start + 1)

$vm = [regex]::Match($src, '\$script:ArtifactClasses\s*=\s*@\((.*?)\n\)', 'Singleline')
$vocab = @([regex]::Matches($vm.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
if ($vocab.Count -lt 10) { Write-Host 'FAIL  could not lift $script:ArtifactClasses' -ForegroundColor Red; exit 1 }
Write-Host ("Lifted Get-ArtifactClass and {0} classes from {1}" -f $vocab.Count, (Split-Path $Collector -Leaf))
Write-Host ''

function Check { param([string]$L,[bool]$Ok,[string]$D='')
    if ($Ok) { Write-Host "  ok   $L"; $script:pass++ }
    else { Write-Host "  FAIL $L" -ForegroundColor Red; if ($D) { Write-Host "       $D" -ForegroundColor DarkYellow }; $script:fail++ }
}

foreach ($line in (Get-Content $Cases)) {
    if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
    $c = $line -split "`t"
    if ($c.Count -lt 5 -or $c[0] -ne 'windows') { continue }
    $cat = $c[1]; $msg = $c[2]; $det = $(if ($c[3] -eq '-') { '' } else { $c[3] }); $expect = $c[4]
    $got = Get-ArtifactClass -Category $cat -Message $msg -Detail $det
    Check ("{0} -> {1}" -f $cat, $expect) ($got -eq $expect) "got '$got'"
    Check ("{0} : '{1}' is in the declared vocabulary" -f $cat, $got) ($vocab -contains $got)
}

Write-Host ''
Write-Host ("artifact class mapping: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
