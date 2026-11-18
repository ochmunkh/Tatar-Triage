<#
    TATAR Triage Toolkit - hosts "stock line" unit tests (Windows edition).

    The hosts finding counts custom entries. A line is stock only if its address
    AND every name on it are ones the operating system ships, so that

        127.0.0.1 update.vendor.example
        203.0.113.9 login.bank.example 127.0.0.1

    are reported rather than hidden by the loopback address they contain.

    Case table shared with tests/test-hosts-default.sh, so both editions are
    held to the same rule. Test-HostsDefault is lifted out of the collector by
    text.

    Run from the repo root: powershell -NoProfile -File tests\Test-HostsDefault.ps1
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\hosts-default-cases.tsv')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$src = [IO.File]::ReadAllText($Collector)
$fn = 'function Test-HostsDefault'
$st = $src.IndexOf($fn)
if ($st -lt 0) { Write-Host "FAIL  $fn not found" -ForegroundColor Red; exit 1 }
$d = 0; $i = $src.IndexOf('{', $st)
while ($i -lt $src.Length) { if ($src[$i] -eq '{') { $d++ } elseif ($src[$i] -eq '}') { $d--; if ($d -eq 0) { break } }; $i++ }
Invoke-Expression $src.Substring($st, $i - $st + 1)
Write-Host ("Lifted Test-HostsDefault from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''
function Check { param([string]$L,[bool]$Ok,[string]$D='')
    if ($Ok) { Write-Host "  ok   $L"; $script:pass++ }
    else { Write-Host "  FAIL $L" -ForegroundColor Red; if ($D) { Write-Host "       $D" -ForegroundColor DarkYellow }; $script:fail++ } }

foreach ($line in (Get-Content $Cases)) {
    if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
    $c = $line -split "`t"
    if ($c.Count -lt 3) { continue }
    $got = if (Test-HostsDefault $c[0] 'myhost') { 'default' } else { 'custom' }
    Check $c[2] ($got -eq $c[1]) "[$($c[0])] expected $($c[1]), got $got"
}

foreach ($l in @('', '   ', '# 127.0.0.1 localhost', '   # a comment')) {
    Check "not an entry: [$l]" (Test-HostsDefault $l 'myhost') 'a blank or comment-only line was counted'
}
Check 'TAB-separated fields read like space-separated ones' (Test-HostsDefault "127.0.0.1`tlocalhost" 'myhost')
Check 'a wildcard character in a name is compared as text' (-not (Test-HostsDefault '127.0.0.1 *' 'myhost'))
Check '127.0.1.1 is custom when the host name is unknown' (-not (Test-HostsDefault '127.0.1.1 myhost' ''))

Write-Host ''
Write-Host ("hosts stock lines: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
