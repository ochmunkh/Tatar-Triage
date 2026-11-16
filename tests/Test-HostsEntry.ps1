<#
    TATAR Triage Toolkit - hosts entry unit tests (Windows edition).

    The hosts finding quotes the first few overrides into its detail so the
    analyst sees what was redirected without opening another file. That text
    comes from the suspect host, and a finding's detail is read by the path
    extractor and the allowlist. A crafted line such as

        1.2.3.4  C:\Windows\System32\svchost.exe

    would otherwise put a signed system binary into paths[], and a publisher
    or path rule could then suppress the very finding that reports the
    tampering.

    Case table shared with tests/test-hosts-entry.sh, so both editions are held
    to the same rule. Format-HostsEntry and Get-PathCandidate are lifted out of
    the collector by text.

    Run from the repo root: powershell -NoProfile -File tests\Test-HostsEntry.ps1
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\hosts-entry-cases.tsv')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$src = [IO.File]::ReadAllText($Collector)
foreach ($fn in 'function Format-HostsEntry','function Get-PathCandidate') {
    $st = $src.IndexOf($fn)
    if ($st -lt 0) { Write-Host "FAIL  $fn not found" -ForegroundColor Red; exit 1 }
    $d = 0; $i = $src.IndexOf('{', $st)
    while ($i -lt $src.Length) { if ($src[$i] -eq '{') { $d++ } elseif ($src[$i] -eq '}') { $d--; if ($d -eq 0) { break } }; $i++ }
    Invoke-Expression $src.Substring($st, $i - $st + 1)
}
Write-Host ("Lifted Format-HostsEntry and Get-PathCandidate from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''
function Check { param([string]$L,[bool]$Ok,[string]$D='')
    if ($Ok) { Write-Host "  ok   $L"; $script:pass++ }
    else { Write-Host "  FAIL $L" -ForegroundColor Red; if ($D) { Write-Host "       $D" -ForegroundColor DarkYellow }; $script:fail++ } }

# The detail exactly as the collector builds it, so the path check below is
# made against the real sentence and not against the bare entry.
$fmt = 'First {0} of {1}: {2} | Review hosts.txt in the output folder - static host overrides can redirect traffic (T1565.001)'

foreach ($line in (Get-Content $Cases)) {
    if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
    $c = $line -split "`t"
    if ($c.Count -lt 3) { continue }
    $got = [string](Format-HostsEntry $c[0])
    Check $c[2] ($got -ceq $c[1]) "[$($c[0])] expected [$($c[1])] got [$got]"
    # the property the table exists for, checked on every row rather than
    # trusted to the expected column: the finding must name no file
    $cand = @(Get-PathCandidate ($fmt -f 1, 1, $got))
    if ($cand.Count -ne 0) { Check "$($c[2]) - yields no path candidate" $false ($cand -join ' ; ') }
}

$got = [string](Format-HostsEntry "10.0.0.5`ta.local`tb.local")
Check 'TAB-separated fields read like space-separated ones' ($got -ceq '10.0.0.5 -> a.local b.local') "got [$got]"

$long = '1.2.3.4'
foreach ($n in 1..40) { $long += " alias$n.example" }
$got = [string](Format-HostsEntry $long)
Check 'a line with many aliases is capped at 100 characters' (($got.Length -eq 103) -and $got.EndsWith('...')) "length $($got.Length)"

# The control: the same crafted line, quoted WITHOUT the helper, does plant a
# path. If this ever stops being true the assertions above prove nothing.
$raw = @(Get-PathCandidate ($fmt -f 1, 1, '1.2.3.4 C:\Windows\System32\svchost.exe'))
Check 'control: the raw line would have planted a path' ($raw.Count -ge 1) 'the extractor no longer sees the raw path'

Write-Host ''
Write-Host ("hosts entry: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
