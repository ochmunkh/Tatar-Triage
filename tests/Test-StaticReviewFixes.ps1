<#
    TATAR Triage Toolkit - unit tests for the WINDOWS_STATIC_REVIEW fixes that
    have a Linux-testable surface.

    The modules those fixes live in need Win32_*, Get-WinEvent and the registry
    providers, so they never execute off Windows and the contract tests in
    Invoke-Tests.ps1 cannot see any of this. What CAN be tested here is the part
    of each fix that is pure: a classification function that only reads an
    ErrorRecord, and a list literal.

    Covered:
      SE-2  Test-NoMatchingEvents - a Get-WinEvent failure is either "the filter
            matched nothing", which is a CLEAN result, or "the log could not be
            read". Reporting both as "not available / access denied" sent an
            operator on a quiet host off to re-run the collection elevated for
            nothing. Driven from fixtures/winevent-error-cases.tsv.
      PE-3  Collect-Persistence's $runKeys - Run and RunOnce under both hives and
            under the 32-bit Wow6432Node view. HKCU RunOnce and the 32-bit
            RunOnce were missing, so two standard persistence locations produced
            no line in the report, which reads as "nothing there".

    Both are lifted out of the collector by text rather than dot sourcing it:
    dot sourcing Tatar.ps1 would run a collection.

    Run from the repo root:
        pwsh -NoProfile -File tests/Test-StaticReviewFixes.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\winevent-error-cases.tsv')
)

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

$src = [IO.File]::ReadAllText($Collector)

# ---- lift a named function out of the collector -----------------------------
# Returns the source text; the caller runs Invoke-Expression at SCRIPT scope,
# because a function defined inside a helper function dies with that helper.
function Get-CollectorFunction {
    param([string]$Name)
    $start = $src.IndexOf("function $Name")
    if ($start -lt 0) { Write-Host ("FAIL  {0} not found in the collector" -f $Name) -ForegroundColor Red; exit 1 }
    $depth = 0; $i = $src.IndexOf('{', $start)
    while ($i -lt $src.Length) {
        if     ($src[$i] -eq '{') { $depth++ }
        elseif ($src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
        $i++
    }
    if ($depth -ne 0) { Write-Host ("FAIL  could not delimit {0}" -f $Name) -ForegroundColor Red; exit 1 }
    return $src.Substring($start, $i - $start + 1)
}

Invoke-Expression (Get-CollectorFunction 'Test-NoMatchingEvents')
Write-Host ("Lifted Test-NoMatchingEvents from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''

# ---- SE-2: Get-WinEvent failure classification ------------------------------
# A real Get-WinEvent ErrorRecord cannot be produced here, so one is built with
# the same two fields the function reads. Constructed without invocation info,
# FullyQualifiedErrorId is exactly the errorId passed in.
function New-TestErrorRecord {
    param([string]$ErrorId, [string]$Message)
    New-Object System.Management.Automation.ErrorRecord(
        (New-Object System.Exception($Message)),
        $ErrorId,
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null)
}

Write-Host 'SE-2  Get-WinEvent failure: empty log vs unreadable log'
foreach ($line in [IO.File]::ReadAllLines($Cases)) {
    if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
    $f = $line -split "`t"
    if ($f.Count -lt 3) { continue }
    $fqeid  = if ($f[0] -eq '(empty)') { '' } else { $f[0] }
    $msg    = if ($f[1] -eq '(empty)') { '' } else { $f[1] }
    $expect = [bool]($f[2] -eq 'true')
    $note   = if ($f.Count -gt 3) { $f[3] } else { '' }

    $got = [bool](Test-NoMatchingEvents (New-TestErrorRecord -ErrorId $fqeid -Message $msg))
    $label = if ($fqeid) { $fqeid } else { $msg }
    if ($got -eq $expect) {
        $pass++
        Write-Host ("  PASS  {0}" -f $label) -ForegroundColor Green
    } else {
        $fail++
        Write-Host ("  FAIL  {0}" -f $label) -ForegroundColor Red
        Write-Host ("        expected [{0}], got [{1}]  --  {2}" -f $expect, $got, $note) -ForegroundColor Red
    }
}

# A null ErrorRecord is not reachable from the catch block, but the function is
# a predicate other code may reuse and must not throw on one.
if (-not (Test-NoMatchingEvents $null)) {
    $pass++; Write-Host '  PASS  a null ErrorRecord classifies as a real failure' -ForegroundColor Green
} else {
    $fail++; Write-Host '  FAIL  a null ErrorRecord classifies as a real failure' -ForegroundColor Red
}

# ---- PE-3: Run-key coverage -------------------------------------------------
# The list is a literal inside Collect-Persistence, so it is read out of the
# source rather than lifted as a function.
Write-Host ''
Write-Host 'PE-3  Run/RunOnce ASEP coverage in Collect-Persistence'
$m = [regex]::Match($src, '\$runKeys\s*=\s*@\((?<body>[^)]*)\)')
if (-not $m.Success) {
    $fail++; Write-Host '  FAIL  $runKeys literal not found in Collect-Persistence' -ForegroundColor Red
} else {
    $body = $m.Groups['body'].Value
    $required = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $required) {
        # Quoted and comma/paren-terminated, so 'Run' cannot be satisfied by the
        # 'RunOnce' entry that contains it as a prefix.
        if ($body -match ("'" + [regex]::Escape($k) + "'")) {
            $pass++; Write-Host ("  PASS  {0}" -f $k) -ForegroundColor Green
        } else {
            $fail++; Write-Host ("  FAIL  {0} is not collected" -f $k) -ForegroundColor Red
        }
    }
}

Write-Host ''
Write-Host ("Static-review fixes: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
