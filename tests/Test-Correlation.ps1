<#
    TATAR Triage Toolkit - evidence correlation unit tests (Windows edition).

    Invoke-EvidenceCorrelation is the one place in the tool that RAISES the
    confidence of a finding on the strength of ANOTHER finding, so the ways it
    must NOT fire matter at least as much as the way it must:

      - a module agreeing with itself is one artifact seen twice, not two
        artifacts agreeing, and must raise nothing
      - a suppressed finding was already judged known-good by the allowlist;
        correlating on it would re-raise exactly the noise the allowlist removed
      - an IOC hit already carries 0.95 and must not be demoted to 0.85
      - the Windows filesystem is case-INSENSITIVE, so C:\Temp\x.exe and
        c:\temp\X.EXE are the same file and MUST correlate (the Linux edition
        is the mirror image of this case, and asserts the opposite)
      - severity, message, module and paths may not change: correlation makes an
        existing lead more credible, it does not make a new claim

    These cases are the Windows half of a pair. tests/test-correlation.sh
    asserts the same rules against the shell edition, and
    check_contract_parity.py holds the two harnesses to the same claims.

    The function and the rule table are both lifted out of the collector by
    text: dot sourcing Tatar.ps1 would run a collection, and a test carrying its
    own copy of the rules would pass while the shipped rules were broken.

    Run from the repo root:
        powershell -NoProfile -File tests\Test-Correlation.ps1

    Exit code: 0 = all cases passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param([string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'))

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0

function Lift-Block {
    param([string]$Src, [string]$Needle)
    $start = $Src.IndexOf($Needle)
    if ($start -lt 0) { throw "not found: $Needle" }
    $depth = 0; $i = $Src.IndexOf('{', $start)
    while ($i -lt $Src.Length) {
        if     ($Src[$i] -eq '{') { $depth++ }
        elseif ($Src[$i] -eq '}') { $depth--; if ($depth -eq 0) { break } }
        $i++
    }
    if ($depth -ne 0) { throw "could not delimit: $Needle" }
    return $Src.Substring($start, $i - $start + 1)
}

$src = [IO.File]::ReadAllText($Collector)
try {
    Invoke-Expression (Lift-Block -Src $src -Needle 'function Invoke-EvidenceCorrelation')
} catch {
    Write-Host "FAIL  could not lift Invoke-EvidenceCorrelation: $_" -ForegroundColor Red; exit 1
}
# the rule table is an array literal, not a block: take it line by line
$ruleStart = $src.IndexOf('$script:CorrelationRules = @(')
if ($ruleStart -lt 0) { Write-Host 'FAIL  CorrelationRules not found in the collector' -ForegroundColor Red; exit 1 }
$ruleEnd = $src.IndexOf("`n)", $ruleStart)
Invoke-Expression $src.Substring($ruleStart, $ruleEnd - $ruleStart + 2)
Write-Host ("Lifted Invoke-EvidenceCorrelation and {0} rule(s) from {1}" -f @($script:CorrelationRules).Count, (Split-Path $Collector -Leaf))
Write-Host ("Rules under test: {0}" -f (($script:CorrelationRules | ForEach-Object { $_.Id }) -join ', '))
Write-Host ''

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host "  ok   $Label"; $script:pass++ }
    else {
        Write-Host "  FAIL $Label" -ForegroundColor Red
        if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkYellow }
        $script:fail++
    }
}

function New-F {
    param([string]$Id, [string]$Sev, [string]$Module, [string[]]$Paths,
          [double]$Conf, [bool]$Suppressed = $false, [bool]$Ioc = $false)
    [pscustomobject]@{
        id = $Id; severity = $Sev; category = $Module; technique = @('T1059')
        message = 'msg'; detail = 'detail'; confidence = $Conf
        confidenceReason = 'original reason'; suppressed = $Suppressed
        suppressReason = ''; iocMatch = $Ioc; iocIndicator = ''
        module = $Module; collected_at = '2026-01-01T00:00:00Z'; paths = @($Paths)
    }
}

Write-Host '-- COR-01 fires when motw and useractivity name the same path --'
$a = New-F 'TTR-F-001' 'Review' 'motw'         @('C:\Users\A\Downloads\x.exe') 0.4
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('C:\Users\A\Downloads\x.exe') 0.7
$n = Invoke-EvidenceCorrelation -Findings @($a, $b)
Check 'T1 : both sides were raised (count = 2)' ($n -eq 2) "got $n"
Check 'T2 : motw confidence is 0.85'         ($a.confidence -eq 0.85) "got $($a.confidence)"
Check 'T3 : useractivity confidence is 0.85' ($b.confidence -eq 0.85) "got $($b.confidence)"
Check 'T4 : the reason names the rule id'       ($a.confidenceReason -like '*COR-01*')                $a.confidenceReason
Check 'T5 : the reason names the rule'          ($a.confidenceReason -like '*download-then-execute*') $a.confidenceReason
Check 'T6 : the reason names BOTH modules'      ($a.confidenceReason -like '*motw*useractivity*')      $a.confidenceReason
Check 'T7 : the reason names the other finding' ($a.confidenceReason -like '*TTR-F-002*')              $a.confidenceReason
Check 'T8 : the reason names the shared path'   ($a.confidenceReason -like '*downloads\x.exe*')        $a.confidenceReason
Check 'T9 : severity was NOT changed'           ($a.severity -eq 'Review')  "got $($a.severity)"
Check 'T10: module was NOT changed'             ($a.module -eq 'motw')      "got $($a.module)"
Check 'T11: paths were NOT changed'             (@($a.paths).Count -eq 1)   "got $(@($a.paths).Count)"

Write-Host '-- COR-02: an autorun entry pointing at a suspect file --'
$a = New-F 'TTR-F-001' 'Review' 'persistence' @('C:\Users\Public\run.exe') 0.4
$b = New-F 'TTR-F-002' 'Review' 'indicators'  @('C:\Users\Public\run.exe') 0.4
$n = Invoke-EvidenceCorrelation -Findings @($a, $b)
Check 'T12: COR-02 fires across persistence + indicators' ($n -eq 2) "got $n"
Check 'T13: and names COR-02' ($a.confidenceReason -like '*COR-02*') $a.confidenceReason

Write-Host '-- the ways it must NOT fire --'
$a = New-F 'TTR-F-001' 'Review' 'motw' @('C:\x.exe') 0.4
$b = New-F 'TTR-F-002' 'Review' 'motw' @('C:\x.exe') 0.4
Check 'T14: a module agreeing with ITSELF raises nothing' ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 0)

$a = New-F 'TTR-F-001' 'Review' 'motw'         @('C:\x.exe') 0.4 $true
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('C:\x.exe') 0.7
Check 'T15: a SUPPRESSED finding does not correlate' ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 0)
Check 'T16: and the other side keeps its confidence'  ($b.confidence -eq 0.7) "got $($b.confidence)"

$a = New-F 'TTR-F-001' 'High' 'motw'         @('C:\x.exe') 0.95 $false $true
$b = New-F 'TTR-F-002' 'High' 'useractivity' @('C:\x.exe') 0.7
$n = Invoke-EvidenceCorrelation -Findings @($a,$b)
Check 'T17: an IOC hit is not demoted to 0.85' ($a.confidence -eq 0.95) "got $($a.confidence)"
Check 'T18: and it does not correlate' ($n -eq 0) "got $n"

$a = New-F 'TTR-F-001' 'Review' 'motw'         @('C:\x.exe') 0.4
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('C:\y.exe') 0.7
Check 'T19: different paths raise nothing' ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 0)

$a = New-F 'TTR-F-001' 'Review' 'users'   @('C:\x.exe') 0.4
$b = New-F 'TTR-F-002' 'High'   'process' @('C:\x.exe') 0.7
Check 'T20: modules no rule names raise nothing' ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 0)

$a = New-F 'TTR-F-001' 'Review' 'motw'         @('') 0.4
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('') 0.7
Check 'T21: findings with no path raise nothing' ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 0)

Check 'T22: an empty finding set returns 0, not an error' ((Invoke-EvidenceCorrelation -Findings @()) -eq 0)

Write-Host '-- Windows case folding and a second run --'
$a = New-F 'TTR-F-001' 'Review' 'motw'         @('C:\Temp\X.EXE') 0.4
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('c:\temp\x.exe') 0.7
Check 'T23: the Windows filesystem is case-INSENSITIVE - these DO correlate' `
      ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 2) `
      'the Linux edition asserts the opposite, by design'

$a = New-F 'TTR-F-001' 'Review' 'motw'         @('C:\x.exe') 0.4
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('C:\x.exe') 0.7
Invoke-EvidenceCorrelation -Findings @($a,$b) | Out-Null
$before = $a.confidenceReason
$n = Invoke-EvidenceCorrelation -Findings @($a,$b)
Check 'T24: a second run is idempotent (raises nothing more)' ($n -eq 0) "got $n"
Check 'T25: and leaves the reason unchanged' ($a.confidenceReason -eq $before)

Write-Host '-- multiple paths in one finding --'
$a = New-F 'TTR-F-001' 'Review' 'motw'         @('C:\clean.exe','C:\x.exe') 0.4
$b = New-F 'TTR-F-002' 'High'   'useractivity' @('C:\x.exe') 0.7
Check "T26: agreement on ANY of a finding's paths is enough" `
      ((Invoke-EvidenceCorrelation -Findings @($a,$b)) -eq 2)

Write-Host ''
Write-Host '-------------------------------------------'
Write-Host ("passed: {0}   failed: {1}" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
