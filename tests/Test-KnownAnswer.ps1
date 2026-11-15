<#
    TATAR Triage Toolkit - known-answer verification (Windows edition).

    Every other test here proves something about a run on the machine it runs
    on. None of them lets an OPERATOR answer the question a forensic tool is
    supposed to answer before it touches evidence: does this build, on this
    machine, behave correctly on data whose correct answer is already known?

    That is what this is. It replays a RECORDED finding set through the real
    analysis code lifted out of the collector, and checks the result against a
    known answer worked out from the rules rather than from what the code
    happens to do. Nothing is collected, nothing on the host is touched, and
    the outcome cannot drift with the machine - so a mismatch is the build,
    not the environment.

    Deliberately NOT a --self-test that plants suspicious-looking artifacts and
    checks they are found: on Windows that is a Defender detection waiting to
    happen, and this tool's first constraint is that it does not trip AV.

    Run from the repo root:  powershell -NoProfile -File tests\Test-KnownAnswer.ps1
    Exit: 0 the build agrees with the known answer, 1 it does not.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Fixture   = (Join-Path $PSScriptRoot 'fixtures\known-answer\findings.json'),
    [string]$Expected  = (Join-Path $PSScriptRoot 'fixtures\known-answer\expected.json')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Check { param([string]$L,[bool]$Ok,[string]$D='')
    if ($Ok) { Write-Host "  ok   $L"; $script:pass++ }
    else { Write-Host "  FAIL $L" -ForegroundColor Red; if ($D) { Write-Host "       $D" -ForegroundColor DarkYellow }; $script:fail++ } }

function Lift { param([string]$Src,[string]$Needle)
    $st = $Src.IndexOf($Needle); if ($st -lt 0) { throw "not found: $Needle" }
    $d = 0; $i = $Src.IndexOf('{', $st)
    while ($i -lt $Src.Length) { if ($Src[$i] -eq '{') { $d++ } elseif ($Src[$i] -eq '}') { $d--; if ($d -eq 0) { break } }; $i++ }
    return $Src.Substring($st, $i - $st + 1) }

$src = [IO.File]::ReadAllText($Collector)
Invoke-Expression (Lift $src 'function Invoke-EvidenceCorrelation')
$rm = [regex]::Match($src, '\$script:CorrelationRules\s*=\s*@\((.*?)\n\)', 'Singleline')
Invoke-Expression ('$script:CorrelationRules = @(' + $rm.Groups[1].Value + "`n)")

$doc = Get-Content $Fixture  -Raw | ConvertFrom-Json
$exp = Get-Content $Expected -Raw | ConvertFrom-Json
$f   = @($doc.findings)
Write-Host ("Replaying {0} recorded findings through {1}" -f $f.Count, (Split-Path $Collector -Leaf))
Write-Host ''

Check "the recorded document still has the shape the answer was written for" `
      ($f.Count -eq $exp.findingsCount -and @($f | Where-Object { $_.suppressed }).Count -eq $exp.suppressedCount)

# ---- the analysis under test -------------------------------------------------
$n = Invoke-EvidenceCorrelation -Findings $f
$raised = @($f | Where-Object { [double]$_.confidence -eq 0.85 } | ForEach-Object { $_.id } | Sort-Object)
$want   = @($exp.correlation.raisedTo085 | Sort-Object)
Check ("correlation raises exactly {0}" -f ($want -join ', ')) `
      ((($raised -join ',') -eq ($want -join ','))) ("got: " + ($raised -join ', '))
Check "the count it reports equals the number it changed" ($n -eq $want.Count) "got $n"

foreach ($p in $exp.correlation.mustNotRise.PSObject.Properties) {
    $x = @($f | Where-Object { $_.id -eq $p.Name })[0]
    Check ("{0} must not rise - {1}" -f $p.Name, $p.Value) ([double]$x.confidence -ne 0.85) "confidence $($x.confidence)"
}

# ---- invariants that must hold whatever the data ----------------------------
$ladder = @($exp.confidenceLadder)
$badC = @($f | Where-Object { $ladder -notcontains [double]$_.confidence })
Check "every confidence is on the declared ladder" ($badC.Count -eq 0) (($badC | ForEach-Object { "$($_.id)=$($_.confidence)" }) -join ',')

$sev = @($f | Where-Object { $_.severity -notin 'High','Review' })
Check "correlation did not change any severity" ($sev.Count -eq 0) (($sev | ForEach-Object { $_.id }) -join ',')

$vm = [regex]::Match($src, '\$script:ArtifactClasses\s*=\s*@\((.*?)\n\)', 'Singleline')
$vocab = @([regex]::Matches($vm.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
$badK = @($f | Where-Object { $vocab -notcontains $_.artifactClass })
Check "every recorded artifactClass is still in the shipped vocabulary" ($badK.Count -eq 0) (($badK | ForEach-Object { "$($_.id)=$($_.artifactClass)" }) -join ',')

$present = @($f | ForEach-Object { $_.artifactClass } | Sort-Object -Unique)
Check "the recorded classes are the ones the answer expects" `
      ((($present -join ',') -eq (@($exp.classesPresent) -join ','))) ("got: " + ($present -join ', '))

Write-Host ''
Write-Host ("known answer: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
