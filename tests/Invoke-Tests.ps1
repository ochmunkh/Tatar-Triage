<#
    TATAR Triage Toolkit - contract tests (Windows edition).

    Black-box: runs the collector with controlled allowlist / IOC fixtures and
    asserts the OUTPUT CONTRACT (summary.json). No test touches the collector's
    internals, so these tests keep working across refactors.

    Run from the repo root:
        powershell -NoProfile -File tests\Invoke-Tests.ps1

    Exit code: 0 = all assertions passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Modules   = 'sysinfo,network,users'
)

$ErrorActionPreference = 'Continue'
$script:PassCount = 0
$script:FailCount = 0
$Fixtures = Join-Path $PSScriptRoot 'fixtures'

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { $script:PassCount++; Write-Host ("  PASS  " + $Name) -ForegroundColor Green }
    else     { $script:FailCount++; Write-Host ("  FAIL  " + $Name + "  " + $Detail) -ForegroundColor Red }
}

function Invoke-Collector {
    param([string]$Label, [string[]]$Extra = @())
    $root = Join-Path $env:TEMP ('tatar-test-' + $Label + '-' + (Get-Random))
    $argList = @('-Modules', $Modules, '-Silent', '-OutputPath', $root) + $Extra
    & powershell -NoProfile -File $Collector @argList | Out-Null
    $code = $LASTEXITCODE
    $dir  = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    $path = $null; if ($dir) { $path = $dir.FullName }
    [pscustomobject]@{ Label = $Label; ExitCode = $code; Dir = $path; Root = $root }
}

function Get-Summary {
    param($Run)
    if (-not $Run.Dir) { return $null }
    $f = Join-Path $Run.Dir 'summary.json'
    if (-not (Test-Path $f)) { return $null }
    try { return (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

# ---- the output contract every run must satisfy -------------------------------
function Assert-Contract {
    param($S, [string]$Label)
    Check "$Label : summary.json parses"            ($null -ne $S)
    if ($null -eq $S) { return }

    Check "$Label : schemaVersion is 1.2"           ($S.schemaVersion -eq '1.2') "got '$($S.schemaVersion)'"
    Check "$Label : version is SemVer"              ($S.version -match '^\d+\.\d+\.\d+$') "got '$($S.version)'"
    Check "$Label : platform is windows"            ($S.platform -eq 'windows')

    $hasFindings = $S.PSObject.Properties.Name -contains 'findings'
    Check "$Label : findings key present"           $hasFindings
    if (-not $hasFindings) { return }

    $f = @($S.findings)
    Check "$Label : findings is never null"         ($null -ne $S.findings)
    Check "$Label : counts add up (active + suppressed = findings)" `
          (($S.activeFindingsCount + $S.suppressedCount) -eq $f.Count) `
          "active=$($S.activeFindingsCount) suppressed=$($S.suppressedCount) findings=$($f.Count)"
    Check "$Label : findingsCount matches array"    ($S.findingsCount -eq $f.Count) `
          "findingsCount=$($S.findingsCount) array=$($f.Count)"

    if ($f.Count -eq 0) { return }

    $ids = @($f | ForEach-Object { $_.id })
    Check "$Label : finding ids unique"             (($ids | Select-Object -Unique).Count -eq $ids.Count)
    Check "$Label : finding ids well formed"        (@($ids | Where-Object { $_ -notmatch '^TTR-F-\d{3,}$' }).Count -eq 0)

    $required = 'id','severity','category','message','confidence','suppressed','iocMatch'
    $missing  = @()
    foreach ($x in $f) { foreach ($k in $required) { if ($x.PSObject.Properties.Name -notcontains $k) { $missing += "$($x.id):$k" } } }
    Check "$Label : v2 fields on every finding"     ($missing.Count -eq 0) ($missing -join ',')

    $badSev = @($f | Where-Object { $_.severity -notin 'High','Review' })
    Check "$Label : severity is High or Review"     ($badSev.Count -eq 0) (($badSev | ForEach-Object { $_.severity }) -join ',')

    $badConf = @($f | Where-Object { [double]$_.confidence -notin 0.3,0.4,0.7,0.95 })
    Check "$Label : confidence from the fixed set"  ($badConf.Count -eq 0) (($badConf | ForEach-Object { "$($_.id)=$($_.confidence)" }) -join ',')

    # an IOC hit must always win: High, 0.95, not suppressed
    $badIoc = @($f | Where-Object { $_.iocMatch -and (($_.severity -ne 'High') -or ([double]$_.confidence -ne 0.95) -or $_.suppressed) })
    Check "$Label : IOC hit implies High/0.95/active" ($badIoc.Count -eq 0) (($badIoc | ForEach-Object { $_.id }) -join ',')

    # a suppressed finding must say why
    $badSup = @($f | Where-Object { $_.suppressed -and [string]::IsNullOrWhiteSpace($_.suppressReason) })
    Check "$Label : suppressed findings carry a reason" ($badSup.Count -eq 0) (($badSup | ForEach-Object { $_.id }) -join ',')
}

function Get-IocFindings { param($S) @(@($S.findings) | Where-Object { $_.iocMatch -or $_.category -eq 'ioc' }) }

Write-Host ''
Write-Host 'TATAR Triage - Windows contract tests' -ForegroundColor Cyan
Write-Host ("collector: " + (Resolve-Path $Collector).Path)
Write-Host ''

# T1 - baseline run, no allowlist / no IOC
Write-Host 'T1  baseline run (no allowlist, no IOC)'
$t1 = Invoke-Collector 't1'
Check 'T1 : exit code is 0 or 2' ($t1.ExitCode -in 0,2) "got $($t1.ExitCode)"
$s1 = Get-Summary $t1
Assert-Contract $s1 'T1'
$ioc1 = @(Get-IocFindings $s1)
Check 'T1 : no IOC findings without an IOC feed' ($ioc1.Count -eq 0) "got $($ioc1.Count)"

# T2 - IOC feed of PARTIAL tokens that must NOT match (boundary test)
#      127.0.0    is a prefix of 127.0.0.1   -> must not match
#      ocalhost   is inside  localhost       -> must not match
#      vchost.exe is inside  svchost.exe     -> must not match
Write-Host ''
Write-Host 'T2  IOC feed with partial tokens (must not match)'
$t2 = Invoke-Collector 't2' @('-IOCFile', (Join-Path $Fixtures 'ioc-negative.json'))
Check 'T2 : exit code is 0 or 2' ($t2.ExitCode -in 0,2) "got $($t2.ExitCode)"
$s2 = Get-Summary $t2
Assert-Contract $s2 'T2'
$ioc2 = @(Get-IocFindings $s2)
Check 'T2 : partial IOC tokens raise no finding' ($ioc2.Count -eq 0) `
      ("matched: " + (($ioc2 | ForEach-Object { $_.message }) -join ' | '))

# T3 - IOC feed with a value that is certain to be present (mechanism works)
Write-Host ''
Write-Host 'T3  IOC feed with a whole token (must match)'
$t3 = Invoke-Collector 't3' @('-IOCFile', (Join-Path $Fixtures 'ioc-positive.json'), '-CaseId', 'TATAR-IOC-PROBE-4711')
$s3 = Get-Summary $t3
Assert-Contract $s3 'T3'
$ioc3 = @(Get-IocFindings $s3)
Check 'T3 : whole IOC token is detected' ($ioc3.Count -ge 1) "got $($ioc3.Count)"

# T4 - malformed allowlist + malformed IOC json: warn and carry on, never crash
Write-Host ''
Write-Host 'T4  malformed allowlist and IOC files'
$t4 = Invoke-Collector 't4' @('-Allowlist', (Join-Path $Fixtures 'allowlist-malformed.json'),
                              '-IOCFile',   (Join-Path $Fixtures 'ioc-malformed.json'))
Check 'T4 : run still completes (exit 0 or 2)' ($t4.ExitCode -in 0,2) "got $($t4.ExitCode)"
$s4 = Get-Summary $t4
Assert-Contract $s4 'T4'

# cleanup
foreach ($r in @($t1,$t2,$t3,$t4)) { if ($r.Root -and (Test-Path $r.Root)) { Remove-Item $r.Root -Recurse -Force -ErrorAction SilentlyContinue } }

Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}" -f $script:PassCount, $script:FailCount) -ForegroundColor $(if ($script:FailCount) { 'Red' } else { 'Green' })
if ($script:FailCount -gt 0) { exit 1 } else { exit 0 }
