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
    [string]$Modules   = 'sysinfo,network,users',
    [string]$Schema    = (Join-Path $PSScriptRoot '..\schema\summary.schema.json')
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

    # A requested module that never ran must be visible to the pipeline, not
    # only to whoever reads the log.
    $hasSkipped = $S.PSObject.Properties.Name -contains 'modulesSkipped'
    Check "$Label : modulesSkipped key present"     $hasSkipped
    if ($hasSkipped) {
        Check "$Label : nothing was skipped for a valid module list" (@($S.modulesSkipped).Count -eq 0) `
              ((@($S.modulesSkipped)) -join ',')
    }

    # summary.json is the cross-platform contract: a counter is a NUMBER on every
    # platform and uses the one canonical key the schema names for that concept.
    if ($S.PSObject.Properties.Name -contains 'stats') {
        $statProps = @($S.stats.PSObject.Properties)
        $quoted = @($statProps | Where-Object { $_.Value -is [string] -and $_.Value -match '^-?\d+$' } | ForEach-Object { $_.Name })
        Check "$Label : stats counters are JSON numbers, not strings" ($quoted.Count -eq 0) ($quoted -join ',')
        $canon = @()
        try { $canon = @((Get-Content $Schema -Raw | ConvertFrom-Json).properties.stats.'x-canonicalStatKeys') } catch { }
        Check "$Label : the schema declares x-canonicalStatKeys" ($canon.Count -gt 0)
        if ($canon.Count -gt 0) {
            $drifted = @($statProps | Where-Object { $canon -notcontains $_.Name } | ForEach-Object { $_.Name })
            Check "$Label : every stats key is the canonical cross-platform spelling" ($drifted.Count -eq 0) ($drifted -join ',')
        }
    }

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

    $badConf = @($f | Where-Object { [double]$_.confidence -notin 0.4,0.7,0.95 })
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
# summary.txt tells the analyst to grep the log for FAILED, so a clean run must
# not contain one - and the log must exist at all.
$log1 = if ($t1.Dir) { Get-Content (Join-Path $t1.Dir 'tatar.log') -Raw -ErrorAction SilentlyContinue } else { '' }
Check 'T1 : the execution log was written' (-not [string]::IsNullOrWhiteSpace($log1))
Check 'T1 : a healthy run logs no FAILED module' (([regex]::Matches([string]$log1, 'FAILED')).Count -eq 0)
# The manifest is the chain-of-custody artifact: if it cannot be verified, it is
# decoration. It used to hash the consolidated report BEFORE the collector
# appended its last line, so one entry was permanently wrong.
$man1 = if ($t1.Dir) { Join-Path $t1.Dir 'manifest_sha256.txt' } else { $null }
Check 'T1 : the manifest was written' ([bool]($man1 -and (Test-Path $man1)))
if ($man1 -and (Test-Path $man1)) {
    $bad = @()
    foreach ($line in [IO.File]::ReadAllLines($man1)) {
        if ($line.Trim() -eq '') { continue }
        $parts = $line -split '  ', 2
        if ($parts.Count -ne 2) { $bad += "malformed: $line"; continue }
        $rel = ($parts[1] -replace '^\./', '') -replace '/', '\'
        $p   = Join-Path $t1.Dir $rel
        if (-not (Test-Path -LiteralPath $p)) { $bad += "missing: $rel"; continue }
        if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() -ne $parts[0].ToLower()) { $bad += "changed after hashing: $rel" }
    }
    Check 'T1 : every manifest hash still matches its file' ($bad.Count -eq 0) ((@($bad) | Select-Object -First 2) -join '; ')
}

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

# T5 - a path that does not exist must NOT be skipped in silence. Reading
# "no active findings" while the IOC feed never ran is the failure mode this
# whole test file exists to prevent, so it is asserted, not assumed.
Write-Host ''
Write-Host 'T5  missing allowlist and IOC paths are reported, not ignored'
$t5 = Invoke-Collector 't5' @('-Allowlist', (Join-Path $Fixtures 'does-not-exist.json'),
                              '-IOCFile',   (Join-Path $Fixtures 'also-missing.json'))
Check 'T5 : unreadable feed paths force the error exit code' ($t5.ExitCode -eq 2) "got $($t5.ExitCode)"
$s5 = Get-Summary $t5
Assert-Contract $s5 'T5'
Check 'T5 : the run records the errors' ($s5.errorsLogged -ge 2) "got $($s5.errorsLogged)"
$log5 = if ($t5.Dir) { Get-Content (Join-Path $t5.Dir 'tatar.log') -Raw -ErrorAction SilentlyContinue } else { '' }
Check 'T5 : the log names both files as NOT applied' (([regex]::Matches($log5, 'NOT applied')).Count -ge 2)

# T6 - a value-taking flag whose value is missing used to consume the NEXT FLAG
#      (or nothing): '-OutputPath -CaseId IR-1' created a directory literally
#      called '-CaseId' and dropped the case id from the chain of custody.
Write-Host ''
Write-Host 'T6  a value-taking flag with no value is a usage error'
& powershell -NoProfile -File $Collector -Modules $Modules -Silent -OutputPath | Out-Null
Check 'T6 : -OutputPath with no value exits 1' ($LASTEXITCODE -eq 1) "got $LASTEXITCODE"
& powershell -NoProfile -File $Collector -Modules $Modules -Silent -OutputPath -CaseId IR-T6 | Out-Null
Check 'T6 : -OutputPath followed by another flag exits 1' ($LASTEXITCODE -eq 1) "got $LASTEXITCODE"
& powershell -NoProfile -File $Collector -Silent -Modules | Out-Null
Check 'T6 : -Modules with no value exits 1' ($LASTEXITCODE -eq 1) "got $LASTEXITCODE"
Check 'T6 : no evidence folder was created for the flag name' (-not (Test-Path -LiteralPath (Join-Path (Get-Location).Path '-CaseId')))

# T7 - an unknown option used to be a console-only warning that -Silent
#      swallowed, and an unknown module name only warned: both exited 0, so a
#      run that collected a quarter of what was asked looked clean.
Write-Host ''
Write-Host 'T7  unknown option and unknown module are recorded, not swallowed'
$t7 = Invoke-Collector 't7' @('-TatarBogusFlag', '-Modules', 'sysinfo,notamodule')
Check 'T7 : unknown option / module force the error exit code' ($t7.ExitCode -eq 2) "got $($t7.ExitCode)"
$log7 = if ($t7.Dir) { Get-Content (Join-Path $t7.Dir 'tatar.log') -Raw -ErrorAction SilentlyContinue } else { '' }
Check 'T7 : the log names the unknown option' ([string]$log7 -match 'TatarBogusFlag')
Check 'T7 : the log names the unknown module' ([string]$log7 -match 'notamodule')
$s7 = Get-Summary $t7
Check 'T7 : summary.json reports the skipped module' ((@($s7.modulesSkipped) -join ',') -eq 'notamodule') `
      ("modulesSkipped=" + (@($s7.modulesSkipped) -join ','))

# T8 - the preview has to resolve the plan WITHOUT touching the disk: on a
#      forensic collector the first write is itself evidence-destroying, and
#      -CollectHives / -MemoryDump are documented as EDR-triggering.
Write-Host ''
Write-Host 'T8  -DryRun resolves the plan and writes nothing'
$root8 = Join-Path $env:TEMP ('tatar-test-t8-' + (Get-Random))
$out8  = & powershell -NoProfile -File $Collector -All -DryRun -OutputPath $root8 -Allowlist (Join-Path $Fixtures 'does-not-exist.json') 2>&1 | Out-String
Check 'T8 : -DryRun exits 0' ($LASTEXITCODE -eq 0) "got $LASTEXITCODE"
Check 'T8 : -DryRun creates no output directory' (-not (Test-Path $root8))
Check 'T8 : the preview names the resolved output dir' ($out8 -match [regex]::Escape($root8))
Check 'T8 : the preview names the module count and order' ($out8 -match '\d+ module\(s\) in this order')
Check 'T8 : the preview reports an unreadable feed before collecting' ($out8 -match 'NOT READABLE')

# cleanup
foreach ($r in @($t1,$t2,$t3,$t4,$t5,$t7)) { if ($r -and $r.Root -and (Test-Path $r.Root)) { Remove-Item $r.Root -Recurse -Force -ErrorAction SilentlyContinue } }
if ($root8 -and (Test-Path $root8)) { Remove-Item $root8 -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}" -f $script:PassCount, $script:FailCount) -ForegroundColor $(if ($script:FailCount) { 'Red' } else { 'Green' })
if ($script:FailCount -gt 0) { exit 1 } else { exit 0 }
