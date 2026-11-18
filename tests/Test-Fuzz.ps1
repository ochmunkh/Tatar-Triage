<#
    TATAR Triage Toolkit - fuzz tests (Windows edition).

    Random and mutated input goes to the functions that parse text from the
    suspect host, and a property that must hold for EVERY input is checked.
    The functions are lifted from Tatar.ps1 with the PowerShell parser, so the
    code under test is the code that ships.

      Z1  Remove-ControlChar   no control, DEL or bidi character survives
      Z2  Protect-CsvCell      no cell can begin a spreadsheet formula
      Z3  Format-HostsEntry    only legal address / name characters, bounded
      Z4  Get-PathCandidate    every token is a drive-letter path without
                               characters Windows forbids in a name
      Z5  feeds                a mutated allowlist or IOC file never crashes a
                               run: exit 0 or 2, summary.json still valid

    A fixed seed makes a run reproducible; set TATAR_FUZZ_SEED to vary it.
    Source is ASCII only (Windows PowerShell 5.1 reads BOM-less files as ANSI).

        pwsh -NoProfile -File tests/Test-Fuzz.ps1 [-Iterations 1500] [-FeedIterations 6]
    Exit code: 0 = no property violated, 1 = at least one.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [int]$Iterations = 1500,
    [int]$FeedIterations = 6
)
$ErrorActionPreference = 'Continue'
$Seed = if ($env:TATAR_FUZZ_SEED) { [int]$env:TATAR_FUZZ_SEED } else { 20261118 }
$Rng = New-Object System.Random($Seed)
$script:Pass = 0; $script:Fail = 0

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { $script:Pass++; Write-Host ('  PASS  ' + $Name) -ForegroundColor Green }
    else { $script:Fail++; Write-Host ('  FAIL  ' + $Name + '  ' + $Detail) -ForegroundColor Red }
}

# ---- lift functions from the collector with the parser
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Collector).Path, [ref]$tokens, [ref]$errs)
foreach ($n in @('Remove-ControlChar', 'Protect-CsvCell', 'Format-HostsEntry', 'Get-PathCandidate')) {
    $def = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true)
    if (-not $def) { Write-Host ('FAIL  ' + $n + ' not found'); exit 1 }
    . ([scriptblock]::Create($def.Extent.Text))
}

# ---- generators
$Interesting = @(
    '', ' ', '=', '+', '-', '@', "'", '"', '\', '/', '..', "`t", "`r", "`n", ([string][char]27 + '[31m'),
    [string][char]7, [string][char]127, [string][char]0x202E, [string][char]0x2066, [string][char]0xFFFD,
    '$(id)', '`id`', ';id', '|id', '&&id', '*', '?', '<', '>', ':', 'C:\Windows\System32\cmd.exe',
    'C:\Users\A\AppData\Local\Temp\x.0p1\Setup.ps1', '127.0.0.1', '::1', '1.2.3.4  C:\evil.exe', ('0' * 40)
)
function New-RandText {
    $sb = New-Object System.Text.StringBuilder
    $parts = $Rng.Next(0, 9)
    for ($i = 0; $i -lt $parts; $i++) {
        $r = $Rng.NextDouble()
        if ($r -lt 0.35) { [void]$sb.Append($Interesting[$Rng.Next(0, $Interesting.Count)]) }
        elseif ($r -lt 0.7) { $n = $Rng.Next(0, 60); for ($k = 0; $k -lt $n; $k++) { [void]$sb.Append([char]$Rng.Next(32, 127)) } }
        elseif ($r -lt 0.9) { $n = $Rng.Next(0, 12); for ($k = 0; $k -lt $n; $k++) { [void]$sb.Append([char]$Rng.Next(1, 0x2FFF)) } }
        else { [void]$sb.Append('x' * $Rng.Next(100, 2000)) }
    }
    $sb.ToString()
}
function Show { param([string]$s) ($s.ToCharArray() | ForEach-Object { if ([int]$_ -lt 32 -or [int]$_ -gt 126) { '\u{0:X4}' -f [int]$_ } else { [string]$_ } }) -join '' }

function Run-Property {
    param([string]$Label, [scriptblock]$Fn, [scriptblock]$Prop)
    $bad = $null
    for ($i = 0; $i -lt $Iterations; $i++) {
        $in = New-RandText
        try { $out = & $Fn $in } catch { $bad = "threw on input '$(Show $in)': $($_.Exception.Message)"; break }
        if (-not (& $Prop $in $out)) { $bad = "input='$(Show $in)' output='$(Show ([string]$out))'"; break }
    }
    Check ("{0}: {1} random inputs, property holds (seed {2})" -f $Label, $Iterations, $Seed) ($null -eq $bad) $bad
}

Write-Host "`nZ1  Remove-ControlChar removes control and bidi characters"
Run-Property 'Z1' { param($s) Remove-ControlChar $s } { param($i, $o) -not [regex]::IsMatch([string]$o, '[\x00-\x1F\x7F\u202A-\u202E\u2066-\u2069]') }

Write-Host "`nZ2  Protect-CsvCell never starts a formula"
Run-Property 'Z2' { param($s) Protect-CsvCell $s } {
    param($i, $o)
    $t = [string]$o
    if ($t.Length -eq 0) { return $true }
    if ($t -match '^[=+@\t\r]') { return $false }
    if ($t -match '^-' -and $t -notmatch '^-\d+([.,]\d+)?$') { return $false }
    $true
}

Write-Host "`nZ3  Format-HostsEntry keeps only legal characters"
Run-Property 'Z3' { param($s) Format-HostsEntry $s } {
    param($i, $o)
    $t = ([string]$o) -replace '->', '', 1
    if ($t -match '[\\/"''`$;|&<>\x00-\x08\x0B-\x1F\x7F]') { return $false }
    ([string]$o).Length -le 103 -and ([string]$o) -notmatch "[`r`n]"
}

Write-Host "`nZ4  Get-PathCandidate emits only drive-letter paths without forbidden characters"
Run-Property 'Z4' { param($s) , @(Get-PathCandidate $s) } {
    param($i, $o)
    foreach ($tok in @($o)) {
        if ($tok -isnot [string]) { continue }
        if ($tok -notmatch '^[A-Za-z]:\\') { return $false }
        if ($tok.Substring(2) -match '[:*?"<>|/\r\n]') { return $false }
    }
    $true
}

# ---- feeds
Write-Host "`nZ5  mutated allowlist and IOC feeds never crash a run"
$here = Split-Path -Parent (Resolve-Path -LiteralPath $Collector).Path
$base = @{
    allowlist = [IO.File]::ReadAllBytes((Join-Path $here 'allowlist.sample.json'))
    ioc       = [IO.File]::ReadAllBytes((Join-Path $here 'ioc.sample.json'))
}
$PwshHost = if ($PSVersionTable.PSEdition -eq 'Core') { (Get-Process -Id $PID).Path } else { 'powershell' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('tatar-fuzz-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
function Get-Mutant {
    param([byte[]]$Data)
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange($Data)
    $ops = $Rng.Next(1, 7)
    for ($k = 0; $k -lt $ops; $k++) {
        if ($b.Count -eq 0) { $b.AddRange([byte[]](123, 125)) }
        $i = $Rng.Next(0, $b.Count)
        switch ($Rng.Next(0, 6)) {
            0 { $b[$i] = [byte]$Rng.Next(0, 256) }
            1 { $n = [Math]::Min($Rng.Next(1, 21), $b.Count - $i); $b.RemoveRange($i, $n) }
            2 { $ins = [Text.Encoding]::UTF8.GetBytes($Interesting[$Rng.Next(0, $Interesting.Count)]); $b.InsertRange($i, $ins) }
            3 { $b.RemoveRange($i, $b.Count - $i) }
            4 { $n = $Rng.Next(1, 40); $junk = New-Object byte[] $n; $Rng.NextBytes($junk); $b.InsertRange($i, $junk) }
            default { $b.InsertRange($i, [byte[]](,[byte]91 * $Rng.Next(1, 2000))) }
        }
    }
    , $b.ToArray()
}
$badRun = @()
for ($n = 0; $n -lt $FeedIterations; $n++) {
    $kind = if ($n % 2 -eq 0) { 'allowlist' } else { 'ioc' }
    $feed = Join-Path $work ("feed$n.json")
    [IO.File]::WriteAllBytes($feed, (Get-Mutant $base[$kind]))
    $out = Join-Path $work "out$n"
    $flag = if ($kind -eq 'allowlist') { '-Allowlist' } else { '-IOCFile' }
    $p = Start-Process -FilePath $PwshHost -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $Collector + '"'), '-Modules', 'sysinfo', '-Silent', '-OutputPath', ('"' + $out + '"'), $flag, ('"' + $feed + '"')) -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit(180000)) { try { $p.Kill() } catch {}; $badRun += "timeout ($kind feed$n)"; continue }
    $code = $p.ExitCode
    $why = $null
    if ($code -ne 0 -and $code -ne 2) { $why = "exit $code" }
    else {
        $d = Get-ChildItem -LiteralPath $out -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $d) { $why = 'no evidence folder' }
        else { try { $null = [IO.File]::ReadAllText((Join-Path $d.FullName 'summary.json'), [Text.Encoding]::UTF8) | ConvertFrom-Json } catch { $why = 'summary.json invalid' } }
    }
    if ($why) { $keep = Join-Path ([IO.Path]::GetTempPath()) ("tatar-fuzz-fail-$n.json"); Copy-Item -LiteralPath $feed -Destination $keep -Force; $badRun += "$why ($kind feed kept at $keep)" }
}
Check ("Z5 feeds: {0} mutated feeds, exit 0/2, summary.json valid" -f $FeedIterations) ($badRun.Count -eq 0) ($badRun -join '; ')
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}  (seed {2})" -f $script:Pass, $script:Fail, $Seed)
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
