<#
    TATAR Triage Toolkit - containment test with Windows Firewall (Windows edition).

    Test-Security.ps1 W8 polls TCP connections while the collector runs, which can
    miss a very short connection. This test asks the operating system instead:

      1. the Windows Filtering Platform connection audit (events 5156 allowed,
         5157 blocked) is switched on;
      2. an outbound BLOCK rule is created for the PowerShell host that runs the
         collector, so a connection attempt cannot succeed and is recorded either
         way;
      3. the collector runs;
      4. the audit log is read: the collector (and any network-capable program it
         could start) must have made NO connection to a non-loopback address.

    Needs an elevated session (firewall rule, audit policy). Without one the test
    is reported as SKIP, never as PASS. Everything it changes is restored in a
    finally block: the rule is removed and the audit setting is put back.

        pwsh -NoProfile -File tests/Test-Containment.ps1
    Exit code: 0 = no failure (or skipped), 1 = at least one failure.
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Modules = 'sysinfo,network,process,users'
)
$ErrorActionPreference = 'Continue'
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0
function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { $script:Pass++; Write-Host ('  PASS  ' + $Name) -ForegroundColor Green }
    else { $script:Fail++; Write-Host ('  FAIL  ' + $Name + '  ' + $Detail) -ForegroundColor Red }
}
function Finish {
    Write-Host ''
    Write-Host ("RESULT  passed: {0}  failed: {1}  skipped: {2}" -f $script:Pass, $script:Fail, $script:Skip)
    if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
}

Write-Host "`nW13  containment with Windows Firewall: no outbound connection attempt"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { $script:Skip++; Write-Host '  SKIP  W13 : needs an elevated session (firewall rule and audit policy)' -ForegroundColor Yellow; Finish }
if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) { $script:Skip++; Write-Host '  SKIP  W13 : NetSecurity module not available' -ForegroundColor Yellow; Finish }

$PwshHost = if ($PSVersionTable.PSEdition -eq 'Core') { (Get-Process -Id $PID).Path } else { (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') }
$RuleName = 'TATAR-containment-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$Work = Join-Path ([IO.Path]::GetTempPath()) ('tatar-fw-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$Sub = 'Filtering Platform Connection'

# remember the audit setting so it can be restored exactly
$oldAudit = (& auditpol.exe /get /subcategory:"$Sub" /r 2>$null | Select-Object -Skip 1 | ForEach-Object { $_ -split ',' } | Select-Object -Last 1)
$oldAuditText = [string]$oldAudit
try {
    & auditpol.exe /set /subcategory:"$Sub" /success:enable /failure:enable | Out-Null
    $auditOn = ((& auditpol.exe /get /subcategory:"$Sub" 2>$null) -join ' ') -match 'Success and Failure'
    Check 'W13 : connection audit (5156/5157) is on' $auditOn 'auditpol could not enable it'

    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Action Block -Program $PwshHost -Profile Any | Out-Null
    $ruleOk = [bool](Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)
    Check 'W13 : outbound block rule for the collector host exists' $ruleOk

    $start = Get-Date
    $out = Join-Path $Work 'out'
    $p = Start-Process -FilePath $PwshHost -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $Collector + '"'), '-Modules', $Modules, '-Silent', '-OutputPath', ('"' + $out + '"')) -PassThru -WindowStyle Hidden
    $done = $p.WaitForExit(600000)
    if (-not $done) { try { $p.Kill() } catch {} }
    Check 'W13 : the collector finished with outbound blocked (exit 0 or 2)' ($done -and ($p.ExitCode -eq 0 -or $p.ExitCode -eq 2)) "exit $($p.ExitCode)"
    Start-Sleep -Seconds 3   # let the audit log catch up
    $end = Get-Date

    $names = @('powershell.exe', 'pwsh.exe', 'netstat.exe', 'nslookup.exe', 'ping.exe', 'curl.exe', 'certutil.exe', 'bitsadmin.exe', 'ftp.exe', 'tracert.exe', 'telnet.exe', 'ssh.exe', 'tftp.exe')
    $hits = New-Object System.Collections.Generic.List[string]
    $blocked = 0; $seen = 0
    foreach ($eid in 5156, 5157) {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $eid; StartTime = $start; EndTime = $end } -ErrorAction SilentlyContinue)
        foreach ($e in $ev) {
            $x = [xml]$e.ToXml()
            $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
            $app = [string]$d['Application']
            if (-not $app) { continue }
            $leaf = [IO.Path]::GetFileName($app).ToLowerInvariant()
            if ($names -notcontains $leaf) { continue }
            $dest = [string]$d['DestAddress']
            if ($dest -in @('127.0.0.1', '::1', '0.0.0.0', '::', '') -or $dest -like 'fe80:*') { continue }
            $seen++
            if ($eid -eq 5157) { $blocked++ }
            $hits.Add("$eid $leaf -> $dest`:$($d['DestPort'])")
        }
    }
    # the test's own process is the same executable as the collector host, so a
    # hit is only counted against the collector when it falls in the run window
    Check 'W13 : no connection to a non-loopback address was attempted or made' ($hits.Count -eq 0) (($hits | Select-Object -First 5) -join '; ')
    Write-Host ("        audit events in window: attempts seen {0}, of which blocked {1}" -f $seen, $blocked)
    $d2 = Get-ChildItem -LiteralPath $out -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    Check 'W13 : evidence was still produced (summary.json present)' ([bool]($d2 -and (Test-Path -LiteralPath (Join-Path $d2.FullName 'summary.json'))))
}
finally {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $gone = -not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)
    if ($oldAuditText -match 'Success' -or $oldAuditText -match 'Failure') {
        $s = if ($oldAuditText -match 'Success') { 'enable' } else { 'disable' }
        $f = if ($oldAuditText -match 'Failure') { 'enable' } else { 'disable' }
        & auditpol.exe /set /subcategory:"$Sub" /success:$s /failure:$f | Out-Null
    }
    else { & auditpol.exe /set /subcategory:"$Sub" /success:disable /failure:disable | Out-Null }
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    Check 'W13 : the firewall rule was removed again' $gone
}
Finish
