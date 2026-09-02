<#
.SYNOPSIS
    TATAR Triage Toolkit - Windows quick DFIR triage / incident-response collector.

.DESCRIPTION
    Read-only-first triage collector for Windows endpoints. Collects volatile and
    non-volatile artifacts in RFC 3227 order-of-volatility, writes a consolidated
    report plus per-artifact files, and produces a SHA-256 manifest for
    chain-of-custody. Module based: run everything or pick specific modules.

    v1.1 additions:
      * summary.txt / summary.json - analyst-first triage summary with an
        aggregated "Suspicious findings" list (leads for REVIEW, not verdicts).
      * Tatar.log - timestamped execution log (START/OK/WARN/FAILED per module).
      * -Silent - suppress all console output (banner, progress, status lines)
        for WinRM / scheduled / automated runs. Exit codes: 0 = success,
        1 = fatal / usage error, 2 = completed with collection errors.

    Design principles:
      * Transparent, NOT evasive. Do NOT obfuscate or bypass AMSI/AV.
        Instead: code-sign this script, publish its SHA-256, and have the SOC
        allow-list it on the forensic host (see README).
      * Order of volatility: memory -> network -> processes -> ... -> disk/registry/logs.
      * Write evidence to an EXTERNAL drive, not the suspect's system disk.

.PARAMETER All
    Run all collector modules (in order-of-volatility).

.PARAMETER Modules
    Run only the named modules, e.g. -Modules network,process,persistence

.PARAMETER List
    List available modules and exit.

.PARAMETER Help
    Show usage help and exit.

.PARAMETER OutputPath
    Base output directory. Default C:\Forensic. USE AN EXTERNAL DRIVE where possible.

.PARAMETER CaseId
    Optional case / incident identifier recorded in chain-of-custody metadata.

.PARAMETER Examiner
    Optional examiner name recorded in chain-of-custody metadata.

.PARAMETER Compress
    Compress the output folder to a .zip and hash it at the end.

.PARAMETER CollectHives
    Save HKLM SAM/SECURITY/SYSTEM/SOFTWARE + NTUSER.DAT (credential material; may trigger EDR).

.PARAMETER ExportEvtx
    Export full .evtx event logs (Security/System/Application/Sysmon).

.PARAMETER MemoryDump
    Attempt a raw memory image using tools\winpmem.exe (must be present; may trigger EDR).

.PARAMETER Silent
    Suppress ALL console output (banner, progress bar, status lines). Everything
    is still written to files, including Tatar.log. Use for WinRM / scheduled /
    remote automation. Alias: -Quiet.

.EXAMPLE
    .\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Enkhbat.O" -Compress

.EXAMPLE
    .\Tatar.ps1 -Modules network,process,rdp,lateral

.EXAMPLE
    .\Tatar.ps1 -All -Silent -OutputPath E:\Evidence; if ($LASTEXITCODE -ne 0) { "check Tatar.log" }

.EXAMPLE
    .\Tatar.ps1 -List

.NOTES
    Author : Enkhbat.O (Security Analyst)  |  TATAR Triage Toolkit v1.1
    Requires: Windows 10/11, PowerShell 5.1+ (PS7 compatible). Run as Administrator.
    Exit codes: 0 = success | 1 = fatal / usage error | 2 = completed with errors (see Tatar.log).
    This tool does NOT extract or decrypt saved passwords.
#>

#Requires -Version 5.1
# NOTE: No param() block. Arguments are parsed manually below so that BOTH
#       single-dash (-All) and double-dash (--all) styles work, any case.

$ErrorActionPreference = 'Continue'

# ---- manual argument parsing (-flag / --flag / /flag, case-insensitive) ----
$All=$false; $List=$false; $Help=$false; $Compress=$false
$CollectHives=$false; $ExportEvtx=$false; $MemoryDump=$false; $Silent=$false
$Modules=@(); $OutputPath='C:\Forensic'; $CaseId=''; $Examiner=''; $Allowlist=''; $IOCFile=''; $UnknownOpts=@()
for ($k = 0; $k -lt $args.Count; $k++) {
    $tok  = [string]$args[$k]
    $name = $tok.TrimStart('-','/').ToLower()
    switch ($name) {
        'all'          { $All = $true }
        'list'         { $List = $true }
        'help'         { $Help = $true }
        'h'            { $Help = $true }
        '?'            { $Help = $true }
        'compress'     { $Compress = $true }
        'collecthives' { $CollectHives = $true }
        'exportevtx'   { $ExportEvtx = $true }
        'memorydump'   { $MemoryDump = $true }
        'silent'       { $Silent = $true }
        'quiet'        { $Silent = $true }
        'q'            { $Silent = $true }
        'modules'      { if ($k+1 -lt $args.Count) { $Modules = ([string]$args[++$k] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
        'outputpath'   { if ($k+1 -lt $args.Count) { $OutputPath = [string]$args[++$k] } }
        'caseid'       { if ($k+1 -lt $args.Count) { $CaseId = [string]$args[++$k] } }
        'examiner'     { if ($k+1 -lt $args.Count) { $Examiner = [string]$args[++$k] } }
        'allowlist'    { if ($k+1 -lt $args.Count) { $Allowlist = [string]$args[++$k] } }
        'iocfile'      { if ($k+1 -lt $args.Count) { $IOCFile = [string]$args[++$k] } }
        'ioc'          { if ($k+1 -lt $args.Count) { $IOCFile = [string]$args[++$k] } }
        default        { $UnknownOpts += $tok }
    }
}
$script:Silent = $Silent

# =====================================================================
#  Helpers
# =====================================================================
$script:ErrorCount = 0
$script:ExecLog    = $null
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:Stats      = [ordered]@{}

function Write-Console {
    # Console output wrapper: fully suppressed by -Silent. File output is never affected.
    param([string]$Text = '', [string]$Color = 'Gray')
    if (-not $script:Silent) { Write-Host $Text -ForegroundColor $Color }
}

function Write-ExecLog {
    # P4: execution log (Tatar.log). Levels: INFO / START / OK / WARN / FAILED / ERROR / FATAL
    param([string]$Level, [string]$Msg)
    if (-not $script:ExecLog) { return }
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    ("[{0}] [{1,-6}] {2}" -f $t, $Level, $Msg) | Out-File -FilePath $script:ExecLog -Append -Encoding UTF8
}

function Get-Technique {
    # Centralized MITRE ATT&CK mapping - all technique logic lives here.
    param([string]$Category, [string]$Message)
    switch ($Category) {
        'process'    {
            if ($Message -match 'powershell') { return @('T1059.001') }
            elseif ($Message -match 'parent') { return @('T1059','T1055') }
            elseif ($Message -match 'cmd')    { return @('T1059.003') }
            elseif ($Message -match 'wscript|cscript') { return @('T1059.005','T1059.007') }
            elseif ($Message -match 'mshta')  { return @('T1218.005') }
            elseif ($Message -match 'rundll32') { return @('T1218.011') }
            elseif ($Message -match 'regsvr32') { return @('T1218.010') }
            elseif ($Message -match 'certutil|bitsadmin') { return @('T1105','T1140') }
            else { return @('T1059') }
        }
        'sessions'   { return @('T1110') }
        'obfscan'    { return @('T1027','T1140') }
        'lateral'    {
            if ($Message -match 'PsExec') { return @('T1569.002','T1021.002') }
            elseif ($Message -match 'WMI') { return @('T1546.003','T1047') }
            else { return @('T1021') }
        }
        'privesc'    {
            if ($Message -match 'nquoted') { return @('T1574.009') }
            elseif ($Message -match 'user-writable') { return @('T1574.010') }
            elseif ($Message -match 'AlwaysInstallElevated') { return @('T1548.002') }
            else { return @('T1068') }
        }
        'persistence' {
            if ($Message -match 'IFEO|Image File Execution') { return @('T1546.012') }
            elseif ($Message -match 'AppInit')  { return @('T1546.010') }
            elseif ($Message -match 'AppCert')  { return @('T1546.009') }
            elseif ($Message -match 'Winlogon') { return @('T1547.004') }
            elseif ($Message -match 'LSA')      { return @('T1547.005','T1556.002') }
            elseif ($Message -match 'Print')    { return @('T1547.012') }
            else { return @('T1547.001') }
        }
        'eventlogs'  { return @('T1070.001') }
        'indicators' {
            if ($Message -match 'service') { return @('T1543.003') }
            else { return @('T1036','T1105') }
        }
        default      { return @() }
    }
}

$script:FindingSeq = 0
function Add-Finding {
    # P3: aggregated suspicious findings. LEADS for analyst review, NOT verdicts.
    param([string]$Severity = 'Review', [string]$Category, [string]$Message, [string]$Detail = '', [string[]]$Technique)
    if (-not $Technique -or $Technique.Count -eq 0) { $Technique = Get-Technique -Category $Category -Message $Message }
    $script:FindingSeq++
    $conf = switch ($Severity) { 'High' { 0.7 } 'Review' { 0.4 } default { 0.3 } }
    $script:Findings.Add([pscustomobject]@{
        id             = ('TTR-F-{0:D3}' -f $script:FindingSeq)
        severity       = $Severity
        category       = $Category
        technique      = @($Technique)
        message        = $Message
        detail         = $Detail
        confidence     = $conf
        suppressed     = $false
        suppressReason = ''
        iocMatch       = $false
    })
}

function Show-Banner {
    $art = @(
    '  _____  _    _____  _    ____  ',
    ' |_   _|/ \  |_   _|/ \  |  _ \ ',
    '   | | / _ \   | | / _ \ | |_) |',
    '   | |/ ___ \  | |/ ___ \|  _ < ',
    '   |_/_/   \_\ |_/_/   \_\_| \_\'
    )
    $w = 62
    $bar = '+' + ('=' * $w) + '+'
    Write-Host ""
    foreach ($l in $art) { Write-Host ("   " + $l) -ForegroundColor Cyan }
    Write-Host ""
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host ('|' + ('   TATAR TRIAGE TOOLKIT   v1.1').PadRight($w) + '|') -ForegroundColor White
    Write-Host ('|' + ('   Windows Quick Triage / Incident Response Collector').PadRight($w) + '|') -ForegroundColor Gray
    Write-Host ('|' + ('   Transparent DFIR  -  sign & allow-list, do not evade').PadRight($w) + '|') -ForegroundColor DarkGray
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-Help {
@"
TATAR Triage Toolkit v1.1 - Windows quick triage collector

USAGE:
  .\Tatar.ps1 -All                          Run all modules (order of volatility)
  .\Tatar.ps1 -Modules net,process,rdp      Run selected modules
  .\Tatar.ps1 -List                         List available modules
  .\Tatar.ps1 -Help                         Show this help

OPTIONS:
  -OutputPath <path>   Output base dir (default C:\Forensic; PREFER an external drive)
  -CaseId <id>         Case / incident id for chain of custody
  -Examiner <name>     Examiner name for chain of custody
  -Compress            Zip + SHA256 the output at the end
  -CollectHives        Save SAM/SECURITY/SYSTEM/SOFTWARE + NTUSER (may trigger EDR)
  -ExportEvtx          Export full .evtx logs
  -MemoryDump          Raw memory image via tools\winpmem.exe (may trigger EDR)
  -Silent              No console output (for WinRM/scheduled runs). Alias: -Quiet
  -Allowlist <json>    Suppress known-good findings (paths[], publishers[], hashes[])
  -IOCFile <json>      Match findings/evidence vs IOCs (hashes[],ips[],domains[],filenames[])

OUTPUT EXTRAS (always written):
  summary.txt / summary.json   Analyst-first triage summary + aggregated findings
  Tatar.log                    Timestamped execution log (START/OK/WARN/FAILED)

EXIT CODES:
  0 = success   1 = fatal / usage error   2 = completed with errors (see Tatar.log)

NOTES:
  * Run PowerShell as Administrator for full collection.
  * Do NOT shut down / restart the host before collection finishes.
  * Transparent by design: code-sign & allow-list this tool; do not evade AV/EDR.
"@ | Write-Host
}

function Add-Report  { param([string]$Text = '') $Text | Out-File -FilePath $script:ReportFile -Append -Encoding UTF8 }
function Add-Section { param([string]$Title) "`n===== $Title =====`n" | Out-File -FilePath $script:ReportFile -Append -Encoding UTF8 }
function Add-Err     {
    param([string]$Msg)
    $script:ErrorCount++
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$t] ERROR: $Msg" | Out-File -FilePath $script:ReportFile -Append -Encoding UTF8
    if ($script:ExecLog) { ("[{0}] [{1,-6}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), 'ERROR', $Msg) | Out-File -FilePath $script:ExecLog -Append -Encoding UTF8 }
}

function Invoke-Ext {
    param([string]$File, [string[]]$Arguments, [string]$OutFile)
    try {
        if ($OutFile) { & $File @Arguments *> $OutFile }
        else { (& $File @Arguments 2>&1) | Out-File -FilePath $script:ReportFile -Append -Encoding UTF8 }
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            Add-Err ("{0} {1} exit code {2}" -f $File, ($Arguments -join ' '), $LASTEXITCODE)
        }
    } catch { Add-Err ("Invoke-Ext {0} failed: {1}" -f $File, $_) }
}

function New-SubDir { param([string]$Name) $p = Join-Path $script:OutDir $Name; New-Item -ItemType Directory -Force -Path $p | Out-Null; return $p }

# Safe test: never throw on access-denied
function Test-PathSafe { param([string]$Path) try { return [bool](Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) } catch { return $false } }
function Copy-Safe {
    param([string]$Src, [string]$Dst)
    try { if (Test-PathSafe $Src) { Copy-Item -LiteralPath $Src -Destination $Dst -Recurse -Force -ErrorAction SilentlyContinue } } catch { Add-Err "Copy $Src failed: $_" }
}

# Note = expected/benign condition. Logged as WARN; does NOT count as an error or change exit code.
function Add-Note {
    param([string]$Msg)
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$t] NOTE: $Msg" | Out-File -FilePath $script:ReportFile -Append -Encoding UTF8
    Write-ExecLog 'WARN' $Msg
}

# Best-effort copy for files commonly locked on a live host (Amcache.hve, NTUSER.DAT...).
# A failure here is EXPECTED, not a collection error -> logged as a NOTE (exit code stays 0).
function Copy-BestEffort {
    param([string]$Src, [string]$Dst, [string]$Hint = 'locked by the OS on a live system; acquire via VSS / RawCopy / offline')
    if (-not (Test-PathSafe $Src)) { return }
    try { Copy-Item -LiteralPath $Src -Destination $Dst -Force -ErrorAction Stop }
    catch { Add-Note ("Could not copy {0} - {1}." -f $Src, $Hint) }
}

# =====================================================================
#  Collector modules
# =====================================================================

function Collect-Memory {
    Add-Section '01 Memory Image (winpmem)'
    if (-not $MemoryDump) { Add-Report 'Skipped (use -MemoryDump to enable).'; return }
    $tool = Join-Path $PSScriptRoot 'tools\winpmem.exe'
    if (-not (Test-PathSafe $tool)) { Add-Report 'winpmem.exe not in tools\. Skipping.'; return }
    $img = Join-Path $script:OutDir 'memory.raw'
    Invoke-Ext -File $tool -Arguments @('--output', $img, '--format', 'raw') -OutFile (Join-Path $script:OutDir 'winpmem_log.txt')
    if ((Test-PathSafe $img) -and ((Get-Item $img -ErrorAction SilentlyContinue).Length -gt 0)) {
        (Get-FileHash $img -Algorithm SHA256).Hash | Out-File (Join-Path $script:OutDir 'memory.raw.sha256.txt') -Encoding UTF8
        Add-Report ("Memory image captured: {0:N0} bytes." -f (Get-Item $img).Length)
    } else {
        Add-Err 'winpmem produced no/empty image - on Win10/11 with HVCI / Core Isolation / Memory Integrity the driver is commonly blocked. Check winpmem_log.txt; use a signed acquisition tool or disable VBS on the forensic host.'
    }
}

function Collect-Network {
    Add-Section '02 Network (connections, ARP, routes, DNS)'
    try {
        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }
        $connCount = 0
        try {
            foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
                $connCount++
                $pn = if ($procMap.ContainsKey([int]$c.OwningProcess)) { $procMap[[int]$c.OwningProcess] } else { '' }
                ("{0}:{1} -> {2}:{3} [{4}] PID:{5} {6}" -f $c.LocalAddress,$c.LocalPort,$c.RemoteAddress,$c.RemotePort,$c.State,$c.OwningProcess,$pn) | Out-File $script:ReportFile -Append -Encoding UTF8
            }
            $script:Stats['TcpConnections'] = $connCount
        } catch { cmd /c "netstat -ano" | Out-File $script:ReportFile -Append -Encoding UTF8 }
        arp -a | Out-File (Join-Path $script:OutDir 'arp.txt') -Encoding UTF8
        route print | Out-File (Join-Path $script:OutDir 'routes.txt') -Encoding UTF8
        ipconfig /displaydns | Out-File (Join-Path $script:OutDir 'dns_cache.txt') -Encoding UTF8
        ipconfig /all | Out-File (Join-Path $script:OutDir 'ipconfig.txt') -Encoding UTF8
        Get-Content 'C:\Windows\System32\drivers\etc\hosts' -ErrorAction SilentlyContinue | Out-File (Join-Path $script:OutDir 'hosts.txt') -Encoding UTF8
        Add-Report 'Network artifacts saved (arp/routes/dns_cache/ipconfig/hosts).'
    } catch { Add-Err "Network failed: $_" }
}

function Collect-Process {
    Add-Section '03 Processes (+ suspicious LOLBAS patterns)'
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction Stop |
                 Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate
        $script:Stats['Processes'] = @($procs).Count
        $procs | Sort-Object ProcessId | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $script:ReportFile -Append -Encoding UTF8
        $sus = @('powershell','cmd\.exe','rundll32','mshta','regsvr32','certutil','bitsadmin','wmic',
                 'wscript','cscript','\bnc\.exe','\bncat','psexec','mimikatz','-enc ','frombase64string','downloadstring','\biex\b')
        Add-Report "`n-- Suspicious process indicators --"
        foreach ($p in $procs) {
            if ($p.CommandLine) {
                foreach ($s in $sus) {
                    if ($p.CommandLine -imatch $s) {
                        ("[!] PID {0} (parent {1}) {2}`n    Path: {3}`n    Cmd : {4}" -f $p.ProcessId,$p.ParentProcessId,$p.Name,$p.ExecutablePath,$p.CommandLine) | Out-File $script:ReportFile -Append -Encoding UTF8
                        $cl = [string]$p.CommandLine; if ($cl.Length -gt 200) { $cl = $cl.Substring(0,200) + '...' }
                        Add-Finding -Category 'process' -Message ("Suspicious command-line pattern '{0}' in {1} (PID {2})" -f $s, $p.Name, $p.ProcessId) -Detail $cl
                        break
                    }
                }
            }
        }
        # -- Process genealogy (parent -> child tree) --
        Add-Report "`n-- Process tree (parent -> child) --"
        $script:pcById = @{}; foreach ($xp in $procs) { $script:pcById[[int]$xp.ProcessId] = $xp }
        $script:pcChild = @{}
        foreach ($xp in $procs) { $xpid=[int]$xp.ParentProcessId; if (-not $script:pcChild.ContainsKey($xpid)) { $script:pcChild[$xpid]=@() }; $script:pcChild[$xpid]+=$xp }
        function Write-ProcTree { param($proc,$depth)
            ("{0}{1} (PID {2})" -f ('  '*$depth), $proc.Name, $proc.ProcessId) | Out-File $script:ReportFile -Append -Encoding UTF8
            if ($depth -lt 12) { foreach ($ch in @($script:pcChild[[int]$proc.ProcessId])) { if ($ch -and [int]$ch.ProcessId -ne [int]$proc.ProcessId) { Write-ProcTree -proc $ch -depth ($depth+1) } } }
        }
        foreach ($xp in $procs) { if (-not $script:pcById.ContainsKey([int]$xp.ParentProcessId)) { Write-ProcTree -proc $xp -depth 0 } }
        # -- Suspicious parent-child lineage (office/script host spawning a shell) --
        $parProc = 'winword','excel','powerpnt','outlook','msaccess','mspub','onenote','acrobat','acrord32','wscript','cscript','mshta','wmiprvse'
        $shProc  = 'powershell','pwsh','cmd','wscript','cscript','mshta','rundll32','regsvr32','bitsadmin','certutil','curl'
        foreach ($xp in $procs) {
            $par = $script:pcById[[int]$xp.ParentProcessId]
            if ($par) {
                $pn = ($par.Name -replace '\.exe$',''); $cn = ($xp.Name -replace '\.exe$','')
                if (($parProc -contains $pn.ToLower()) -and ($shProc -contains $cn.ToLower())) {
                    Add-Finding -Severity 'High' -Category 'process' -Message ("Suspicious parent-child: {0} -> {1} (PID {2})" -f $par.Name, $xp.Name, $xp.ProcessId) -Detail ("Office/script host spawning a shell = common macro/phishing execution chain. Cmd: " + ([string]$xp.CommandLine))
                }
            }
        }
    } catch { Add-Err "Process failed: $_" }
}

function Collect-Sessions {
    Add-Section '04 Logon sessions & recent logons (4624/4625)'
    try {
        (quser 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        (net session 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        foreach ($id in 4624,4625) {
            Add-Report "`n-- Security Event $id (last 15) --"
            try {
                $evts = Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id} -MaxEvents 15 -ErrorAction Stop
                $evts | Select-Object TimeCreated, Id, Message | Format-List | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
                if ($id -eq 4625) {
                    $script:Stats['RecentFailedLogons'] = @($evts).Count
                    if (@($evts).Count -ge 15) { Add-Finding -Category 'sessions' -Message 'High volume of failed logons (4625): 15+ in recent Security log' -Detail 'See report section 04; possible brute force - review source accounts/IPs' }
                }
            } catch { Add-Report "  (event $id not available / access denied)" }
        }
    } catch { Add-Err "Sessions failed: $_" }
}

function Collect-Services {
    Add-Section '05 Services (with binary path)'
    try {
        $svcs = Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
        $script:Stats['Services'] = @($svcs).Count
        $svcs | Sort-Object State | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "Services failed: $_" }
}

function Collect-SysInfo {
    Add-Section '06 System information'
    try {
        (hostname) | Out-File $script:ReportFile -Append -Encoding UTF8
        (whoami /all 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, CSName, LastBootUpTime, InstallDate | Format-List | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, Domain, PartOfDomain | Format-List | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        "TimeZone: $((Get-TimeZone).Id)" | Out-File $script:ReportFile -Append -Encoding UTF8
        Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn -Descending | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "SysInfo failed: $_" }
}

function Collect-Users {
    Add-Section '07 User accounts & admins'
    try {
        (net user 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        (net localgroup administrators 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        $lu = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon, PasswordLastSet
        if ($lu) { $script:Stats['LocalUsers'] = @($lu).Count }
        $lu | Format-Table -AutoSize | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "Users failed: $_" }
}

function Collect-Persistence {
    Add-Section '08 Persistence (startup, Run keys, scheduled tasks)'
    try {
        Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $script:ReportFile -Append -Encoding UTF8
        $runKeys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($k in $runKeys) { if (Test-PathSafe $k) { Add-Report "`n[$k]"; (Get-ItemProperty $k -ErrorAction SilentlyContinue) | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8 } }
        Add-Report "`n-- Scheduled tasks (non-Microsoft) --"
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Select-Object TaskName, TaskPath, State | Format-Table -AutoSize | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        # -- Additional autostart/execution points (ASEPs) --
        Add-Report "`n-- Additional ASEPs (IFEO / AppInit / AppCert / Winlogon / LSA / Print) --"
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-PathSafe $ifeo) {
            Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
                $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
                if ($dbg) { Add-Report ("[IFEO] {0} Debugger = {1}" -f $_.PSChildName, $dbg); Add-Finding -Severity 'High' -Category 'persistence' -Message ("IFEO Debugger hijack on {0}" -f $_.PSChildName) -Detail ("Debugger = $dbg  (launches attacker binary when target runs)") }
            }
        }
        foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
            $ai = (Get-ItemProperty $k -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
            if ($ai) { Add-Report "[AppInit_DLLs] $k = $ai"; Add-Finding -Category 'persistence' -Message 'AppInit_DLLs is set (DLL loaded into most user processes)' -Detail "$k AppInit_DLLs = $ai" }
        }
        $ac = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
        if (Test-PathSafe $ac) {
            $acp = Get-ItemProperty $ac -ErrorAction SilentlyContinue
            $acn = @($acp.PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS' })
            if ($acn.Count -gt 0) { Add-Report '[AppCertDlls] present'; ($acp | Out-String) | Out-File $script:ReportFile -Append -Encoding UTF8; Add-Finding -Category 'persistence' -Message 'AppCertDlls registered (loads into CreateProcess callers)' -Detail 'HKLM\...\Session Manager\AppCertDlls' }
        }
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-PathSafe $wl) {
            $wlp = Get-ItemProperty $wl -ErrorAction SilentlyContinue
            Add-Report ("[Winlogon] Shell='{0}'  Userinit='{1}'" -f $wlp.Shell, $wlp.Userinit)
            if ($wlp.Shell -and $wlp.Shell -notmatch '^explorer\.exe,?\s*$') { Add-Finding -Severity 'High' -Category 'persistence' -Message 'Winlogon Shell is non-default' -Detail ("Shell = $($wlp.Shell) (expected explorer.exe)") }
            if ($wlp.Userinit -and $wlp.Userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?\s*$') { Add-Finding -Severity 'High' -Category 'persistence' -Message 'Winlogon Userinit is non-default' -Detail ("Userinit = $($wlp.Userinit)") }
        }
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (Test-PathSafe $lsa) {
            $lsap = Get-ItemProperty $lsa -ErrorAction SilentlyContinue
            foreach ($vn in 'Security Packages','Authentication Packages','Notification Packages') {
                if ($lsap.$vn) { Add-Report ("[LSA] {0} = {1}" -f $vn, ($lsap.$vn -join ', ')) }
            }
        }
        $pmon = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
        if (Test-PathSafe $pmon) { Get-ChildItem $pmon -ErrorAction SilentlyContinue | ForEach-Object { $drv=(Get-ItemProperty $_.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver; if ($drv) { Add-Report ("[PrintMonitor] {0} Driver={1}" -f $_.PSChildName,$drv) } } }
    } catch { Add-Err "Persistence failed: $_" }
}

function Collect-Autoruns {
    Add-Section '09 Autoruns (Sysinternals, optional)'
    $tool = Join-Path $PSScriptRoot 'tools\autoruns64.exe'
    if (-not (Test-PathSafe $tool)) { Add-Report 'autoruns64.exe not in tools\. Skipping.'; return }
    Invoke-Ext -File $tool -Arguments @('-accepteula','-a','*','-c','-h','-s') -OutFile (Join-Path $script:OutDir 'autoruns.csv')
    Add-Report 'Autoruns CSV saved.'
}

function Collect-Shares {
    Add-Section '10 SMB shares'
    try {
        Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description | Format-Table -AutoSize | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        (net share 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "Shares failed: $_" }
}

function Collect-Firewall {
    Add-Section '11 Firewall profiles & enabled rules'
    try {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action, Profile | Out-String | Out-File (Join-Path $script:OutDir 'firewall_rules.txt') -Encoding UTF8
        Add-Report 'Enabled firewall rules saved to firewall_rules.txt.'
    } catch { Add-Err "Firewall failed: $_" }
}

function Collect-Drivers {
    Add-Section '12 Running kernel drivers'
    try {
        Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | Select-Object Name, DisplayName, PathName | Sort-Object Name | Out-String -Width 4096 | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "Drivers failed: $_" }
}

function Collect-InstalledApps {
    Add-Section '13 Installed applications'
    try {
        $paths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = foreach ($p in $paths) { Get-ItemProperty $p -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate }
        $apps | Where-Object DisplayName | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "InstalledApps failed: $_" }
}

function Collect-Prefetch {
    Add-Section '14 Prefetch (last 60 days)'
    try {
        $pf = 'C:\Windows\Prefetch'
        if (Test-PathSafe $pf) {
            $cutoff = (Get-Date).AddDays(-60)
            Get-ChildItem $pf -Filter *.pf -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff } | Sort-Object LastWriteTime -Descending | Select-Object Name, Length, LastWriteTime | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        } else { Add-Report 'Prefetch not present (may be disabled).' }
    } catch { Add-Err "Prefetch failed: $_" }
}

function Collect-USB {
    Add-Section '15 USB device history'
    try {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (Test-PathSafe $k) {
            Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $fn = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).FriendlyName
                    "$($_.PSChildName)  |  $fn"
                }
            } | Out-File $script:ReportFile -Append -Encoding UTF8
        } else { Add-Report 'No USBSTOR key.' }
    } catch { Add-Err "USB failed: $_" }
}

function Collect-PSHistory {
    Add-Section '16 PowerShell console history'
    try {
        $hp = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-PathSafe $hp) { Add-Report "[$hp]"; Get-Content $hp -ErrorAction SilentlyContinue | Out-File $script:ReportFile -Append -Encoding UTF8 }
        else { Add-Report 'No PSReadLine history found.' }
    } catch { Add-Err "PSHistory failed: $_" }
}

function Collect-ObfScan {
    Add-Section '17 Obfuscated/suspicious script scan (Downloads/Desktop/Temp, 30d)'
    try {
        $paths = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP")
        $patterns = @('IEX','Invoke-Expression','FromBase64String','ConvertFrom-Base64','-enc','-encodedcommand','DownloadString','DownloadFile','fromCharCode','eval(','WScript.Shell','-w hidden')
        $cutoff = (Get-Date).AddDays(-30)
        foreach ($base in $paths) {
            if (-not (Test-PathSafe $base)) { continue }
            $files = Get-ChildItem $base -Recurse -Include *.ps1,*.psm1,*.js,*.vbs,*.bat,*.hta -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff -and $_.FullName -ne $PSCommandPath } | Sort-Object LastWriteTime -Descending | Select-Object -First 100
            foreach ($f in $files) {
                $m = Select-String -Path $f.FullName -Pattern $patterns -SimpleMatch -List -ErrorAction SilentlyContinue
                if ($m) {
                    $snip = $m.Line; if ($snip.Length -gt 160) { $snip = $snip.Substring(0,160)+'...' }
                    ("[!] {0} | line {1} | {2} | {3}" -f $f.FullName,$m.LineNumber,$m.Pattern,$snip) | Out-File $script:ReportFile -Append -Encoding UTF8
                    Add-Finding -Category 'obfscan' -Message ("Suspicious pattern '{0}' in {1}" -f $m.Pattern, $f.FullName) -Detail ("line {0}: {1}" -f $m.LineNumber, $snip)
                }
            }
        }
        Add-Report 'Obfuscation scan complete.'
    } catch { Add-Err "ObfScan failed: $_" }
}

function Collect-RDP {
    Add-Section '18 RDP activity (remote desktop)'
    try {
        $rd = New-SubDir 'RDP'
        # RemoteInteractive logons (Security 4624 LogonType 10) + connect/disconnect
        foreach ($pair in @(@('Security',4624),@('Security',4778),@('Security',4779))) {
            try {
                Get-WinEvent -FilterHashtable @{LogName=$pair[0]; Id=[int]$pair[1]} -MaxEvents 40 -ErrorAction Stop |
                    Select-Object TimeCreated, Id, Message | Export-Csv (Join-Path $rd ("sec_$($pair[1]).csv")) -NoTypeInformation -Encoding UTF8
            } catch {}
        }
        foreach ($lg in 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational') {
            try {
                Get-WinEvent -LogName $lg -MaxEvents 60 -ErrorAction Stop | Select-Object TimeCreated, Id, Message |
                    Export-Csv (Join-Path $rd (($lg -split '/')[0].Split('-')[-1] + '.csv')) -NoTypeInformation -Encoding UTF8
            } catch {}
        }
        # RDP client MRU (outbound destinations)
        $mru = 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
        if (Test-PathSafe $mru) { Add-Report '-- Outbound RDP MRU (HKCU Terminal Server Client) --'; (Get-ItemProperty $mru -ErrorAction SilentlyContinue) | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8 }
        Add-Report 'RDP event CSVs saved to RDP\.'
    } catch { Add-Err "RDP failed: $_" }
}

function Collect-Lateral {
    Add-Section '19 Lateral movement artifacts'
    try {
        Add-Report '-- Mapped drives / SMB mappings --'
        (net use 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        Get-SmbMapping -ErrorAction SilentlyContinue | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        Add-Report '-- Inbound SMB sessions / open files --'
        Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        Add-Report '-- PsExec artifacts --'
        if (Test-PathSafe 'C:\Windows\PSEXESVC.exe') {
            Add-Report 'PSEXESVC.exe present in C:\Windows (PsExec was used).'
            Add-Finding -Severity 'High' -Category 'lateral' -Message 'PsExec service binary present (C:\Windows\PSEXESVC.exe)' -Detail 'PsExec was executed against this host at some point - correlate with logon events'
        }
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'PSEXESVC' } | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        Add-Report '-- WMI persistence (root\subscription) --'
        foreach ($cls in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') {
            $r = Get-CimInstance -Namespace root\subscription -ClassName $cls -ErrorAction SilentlyContinue
            if ($r) {
                "[$cls]" | Out-File $script:ReportFile -Append -Encoding UTF8
                $r | Format-List | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
                if ($cls -like '*Consumer*') { Add-Finding -Category 'lateral' -Message ("WMI event subscription consumer found: {0} ({1} entry/entries)" -f $cls, @($r).Count) -Detail 'Review report section 19 - WMI consumers are a known persistence technique (T1546.003)' }
            }
        }
        Add-Report '-- WinRM state --'
        (Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Name, Status) | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
    } catch { Add-Err "Lateral failed: $_" }
}

function Collect-PrivEsc {
    Add-Section '20 Privilege-escalation indicators'
    try {
        Add-Report '-- Token privileges (whoami /priv) --'
        (whoami /priv 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8
        Add-Report '-- Unquoted service paths (with spaces, outside System32) --'
        $unq = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -match '\.exe' -and $_.PathName -notmatch '(?i)^C:\\Windows'
        } | Select-Object Name, PathName
        $unq | Format-Table -AutoSize | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        foreach ($u in @($unq)) { Add-Finding -Category 'privesc' -Message ("Unquoted service path: {0}" -f $u.Name) -Detail $u.PathName }
        Add-Report '-- Service binaries in user-writable locations --'
        $wr = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -imatch 'users\\|\\appdata\\|\\temp\\|\\programdata\\' } | Select-Object Name, PathName
        $wr | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        foreach ($w in @($wr)) { Add-Finding -Category 'privesc' -Message ("Service binary in user-writable location: {0}" -f $w.Name) -Detail $w.PathName }
        Add-Report '-- AlwaysInstallElevated --'
        foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer') {
            $v = (Get-ItemProperty $k -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
            if ($null -ne $v) {
                "$k AlwaysInstallElevated = $v" | Out-File $script:ReportFile -Append -Encoding UTF8
                if ($v -eq 1) { Add-Finding -Severity 'High' -Category 'privesc' -Message "AlwaysInstallElevated is ENABLED ($k)" -Detail 'Any user can install MSI packages as SYSTEM (T1548)' }
            }
        }
    } catch { Add-Err "PrivEsc failed: $_" }
}

function Collect-Browser {
    Add-Section '21 Browser artifacts (metadata, all profiles, AV-safe)'
    try {
        $bdir = New-SubDir 'BrowserArtifacts'
        $summary = Join-Path $bdir 'browser_artifacts_summary.txt'
        "Browser artifact metadata (no DB execution, no password extraction)`n" | Out-File $summary -Encoding UTF8
        foreach ($r in @(@{N='Chrome';B="$env:LOCALAPPDATA\Google\Chrome\User Data"},@{N='Edge';B="$env:LOCALAPPDATA\Microsoft\Edge\User Data"})) {
            if (-not (Test-PathSafe $r.B)) { continue }
            $profiles = Get-ChildItem $r.B -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' }
            foreach ($pf in $profiles) {
                Add-Content $summary "`n[$($r.N) / $($pf.Name)] $($pf.FullName)"
                foreach ($art in 'History','Cookies','Login Data','Web Data','Bookmarks') {
                    $fp = Join-Path $pf.FullName $art
                    if (Test-PathSafe $fp) { $fi = Get-Item $fp; Add-Content $summary ("   - {0}  ({1} KB, modified {2})" -f $art,[math]::Round($fi.Length/1KB,1),$fi.LastWriteTime) }
                }
            }
        }
        $ff = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-PathSafe $ff) {
            Get-ChildItem $ff -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Add-Content $summary "`n[Firefox / $($_.Name)] $($_.FullName)"
                foreach ($art in 'places.sqlite','cookies.sqlite','formhistory.sqlite') { $fp = Join-Path $_.FullName $art; if (Test-PathSafe $fp) { $fi = Get-Item $fp; Add-Content $summary ("   - {0}  ({1} KB, modified {2})" -f $art,[math]::Round($fi.Length/1KB,1),$fi.LastWriteTime) } }
            }
        }
        Add-Report 'Browser metadata saved to BrowserArtifacts\ (no files copied/decrypted).'
    } catch { Add-Err "Browser failed: $_" }
}

function Collect-FsArtifacts {
    Add-Section '22 Filesystem artifacts (Recent, Amcache; USN/volumes)'
    try {
        $fs = New-SubDir 'FsArtifacts'
        Copy-Safe "$env:APPDATA\Microsoft\Windows\Recent" (Join-Path $fs 'Recent')
        Copy-BestEffort 'C:\Windows\AppCompat\Programs\Amcache.hve' (Join-Path $fs 'Amcache.hve') 'Amcache.hve is locked on a live host; acquire via VSS / RawCopy for offline parsing'
        try { fsutil usn queryjournal C: 2>$null | Out-File (Join-Path $fs 'usn_queryjournal.txt') -Encoding UTF8 } catch {}
        Get-Volume -ErrorAction SilentlyContinue | Out-File (Join-Path $fs 'volumes.txt') -Encoding UTF8
        Get-Disk   -ErrorAction SilentlyContinue | Out-File (Join-Path $fs 'disks.txt')   -Encoding UTF8
        Add-Report 'Filesystem artifacts saved to FsArtifacts\.'
    } catch { Add-Err "FsArtifacts failed: $_" }
}

function Collect-Deleted {
    Add-Section '23 Deleted files (Recycle Bin)'
    try {
        $shell = New-Object -ComObject Shell.Application
        $rb = $shell.NameSpace(0x0a)   # Recycle Bin
        if ($rb) {
            $rows = foreach ($it in $rb.Items()) {
                [pscustomobject]@{
                    Name        = $it.Name
                    OrigLocation= $rb.GetDetailsOf($it, 1)
                    DateDeleted = $rb.GetDetailsOf($it, 2)
                    Size        = $rb.GetDetailsOf($it, 3)
                }
            }
            $rows | Export-Csv (Join-Path $script:OutDir 'recyclebin.csv') -NoTypeInformation -Encoding UTF8
            Add-Report ("Recycle Bin items: {0} (saved to recyclebin.csv)" -f (@($rows).Count))
        } else { Add-Report 'Recycle Bin namespace not available.' }
    } catch { Add-Err "Deleted (Recycle Bin) failed: $_" }
}

function Collect-ShadowCopies {
    Add-Section '24 Volume Shadow Copies'
    try { (vssadmin list shadows 2>&1) | Out-File $script:ReportFile -Append -Encoding UTF8 } catch { Add-Err "ShadowCopies failed: $_" }
}

function Collect-EventLogs {
    Add-Section '25 Key event summary (+ optional EVTX export)'
    try {
        $ev = New-SubDir 'EventLogs'
        $map = @{ '4688'='Process creation'; '7045'='Service install'; '4720'='User created'; '4672'='Special privileges'; '1102'='Security log cleared'; '4104'='PS scriptblock'; '4698'='Scheduled task created'; '4699'='Scheduled task deleted'; '4719'='Audit policy changed'; '4648'='Logon w/ explicit creds'; '4768'='Kerberos TGT'; '4769'='Kerberos svc ticket'; '4776'='NTLM auth'; '5140'='Net share access'; '4627'='Group membership' }
        foreach ($id in $map.Keys) {
            $log = if ($id -eq '4104') { 'Microsoft-Windows-PowerShell/Operational' } else { 'Security' }
            try {
                $evts = Get-WinEvent -FilterHashtable @{LogName=$log; Id=[int]$id} -MaxEvents 50 -ErrorAction Stop
                $evts | Select-Object TimeCreated, Id, Message | Export-Csv (Join-Path $ev ("evt_$id.csv")) -NoTypeInformation -Encoding UTF8
                if ($id -eq '1102' -and @($evts).Count -gt 0) {
                    Add-Finding -Severity 'High' -Category 'eventlogs' -Message ("Security log cleared - event 1102 present ({0} occurrence(s))" -f @($evts).Count) -Detail 'See EventLogs\evt_1102.csv - log clearing is a strong anti-forensics indicator (T1070.001)'
                }
            } catch {}
        }
        Add-Report "Key event CSVs saved (IDs: $($map.Keys -join ', '))."
        if ($ExportEvtx) {
            foreach ($pair in @(@('Security','Security.evtx'),@('System','System.evtx'),@('Application','Application.evtx'),@('Microsoft-Windows-Sysmon/Operational','Sysmon.evtx'))) {
                Invoke-Ext -File 'wevtutil.exe' -Arguments @('epl', $pair[0], (Join-Path $ev $pair[1]))
            }
            Add-Report 'Full EVTX exported.'
        }
    } catch { Add-Err "EventLogs failed: $_" }
}

function Collect-Hives {
    Add-Section '26 Registry hives (optional; credential material)'
    if (-not $CollectHives) { Add-Report 'Skipped (use -CollectHives to enable; may trigger EDR).'; return }
    try {
        $hd = New-SubDir 'RegistryHives'
        $hives = @{ 'HKLM\SYSTEM'='SYSTEM.hive'; 'HKLM\SAM'='SAM.hive'; 'HKLM\SECURITY'='SECURITY.hive'; 'HKLM\SOFTWARE'='SOFTWARE.hive' }
        foreach ($k in $hives.Keys) {
            $dst = Join-Path $hd $hives[$k]
            Invoke-Ext -File 'reg.exe' -Arguments @('save', $k, $dst, '/y') -OutFile (Join-Path $hd 'reg_save.log')
            if (Test-PathSafe $dst) { Add-Report "Saved $k" }
        }
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $nt = Join-Path $_.FullName 'NTUSER.DAT'
            if (Test-PathSafe $nt) { Copy-BestEffort $nt (Join-Path $hd ("NTUSER_" + $_.Name + ".dat")) 'NTUSER.DAT of an active profile is locked; acquire offline / via VSS' }
        }
        Add-Report 'NOTE: hives contain credential material - encrypt output and handle per policy.'
    } catch { Add-Err "Hives failed: $_" }
}

function Collect-MFT {
    Add-Section '27 NTFS / MFT information'
    try {
        $mo = New-SubDir 'MFT'
        (fsutil fsinfo ntfsinfo C: 2>&1) | Out-File (Join-Path $mo 'ntfsinfo_C.txt') -Encoding UTF8
        (fsutil fsinfo statistics C: 2>&1) | Out-File (Join-Path $mo 'ntfs_statistics_C.txt') -Encoding UTF8
        Add-Report 'NTFS volume/MFT info saved to MFT\.'
        Add-Report 'NOTE: full $MFT record parsing requires an offline tool (e.g. MFTECmd / RawCopy) or a mounted shadow copy; not performed in-place to avoid disk modification.'
    } catch { Add-Err "MFT failed: $_" }
}

function Collect-Indicators {
    Add-Section '28 Suspicious indicators summary'
    try {
        Add-Report '-- Non-Microsoft services with unusual binary paths --'
        $oddSvc = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and ($_.PathName -imatch 'temp|appdata|\\programdata\\[^\\]+\.exe|\\users\\') } | Select-Object Name, PathName
        $oddSvc | Format-Table -AutoSize | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
        foreach ($s in @($oddSvc)) { Add-Finding -Category 'indicators' -Message ("Service with unusual binary path: {0}" -f $s.Name) -Detail $s.PathName }
        Add-Report '-- Executables written to temp locations (last 14 days) --'
        $tmpCount = 0
        foreach ($d in @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp")) {
            if (Test-PathSafe $d) {
                $items = Get-ChildItem $d -Recurse -Include *.exe,*.dll,*.scr -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-14) } | Select-Object FullName, Length, LastWriteTime
                $tmpCount += @($items).Count
                $items | Out-String | Out-File $script:ReportFile -Append -Encoding UTF8
            }
        }
        $script:Stats['RecentTempExecutables'] = $tmpCount
        if ($tmpCount -gt 0) { Add-Finding -Category 'indicators' -Message ("{0} executable file(s) written to temp/appdata locations in the last 14 days" -f $tmpCount) -Detail 'See report section 28 for full paths - legitimate installers/updaters also appear here' }
    } catch { Add-Err "Indicators failed: $_" }
}

function Collect-Hashes {
    Add-Section '29 Hash collection (running/startup/service binaries)'
    try {
        $paths = New-Object System.Collections.Generic.HashSet[string]
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { if ($_.ExecutablePath) { [void]$paths.Add($_.ExecutablePath) } }
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PathName) { $p = ($_.PathName -replace '^"([^"]+)".*','$1'); if ($p -match '\.exe') { [void]$paths.Add($p.Trim()) } }
        }
        $rows = foreach ($p in $paths) {
            if (Test-PathSafe $p) {
                try { $h = Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop; [pscustomobject]@{ Path=$p; SHA256=$h.Hash } } catch {}
            }
        }
        $rows | Sort-Object Path | Export-Csv (Join-Path $script:OutDir 'binary_hashes.csv') -NoTypeInformation -Encoding UTF8
        $script:Stats['HashedBinaries'] = @($rows).Count
        Add-Report ("Hashed {0} binaries -> binary_hashes.csv (feed to VirusTotal / IOC matching)." -f (@($rows).Count))
    } catch { Add-Err "Hashes failed: $_" }
}

function Collect-Timeline {
    Add-Section '30 Timeline generation (super-timeline lite)'
    try {
        $tl = New-Object System.Collections.Generic.List[object]
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { if ($_.CreationDate) { $tl.Add([pscustomobject]@{ Time=$_.CreationDate; Source='Process'; Detail=("{0} (PID {1})" -f $_.Name,$_.ProcessId) }) } }
        if (Test-PathSafe 'C:\Windows\Prefetch') { Get-ChildItem 'C:\Windows\Prefetch' -Filter *.pf -ErrorAction SilentlyContinue | ForEach-Object { $tl.Add([pscustomobject]@{ Time=$_.LastWriteTime; Source='Prefetch'; Detail=$_.Name }) } }
        $rec = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-PathSafe $rec) { Get-ChildItem $rec -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object { $tl.Add([pscustomobject]@{ Time=$_.LastWriteTime; Source='RecentLnk'; Detail=$_.Name }) } }
        foreach ($p in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
            Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.InstallDate } | ForEach-Object { $tl.Add([pscustomobject]@{ Time=$_.InstallDate; Source='AppInstall'; Detail=$_.DisplayName }) }
        }
        $tl | Where-Object { $_.Time } | Sort-Object Time -Descending | Export-Csv (Join-Path $script:OutDir 'timeline.csv') -NoTypeInformation -Encoding UTF8
        $script:Stats['TimelineEntries'] = $tl.Count
        Add-Report ("Timeline entries: {0} -> timeline.csv" -f $tl.Count)
    } catch { Add-Err "Timeline failed: $_" }
}

# =====================================================================
#  Summary (P3): analyst-first one-pager, txt + json
# =====================================================================
function Write-Summary {
    param([datetime]$Start, [datetime]$End, [string[]]$ModulesRun, [bool]$IsAdmin)
    $osCap = ''; $osVer = ''
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $osCap = $os.Caption; $osVer = $os.Version } catch {}
    $hn = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
    # Execution-context detection (best-effort)
    $envVirt = 'none'; $envContainer = $false; $envRuntime = 'none'; $envSecmod = 'none'
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $mdl = "$($cs.Manufacturer) $($cs.Model)"
        if     ($mdl -match 'VMware')         { $envVirt = 'vmware' }
        elseif ($mdl -match 'Virtual|Hyper')  { $envVirt = 'hyperv' }
        elseif ($mdl -match 'KVM|QEMU|Bochs') { $envVirt = 'kvm' }
        elseif ($mdl -match 'VirtualBox')     { $envVirt = 'virtualbox' }
        elseif ($mdl -match 'Xen')            { $envVirt = 'xen' }
    } catch {}
    try { if ((Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status -eq 'Running') { $envSecmod = 'defender' } } catch {}
    $sevOrder = @{ 'High' = 0; 'Review' = 1 }
    $sorted = @($script:Findings | Sort-Object { if ($sevOrder.ContainsKey($_.Severity)) { $sevOrder[$_.Severity] } else { 2 } }, Category)

    # ---------- summary.txt ----------
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('==============================================================')
    $L.Add(' TATAR Triage Toolkit v1.1 - TRIAGE SUMMARY')
    $L.Add('==============================================================')
    $L.Add(("Host       : {0}" -f $hn))
    $L.Add(("OS         : {0} ({1})" -f $osCap, $osVer))
    $L.Add(("User       : {0}" -f $env:USERNAME))
    $L.Add(("Case ID    : {0}" -f $CaseId))
    $L.Add(("Examiner   : {0}" -f $Examiner))
    $L.Add(("Started    : {0}" -f $Start.ToString('o')))
    $L.Add(("Finished   : {0}" -f $End.ToString('o')))
    $L.Add(("Duration   : {0} min" -f [math]::Round(($End - $Start).TotalMinutes, 2)))
    $L.Add(("Privileged : {0}" -f $IsAdmin))
    $L.Add(("Environment: virt={0} container={1} runtime={2} secmod={3}" -f $envVirt, $envContainer, $envRuntime, $envSecmod))
    $L.Add(("Modules    : {0}" -f ($ModulesRun -join ', ')))
    $L.Add(("Errors     : {0} (see Tatar.log)" -f $script:ErrorCount))
    $L.Add('')
    $L.Add('-------------------- QUICK STATS ----------------------------')
    if ($script:Stats.Count -gt 0) {
        foreach ($key in $script:Stats.Keys) { $L.Add(("  {0,-24} : {1}" -f $key, $script:Stats[$key])) }
    } else { $L.Add('  (no stats collected - modules with counters were not run)') }
    $L.Add('')
    # ---- allowlist suppression (path glob + Authenticode publisher + hash) ----
    if ($Allowlist -and (Test-Path $Allowlist)) {
        try {
            $al = Get-Content $Allowlist -Raw | ConvertFrom-Json
            $alPaths  = @($al.paths)
            $alPubs   = @($al.publishers)
            $alHashes = @($al.hashes | ForEach-Object { "$_".ToLower() })
            foreach ($f in $sorted) {
                $blob  = "$($f.message) $($f.detail)"
                $cands = @([regex]::Matches($blob, '([A-Za-z]:\\[^"''\r\n]+?\.(?:exe|dll|sys|ps1|bat|scr|cmd))') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
                foreach ($cp in $cands) {
                    $hit = $false
                    foreach ($g in $alPaths) { if ($cp -like $g) { $f.suppressed = $true; $f.suppressReason = "allowlist path: $g"; $hit = $true; break } }
                    if (-not $hit -and $alPubs.Count -and (Test-Path -LiteralPath $cp)) {
                        try {
                            $sig = Get-AuthenticodeSignature -LiteralPath $cp -ErrorAction SilentlyContinue
                            if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
                                foreach ($pub in $alPubs) { if ($sig.SignerCertificate.Subject -match [regex]::Escape($pub)) { $f.suppressed = $true; $f.suppressReason = "signed: $pub"; $hit = $true; break } }
                            }
                        } catch {}
                    }
                    if ($hit) { break }
                }
                if (-not $f.suppressed -and $alHashes.Count) {
                    $hm = [regex]::Match($blob, '\b[a-fA-F0-9]{64}\b')
                    if ($hm.Success -and ($alHashes -contains $hm.Value.ToLower())) { $f.suppressed = $true; $f.suppressReason = 'allowlist hash' }
                }
            }
            Write-ExecLog 'INFO' ("Allowlist applied: {0}/{1} findings suppressed" -f (@($sorted | Where-Object { $_.suppressed }).Count), $sorted.Count)
        } catch { Add-Err "Allowlist failed: $_" }
    }
    # ---- IOC matching (known-bad OVERRIDES the allowlist) ----
    if ($IOCFile -and (Test-Path $IOCFile)) {
        try {
            $ioc       = Get-Content $IOCFile -Raw | ConvertFrom-Json
            $iocHashes = @($ioc.hashes    | ForEach-Object { "$_".ToLower() } | Where-Object { $_ })
            $iocStr    = @(@($ioc.ips) + @($ioc.domains) + @($ioc.filenames) | Where-Object { $_ })
            $iocSeen   = New-Object System.Collections.Generic.List[string]
            $iocHits   = 0
            # Pass A: annotate existing findings; a hit re-activates + escalates.
            foreach ($f in $sorted) {
                $blob = "$($f.message) $($f.detail)"
                $hit  = $null
                foreach ($s in $iocStr) { if ($blob -match [regex]::Escape($s)) { $hit = $s; break } }
                if (-not $hit -and $iocHashes.Count) {
                    $cp = ([regex]::Match($blob, '([A-Za-z]:\\[^"''\r\n]+?\.(?:exe|dll|sys|ps1|bat|scr|cmd))')).Groups[1].Value
                    if ($cp -and (Test-Path -LiteralPath $cp)) {
                        $h = (Get-FileHash -LiteralPath $cp -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        if ($h -and ($iocHashes -contains $h.ToLower())) { $hit = $h.ToLower() }
                    }
                }
                if ($hit) {
                    $iocHits++; if (-not $iocSeen.Contains($hit)) { $iocSeen.Add($hit) }
                    $f.iocMatch = $true; $f.suppressed = $false; $f.suppressReason = ''
                    $f.severity = 'High'; $f.confidence = 0.95
                    $f.detail = "IOC match: $hit | $($f.detail)"
                }
            }
            # Pass B: raise new findings for IOCs seen anywhere in collected artifacts.
            $scan = @(Get-ChildItem -Path $script:OutDir -Recurse -File -Include *.txt,*.csv,*.log -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'summary.txt' })
            foreach ($val in (@($iocStr) + @($iocHashes))) {
                if (-not $val -or $iocSeen.Contains($val)) { continue }
                $found = $null
                foreach ($file in $scan) {
                    $m = Select-String -LiteralPath $file.FullName -SimpleMatch -Pattern $val -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($m) { $found = $m.Line.Trim(); break }
                }
                if ($found) {
                    $iocSeen.Add($val)
                    $script:FindingSeq++
                    $script:Findings.Add([pscustomobject]@{
                        id             = ('TTR-F-{0:D3}' -f $script:FindingSeq)
                        severity       = 'High'; category = 'ioc'; technique = @('T1071')
                        message        = "IOC observed in collected evidence: $val"
                        detail         = $found.Substring(0, [Math]::Min(160, $found.Length))
                        confidence     = 0.95; suppressed = $false; suppressReason = ''; iocMatch = $true
                    })
                }
            }
            $sorted = @($script:Findings | Sort-Object { if ($sevOrder.ContainsKey($_.Severity)) { $sevOrder[$_.Severity] } else { 2 } }, Category)
            Write-ExecLog 'INFO' ("IOC matching: {0} hit(s) on existing findings; {1} findings total" -f $iocHits, $sorted.Count)
        } catch { Add-Err "IOC matching failed: $_" }
    }
    $active     = @($sorted | Where-Object { -not $_.suppressed })
    $suppressed = @($sorted | Where-Object { $_.suppressed })
    $L.Add(("---------- SUSPICIOUS FINDINGS: {0} active{1} (review leads, NOT verdicts) ----------" -f $active.Count, $(if ($suppressed.Count) { ", $($suppressed.Count) allowlisted" } else { '' })))
    if ($active.Count -gt 0) {
        foreach ($f in $active) {
            $tech = if ($f.technique -and @($f.technique).Count -gt 0) { ' [' + (@($f.technique) -join ',') + ']' } else { '' }
            $ioc  = if ($f.iocMatch) { '[IOC] ' } else { '' }
            $L.Add(("  [{0}] ({1}){2} {3}{4}" -f $f.severity, $f.category, $tech, $ioc, $f.message))
            if ($f.detail) { $L.Add(("        {0}" -f $f.detail)) }
        }
        $L.Add('')
        $L.Add('  NOTE: entries above are automated pattern matches. Legitimate software')
        $L.Add('  (updaters, IT tools, this script itself) can appear. Validate each lead')
        $L.Add('  against the full report before drawing conclusions.')
    } else {
        $L.Add('  No active findings (after allowlist). This does NOT prove the host is')
        $L.Add('  clean - review the full report and collected artifacts.')
    }
    if ($suppressed.Count -gt 0) {
        $L.Add('')
        $L.Add(("---------- SUPPRESSED BY ALLOWLIST: {0} (kept for audit) ----------" -f $suppressed.Count))
        foreach ($f in $suppressed) { $L.Add(("  [{0}] ({1}) {2}   <- {3}" -f $f.severity, $f.category, $f.message, $f.suppressReason)) }
    }
    $L.Add('')
    $L.Add('-------------------- NEXT STEPS ------------------------------')
    $L.Add('  1. Review the findings above against the full TATAR_Report_*.txt')
    $L.Add('  2. Check Tatar.log for FAILED/WARN collection steps (missing evidence).')
    $L.Add('  3. Submit binary_hashes.csv to VirusTotal / IOC matching.')
    $L.Add('  4. Pivot on timeline.csv around any confirmed finding timestamps.')
    $L | Out-File -FilePath (Join-Path $script:OutDir 'summary.txt') -Encoding UTF8

    # ---------- summary.json ----------
    $jsonObj = [pscustomobject]@{
        tool            = 'TATAR Triage Toolkit'
        version         = '1.1'
        schemaVersion   = '1.2'
        platform        = 'windows'
        host            = $hn
        os              = $osCap
        osVersion       = $osVer
        user            = $env:USERNAME
        privileged      = $IsAdmin
        caseId          = $CaseId
        examiner        = $Examiner
        started         = $Start.ToString('o')
        finished        = $End.ToString('o')
        durationSeconds = [math]::Round(($End - $Start).TotalSeconds, 0)
        environment     = [pscustomobject]@{ virtualization = $envVirt; container = $envContainer; containerRuntime = $envRuntime; securityModule = $envSecmod }
        errorsLogged    = $script:ErrorCount
        modulesRun      = @($ModulesRun)
        stats           = [pscustomobject]$script:Stats
        findingsCount        = $sorted.Count
        activeFindingsCount  = $active.Count
        suppressedCount      = $suppressed.Count
        findings        = $sorted
    }
    $jsonObj | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $script:OutDir 'summary.json') -Encoding UTF8

    # findings-only file for SOAR / SIEM ingestion
    $findObj = [pscustomobject]@{
        tool          = 'TATAR Triage Toolkit'
        schemaVersion = '1.2'
        platform      = 'windows'
        host          = $hn
        caseId        = $CaseId
        generated     = $End.ToString('o')
        findingsCount        = $sorted.Count
        activeFindingsCount  = $active.Count
        suppressedCount      = $suppressed.Count
        findings      = $sorted
    }
    $findObj | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $script:OutDir 'findings.json') -Encoding UTF8
}

# =====================================================================
#  Module registry  (ORDER = order of volatility, then derived artifacts)
# =====================================================================
$script:Collectors = [ordered]@{
    memory      = ${function:Collect-Memory}
    network     = ${function:Collect-Network}
    process     = ${function:Collect-Process}
    sessions    = ${function:Collect-Sessions}
    services    = ${function:Collect-Services}
    sysinfo     = ${function:Collect-SysInfo}
    users       = ${function:Collect-Users}
    persistence = ${function:Collect-Persistence}
    autoruns    = ${function:Collect-Autoruns}
    shares      = ${function:Collect-Shares}
    firewall    = ${function:Collect-Firewall}
    drivers     = ${function:Collect-Drivers}
    apps        = ${function:Collect-InstalledApps}
    prefetch    = ${function:Collect-Prefetch}
    usb         = ${function:Collect-USB}
    pshistory   = ${function:Collect-PSHistory}
    obfscan     = ${function:Collect-ObfScan}
    rdp         = ${function:Collect-RDP}
    lateral     = ${function:Collect-Lateral}
    privesc     = ${function:Collect-PrivEsc}
    browser     = ${function:Collect-Browser}
    fsartifacts = ${function:Collect-FsArtifacts}
    deleted     = ${function:Collect-Deleted}
    shadow      = ${function:Collect-ShadowCopies}
    eventlogs   = ${function:Collect-EventLogs}
    hives       = ${function:Collect-Hives}
    mft         = ${function:Collect-MFT}
    indicators  = ${function:Collect-Indicators}
    hashes      = ${function:Collect-Hashes}
    timeline    = ${function:Collect-Timeline}
}

# =====================================================================
#  Dispatch
# =====================================================================
if (-not $Silent) { Show-Banner }
foreach ($u in $UnknownOpts) { Write-Console "[!] Unknown option: $u" 'Yellow' }
if ($Help) { Show-Help; exit 0 }
if ($List) {
    Write-Host "Available modules (order of volatility):`n"
    $script:Collectors.Keys | ForEach-Object { Write-Host "  $_" }
    Write-Host "`nTotal: $($script:Collectors.Count) modules"
    exit 0
}

$toRun = if ($All) { @($script:Collectors.Keys) }
         elseif ($Modules) { $Modules }
         else {
             if (-not $Silent) { Show-Help; Write-Host "`n[i] Nothing selected. Use -All or -Modules." -ForegroundColor Yellow }
             exit 1
         }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Console "[!] Not running as Administrator - some artifacts will be incomplete." 'Yellow' }

$hostn = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$script:OutDir     = Join-Path $OutputPath ("{0}_{1}" -f $hostn, $stamp)
$script:ReportFile = Join-Path $script:OutDir ("TATAR_Report_{0}_{1}.txt" -f $hostn, $stamp)
try {
    New-Item -ItemType Directory -Force -Path $script:OutDir -ErrorAction Stop | Out-Null
} catch {
    if (-not $Silent) { Write-Host "[x] FATAL: cannot create output directory ${script:OutDir}: $_" -ForegroundColor Red }
    exit 1
}

# P4: execution log lives next to the evidence, excluded from the manifest (operational log, not evidence)
$script:ExecLog = Join-Path $script:OutDir 'Tatar.log'
Write-ExecLog 'INFO' ("TATAR Triage Toolkit v1.1 starting on {0} as {1} (admin={2}, silent={3})" -f $hostn, $env:USERNAME, $isAdmin, $Silent)
Write-ExecLog 'INFO' ("CaseId='{0}' Examiner='{1}' OutDir={2}" -f $CaseId, $Examiner, $script:OutDir)
Write-ExecLog 'INFO' ("Modules selected: {0}" -f ($toRun -join ', '))
if (-not $isAdmin) { Write-ExecLog 'WARN' 'Not running as Administrator - collection will be incomplete.' }

if ((Split-Path $OutputPath -Qualifier) -eq $env:SystemDrive) {
    Write-Console "[!] WARNING: writing evidence to the SYSTEM drive ($env:SystemDrive). This can overwrite deleted-file evidence. Prefer an external drive (-OutputPath E:\Evidence)." 'Red'
    Write-ExecLog 'WARN' "Evidence is being written to the system drive $env:SystemDrive - prefer an external drive."
}

$start = Get-Date
@"
TATAR Triage Toolkit v1.1 - Collection Report
Host        : $hostn
Case ID     : $CaseId
Examiner    : $Examiner
Started     : $($start.ToString('o'))
TimeZone    : $((Get-TimeZone).Id)
Admin       : $isAdmin
Modules     : $($toRun -join ', ')
OutputDir   : $script:OutDir
"@ | Out-File $script:ReportFile -Encoding UTF8

Write-Console "`n[i] Output: $script:OutDir`n" 'Green'
$i = 0; $n = $toRun.Count; $ran = 0
foreach ($m in $toRun) {
    $i++
    if (-not $script:Collectors.Contains($m)) {
        Write-Console "[!] Unknown module: $m" 'Yellow'
        Write-ExecLog 'WARN' "Unknown module requested: $m"
        continue
    }
    if (-not $Silent) { Write-Progress -Activity 'TATAR Triage' -Status $m -PercentComplete (($i/$n)*100) }
    Write-Console ("[{0}/{1}] {2}" -f $i, $n, $m) 'Cyan'
    Write-ExecLog 'START' ("module {0} ({1}/{2})" -f $m, $i, $n)
    $mStart = Get-Date; $errBefore = $script:ErrorCount; $crashed = $false
    try { & $script:Collectors[$m]; $ran++ } catch { Add-Err "Module $m crashed: $_"; $crashed = $true }
    $secs = [math]::Round(((Get-Date) - $mStart).TotalSeconds, 1)
    if ($crashed) { Write-ExecLog 'FAILED' ("module {0} crashed after {1}s - see ERROR above" -f $m, $secs) }
    elseif ($script:ErrorCount -gt $errBefore) { Write-ExecLog 'WARN' ("module {0} finished in {1}s with {2} error(s)" -f $m, $secs, ($script:ErrorCount - $errBefore)) }
    else { Write-ExecLog 'OK' ("module {0} finished in {1}s" -f $m, $secs) }
}

if ($ran -eq 0) {
    Write-Console '[x] No valid modules were run.' 'Red'
    Write-ExecLog 'FATAL' 'No valid modules were run.'
    exit 1
}

# =====================================================================
#  Finalize: summary + chain of custody + manifest + optional compress
# =====================================================================
Write-Console "`n[i] Finalizing (summary, metadata, manifest, hashes)..." 'Green'
$end = Get-Date
$selfHash = ''
try { if ($PSCommandPath) { $selfHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash } } catch {}

@"
=== CHAIN OF CUSTODY ===
Case ID      : $CaseId
Examiner     : $Examiner
Host         : $hostn
Started      : $($start.ToString('o'))
Finished     : $($end.ToString('o'))
Duration     : $([math]::Round(($end-$start).TotalMinutes,2)) min
Script       : $PSCommandPath
Script SHA256: $selfHash
Tool         : TATAR Triage Toolkit v1.1
"@ | Out-File (Join-Path $script:OutDir 'chain_of_custody.txt') -Encoding UTF8

Write-ExecLog 'INFO' 'Writing summary.txt / summary.json'
try { Write-Summary -Start $start -End $end -ModulesRun $toRun -IsAdmin $isAdmin } catch { Add-Err "Summary failed: $_" }

try {
    $manifest = Join-Path $script:OutDir 'manifest_sha256.csv'
    $exclude  = @($manifest, $script:ExecLog)   # Tatar.log keeps growing after hashing, so it is excluded
    Get-ChildItem -Path $script:OutDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $exclude -notcontains $_.FullName } |
        Get-FileHash -Algorithm SHA256 -ErrorAction SilentlyContinue | Select-Object Hash, Path | Export-Csv -Path $manifest -NoTypeInformation -Encoding UTF8
    Write-ExecLog 'INFO' "Manifest written: $manifest"
} catch { Add-Err "Manifest failed: $_" }

Add-Report "`n=== Collection finished: $($end.ToString('o')) ==="

if ($Compress) {
    try {
        $zip = Join-Path $OutputPath ("TATAR_{0}_{1}.zip" -f $hostn, $stamp)
        Compress-Archive -Path (Join-Path $script:OutDir '*') -DestinationPath $zip -Force
        (Get-FileHash $zip -Algorithm SHA256).Hash | Out-File ($zip + '.sha256.txt') -Encoding UTF8
        Write-ExecLog 'INFO' "Archive created + hashed: $zip"
        Write-Console "[i] Archive: $zip" 'Green'
    } catch {
        Add-Err "Compression failed: $_"
        Write-Console "[!] Compression failed: $_" 'Yellow'
    }
}

$exitCode = if ($script:ErrorCount -gt 0) { 2 } else { 0 }
Write-ExecLog 'INFO' ("Run complete. Findings: {0} | Errors: {1} | Exit code: {2}" -f $script:Findings.Count, $script:ErrorCount, $exitCode)

Write-Console "`n[+] Done. Report  : $script:ReportFile" 'Green'
Write-Console ("[+] Summary : {0}" -f (Join-Path $script:OutDir 'summary.txt')) 'Green'
Write-Console ("[+] Findings: {0} lead(s) for review | Errors logged: {1} | Exit code: {2}" -f $script:Findings.Count, $script:ErrorCount, $exitCode) 'Green'
Write-Console "[i] This tool does NOT extract passwords. Encrypt & handle output per policy." 'DarkGray'
exit $exitCode
