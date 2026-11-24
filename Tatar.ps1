<#
.SYNOPSIS
    TATAR Triage Toolkit - Windows quick DFIR triage / incident-response collector.

.DESCRIPTION
    Read-only-first triage collector for Windows endpoints. Collects volatile and
    non-volatile artifacts in RFC 3227 order-of-volatility, writes a consolidated
    report plus per-artifact files, and produces a SHA-256 manifest for
    chain-of-custody. Module based: run everything or pick specific modules.

    v1.2 additions:
      * -Allowlist <json> - suppress known-good findings by path glob, Authenticode
        publisher or SHA-256 (kept in the report as suppressed, with a reason).
      * -IOCFile <json>   - offline IOC feed (hashes/ips/domains/filenames); a hit
        overrides the allowlist and escalates to High / 0.95.
      * findings v2 fields (id, confidence, suppressed, suppressReason, iocMatch,
        artifactClass, recommendation), schemaVersion 1.8.

    v1.1 additions:
      * summary.txt / summary.json - analyst-first triage summary with an
        aggregated "Suspicious findings" list (leads for REVIEW, not verdicts).
      * tatar.log - timestamped execution log (START/OK/WARN/FAILED per module).
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
    is still written to files, including tatar.log. Use for WinRM / scheduled /
    remote automation. Alias: -Quiet.

.EXAMPLE
    .\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Enkhbat.O" -Compress

.EXAMPLE
    .\Tatar.ps1 -Modules network,process,rdp,lateral

.EXAMPLE
    .\Tatar.ps1 -All -Silent -OutputPath E:\Evidence; if ($LASTEXITCODE -ne 0) { "check tatar.log" }

.EXAMPLE
    .\Tatar.ps1 -List

.NOTES
    Author : Enkhbat.O (Security Analyst)  |  TATAR Triage Toolkit
    Requires: Windows 10/11, PowerShell 5.1+ (PS7 compatible). Run as Administrator.
    Exit codes: 0 = success | 1 = fatal / usage error | 2 = completed with errors (see tatar.log).
    This tool does NOT extract or decrypt saved passwords.
#>

#Requires -Version 5.1
# NOTE: No param() block. Arguments are parsed manually below so that BOTH
#       single-dash (-All) and double-dash (--all) styles work, any case.

$ErrorActionPreference = 'Continue'

# Single source of truth for the tool version (banner, help, summary, JSON, chain of custody).
$script:ToolVersion = '1.13.0'

# ---- manual argument parsing (-flag / --flag / /flag, case-insensitive) ----
$All=$false; $Quick=$false; $List=$false; $Help=$false; $Compress=$false; $DryRun=$false
$CollectHives=$false; $ExportEvtx=$false; $MemoryDump=$false; $Silent=$false
$Modules=@(); $OutputPath='C:\Forensic'; $CaseId=''; $Examiner=''; $Allowlist=''; $IOCFile=''; $UnknownOpts=@()

function Read-ArgValue {
    # A value-taking flag must be followed by an actual value, not by the next
    # flag and not by nothing at all: '-OutputPath -CaseId IR-1' used to set
    # $OutputPath = '-CaseId' and then create a directory with that name, and a
    # trailing '-Modules' silently selected nothing. The usage error goes to
    # stderr and exits 1 even under -Silent - a WinRM / scheduled run must not
    # fail mutely - which is the '1 = fatal / usage error' code the README documents.
    param([string]$Flag, [object]$Value)
    # An ARRAY must be rejoined, not cast. Called from a PowerShell prompt,
    # '.\Tatar.ps1 -Modules network,process' hands this an array of two strings,
    # because PowerShell parses a,b in argument mode as an array -- and
    # [string] on an array joins with a SPACE, so '-Modules network,process'
    # became the single module name 'network process' and the run died with
    # "No valid modules were run". From cmd.exe the same flag arrives as a
    # literal string and worked, which is why the README's own example was
    # broken in the shell a responder is most likely to be sitting in.
    $v = if ($null -eq $Value) { '' }
         elseif ($Value -is [array]) { (@($Value) | ForEach-Object { [string]$_ }) -join ',' }
         else { [string]$Value }
    if ($v -eq '' -or $v.StartsWith('-')) {
        [Console]::Error.WriteLine("[x] FATAL: $Flag requires a value")
        exit 1
    }
    return $v
}

for ($k = 0; $k -lt $args.Count; $k++) {
    $tok  = [string]$args[$k]
    $name = $tok.TrimStart('-','/').ToLower()
    $next = if ($k+1 -lt $args.Count) { $args[$k+1] } else { $null }
    switch ($name) {
        'all'          { $All = $true }
        'quick'        { $Quick = $true }
        'fast'         { $Quick = $true }
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
        'dryrun'       { $DryRun = $true }
        'dry-run'      { $DryRun = $true }
        'preview'      { $DryRun = $true }
        'modules'      { $Modules = ((Read-ArgValue $tok $next) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); $k++ }
        # -Output / -o are what the Linux collector takes; both editions must
        # accept the same spellings or an operator who learns one is bitten by
        # the other. -OutputPath stays for anything already scripted against it.
        { $_ -in 'outputpath','output','o' } { $OutputPath = Read-ArgValue $tok $next; $k++ }
        { $_ -in 'caseid','case' }  { $CaseId    = Read-ArgValue $tok $next; $k++ }
        'examiner'     { $Examiner   = Read-ArgValue $tok $next; $k++ }
        { $_ -in 'allowlist','allow' } { $Allowlist = Read-ArgValue $tok $next; $k++ }
        { $_ -in 'iocfile','ioc','iocs' } { $IOCFile = Read-ArgValue $tok $next; $k++ }
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
# What a module could not do, machine-readable. Schema 1.3 considered putting
# this on every finding and refused: "could not read /proc/N" describes a
# MODULE, not a finding, so per-finding it would have been copy-pasted
# boilerplate. This is that field at the level it belongs to.
$script:ModuleLimitations = New-Object System.Collections.Generic.List[object]
$script:ModulesSkipped = New-Object System.Collections.Generic.List[string]
# One entry per requested module: how it ended. Read with .ToArray(), never @(): see the 5.1 note at the summary writer.
$script:ModuleStatus = New-Object System.Collections.Generic.List[object]
$script:ObfHits       = New-Object System.Collections.Generic.List[object]

# Evidence correlation rules. Deliberately FEW and NAMED: a generic
# "anything that co-occurs" pass would relabel coincidence as evidence, which
# is the failure mode this project keeps having to correct for (the first
# useractivity draft raised 144 findings, 142 of them noise). A rule fires only
# when two findings from DIFFERENT modules name the SAME path, and it says in
# words what the agreement means. COR-01 is Windows-only and declared as such
# in .github/scripts/check_docs_parity.py: Mark-of-the-Web has no Linux
# equivalent, so there is nothing for the shell edition to mirror.
#
# 'prefetch' and 'autoruns' are deliberately NOT named here. Both collect into
# the report but neither calls Add-Finding, so naming them was a rule half that
# could never fire while the README documented it as working -- shipped in
# the previous release and caught afterwards by a real run. check_docs_parity.py now refuses a
# rule that names a module which raises no finding, so re-adding either one
# fails the build until that module actually raises findings.
$script:CorrelationRules = @(
    [pscustomobject]@{
        Id = 'COR-01'; Name = 'download-then-execute'
        A  = @('motw'); B = @('useractivity')
        Reason = 'a file that arrived from the internet was also executed'
    }
    [pscustomobject]@{
        Id = 'COR-02'; Name = 'autorun-on-suspect-file'
        A  = @('persistence'); B = @('motw','indicators')
        Reason = 'an autorun entry points at a file that is itself suspect'
    }
)

# Windows is not always on C:. The collector hardcoded 'C:\Windows' / 'C:' in
# nine places, and two of them are FINDING predicates: on a host installed to
# D:, the default Winlogon Userinit and every service under D:\Windows were
# reported as High-severity tampering. The rest simply looked in the wrong place
# and reported nothing. Resolve once, here. The literals stay as the fallback so
# a host without these variables (the cross-platform suite runs on Linux, where
# both are empty and Join-Path throws on a null Path) behaves exactly as before.
$script:SysRoot  = if ($env:SystemRoot)  { $env:SystemRoot.TrimEnd('\') }  else { 'C:\Windows' }
$script:SysDrive = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd('\') } else { 'C:' }

function Join-WinPath {
    # Join Windows path segments LITERALLY, with a single backslash.
    #
    # Join-Path resolves the drive of its first segment, so on a non-Windows
    # host 'C:\Windows' makes it throw "Cannot find drive. A drive with the name
    # 'C' does not exist" -- a red error block on a run that is otherwise silent.
    # These are constants being assembled, not paths being resolved, so no drive
    # lookup is wanted on any platform. The parse/analyse/dry-run checks all run
    # on Linux, and an error there is noise that hides a real one.
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Child)
    return ($Base.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Write-Console {
    # Console output wrapper: fully suppressed by -Silent. File output is never affected.
    param([string]$Text = '', [string]$Color = 'Gray')
    if (-not $script:Silent) { Write-Host $Text -ForegroundColor $Color }
}

function Write-ExecLog {
    # P4: execution log (tatar.log). Levels: INFO / START / OK / WARN / FAILED / ERROR / FATAL
    param([string]$Level, [string]$Msg)
    if (-not $script:ExecLog) { return }
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    ("[{0}] [{1,-6}] {2}" -f $t, $Level, $Msg) | Out-FileNoBom -FilePath $script:ExecLog -Append
}

function Get-Recommendation {
    # One static next step per category (schema 1.8). A pointer for the analyst, not a verdict.
    # Same text as recommendation_for in linux/tatar-linux.sh; tests/fixtures/recommendations.tsv is the shared reference.
    param([string]$Category)
    switch ($Category) {
        'process' { return 'Check the image path, signature, parent process and network connections; hash the binary and look it up before ending the process.' }
        'persistence' { return 'Find who created the entry and when, hash what it launches, and compare it with a known-good build before removing it.' }
        'privesc' { return 'Confirm a standard user can write to the path or setting; fix the permissions or quote the path, then re-scan to confirm it is gone.' }
        'lateral' { return 'Identify the source host and account, check the matching logon events from the same time, and look for the same tool on other hosts.' }
        'rmm' { return 'Ask the owner whether this remote-management tool is approved; if not, record when and by which account it was installed before removing it.' }
        'useractivity' { return 'Ask the user whether they ran it; check where the file came from and when it first appeared.' }
        'obfscan' { return 'Decode the script in a safe place without running it; look for download commands, encoded payloads and where the file came from.' }
        'indicators' { return 'Hash the file, check where it came from and when it was created, and compare it with your allowlist before treating it as hostile.' }
        'motw' { return 'Check where the download came from and whether it was opened or run afterwards.' }
        'network' { return 'Compare the entry with what this host is meant to use; unexpected overrides can redirect traffic.' }
        'sessions' { return 'List the source addresses and target accounts in the logon events and check whether any attempt later succeeded.' }
        'users' { return 'Confirm the account is expected, who created it and when; set a password or disable the account if it is not needed.' }
        'eventlogs' { return 'Check whether the log was cleared or stopped on purpose and compare it with a copy forwarded to a collector.' }
        'suid' { return 'Verify the file against the package manager and confirm it is meant to carry the setuid bit.' }
        'sshkeys' { return 'Confirm each key belongs to a known person or system and check when authorized_keys last changed.' }
        'bashhistory' { return 'Read the surrounding commands and timestamps for downloads, credential use and cleanup.' }
        'context' { return 'Confirm whether this host is meant to run containers or is inside one; review mounted paths and privileges.' }
        'ioc' { return 'A match from your own indicator list; confirm it is not a coincidence, then search other hosts for the same indicator.' }
        default { return 'Review the evidence section named in this finding and confirm with the owner whether it is expected.' }
    }
}

function Get-Technique {
    # Centralized MITRE ATT&CK mapping - all technique logic lives here.
    param([string]$Category, [string]$Message)
    switch ($Category) {
        'process'    {
            if     ($Message -match 'credential dump')            { return @('T1003.001') }
            elseif ($Message -match 'URL written in (hex|base64)') { return @('T1027','T1140') }
            elseif ($Message -match 'powershell') { return @('T1059.001') }
            elseif ($Message -match 'parent') { return @('T1059','T1055') }
            elseif ($Message -match 'cmd')    { return @('T1059.003') }
            elseif ($Message -match 'wscript|cscript') { return @('T1059.005','T1059.007') }
            elseif ($Message -match 'mshta')  { return @('T1218.005') }
            elseif ($Message -match 'rundll32') { return @('T1218.011') }
            elseif ($Message -match 'regsvr32') { return @('T1218.010') }
            elseif ($Message -match 'certutil|bitsadmin') { return @('T1105','T1140') }
            else { return @('T1059') }
        }
        'rmm'        { return @('T1219') }
        'motw'       { if ($Message -match 'macro') { return @('T1204.002','T1566.001') } else { return @('T1189','T1566.001') } }
        'useractivity' {
            # The evidence source does not decide the technique; what the
            # evidence SHOWS does. A cached download is ingress, a typed
            # command is a command interpreter, a shell-launched binary is
            # user execution.
            if     ($Message -match 'crypto stack')   { return @('T1105','T1140') }
            elseif ($Message -match 'Run dialog')     { return @('T1059') }
            elseif ($Message -match 'over the network') { return @('T1021.002') }
            else { return @('T1204.002') }
        }
        'sessions'   { return @('T1110') }
        'users'      { return @('T1078') }
        'network'    { return @('T1565.001') }
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
            # The three techniques added in this release come first: each has its own
            # ATT&CK id, and without them they would all have fallen through to
            # T1547.001 (Run keys) - a finding mapped to the wrong technique is
            # worse than one mapped to none, because a coverage report built
            # from it is confidently wrong.
            if     ($Message -match 'COM CLSID')        { return @('T1546.015') }
            elseif ($Message -match 'netsh helper')     { return @('T1546.007') }
            elseif ($Message -match 'Protocol handler|Protocol filter') { return @('T1546.015','T1112') }
            elseif ($Message -match 'IFEO|Image File Execution') { return @('T1546.012') }
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

# ONE timestamp format for the whole tool: ISO 8601, UTC, second precision.
#
# It used to be two. `.ToString('o')` on a local DateTime yields
# 2026-10-26T21:01:29.1909204+08:00 while the Linux edition writes
# 2026-10-26T13:01:29Z, so a single "unified" document carried both shapes and
# output from the two editions could not be sorted together without a parser
# that normalises offsets. Within ONE document it was worse: schema 1.3 added
# collected_at in UTC Z next to a `generated` in local time with an offset.
#
# Quoted 'Z' on purpose: unquoted Z is not a .NET format specifier, and relying
# on an unrecognised character being echoed literally is not a format, it is a
# coincidence that happens to hold.
function Get-IsoUtc {
    param([datetime]$When = (Get-Date))
    return $When.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss'Z'")
}

function Resolve-KnownFolder {
    <#
        UserAssist records many entries with a {KNOWNFOLDERID} prefix standing
        in for a directory. The collector used to leave them all raw, on the
        reasoning that a wrong translation is worse than an untranslated one -
        which is right, and is why this resolves ONLY the folder ids whose
        meaning is fixed by Windows, from this host's own environment, for the
        same user whose UserAssist is being read. Anything not on the list is
        returned unchanged and the caller says so.

        Leaving them all raw had a cost that was not visible until a live run:
        an unresolved entry carries no drive-letter path, so Get-PathCandidate
        returns nothing, and a finding with no path can never be allowlisted,
        matched against an IOC feed, or correlated. The entry was unusable.
    #>
    param([string]$Name)
    if ($Name -notmatch '^\{([0-9A-Fa-f-]{36})\}\\?(.*)$') { return $Name }
    $id   = $matches[1].ToUpper()
    $rest = $matches[2]
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $map = @{
        '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7' = (Join-WinPath $script:SysRoot 'System32')
        'D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27' = (Join-WinPath $script:SysRoot 'SysWOW64')
        'F38BF404-1D43-42F2-9305-67DE0B28FC23' = $script:SysRoot
        '6D809377-6AF0-444B-8957-A3773F02200E' = $env:ProgramFiles
        '905E63B6-C1BF-494E-B29C-65B732D3D21A' = $env:ProgramFiles
        '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E' = $pf86
        'B4BFCC3A-DB2C-424C-B029-7FE99A87C641' = (Join-Path $env:USERPROFILE 'Desktop')
        '374DE290-123F-4565-9164-39C4925E467B' = (Join-Path $env:USERPROFILE 'Downloads')
        'FDD39AD0-238F-46AF-ADB4-6C85480369C7' = (Join-Path $env:USERPROFILE 'Documents')
        '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D' = $env:APPDATA
        'F1B32785-6FBA-4FCF-9D55-7B8E7F157091' = $env:LOCALAPPDATA
        'A77F5D77-2E2B-44C3-A6A2-ABA601054A51' = (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs')
        '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8' = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')
    }
    $base = $map[$id]
    if (-not $base) { return $Name }
    if ($rest) { return (Join-Path $base $rest) }
    return $base
}

function Get-PathCandidate {
    # Every drive-letter path a finding names, de-duplicated. The allowlist,
    # publisher, hash and IOC passes can only reach files that appear here, so
    # this is the single definition of "the files this finding is about" - and
    # the reason a finding that names no file can never be suppressed.
    param([string]$Text)
    # Directory segments are matched GREEDILY, the file name lazily. The old
    # pattern was lazy throughout, so it stopped at the FIRST dotted segment:
    # a real finding naming
    #   C:\Users\A\AppData\Local\Temp\x4hwcywj.0p1\PrecheckTools\Setup.ps1
    # yielded only  ...\Temp\x4hwcywj.0p1  -- a DIRECTORY whose random name
    # merely looks like a file. Every downstream pass judges what is in here, so
    # the allowlist could never match the real script, the hash pass hashed a
    # directory, and correlation keyed on the wrong string. Found in a live run.
    #
    # The segment class excludes the characters Windows forbids in a path name
    # (\ / : * ? " < > |), which is also what stops a match from running past
    # the end of a path into the prose around it -- prose contains no
    # backslashes, and a second path cannot be reached without crossing its
    # drive-letter colon.
    return @([regex]::Matches([string]$Text, '([A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*?\.[A-Za-z0-9]{1,8})(?![A-Za-z0-9])') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
}

# The module currently running, recorded on every finding it raises so an
# analyst can tell which collector made the claim. Set by the dispatch loop.
$script:CurrentModule = ''

# Why a finding carries the confidence it does. The number is derived, so the
# reason is derived with it - stating it in the record is what makes the number
# auditable instead of a magic constant the consumer has to look up. Kept
# word-for-word identical to conf_reason() in the Linux edition: one output
# contract means the same finding reads the same on both platforms.
function Invoke-EvidenceCorrelation {
    <#
        One artifact is a lead. Two independent artifacts naming the SAME path
        is a different kind of statement, and the tool used to throw it away: an
        analyst had to notice by eye that the file MOTW says was downloaded is
        the file UserAssist says was run.

        A function rather than inline code so tests\Test-Correlation.ps1 can
        lift and exercise it against synthetic findings without running a
        collection -- the technique tests\Test-IocBoundary.ps1 established.

        Input : -Findings, the finding list AFTER the allowlist and IOC passes.
        Output: the number of findings raised, as an int. The findings are
                mutated in place; only confidence and confidenceReason change.

        Runs LAST and skips both suppressed findings -- the allowlist already
        judged that path known-good, so correlating on it would re-raise exactly
        the noise it was there to remove -- and IOC hits, whose 0.95 already
        outranks 0.85. Severity is the analyst's scale and is never touched,
        nothing is merged away, and nothing is invented: correlation makes an
        existing lead more credible, it does not make a new claim.
    #>
    param(
        [object[]]$Findings,
        [object[]]$Rules = $script:CorrelationRules
    )
    $corrCount = 0
    $byPath = @{}
    foreach ($f in $Findings) {
        if ($f.suppressed -or $f.iocMatch) { continue }
        foreach ($p in @($f.paths)) {
            if (-not $p) { continue }
            # Lowercased because the Windows filesystem is case-insensitive:
            # C:\Temp\x.exe and c:\temp\X.EXE are the same file and must
            # correlate. The Linux edition deliberately does NOT fold case, for
            # the opposite reason -- see correlate_findings in tatar-linux.sh.
            $k = $p.ToLower()
            if (-not $byPath.ContainsKey($k)) { $byPath[$k] = New-Object System.Collections.Generic.List[object] }
            $byPath[$k].Add($f)
        }
    }
    foreach ($rule in $Rules) {
        foreach ($k in @($byPath.Keys)) {
            # .ToArray(), NOT @(...): on PowerShell 5.1 the array subexpression
            # operator over a List[object] throws "Argument types do not match".
            # This is the same 5.1 trap that silently emptied moduleLimitations
            # in 1.4, which is why the collector keeps using .ToArray() for it.
            $group = $byPath[$k].ToArray()
            foreach ($l in @($group | Where-Object { $rule.A -contains $_.module })) {
                foreach ($r in @($group | Where-Object { $rule.B -contains $_.module })) {
                    # the two sides must be different findings raised by
                    # different modules: a module agreeing with itself is one
                    # artifact seen twice, not two artifacts agreeing.
                    if ($l.id -eq $r.id -or $l.module -eq $r.module) { continue }
                    foreach ($pair in @(@($l,$r), @($r,$l))) {
                        $f = $pair[0]; $other = $pair[1]
                        if ($f.confidence -ge 0.85) { continue }
                        $f.confidence       = 0.85
                        $f.confidenceReason = ('{0} ({1}): {2} - {3} and {4} name the same path {5} (see {6})' -f $rule.Name, $rule.Id, $rule.Reason, $f.module, $other.module, $k, $other.id)
                        $corrCount++
                    }
                }
            }
        }
    }
    return $corrCount
}

function Get-ConfidenceReason {
    param([double]$Confidence)
    switch ($Confidence) {
        0.95    { 'an indicator from the supplied IOC feed matched this finding (see iocIndicator)' }
        0.85    { 'two independent artifacts named the same path (the correlation pass overwrites this with the rule that fired)' }
        0.7     { 'severity High: a strong lead on its own, but the tool did not confirm it' }
        0.4     { 'severity Review: the pattern also occurs in benign configurations' }
        default { '' }
    }
}

$script:FindingSeq = 0

# ---------------------------------------------------------------------------
#  Artifact classes
# ---------------------------------------------------------------------------
# `category` says which module raised a finding; `artifactClass` says what the
# evidence IS. They are different axes and the difference is operational:
# `persistence` covers Run keys, IFEO, Winlogon, the Startup folder, scheduled
# tasks and COM hijacks all at once, so an allowlist or an IOC rule written
# against the category cannot aim at one of them. HijackThis made exactly this
# distinction with its O4 / O20 section codes, and it is the reason knowledge
# like "O20 is almost always bad" could be written down and reused.
#
# This is the same vocabulary the artifact dictionary uses for FILES, applied
# to findings. Deriving it centrally - the way Get-Technique already derives
# ATT&CK ids - keeps it out of thirty call sites.
#
# The list is closed on purpose: Add-Finding rejects a class that is not in it,
# so a typo cannot invent a class that no rule will ever match, and the two
# editions are held to the same vocabulary by check_docs_parity.py.
$script:ArtifactClasses = @(
    'account','admin-group','alwaysinstallelevated','bash-history','browser',
    'com-hijack','cron','deleted-binary','dns-cache','event-log','firewall',
    'hosts-file','ifeo','ioc-match','jumplist','logon-failure','lsa-package',
    'mark-of-the-web','muicache','netsh-helper','network-connection',
    'obfuscated-script','package','print-monitor','process-commandline',
    'protocol-handler','rdp','rmm-connection-log','rmm-product','run-key',
    'runmru','scheduled-task','service','service-path','share','shadow-copy',
    'ssh-key','startup-folder','suid','temp-executable','unknown','usb',
    'userassist','winlogon','wmi-subscription','writable-path'
)

function Get-ArtifactClass {
    # Centralized artifact-class mapping - all of it lives here, like
    # Get-Technique. Returns 'unknown' rather than guessing: a wrong class is
    # worse than an honest absence, because a rule written against it would
    # silently aim at the wrong evidence.
    param([string]$Category, [string]$Message, [string]$Detail = '')
    $t = "$Message $Detail"
    switch ($Category) {
        'persistence' {
            if     ($t -match 'AppInit|Winlogon|Userinit|Shell is non-default') { return 'winlogon' }
            elseif ($t -match 'Image File Execution|IFEO')                      { return 'ifeo' }
            elseif ($t -match 'COM|InProcServer32|TreatAs')                     { return 'com-hijack' }
            elseif ($t -match 'scheduled task|Task(Path|Name)')                 { return 'scheduled-task' }
            elseif ($t -match 'Startup folder|Start Menu')                      { return 'startup-folder' }
            elseif ($t -match 'netsh|NetSh\\Helper')                            { return 'netsh-helper' }
            elseif ($t -match 'protocol handler|PROTOCOLS')                     { return 'protocol-handler' }
            elseif ($t -match 'Security Packages|Notification Packages|LSA')    { return 'lsa-package' }
            elseif ($t -match 'Print Monitor|Print Processor')                  { return 'print-monitor' }
            else                                                                { return 'run-key' }
        }
        'lateral'  { if ($t -match 'WMI event subscription|FilterToConsumer') { return 'wmi-subscription' } else { return 'service' } }
        'privesc'  {
            if     ($t -match 'AlwaysInstallElevated') { return 'alwaysinstallelevated' }
            elseif ($t -match 'Unquoted|ImagePath')    { return 'service-path' }
            else                                       { return 'service' }
        }
        'useractivity' {
            if     ($t -match 'MUICache')     { return 'muicache' }
            elseif ($t -match 'Run dialog|RunMRU') { return 'runmru' }
            elseif ($t -match 'jump list|JumpList') { return 'jumplist' }
            else { return 'userassist' }
        }
        'motw'       { return 'mark-of-the-web' }
        # Message only, not message+detail: the "tool present" finding's detail
        # says "check it against the connection history below", which matched
        # the connection-log rule and mislabelled the product finding.
        'rmm'        { if ($Message -match 'connection history|connection_trace|Connections') { return 'rmm-connection-log' } else { return 'rmm-product' } }
        'obfscan'    { return 'obfuscated-script' }
        'indicators' { if ($t -match 'writable') { return 'writable-path' } else { return 'temp-executable' } }
        'network'    { if ($t -match 'hosts file') { return 'hosts-file' } elseif ($t -match 'DNS') { return 'dns-cache' } else { return 'network-connection' } }
        'users'      { if ($t -match 'Administrators') { return 'admin-group' } else { return 'account' } }
        'process'    { if ($t -match 'DELETED|deleted') { return 'deleted-binary' } else { return 'process-commandline' } }
        'eventlogs'  { return 'event-log' }
        'sessions'   { return 'logon-failure' }
        'shadow'     { return 'shadow-copy' }
        'usb'        { return 'usb' }
        'rdp'        { return 'rdp' }
        'browser'    { return 'browser' }
        'firewall'   { return 'firewall' }
        'shares'     { return 'share' }
        'ioc'        { return 'ioc-match' }
        default      { return 'unknown' }
    }
}

function Remove-ControlChar {
    # C0 controls (except tab), DEL, bidi override/isolate characters become U+FFFD; CR/LF/TAB collapse to a space.
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return $s }
    return [regex]::Replace($s, '[\x00-\x1F\x7F\u202A-\u202E\u2066-\u2069]', { param($m) if ($m.Value -match '[\t\r\n]') { ' ' } else { [string][char]0xFFFD } })
}
function Read-TextAuto {
    # Lines of a small text file in whatever encoding it really has. Some tools
    # (AnyDesk's connection_trace.txt is one) write UTF-16; read as bytes-per-
    # character that is a NUL between every letter, which the sanitiser then
    # turned into a U+FFFD between every letter. BOM first, then the NUL pattern
    # of BOM-less UTF-16, else UTF-8. Bounded to 4 MB: these are log tails.
    param([string]$Path)
    $fs = [IO.File]::OpenRead($Path)
    try {
        $n = [int][Math]::Min($fs.Length, 4MB)
        $b = New-Object byte[] $n
        $r = $fs.Read($b, 0, $n)
        if ($r -lt $n) { $b = $b[0..($r - 1)] }
    } finally { $fs.Dispose() }
    if ($b.Length -eq 0) { return @() }
    $enc = $null; $skip = 0
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $enc = [Text.Encoding]::UTF8; $skip = 3 }
    elseif ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { $enc = [Text.Encoding]::Unicode; $skip = 2 }
    elseif ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) { $enc = [Text.Encoding]::BigEndianUnicode; $skip = 2 }
    else {
        $odd = 0; $even = 0; $m = [Math]::Min($b.Length, 512)
        for ($i = 0; $i -lt $m; $i++) { if ($b[$i] -eq 0) { if ($i % 2) { $odd++ } else { $even++ } } }
        if ($odd -gt ($m / 8) -and $odd -gt (2 * $even)) { $enc = [Text.Encoding]::Unicode }
        elseif ($even -gt ($m / 8) -and $even -gt (2 * $odd)) { $enc = [Text.Encoding]::BigEndianUnicode }
        else { $enc = [Text.Encoding]::UTF8 }
    }
    $text = $enc.GetString($b, $skip, $b.Length - $skip)
    return @($text -split "\r?\n")
}
function Hide-UrlSecret {
    # A download URL can carry a bearer credential in its query string (a signed
    # storage link has sig= and a token). Evidence is copied and shared, so the
    # secret is replaced by a marker; host, path and every other parameter stay,
    # which is what an analyst needs. Trailing control characters (the stream a
    # URL is read from ends in NUL) are cut.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text -replace '[\x00-\x1F]+$', ''
    return [regex]::Replace($t, '(?i)([?&;])(sig|signature|jwt|token|access_token|id_token|refresh_token|auth|authorization|key|apikey|api_key|code|password|pwd|secret|sas|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature)=([^&\s]*)', '$1$2=[redacted]')
}
function Test-WritableByUsers {
    # $true  : a standard user could replace this file (the file, or its folder,
    #          grants write to Everyone, Users, Authenticated Users or Interactive)
    # $false : the ACL was read and grants them no write access
    # $null  : the ACL could not be read - the caller must treat that as "unknown"
    param([string]$Path)
    $sids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4')
    $mask = [long][Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
    try {
        foreach ($t in @($Path, (Split-Path -Parent $Path))) {
            if (-not $t) { continue }
            $acl = Get-Acl -LiteralPath $t -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($t -ne $Path -and ([int]$ace.PropagationFlags -band 2)) { continue }   # inherit-only: applies to children, not to the folder
                $sid = $null
                try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
                if ($sids -contains $sid -and (([long]$ace.FileSystemRights) -band $mask) -ne 0) { return $true }
            }
        }
        return $false
    } catch { return $null }
}
function Get-FilesByExtension {
    # Files under a folder whose extension is in a list, newer than a cutoff.
    # One directory walk, the extension tested afterwards. Get-ChildItem
    # -Include does the same job but is several times slower on a large tree
    # (measured on a developer Desktop: 23 s against 5 s for the same 133
    # files), and a standard-user run has no time to spare on it. Same
    # semantics as -Include: case-insensitive, hidden and system files are not
    # listed unless the caller asks for them.
    param([string]$Path, [string[]]$Extension, [datetime]$Since = [datetime]::MinValue)
    $want = @($Extension | ForEach-Object { $_.ToLowerInvariant() })
    Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Since -and ($want -contains $_.Extension.ToLowerInvariant()) }
}
function Remove-ExeToken {
    # The command line without the program that is running it, so a process is
    # judged by what it was TOLD to do and not by the name of its own binary.
    param([string]$CommandLine)
    $c = [string]$CommandLine
    if ($c -match '^\s*"[^"]*"\s*(.*)$') { return $Matches[1] }
    if ($c -match '^\s*\S+\s*(.*)$') { return $Matches[1] }
    return $c
}
function Get-NoPasswordSeverity {
    # "Password required: No" is a policy flag. It does not say whether the
    # account HAS a password. PasswordLastSet does: an account that never had a
    # password set carries no date. So the flag alone is a Review, and a flag
    # plus no date (or a date we could not read) is the High case. Account
    # metadata only; no password is read and no logon is attempted.
    param($PasswordLastSet, [bool]$Known = $true)
    if (-not $Known) { return 'High' }
    if ($null -eq $PasswordLastSet -or [string]$PasswordLastSet -eq '') { return 'High' }
    try { if ([datetime]$PasswordLastSet -le [datetime]'1980-01-01') { return 'High' } } catch { return 'High' }
    return 'Review'
}
function Get-HashText {
    # SHA-256 of a string (UTF-8), lowercase hex, first 16 characters. Short
    # enough to read in a diff, long enough that two different findings do not
    # collide in practice (64 bits over a few thousand findings).
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) } finally { $sha.Dispose() }
    (($b | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 16)
}
function Get-FindingIdentity {
    # Stable identity of a finding ACROSS runs, so two scans of the same host
    # can be compared. fingerprint = what the finding IS (module, class,
    # category, message with volatile numbers masked, the paths it names);
    # contentHash = what it SAYS about it (severity, confidence, detail), so a
    # finding that stays but changes is visible as changed. Masking is
    # deliberately narrow: only a PID and a count followed by a counted noun.
    # Over-masking would merge two different findings and hide a new one.
    # The Linux edition implements the same canon; tests/fixtures/identity-vectors.tsv
    # holds the shared golden vectors.
    param([string]$Module, [string]$ArtifactClass, [string]$Category, [string]$Message, [string]$Detail, [string]$Severity, [string]$Confidence, [string[]]$Paths)
    $m = [string]$Message
    $m = [regex]::Replace($m, '(?i)\bPID[ =:]*[0-9]+', 'PID N')
    $m = [regex]::Replace($m, '\b[0-9]+( (?:files?|entries|items|connections?|processes|accounts?|users?|rules?|tasks?|services?|hits?|matches|events?)\b)', 'N$1')
    $pl = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($Paths)) { if ($x) { $pl.Add([string]$x) } }
    $pl.Sort([StringComparer]::Ordinal)
    $us = [string][char]0x1F; $rs = [string][char]0x1E
    $fp = Get-HashText (($Module, $ArtifactClass, $Category, $m, ($pl -join $rs)) -join $us)
    $ch = Get-HashText (($Severity, $Confidence, [string]$Detail) -join $us)
    [pscustomobject]@{ fingerprint = $fp; contentHash = $ch }
}
function Get-EvidenceSection {
    # The report section a module writes to; static, mirrors the registry order.
    param([string]$Module)
    $map = @{
        memory = '01 Memory Image (winpmem)'; network = '02 Network (connections, ARP, routes, DNS)'
        process = '03 Processes (+ suspicious LOLBAS patterns)'; sessions = '04 Logon sessions & recent logons (4624/4625)'
        services = '05 Services (with binary path)'; sysinfo = '06 System information'; users = '07 User accounts & admins'
        persistence = '08 Persistence (startup, Run keys, scheduled tasks)'; autoruns = '09 Autoruns (Sysinternals, optional)'
        shares = '10 SMB shares'; firewall = '11 Firewall profiles & enabled rules'; drivers = '12 Running kernel drivers'
        apps = '13 Installed applications'; prefetch = '14 Prefetch (last 60 days)'; usb = '15 USB device history'
        pshistory = '16 PowerShell console history'; obfscan = '17 Obfuscated/suspicious script scan (Downloads/Desktop/Temp, 30d)'
        rdp = '18 RDP activity (remote desktop)'; lateral = '19 Lateral movement artifacts'; privesc = '20 Privilege-escalation indicators'
        browser = '21 Browser artifacts (metadata, all profiles, AV-safe)'; fsartifacts = '22 Filesystem artifacts (Recent, Amcache; USN/volumes)'
        deleted = '23 Deleted files (Recycle Bin)'; shadow = '24 Volume Shadow Copies'; eventlogs = '25 Key event summary (+ optional EVTX export)'
        hives = '26 Registry hives (optional; credential material)'; mft = '27 NTFS / MFT information'
        indicators = '28 Suspicious indicators summary'; hashes = '29 Hash collection (running/startup/service binaries)'
        timeline = '30 Timeline generation (super-timeline lite)'; rmm = '31 Remote monitoring & management (RMM) evidence'
        useractivity = '32 User activity & download remnants (current user only)'
        motw = '33 Mark-of-the-Web (Zone.Identifier) - where downloaded files came from'
    }
    if ($map.ContainsKey($Module)) { $map[$Module] } else { '' }
}
function Set-FindingIdentity {
    # Final pass over the findings that will be written: adds fingerprint,
    # contentHash and evidence[] (where in this run's report the finding came
    # from). Done once, at the end, so a finding changed by an IOC match or by
    # correlation is hashed in its final form.
    param($Findings)
    $rep = if ($script:ReportFile) { Split-Path -Leaf $script:ReportFile } else { '' }
    foreach ($f in @($Findings)) {
        $conf = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $f.confidence)
        $id = Get-FindingIdentity -Module $f.module -ArtifactClass $f.artifactClass -Category $f.category -Message $f.message -Detail $f.detail -Severity $f.severity -Confidence $conf -Paths @($f.paths)
        $sec = Get-EvidenceSection $f.module
        $ev = @()
        if ($rep -and $sec) { $ev = @([pscustomobject]@{ file = $rep; section = $sec }) }
        $f | Add-Member -NotePropertyName fingerprint -NotePropertyValue $id.fingerprint -Force
        $f | Add-Member -NotePropertyName contentHash -NotePropertyValue $id.contentHash -Force
        $f | Add-Member -NotePropertyName evidence -NotePropertyValue $ev -Force
    }
}
function Add-Finding {
    # P3: aggregated suspicious findings. LEADS for analyst review, NOT verdicts.
    param([string]$Severity = 'Review', [string]$Category, [string]$Message, [string]$Detail = '', [string[]]$Technique, [string]$ArtifactClass)
    # Host-supplied text (file names, command lines) can carry terminal escapes or bidi controls; neutralise before it reaches any report.
    $Message = Remove-ControlChar $Message; $Detail = Remove-ControlChar $Detail
    if (-not $Technique -or $Technique.Count -eq 0) { $Technique = Get-Technique -Category $Category -Message $Message }
    if (-not $ArtifactClass) { $ArtifactClass = Get-ArtifactClass -Category $Category -Message $Message -Detail $Detail }
    # Closed vocabulary, checked at the call site for the same reason an unknown
    # severity is: a class nobody declared is a class no allowlist or IOC rule
    # will ever match, and it would travel all the way to a SIEM before anyone
    # noticed. Fail here rather than emit a finding the contract does not allow.
    if ($script:ArtifactClasses -notcontains $ArtifactClass) {
        throw "Add-Finding: unknown artifactClass '$ArtifactClass' (add it to `$script:ArtifactClasses)"
    }
    # An unknown severity used to become confidence 0.3 in silence - a value no
    # collector emits and both test suites reject. Fail at the call site instead
    # of shipping a finding the contract does not allow. (Checked before the id
    # is issued, so a rejected call does not leave a gap in the TTR-F sequence.)
    $conf = switch ($Severity) {
        'High'   { 0.7 }
        'Review' { 0.4 }
        default  { throw "Add-Finding: unknown severity '$Severity' (expected High or Review)" }
    }
    $script:FindingSeq++
    # paths[] is the set of paths this finding names, taken with the SAME
    # extractor the allowlist engine judges with, so the two can never
    # disagree about what a suppression decision covered. Recorded whether or
    # not an allowlist was supplied: it is the first thing an analyst wants.
    $fpaths = @(Get-PathCandidate "$Message $Detail")
    $script:Findings.Add([pscustomobject]@{
        id               = ('TTR-F-{0:D3}' -f $script:FindingSeq)
        severity         = $Severity
        category         = $Category
        technique        = @($Technique)
        message          = $Message
        detail           = $Detail
        confidence       = $conf
        confidenceReason = (Get-ConfidenceReason $conf)
        suppressed       = $false
        suppressReason   = ''
        iocMatch         = $false
        iocIndicator     = ''
        module           = $script:CurrentModule
        artifactClass    = $ArtifactClass
        collected_at     = Get-IsoUtc
        paths            = $fpaths
        recommendation   = (Get-Recommendation -Category $Category)
    })
}

function Show-Banner {
    Write-Host ""
    Write-Host ("  TATAR TRIAGE  v{0}  Windows" -f $script:ToolVersion) -ForegroundColor Cyan
    Write-Host "  DFIR / endpoint forensics console  -  read-only first, sign & allow-list, do not evade" -ForegroundColor DarkGray
    Write-Host (' ' + ('=' * 77)) -ForegroundColor DarkCyan
}

function Show-Help {
@"
TATAR Triage Toolkit v$($script:ToolVersion) - Windows quick triage collector

USAGE:
  .\Tatar.ps1 -Quick                        Highest-signal subset, ~10s (see -List)
  .\Tatar.ps1 -All                          Run all modules (order of volatility)
  .\Tatar.ps1 -Modules net,process,rdp      Run selected modules
  .\Tatar.ps1 -All -DryRun                  Preview the plan; write nothing
  .\Tatar.ps1 -List                         List available modules
  .\Tatar.ps1 -Help                         Show this help

FIRST RUN:
  1. Run the quick profile (about 10 seconds): .\Tatar.ps1 -Quick
     Without Administrator the run still works, but some artifacts are skipped and the report says which.
  2. Open summary.txt in the output folder. High findings come first, then Review.
  3. For a filterable view, open viewer.html on your own machine and load summary.json.
  A finding is a lead to check, not a verdict. Nothing on this host is changed except the output folder.

OPTIONS:
  -OutputPath <path>   Output base dir (default C:\Forensic; PREFER an external drive)
  -CaseId <id>         Case / incident id for chain of custody
  -Examiner <name>     Examiner name for chain of custody
  -Compress            Zip + SHA256 the output at the end
  -CollectHives        Save SAM/SECURITY/SYSTEM/SOFTWARE + NTUSER (may trigger EDR)
  -ExportEvtx          Export full .evtx logs
  -MemoryDump          Raw memory image via tools\winpmem.exe (may trigger EDR)
  -Silent              No console output (for WinRM/scheduled runs). Alias: -Quiet
  -DryRun              Show output dir, module order, gated ops and feed verdicts,
                       then exit 0 without creating or writing anything. Alias: -Preview
  -Allowlist <json>    Suppress known-good findings (paths[], publishers[], hashes[])
  -IOCFile <json>      Match findings/evidence vs IOCs (hashes[],ips[],domains[],filenames[])

OUTPUT EXTRAS (always written):
  summary.txt / summary.json   Analyst-first triage summary + aggregated findings
  tatar.log                    Timestamped execution log (START/OK/WARN/FAILED)
  manifest_sha256.txt          SHA-256 of every collected file (sha256sum -c format)

EXIT CODES:
  0 = success   1 = fatal / usage error   2 = completed with errors (see tatar.log)

NOTES:
  * A value-taking flag rejects a missing value: -OutputPath with no path exits 1.
  * Run PowerShell as Administrator for full collection.
  * Do NOT shut down / restart the host before collection finishes.
  * Transparent by design: code-sign & allow-list this tool; do not evade AV/EDR.
"@ | Write-Host
}

function Write-PasteLog {
    <#
        paste.txt: the whole run in 60 lines or fewer, to paste into a ticket,
        a chat or an email. The evidence folder is the record; this is the thing
        a responder can actually show someone while asking "is this normal?".

        Written to be STABLE between runs on an unchanged host. Durations,
        counters and per-run timings are deliberately absent, and the findings
        are sorted by severity, then category, then message - never by discovery
        order, which moves. One line carries the collection time and is marked
        as the only line expected to differ, so `diff` across two runs shows
        what CHANGED on the host rather than what the clock did. That property
        is what kept HijackThis logs useful for a decade.
    #>
    param([object[]]$Findings, [bool]$IsAdmin)
    try {
        $L = New-Object System.Collections.Generic.List[string]
        $hn = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
        $osCap = ''
        try { $osCap = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
        $act = @($Findings | Where-Object { -not $_.suppressed })
        $hi  = @($act | Where-Object { $_.severity -eq 'High' }).Count

        $L.Add("TATAR $($script:ToolVersion) | $hn | $osCap | admin=$IsAdmin")
        $L.Add("collected $(Get-IsoUtc)")
        $L.Add("(two lines differ between runs by design: this one and the sha256 at the end -")
        $L.Add(" everything between them is stable, so a diff of two paste logs shows what")
        $L.Add(" changed on the HOST, not what the clock did)")
        if ($CaseId -or $Examiner) { $L.Add("case=$CaseId examiner=$Examiner") }
        $L.Add("")
        $L.Add("FINDINGS: $($act.Count) active ($hi High) - leads for review, NOT verdicts")
        $L.Add("")

        $sorted = @($act | Sort-Object @{E={ if ($_.severity -eq 'High') { 0 } else { 1 } }}, category, message)
        $shown = 0
        foreach ($f in $sorted) {
            if ($shown -ge 45) { break }
            $tag = if ($f.severity -eq 'High') { 'H' } else { 'R' }
            $msg = [string]$f.message
            # A process id changes on every reboot, so leaving it here would
            # make a diff of two paste logs report a restart as a change on the
            # host. Measured, not guessed: a diff of two consecutive runs showed
            # exactly three differing lines - the collection time, the sha256,
            # and this. The PID is one file away, in summary.txt and
            # findings.json; what this log is for is "is this normal?".
            $msg = [regex]::Replace($msg, '\(PID \d+\)', '(PID n)')
            if ($msg.Length -gt 150) { $msg = $msg.Substring(0,150) + '...' }
            $L.Add(("{0} [{1,-12}] {2}" -f $tag, $f.category, $msg))
            $shown++
        }
        if ($sorted.Count -gt $shown) { $L.Add("... and $($sorted.Count - $shown) more - see summary.txt") }

        $L.Add("")
        if ($script:ModuleLimitations.Count -gt 0) {
            # What was NOT collected belongs in the pasteable log too: without
            # it a reader takes a short finding list for a clean host.
            $L.Add("NOT COLLECTED (so absence of evidence here is not evidence of absence):")
            foreach ($m in $script:ModuleLimitations.ToArray()) {
                $lim = [string]$m.limitation
                if ($lim.Length -gt 110) { $lim = $lim.Substring(0,110) + '...' }
                $L.Add("  - $($m.module): $lim")
            }
            $L.Add("")
        }
        $fj = Join-Path $script:OutDir 'findings.json'
        if (Test-PathSafe $fj) {
            $h = Get-FileHash -LiteralPath $fj -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($h) { $L.Add("sha256(findings.json) = $($h.Hash.ToLower())") }
        }
        $L.Add("Full evidence folder: see ARTIFACTS.md for what each file is.")

        [IO.File]::WriteAllText((Join-Path $script:OutDir 'paste.txt'),
            (($L -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        Write-ExecLog 'INFO' ("paste.txt written: {0} line(s)" -f $L.Count)
    } catch { Add-Err "paste.txt failed: $_" }
}

function Write-SuggestedAllowlist {
    <#
        allowlist.suggested.json: this host's active findings turned into an
        allowlist draft, in the format -Allowlist already reads.

        The workflow it exists for: run on a known-good build, trim the draft by
        hand, and use it as the fleet baseline - after which a run on fifty
        similar machines shows only the DIFFERENCES. HijackThis had the same
        idea as an interactive ignore list; the file is enough here.

        It is a DRAFT on purpose. Every path this host produced goes in, nothing
        is judged, and the comment says so - an allowlist generated from a host
        nobody checked is a way to suppress the compromise you were looking for.
    #>
    param([object[]]$Findings)
    try {
        $paths = New-Object System.Collections.Generic.List[string]
        foreach ($f in @($Findings | Where-Object { -not $_.suppressed })) {
            foreach ($p in @($f.paths)) { if ($p -and -not $paths.Contains([string]$p)) { $paths.Add([string]$p) } }
        }
        $obj = [ordered]@{
            _comment = ("DRAFT generated by TATAR {0} from {1} on {2}. NOT an allowlist yet: it lists every path this host's findings named, with nothing judged. Review every line and delete what you cannot vouch for BEFORE using it with -Allowlist - a baseline taken from a host nobody checked will suppress exactly the compromise you were looking for. Intended use: take it from a known-good build, trim it, and run the fleet against it so only the differences show." -f $script:ToolVersion, $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'this host' }), (Get-IsoUtc))
            paths = @($paths | Sort-Object)
            publishers = @()
            hashes = @()
            packageOwned = $false
        }
        Write-JsonNoBom -Path (Join-Path $script:OutDir 'allowlist.suggested.json') -Json ($obj | ConvertTo-Json -Depth 5)
        Write-ExecLog 'INFO' ("allowlist.suggested.json written: {0} path(s)" -f $paths.Count)
    } catch { Add-Err "allowlist.suggested.json failed: $_" }
}

function Write-ArtifactIndex {
    <#
        Writes ARTIFACTS.md: what is in this evidence folder, what question
        each thing answers, and what opens it.

        Built from the files that were ACTUALLY produced, not from the module
        list, so it describes this run rather than the tool in general - a
        non-Administrator run says less because it collected less.

        The last line is machine-checkable on purpose. Any produced file that
        no pattern in $script:Artifacts claims is counted as uncatalogued, and
        CI fails on a non-zero count: a new module that writes a file nobody
        described breaks the build instead of quietly shipping an unexplained
        artifact. That is the only thing keeping this list from going stale the
        way five other hand-maintained lists in this repo already have.
    #>
    try {
        # -Name returns each path RELATIVE to the directory given, which is
        # what the patterns are written against. The previous version took the
        # prefix off $_.FullName by string arithmetic, and that is wrong twice
        # over: String.StartsWith is case-SENSITIVE while Windows paths are not,
        # and a path can arrive in 8.3 short form ($env:TEMP on a GitHub runner
        # is C:\Users\RUNNER~1\...) while Get-ChildItem hands back the long
        # form, so the prefix does not match in either spelling. No arithmetic,
        # no mismatch.
        $rels  = @(Get-ChildItem -LiteralPath $script:OutDir -Recurse -File -Force -Name -ErrorAction SilentlyContinue)
        $rows  = New-Object System.Collections.Generic.List[object]
        $unmatched = New-Object System.Collections.Generic.List[string]

        foreach ($rel in $rels) {
            $rel = [string]$rel
            # First pattern wins, so the table is ordered specific-before-general
            # (FsArtifacts\*.lnk must be tried before FsArtifacts\*).
            $hit = $null
            foreach ($a in $script:Artifacts) { if ($rel -like $a.Pattern) { $hit = $a; break } }
            if ($hit) { $rows.Add([pscustomobject]@{ Class = $hit.Class; Question = $hit.Question; Next = $hit.Next; Rel = $rel }) }
            else      { $unmatched.Add($rel) }
        }

        $L = New-Object System.Collections.Generic.List[string]
        $L.Add("# Artifacts in this folder")
        $L.Add("")
        $L.Add("Host: $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() })  |  Collected: $(Get-IsoUtc)  |  TATAR $($script:ToolVersion)")
        $L.Add("")
        $L.Add("Start with ``summary.txt``. If a section looks empty, read ``tatar.log`` before")
        $L.Add("concluding that nothing was there - it records what the collector could not reach.")
        $L.Add("")
        $L.Add("| What | Files | Answers | Open it with |")
        $L.Add("|---|---|---|---|")
        foreach ($g in ($rows | Group-Object Class)) {
            $n = @($g.Group).Count
            $first = @($g.Group)[0]
            $names = if ($n -eq 1) { '`' + $first.Rel + '`' } else { "$n files" }
            $L.Add(("| {0} | {1} | {2} | {3} |" -f $g.Name, $names, $first.Question, $first.Next))
        }
        $L.Add("")
        $L.Add("Written before ``manifest_sha256.txt`` and the tail of ``tatar.log``, so those two")
        $L.Add("are described above but may not yet have existed when this index was built.")
        if ($unmatched.Count -gt 0) {
            $L.Add("")
            $L.Add("## Uncatalogued")
            $L.Add("")
            $L.Add("These files were produced but no entry in the artifact dictionary claims them.")
            $L.Add("That is a gap in the tool's documentation, not in the evidence:")
            $L.Add("")
            foreach ($u in ($unmatched | Select-Object -First 40)) { $L.Add("- ``$u``") }
        }
        $L.Add("")
        $L.Add(("Uncatalogued: {0}" -f $unmatched.Count))

        $idx = Join-Path $script:OutDir 'ARTIFACTS.md'
        [IO.File]::WriteAllText($idx, (($L -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        Write-ExecLog 'INFO' ("Artifact index written: {0} file(s) catalogued, {1} uncatalogued" -f $rows.Count, $unmatched.Count)
        if ($unmatched.Count -gt 0) {
            Add-Note ("{0} produced file(s) are not described in the artifact dictionary - see ARTIFACTS.md" -f $unmatched.Count)
        }
    } catch { Add-Err "Artifact index failed: $_" }
}

function Protect-CsvCell {
    <#
        Stops collected text from becoming a FORMULA when the analyst opens the
        CSV in a spreadsheet.

        Excel, LibreOffice and Google Sheets treat a cell beginning with =, +,
        @ or - as a formula, so a file named

            =cmd|'/c calc'!A1.txt

        on the suspect host becomes code that runs on the ANALYST's machine the
        moment they open timeline.csv. Every CSV this tool writes carries
        host-controlled text - file names, command lines, event messages - so
        this is the spreadsheet version of the separator-injection problem the
        flat record already solves for the findings pipeline, and it lands
        somewhere worse: the analyst is certain to open the file.

        A leading apostrophe is the documented fix; the spreadsheet shows the
        original text and evaluates nothing. A negative NUMBER is left alone,
        because -1 is not a formula and quoting it would corrupt real data.
    #>
    param([object]$Value)
    if ($null -eq $Value) { return $Value }
    $s = [string]$Value
    if ($s.Length -eq 0) { return $Value }
    if ($s -match '^[=+@\t\r]') { return "'" + $s }
    if ($s -match '^-' -and $s -notmatch '^-\d+([.,]\d+)?$') { return "'" + $s }
    return $Value
}

function ConvertTo-SafeCsv {
    # ConvertTo-Csv with every cell run through Protect-CsvCell first. Every CSV
    # this tool writes goes through here; check_av_safety.py (AV-09) fails the
    # build if a bare ConvertTo-Csv or Export-Csv reappears.
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)][object]$InputObject)
    begin { $rows = New-Object System.Collections.Generic.List[object] }
    process {
        if ($null -eq $InputObject) { return }
        $o = [ordered]@{}
        foreach ($pr in $InputObject.PSObject.Properties) { $o[$pr.Name] = Protect-CsvCell $pr.Value }
        $rows.Add([pscustomobject]$o)
    }
    end { if ($rows.Count -gt 0) { $rows.ToArray() | ConvertTo-Csv -NoTypeInformation } }
}

function Format-HostsEntry {
    # One hosts line -> "address -> name [name ...]", for a finding's detail.
    #
    # The line is text from the suspect host, and a finding's detail is read by
    # the path extractor, the allowlist and the IOC pass. Left as written, a
    # crafted line such as
    #     1.2.3.4  C:\Windows\System32\svchost.exe
    # would put a signed system binary into paths[], and a publisher or path
    # rule could then suppress the very finding that reports the tampering.
    # So each field is reduced to the characters it can legally contain: an
    # address keeps hex digits, ':' and '.', a name keeps letters, digits,
    # '.', '_' and '-'. No backslash, slash, quote or control character
    # survives, which is what makes the result safe to quote.
    param([string]$Line)
    $t = ($Line -replace '#.*$', '').Trim()
    if (-not $t) { return '' }
    $parts = @($t -split '\s+')
    $addr  = $parts[0] -replace '[^0-9A-Fa-f:.]', '?'
    $names = @($parts | Select-Object -Skip 1 | ForEach-Object { $_ -replace '[^A-Za-z0-9._-]', '?' })
    if ($names.Count -eq 0) { $names = @('(no name)') }
    $s = '{0} -> {1}' -f $addr, ($names -join ' ')
    # A hosts line may carry hundreds of aliases; the report has the full file.
    if ($s.Length -gt 100) { $s = $s.Substring(0, 100) + '...' }
    return $s
}

function Test-HostsDefault {
    # Is this hosts line a stock entry the operating system ships, rather than
    # an override somebody added?
    #
    # A line is stock only if its ADDRESS is one of the well-known ones AND
    # every name on it is a name that address ships with. Anchoring on the
    # address alone would hide `127.0.0.1 update.vendor.example` - a sinkhole
    # that stops a machine reaching its own update server - and testing for the
    # address anywhere on the line would hide `203.0.113.9 login.bank.example
    # 127.0.0.1`, where the loopback is merely an alias. Both are exactly what
    # an attacker would write, so neither shortcut is acceptable.
    #
    # Names for 127.0.1.1 are matched against THIS host's own name, with no
    # lookup: asking for the fully qualified name would send a DNS query from
    # the machine under examination.
    param([string]$Line, [string]$HostName = '')
    $t = ($Line -replace '#.*$', '').Trim()
    if (-not $t) { return $true }
    $parts = @($t -split '\s+')
    $addr  = $parts[0].ToLowerInvariant()
    $names = @($parts | Select-Object -Skip 1 | ForEach-Object { $_.ToLowerInvariant() })
    if ($names.Count -eq 0) { return $false }
    $own = $HostName.ToLowerInvariant()
    if ($addr -eq '127.0.1.1') {
        if (-not $own) { return $false }
        foreach ($n in $names) { if ($n -ne $own -and -not $n.StartsWith($own + '.')) { return $false } }
        return $true
    }
    $stock = @{
        '127.0.0.1' = @('localhost', 'localhost.localdomain', 'localhost4', 'localhost4.localdomain4')
        '::1'       = @('localhost', 'localhost.localdomain', 'localhost6', 'localhost6.localdomain6', 'ip6-localhost', 'ip6-loopback')
        'fe00::0'   = @('ip6-localnet')
        'fe00::'    = @('ip6-localnet')
        'ff00::0'   = @('ip6-mcastprefix')
        'ff00::'    = @('ip6-mcastprefix')
        'ff02::1'   = @('ip6-allnodes')
        'ff02::2'   = @('ip6-allrouters')
        'ff02::3'   = @('ip6-allhosts')
    }
    if (-not $stock.ContainsKey($addr)) { return $false }
    foreach ($n in $names) { if ($stock[$addr] -notcontains $n) { return $false } }
    return $true
}

function Out-FileNoBom {
    <#
        Out-File -Encoding UTF8 writes a UTF-8 BOM on Windows PowerShell 5.1 and
        none on pwsh 7. The JSON documents were moved off it in 1.4 after the BOM
        made them unparseable by Python; every OTHER text output was left behind,
        so on 5.1 the report, the summary and - worst - tatar.log all began with
        a stray U+FEFF. In the log that breaks the first record for grep '^\[',
        for awk, and for any ingester that anchors a pattern at the line start.

        Same call shape as Out-File so the 70-odd call sites read unchanged,
        minus the -Encoding argument, which no longer has anything to decide.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)][object]$InputObject,
        [Parameter(Position = 0)][string]$FilePath,
        [switch]$Append
    )
    begin { $sb = New-Object System.Text.StringBuilder }
    process { [void]$sb.AppendLine([string]$InputObject) }
    end {
        if (-not $FilePath) { return }
        $enc = New-Object System.Text.UTF8Encoding $false
        # Every text this collector writes is read in a terminal: control, escape and bidi characters that host data carried in become U+FFFD.
        $txt = [regex]::Replace($sb.ToString(), '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u202A-\u202E\u2066-\u2069]', [string][char]0xFFFD)
        try {
            if ($Append) { [System.IO.File]::AppendAllText($FilePath, $txt, $enc) }
            else         { [System.IO.File]::WriteAllText($FilePath, $txt, $enc) }
        } catch {
            # Never let an output-encoding problem take a collection down.
            [Console]::Error.WriteLine("[!] write failed: $FilePath - $_")
        }
    }
}

function Add-Report  { param([string]$Text = '') $Text | Out-FileNoBom -FilePath $script:ReportFile -Append }
function Add-Section { param([string]$Title) "`n===== $Title =====`n" | Out-FileNoBom -FilePath $script:ReportFile -Append }
function Add-Err     {
    param([string]$Msg)
    $script:ErrorCount++
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$t] ERROR: $Msg" | Out-FileNoBom -FilePath $script:ReportFile -Append
    if ($script:ExecLog) { ("[{0}] [{1,-6}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), 'ERROR', $Msg) | Out-FileNoBom -FilePath $script:ExecLog -Append }
}

function Invoke-Ext {
    param([string]$File, [string[]]$Arguments, [string]$OutFile)
    try {
        if ($OutFile) { & $File @Arguments *> $OutFile }
        else { (& $File @Arguments 2>&1) | Out-FileNoBom -FilePath $script:ReportFile -Append }
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            Add-Err ("{0} {1} exit code {2}" -f $File, ($Arguments -join ' '), $LASTEXITCODE)
        }
    } catch { Add-Err ("Invoke-Ext {0} failed: {1}" -f $File, $_) }
}

# The two JSON documents are the machine contract, so they are written through
# one function with an encoding that does not depend on which PowerShell is
# running. `Out-File -Encoding UTF8` means UTF-8 WITH a byte-order mark on
# Windows PowerShell 5.1 - the version this tool declares as its minimum - and
# WITHOUT one on PowerShell 7. A leading BOM is not valid JSON text to a strict
# parser: Python's json.load refuses the file outright. CI runs pwsh 7, so for
# three releases the flagship producer shipped a document that a standard
# parser rejected on the very version most responders run it with, and nothing
# noticed. Both harnesses now assert the first byte.
function Write-JsonNoBom {
    param([string]$Json, [string]$Path)
    [System.IO.File]::WriteAllText($Path, $Json, (New-Object System.Text.UTF8Encoding $false))
}

function New-SubDir { param([string]$Name) $p = Join-Path $script:OutDir $Name; New-Item -ItemType Directory -Force -Path $p | Out-Null; return $p }

# Safe test: never throw on access-denied
function Test-PathSafe { param([string]$Path) try { return [bool](Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) } catch { return $false } }
function Copy-Safe {
    param([string]$Src, [string]$Dst)
    try { if (Test-PathSafe $Src) { Copy-Item -LiteralPath $Src -Destination $Dst -Recurse -Force -ErrorAction SilentlyContinue } } catch { Add-Err "Copy $Src failed: $_" }
}

# Note = expected/benign condition. Logged as WARN; does NOT count as an error or change exit code.
#
# Every existing call site is already a statement of what a module could not do
# - "RecentFailedLogons was NOT measured", "capped at N by -MaxEvents", "fell
# back to netstat". They were readable only by whoever opened the log. Recording
# them here as well makes the whole set machine-readable through
# summary.moduleLimitations without touching a single call site, which is the
# point: a limitation nobody can query is a limitation nobody acts on.
function Add-Note {
    param([string]$Msg)
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$t] NOTE: $Msg" | Out-FileNoBom -FilePath $script:ReportFile -Append
    Write-ExecLog 'WARN' $Msg
    $script:ModuleLimitations.Add([pscustomobject]@{
        # '(run)', not '': a limitation raised before any module starts - the
        # "not running as Administrator" one above all - grouped under a blank
        # key in summary.json and was dropped from paste.txt, which is the one
        # place a reader most needs to see it.
        module     = $(if ($script:CurrentModule) { $script:CurrentModule } else { '(run)' })
        limitation = $Msg
    })
}

# Best-effort copy for files commonly locked on a live host (Amcache.hve, NTUSER.DAT...).
# A failure here is EXPECTED, not a collection error -> logged as a NOTE (exit code stays 0).
function Copy-BestEffort {
    param([string]$Src, [string]$Dst, [string]$Hint = 'locked by the OS on a live system; acquire via VSS / RawCopy / offline')
    if (-not (Test-PathSafe $Src)) { return }
    try { Copy-Item -LiteralPath $Src -Destination $Dst -Force -ErrorAction Stop }
    catch { Add-Note ("Could not copy {0} - {1}." -f $Src, $Hint) }
}

function Get-ServiceImagePath {
    # The executable out of a service ImagePath, which is a COMMAND LINE, not a
    # path: 'C:\Windows\system32\svchost.exe -k netsvcs' is the normal form.
    # Stripping only surrounding quotes left the arguments attached, so
    # Test-Path failed and svchost - i.e. most of Windows - was never hashed.
    # Quoted wins outright; otherwise take the shortest leading run that ends in
    # .exe at a word boundary, which is also what the service control manager
    # resolves first. Returns $null when there is no .exe (driver .sys entries).
    param([string]$PathName)
    # The .exe rule applies to the quoted form too. It used to return whatever
    # was inside the quotes, so a quoted driver entry -- "C:\Windows\system32\
    # drivers\foo.sys" -- came back as a path and was fed to Get-FileHash,
    # contradicting the contract two lines above and hashing a driver as though
    # it were a service executable.
    if ($PathName -match '^\s*"([^"]+)"') {
        # Capture BEFORE the next -match: that operator reassigns $matches, so
        # testing $matches[1] and then returning $matches[1] returns the inner
        # match's groups, i.e. $null.
        $quoted = $matches[1]
        if ($quoted -match '\.exe$') { return $quoted }
        return $null
    }
    if ($PathName -match '^\s*(\S.*?\.exe)(\s|$)') { return $matches[1] }
    return $null
}

function Test-NoMatchingEvents {
    # Get-WinEvent -ErrorAction Stop throws for two completely different
    # reasons: the log could not be read (access denied, log disabled), and the
    # filter simply matched nothing - which is a CLEAN result. Collect-Sessions
    # reported both as '(not available / access denied)', so an operator on a
    # quiet host was told they had a permissions problem they did not have, and
    # then went and re-ran the whole collection elevated for nothing.
    #
    # The fully-qualified error id is the documented discriminator. The message
    # test behind it is deliberate belt-and-braces: the id has NOT been confirmed
    # against a live Get-WinEvent from here (no Windows host), and the caller's
    # other branch now prints the real exception text, so a miss degrades to the
    # truth rather than back to a guess.
    param($ErrorRecord)
    if (-not $ErrorRecord) { return $false }
    if ("$($ErrorRecord.FullyQualifiedErrorId)" -like '*NoMatchingEventsFound*') { return $true }
    return ("$($ErrorRecord.Exception.Message)" -match '(?i)no events were found that match')
}

# =====================================================================
#  Collector modules
# =====================================================================

function Collect-Memory {
    Add-Section '01 Memory Image (winpmem)'
    if (-not $MemoryDump) { Add-Report 'Skipped (use -MemoryDump to enable).'; Add-Note 'memory was NOT captured: -MemoryDump was not supplied'; return }
    $tool = Join-Path $PSScriptRoot 'tools\winpmem.exe'
    if (-not (Test-PathSafe $tool)) { Add-Report 'winpmem.exe not in tools\. Skipping.'; Add-Note 'memory was NOT captured: tools\winpmem.exe is not present'; return }
    $img = Join-Path $script:OutDir 'memory.raw'
    Invoke-Ext -File $tool -Arguments @('--output', $img, '--format', 'raw') -OutFile (Join-Path $script:OutDir 'winpmem_log.txt')
    if ((Test-PathSafe $img) -and ((Get-Item $img -ErrorAction SilentlyContinue).Length -gt 0)) {
        (Get-FileHash $img -Algorithm SHA256).Hash | Out-FileNoBom (Join-Path $script:OutDir 'memory.raw.sha256.txt')
        Add-Report ("Memory image captured: {0:N0} bytes." -f (Get-Item $img).Length)
    } else {
        Add-Err 'winpmem produced no/empty image - on Win10/11 with HVCI / Core Isolation / Memory Integrity the driver is commonly blocked. Check winpmem_log.txt; use a signed acquisition tool or disable VBS on the forensic host.'
    }
}

function Test-PublicAddress {
    # True for an address a reputation service can say something about: a
    # globally routed IPv4 or IPv6 unicast address. Loopback, private,
    # link-local, shared (100.64/10), documentation, benchmarking, multicast and
    # reserved ranges are not. An IPv4-mapped IPv6 address is judged as the IPv4
    # inside it. The Linux edition applies the same rule (public_addr_filter);
    # tests/fixtures/public-address-cases.tsv holds both to it.
    param([string]$Address)
    $a = ($Address -replace '%.*$', '').Trim()
    if (-not ($a -match '^\d{1,3}(\.\d{1,3}){3}$' -or $a.Contains(':'))) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -eq 'InterNetworkV6' -and $ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq 'InterNetwork') {
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 0 -and ($b[2] -eq 0 -or $b[2] -eq 2)) { return $false }
        if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) { return $false }
        if ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) { return $false }
        if ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113) { return $false }
        return $true
    }
    if ($ip.AddressFamily -eq 'InterNetworkV6') {
        if (($b[0] -band 0xE0) -ne 0x20) { return $false }    # global unicast is 2000::/3 only
        if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0D -and $b[3] -eq 0xB8) { return $false }   # 2001:db8::/32 documentation
        return $true
    }
    $false
}

function Collect-Network {
    Add-Section '02 Network (connections, ARP, routes, DNS)'
    try {
        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }
        $listenCount = 0; $estabCount = 0
        # Public addresses of established connections, one line per address,
        # port and process: the list an analyst looks up afterwards, on their own
        # machine. The collector itself looks nothing up.
        $extRows = New-Object 'System.Collections.Generic.HashSet[string]'
        $extAddr = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        try {
            foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
                if     ($c.State -eq 'Listen')      { $listenCount++ }
                elseif ($c.State -eq 'Established') { $estabCount++ }
                $pn = if ($procMap.ContainsKey([int]$c.OwningProcess)) { $procMap[[int]$c.OwningProcess] } else { '' }
                ("{0}:{1} -> {2}:{3} [{4}] PID:{5} {6}" -f $c.LocalAddress,$c.LocalPort,$c.RemoteAddress,$c.RemotePort,$c.State,$c.OwningProcess,$pn) | Out-FileNoBom $script:ReportFile -Append
                if ($c.State -eq 'Established' -and (Test-PublicAddress ([string]$c.RemoteAddress))) {
                    [void]$extAddr.Add([string]$c.RemoteAddress)
                    [void]$extRows.Add(("{0}`t{1}`t{2} (PID {3})" -f $c.RemoteAddress, $c.RemotePort, $(if ($pn) { $pn } else { '?' }), $c.OwningProcess))
                }
            }
            $extFile = Join-Path $script:OutDir 'external_ips.txt'
            $extText = @('# Public remote addresses of established TCP connections at collection time.',
                         '# address<TAB>remote port<TAB>process (PID). Look them up on the analyst machine; the collector looks nothing up.') +
                       @($extRows | Sort-Object)
            [IO.File]::WriteAllText($extFile, (($extText -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
            $script:Stats['ExternalAddresses'] = $extAddr.Count
            Add-Report ("Public remote addresses of established connections: {0} -> external_ips.txt" -f $extAddr.Count)
            # The same two counters the Linux edition emits (ss -tlnp / ss -tuna),
            # instead of one Windows-only 'TcpConnections': one dashboard has to
            # be able to plot "listening ports" across platforms.
            $script:Stats['ListeningTcpPorts']      = $listenCount
            $script:Stats['EstablishedConnections'] = $estabCount
        } catch {
            # The reason used to be thrown away: the operator saw netstat output
            # and no statement that Get-NetTCPConnection had failed, let alone
            # why - and 'not elevated enough' and 'the cmdlet is genuinely
            # absent' mean different things for the evidence.
            Add-Note ("Get-NetTCPConnection failed ({0}); fell back to netstat -ano." -f $_.Exception.Message)
            # ListeningTcpPorts / EstablishedConnections are set INSIDE the try,
            # so on this path they are never set. They are left absent on
            # purpose rather than zeroed - 0 reads as 'no listening ports' when
            # the truth is 'not measured' - and the gap is stated here so it is
            # visible in the report and the log instead of only as a missing
            # key. Parsing the two counters back out of netstat is the real
            # repair; netstat's state column is localised, so it needs a
            # non-English Windows first (N-2 in tests/WINDOWS_STATIC_REVIEW.md).
            Add-Note 'ListeningTcpPorts / EstablishedConnections were NOT measured on the netstat fallback path.'
            Add-Note 'external_ips.txt was NOT written on the netstat fallback path.'
            cmd /c "netstat -ano" | Out-FileNoBom $script:ReportFile -Append
        }
        arp -a | Out-FileNoBom (Join-Path $script:OutDir 'arp.txt')
        route print | Out-FileNoBom (Join-Path $script:OutDir 'routes.txt')
        ipconfig /displaydns | Out-FileNoBom (Join-Path $script:OutDir 'dns_cache.txt')
        ipconfig /all | Out-FileNoBom (Join-Path $script:OutDir 'ipconfig.txt')
        $hostsFile = Join-WinPath $script:SysRoot 'System32\drivers\etc\hosts'
        Get-Content $hostsFile -ErrorAction SilentlyContinue | Out-FileNoBom (Join-Path $script:OutDir 'hosts.txt')
        # Mirror of the Linux check: the file is already being collected, and a
        # static host override that silently redirects traffic is one of the
        # cheapest, highest-signal triage checks there is. Windows collected the
        # file and never looked at it, while docs/MITRE_ATTACK.md advertised the
        # check. (Counted like the Linux side: comments, blanks and the stock
        # loopback / IPv6 lines do not count as custom entries - see
        # Test-HostsDefault for what "stock" means and why it is that strict.)
        $hx = @(Get-Content $hostsFile -ErrorAction SilentlyContinue |
                Where-Object { -not (Test-HostsDefault $_ $env:COMPUTERNAME) })
        if ($hx.Count -gt 0) {
            # The count alone made the analyst open hosts.txt to learn anything.
            # Name the first few overrides in the finding itself, so the address
            # and the host name it captures are visible in the summary and
            # reachable by the IOC pass. Format-HostsEntry is what keeps that
            # host-supplied text from planting a path in paths[].
            $hfirst = @($hx | Select-Object -First 5 | ForEach-Object { Format-HostsEntry $_ })
            Add-Finding -Severity 'Review' -Category 'network' -Message ("hosts file has {0} custom entries" -f $hx.Count) -Detail ("First {0} of {1}: {2} | Review hosts.txt in the output folder - static host overrides can redirect traffic (T1565.001)" -f $hfirst.Count, $hx.Count, ($hfirst -join ' ; '))
        }
        Add-Report 'Network artifacts saved (arp/routes/dns_cache/ipconfig/hosts).'
    } catch { Add-Err "Network failed: $_" }
}

# What a credential dump by ANOTHER program looks like on a command line. These
# rules are only matched against text the run collected (command lines, the
# PowerShell history, event 4688); nothing here opens a process. AV-02 forbids
# these words anywhere else in the collector, and check_av_safety.py exempts
# this one table and nothing else.
$script:CredDumpRules = @(
    @{ All = @('comsvcs', 'minidump|\u0023\+?0*24\b'); Label = 'LSASS memory dump through comsvcs.dll MiniDump' },
    @{ All = @('\bprocdump(64)?(\.exe)?\b', '\blsass\b'); Label = 'LSASS memory dump through ProcDump' }
)

function Get-TextIndicator {
    # The strongest indicator in one piece of collected text, or nothing: a
    # credential dump (High, labelled "credential dump"), or a URL written in
    # hex or base64 (Review). Only the encoded start of "http://" and
    # "https://" counts, which no format or tool name changes, and only where
    # an encoded value starts: inside a longer hex or base64 run (a
    # certificate, a hex dump) the same characters are data. Shared cases:
    # tests/fixtures/text-indicator-cases.tsv.
    param([string]$Text)
    if (-not $Text) { return }
    foreach ($r in $script:CredDumpRules) {
        $ok = $true
        foreach ($p in $r.All) { if ($Text -notmatch "(?i)$p") { $ok = $false; break } }
        if ($ok) { return [pscustomobject]@{ Kind = 'credential dump'; Label = $r.Label; Severity = 'High' } }
    }
    if ($Text -match '(?i)(?<![0-9a-f])(68747470733a2f2f|687474703a2f2f)') { return [pscustomobject]@{ Kind = 'URL written in hex'; Label = 'URL written in hex'; Severity = 'Review' } }
    if ($Text -cmatch '(?<![A-Za-z0-9+/])(aHR0cHM6Ly|aHR0cDovL)') { return [pscustomobject]@{ Kind = 'URL written in base64'; Label = 'URL written in base64'; Severity = 'Review' } }
}

function Format-TextIndicatorMessage {
    # One wording for every place a text indicator is found, so Get-Technique
    # maps it the same way: "credential dump" and "URL written in hex|base64".
    param($Indicator, [string]$Where)
    if ($Indicator.Kind -eq 'credential dump') { return ("Credential dump command line: {0} in {1}" -f $Indicator.Label, $Where) }
    return ("Command line carries a {0} in {1}" -f $Indicator.Label, $Where)
}

function Get-OfficeMacroMarker {
    # Whether an Office file carries a VBA project, from its bytes alone: an
    # OOXML file (.docm, .xlsm...) is a zip, and a zip stores the entry name
    # vbaProject.bin uncompressed; a legacy OLE file (.doc, .xls...) names the
    # stream _VBA_PROJECT in UTF-16. The file is read, never opened by Office
    # and never parsed, so nothing in it runs. Returns the marker or ''.
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 16) { return '' }
    $s = [Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    if ($s.IndexOf('vbaProject.bin', [StringComparison]::OrdinalIgnoreCase) -ge 0) { return 'vbaProject.bin' }
    if ($s.IndexOf("_`0V`0B`0A`0_`0P`0R`0O`0J`0E`0C`0T`0", [StringComparison]::Ordinal) -ge 0) { return '_VBA_PROJECT' }
    ''
}

function Collect-Process {
    Add-Section '03 Processes (+ suspicious LOLBAS patterns)'
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction Stop |
                 Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate
        $script:Stats['Processes'] = @($procs).Count
        $procs | Sort-Object ProcessId | Format-Table -AutoSize | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
        $sus = @('powershell','cmd\.exe','rundll32','mshta','regsvr32','certutil','bitsadmin','wmic',
                 'wscript','cscript','\bnc\.exe','\bncat','psexec','mimikatz',$script:EncArgPattern,'frombase64string','downloadstring','\biex\b')
        Add-Report "`n-- Suspicious process indicators --"
        foreach ($p in $procs) {
            if ($p.CommandLine) {
                $ti = Get-TextIndicator ([string]$p.CommandLine)
                if ($ti) {
                    ("[!] PID {0} (parent {1}) {2}: {3}`n    Cmd : {4}" -f $p.ProcessId,$p.ParentProcessId,$p.Name,$ti.Label,$p.CommandLine) | Out-FileNoBom $script:ReportFile -Append
                    $cl = [string]$p.CommandLine; if ($cl.Length -gt 200) { $cl = $cl.Substring(0,200) + '...' }
                    Add-Finding -Severity $ti.Severity -Category 'process' -Message (Format-TextIndicatorMessage $ti ("{0} (PID {1})" -f $p.Name, $p.ProcessId)) -Detail $cl
                    continue
                }
                foreach ($s in $sus) {
                    # A bare powershell.exe / cmd.exe is not a lead; what it was told to run is.
                    $subject = [string]$p.CommandLine
                    if ($s -eq 'powershell' -or $s -eq 'cmd\.exe') { $subject = Remove-ExeToken $subject }
                    if ($subject -imatch $s) {
                        ("[!] PID {0} (parent {1}) {2}`n    Path: {3}`n    Cmd : {4}" -f $p.ProcessId,$p.ParentProcessId,$p.Name,$p.ExecutablePath,$p.CommandLine) | Out-FileNoBom $script:ReportFile -Append
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
            ("{0}{1} (PID {2})" -f ('  '*$depth), $proc.Name, $proc.ProcessId) | Out-FileNoBom $script:ReportFile -Append
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
        # quser.exe ships with the Remote Desktop Services tools, which Windows
        # Home does not have. Calling it there threw CommandNotFound into the
        # catch below and skipped net session and the 4624/4625 queries too.
        if (Get-Command 'quser.exe' -CommandType Application -ErrorAction SilentlyContinue) {
            (quser 2>&1) | Out-FileNoBom $script:ReportFile -Append
        } else {
            Add-Report 'quser.exe is not present on this Windows edition; interactive sessions were not listed.'
            Add-Note 'interactive sessions were NOT listed: quser.exe is not present on this Windows edition (Home has none)'
        }
        (net session 2>&1) | Out-FileNoBom $script:ReportFile -Append
        # The cap was written three times - -MaxEvents, the report heading and
        # the saturation test - so it could be changed in one place and leave
        # the heading asserting a number that was never read.
        $evtCap = 15
        foreach ($id in 4624,4625) {
            Add-Report ("`n-- Security Event {0} (last {1}) --" -f $id, $evtCap)
            try {
                $evts = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id} -MaxEvents $evtCap -ErrorAction Stop)
                $evts | Select-Object TimeCreated, Id, Message | Format-List | Out-String | Out-FileNoBom $script:ReportFile -Append
                if ($id -eq 4625) {
                    $script:Stats['RecentFailedLogons'] = $evts.Count
                    if ($evts.Count -ge $evtCap) {
                        # The counter SATURATES: -MaxEvents stops at the cap, so
                        # the cap value means 'this many or more', never exactly
                        # this many - and 'four thousand failed logons' is the
                        # case this check exists to surface. An uncapped count
                        # needs a second, count-only query whose cost on a large
                        # Security log has to be measured on Windows (SE-1), so
                        # until then the limit is stated instead of implied.
                        Add-Note ("RecentFailedLogons is capped at {0} by -MaxEvents; the true 4625 count is {0} or higher." -f $evtCap)
                        Add-Finding -Category 'sessions' -Message ("High volume of failed logons (4625): {0}+ in recent Security log" -f $evtCap) -Detail 'See report section 04; possible brute force - review source accounts/IPs'
                    }
                }
            } catch {
                if (Test-NoMatchingEvents $_) {
                    Add-Report ("  (no event {0} records in the Security log)" -f $id)
                    # A query that ran and matched nothing is a real zero, so the
                    # key belongs in summary.json. Previously it was absent here
                    # too, which a consumer cannot tell apart from 'not measured'.
                    if ($id -eq 4625) { $script:Stats['RecentFailedLogons'] = 0 }
                } else {
                    Add-Report ("  (event {0} could not be read: {1})" -f $id, $_.Exception.Message)
                    if ($id -eq 4625) { Add-Note 'RecentFailedLogons was NOT measured: the 4625 query failed.' }
                }
            }
        }
    } catch { Add-Err "Sessions failed: $_" }
}

function Collect-Services {
    Add-Section '05 Services (with binary path)'
    try {
        $svcs = Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
        # Canonical key shared with the Linux edition, which counts RUNNING
        # units - so this counts running services, not every defined service.
        $script:Stats['RunningServices'] = @($svcs | Where-Object { $_.State -eq 'Running' }).Count
        $svcs | Sort-Object State | Format-Table -AutoSize | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Err "Services failed: $_" }
}

function Collect-SysInfo {
    Add-Section '06 System information'
    try {
        (hostname) | Out-FileNoBom $script:ReportFile -Append
        (whoami /all 2>&1) | Out-FileNoBom $script:ReportFile -Append
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, CSName, LastBootUpTime, InstallDate | Format-List | Out-String | Out-FileNoBom $script:ReportFile -Append
        Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, Domain, PartOfDomain | Format-List | Out-String | Out-FileNoBom $script:ReportFile -Append
        # DomainRole 4 and 5 are backup and primary domain controllers. Say so in the report and
        # as a limitation: on a controller the "local" account and group lists describe the domain,
        # and the directory itself (objects, replication, the NTDS database) is not examined here.
        try {
            $dr = [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole
            $drName = @('standalone workstation','member workstation','standalone server','member server','backup domain controller','primary domain controller')[$dr]
            "DomainRole: $dr ($drName)" | Out-FileNoBom $script:ReportFile -Append
            if ($dr -ge 4) { Add-Note "This host is a domain controller: the account and group lists describe the domain, and Active Directory itself (objects, replication, the directory database) is NOT examined by this tool." }
        } catch { Add-Note "Domain role was NOT read: $_" }
        "TimeZone: $((Get-TimeZone).Id)" | Out-FileNoBom $script:ReportFile -Append
        Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn -Descending | Out-String | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Err "SysInfo failed: $_" }
}

function Collect-Users {
    Add-Section '07 User accounts & admins'
    try {
        (net user 2>&1) | Out-FileNoBom $script:ReportFile -Append
        (net localgroup administrators 2>&1) | Out-FileNoBom $script:ReportFile -Append
        # Absent is not zero. -ErrorAction SilentlyContinue turned a FAILED query
        # into $null, the guard then left 'Accounts' out of summary.json, and a
        # consumer read that as 'this host has no local accounts' - off a query
        # that never ran. Get-LocalUser genuinely fails on a domain controller
        # and under some AppLocker policies, so this is not hypothetical. Stop
        # plus a catch separates the two: a result that came back sets the
        # counter, zero included; a failure leaves it absent and says so.
        $lu = @()
        try {
            $lu = @(Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet)
            $script:Stats['Accounts'] = $lu.Count
        } catch { Add-Note "Get-LocalUser failed, Accounts was NOT measured: $_" }
        $lu | Format-Table -AutoSize | Out-String | Out-FileNoBom $script:ReportFile -Append
        # Mirrors of the Linux users checks (second UID-0 account / empty
        # password): this module collected the data and raised nothing, so the
        # same incident produced a High finding on a Linux host and silence on a
        # Windows one - not because Windows was clean, but because nobody looked.
        try {
            $noPwd = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
                       Where-Object { -not $_.Disabled -and -not $_.PasswordRequired })
            foreach ($u in $noPwd) {
                $row = @($lu | Where-Object { $_.Name -eq $u.Name } | Select-Object -First 1)
                $known = ($row.Count -eq 1)
                $pls = if ($known) { $row[0].PasswordLastSet } else { $null }
                $sev = Get-NoPasswordSeverity -PasswordLastSet $pls -Known $known
                $det = if ($sev -eq 'High') {
                    'PasswordLastSet is empty or unreadable, so a password has probably never been set. UNCONFIRMED: the account is enabled and PasswordRequired is false, which is a policy flag, not proof. Confirm against the host policy and the account owner - see report section 07'
                } else {
                    ('A password was set ({0}); PasswordRequired false is a policy setting that ALLOWS an empty password, not proof of one. Worth tightening (net user {1} /passwordreq:yes), not an emergency - see report section 07' -f ([datetime]$pls).ToString('yyyy-MM-dd'), $u.Name)
                }
                Add-Finding -Severity $sev -Category 'users' -Message ("Enabled local account with NO password required: {0}" -f $u.Name) -Detail $det
            }
        } catch { Add-Note "Win32_UserAccount query failed: $_" }
        try {
            # Anything in local Administrators other than the built-in RID-500
            # account is worth an analyst's eye; the SID suffix is the only
            # locale-independent way to recognise that account. The GROUP has to
            # be resolved the same way: 'Administrators' is localised - it is
            # Administradores, Administrateurs, Администраторы - so looking it up
            # by name threw on every non-English Windows and this check reported
            # silence about a host it had never actually examined. S-1-5-32-544
            # is the same group everywhere.
            $extraAdmins = @(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544') -ErrorAction Stop |
                             Where-Object { $_.SID -and ($_.SID.Value -notmatch '-500$') })
            if ($extraAdmins.Count -gt 0) {
                Add-Finding -Severity 'Review' -Category 'users' -Message ("{0} local Administrators member(s) besides the built-in account" -f $extraAdmins.Count) -Detail (("Members: " + (($extraAdmins | ForEach-Object { $_.Name }) -join ', ')))
            }
        } catch { Add-Note "Get-LocalGroupMember Administrators failed: $_" }
    } catch { Add-Err "Users failed: $_" }
}

function Get-RiskyAutostartFolder {
    # Names the folder an autostart command points into when that folder is one a
    # standard user can write to AND is not where ordinary software keeps its
    # updaters; returns '' otherwise. Deliberately NOT AppData: OneDrive, Teams and
    # most updaters autostart from there, and a rule that fired on all of them would
    # be the 144-findings-of-which-142-were-noise module this project already shipped
    # once. ProgramData is out too: a real workstation raised a lead for an ordinary game
    # launcher that autostarts from there, and remote-access tools have their own check.
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = $Command
    try { $c = [Environment]::ExpandEnvironmentVariables($Command) } catch {}
    if     ($c -match '(?i)\\Users\\Public\\')                                 { return 'Users\Public' }
    elseif ($c -match '(?i)\\Windows\\Temp\\')                                  { return 'Windows\Temp' }
    elseif ($c -match '(?i)\\AppData\\Local\\Temp\\')                           { return 'a user Temp folder' }
    elseif ($c -match '(?i)\\Users\\[^\\]+\\Downloads\\')                      { return 'a Downloads folder' }
    elseif ($c -match '(?i)\\\$Recycle\.Bin\\')                                 { return 'the Recycle Bin' }
    return ''
}

function Add-AutostartFindings {
    # Entries: objects with Name, Command, Location, Kind (run-key | startup-folder |
    # scheduled-task) and What ('Autostart entry' | 'Scheduled task'). Capped so a
    # host with a whole folder of such entries is one readable lead, not fifty.
    param([object[]]$Entries)
    $n = 0
    foreach ($e in @($Entries)) {
        $where = Get-RiskyAutostartFolder ([string]$e.Command)
        if (-not $where) { continue }
        $n++
        if ($n -gt 10) { continue }
        $tech = if ($e.Kind -eq 'scheduled-task') { 'T1053.005' } else { 'T1547.001' }
        $cmd = [string]$e.Command; if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) + '...' }
        Add-Finding -Severity 'Review' -Category 'persistence' -ArtifactClass $e.Kind -Technique $tech `
            -Message ("{0} '{1}' starts a program from {2}" -f $e.What, $e.Name, $where) `
            -Detail ("{0} -> {1} . Software that autostarts from here is not installed the way ordinary software is; check who put it there." -f $e.Location, $cmd)
    }
    if ($n -gt 10) { Add-Report ("({0} more autostart entries point into those folders; only the first 10 are raised as findings.)" -f ($n - 10)) }
    if ($n -gt 0) { Add-Report ("{0} autostart entr{1} point into a user-writable folder (Users\Public, Temp, Downloads, Recycle Bin)." -f $n, $(if ($n -eq 1) { 'y' } else { 'ies' })) }
}

function Collect-Persistence {
    Add-Section '08 Persistence (startup, Run keys, scheduled tasks)'
    try {
        $startupCmds = @(Get-CimInstance Win32_StartupCommand)
        $startupCmds | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
        # Run and RunOnce are the same ASEP in two flavours and an attacker
        # picks whichever is unwatched, so the list covers both under each hive
        # and under the 32-bit Wow6432Node view. HKCU RunOnce and the 32-bit
        # RunOnce were missing, which meant two standard persistence locations
        # produced no line in the report at all - and a blank report reads as
        # 'nothing there', not as 'never looked'.
        $runKeys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        # HKCU: is the hive of whoever is RUNNING the collector. Under SYSTEM,
        # or under a responder's own admin account, that is not the compromised
        # user, and this module then reports on a hive nobody cares about while
        # looking like it covered per-user persistence. Sweeping HKU\* instead
        # means mounting other users' NTUSER.DAT on a live host, which is a
        # scope decision with evidence-integrity consequences and not a bug fix
        # (PE-2). Until it is taken, the limit is named in the evidence rather
        # than left for the reader to infer from an empty section.
        Add-Report ("`n(The HKCU keys below are the hive of the collecting user '{0}' ONLY. Other users' Run/RunOnce keys are NOT collected - see PE-2 in tests/WINDOWS_STATIC_REVIEW.md.)" -f $env:USERNAME)
        foreach ($k in $runKeys) { if (Test-PathSafe $k) { Add-Report "`n[$k]"; (Get-ItemProperty $k -ErrorAction SilentlyContinue) | Out-String | Out-FileNoBom $script:ReportFile -Append } }
        Add-Report "`n-- Scheduled tasks (non-Microsoft) --"
        # Without its ACTION a task cannot be triaged from the report at all: an
        # innocuous TaskName says nothing about what the task runs, so every
        # non-Microsoft task sent the analyst back to the host. The non-exec
        # action types (ComHandler, and the deprecated mail/message ones) have
        # no Execute and are named by what they are instead of coming out blank.
        $autoTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
        $autoTasks |
            Select-Object TaskName, TaskPath, State, @{ Name = 'Action'; Expression = {
                (@(foreach ($a in @($_.Actions)) {
                    if     ($a.Execute) { ("{0} {1}" -f $a.Execute, $a.Arguments).Trim() }
                    elseif ($a.ClassId) { "COM:$($a.ClassId)" }
                    else                { '(non-exec action)' }
                }) -join ' ; ')
            } } | Format-Table -AutoSize | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
        # What the autostart entries POINT AT is judged here: the lists above only say what exists.
        $autoEntries = New-Object System.Collections.Generic.List[object]
        foreach ($s in $startupCmds) {
            $k = if ("$($s.Location)" -match '(?i)startup') { 'startup-folder' } else { 'run-key' }
            $autoEntries.Add([pscustomobject]@{ Name = $s.Name; Command = $s.Command; Location = $s.Location; Kind = $k; What = 'Autostart entry' })
        }
        # The Run keys are read directly as well: Win32_StartupCommand lists the hives of loaded interactive
        # profiles, so a Run value in the collecting user's own hive can be missing from it (a service session,
        # a build runner). Entries both sources return are judged once.
        $seenAuto = @{}; foreach ($e in $autoEntries) { $seenAuto[('{0}|{1}' -f $e.Name, $e.Command)] = $true }
        foreach ($rk2 in $runKeys) {
            if (-not (Test-PathSafe $rk2)) { continue }
            $rp = Get-ItemProperty $rk2 -ErrorAction SilentlyContinue
            foreach ($pn in @($rp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $cmd2 = [string]$pn.Value
                if (-not $cmd2 -or $seenAuto.ContainsKey(('{0}|{1}' -f $pn.Name, $cmd2))) { continue }
                $seenAuto[('{0}|{1}' -f $pn.Name, $cmd2)] = $true
                $autoEntries.Add([pscustomobject]@{ Name = $pn.Name; Command = $cmd2; Location = $rk2; Kind = 'run-key'; What = 'Autostart entry' })
            }
        }
        foreach ($tk in $autoTasks) {
            foreach ($a in @($tk.Actions)) {
                if ($a.Execute) { $autoEntries.Add([pscustomobject]@{ Name = $tk.TaskName; Command = ("{0} {1}" -f $a.Execute, $a.Arguments).Trim(); Location = $tk.TaskPath; Kind = 'scheduled-task'; What = 'Scheduled task' }) }
            }
        }
        Add-AutostartFindings -Entries $autoEntries.ToArray()
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
            $appInit = (Get-ItemProperty $k -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
            if ($appInit) { Add-Report "[AppInit_DLLs] $k = $appInit"; Add-Finding -Category 'persistence' -Message 'AppInit_DLLs is set (DLL loaded into most user processes)' -Detail "$k AppInit_DLLs = $appInit" }
        }
        $ac = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
        if (Test-PathSafe $ac) {
            $acp = Get-ItemProperty $ac -ErrorAction SilentlyContinue
            $acn = @($acp.PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS' })
            if ($acn.Count -gt 0) { Add-Report '[AppCertDlls] present'; ($acp | Out-String) | Out-FileNoBom $script:ReportFile -Append; Add-Finding -Category 'persistence' -Message 'AppCertDlls registered (loads into CreateProcess callers)' -Detail 'HKLM\...\Session Manager\AppCertDlls' }
        }
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-PathSafe $wl) {
            $wlp = Get-ItemProperty $wl -ErrorAction SilentlyContinue
            Add-Report ("[Winlogon] Shell='{0}'  Userinit='{1}'" -f $wlp.Shell, $wlp.Userinit)
            if ($wlp.Shell -and $wlp.Shell -notmatch '^explorer\.exe,?\s*$') { Add-Finding -Severity 'High' -Category 'persistence' -Message 'Winlogon Shell is non-default' -Detail ("Shell = $($wlp.Shell) (expected explorer.exe)") }
            # Built from the real SystemRoot: the default value is
            # '<SystemRoot>\system32\userinit.exe,', so pinning the drive to C:
            # raised a HIGH 'Userinit is non-default' on every host that boots
            # from another drive - a false positive on an untouched machine.
            $uiDefault = '(?i)^' + [regex]::Escape((Join-WinPath $script:SysRoot 'system32\userinit.exe')) + ',?\s*$'
            if ($wlp.Userinit -and $wlp.Userinit -notmatch $uiDefault) { Add-Finding -Severity 'High' -Category 'persistence' -Message 'Winlogon Userinit is non-default' -Detail ("Userinit = $($wlp.Userinit)") }
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
    # Three more techniques, same module: see Collect-PersistenceExtra.
    Collect-PersistenceExtra

}

function Collect-PersistenceExtra {
    <#
        Three persistence techniques the module did not look at, all of them
        still in active use and all of them plain registry reads - no new
        module, no new permission, nothing an EDR has a reason to flag.

        Deliberately narrow. The naive version of each of these produces more
        noise than signal on an ordinary workstation, and this project has
        already shipped one module that raised 144 findings of which 142 were
        noise. So each rule looks for the SHADOWING or the DEVIATION, not for
        the mere existence of the key.
    #>
    try {
        # ---- COM hijack (T1546.015) ------------------------------------
        # HKCU\Software\Classes\CLSID shadows HKLM for the current user, so a
        # CLSID registered in BOTH is the hijack: the user-level copy wins and
        # the process loads the attacker's DLL instead of the real one. No
        # Administrator needed to plant it, which is the point of the technique.
        #
        # Only the HKCU side is enumerated. Walking all of HKLM\CLSID is tens of
        # thousands of keys and would wreck -Quick for no extra signal - the
        # attack lives in HKCU by definition.
        $comRoot = 'HKCU:\Software\Classes\CLSID'
        $comHits = 0
        $hklmClsid = $null
        try { $hklmClsid = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('Software\Classes\CLSID') } catch {}
        if ((Test-PathSafe $comRoot) -and $hklmClsid) {
            foreach ($k in @(Get-ChildItem $comRoot -ErrorAction SilentlyContinue)) {
                foreach ($srv in 'InProcServer32','LocalServer32') {
                    $up = Join-Path $k.PSPath $srv
                    if (-not (Test-PathSafe $up)) { continue }
                    $dll = $null
                    try { $dll = (Get-ItemProperty -LiteralPath $up -ErrorAction SilentlyContinue).'(default)' } catch {}
                    if (-not $dll) { continue }
                    $comHits++
                    # OpenSubKey, NOT Test-Path. Test-Path on a key that does
                    # not exist under HKLM\Software\Classes\CLSID costs about
                    # TWO SECONDS each - the measured cost of a miss against the
                    # merged HKCR view - and twenty-two of them turned a 0.8s
                    # module into a 22s one. persistence is in -Quick, so that
                    # is not a trade this tool can make. The .NET call returns
                    # null immediately on a miss.
                    $machineKey = $null
                    try { $machineKey = $hklmClsid.OpenSubKey("$($k.PSChildName)\$srv") } catch {}
                    if ($machineKey) {
                        $machineKey.Close()
                        Add-Finding -Severity 'High' -Category 'persistence' -ArtifactClass 'com-hijack' `
                            -Message ("COM CLSID registered per-user AND machine-wide: {0}" -f $k.PSChildName) `
                            -Detail ("HKCU {0} -> {1} . A per-user registration shadows the machine one, so this DLL loads instead of the system's. It needs no Administrator to plant, which is why it is used. Compare against the HKLM value before judging." -f $srv, $dll)
                    }
                }
            }
            Add-Report ("COM: {0} per-user CLSID server registration(s) examined." -f $comHits)
        }
        if ($hklmClsid) { $hklmClsid.Close() }

        # ---- netsh helper DLLs (T1546.007) -----------------------------
        # netsh.exe loads every DLL listed here on each invocation. The default
        # set ships with Windows; anything else is a persistence mechanism.
        # Judged by WHERE the DLL is, not by whether its name is on a list.
        # The first draft carried a hand-written list of default helper names
        # and immediately raised dnsclient and netprofm on a clean machine -
        # both shipped by Windows, both missing from my list. A name list of
        # this kind cannot be kept correct, and this repo has shipped five
        # stale ones already. A bare name resolves out of System32, which only
        # an Administrator can write to; the attack has to put its DLL
        # somewhere the user can write. That is the thing worth saying.
        $nsKey = 'HKLM:\SOFTWARE\Microsoft\NetSh'
        if (Test-PathSafe $nsKey) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $nsKey -ErrorAction SilentlyContinue } catch {}
            if ($props) {
                foreach ($pr in @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
                    $leaf = [string]$pr.Value
                    # A bare file name means System32, which is not user-writable.
                    if ($leaf -notmatch '[\\/]') { continue }
                    if ($leaf -notmatch $script:UserWritablePattern) { continue }
                    Add-Finding -Severity 'High' -Category 'persistence' -ArtifactClass 'netsh-helper' `
                        -Message ("netsh helper DLL in a user-writable location: {0}" -f $pr.Name) `
                        -Detail ("{0} - netsh.exe loads every helper registered here, so this DLL runs whenever netsh does, and it sits where a non-Administrator can replace it." -f $leaf)
                }
            }
        }

        # ---- protocol handlers / filters (HijackThis O18) ---------------
        # A handler maps a URL scheme to a DLL. Replacing one redirects every
        # application that resolves that scheme, browsers included.
        foreach ($proto in @('Handler','Filter')) {
            $pk = "HKLM:\SOFTWARE\Classes\PROTOCOLS\$proto"
            if (-not (Test-PathSafe $pk)) { continue }
            foreach ($h in @(Get-ChildItem $pk -ErrorAction SilentlyContinue)) {
                $clsid = $null
                try { $clsid = (Get-ItemProperty -LiteralPath $h.PSPath -ErrorAction SilentlyContinue).CLSID } catch {}
                if (-not $clsid) { continue }
                $srvKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32"
                $dll = $null
                try { $dll = (Get-ItemProperty -LiteralPath $srvKey -ErrorAction SilentlyContinue).'(default)' } catch {}
                if (-not $dll) { continue }
                # "Outside %SystemRoot%" was the first rule and it was wrong:
                # Office alone registers five handlers under Program Files and
                # every one of them came out as a finding on a clean machine.
                # Program Files needs Administrator to write, so it is not the
                # hijack vector. A user-writable path is.
                if ($dll -notmatch $script:UserWritablePattern) { continue }
                Add-Finding -Severity 'High' -Category 'persistence' -ArtifactClass 'protocol-handler' `
                    -Message ("Protocol {0} served by a DLL in a user-writable location: {1}" -f $proto.ToLower(), $h.PSChildName) `
                    -Detail ("{0} -> {1} . Every application that resolves this scheme loads that DLL, and it sits where a non-Administrator can replace it." -f $clsid, $dll)
            }
        }

        # -- BITS transfer jobs of the collecting user --
        # A job that runs a command when it finishes is a persistence and download trick that
        # needs no file of its own. Other users' jobs need Administrator; this says so.
        Add-Report "`n-- BITS transfer jobs (collecting user only; -AllUsers needs Administrator) --"
        $bits = @(); try { if ((Get-Service -Name BITS -ErrorAction Stop).Status -eq 'Running') { $bits = @(Get-BitsTransfer -ErrorAction Stop) } } catch {}  # only when BITS already runs: asking a stopped service would start it
        if ($bits.Count -eq 0) { Add-Report '(none, or the BITS service is not running and was left alone)' }
        foreach ($b in $bits) {
            # NotifyCmdLine is a two-element array (program, parameters); an empty one is still a
            # non-null collection, which made every Chrome and Edge updater job a false lead.
            $notify = @($b.NotifyCmdLine | Where-Object { $_ })
            Add-Report ("[{0}] {1} state={2} notify='{3}'" -f $b.JobId, $b.DisplayName, $b.JobState, ($notify -join ' '))
            if ($notify.Count -gt 0) {
                Add-Finding -Severity 'Review' -Category 'persistence' -ArtifactClass 'unknown' -Technique 'T1197' `
                    -Message ("BITS job '{0}' runs a program when it finishes" -f $b.DisplayName) `
                    -Detail ("{0} . A background transfer that starts a program is not how ordinary software uses BITS." -f ($notify -join ' '))
            }
        }

        # -- PowerShell profiles: run at the start of every PowerShell session --
        Add-Report "`n-- PowerShell profile scripts --"
        $profiles = @(
            (Join-Path $PSHOME 'profile.ps1'), (Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1'),
            (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\profile.ps1'),
            (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
            (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\profile.ps1'),
            (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Microsoft.PowerShell_profile.ps1'))
        $psSeen = 0
        foreach ($pf in $profiles) {
            if (-not (Test-PathSafe $pf)) { continue }
            $psSeen++
            $fi = Get-Item -LiteralPath $pf -ErrorAction SilentlyContinue
            Add-Report ("{0}  ({1} bytes, modified {2})" -f $pf, $fi.Length, (Get-IsoUtc $fi.LastWriteTimeUtc))
            $body = ''
            try { if ($fi.Length -le 65536) { $body = [IO.File]::ReadAllText($pf) } } catch {}
            if ($body -match '(?i)DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|FromBase64String|-EncodedCommand|\bIEX\b|Invoke-Expression|Start-BitsTransfer') {
                Add-Finding -Severity 'Review' -Category 'persistence' -ArtifactClass 'unknown' -Technique 'T1546.013' `
                    -Message ("PowerShell profile downloads or decodes code: {0}" -f $pf) `
                    -Detail 'The profile runs at the start of every PowerShell session and contains a download, decode or Invoke-Expression call. Read it and find out when it was written.'
            }
        }
        if ($psSeen -eq 0) { Add-Report '(no profile scripts)' }

        # -- Group Policy logon/startup scripts: listed, not judged (normal on a domain) --
        Add-Report "`n-- Group Policy scripts --"
        $gpSeen = 0
        foreach ($gp in 'Machine\Scripts\Startup','Machine\Scripts\Shutdown','User\Scripts\Logon','User\Scripts\Logoff') {
            $d = Join-WinPath $script:SysRoot ("System32\GroupPolicy\{0}" -f $gp)
            if (Test-PathSafe $d) { foreach ($f in @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)) { $gpSeen++; Add-Report ("{0}\{1}  ({2} bytes)" -f $gp, $f.Name, $f.Length) } }
        }
        if ($gpSeen -eq 0) { Add-Report '(none)' }
    } catch { Add-Err "PersistenceExtra failed: $_" }
}

function Collect-Autoruns {
    Add-Section '09 Autoruns (Sysinternals, optional)'
    $tool = Join-Path $PSScriptRoot 'tools\autoruns64.exe'
    if (-not (Test-PathSafe $tool)) { Add-Report 'autoruns64.exe not in tools\. Skipping.'; Add-Note 'autoruns were NOT collected: tools\autoruns64.exe is not present'; return }
    Invoke-Ext -File $tool -Arguments @('-accepteula','-a','*','-c','-h','-s') -OutFile (Join-Path $script:OutDir 'autoruns.csv')
    Add-Report 'Autoruns CSV saved.'
}

function Collect-Shares {
    Add-Section '10 SMB shares'
    try {
        Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description | Format-Table -AutoSize | Out-String | Out-FileNoBom $script:ReportFile -Append
        (net share 2>&1) | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Err "Shares failed: $_" }
}

function Collect-DefenderState {
    # Turning real-time protection off and excluding a folder are two of the most common
    # first moves of an intruder, and both are plain reads. The exclusions need
    # Administrator to be shown; as a standard user the service answers with a placeholder,
    # and that is said in the report instead of being read as "no exclusions".
    Add-Report "`n-- Microsoft Defender (real-time protection and exclusions) --"
    try {
        $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if (-not $svc) { Add-Report 'The Windows Defender service is not present.'; return }
        if ($svc.Status -ne 'Running') { Add-Report ("The WinDefend service is {0}; another antivirus product may be the active one." -f $svc.Status); return }
        $st = $null; $mp = $null
        try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
        try { $mp = Get-MpPreference -ErrorAction Stop } catch {}
        if ($st) {
            Add-Report ("AMRunningMode={0}  AntivirusEnabled={1}  RealTimeProtectionEnabled={2}  TamperProtected={3}" -f $st.AMRunningMode, $st.AntivirusEnabled, $st.RealTimeProtectionEnabled, $st.IsTamperProtected)
            $passive = ($st.AMRunningMode -and "$($st.AMRunningMode)" -ne 'Normal')
            if ($st.AntivirusEnabled -eq $true -and $st.RealTimeProtectionEnabled -eq $false -and -not $passive) {
                Add-Finding -Severity 'Review' -Category 'firewall' -ArtifactClass 'unknown' -Technique 'T1562.001' `
                    -Message 'Microsoft Defender real-time protection is switched off' `
                    -Detail 'Defender is the active antivirus but does not scan files as they are used. Find out who turned it off and when (Microsoft-Windows-Windows Defender/Operational, event 5001).'
            }
        } else { Add-Note 'Defender status could not be read, so real-time protection was NOT checked.' }
        if ($mp) {
            $paths = @($mp.ExclusionPath | Where-Object { $_ }); $exts = @($mp.ExclusionExtension | Where-Object { $_ }); $procs = @($mp.ExclusionProcess | Where-Object { $_ })
            if (@($paths + $exts + $procs | Where-Object { "$_" -match 'Must be an administrator' }).Count -gt 0) {
                Add-Report 'Exclusions: NOT readable without Administrator.'
                Add-Note 'Defender exclusions were NOT read: Administrator is needed to see them, so an exclusion on a user-writable folder would not show here.'
            } else {
                Add-Report ("Exclusions: {0} path(s), {1} extension(s), {2} process(es)." -f $paths.Count, $exts.Count, $procs.Count)
                foreach ($x in ($paths + $exts + $procs)) { Add-Report ("    {0}" -f $x) }
                $hit = @($paths | Where-Object { Get-RiskyAutostartFolder ([string]$_ + '\') })
                foreach ($x in ($hit | Select-Object -First 10)) {
                    Add-Finding -Severity 'Review' -Category 'firewall' -ArtifactClass 'unknown' -Technique 'T1562.001' `
                        -Message ("Microsoft Defender excludes a user-writable folder: {0}" -f $x) `
                        -Detail 'Files in an excluded folder are not scanned. Find out who added the exclusion and what is in the folder.'
                }
            }
        }
    } catch { Add-Err "Defender state failed: $_" }
}

function Collect-Firewall {
    Add-Section '11 Firewall profiles & enabled rules'
    try {
        # A missing NetSecurity module is a CommandNotFoundException, which
        # -ErrorAction cannot suppress, so it used to abort the whole module and
        # the operator got neither the profiles nor the rules - on a host where
        # netsh would have answered both questions. netsh prints localised text,
        # which is why it is the fallback and not the primary source, but
        # localised text an analyst can read beats an empty section.
        try {
            Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String | Out-FileNoBom $script:ReportFile -Append
            Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action, Profile | Out-String | Out-FileNoBom (Join-Path $script:OutDir 'firewall_rules.txt')
            Add-Report 'Enabled firewall rules saved to firewall_rules.txt.'
        } catch {
            Add-Note ("NetSecurity cmdlets unavailable ({0}); falling back to netsh." -f $_.Exception.Message)
            (netsh advfirewall show allprofiles 2>&1) | Out-FileNoBom $script:ReportFile -Append
            (netsh advfirewall firewall show rule name=all 2>&1) | Out-FileNoBom (Join-Path $script:OutDir 'firewall_rules.txt')
            Add-Report 'Firewall profiles and rules collected via netsh (localised text - NetSecurity was unavailable).'
        }
        # Whether the firewall keeps a log at all decides if there will be anything to read later.
        try {
            $fwl = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, LogAllowed, LogBlocked, LogFileName)
            Add-Report "`n-- Firewall logging --"
            ($fwl | Format-Table -AutoSize | Out-String -Width 400) | Out-FileNoBom $script:ReportFile -Append
        } catch {}
    } catch { Add-Err "Firewall failed: $_" }
    Collect-DefenderState
}

function Collect-Drivers {
    Add-Section '12 Running kernel drivers'
    try {
        Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | Select-Object Name, DisplayName, PathName | Sort-Object Name | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Err "Drivers failed: $_" }
}

function Collect-InstalledApps {
    Add-Section '13 Installed applications'
    try {
        $paths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = foreach ($p in $paths) { Get-ItemProperty $p -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate }
        $apps | Where-Object DisplayName | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Err "InstalledApps failed: $_" }
}

function Collect-Prefetch {
    Add-Section '14 Prefetch (last 60 days)'
    try {
        $pf = Join-WinPath $script:SysRoot 'Prefetch'
        if (Test-PathSafe $pf) {
            $cutoff = (Get-Date).AddDays(-60)
            # Counted, not piped straight out. An empty Prefetch section reads
            # as "nothing executed recently", which is the opposite of what an
            # unreadable directory means -- a non-Administrator run cannot open
            # %SystemRoot%\Prefetch at all, and the section used to come out
            # blank with no error, no note and nothing in moduleLimitations.
            $pfErr = $null
            $all = @(Get-ChildItem $pf -Filter *.pf -ErrorAction SilentlyContinue -ErrorVariable pfErr)
            $recent = @($all | Where-Object { $_.LastWriteTime -ge $cutoff })
            if ($recent.Count -gt 0) {
                $recent | Sort-Object LastWriteTime -Descending | Select-Object Name, Length, LastWriteTime | Out-String | Out-FileNoBom $script:ReportFile -Append
            }
            Add-Report ("Prefetch files: {0} in the last 60 days ({1} total)." -f $recent.Count, $all.Count)
            if ($all.Count -eq 0) {
                if (-not $isAdmin) {
                    Add-Note 'prefetch was NOT collected: %SystemRoot%\Prefetch needs Administrator, so an empty section here does NOT mean nothing ran'
                } elseif ($pfErr) {
                    Add-Note ("prefetch was NOT collected: the directory could not be read ({0})" -f ($pfErr[0].Exception.Message -replace '\s+',' '))
                } else {
                    Add-Note 'prefetch is empty: prefetching may be disabled on this host (EnablePrefetcher=0 is common on SSD/server builds)'
                }
            } elseif ($recent.Count -eq 0) {
                Add-Note ("prefetch holds {0} file(s) but none inside the 60-day window" -f $all.Count)
            }
        } else {
            Add-Report 'Prefetch not present (may be disabled).'
            if (-not $isAdmin) { Add-Note 'prefetch was NOT collected: %SystemRoot%\Prefetch is not readable without Administrator' }
            else { Add-Note 'prefetch was NOT collected: %SystemRoot%\Prefetch does not exist (prefetching disabled)' }
        }
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
            } | Out-FileNoBom $script:ReportFile -Append
        } else { Add-Report 'No USBSTOR key.' }
    } catch { Add-Err "USB failed: $_" }
}

function Collect-PSHistory {
    Add-Section '16 PowerShell console history'
    try {
        $hp = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-PathSafe $hp) {
            Add-Report "[$hp]"
            $hl = @(Get-Content $hp -ErrorAction SilentlyContinue)
            $hl | Out-FileNoBom $script:ReportFile -Append
            # A typed command is a command line that ran: the same text
            # indicators apply. One finding per indicator kind, naming the line.
            $hseen = @{}
            for ($i = 0; $i -lt $hl.Count; $i++) {
                $ti = Get-TextIndicator ([string]$hl[$i])
                if (-not $ti -or $hseen.ContainsKey($ti.Label)) { continue }
                $hseen[$ti.Label] = $true
                $cl = [string]$hl[$i]; if ($cl.Length -gt 200) { $cl = $cl.Substring(0,200) + '...' }
                Add-Finding -Severity $ti.Severity -Category 'process' -ArtifactClass 'process-commandline' `
                    -Message (Format-TextIndicatorMessage $ti ("PowerShell history, line {0}" -f ($i + 1))) `
                    -Detail ("{0} | {1}" -f $hp, $cl)
            }
        }
        else { Add-Report 'No PSReadLine history found.' }
    } catch { Add-Err "PSHistory failed: $_" }
}

# The scan patterns are regexes; some read badly in a finding. Show the analyst
# what each one means, not the expression. The report line keeps the raw form.
function Get-ObfPatternLabel {
    param([string]$Pattern)
    if ($Pattern -ceq $script:EncArgPattern) { return 'encoded command argument (-enc / -EncodedCommand)' }
    switch -CaseSensitive ($Pattern) {
        '-w\s+hidden'    { return 'hidden window flag (-w hidden)' }
        'eval\('         { return 'eval(' }
        'WScript\.Shell' { return 'WScript.Shell' }
        'WinHttp\.WinHttpRequest' { return 'WinHttp.WinHttpRequest (download)' }
        'MSXML2\.(Server)?XMLHTTP' { return 'MSXML2.XMLHTTP (download)' }
        'ADODB\.Stream'  { return 'ADODB.Stream (writes a downloaded file)' }
        '(?<![0-9A-Fa-f])68747470733a2f2f'   { return 'URL written in hex (https://)' }
        '(?<![0-9A-Fa-f])687474703a2f2f'     { return 'URL written in hex (http://)' }
        '(?<![A-Za-z0-9+/])aHR0cHM6Ly'      { return 'URL written in base64 (https://)' }
        '(?<![A-Za-z0-9+/])aHR0cDovL'       { return 'URL written in base64 (http://)' }
        default          { return $Pattern }
    }
}

function Collect-ObfScan {
    Add-Section '17 Obfuscated/suspicious script scan (Downloads/Desktop/Temp, 30d)'
    try {
        $paths = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP")
        # Regex, not -SimpleMatch: the encoded-command pattern has to be a regex
        # (see $script:EncArgPattern), and the literals below carry no regex
        # metacharacters except the two that are escaped here.
        $patterns = @('IEX','Invoke-Expression','FromBase64String','ConvertFrom-Base64',$script:EncArgPattern,'DownloadString','DownloadFile','fromCharCode','eval\(','WScript\.Shell','-w\s+hidden',
                      # how a dropped VBScript/JScript stage downloads and writes its next file
                      'WinHttp\.WinHttpRequest','MSXML2\.(Server)?XMLHTTP','ADODB\.Stream',
                      # the encoded start of http:// and https://, in hex and in base64
                      '(?<![0-9A-Fa-f])68747470733a2f2f','(?<![0-9A-Fa-f])687474703a2f2f','(?<![A-Za-z0-9+/])aHR0cHM6Ly','(?<![A-Za-z0-9+/])aHR0cDovL')
        $cutoff = (Get-Date).AddDays(-30)
        # The collector's own tests and tools match its own detection patterns by design.
        # They stay in the report but raise no finding; the count is a Stat.
        $selfRoot = ''; try { if ($PSCommandPath) { $selfRoot = Split-Path -Parent $PSCommandPath } } catch {}
        foreach ($base in $paths) {
            if (-not (Test-PathSafe $base)) { continue }
            $files = Get-FilesByExtension -Path $base -Extension '.ps1','.psm1','.js','.jse','.vbs','.vbe','.wsf','.bat','.hta' -Since $cutoff | Where-Object { $_.FullName -ne $PSCommandPath } | Sort-Object LastWriteTime -Descending | Select-Object -First 100
            foreach ($f in $files) {
                $m = Select-String -Path $f.FullName -Pattern $patterns -List -ErrorAction SilentlyContinue
                if ($m) {
                    $snip = $m.Line; if ($snip.Length -gt 160) { $snip = $snip.Substring(0,160)+'...' }
                    $own = $false
                    # The REPORT still gets one line per file: nothing is lost.
                    if ($selfRoot -and $f.FullName.StartsWith($selfRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
                        $rel = $f.FullName.Substring($selfRoot.Length + 1)
                        if ($rel -imatch '^(tests|tools|linux|docs|release|schema|backup|presentation)\\' -or $rel -ieq 'Tatar.ps1') { $own = $true }
                    }
                    ("[!]{4} {0} | line {1} | {2} | {3}" -f $f.FullName,$m.LineNumber,$m.Pattern,$snip,$(if ($own) { ' [collector own file, no finding raised]' } else { '' })) | Out-FileNoBom $script:ReportFile -Append
                    if ($own) { continue }
                    $script:ObfHits.Add([pscustomobject]@{
                        Pattern = [string]$m.Pattern
                        Dir     = [string](Split-Path $f.FullName -Parent)
                        Leaf    = [string]$f.Name
                        File    = [string]$f.FullName
                        Line    = $m.LineNumber
                        Snip    = $snip
                    })
                }
            }
        }
        # FINDINGS are grouped by pattern + directory. One finding per file made
        # this module 43 of 65 findings on an ordinary workstation, 35 of them a
        # single installer unpacking the same signed script into 35 random temp
        # directories. That is not 35 leads, it is one, and burying the other
        # eight under it is the same failure the first useractivity draft had.
        # Grouping keeps every file in the report and gives the analyst a count.
        # Grouped by pattern + FILE NAME, not by directory. Grouping on the
        # directory was the obvious key and the wrong one: an installer unpacks
        # the same signed script into a fresh RANDOM temp directory every run,
        # so 35 copies of one file had 35 distinct parents and 35 findings
        # survived the grouping. The thing that repeats is the file, not where
        # it landed.
        $groups = @($script:ObfHits | Group-Object { $_.Pattern + '|' + $_.Leaf })
        foreach ($g in $groups) {
            $h = @($g.Group)
            $first = $h[0]
            if ($h.Count -eq 1) {
                Add-Finding -Category 'obfscan' `
                    -Message ("Suspicious pattern '{0}' in {1}" -f (Get-ObfPatternLabel $first.Pattern), $first.File) `
                    -Detail  ("line {0}: {1}" -f $first.Line, $first.Snip)
            } else {
                $dirs   = @($h | ForEach-Object { $_.Dir } | Select-Object -Unique).Count
                $sample = ($h | Select-Object -First 3 | ForEach-Object { $_.File }) -join ' ; '
                Add-Finding -Category 'obfscan' `
                    -Message ("Suspicious pattern '{0}' in {1} cop(ies) of {2}, across {3} director(ies)" -f (Get-ObfPatternLabel $first.Pattern), $h.Count, $first.Leaf, $dirs) `
                    -Detail  ("First {0} of {1}: {2} | line {3}: {4} | every match is listed individually in report section 17. Many copies of one file under temp directories is the shape of an installer unpacking itself; confirm the publisher before treating it as a lead." -f ([Math]::Min(3,$h.Count)), $h.Count, $sample, $first.Line, $first.Snip)
            }
        }
        Add-Report ("Obfuscation scan complete: {0} match(es) in {1} finding group(s)." -f $script:ObfHits.Count, $groups.Count)
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
                    Select-Object TimeCreated, Id, Message | ConvertTo-SafeCsv | Out-FileNoBom (Join-Path $rd ("sec_$($pair[1]).csv"))
            } catch {}
        }
        foreach ($lg in 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational') {
            try {
                Get-WinEvent -LogName $lg -MaxEvents 60 -ErrorAction Stop | Select-Object TimeCreated, Id, Message |
                    ConvertTo-SafeCsv | Out-FileNoBom (Join-Path $rd (($lg -split '/')[0].Split('-')[-1] + '.csv'))
            } catch {}
        }
        # RDP client MRU (outbound destinations)
        $mru = 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
        if (Test-PathSafe $mru) { Add-Report '-- Outbound RDP MRU (HKCU Terminal Server Client) --'; (Get-ItemProperty $mru -ErrorAction SilentlyContinue) | Out-String | Out-FileNoBom $script:ReportFile -Append }
        # Is inbound Remote Desktop switched on, and does it ask for Network Level Authentication?
        # Enabled on its own is ordinary on a server, so that is a report line; enabled WITHOUT
        # NLA lets anyone who can reach the port see the logon screen, which is the lead.
        try {
            $tsk = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            $deny = (Get-ItemProperty -LiteralPath $tsk -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
            $nla  = (Get-ItemProperty -LiteralPath "$tsk\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
            if ($null -ne $deny) {
                Add-Report ("-- Inbound Remote Desktop: {0}; Network Level Authentication: {1} --" -f $(if ($deny -eq 0) { 'ENABLED' } else { 'disabled' }), $(if ($null -eq $nla) { 'unknown' } elseif ($nla -eq 1) { 'required' } else { 'NOT required' }))
                if ($deny -eq 0 -and $nla -eq 0) {
                    Add-Finding -Severity 'Review' -Category 'lateral' -ArtifactClass 'rdp' -Technique 'T1021.001' `
                        -Message 'Remote Desktop is enabled and does not require Network Level Authentication' `
                        -Detail 'Anyone who can reach the port gets the Windows logon screen before proving who they are. Check whether this was changed on purpose.'
                }
            }
        } catch {}
        Add-Report 'RDP event CSVs saved to RDP\.'
    } catch { Add-Err "RDP failed: $_" }
}

function Test-WmiDefaultBinding {
    # $true only for the binding Windows itself installs: the SCM Event Log
    # Consumer (an NTEventLogEventConsumer - it writes to the event log and runs
    # nothing) fed by the SCM Event Log Filter whose query is the stock one. A
    # fresh Windows has exactly this, so reporting it made every machine raise the
    # same lead. Judged by structure, never by the name alone: a consumer of any
    # other class, or a filter with any other query, is NOT the default.
    param($Binding, $Filters)
    try {
        $c = $Binding.Consumer; $f = $Binding.Filter
        $cClass = ''
        if ($c -and $c.CimClass) { $cClass = [string]$c.CimClass.CimClassName }
        if ($cClass -ne 'NTEventLogEventConsumer') { return $false }
        if ([string]$c.Name -ne 'SCM Event Log Consumer') { return $false }
        if ([string]$f.Name -ne 'SCM Event Log Filter') { return $false }
        $q = [string]$f.Query
        if (-not $q) { foreach ($x in @($Filters)) { if ([string]$x.Name -eq 'SCM Event Log Filter') { $q = [string]$x.Query } } }
        return [bool]($q -match '^\s*select\s+\*\s+from\s+MSFT_SCMEventLogEvent\s*$')
    } catch { return $false }
}
function Collect-Lateral {
    Add-Section '19 Lateral movement artifacts'
    try {
        Add-Report '-- Mapped drives / SMB mappings --'
        (net use 2>&1) | Out-FileNoBom $script:ReportFile -Append
        Get-SmbMapping -ErrorAction SilentlyContinue | Out-String | Out-FileNoBom $script:ReportFile -Append
        Add-Report '-- Inbound SMB sessions / open files --'
        Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens | Out-String | Out-FileNoBom $script:ReportFile -Append
        Add-Report '-- PsExec artifacts --'
        $psexesvc = Join-WinPath $script:SysRoot 'PSEXESVC.exe'
        if (Test-PathSafe $psexesvc) {
            Add-Report ("PSEXESVC.exe present in {0} (PsExec was used)." -f $script:SysRoot)
            Add-Finding -Severity 'High' -Category 'lateral' -Message ("PsExec service binary present ({0})" -f $psexesvc) -Detail 'PsExec was executed against this host at some point - correlate with logon events'
        }
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'PSEXESVC' } | Out-String | Out-FileNoBom $script:ReportFile -Append
        Add-Report '-- WMI persistence (root\subscription) --'
        $wmiFilters = @()
        foreach ($cls in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') {
            $r = Get-CimInstance -Namespace root\subscription -ClassName $cls -ErrorAction SilentlyContinue
            if ($cls -eq '__EventFilter') { $wmiFilters = @($r) }
            if ($r -and $cls -eq '__FilterToConsumerBinding') {
                "[$cls]" | Out-FileNoBom $script:ReportFile -Append
                $r | Format-List | Out-String | Out-FileNoBom $script:ReportFile -Append
                $custom = @($r | Where-Object { -not (Test-WmiDefaultBinding $_ $wmiFilters) })
                $stock = @($r).Count - $custom.Count
                if ($stock -gt 0) { Add-Report ("(not flagged: {0} stock Windows binding(s) - SCM Event Log Consumer, an event-log writer that runs nothing)" -f $stock) }
                if ($custom.Count -gt 0) { Add-Finding -Category 'lateral' -Message ("WMI event subscription consumer found: {0} ({1} entry/entries)" -f $cls, $custom.Count) -Detail 'Review report section 19 - WMI consumers are a known persistence technique (T1546.003)' }
                continue
            }
            if ($r) {
                "[$cls]" | Out-FileNoBom $script:ReportFile -Append
                $r | Format-List | Out-String | Out-FileNoBom $script:ReportFile -Append
                if ($cls -like '*Consumer*') { Add-Finding -Category 'lateral' -Message ("WMI event subscription consumer found: {0} ({1} entry/entries)" -f $cls, @($r).Count) -Detail 'Review report section 19 - WMI consumers are a known persistence technique (T1546.003)' }
            }
        }
        Add-Report '-- WinRM state --'
        (Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Name, Status) | Out-String | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Err "Lateral failed: $_" }
}

function Collect-PrivEsc {
    Add-Section '20 Privilege-escalation indicators'
    try {
        Add-Report '-- Token privileges (whoami /priv) --'
        (whoami /priv 2>&1) | Out-FileNoBom $script:ReportFile -Append
        Add-Report '-- Unquoted service paths (with spaces, outside System32) --'
        # The space has to be in the IMAGE PATH, not anywhere in the command
        # line. Testing the whole PathName flagged 'C:\Apps\svc.exe -k foo' -
        # not vulnerable, the binary path has no space - and anchoring the quote
        # test at ^" flagged an ImagePath that legally begins with whitespace
        # before its opening quote. Both were noise on every run.
        $sysRootRe = '(?i)^' + [regex]::Escape($script:SysRoot + '\')
        $unq = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            $img = Get-ServiceImagePath $_.PathName
            $img -and $_.PathName -notmatch '^\s*"' -and $img -match ' ' -and $img -notmatch $sysRootRe
        } | Select-Object Name, PathName
        $unq | Format-Table -AutoSize | Out-String | Out-FileNoBom $script:ReportFile -Append
        foreach ($u in @($unq)) { Add-Finding -Category 'privesc' -Message ("Unquoted service path: {0}" -f $u.Name) -Detail $u.PathName }
        Add-Report '-- Service binaries in user-writable locations --'
        # Same reason: match the binary, not an argument that merely mentions a
        # path under \Users\ (a log file destination is not a writable binary).
        # ProgramData is only writable by a standard user in parts of it. For a
        # binary there, the file's own ACL decides (Defender's Platform folder is
        # not writable by users); an unreadable ACL keeps the finding.
        $wrSkipped = New-Object System.Collections.Generic.List[string]
        $wr = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            $img = Get-ServiceImagePath $_.PathName
            if (-not $img) { return $false }
            if ($img -imatch 'users\\|\\appdata\\|\\temp\\') { return $true }
            if ($img -imatch '\\programdata\\') {
                $w = Test-WritableByUsers $img
                if ($w -eq $false) { $wrSkipped.Add(("{0}  {1}" -f $_.Name, $img)); return $false }
                return $true
            }
            return $false
        } | Select-Object Name, PathName
        $wr | Out-String | Out-FileNoBom $script:ReportFile -Append
        if ($wrSkipped.Count) { Add-Report ("(not flagged: under ProgramData but the ACL gives standard users no write access)"); foreach ($k in $wrSkipped) { Add-Report ("    " + $k) } }
        foreach ($w in @($wr)) { Add-Finding -Category 'privesc' -Message ("Service binary in user-writable location: {0}" -f $w.Name) -Detail $w.PathName }
        Add-Report '-- AlwaysInstallElevated --'
        # The escalation needs BOTH hives set to 1: the installer elevates only
        # when the machine policy and the user policy agree. Raising High on
        # either one alone sent the analyst after a half-configured policy that
        # grants nothing. The single-hive case is still worth an eye, so it is
        # kept - as a Review lead, which is what it is.
        $aieM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $aieU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $aieMTxt = if ($null -ne $aieM) { "$aieM" } else { '(not set)' }
        $aieUTxt = if ($null -ne $aieU) { "$aieU" } else { '(not set)' }
        "HKLM AlwaysInstallElevated = $aieMTxt" | Out-FileNoBom $script:ReportFile -Append
        "HKCU AlwaysInstallElevated = $aieUTxt" | Out-FileNoBom $script:ReportFile -Append
        if ($aieM -eq 1 -and $aieU -eq 1) {
            Add-Finding -Severity 'High' -Category 'privesc' -Message 'AlwaysInstallElevated is ENABLED in both HKLM and HKCU' -Detail 'Any user can install an MSI package as SYSTEM (T1548.002)'
        } elseif ($aieM -eq 1 -or $aieU -eq 1) {
            Add-Finding -Category 'privesc' -Message ("AlwaysInstallElevated is set in only one hive (HKLM={0} HKCU={1})" -f $aieMTxt, $aieUTxt) -Detail 'Not exploitable on its own - both hives must be 1. NOTE: HKCU is read for the account running the collector, so a different logged-on user may still have it set.'
        }
    } catch { Add-Err "PrivEsc failed: $_" }
}

function Collect-Browser {
    Add-Section '21 Browser artifacts (metadata, all profiles, AV-safe)'
    try {
        $bdir = New-SubDir 'BrowserArtifacts'
        $summary = Join-Path $bdir 'browser_artifacts_summary.txt'
        "Browser artifact metadata (no DB execution, no password extraction)`n" | Out-FileNoBom $summary
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
        Copy-BestEffort (Join-WinPath $script:SysRoot 'AppCompat\Programs\Amcache.hve') (Join-Path $fs 'Amcache.hve') 'Amcache.hve is locked on a live host; acquire via VSS / RawCopy for offline parsing'
        try { fsutil usn queryjournal $script:SysDrive 2>$null | Out-FileNoBom (Join-Path $fs 'usn_queryjournal.txt') } catch {}
        Get-Volume -ErrorAction SilentlyContinue | Out-FileNoBom (Join-Path $fs 'volumes.txt')
        Get-Disk   -ErrorAction SilentlyContinue | Out-FileNoBom (Join-Path $fs 'disks.txt')
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
            $rows | ConvertTo-SafeCsv | Out-FileNoBom (Join-Path $script:OutDir 'recyclebin.csv')
            Add-Report ("Recycle Bin items: {0} (saved to recyclebin.csv)" -f (@($rows).Count))
        } else { Add-Report 'Recycle Bin namespace not available.' }
    } catch { Add-Err "Deleted (Recycle Bin) failed: $_" }
}

function Collect-ShadowCopies {
    Add-Section '24 Volume Shadow Copies'
    # Both sources need Administrator. Without it vssadmin prints a localised
    # error into the report and Win32_ShadowCopy fails with "Initialization
    # failure", which reads like a defect rather than a missing privilege - and
    # an empty section reads like "no shadow copies". Say what it is instead.
    if (-not $script:isAdmin) {
        Add-Report 'Shadow copies were NOT queried: this needs Administrator.'
        Add-Note 'shadow copies were NOT queried: listing them needs Administrator, so an empty section here does NOT mean there are none'
        return
    }
    try { (vssadmin list shadows 2>&1) | Out-FileNoBom $script:ReportFile -Append } catch { Add-Err "ShadowCopies failed: $_" }
    # vssadmin emits LOCALISED console text and nothing else, so on a Mongolian,
    # Russian or Japanese Windows the only record of which shadow copies existed
    # is unparseable by anything downstream - and shadow copies are often where
    # the one clean copy of a tampered file lives. Win32_ShadowCopy carries the
    # same facts as structured, locale-independent data. Kept in its OWN try so
    # neither source can take the other down with it.
    try {
        Add-Report "`n-- Win32_ShadowCopy (structured, locale-independent) --"
        Get-CimInstance Win32_ShadowCopy -ErrorAction Stop |
            Select-Object ID, InstallDate, VolumeName, DeviceObject |
            Format-Table -AutoSize | Out-String -Width 4096 | Out-FileNoBom $script:ReportFile -Append
    } catch { Add-Note "Win32_ShadowCopy query failed: $_" }
}

function Write-LoggingCoverage {
    # What this host records at all. An empty event section means nothing until
    # it is known whether the event could have been written: with script-block
    # logging off, most PowerShell that ran left no 4104; with process-creation
    # auditing off there is no 4688 to find. Every value here is read, nothing
    # is switched on or changed. A gap is reported as a module limitation, the
    # same list as "not collected", because it is the same kind of statement:
    # an absence on this host that is not evidence of absence.
    $gaps = New-Object 'System.Collections.Generic.List[string]'
    Add-Report ''
    Add-Report '-- Logging coverage (read only; nothing is changed) --'
    function Get-PolicyValue { param([string]$Key, [string]$Name)
        try { (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop).$Name } catch { $null } }
    $psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $sbl = (Get-PolicyValue "$psPol\ScriptBlockLogging" 'EnableScriptBlockLogging') -eq 1
    $mol = (Get-PolicyValue "$psPol\ModuleLogging"      'EnableModuleLogging') -eq 1
    $trn = (Get-PolicyValue "$psPol\Transcription"      'EnableTranscripting') -eq 1
    $cmd = (Get-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1
    Add-Report ("  PowerShell script-block logging : {0}" -f $(if ($sbl) { 'on' } else { 'off - only blocks PowerShell itself rates as suspicious are logged' }))
    Add-Report ("  PowerShell module logging       : {0}" -f $(if ($mol) { 'on' } else { 'off' }))
    Add-Report ("  PowerShell transcription        : {0}" -f $(if ($trn) { 'on' } else { 'off' }))
    Add-Report ("  Command line in event 4688      : {0}" -f $(if ($cmd) { 'on' } else { 'off - a 4688 names the program but not its arguments' }))
    if (-not $sbl) { $gaps.Add('PowerShell script-block logging is off, so most PowerShell that ran left no 4104 event') }
    if (-not $cmd) { $gaps.Add('process-creation events (4688) do not record the command line') }
    # Process-creation auditing itself is only visible in the Security log. A
    # filtered query that is not allowed to read the log answers "no events
    # found", exactly like a log with no 4688 in it, so the log is first read
    # without a filter: only a log that can be read can say auditing is off.
    $secReadable = $false
    if ($isAdmin) { try { $null = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop; $secReadable = $true } catch { } }
    if (-not $secReadable) {
        Add-Report '  Process-creation auditing (4688): not measured (the Security log needs Administrator)'
    } else {
        try {
            $null = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } -MaxEvents 1 -ErrorAction Stop
            Add-Report '  Process-creation auditing (4688): events present'
        } catch {
            if (Test-NoMatchingEvents $_) {
                Add-Report '  Process-creation auditing (4688): no event in the Security log'
                $gaps.Add('the Security log holds no process-creation event (4688): process auditing looks off')
            } else {
                Add-Report ("  Process-creation auditing (4688): not measured ({0})" -f $_.Exception.Message)
            }
        }
    }
    $channels = @('Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
                  'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
                  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-Windows Defender/Operational',
                  'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Bits-Client/Operational')
    Add-Report ''
    Add-Report ('  {0,-68} {1,-8} {2,8} {3,10}  {4}' -f 'Channel', 'Enabled', 'Max MB', 'Records', 'Oldest event')
    foreach ($ch in $channels) {
        $cfg = $null
        try { $cfg = Get-WinEvent -ListLog $ch -ErrorAction Stop } catch {
            if ($ch -like '*Sysmon*') { Add-Report ('  {0,-68} {1}' -f $ch, 'not installed') }
            else { Add-Report ('  {0,-68} {1}' -f $ch, 'not readable or not present') }
            continue
        }
        $oldest = ''
        try { $oldest = (Get-WinEvent -LogName $ch -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd') } catch { $oldest = '-' }
        Add-Report ('  {0,-68} {1,-8} {2,8} {3,10}  {4}' -f $ch, $cfg.IsEnabled, [int]($cfg.MaximumSizeInBytes / 1MB), $cfg.RecordCount, $oldest)
        if (-not $cfg.IsEnabled -and $ch -notlike '*Sysmon*') { $gaps.Add(("the {0} log is disabled" -f $ch)) }
        if ($ch -eq 'Security' -and $oldest -and $oldest -ne '-') {
            $days = ((Get-Date).ToUniversalTime() - [datetime]::ParseExact($oldest, 'yyyy-MM-dd', $null)).TotalDays
            if ($days -lt 7) { $gaps.Add(("the Security log reaches back only {0:N0} day(s)" -f $days)) }
        }
    }
    foreach ($g in $gaps) { Add-Note ("logging gap on this host: {0}" -f $g) }
    $script:Stats['LoggingGaps'] = $gaps.Count
    Add-Report ("Logging gaps: {0} (listed under moduleLimitations)." -f $gaps.Count)
}

function Collect-EventLogs {
    Add-Section '25 Key event summary (+ optional EVTX export)'
    try {
        $ev = New-SubDir 'EventLogs'
        $map = @{ '4688'='Process creation'; '7045'='Service install'; '4720'='User created'; '4672'='Special privileges'; '1102'='Security log cleared'; '4104'='PS scriptblock'; '4698'='Scheduled task created'; '4699'='Scheduled task deleted'; '4719'='Audit policy changed'; '4648'='Logon w/ explicit creds'; '4768'='Kerberos TGT'; '4769'='Kerberos svc ticket'; '4776'='NTLM auth'; '5140'='Net share access'; '4627'='Group membership' }
        # PowerShell logs a script block it rates as suspicious even with
        # script-block logging off, and this collector names the tools it looks
        # for (mimikatz, PsExec...), so its own code lands in event 4104. Read
        # back, that made the run report itself: a feed naming psexesvc.exe
        # matched the collector's source in evt_4104.csv. A 4104 whose text is
        # part of this script is left out and counted. Only text identical to
        # this file qualifies, so naming another script Tatar.ps1 hides nothing.
        $ownCode = ''
        try { if ($PSCommandPath) { $ownCode = ([IO.File]::ReadAllText($PSCommandPath)) -replace "`r", '' } } catch { }
        foreach ($id in $map.Keys) {
            $log = if ($id -eq '4104') { 'Microsoft-Windows-PowerShell/Operational' } else { 'Security' }
            try {
                if ($id -eq '4104' -and $ownCode) {
                    $all  = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=4104} -MaxEvents 500 -ErrorAction Stop)
                    $kept = @($all | Where-Object {
                        $sb = if ($_.Properties.Count -gt 2) { [string]$_.Properties[2].Value } else { '' }
                        -not ($sb.Trim() -and $ownCode.Contains(($sb -replace "`r", ''))) })
                    $self = $all.Count - $kept.Count
                    if ($self -gt 0) { Add-Report ("Event 4104: {0} script block(s) of this collector's own code left out of evt_4104.csv." -f $self) }
                    if ($kept.Count -eq 0) { continue }
                    $evts = @($kept | Select-Object -First 50)
                } else {
                    $evts = Get-WinEvent -FilterHashtable @{LogName=$log; Id=[int]$id} -MaxEvents 50 -ErrorAction Stop
                }
                $evts | Select-Object TimeCreated, Id, Message | ConvertTo-SafeCsv | Out-FileNoBom (Join-Path $ev ("evt_$id.csv"))
                if ($id -eq '1102' -and @($evts).Count -gt 0) {
                    Add-Finding -Severity 'High' -Category 'eventlogs' -Message ("Security log cleared - event 1102 present ({0} occurrence(s))" -f @($evts).Count) -Detail 'See EventLogs\evt_1102.csv - log clearing is a strong anti-forensics indicator (T1070.001)'
                }
            } catch {}
        }
        Add-Report "Key event CSVs saved (IDs: $($map.Keys -join ', '))."
        # Process-creation events carry the command lines of programs that have
        # already exited - a credential dump runs for seconds, so this is where
        # it is usually still visible. The command line is a field of the event
        # (index 8), read without rendering the message, which keeps 2000
        # events fast. Needs the Security log, so Administrator.
        if ($isAdmin) {
            try {
                $c4688 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } -MaxEvents 2000 -ErrorAction Stop)
                $eseen = @{}; $ehits = 0
                foreach ($e in $c4688) {
                    if ($e.Properties.Count -lt 9) { continue }
                    $ecmd = [string]$e.Properties[8].Value
                    $ti = Get-TextIndicator $ecmd
                    if (-not $ti) { continue }
                    $key = $ti.Label + '|' + $ecmd
                    if ($eseen.ContainsKey($key) -or $ehits -ge 10) { continue }
                    $eseen[$key] = $true; $ehits++
                    $ecl = $ecmd; if ($ecl.Length -gt 200) { $ecl = $ecl.Substring(0,200) + '...' }
                    Add-Finding -Severity $ti.Severity -Category 'process' -ArtifactClass 'event-log' `
                        -Message (Format-TextIndicatorMessage $ti ("event 4688 at {0:yyyy-MM-dd HH:mm} UTC, {1}" -f $e.TimeCreated.ToUniversalTime(), (Split-Path -Leaf ([string]$e.Properties[5].Value)))) `
                        -Detail $ecl
                }
                Add-Report ("Event 4688: {0} process-creation event(s) checked for credential dumps and encoded URLs, {1} finding(s)." -f $c4688.Count, $ehits)
            } catch {
                if (-not (Test-NoMatchingEvents $_)) { Add-Report ("Event 4688 command lines were not checked: {0}" -f $_.Exception.Message) }
            }
        }
        Write-LoggingCoverage
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
    if (-not $CollectHives) { Add-Report 'Skipped (use -CollectHives to enable; may trigger EDR).'; Add-Note 'registry hives were NOT collected: -CollectHives was not supplied'; return }
    try {
        $hd = New-SubDir 'RegistryHives'
        $hives = @{ 'HKLM\SYSTEM'='SYSTEM.hive'; 'HKLM\SAM'='SAM.hive'; 'HKLM\SECURITY'='SECURITY.hive'; 'HKLM\SOFTWARE'='SOFTWARE.hive' }
        foreach ($k in $hives.Keys) {
            $dst = Join-Path $hd $hives[$k]
            Invoke-Ext -File 'reg.exe' -Arguments @('save', $k, $dst, '/y') -OutFile (Join-Path $hd 'reg_save.log')
            if (Test-PathSafe $dst) { Add-Report "Saved $k" }
        }
        Get-ChildItem (Join-WinPath $script:SysDrive 'Users') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
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
        # The system drive, not a literal C:. The filenames follow the drive
        # actually queried, so the evidence says which volume it came from.
        $mftDrv = $script:SysDrive
        $mftTag = ($mftDrv -replace '[^A-Za-z]', '')
        (fsutil fsinfo ntfsinfo $mftDrv 2>&1)   | Out-FileNoBom (Join-Path $mo ("ntfsinfo_{0}.txt" -f $mftTag))
        (fsutil fsinfo statistics $mftDrv 2>&1) | Out-FileNoBom (Join-Path $mo ("ntfs_statistics_{0}.txt" -f $mftTag))
        Add-Report 'NTFS volume/MFT info saved to MFT\.'
        Add-Report 'NOTE: full $MFT record parsing requires an offline tool (e.g. MFTECmd / RawCopy) or a mounted shadow copy; not performed in-place to avoid disk modification.'
    } catch { Add-Err "MFT failed: $_" }
}

function Collect-Indicators {
    Add-Section '28 Suspicious indicators summary'
    try {
        Add-Report '-- Non-Microsoft services with unusual binary paths --'
        $oddSvc = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and ($_.PathName -imatch 'temp|appdata|\\programdata\\[^\\]+\.exe|\\users\\') } | Select-Object Name, PathName
        $oddSvc | Format-Table -AutoSize | Out-String | Out-FileNoBom $script:ReportFile -Append
        foreach ($s in @($oddSvc)) { Add-Finding -Category 'indicators' -Message ("Service with unusual binary path: {0}" -f $s.Name) -Detail $s.PathName }
        Add-Report '-- Executables written to temp locations (last 14 days) --'
        $tmpCount = 0
        $tmpFirst = New-Object System.Collections.Generic.List[string]
        $tmpTop = @{}
        # %TEMP% and %LOCALAPPDATA%\Temp are the SAME directory for an
        # interactive user, so every executable under it was counted twice -
        # in the finding text and in the ExecInTempDirs counter that
        # summary.json publishes. They differ only when running as SYSTEM, so
        # keep both and de-duplicate instead of dropping one. Windows paths are
        # case-insensitive; the HashSet has to be told that.
        $tmpDirs = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($cand in @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")) {
            if ($cand -and $cand.Trim()) { [void]$tmpDirs.Add($cand.TrimEnd('\')) }
        }
        foreach ($d in $tmpDirs) {
            if (Test-PathSafe $d) {
                $items = Get-FilesByExtension -Path $d -Extension '.exe','.dll','.scr' -Since (Get-Date).AddDays(-14) | Select-Object FullName, Length, LastWriteTime
                $tmpCount += @($items).Count
                foreach ($it in @($items)) {
                    if ($tmpFirst.Count -lt 10) { $tmpFirst.Add([string]$it.FullName) }
                    # Which top-level folder holds the files: 30000 files under one
                    # installer or runtime folder read very differently from 30 spread out.
                    $full = [string]$it.FullName
                    $rel = $full.Substring([Math]::Min($d.Length + 1, $full.Length))
                    $top = if ($rel.IndexOf('\') -lt 0) { '(top level)' } else { $rel.Split('\')[0] }
                    $tmpTop[$top] = 1 + [int]$tmpTop[$top]
                }
                $items | Out-String | Out-FileNoBom $script:ReportFile -Append
            }
        }
        $script:Stats['ExecInTempDirs'] = $tmpCount
        if ($tmpCount -gt 0) {
            # The paths have to be INSIDE the finding: the allowlist, publisher
            # and hash passes only ever see message+detail, so this aggregate -
            # the noisiest finding the tool raises, by its own admission - named
            # no file and could not be reached by any allowlist rule.
            $tmpWhere = (@($tmpTop.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })) -join ', '
            Add-Finding -Category 'indicators' -Message ("{0} executable file(s) written to temp/appdata locations in the last 14 days" -f $tmpCount) -Detail ("In {0} top-level folder(s), the largest: {1} | First {2} of {3}: {4} | see report section 28 for all - legitimate installers/updaters also appear here" -f $tmpTop.Count, $tmpWhere, $tmpFirst.Count, $tmpCount, ($tmpFirst -join ' '))
        }
    } catch { Add-Err "Indicators failed: $_" }
}

function Collect-Hashes {
    Add-Section '29 Hash collection (running/startup/service binaries)'
    try {
        # Case-insensitive, because Windows paths are: Win32_Process and
        # Win32_Service disagree on the casing of the same binary often enough
        # that the default ordinal comparer hashed svchost.exe twice and emitted
        # two identical lines to the IOC feed.
        $paths = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { if ($_.ExecutablePath) { [void]$paths.Add($_.ExecutablePath) } }
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ServiceImagePath $_.PathName
            if ($p) { [void]$paths.Add($p) }
        }
        $rows = foreach ($p in $paths) {
            if (Test-PathSafe $p) {
                try { $h = Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop; [pscustomobject]@{ Path=$p; SHA256=$h.Hash } } catch {}
            }
        }
        # Same filename and same 'sha256sum' format as the Linux edition, so one
        # VirusTotal / IOC pipeline ingests either platform's feed instead of
        # needing a CSV parser for one and a text parser for the other.
        $hashFile  = Join-Path $script:OutDir 'binary_hashes.txt'
        $hashLines = @($rows | Where-Object { $_ } | Sort-Object Path | ForEach-Object { "{0}  {1}" -f $_.SHA256.ToLower(), $_.Path })
        [IO.File]::WriteAllText($hashFile, (($hashLines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
        $script:Stats['HashedBinaries'] = @($rows).Count
        Add-Report ("Hashed {0} binaries -> binary_hashes.txt (feed to VirusTotal / IOC matching)." -f (@($rows).Count))
    } catch { Add-Err "Hashes failed: $_" }
}

function Collect-Timeline {
    Add-Section '30 Timeline generation (super-timeline lite)'
    try {
        $tl = New-Object System.Collections.Generic.List[object]
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { if ($_.CreationDate) { $tl.Add([pscustomobject]@{ Time=$_.CreationDate; Source='Process'; Detail=("{0} (PID {1})" -f $_.Name,$_.ProcessId) }) } }
        $pfDir = Join-WinPath $script:SysRoot 'Prefetch'
        if (Test-PathSafe $pfDir) { Get-ChildItem $pfDir -Filter *.pf -ErrorAction SilentlyContinue | ForEach-Object { $tl.Add([pscustomobject]@{ Time=$_.LastWriteTime; Source='Prefetch'; Detail=$_.Name }) } }
        $rec = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-PathSafe $rec) { Get-ChildItem $rec -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object { $tl.Add([pscustomobject]@{ Time=$_.LastWriteTime; Source='RecentLnk'; Detail=$_.Name }) } }
        # InstallDate is a REG_SZ 'yyyyMMdd'. Added raw, it made Time a mixed
        # DateTime/String column: Sort-Object then compared a string against a
        # DateTime, silently gave up on those rows and shipped a timeline that
        # is NOT in time order - the one property a timeline has to have. Rows
        # whose date will not parse are dropped rather than left in to corrupt
        # the ordering of every other row, and counted so the drop is visible.
        $badDates = 0
        foreach ($p in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
            Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.InstallDate } | ForEach-Object {
                $when = $null
                try { $when = [datetime]::ParseExact([string]$_.InstallDate, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture) }
                catch { try { $when = [datetime]::Parse([string]$_.InstallDate, [Globalization.CultureInfo]::InvariantCulture) } catch { $when = $null } }
                if ($when) { $tl.Add([pscustomobject]@{ Time=$when; Source='AppInstall'; Detail=$_.DisplayName }) }
                else { $badDates++ }
            }
        }
        if ($badDates -gt 0) { Add-Note ("{0} Uninstall entry/entries had an InstallDate that does not parse as a date and are not in timeline.csv." -f $badDates) }
        $tl | Where-Object { $_.Time } | Sort-Object Time -Descending | Select-Object @{ N = 'Time'; E = { ([datetime]$_.Time).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } }, Source, Detail | ConvertTo-SafeCsv | Out-FileNoBom (Join-Path $script:OutDir 'timeline.csv')
        $script:Stats['TimelineEntries'] = $tl.Count
        Add-Report ("Timeline entries: {0} -> timeline.csv" -f $tl.Count)
    } catch { Add-Err "Timeline failed: $_" }
}

# =====================================================================
#  Summary (P3): analyst-first one-pager, txt + json
# =====================================================================
# powershell.exe accepts any unambiguous abbreviation of -EncodedCommand, so
# -e, -en, -enc, -enco, -encod ... all run base64 just as well as the full
# spelling, and an operator writing an evasion uses the short one. Two places
# looked for this and both were wrong in opposite directions: Collect-Process
# matched the regex '-enc ' and so missed every abbreviation AND the no-space
# forms, while Collect-ObfScan matched the literal '-enc' with -SimpleMatch and
# so flagged every -Encoding utf8 in every ordinary script it read.
#
# The prefixes of 'encodedcommand' are listed longest first (alternation is
# first-match) and the trailing (?![A-Za-z]) is what separates the two cases:
# -encod stops at a non-letter and matches, -encoding continues into 'i' and
# does not. -ExecutionPolicy is not a prefix of encodedcommand at all, so -e
# followed by 'x' never enters the alternation. 'ec' is in the list even
# though it is not a strict prefix: it is what gets typed in the wild, and for
# a detection pattern the cost of catching it is a Review lead on an odd token,
# while the cost of missing it is the whole point of the check.
# One definition of "a location a standard user can write to". Two modules now
# judge a path by it (rmm, useractivity), and a second copy is a second answer:
# the whole point is that both agree on what counts as outside Program Files.
# Deliberately narrow - the user profile, Windows\Temp and the public share.
# ProgramData is NOT in it on purpose: standard users can write to parts of it,
# but it is also where AnyDesk, TeamViewer and ScreenConnect legitimately keep
# their files, so including it would have made the High finding fire on every
# normal RMM install. High has to stay rare to mean anything.
$script:UserWritablePattern = '(?i)\\(?:Users\\[^\\]+\\(?:AppData|Downloads|Desktop|Documents)|Windows\\Temp|Users\\Public)\\'

$script:EncArgPattern = '(?<=^|\s)[-/](?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|encoded|encode|encod|enco|enc|ec|en|e)(?![A-Za-z])'

function Get-IocPattern {
    # Boundary-aware regex for one IOC token. Plain substring matching used to let
    # "127.0.0" match 127.0.0.1 and "ocalhost" match localhost, raising false High
    # findings. An indicator now only counts when the characters around it are not
    # part of the same address / hostname / filename.
    param([string]$Token)
    $e = [regex]::Escape($Token)
    if ($Token -match '^\d{1,3}(\.\d{1,3}){3}$') {
        # IPv4: only a digit or a dot can extend the address. A colon must NOT
        # block the match - netstat and almost every log write addr:port, so
        # treating ':' as part of the address made IPv4 indicators unmatchable.
        return "(?<![0-9.])$e(?![0-9.])"
    }
    if ($Token -match '^[0-9A-Fa-f:]+$' -and $Token.Contains(':')) {
        return "(?<![0-9A-Fa-f.:])$e(?![0-9A-Fa-f.:])"       # IPv6 literal
    }
    return "(?<![\w.-])$e(?![\w-])(?!\.[A-Za-z0-9])"         # domain / filename
}

function New-IocIndex {
    # Lookup tables for a whole feed. Each indicator used to be searched with its
    # own regex across every evidence file, about 40 ms per indicator, so a feed
    # of ten thousand added seven minutes to a run. The tables hold the three
    # shapes Get-IocPattern knows: an indicator of one of them can only match a
    # run of the same characters in the text, so the runs of a text are looked
    # up in a set instead of every indicator being tried. Find-IocInText still
    # confirms each candidate with Get-IocPattern, so the boundary rule is the
    # same one. An indicator with a character none of the shapes can hold goes
    # on the Slow list and is matched the old way; a feed of plain IPs, domains,
    # file names and hashes has none.
    param([object[]]$Indicators)
    $cmp = [StringComparer]::OrdinalIgnoreCase
    $word = New-Object 'System.Collections.Generic.Dictionary[string,string]' $cmp
    $v4   = New-Object 'System.Collections.Generic.Dictionary[string,string]' $cmp
    $v6   = New-Object 'System.Collections.Generic.Dictionary[string,string]' $cmp
    $slow = New-Object 'System.Collections.Generic.List[string]'
    $rank = New-Object 'System.Collections.Generic.Dictionary[string,int]' $cmp
    $reV4 = [regex]'^\d{1,3}(\.\d{1,3}){3}$'; $reV6 = [regex]'^[0-9A-Fa-f:]+$'; $reW = [regex]'^[\w.-]+$'
    for ($i = 0; $i -lt $Indicators.Count; $i++) {
        $t = [string]$Indicators[$i]
        if (-not $t -or $rank.ContainsKey($t)) { continue }
        $rank[$t] = $i
        if ($reV4.IsMatch($t)) {
            if ($t -cmatch '^[0-9.]+$') { $v4[$t] = $t } else { $slow.Add($t) }
        } elseif ($t.Contains(':') -and $reV6.IsMatch($t)) {
            $v6[$t] = $t
        } elseif ($reW.IsMatch($t)) {
            $word[$t] = $t
        } else {
            $slow.Add($t)
        }
    }
    [pscustomobject]@{
        Word = $word; V4 = $v4; V6 = $v6; Slow = $slow; Rank = $rank
        # Sets with the same comparer, so HashSet.IntersectWith takes its fast path.
        WordSet = [System.Collections.Generic.HashSet[string]]::new($word.Keys, $cmp)
        V4Set   = [System.Collections.Generic.HashSet[string]]::new($v4.Keys, $cmp)
        V6Set   = [System.Collections.Generic.HashSet[string]]::new($v6.Keys, $cmp)
    }
}

function Find-IocInText {
    # The indicators of a New-IocIndex table that occur in $Text on a boundary,
    # each spelled as the feed first spelled it. Get-IocPattern decides; the
    # sets only choose which indicators are worth asking it about:
    #   domain/file name/hash - it is a whole run of [\w.-], or such a run cut
    #                           just before a '.' that does not start a label
    #   IPv4                  - it is a whole run of [0-9.]
    #   IPv6                  - it is a whole run of [0-9A-Fa-f.:]
    # The runs are cut and compared by .NET in bulk: a loop over every word of a
    # report, in PowerShell, cost more than the per-indicator search it replaced.
    # Cutting a large text into runs still costs a second or two, so a short
    # list (64 or fewer of a shape) is simply asked about one by one.
    param([string]$Text, $Index)
    if (-not $Text) { return }
    $cmp  = [StringComparer]::OrdinalIgnoreCase
    $cand = New-Object 'System.Collections.Generic.List[string]'
    $few  = 64
    if ($Index.Word.Count -and $Index.Word.Count -le $few) { $cand.AddRange($Index.Word.Values) }
    elseif ($Index.Word.Count) {
        $hs = [System.Collections.Generic.HashSet[string]]::new([string[]][regex]::Split($Text, '[^\w.-]+'), $cmp)
        $hs.IntersectWith($Index.WordSet)
        foreach ($r in $hs) { $cand.Add($Index.Word[$r]) }
        foreach ($m in [regex]::Matches($Text, '(?<![\w.-])[\w.-]*\.(?![A-Za-z0-9])[\w.-]*')) {
            $r = $m.Value; $p = $r.IndexOf('.')
            while ($p -ge 0) {
                if ($p -gt 0) {
                    $pre = $r.Substring(0, $p)
                    if ($Index.Word.ContainsKey($pre)) { $cand.Add($Index.Word[$pre]) }
                }
                $p = $r.IndexOf('.', $p + 1)
            }
        }
    }
    if ($Index.V4.Count -and $Index.V4.Count -le $few) { $cand.AddRange($Index.V4.Values) }
    elseif ($Index.V4.Count) {
        $hs = [System.Collections.Generic.HashSet[string]]::new([string[]][regex]::Split($Text, '[^0-9.]+'), $cmp)
        $hs.IntersectWith($Index.V4Set)
        foreach ($r in $hs) { $cand.Add($Index.V4[$r]) }
    }
    if ($Index.V6.Count -and $Index.V6.Count -le $few) { $cand.AddRange($Index.V6.Values) }
    elseif ($Index.V6.Count) {
        $hs = [System.Collections.Generic.HashSet[string]]::new([string[]][regex]::Split($Text, '[^0-9A-Fa-f.:]+'), $cmp)
        $hs.IntersectWith($Index.V6Set)
        foreach ($r in $hs) { $cand.Add($Index.V6[$r]) }
    }
    foreach ($s in $Index.Slow) { $cand.Add($s) }
    $done = New-Object 'System.Collections.Generic.HashSet[string]' $cmp
    foreach ($c in $cand) {
        if (-not $done.Add($c)) { continue }
        if ([regex]::IsMatch($Text, (Get-IocPattern $c), 'IgnoreCase')) { $c }
    }
}

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
    # The schema has carried container / containerRuntime since 1.1 while the
    # Windows edition never populated them, so it always claimed 'not a
    # container'. Windows containers do exist; these are the documented signals.
    try {
        if ($env:USERNAME -eq 'ContainerAdministrator' -or (Get-Service -Name cexecsvc -ErrorAction SilentlyContinue)) {
            $envContainer = $true; $envRuntime = 'windows-container'
        }
    } catch {}
    $sevOrder = @{ 'High' = 0; 'Review' = 1 }
    $sorted = @($script:Findings | Sort-Object { if ($sevOrder.ContainsKey($_.Severity)) { $sevOrder[$_.Severity] } else { 2 } }, Category)

    # ---------- summary.txt ----------
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('==============================================================')
    $L.Add(" TATAR Triage Toolkit v$($script:ToolVersion) - TRIAGE SUMMARY")
    $L.Add('==============================================================')
    $L.Add(("Host       : {0}" -f $hn))
    $L.Add(("OS         : {0} ({1})" -f $osCap, $osVer))
    $L.Add(("User       : {0}" -f $env:USERNAME))
    $L.Add(("Case ID    : {0}" -f $CaseId))
    $L.Add(("Examiner   : {0}" -f $Examiner))
    $L.Add(("Started    : {0}" -f (Get-IsoUtc $Start)))
    $L.Add(("Finished   : {0}" -f (Get-IsoUtc $End)))
    $L.Add(("Duration   : {0} min" -f [math]::Round(($End - $Start).TotalMinutes, 2)))
    $L.Add(("Privileged : {0}" -f $IsAdmin))
    $L.Add(("Environment: virt={0} container={1} runtime={2} secmod={3}" -f $envVirt, $envContainer, $envRuntime, $envSecmod))
    $L.Add(("Modules    : {0}" -f ($ModulesRun -join ', ')))
    if ($script:ModulesSkipped.Count -gt 0) { $L.Add(("SKIPPED    : {0} (not a module name - NOTHING was collected for it)" -f ($script:ModulesSkipped -join ', '))) }
    $L.Add(("Errors     : {0} (see tatar.log)" -f $script:ErrorCount))
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
                $cands = @(Get-PathCandidate $blob)
                # EVERY path the finding names has to be known-good before the
                # finding is hidden. Suppressing on the FIRST match meant one
                # allowlisted updater could hide an aggregate about ten files,
                # with nothing in the output to say which rule applied to what.
                if ($cands.Count) {
                    $allOk = $true; $firstReason = ''
                    foreach ($cp in $cands) {
                        $reason = ''
                        foreach ($g in $alPaths) { if ($cp -like $g) { $reason = "allowlist path: $g"; break } }
                        if (-not $reason -and $alPubs.Count -and (Test-Path -LiteralPath $cp)) {
                            try {
                                $sig = Get-AuthenticodeSignature -LiteralPath $cp -ErrorAction SilentlyContinue
                                if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
                                    foreach ($pub in $alPubs) { if ($sig.SignerCertificate.Subject -match [regex]::Escape($pub)) { $reason = "signed: $pub"; break } }
                                }
                            } catch {}
                        }
                        if (-not $reason) { $allOk = $false; break }
                        if (-not $firstReason) { $firstReason = $reason }
                    }
                    if ($allOk) { $f.suppressed = $true; $f.suppressReason = $firstReason }
                }
                if (-not $f.suppressed -and $alHashes.Count) {
                    # every SHA-256 mentioned in the finding, not only the first one
                    foreach ($hm in [regex]::Matches($blob, '\b[a-fA-F0-9]{64}\b')) {
                        if ($alHashes -contains $hm.Value.ToLower()) { $f.suppressed = $true; $f.suppressReason = 'allowlist hash'; break }
                    }
                }
            }
            Write-ExecLog 'INFO' ("Allowlist applied: {0}/{1} findings suppressed" -f (@($sorted | Where-Object { $_.suppressed }).Count), $sorted.Count)
        } catch { Add-Err "Allowlist failed: $_" }
    }
    # ---- IOC matching (known-bad OVERRIDES the allowlist) ----
    if ($IOCFile -and (Test-Path $IOCFile)) {
        try {
            $ioc       = Get-Content $IOCFile -Raw | ConvertFrom-Json
            # foreach statements, not pipelines: a feed can hold hundreds of thousands of entries
            $iocHashes = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in @($ioc.hashes)) { $v = "$x".ToLower(); if ($v) { $iocHashes.Add($v) } }
            $iocStr = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in (@($ioc.ips) + @($ioc.domains) + @($ioc.filenames))) { if ($x) { $iocStr.Add([string]$x) } }
            $iocHashSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($x in $iocHashes) { [void]$iocHashSet.Add($x) }
            $ixA = New-IocIndex -Indicators $iocStr.ToArray()
            # A feed that parses but holds nothing to look for (an empty file, a list instead of an object,
            # no indicator in any of the four lists) matched nothing without a word. Same silent no-op as an
            # unreadable path, so it counts towards the exit code too.
            if (-not $ioc -or ($iocHashes.Count + $iocStr.Count) -eq 0) {
                Add-Err ('IOC file holds no usable indicator (hashes, ips, domains or filenames), so NO indicator was checked: {0}' -f $IOCFile)
            }
            $iocSeen   = New-Object System.Collections.Generic.List[string]
            $iocHits   = 0
            # Pass A: annotate existing findings; a hit re-activates + escalates.
            foreach ($f in $sorted) {
                $blob = "$($f.message) $($f.detail)"
                $hit  = $null
                # The first indicator in feed order that matches, as before.
                if ($iocStr.Count) {
                    $best = -1
                    foreach ($c in @(Find-IocInText -Text $blob -Index $ixA)) {
                        $r = $ixA.Rank[$c]; if ($best -lt 0 -or $r -lt $best) { $best = $r }
                    }
                    if ($best -ge 0) { $hit = $iocStr[$best] }
                }
                if (-not $hit -and $iocHashes.Count) {
                    # A finding can name several files ("x.exe launched from y.dll").
                    # Hashing only the first one checked the wrong file, so consider
                    # every path mentioned and skip the ones that are not on disk.
                    $hp = @(Get-PathCandidate $blob)
                    foreach ($cp in $hp) {
                        if (-not (Test-PathSafe $cp)) { continue }
                        $h = (Get-FileHash -LiteralPath $cp -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        if ($h -and $iocHashSet.Contains($h)) { $hit = $h.ToLower(); break }
                    }
                }
                if ($hit) {
                    $iocHits++; if (-not $iocSeen.Contains($hit)) { $iocSeen.Add($hit) }
                    $f.iocMatch = $true; $f.suppressed = $false; $f.suppressReason = ''
                    $f.severity = 'High'; $f.confidence = 0.95
                    # The indicator gets its own field. It stays prefixed into
                    # detail as well, because summary.txt and the report are
                    # read by humans and only findings.json gains the field.
                    $f.iocIndicator = $hit
                    $f.confidenceReason = (Get-ConfidenceReason 0.95)
                    $f.detail = "IOC match: $hit | $($f.detail)"
                }
            }
            # An IOC's ATT&CK technique depends on WHAT matched. Tagging a filename
            # or a hash hit as T1071 (application layer protocol) was simply wrong,
            # and a wrong mapping is worse than no mapping at all.
            $iocIps   = @(@($ioc.ips)       | Where-Object { $_ })
            $iocDoms  = @(@($ioc.domains)   | Where-Object { $_ })
            $iocFiles = @(@($ioc.filenames) | Where-Object { $_ })

            # Pass B: raise new findings for IOCs seen anywhere in collected artifacts.
            $scan = @(Get-ChildItem -Path $script:OutDir -Recurse -File -Include *.txt,*.csv,*.log -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'summary.txt' })
            # Each file is read once and every indicator looked up in it, instead
            # of every file being read again for every indicator. The first line
            # that holds an indicator, in file order, is the one reported - the
            # same line the per-indicator search found.
            $iocAll = New-Object 'System.Collections.Generic.List[string]'
            $iocAll.AddRange($iocStr); $iocAll.AddRange($iocHashes)
            $ixB = New-IocIndex -Indicators $iocAll.ToArray()
            $iocFirst = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($file in $scan) {
                if ($iocFirst.Count -ge $ixB.Rank.Count) { break }
                try { $body = [IO.File]::ReadAllText($file.FullName) } catch { continue }   # an unreadable file was skipped before too
                # Skip our own echo: Pass A writes "IOC match: <indicator>" into a
                # finding and tatar.log can quote an indicator back at us. Matching
                # those would raise a finding about the tool, not about the host.
                $body = [regex]::Replace($body, '(?im)^.*IOC match:.*$', '')
                foreach ($c in @(Find-IocInText -Text $body -Index $ixB)) {
                    if ($iocFirst.ContainsKey($c)) { continue }
                    # the first line of the file that holds it on a boundary
                    $m = [regex]::Match($body, (Get-IocPattern $c), 'IgnoreCase')
                    $ls = $body.LastIndexOf("`n", [Math]::Max(0, $m.Index - 1)) + 1
                    if ($m.Index -eq 0) { $ls = 0 }
                    $le = $body.IndexOf("`n", $m.Index); if ($le -lt 0) { $le = $body.Length }
                    $iocFirst[$c] = $body.Substring($ls, $le - $ls).Trim()
                }
            }
            foreach ($val in $iocAll) {
                if (-not $val -or $iocSeen.Contains($val)) { continue }
                $found = $null
                if ($iocFirst.ContainsKey($val)) { $found = $iocFirst[$val] }
                if ($found) {
                    $iocSeen.Add($val)
                    $script:FindingSeq++
                    $bMsg = "IOC observed in collected evidence: $val"
                    $bDet = $found.Substring(0, [Math]::Min(160, $found.Length))
                    $script:Findings.Add([pscustomobject]@{
                        id               = ('TTR-F-{0:D3}' -f $script:FindingSeq)
                        severity         = 'High'; category = 'ioc'
                        technique        = @(if     ($iocIps   -contains $val) { 'T1071'     }
                                             elseif ($iocDoms  -contains $val) { 'T1071.004' }
                                             elseif ($iocFiles -contains $val) { 'T1204.002' }
                                             else                              { 'T1588.001' })
                        message          = $bMsg
                        detail           = $bDet
                        confidence       = 0.95
                        confidenceReason = (Get-ConfidenceReason 0.95)
                        suppressed       = $false; suppressReason = ''; iocMatch = $true
                        iocIndicator     = $val
                        module           = 'ioc'
                        artifactClass    = 'ioc-match'
                        collected_at     = Get-IsoUtc
                        paths            = @(Get-PathCandidate "$bMsg $bDet")
                        recommendation   = (Get-Recommendation -Category 'ioc')
                    })
                }
            }
            Write-ExecLog 'INFO' ("IOC matching: {0} hit(s) on existing findings" -f $iocHits)
        } catch { Add-Err "IOC matching failed: $_" }
        # Re-sort OUTSIDE the try: Pass B may have appended findings before an
        # error, and a stale $sorted would drop them from every output file.
        $sorted = @($script:Findings | Sort-Object { if ($sevOrder.ContainsKey($_.Severity)) { $sevOrder[$_.Severity] } else { 2 } }, Category)
        Write-ExecLog 'INFO' ("IOC matching: {0} findings total after Pass B" -f $sorted.Count)
    }
    # ---- evidence correlation (links findings; never merges or creates them) ----
    $corrCount = 0
    try {
        $corrCount = Invoke-EvidenceCorrelation -Findings $sorted
        if ($corrCount -gt 0) {
            Write-ExecLog 'INFO' ("Evidence correlation: {0} finding(s) raised to confidence 0.85" -f $corrCount)
        }
    } catch { Add-Err "Evidence correlation failed: $_" }

    try { Set-FindingIdentity -Findings $sorted } catch { Add-Err "Finding identity failed: $_" }
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
    $L.Add('  2. Check tatar.log for FAILED/WARN collection steps (missing evidence).')
    $L.Add('  3. Submit binary_hashes.txt to VirusTotal / IOC matching.')
    $L.Add('  4. Pivot on timeline.csv around any confirmed finding timestamps.')
    $L | Out-FileNoBom -FilePath (Join-Path $script:OutDir 'summary.txt')

    # ---------- summary.json ----------
    $jsonObj = [pscustomobject]@{
        tool            = 'TATAR Triage Toolkit'
        version         = $script:ToolVersion
        schemaVersion   = '1.8'
        platform        = 'windows'
        host            = $hn
        os              = $osCap
        osVersion       = $osVer
        user            = $env:USERNAME
        privileged      = $IsAdmin
        caseId          = $CaseId
        examiner        = $Examiner
        started         = Get-IsoUtc $Start
        finished        = Get-IsoUtc $End
        durationSeconds = [math]::Round(($End - $Start).TotalSeconds, 0)
        environment     = [pscustomobject]@{ virtualization = $envVirt; container = $envContainer; containerRuntime = $envRuntime; securityModule = $envSecmod }
        errorsLogged    = $script:ErrorCount
        # .ToArray(), not @(...): on Windows PowerShell 5.1 an array
        # subexpression over a List[object] inside an [ordered]@{} literal
        # throws "Argument types do not match", and assigned to a variable
        # first it silently evaluates to EMPTY. Either way the limitations
        # would have been lost - the second one without a single error.
        moduleLimitations = $script:ModuleLimitations.ToArray()
        modulesRun      = @($ModulesRun)
        modulesSkipped  = @($script:ModulesSkipped)
        # .ToArray() for the same 5.1 reason as moduleLimitations above.
        moduleStatus    = $script:ModuleStatus.ToArray()
        stats           = [pscustomobject]$script:Stats
        findingsCount        = $sorted.Count
        activeFindingsCount  = $active.Count
        suppressedCount      = $suppressed.Count
        findings        = $sorted
    }
    Write-JsonNoBom ($jsonObj | ConvertTo-Json -Depth 6) (Join-Path $script:OutDir 'summary.json')

    # findings-only file for SOAR / SIEM ingestion
    $findObj = [pscustomobject]@{
        tool          = 'TATAR Triage Toolkit'
        schemaVersion = '1.8'
        platform      = 'windows'
        host          = $hn
        caseId        = $CaseId
        generated     = Get-IsoUtc $End
        findingsCount        = $sorted.Count
        activeFindingsCount  = $active.Count
        suppressedCount      = $suppressed.Count
        findings      = $sorted
    }
    Write-JsonNoBom ($findObj | ConvertTo-Json -Depth 6) (Join-Path $script:OutDir 'findings.json')
}

# ---------------------------------------------------------------------
#  31  Remote monitoring & management (RMM) evidence
# ---------------------------------------------------------------------
# Declared per CONTRIBUTING "Adding a module":
#   time        < 1s   (process/service enumeration already in memory, plus a
#                       handful of Test-Path checks and two small text reads)
#   admin       not required - every path read here is readable by a standard
#                       user; admin adds nothing
#   output      metadata only: product name, where it lives, and the tail of a
#                       connection log that is already plain text
#   AV risk     none - no executable is read, hashed or parsed
#
# Why the module exists: a legitimate-looking RMM agent is how a large share of
# intrusions keep their hands on a host, and the tooling is signed, allow-listed
# and often already in use by the IT team - so presence alone is a lead, not a
# verdict. What distinguishes the two is WHERE the client runs from and WHO
# connected: both are cheap to read, and until now neither was collected.
#
# The product table is deliberately detection-by-presence: a wrong path or a
# renamed process yields a MISS, never a false positive. It is not exhaustive
# and does not pretend to be.
$script:RmmProducts = @(
    @{ Name = 'AnyDesk';                Proc = @('AnyDesk');                              Svc = @('AnyDesk');                 Dirs = @("$env:ProgramData\AnyDesk", "$env:APPDATA\AnyDesk") }
    @{ Name = 'TeamViewer';             Proc = @('TeamViewer','TeamViewer_Service');      Svc = @('TeamViewer');              Dirs = @("$env:ProgramData\TeamViewer", "$env:APPDATA\TeamViewer") }
    @{ Name = 'ConnectWise ScreenConnect'; Proc = @('ScreenConnect.ClientService','ScreenConnect.WindowsClient','ConnectWiseControl.Client'); Svc = @('ScreenConnect Client'); Dirs = @("$env:ProgramData\ScreenConnect Client") }
    @{ Name = 'LogMeIn';                Proc = @('LogMeIn','LMIGuardianSvc','LMIIgnition');Svc = @('LMIGuardianSvc','LogMeIn');Dirs = @("$env:ProgramData\LogMeIn") }
    @{ Name = 'Atera';                  Proc = @('AteraAgent');                           Svc = @('AteraAgent');              Dirs = @("$env:ProgramFiles\ATERA Networks") }
    @{ Name = 'Splashtop';              Proc = @('SRService','SRManager','SRServer');     Svc = @('SplashtopRemoteService');  Dirs = @("${env:ProgramFiles(x86)}\Splashtop") }
    @{ Name = 'RemotePC';               Proc = @('RemotePCService','RPCPerformanceService');Svc = @('RemotePCService');       Dirs = @("$env:ProgramFiles\RemotePC") }
    @{ Name = 'Pulseway';               Proc = @('PCMonitorSrv');                         Svc = @('PCMonitorSrv');            Dirs = @("$env:ProgramFiles\Pulseway") }
    @{ Name = 'Supremo';                Proc = @('Supremo','SupremoService');             Svc = @('SupremoService');          Dirs = @("$env:ProgramData\SupremoRemoteDesktop") }
    @{ Name = 'Ammyy Admin';            Proc = @('AA_v3','AMMYY_Admin');                  Svc = @('AmmyyAdmin');              Dirs = @("$env:ProgramData\AMMYY") }
    @{ Name = 'NinjaOne';               Proc = @('NinjaRMMAgent','ninjarmm-cli');          Svc = @('NinjaRMMAgent');           Dirs = @("${env:ProgramFiles(x86)}\NinjaRMMAgent") }
    @{ Name = 'Action1';                Proc = @('action1_agent');                        Svc = @('A1Agent');                 Dirs = @("$env:ProgramFiles\Action1") }
    @{ Name = 'Syncro';                 Proc = @('Syncro.Service','SyncroLive.Agent.Service'); Svc = @('Syncro');             Dirs = @("$env:ProgramFiles\RepairTech\Syncro") }
    @{ Name = 'Kaseya VSA';             Proc = @('AgentMon','KaseyaEndpoint');            Svc = @('KaseyaAgent');             Dirs = @("${env:ProgramFiles(x86)}\Kaseya") }
    @{ Name = 'DWService';              Proc = @('dwagsvc','dwagent');                    Svc = @('DWAgent');                 Dirs = @("$env:ProgramFiles\DWAgent") }
    @{ Name = 'UltraViewer';            Proc = @('UltraViewer_Desktop','UltraViewer_Service'); Svc = @('UltraViewer_Service');Dirs = @("${env:ProgramFiles(x86)}\UltraViewer") }
    @{ Name = 'Chrome Remote Desktop';  Proc = @('remoting_host');                        Svc = @('chromoting');              Dirs = @("${env:ProgramFiles(x86)}\Google\Chrome Remote Desktop") }
    @{ Name = 'MeshCentral agent';      Proc = @('MeshAgent');                            Svc = @('Mesh Agent');              Dirs = @("$env:ProgramFiles\Mesh Agent") }
    @{ Name = 'Tactical RMM';           Proc = @('tacticalrmm','tacticalagent');          Svc = @('tacticalrmm');             Dirs = @("$env:ProgramFiles\TacticalAgent") }
    @{ Name = 'Zoho Assist';            Proc = @('ZA_Access','ZohoMeeting');              Svc = @('ZohoMeeting');             Dirs = @("$env:ProgramFiles\ZohoMeeting") }
    @{ Name = 'GoTo / GoToAssist';      Proc = @('g2aservice','g2acomm','GoToAssist');     Svc = @('GoToAssist Remote Support');Dirs = @("${env:ProgramFiles(x86)}\GoToAssist Remote Support Customer") }
    @{ Name = 'Quick Assist';           Proc = @('quickassist');                          Svc = @();                          Dirs = @() }
)

# Connection histories that are plain text and readable without admin. Only
# products whose log format is a documented, stable text file are read; for
# every other product the module reports WHERE to look instead of guessing at
# a format.
$script:RmmConnLogs = @(
    @{ Name = 'AnyDesk';    Path = "$env:ProgramData\AnyDesk\connection_trace.txt" }
    @{ Name = 'AnyDesk';    Path = "$env:APPDATA\AnyDesk\connection_trace.txt" }
    @{ Name = 'TeamViewer'; Path = "$env:ProgramData\TeamViewer\Connections_incoming.txt" }
    @{ Name = 'TeamViewer'; Path = "$env:APPDATA\TeamViewer\Connections.txt" }
)

function Collect-RMM {
    Add-Section '31 Remote monitoring & management (RMM) evidence'
    try {
        $found = New-Object System.Collections.Generic.List[string]

        # --- running processes and services (cheapest, most reliable) -------
        $procs = @()
        try { $procs = @(Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, Path) } catch {}
        $svcs = @()
        try { $svcs = @(Get-Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status) } catch {}

        foreach ($p in $script:RmmProducts) {
            $hits = New-Object System.Collections.Generic.List[string]

            foreach ($pn in $p.Proc) {
                foreach ($pr in ($procs | Where-Object { $_.Name -eq $pn })) {
                    $where = if ($pr.Path) { $pr.Path } else { '(path unavailable)' }
                    $hits.Add("process $($pr.Name) (PID $($pr.Id)) -> $where")
                    # A signed RMM client is normal in C:\Program Files. The same
                    # client running out of a user-writable directory is the
                    # portable-client pattern: dropped, run once, uninstalled.
                    if ($pr.Path -and $pr.Path -match $script:UserWritablePattern) {
                        Add-Finding -Severity 'High' -Category 'rmm' `
                            -Message ("RMM client running from a user-writable location: {0} (PID {1})" -f $p.Name, $pr.Id) `
                            -Detail ("{0} - a portable remote-access client dropped outside Program Files is how an operator keeps hands-on access without installing anything. Confirm with the IT owner of this host before treating it as benign." -f $pr.Path)
                    }
                }
            }
            foreach ($sn in $p.Svc) {
                foreach ($sv in ($svcs | Where-Object { $_.Name -like "$sn*" -or $_.DisplayName -like "$sn*" })) {
                    $hits.Add("service $($sv.Name) [$($sv.Status)]")
                }
            }
            foreach ($d in $p.Dirs) {
                if ($d -and (Test-PathSafe $d)) {
                    $hits.Add("directory $d")
                    # A directory carries no extension, so Get-PathCandidate
                    # cannot take it and the finding ends up with paths[] empty
                    # -- unsuppressible, unmatchable, uncorrelatable. Name the
                    # product's own executable when it is actually there. One
                    # Test-Path per known process name: no enumeration, no cost.
                    foreach ($pn in $p.Proc) {
                        $exe = Join-Path $d $pn
                        if (Test-PathSafe $exe) { $hits.Add("executable $exe") }
                    }
                }
            }

            if ($hits.Count) {
                $found.Add($p.Name)
                Add-Report ("[{0}]" -f $p.Name)
                foreach ($h in $hits) { Add-Report "    $h" }
                Add-Finding -Category 'rmm' `
                    -Message ("Remote access / RMM tool present: {0}" -f $p.Name) `
                    -Detail ("{0} | Remote access software is frequently legitimate IT tooling AND a common hands-on-keyboard channel. This finding says it is here, not that it is malicious - check it against the asset's approved software list and the connection history below." -f ($hits -join ' ; '))
            }
        }

        if (-not $found.Count) { Add-Report 'No known RMM product detected by process, service or install path.' }
        $script:Stats['RmmProductsPresent'] = $found.Count

        # --- connection history --------------------------------------------
        Add-Report ''
        Add-Report '-- connection history (plain-text logs, most recent last) --'
        $anyLog = $false
        foreach ($l in $script:RmmConnLogs) {
            if (-not (Test-PathSafe $l.Path)) { continue }
            $anyLog = $true
            $lines = @()
            try { $lines = @(Read-TextAuto $l.Path) } catch {}
            $lines = @($lines | Where-Object { $_ -and $_.Trim() })
            Add-Report ("[{0}] {1}  ({2} line(s))" -f $l.Name, $l.Path, $lines.Count)
            # The whole file goes in the report; only a bounded tail goes in the
            # finding, because a finding detail is read by a human and by a SIEM.
            $lines | Out-FileNoBom $script:ReportFile -Append
            if ($lines.Count -gt 0) {
                $tail = @($lines | Select-Object -Last 5)
                Add-Finding -Category 'rmm' `
                    -Message ("{0} connection history present: {1} entr(y/ies)" -f $l.Name, $lines.Count) `
                    -Detail ("{0} | last {1}: {2} | each entry is a session this host took part in - match the timestamps against the incident window and the IDs against your own technicians." -f $l.Path, $tail.Count, (($tail -join ' // ') -replace '\s+', ' '))
            }
        }
        if (-not $anyLog) { Add-Report 'No readable RMM connection log found.' }
    } catch { Add-Err "RMM failed: $_" }
}

# ---------------------------------------------------------------------
#  32  User activity & download remnants
# ---------------------------------------------------------------------
# Declared per CONTRIBUTING "Adding a module":
#   time        < 2s   (four small registry keys, one folder listing, and a
#                       bounded read of files that are a few KB each)
#   admin       not required - and deliberately so: every source here is in
#                       HKCU or the running user's own profile. Other users'
#                       NTUSER.DAT is locked on a live host and would need
#                       admin plus VSS, which is the SRUM/Amcache trade this
#                       project already refused. See the limitation below.
#   output      metadata only: names, counts, timestamps, extracted paths
#   AV risk     none - no executable is read, hashed or parsed
#
# LIMITATION, stated in the report and in a note: this module sees ONE user,
# the one running the collector. "No evidence found" here does not mean the
# host was not used - it means this account shows nothing. On a shared or
# service-account host that distinction decides the investigation.
#
# Why it exists: the toolkit could say what is running and what persists, but
# not what a PERSON ran. UserAssist, MUICache and RunMRU answer that from three
# independent places, cost milliseconds, and need no privilege.

# What makes a HISTORICAL execution record worth reading.
#
# The obvious rule - "flag anything outside Program Files" - was written first
# and measured on a real workstation: it produced 142 findings, every one of
# them an installer in Downloads, a Package Cache MSI or an Electron app's
# updater. On modern Windows, AppData and Downloads ARE where ordinary user
# software lives, so location alone carries almost no signal and burying two
# real findings under 142 false ones is worse than raising none.
#
# What is left is genuinely unusual: a script host or an executable-by-another-
# name started through the shell, a double extension, and the three directories
# that ordinary software does not launch from.
$script:UserActivityOddExt = '(?i)\.(scr|hta|pif|vbs|vbe|jse?|wsf|wsh|bat|cmd|ps1|com|cpl)$'
$script:UserActivityDoubleExt = '(?i)\.(pdf|doc|docx|xls|xlsx|jpe?g|png|txt|rtf|zip)\.(exe|scr|com|pif|bat|cmd|js|vbs|hta)$'
$script:UserActivitySuspectDir = '(?i)(\\Windows\\Temp\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|^\\\\[^\\]+\\)'

function Test-UserActivitySuspect {
    param([string]$Path)
    if (-not $Path) { return $false }
    # A double extension is a lie about the file type wherever it sits.
    if ($Path -match $script:UserActivityDoubleExt) { return $true }
    # A .lnk is a pointer, not a program. Every installer drops one on the
    # Public Desktop, so judging shortcuts by WHERE they live flagged Acrobat,
    # Wireshark and Steam on the first real run. Follow the target, or say
    # nothing - do not report the signpost as the destination.
    if ($Path -match '(?i)\.lnk$') { return $false }
    return ($Path -match $script:UserActivityOddExt) -or
           ($Path -match $script:UserActivitySuspectDir)
}

function Get-Rot13 {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        if     ($c -cmatch '[a-z]') { [void]$sb.Append([char](((([int]$c - 97) + 13) % 26) + 97)) }
        elseif ($c -cmatch '[A-Z]') { [void]$sb.Append([char](((([int]$c - 65) + 13) % 26) + 65)) }
        else                        { [void]$sb.Append($c) }
    }
    return $sb.ToString()
}

function Collect-UserActivity {
    Add-Section '32 User activity & download remnants (current user only)'
    try {
        Add-Report 'SCOPE: HKCU and this user profile only. Another account on this host'
        Add-Report 'leaves its own copies of these artifacts, which are not readable here'
        Add-Report 'without Administrator and a shadow copy. Absence is NOT evidence of'
        Add-Report 'absence for other accounts.'
        Add-Report ''
        Add-Report 'NOTE: UserAssist records some paths with a {GUID} prefix - a Windows'
        Add-Report 'KNOWNFOLDERID standing in for a directory. They are left as recorded'
        Add-Report 'rather than translated: a guessed folder mapping in a forensic record'
        Add-Report 'is worse than an untranslated one. Resolve the GUID against the'
        Add-Report 'published KNOWNFOLDERID list if the path matters to the case.'
        Add-Report ''
        # Stated only when it is TRUE. Emitted unconditionally, this told an
        # Administrator run that it needed Administrator -- a wrong statement in
        # the one output a SIEM reads.
        if (-not $isAdmin) {
            Add-Note 'useractivity covers the running user only; other accounts need Administrator + VSS'
        } else {
            Add-Note 'useractivity covers the running user only; other loaded profiles need their hives mounted (VSS)'
        }

        # ---- UserAssist ------------------------------------------------
        # Value names are ROT13-encoded program paths. The Win7+ blob carries
        # the run count at offset 4 and the last-executed FILETIME at offset 60.
        Add-Report '-- UserAssist (GUI program execution, per user) --'
        $uaRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
        $uaCount = 0; $script:UaUnresolved = 0
        if (Test-PathSafe $uaRoot) {
            foreach ($g in @(Get-ChildItem $uaRoot -ErrorAction SilentlyContinue)) {
                $cnt = Join-Path $g.PSPath 'Count'
                if (-not (Test-PathSafe $cnt)) { continue }
                $props = $null
                try { $props = Get-ItemProperty -LiteralPath $cnt -ErrorAction SilentlyContinue } catch {}
                if (-not $props) { continue }
                foreach ($p in @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
                    $name = Get-Rot13 $p.Name
                    $rawName = $name
                    $name = Resolve-KnownFolder $name
                    if ($name -eq $rawName -and $rawName -match '^\{[0-9A-Fa-f-]{36}\}') { $script:UaUnresolved++ }
                    $runs = $null; $last = $null
                    $blob = $p.Value
                    if ($blob -is [byte[]] -and $blob.Length -ge 68) {
                        try {
                            $runs = [BitConverter]::ToUInt32($blob, 4)
                            $ft   = [BitConverter]::ToInt64($blob, 60)
                            # 0 and absurd values appear in the wild; only
                            # convert what FromFileTime will actually accept.
                            if ($ft -gt 0 -and $ft -lt 2650467743999999999) { $last = [DateTime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm:ss') }
                        } catch {}
                    }
                    $uaCount++
                    Add-Report ("    {0,-6} {1,-20} {2}" -f ($(if ($null -ne $runs) { $runs } else { '?' })), ($(if ($last) { $last } else { '-' })), $name)
                    if (Test-UserActivitySuspect $name) {
                        Add-Finding -Category 'useractivity' `
                            -Message ("Script or unusual executable started from the shell by this user: {0}" -f $name) `
                            -Detail ("UserAssist records {0} launch(es), last {1}. UserAssist only records what was started through the shell - Explorer, the Start menu, a desktop or Run shortcut - so a person double-clicked this, it was not spawned by a script. Installers and portable tools in Downloads are deliberately NOT flagged here; what is flagged is a script host, a double extension, or a launch from Windows\\Temp, Public or a UNC path." -f ($(if ($null -ne $runs) { $runs } else { 'an unknown number of' })), ($(if ($last) { $last } else { 'at an unknown time' })))
                    }
                }
            }
        }
        if ($uaCount -eq 0) { Add-Report '    (no UserAssist entries)' }
        $script:Stats['UserAssistEntries'] = $uaCount

        # ---- MUICache ---------------------------------------------------
        Add-Report ''
        Add-Report '-- MUICache (programs the shell has displayed a name for) --'
        $mui = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
        $muiCount = 0
        if (Test-PathSafe $mui) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $mui -ErrorAction SilentlyContinue } catch {}
            if ($props) {
                foreach ($p in @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
                    $exe = $p.Name -replace '\.FriendlyAppName$', '' -replace '\.ApplicationCompany$', ''
                    if ($p.Name -notmatch 'FriendlyAppName$') { continue }
                    $muiCount++
                    Add-Report ("    {0}  =  {1}" -f $exe, $p.Value)
                    # MUICache carries no timestamp and no run count, so on its
                    # own it is inventory, not a lead - 98 findings' worth of it
                    # on an ordinary workstation. It earns a finding only when
                    # the entry is BOTH unusual in kind and no longer on disk:
                    # the shell once displayed a name for this file, and the
                    # file is gone.
                    if ((Test-UserActivitySuspect $exe) -and -not (Test-PathSafe $exe)) {
                        Add-Finding -Category 'useractivity' `
                            -Message ("MUICache names a script or unusual executable that is no longer on disk: {0}" -f $exe) `
                            -Detail ("Shell friendly name: {0}. The shell displayed a name for this file at some point, so it existed on this host; it is not there now. MUICache carries no timestamp - correlate with UserAssist, the Recycle Bin and the filesystem timeline. Uninstalled software also leaves entries here." -f $p.Value)
                    }
                }
            }
        }
        if ($muiCount -eq 0) { Add-Report '    (no MUICache entries)' }

        # ---- RunMRU ------------------------------------------------------
        # Everything typed into Win+R, in order. Short, and attackers type here.
        Add-Report ''
        Add-Report '-- RunMRU (typed into the Run dialog, newest first) --'
        $runmru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
        $mruCount = 0
        if (Test-PathSafe $runmru) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $runmru -ErrorAction SilentlyContinue } catch {}
            if ($props) {
                $order = [string]$props.MRUList
                $names = @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'MRUList' } | ForEach-Object { $_.Name })
                # MRUList gives the order; anything it does not mention is still
                # reported, so a tampered MRUList cannot hide an entry.
                $ordered = @()
                foreach ($ch in $order.ToCharArray()) { if ($names -contains [string]$ch) { $ordered += [string]$ch } }
                foreach ($n in $names) { if ($ordered -notcontains $n) { $ordered += $n } }
                foreach ($n in $ordered) {
                    $cmd = ([string]$props.$n) -replace "`0", '' -replace '\\1$', ''
                    if (-not $cmd) { continue }
                    $mruCount++
                    Add-Report ("    [{0}] {1}" -f $n, $cmd)
                    if ($cmd -match '(?i)(powershell|cmd\.exe|\\\\|https?://|\.ps1|\.vbs|\.hta|\.bat|certutil|bitsadmin|curl|mshta|rundll32|regsvr32)') {
                        Add-Finding -Category 'useractivity' `
                            -Message ("Command typed into the Run dialog: {0}" -f $cmd) `
                            -Detail ("RunMRU entry [{0}]. This was typed by a person at the keyboard of this account, not launched by a script - which is why it is worth reading even when the command itself is ordinary administration." -f $n)
                    }
                }
            }
        }
        if ($mruCount -eq 0) { Add-Report '    (no RunMRU entries)' }

        # ---- Jump Lists ---------------------------------------------------
        # The files are OLE compound documents. Rather than ship an OLE parser
        # in a single-file collector, the UTF-16 paths inside are extracted
        # directly: imperfect, bounded, and enough to answer "what did this
        # application open". The raw files are already copied by fsartifacts.
        Add-Report ''
        Add-Report '-- Jump Lists (per-application recent items; AppID is not decoded) --'
        $jlCount = 0
        # A time budget, enforced rather than hoped for. Decoding 5 MB of jump
        # lists to UTF-16 and running a path regex over it took 5s on an
        # ordinary workstation - more than this whole module is allowed. Newest
        # first, stop extracting at the budget, and SAY so instead of silently
        # doing less than the section header claims.
        $jlBudgetBytes = 6MB
        $jlSpent = 0
        $jlTruncated = $false
        $jlRemote = New-Object System.Collections.Generic.List[string]
        foreach ($jd in @("$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
                          "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations")) {
            if (-not (Test-PathSafe $jd)) { continue }
            $files = @()
            try { $files = @(Get-ChildItem -LiteralPath $jd -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 40) } catch {}
            foreach ($f in $files) {
                $jlCount++
                $appId = $f.BaseName -replace '\.automaticDestinations-ms$','' -replace '\.customDestinations-ms$',''
                $paths = @()
                try {
                    if ($f.Length -le 512KB -and $jlSpent -lt $jlBudgetBytes) {
                        $jlSpent += $f.Length
                        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                        $txt = [System.Text.Encoding]::Unicode.GetString($bytes)
                        $paths = @([regex]::Matches($txt, '(?:[A-Za-z]:\\|\\\\)[^\x00-\x1f"*?<>|]{3,180}') |
                                   ForEach-Object { $_.Value.Trim() } |
                                   Where-Object { $_ -match '\\' } |
                                   Select-Object -Unique | Select-Object -First 15)
                    } elseif ($f.Length -gt 512KB -or $jlSpent -ge $jlBudgetBytes) {
                        $jlTruncated = $true
                    }
                } catch {}
                Add-Report ("    {0}  {1,-18} {2} item path(s)" -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $appId, $paths.Count)
                foreach ($pp in $paths) { Add-Report "        $pp" }
                foreach ($pp in @($paths | Where-Object { $_ -like '\\\\*' })) {
                    if (-not $jlRemote.Contains($pp)) { $jlRemote.Add($pp) }
                }
            }
        }
        if ($jlCount -eq 0) { Add-Report '    (no Jump Lists)' }
        if ($jlTruncated) {
            Add-Report '    NOTE: some jump lists were not read - per-file or total size budget reached.'
            Add-Note 'useractivity: jump-list extraction hit its size budget; the newest files were read first'
        }
        # ONE finding for all of them. A per-file finding would scale with the
        # number of applications the user has, which is not the thing being
        # measured - the distinct remote locations are.
        if ($jlRemote.Count) {
            Add-Finding -Category 'useractivity' `
                -Message ("{0} item(s) opened over the network appear in this user's Jump Lists" -f $jlRemote.Count) `
                -Detail ("{0}{1} | Opened from a UNC path by this user. On an intrusion this is often how tooling or data moved between hosts; on a normal estate it is a file share. The AppID is deliberately not decoded to an application name - a guessed mapping would be worse than none; see report section 32 for which AppID held which item." -f ((@($jlRemote) | Select-Object -First 8) -join ' ; '), $(if ($jlRemote.Count -gt 8) { ' ...' } else { '' }))
        }
        $script:Stats['JumpListFiles'] = $jlCount

        # ---- CryptnetUrlCache ---------------------------------------------
        # Written by the Windows crypto stack, which means MOST of it is
        # certificate revocation traffic (.crl / OCSP) from ordinary software.
        # The signal is the remainder: `certutil -urlcache -f <url>` leaves its
        # download here, and the entry outlives the process.
        Add-Report ''
        Add-Report '-- CryptnetUrlCache (URLs fetched through the crypto stack) --'
        $cuCount = 0; $cuOther = 0
        $cuOtherUrls = New-Object System.Collections.Generic.List[string]
        $meta = "$env:APPDATA\Microsoft\CryptnetUrlCache\MetaData"
        if (Test-PathSafe $meta) {
            $files = @()
            try { $files = @(Get-ChildItem -LiteralPath $meta -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 200) } catch {}
            foreach ($f in $files) {
                $url = $null
                try {
                    if ($f.Length -le 256KB) {
                        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                        foreach ($enc in @([System.Text.Encoding]::Unicode, [System.Text.Encoding]::ASCII)) {
                            $m = [regex]::Match($enc.GetString($bytes), 'https?://[^\x00-\x1f"<>|]{4,300}')
                            if ($m.Success) { $url = $m.Value.Trim(); break }
                        }
                    }
                } catch {}
                if (-not $url) { continue }
                $cuCount++
                $isRevocation = $url -match '(?i)(\.crl$|\.crt$|\.cer$|/ocsp|ocsp\.|crl\.|\.p7c$|pki\.|/pki/|certificates?\.)'
                Add-Report ("    {0}  {1}  {2}" -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $(if ($isRevocation) { 'revocation' } else { 'OTHER     ' }), $url)
                if (-not $isRevocation) {
                    $cuOther++
                    $cuOtherUrls.Add($url)
                    if ($cuOther -gt 10) { continue }
                    Add-Finding -Category 'useractivity' `
                        -Message ("URL fetched through the crypto stack that is not revocation traffic: {0}" -f $url) `
                        -Detail ("CryptnetUrlCache entry, cached {0}. Nearly everything in this cache is certificate-revocation traffic; an entry that is not is often `certutil -urlcache -f <url>` being used to download a file, and it survives the process that did it. Some installers and update clients also appear here - verify the URL before concluding." -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
                }
            }
        }
        if ($cuCount -eq 0) { Add-Report '    (no CryptnetUrlCache entries)' }
        else { Add-Report ("    {0} entr(y/ies), {1} not revocation traffic" -f $cuCount, $cuOther) }
        # Past ten, one-per-URL stops being a lead and becomes a list. Raise the
        # list itself instead, so the count is still visible and the finding
        # count stays bounded.
        if ($cuOther -gt 10) {
            Add-Finding -Category 'useractivity' `
                -Message ("{0} URLs fetched through the crypto stack are not revocation traffic" -f $cuOther) `
                -Detail ("First 10 were raised individually; see report section 32 for all {0}. A cache this busy with non-revocation URLs is usually an updater or a security product rather than certutil - identify the fetching software before treating the list as downloads." -f $cuOther)
        }
    } catch { Add-Err "UserActivity failed: $_" }
}

# ---------------------------------------------------------------------
#  33  Mark-of-the-Web (Zone.Identifier)
# ---------------------------------------------------------------------
# Declared per CONTRIBUTING "Adding a module":
#   time        3.3s measured on a profile where 290 files carry the stream -
#                      the slowest module in the set, and declared as measured
#                      rather than as hoped. Bounded at the 400 newest files
#                      per location, depth 2; when a location holds more, the
#                      module SAYS so through Add-Note instead of quietly
#                      checking fewer than its section header claims.
#   admin       not required - the user's own download locations
#   output      metadata only: path, zone, and the URL the file came from
#   AV risk     none - the Zone.Identifier STREAM is read, never the file
#
# Why: every other execution-evidence module answers "what ran". This one
# answers "where did it come from", which is the question that turns a
# suspicious binary into an incident narrative. Windows records it for free -
# the browser or mail client writes a Zone.Identifier alternate data stream
# carrying the zone and, on modern Windows, ReferrerUrl and HostUrl. It is
# read with -Stream, so the file's own contents are never touched.
#
# LIMITATION, recorded via Add-Note: MOTW lives in the NTFS stream. A copy
# through a FAT/exFAT volume, most archive tools, or a deliberate
# Unblock-File drops it - so a file WITHOUT the stream is not evidence that it
# came from the machine. Absence proves nothing here; presence is the evidence.
function Collect-MOTW {
    Add-Section '33 Mark-of-the-Web (Zone.Identifier) - where downloaded files came from'
    try {
        Add-Report 'Zone 3 = Internet, 4 = Restricted. The stream is NTFS-only: copying'
        Add-Report 'through FAT/exFAT, unpacking with most archive tools, or Unblock-File'
        Add-Report 'removes it, so a file WITHOUT this stream is not evidence that it was'
        Add-Report 'not downloaded. Presence is the evidence; absence is not.'
        Add-Report ''
        Add-Note 'motw: Mark-of-the-Web is an NTFS stream, so its absence does not prove local origin'

        $roots = @(
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Documents",
            "$env:TEMP",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        # Bounded on purpose: this is a triage collector, not a filesystem
        # crawler. Newest first, so a truncated walk keeps the useful end.
        $maxPerRoot = 400
        $seen = 0; $withMotw = 0; $truncated = $false; $macroChecked = 0; $macroFound = 0
        $interesting = New-Object System.Collections.Generic.List[string]

        foreach ($r in $roots) {
            if (-not (Test-PathSafe $r)) { continue }
            $files = @()
            try {
                $files = @(Get-ChildItem -LiteralPath $r -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                           Sort-Object LastWriteTime -Descending | Select-Object -First ($maxPerRoot + 1))
            } catch {}
            if ($files.Count -gt $maxPerRoot) { $truncated = $true; $files = @($files | Select-Object -First $maxPerRoot) }
            foreach ($f in $files) {
                $seen++
                # An Office document that carries a macro, downloaded or not:
                # the delivery step of most macro phishing. Up to 20 MB, read
                # as bytes only (Get-OfficeMacroMarker).
                if ($f.Extension -match '(?i)^\.(doc|docm|docx|dot|dotm|xls|xlsm|xlsb|xlsx|xlt|xltm|xla|xlam|ppt|pptm|pptx|pot|potm|ppsm|pps)$' -and $f.Length -le 20MB -and $macroChecked -lt 200) {
                    $macroChecked++
                    $mk = ''
                    try { $mk = Get-OfficeMacroMarker ([IO.File]::ReadAllBytes($f.FullName)) } catch { }
                    if ($mk) {
                        $mz = ''
                        try { $mzr = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue -Raw; $mz = ([regex]::Match([string]$mzr, '(?im)^\s*ZoneId\s*=\s*(\d+)')).Groups[1].Value } catch { }
                        $macroFound++
                        Add-Finding -Category 'motw' -Message ("Office document with a macro: {0}" -f $f.FullName) `
                            -Detail ("Contains a VBA project ({0}){1}. Macros are how most document phishing runs code; open it only in an analysis environment, and check whether Office spawned a shell (process findings) after {2:yyyy-MM-dd}." -f $mk, $(if ($mz -in @('3','4')) { "; Mark-of-the-Web ZoneId=$mz, downloaded from outside" } elseif ($mz) { "; ZoneId=$mz" } else { '' }), $f.LastWriteTime)
                    }
                }
                $zoneRaw = $null
                try { $zoneRaw = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue -Raw } catch {}
                if (-not $zoneRaw) { continue }
                $withMotw++
                $zoneId   = ([regex]::Match($zoneRaw, '(?im)^\s*ZoneId\s*=\s*(\d+)')).Groups[1].Value
                $hostUrl  = ([regex]::Match($zoneRaw, '(?im)^\s*HostUrl\s*=\s*(\S.*)$')).Groups[1].Value.Trim()
                $referrer = ([regex]::Match($zoneRaw, '(?im)^\s*ReferrerUrl\s*=\s*(\S.*)$')).Groups[1].Value.Trim()
                $hostUrl  = Hide-UrlSecret $hostUrl
                $referrer = Hide-UrlSecret $referrer
                Add-Report ("    zone={0}  {1}" -f $(if ($zoneId) { $zoneId } else { '?' }), $f.FullName)
                if ($hostUrl)  { Add-Report "        from: $hostUrl" }
                if ($referrer) { Add-Report "        ref : $referrer" }

                # A document or archive from the internet is ordinary. An
                # EXECUTABLE one is the first half of almost every phishing
                # chain, so that is what earns a finding - with the URL, which
                # is the part an analyst cannot reconstruct later.
                if ($f.Extension -match '(?i)^\.(exe|dll|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|lnk|iso|img|vhd|vhdx|one)$' -and
                    $zoneId -in @('3','4')) {
                    if ($interesting.Count -lt 25) { $interesting.Add([string]$f.FullName) }
                    Add-Finding -Category 'motw' `
                        -Message ("Executable or container downloaded from the internet: {0}" -f $f.FullName) `
                        -Detail ("ZoneId={0}{1}{2} | Windows recorded this file as arriving from outside the machine. The URL is the part that cannot be reconstructed after the fact - check it against the incident window and the user's account of where the file came from. Ordinary software downloads look exactly like this, which is why it is Review." -f `
                                 $zoneId, `
                                 $(if ($hostUrl)  { "; HostUrl=$hostUrl" }   else { '' }), `
                                 $(if ($referrer) { "; Referrer=$referrer" } else { '' }))
                }
            }
        }
        if ($truncated) { Add-Note ("motw: a download location held more than {0} files; the newest {0} were checked" -f $maxPerRoot) }
        Add-Report ''
        Add-Report ("    {0} file(s) checked, {1} carry a Zone.Identifier" -f $seen, $withMotw)
        Add-Report ("    {0} Office document(s) checked for a macro, {1} carry one" -f $macroChecked, $macroFound)
        $script:Stats['FilesWithMotw'] = $withMotw
    } catch { Add-Err "MOTW failed: $_" }
}

# --Quick: the highest-signal subset, for the case this tool exists for - a
# responder on a host they want to be off again quickly. Chosen by MEASUREMENT
# on this edition, not by taste. Measured on an ordinary workstation:
#
#   useractivity 3.4s   network 2.1s   persistence 1.5s   services 1.4s
#   sysinfo      1.3s   process 0.8s   rmm        0.5s    sessions 0.4s
#   users        0.3s                            = 10.1s measured end to end
#
#   indicators  16.9s   EXCLUDED - it walks temp and appdata for executables
#                       and costs more than the other nine put together. Its
#                       finding is also the noisiest the tool raises, by its
#                       own admission.
#   motw         3.0s   EXCLUDED - it answers "how did this get here", which
#                       is the --All question. --Quick answers "is something
#                       wrong on this host".
#
# Saying which QUESTION a profile answers is more useful than listing what it
# leaves out. Note the asymmetry with the Linux edition, which keeps
# `indicators` in its profile: the same module name costs 0.27s there. The
# profiles differ per platform because the measurements do.
$script:QuickModules = @('sysinfo','network','process','sessions','users','services','persistence','rmm','useractivity')

# =====================================================================
#  Module registry  (ORDER = order of volatility, then derived artifacts)
# =====================================================================
# ---------------------------------------------------------------------------
#  Artifact dictionary
# ---------------------------------------------------------------------------
# What each output IS, what question it answers, and what opens it. A responder
# who has just run the tool asks "collected - now what?", and until now nothing
# in the evidence folder answered that: they got ~30 files and five directories
# and had to already know what a .automaticDestinations-ms is.
#
# This is a hand-maintained list of names, and this repo has shipped five stale
# ones (module list, version badge, README changelog, version literal, quick
# profile). So it is gated against a REAL RUN rather than against the source:
# Write-ArtifactIndex matches every file actually produced against these
# patterns and reports what it could not place. CI fails on a non-zero count,
# which means a new module that writes a file nobody catalogued breaks the
# build rather than quietly producing an unexplained artifact.
#
# Scope discipline: this names what TATAR produces. It is not a catalogue of
# DFIR artifacts in general, and must not grow into one.
$script:Artifacts = @(
    [pscustomobject]@{ Pattern = 'summary.json';            Class = 'triage summary (structured)'; Question = 'what the run found, machine-readable';                 Next = 'SIEM / SOAR ingest; validates against schema/summary.schema.json' }
    [pscustomobject]@{ Pattern = 'findings.json';           Class = 'findings only (structured)';  Question = 'the leads, without the rest of the summary';           Next = 'SIEM / SOAR ingest; schema/findings.schema.json' }
    [pscustomobject]@{ Pattern = 'summary.txt';             Class = 'triage summary (human)';      Question = 'the same findings, to read now';                      Next = 'read directly - start here' }
    [pscustomobject]@{ Pattern = 'TATAR_Report_*.txt';      Class = 'full collection report';      Question = 'everything every module collected, in order';         Next = 'read directly; grep by section number' }
    [pscustomobject]@{ Pattern = 'tatar.log';               Class = 'execution log';               Question = 'what the collector did, and what it could NOT do';    Next = 'read directly - check this before trusting an empty section' }
    [pscustomobject]@{ Pattern = 'ARTIFACTS.md';            Class = 'this index';                  Question = 'what is in this folder and what opens it';            Next = 'you are reading it' }
    [pscustomobject]@{ Pattern = 'paste.txt';               Class = 'pasteable summary';          Question = 'the whole run in under 60 lines, to show someone';    Next = 'paste into a ticket or chat. Stable between runs, so diff two of them to see what changed on the host' }
    [pscustomobject]@{ Pattern = 'allowlist.suggested.json'; Class = 'allowlist draft';           Question = 'what a baseline for this host would look like';       Next = 'review EVERY line, delete what you cannot vouch for, then pass it to -Allowlist' }
    [pscustomobject]@{ Pattern = 'manifest_sha256.txt';     Class = 'integrity manifest';          Question = 'has anything in this folder changed since collection'; Next = 'sha256sum -c manifest_sha256.txt' }
    [pscustomobject]@{ Pattern = 'chain_of_custody.txt';    Class = 'chain of custody';            Question = 'who collected this, where and when';                  Next = 'read directly; attach to the case file' }
    [pscustomobject]@{ Pattern = 'timeline.csv';            Class = 'timeline';                    Question = 'what happened in what order';                         Next = 'Timeline Explorer, Excel, or any CSV viewer' }
    [pscustomobject]@{ Pattern = 'binary_hashes.txt';       Class = 'binary hashes';               Question = 'which binaries were running, by SHA-256';             Next = 'VirusTotal / an internal hash reputation service (offline: compare to a known-good baseline)' }
    [pscustomobject]@{ Pattern = 'hosts.txt';               Class = 'name resolution';             Question = 'has name resolution been tampered with';              Next = 'read directly - any non-default line is worth a look' }
    [pscustomobject]@{ Pattern = 'external_ips.txt';        Class = 'network state';               Question = 'which public addresses this host was connected to';   Next = 'look them up on the analyst machine (a reputation service or threat intelligence); the collector looks nothing up' }
    [pscustomobject]@{ Pattern = 'arp.txt';                 Class = 'network state';               Question = 'who this host has been talking to on the LAN';        Next = 'read directly' }
    [pscustomobject]@{ Pattern = 'routes.txt';              Class = 'network state';               Question = 'where traffic from this host goes';                   Next = 'read directly - an unexpected route is a redirect' }
    [pscustomobject]@{ Pattern = 'ipconfig.txt';            Class = 'network state';               Question = 'the host addressing and DNS servers';                 Next = 'read directly' }
    [pscustomobject]@{ Pattern = 'dns_cache.txt';           Class = 'DNS cache';                   Question = 'what names this host resolved recently';              Next = 'read directly; cross-check against a C2 domain list' }
    [pscustomobject]@{ Pattern = 'firewall_rules.txt';      Class = 'firewall configuration';      Question = 'what was allowed in or out';                          Next = 'read directly - look for rules nobody recognises' }
    [pscustomobject]@{ Pattern = 'recyclebin.csv';          Class = 'deleted files';               Question = 'what was deleted, from where, and when';              Next = 'any CSV viewer' }
    [pscustomobject]@{ Pattern = 'autoruns.csv';            Class = 'autoruns (Sysinternals)';     Question = 'everything configured to start automatically';        Next = 'Autoruns GUI, or any CSV viewer' }
    [pscustomobject]@{ Pattern = 'EventLogs\evt_*.csv';     Class = 'event log preview';           Question = 'the 15 highest-signal Security event IDs';            Next = 'read directly. Capped at 50 events each - NOT a hunting corpus' }
    [pscustomobject]@{ Pattern = 'EventLogs\*.evtx';        Class = 'Windows event log';           Question = 'the full log history';                                Next = 'Hayabusa, Chainsaw (Sigma), or Event Viewer. Needs -ExportEvtx' }
    [pscustomobject]@{ Pattern = 'RDP\*.csv';               Class = 'RDP session evidence';        Question = 'who connected over RDP, and from where';              Next = 'any CSV viewer' }
    [pscustomobject]@{ Pattern = 'BrowserArtifacts\*';      Class = 'browser metadata';            Question = 'what the browser profiles look like';                 Next = 'read the summary; the profile files themselves need a browser-forensics tool' }
    [pscustomobject]@{ Pattern = 'FsArtifacts\*.lnk';       Class = 'shortcut (LNK)';              Question = 'what files were opened, and from what volume';        Next = 'LECmd' }
    [pscustomobject]@{ Pattern = 'FsArtifacts\*Destinations-ms'; Class = 'jump list';              Question = 'what each application opened, per user';              Next = 'JLECmd' }
    [pscustomobject]@{ Pattern = 'FsArtifacts\*.hve';       Class = 'registry hive fragment';      Question = 'user-activity keys taken from a loaded profile';      Next = 'RegRipper, Registry Explorer' }
    [pscustomobject]@{ Pattern = 'FsArtifacts\*';           Class = 'filesystem artifacts';        Question = 'volume, disk and USN state';                          Next = 'read directly' }
    [pscustomobject]@{ Pattern = 'MFT\*';                   Class = 'NTFS / MFT information';      Question = 'volume geometry and MFT layout';                      Next = 'read directly. Full $MFT parsing needs MFTECmd on an offline image' }
    [pscustomobject]@{ Pattern = 'RegistryHives\*';         Class = 'registry hive';               Question = 'the full registry, offline';                          Next = 'RegRipper, Registry Explorer. Contains CREDENTIAL MATERIAL - encrypt' }
    [pscustomobject]@{ Pattern = 'memory.raw';              Class = 'memory image';                Question = 'what was in RAM';                                     Next = 'Volatility 3' }
    [pscustomobject]@{ Pattern = 'memory.raw.sha256.txt';   Class = 'memory image hash';           Question = 'integrity of the memory image';                       Next = 'compare before analysis' }
    [pscustomobject]@{ Pattern = 'winpmem_log.txt';         Class = 'acquisition log';             Question = 'whether memory acquisition actually worked';          Next = 'read directly if memory.raw is missing or empty' }
)

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
    rmm         = ${function:Collect-RMM}
    useractivity = ${function:Collect-UserActivity}
    motw        = ${function:Collect-MOTW}
    hashes      = ${function:Collect-Hashes}
    timeline    = ${function:Collect-Timeline}
}

# =====================================================================
#  Dispatch
# =====================================================================
if (-not $Silent) { Show-Banner }
# Console hint now, so -Help / -List users see it too; the durable record (log +
# error count) is written further down, once the exec log and report exist.
foreach ($u in $UnknownOpts) { Write-Console "[!] Unknown option: $u" 'Yellow' }
if ($Help) { Show-Help; exit 0 }
if ($List) {
    Write-Host "Available modules (order of volatility):`n"
    $script:Collectors.Keys | ForEach-Object {
        if ($script:QuickModules -contains $_) { Write-Host ("  {0}   [quick]" -f $_) } else { Write-Host "  $_" }
    }
    Write-Host ("`nTotal: {0} modules | -Quick runs the {1} marked [quick]" -f $script:Collectors.Count, @($script:QuickModules).Count)
    exit 0
}

# Two module selectors at once is a usage error, not a silent precedence rule.
# Quietly preferring one would be the same class of defect as a value-less flag
# consuming the next token: the run looks fine and collected something other
# than what was asked for.
$selectors = @($All, $Quick, [bool]$Modules) | Where-Object { $_ }
if ($selectors.Count -gt 1) {
    [Console]::Error.WriteLine('[x] FATAL: use only one of -All, -Quick or -Modules')
    exit 1
}
$toRun = if ($All) { @($script:Collectors.Keys) }
         elseif ($Quick) { @($script:QuickModules) }
         elseif ($Modules) { $Modules }
         else {
             if (-not $Silent) { Show-Help; Write-Host "`n[i] Nothing selected. Use -Quick, -All or -Modules." -ForegroundColor Yellow }
             exit 1
         }

# If the identity check cannot run, assume NOT administrator: the run then warns
# that artifacts will be incomplete, which is the safe reading. Letting the
# exception through left $isAdmin empty, and Write-Summary -IsAdmin takes a
# [bool], so the binding failed and summary.json -- the machine-readable output
# contract -- was never written at all, while the text report still appeared.
$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    Write-Console "[!] Could not determine administrator status ($($_.Exception.Message)) - assuming standard user." 'Yellow'
}
if (-not $isAdmin) { Write-Console "[!] Not running as Administrator - some artifacts will be incomplete." 'Yellow' }

$hostn = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$script:OutDir     = Join-Path $OutputPath ("{0}_{1}" -f $hostn, $stamp)
$script:ReportFile = Join-Path $script:OutDir ("TATAR_Report_{0}_{1}.txt" -f $hostn, $stamp)

# -DryRun: every input an operator wants to check first - the resolved output
# path, the module order, the armed gated operations, the feed verdicts - is
# already known here. It used to be printed only AFTER the output directory had
# been created, i.e. after the first write to the disk being preserved, and
# -CollectHives / -MemoryDump are documented as EDR-triggering. Print it and
# stop, touching nothing. Not silenced by -Silent: a preview nobody can see has
# no purpose. (There is no param() block, so -WhatIf is not available.)
if ($DryRun) {
    $unknownMods = @($toRun | Where-Object { -not $script:Collectors.Contains($_) })
    Write-Host ''
    Write-Host '=== TATAR DRY RUN - nothing is collected and nothing is written ===' -ForegroundColor Cyan
    Write-Host ("  {0,-14}: TATAR Triage Toolkit v{1}" -f 'Tool', $script:ToolVersion)
    Write-Host ("  {0,-14}: {1}" -f 'Host', $hostn)
    Write-Host ("  {0,-14}: {1} (Administrator)" -f 'Privileged', $isAdmin)
    Write-Host ("  {0,-14}: {1}" -f 'Output dir', $script:OutDir)
    if ((Split-Path $OutputPath -Qualifier -ErrorAction SilentlyContinue) -eq $env:SystemDrive) {
        Write-Host ("  {0,-14}: the output path is on the SYSTEM drive ({1}) - writing evidence there can overwrite deleted-file evidence. Prefer an external drive (-OutputPath E:\Evidence)." -f 'WARNING', $env:SystemDrive) -ForegroundColor Red
    }
    Write-Host ("  {0,-14}: {1}" -f 'Case ID', $(if ($CaseId) { $CaseId } else { '(none)' }))
    Write-Host ("  {0,-14}: {1}" -f 'Examiner', $(if ($Examiner) { $Examiner } else { '(none)' }))
    Write-Host ("  {0,-14}: {1} module(s) in this order: {2}" -f 'Modules', @($toRun).Count, (@($toRun) -join ' '))
    if ($unknownMods.Count) { Write-Host ("  {0,-14}: NOT a module, nothing would be collected for it: {1}" -f 'WARNING', ($unknownMods -join ' ')) -ForegroundColor Red }
    Write-Host ("  {0,-14}: -CollectHives={1} -ExportEvtx={2} -MemoryDump={3} -Compress={4} -Silent={5}" -f 'Gated ops', $CollectHives, $ExportEvtx, $MemoryDump, $Compress, $Silent)
    foreach ($spec in @(@{ Name = 'Allowlist'; Path = $Allowlist }, @{ Name = 'IOC file'; Path = $IOCFile })) {
        if (-not $spec.Path)                { Write-Host ("  {0,-14}: (none supplied)" -f $spec.Name) }
        elseif (Test-PathSafe $spec.Path)   { Write-Host ("  {0,-14}: readable, WILL be applied: {1}" -f $spec.Name, $spec.Path) }
        else                                { Write-Host ("  {0,-14}: NOT READABLE, would NOT be applied: {1}" -f $spec.Name, $spec.Path) -ForegroundColor Red }
    }
    foreach ($u in $UnknownOpts) { Write-Host ("  {0,-14}: unknown option, would be ignored: {1}" -f 'WARNING', $u) -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Re-run without -DryRun to collect.'
    Write-Host ''
    exit 0
}

try {
    # Refuse to write evidence through a reparse point (junction/symlink).
    $op = Split-Path -Parent $script:OutDir
    if ($op -and (Test-Path -LiteralPath $op) -and ((Get-Item -LiteralPath $op -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'output path is a reparse point (junction/symlink); refusing' }
    if (Test-Path -LiteralPath $script:OutDir) { throw 'evidence directory already exists; refusing to reuse' }
    New-Item -ItemType Directory -Force -Path $script:OutDir -ErrorAction Stop | Out-Null
    # Evidence is private: no inherited ACEs; SYSTEM, Administrators and the current user only.
    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) { $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
        Set-Acl -LiteralPath $script:OutDir -AclObject $acl
    } catch { }
} catch {
    if (-not $Silent) { Write-Host "[x] FATAL: cannot create output directory ${script:OutDir}: $_" -ForegroundColor Red }
    exit 1
}
# Normalise to a full path now that it exists: the manifest computes paths
# relative to it, and a .NET file write resolves a relative path against the
# process directory rather than PowerShell's, so a relative -OutputPath must
# not leak past this point.
$script:OutDir     = (Resolve-Path -LiteralPath $script:OutDir).Path
$script:ReportFile = Join-Path $script:OutDir ("TATAR_Report_{0}_{1}.txt" -f $hostn, $stamp)

# P4: execution log lives next to the evidence, excluded from the manifest
# (operational log, not evidence). Lower case, like the Linux edition: the two
# spellings collide if an analyst merges a Windows and a Linux output folder.
$script:ExecLog = Join-Path $script:OutDir 'tatar.log'
Write-ExecLog 'INFO' ("TATAR Triage Toolkit v$($script:ToolVersion) starting on {0} as {1} (admin={2}, silent={3})" -f $hostn, $env:USERNAME, $isAdmin, $Silent)
Write-ExecLog 'INFO' ("CaseId='{0}' Examiner='{1}' OutDir={2}" -f $CaseId, $Examiner, $script:OutDir)
Write-ExecLog 'INFO' ("Modules selected: {0}" -f ($toRun -join ', '))
if (-not $isAdmin) { Write-ExecLog 'WARN' 'Not running as Administrator - collection will be incomplete.' }

# -Qualifier throws on any path that has no drive letter, and a UNC target such
# as \\fileserver\Evidence is exactly that -- writing triage output to a network
# share is an ordinary workflow, so this warning must not abort the run.
$outQualifier = try { Split-Path $OutputPath -Qualifier -ErrorAction Stop } catch { '' }
if ($outQualifier -and $env:SystemDrive -and $outQualifier -eq $env:SystemDrive) {
    Write-Console "[!] WARNING: writing evidence to the SYSTEM drive ($env:SystemDrive). This can overwrite deleted-file evidence. Prefer an external drive (-OutputPath E:\Evidence)." 'Red'
    Write-ExecLog 'WARN' "Evidence is being written to the system drive $env:SystemDrive - prefer an external drive."
}

$start = Get-Date
@"
TATAR Triage Toolkit v$($script:ToolVersion) - Collection Report
Host        : $hostn
Case ID     : $CaseId
Examiner    : $Examiner
Started     : $(Get-IsoUtc $start)
TimeZone    : $((Get-TimeZone).Id)
Admin       : $isAdmin
Modules     : $($toRun -join ', ')
OutputDir   : $script:OutDir
"@ | Out-FileNoBom $script:ReportFile

$hdrCase = if ($CaseId) { [string]$CaseId } else { '-' }
Write-Console ("  HOST      {0}   CASE  {1}" -f $hostn, $hdrCase) 'White'
if ($isAdmin) { Write-Console "  ADMIN     yes" 'Green' }
else { Write-Console "  ADMIN     LIMITED   ! run as Administrator for full coverage" 'Yellow' }
Write-Console ("  EVIDENCE  {0}   MODE  read-only" -f $script:OutDir) 'White'
Write-Console (' ' + ('-' * 77)) 'DarkCyan'

# An allowlist / IOC path that cannot be read used to be skipped in silence.
# That is the worst failure mode a triage tool has: the analyst reads "no
# active findings" believing their feed was applied, when it never ran. Say so
# loudly, before the collection, and make it count towards the exit code.
foreach ($spec in @(@{ Name = 'Allowlist'; Path = $Allowlist }, @{ Name = 'IOC file'; Path = $IOCFile })) {
    if (-not $spec.Path) { continue }
    if (Test-PathSafe $spec.Path) {
        Write-ExecLog 'INFO' ("{0} will be applied: {1}" -f $spec.Name, $spec.Path)
    } else {
        Write-Console ("[!] {0} NOT READABLE: {1}" -f $spec.Name, $spec.Path) 'Red'
        Write-Console ("    It will NOT be applied. Fix the path and re-run.") 'Red'
        Add-Err ("{0} not readable, so it was NOT applied: {1}" -f $spec.Name, $spec.Path)
    }
}

# Same class of quiet no-op: an unknown option was a console-only warning, which
# -Silent swallowed completely - a scheduled / WinRM run with a misspelled flag
# looked identical to a clean one and still exited 0. Log it and make it count.
foreach ($u in $UnknownOpts) { Add-Err ("Unknown option ignored: {0}" -f $u) }

$i = 0; $n = $toRun.Count; $ran = 0
foreach ($m in $toRun) {
    $i++
    if (-not $script:Collectors.Contains($m)) {
        # A misspelled module name must never read as "collected and empty".
        Write-Console "[!] Unknown module: $m" 'Yellow'
        $script:ModulesSkipped.Add([string]$m)
        $script:ModuleStatus.Add([pscustomobject]@{ module = [string]$m; status = 'skipped'; seconds = 0; errors = 0 })
        Add-Err ("Unknown module requested, nothing was collected for it: {0}" -f $m)
        continue
    }
    if (-not $Silent) { Write-Progress -Activity 'TATAR Triage' -Status $m -PercentComplete (($i/$n)*100) }
    $barW = 20; $fill = [int][math]::Round(($i / $n) * $barW, [MidpointRounding]::AwayFromZero)
    $lineHead = "  [{0}{1}] {2,2}/{3}  {4}  " -f ('#' * $fill), ('-' * ($barW - $fill)), $i, $n, ([string]$m).PadRight(13)
    Write-ExecLog 'START' ("module {0} ({1}/{2})" -f $m, $i, $n)
    $script:CurrentModule = $m
    $mStart = Get-Date; $errBefore = $script:ErrorCount; $crashed = $false
    try { & $script:Collectors[$m]; $ran++ } catch { Add-Err "Module $m crashed: $_"; $crashed = $true }
    $secs = [math]::Round(((Get-Date) - $mStart).TotalSeconds, 1)
    $mErrs = $script:ErrorCount - $errBefore
    $mStat = if ($crashed) { 'failed' } elseif ($mErrs -gt 0) { 'warn' } else { 'ok' }
    $script:ModuleStatus.Add([pscustomobject]@{ module = [string]$m; status = $mStat; seconds = $secs; errors = $mErrs })
    $mColor = switch ($mStat) { 'ok' { 'Green' } 'warn' { 'Yellow' } default { 'Red' } }
    Write-Console ($lineHead + ("{0,-6} {1}s" -f $mStat, $secs)) $mColor
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
Write-Console (' ' + ('-' * 77)) 'DarkCyan'
Write-Console "  Finalizing (summary, metadata, manifest, hashes)..." 'Green'
$end = Get-Date
$selfHash = ''
try { if ($PSCommandPath) { $selfHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash } } catch {}

@"
=== CHAIN OF CUSTODY ===
Case ID      : $CaseId
Examiner     : $Examiner
Host         : $hostn
Started      : $(Get-IsoUtc $start)
Finished     : $(Get-IsoUtc $end)
Time zone    : $((Get-TimeZone).Id) (UTC$($start.ToString('zzz')))
Clock        : host clock; not compared with an external time source (the tool is offline)
Duration     : $([math]::Round(($end-$start).TotalMinutes,2)) min
Script       : $PSCommandPath
Script SHA256: $selfHash
Tool         : TATAR Triage Toolkit v$($script:ToolVersion)
"@ | Out-FileNoBom (Join-Path $script:OutDir 'chain_of_custody.txt')

Write-ExecLog 'INFO' 'Writing summary.txt / summary.json'
try { Write-Summary -Start $start -End $end -ModulesRun $toRun -IsAdmin $isAdmin } catch { Add-Err "Summary failed: $_" }

# The report trailer has to be written BEFORE the manifest hashes the report:
# appending to an already-hashed file left one entry permanently wrong.
Add-Report "`n=== Collection finished: $(Get-IsoUtc $end) ==="

try {
    # Same name and the same "<sha256>  ./<relative path>" format as the Linux
    # edition, written LF-only and without a BOM, so `sha256sum -c
    # manifest_sha256.txt` verifies an evidence folder from either platform.
    # The CSV this used to write was not checkable by any standard tool.
    # Both read the finished finding set, and paste.txt hashes findings.json,
    # so they run after the JSON documents are on disk and before the index
    # catalogues them and the manifest hashes them.
    # .ToArray(), NOT @(...): the array subexpression operator over a
    # List[object] throws "Argument types do not match" on Windows PowerShell
    # 5.1. Third time in this project - moduleLimitations in 1.4, the
    # correlation pass in 1.5, here now.
    Write-PasteLog -Findings $script:Findings.ToArray() -IsAdmin $isAdmin
    Write-SuggestedAllowlist -Findings $script:Findings.ToArray()
    Write-ArtifactIndex

    # Generated text is read in terminals: neutralise control, escape and bidi characters that host-supplied names
    # and command lines may have carried into it. Verbatim evidence copies are NOT touched.
    try {
        foreach ($gf in @(Get-ChildItem -LiteralPath $script:OutDir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('summary.txt','paste.txt','ARTIFACTS.md','timeline.csv','chain_of_custody.txt') -or $_.Name -like 'TATAR_Report_*' })) {
            try {
                $raw = [IO.File]::ReadAllText($gf.FullName, [Text.Encoding]::UTF8)
            $clean = [regex]::Replace($raw, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u202A-\u202E\u2066-\u2069]', [string][char]0xFFFD)
            $clean = [regex]::Replace($clean, '\r(?!\n)', ' ')
            if ($clean -cne $raw) { [IO.File]::WriteAllText($gf.FullName, $clean, (New-Object Text.UTF8Encoding($false))) }
            } catch { Add-Err "control-character pass failed for $($gf.Name): $_" }
        }
    } catch { Add-Err "control-character pass failed: $_" }

    # Written BEFORE the walk. Appending to the report after the manifest has
    # hashed it is exactly the trailer bug this file already carries a warning
    # about, and it would leave one manifest entry permanently wrong.
    Add-Report ''
    Add-Report 'Manifest coverage: every collected file is hashed in manifest_sha256.txt, including hidden and system files. Two are NOT covered, by construction: manifest_sha256.txt (cannot hash itself; its own SHA-256 is printed at the end of the run and written to manifest_sha256.txt.sha256) and tatar.log (still being appended while the manifest is built).'
    $manifest = Join-Path $script:OutDir 'manifest_sha256.txt'
    # Compared by NAME, not by full path: the relative names come from
    # Get-ChildItem -Name while these two were built with Join-Path, and the two
    # spellings need not agree (8.3 vs long form). Matching on the name cannot
    # drift. tatar.log keeps growing after hashing, so it is excluded.
    $exclude  = @('manifest_sha256.txt', (Split-Path $script:ExecLog -Leaf))
    $mLines   = New-Object System.Collections.Generic.List[string]
    # -Force, because Get-ChildItem hides hidden and system files by default and
    # the collection picks some up: FsArtifacts\Recent carries desktop.ini, which
    # was being written into the evidence folder and then left out of the
    # manifest. A collected file that is not hashed is a hole in the chain of
    # custody, however uninteresting the file is.
    # -Name, for the same reason as Write-ArtifactIndex: taking the prefix off
    # a full path by string arithmetic breaks on a case difference and on an
    # 8.3 short path, and when it breaks here the manifest silently records
    # ABSOLUTE paths - which makes `sha256sum -c` fail for whoever verifies the
    # folder on another machine. A chain-of-custody defect no test would see.
    foreach ($rel in @(Get-ChildItem -LiteralPath $script:OutDir -Recurse -File -Force -Name -ErrorAction SilentlyContinue | Sort-Object)) {
        if ($exclude -contains ([string]$rel)) { continue }
        $full = Join-Path $script:OutDir ([string]$rel)
        $h = Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($h) {
            $mLines.Add(("{0}  ./{1}" -f $h.Hash.ToLower(), ([string]$rel).Replace('\','/')))
        }
    }
    [IO.File]::WriteAllText($manifest, (($mLines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-ExecLog 'INFO' "Manifest written: $manifest ($($mLines.Count) file(s))"
    # The manifest cannot hash itself, so its own digest is the one number an
    # analyst has to carry out of band. Print it, log it, and leave it beside the
    # manifest in sha256sum format: `sha256sum -c manifest_sha256.txt.sha256`.
    $mh = Get-FileHash -LiteralPath $manifest -Algorithm SHA256 -ErrorAction Stop
    [IO.File]::WriteAllText((Join-Path $script:OutDir 'manifest_sha256.txt.sha256'), ("{0}  manifest_sha256.txt`n" -f $mh.Hash.ToLower()), (New-Object System.Text.UTF8Encoding($false)))
    Write-ExecLog 'INFO' ("Manifest SHA-256: {0}" -f $mh.Hash.ToLower())
    Write-Console ("  Manifest SHA-256: {0}" -f $mh.Hash.ToLower()) 'Green'
} catch { Add-Err "Manifest failed: $_" }

if ($Compress) {
    try {
        $zip = Join-Path $OutputPath ("TATAR_{0}_{1}.zip" -f $hostn, $stamp)
        Compress-Archive -Path (Join-Path $script:OutDir '*') -DestinationPath $zip -Force
        (Get-FileHash $zip -Algorithm SHA256).Hash | Out-FileNoBom ($zip + '.sha256.txt')
        Write-ExecLog 'INFO' "Archive created + hashed: $zip"
        Write-Console "[i] Archive: $zip" 'Green'
    } catch {
        Add-Err "Compression failed: $_"
        Write-Console "[!] Compression failed: $_" 'Yellow'
    }
}

$exitCode = if ($script:ErrorCount -gt 0) { 2 } else { 0 }
Write-ExecLog 'INFO' ("Run complete. Findings: {0} | Errors: {1} | Exit code: {2}" -f $script:Findings.Count, $script:ErrorCount, $exitCode)

Write-Console (' ' + ('=' * 77)) 'DarkCyan'
$doneColor = if ($exitCode -eq 0) { 'Green' } else { 'Yellow' }
Write-Console ("  DONE      {0}/{1} modules   {2}s   {3} lead(s) for review   errors {4}   exit {5}" -f $ran, $n, [math]::Round(((Get-Date) - $start).TotalSeconds), $script:Findings.Count, $script:ErrorCount, $exitCode) $doneColor
if (-not $isAdmin) { Write-Console "  ADMIN     limited run: locked files and some logs were not readable" 'Yellow' }
Write-Console ("  REPORT    {0}" -f $script:ReportFile) 'White'
Write-Console ("  SUMMARY   {0}" -f (Join-Path $script:OutDir 'summary.txt')) 'White'
Write-Console "  NEXT      open viewer.html on the analyst machine, then load summary.json" 'White'
Write-Console "  This tool does NOT extract passwords. Encrypt & handle output per policy." 'DarkGray'
exit $exitCode
