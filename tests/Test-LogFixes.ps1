<#
    TATAR Triage Toolkit - unit tests for the fixes found by reading a real scan
    (v1.8.1). The functions are lifted from Tatar.ps1 with the parser, so the
    code under test is the code that ships. Source is ASCII only.

      L1  Read-TextAuto       UTF-16 (BOM, BE, BOM-less) and UTF-8 logs read as text
      L2  Hide-UrlSecret      signed-URL credentials are redacted, the rest is kept
      L3  Remove-ExeToken     a process is judged by its arguments, not its own name
      L5  Test-WmiDefaultBinding  only Windows' own SCM binding is "stock"; judged by structure
      L4  Test-WritableByUsers a user-writable file is detected, a system file is not,
                              an unreadable ACL is "unknown" (never "safe")

        pwsh -NoProfile -File tests/Test-LogFixes.ps1
    Exit code: 0 = all passed, 1 = at least one failed.
#>
#Requires -Version 5.1
param([string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'))
$ErrorActionPreference = 'Continue'
$script:Pass = 0; $script:Fail = 0
function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { $script:Pass++; Write-Host ('  PASS  ' + $Name) -ForegroundColor Green }
    else { $script:Fail++; Write-Host ('  FAIL  ' + $Name + '  ' + $Detail) -ForegroundColor Red }
}
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Collector).Path, [ref]$tokens, [ref]$errs)
foreach ($n in @('Read-TextAuto', 'Hide-UrlSecret', 'Remove-ExeToken', 'Test-WritableByUsers', 'Test-WmiDefaultBinding', 'Get-FilesByExtension')) {
    $def = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true)
    if (-not $def) { Write-Host ('FAIL  ' + $n + ' not found'); exit 1 }
    . ([scriptblock]::Create($def.Extent.Text))
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('tatar-lf-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null

Write-Host "`nL1  Read-TextAuto"
$text = "Incoming    2026-08-26, 03:02    User    365429176`r`nOutgoing    2026-08-27, 10:11    User    123456789`r`n"
function Write-Enc { param([string]$Name, [byte[]]$Bytes) $p = Join-Path $work $Name; [IO.File]::WriteAllBytes($p, $Bytes); $p }
$cases = [ordered]@{
    'UTF-16 LE with BOM'    = ([byte[]](0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes($text))
    'UTF-16 LE no BOM'      = [Text.Encoding]::Unicode.GetBytes($text)
    'UTF-16 BE with BOM'    = ([byte[]](0xFE, 0xFF) + [Text.Encoding]::BigEndianUnicode.GetBytes($text))
    'UTF-16 BE no BOM'      = [Text.Encoding]::BigEndianUnicode.GetBytes($text)
    'UTF-8 with BOM'        = ([byte[]](0xEF, 0xBB, 0xBF) + [Text.Encoding]::UTF8.GetBytes($text))
    'UTF-8 no BOM'          = [Text.Encoding]::UTF8.GetBytes($text)
}
foreach ($k in $cases.Keys) {
    $lines = @(Read-TextAuto (Write-Enc ('t' + [guid]::NewGuid().ToString('N') + '.txt') $cases[$k]) | Where-Object { $_ -and $_.Trim() })
    $ok = ($lines.Count -eq 2) -and ($lines[0] -match '^Incoming\s+2026-08-26, 03:02\s+User\s+365429176$') -and ($lines -join '' -notmatch '[\x00\uFFFD]')
    Check "L1 : $k reads as clean text" $ok (($lines -join ' / ').Substring(0, [Math]::Min(80, ($lines -join ' / ').Length)))
}
Check 'L1 : an empty file gives no lines' (@(Read-TextAuto (Write-Enc 'empty.txt' ([byte[]]@()))).Count -eq 0)

Write-Host "`nL2  Hide-UrlSecret"
$nul = [string][char]0
$u = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r&sv=2018-11-09&se=2026-10-17T11%3A13%3A55Z&skoid=abc&sig=SECRETSIG%3D&jwt=eyJ0eXAi.SECRETJWT.x&response-content-type=application%2Foctet-stream' + $nul
$r = Hide-UrlSecret $u
Check 'L2 : sig value removed' ($r -notmatch 'SECRETSIG')
Check 'L2 : jwt value removed' ($r -notmatch 'SECRETJWT')
Check 'L2 : the markers are present' (($r -match 'sig=\[redacted\]') -and ($r -match 'jwt=\[redacted\]'))
Check 'L2 : host, path and other parameters are kept' (($r -match 'release-assets\.githubusercontent\.com/github-production-release-asset/1/2') -and ($r -match 'sp=r') -and ($r -match 'se=2026-10-17'))
Check 'L2 : trailing NUL is cut' ($r -notmatch '[\x00-\x1F]')
Check 'L2 : a URL without a query is unchanged' ((Hide-UrlSecret 'https://example.com/a/b.exe') -eq 'https://example.com/a/b.exe')
Check 'L2 : a name that only contains "key" is not touched' ((Hide-UrlSecret 'https://e.com/?monkey=1&token=abc') -eq 'https://e.com/?monkey=1&token=[redacted]')
Check 'L2 : empty and null pass through' (([string](Hide-UrlSecret '')) -eq '' -and ([string](Hide-UrlSecret $null)) -eq '')

Write-Host "`nL3  Remove-ExeToken"
Check 'L3 : bare quoted powershell has no arguments' ((Remove-ExeToken '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" ') -eq '')
Check 'L3 : arguments are kept (quoted exe)' ((Remove-ExeToken '"C:\Program Files\PowerShell\7\pwsh.exe" -File x.ps1') -eq '-File x.ps1')
Check 'L3 : arguments are kept (bare exe)' ((Remove-ExeToken 'cmd.exe /c powershell -nop') -eq '/c powershell -nop')
Check 'L3 : "powershell" inside the arguments still matches' ((Remove-ExeToken 'C:\Windows\system32\cmd.exe /c powershell -nop') -imatch 'powershell')

Write-Host "`nL4  Test-WritableByUsers"
$sys = Join-Path $env:SystemRoot 'System32\cmd.exe'
Check 'L4 : cmd.exe in System32 is not writable by standard users' ((Test-WritableByUsers $sys) -eq $false)
Check 'L4 : a path that does not exist is unknown, not safe' ($null -eq (Test-WritableByUsers (Join-Path $work 'nope\none.exe')))
$open = Join-Path $work 'open'; New-Item -ItemType Directory -Path $open -Force | Out-Null
$f = Join-Path $open 'a.exe'; Set-Content -LiteralPath $f -Value 'x'
try {
    $acl = Get-Acl -LiteralPath $open
    $rule = New-Object Security.AccessControl.FileSystemAccessRule('Users', 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule); Set-Acl -LiteralPath $open -AclObject $acl
    Check 'L4 : a folder that grants Users Modify is detected' ((Test-WritableByUsers $f) -eq $true)
} catch { Write-Host ('  SKIP  L4 : could not change an ACL here (' + $_.Exception.Message + ')') -ForegroundColor Yellow }

Write-Host "`nL5  Test-WmiDefaultBinding"
function New-Bind { param([string]$CClass, [string]$CName, [string]$FName, [string]$Query)
    [pscustomobject]@{
        Consumer = [pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = $CClass }; Name = $CName }
        Filter   = [pscustomobject]@{ Name = $FName; Query = $Query }
    }
}
$stockQ = 'select * from MSFT_SCMEventLogEvent'
Check 'L5 : the stock SCM binding is recognised' (Test-WmiDefaultBinding (New-Bind 'NTEventLogEventConsumer' 'SCM Event Log Consumer' 'SCM Event Log Filter' $stockQ) @())
Check 'L5 : the query is also found through the filter list' (Test-WmiDefaultBinding (New-Bind 'NTEventLogEventConsumer' 'SCM Event Log Consumer' 'SCM Event Log Filter' '') @([pscustomobject]@{ Name = 'SCM Event Log Filter'; Query = $stockQ }))
Check 'L5 : same names, a command-line consumer is NOT stock' (-not (Test-WmiDefaultBinding (New-Bind 'CommandLineEventConsumer' 'SCM Event Log Consumer' 'SCM Event Log Filter' $stockQ) @()))
Check 'L5 : same names, a different query is NOT stock' (-not (Test-WmiDefaultBinding (New-Bind 'NTEventLogEventConsumer' 'SCM Event Log Consumer' 'SCM Event Log Filter' 'select * from __InstanceCreationEvent') @()))
Check 'L5 : a different consumer name is NOT stock' (-not (Test-WmiDefaultBinding (New-Bind 'NTEventLogEventConsumer' 'Updater' 'SCM Event Log Filter' $stockQ) @()))
Check 'L5 : a different filter name is NOT stock' (-not (Test-WmiDefaultBinding (New-Bind 'NTEventLogEventConsumer' 'SCM Event Log Consumer' 'X' $stockQ) @()))
Check 'L5 : no query anywhere is NOT stock (unknown stays a lead)' (-not (Test-WmiDefaultBinding (New-Bind 'NTEventLogEventConsumer' 'SCM Event Log Consumer' 'SCM Event Log Filter' '') @()))
Check 'L5 : null input is NOT stock' (-not (Test-WmiDefaultBinding $null @()))
$live = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
if ($live.Count -gt 0) {
    $lf = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
    $scm = @($live | Where-Object { [string]$_.Filter.Name -eq 'SCM Event Log Filter' })
    if ($scm.Count -gt 0) { Check 'L5 : the real SCM binding on this machine is recognised' (Test-WmiDefaultBinding $scm[0] $lf) }
} else { Write-Host '  SKIP  L5 : no WMI binding on this machine to read' -ForegroundColor Yellow }

Write-Host "`nL6  Get-FilesByExtension"
$tree = Join-Path $work 'tree'; New-Item -ItemType Directory -Path (Join-Path $tree 'a\b') -Force | Out-Null
foreach ($n in 'x.ps1', 'a\y.PS1', 'a\b\z.js', 'a\b\w.exe', 'a\skip.txt', 'a\ps1.bak', 'a\b\k.js1', 'a\b\m.ps1x') { Set-Content -LiteralPath (Join-Path $tree $n) -Value 'x' }
$old = Join-Path $tree 'a\old.ps1'; Set-Content -LiteralPath $old -Value 'x'; (Get-Item -LiteralPath $old).LastWriteTime = (Get-Date).AddDays(-90)
$got = @(Get-FilesByExtension -Path $tree -Extension '.ps1', '.js' | ForEach-Object { $_.Name } | Sort-Object)
$ref = @(Get-ChildItem -Path $tree -Recurse -Include *.ps1, *.js -File | ForEach-Object { $_.Name } | Sort-Object)
Check 'L6 : same files as -Include (case-insensitive, no extension-prefix matches)' (($got -join ',') -eq ($ref -join ',')) (($got -join ',') + ' | ' + ($ref -join ','))
Check 'L6 : .js1 and .ps1x are not matched' (-not ($got -contains 'k.js1' -or $got -contains 'm.ps1x'))
$recent = @(Get-FilesByExtension -Path $tree -Extension '.ps1' -Since (Get-Date).AddDays(-30) | ForEach-Object { $_.Name })
Check 'L6 : the date cutoff drops the old file' (-not ($recent -contains 'old.ps1') -and ($recent -contains 'x.ps1'))
Check 'L6 : a missing folder gives nothing and no error' (@(Get-FilesByExtension -Path (Join-Path $work 'nope') -Extension '.ps1').Count -eq 0)

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ("RESULT  passed: {0}  failed: {1}" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
