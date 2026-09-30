# Static review — the 18 Windows-only modules of `Tatar.ps1`

**Date:** 2026-09-30 · **Tool version reviewed:** see `$script:ToolVersion` in `Tatar.ps1`
**Companion document:** [`WINDOWS_TEST_PLAN.md`](WINDOWS_TEST_PLAN.md), which says how to
verify these modules on Windows. This one says what reading them found.

## Why this file exists

`tests/WINDOWS_TEST_PLAN.md` lists 18 modules that need Windows APIs and therefore
never execute here: `sysinfo`, `network`, `process`, `sessions`, `services`, `users`,
`persistence`, `shares`, `firewall`, `drivers`, `privesc`, `lateral`, `fsartifacts`,
`shadow`, `mft`, `indicators`, `hashes`, `timeline`. A green suite on Linux says
nothing about them, so they were reviewed by reading instead.

PowerShell 7.6.6 is installed, so the file can be parsed, linted and reasoned about.
It cannot be *run*: `Get-CimInstance`, `Get-WinEvent`, the registry providers,
`fsutil`, `vssadmin`, `net`, `cmd` and `quser` are all absent.

### What was actually executed for this review

| Check | First pass | Second pass |
|---|---|---|
| AST parse (`[Parser]::ParseFile`) | 0 errors | 0 errors |
| PSScriptAnalyzer, repo settings | 0 errors, 11 warnings — all `PSAvoidUsingEmptyCatchBlock` | 0 errors, 11 warnings — the same 11 |
| `bash tests/run-tests.sh` | 42 passed / 0 failed | 42 passed / 0 failed |
| `pwsh -NoProfile -File tests/Invoke-Tests.ps1` | 98 passed / 0 failed | 98 passed / 0 failed |
| `pwsh -File tests/Test-ServicePath.ps1` | 14 passed / 0 failed | 16 passed / 0 failed |
| `pwsh -File tests/Test-StaticReviewFixes.ps1` (new) | — | 15 passed / 0 failed |
| `python3 .github/scripts/check_docs_parity.py` | — | OK |
| `python3 .github/scripts/check_readme_parity.py` | — | OK |
| `pwsh -File ./Tatar.ps1 -All` on Linux | 11 modules OK, 19 error — the same set as before the fixes | not re-run |

**Nothing in the 18 modules was executed, in either pass.** Every fix below is written
blind and needs the Windows confirmation named in its row.

### The second pass

The first pass fixed 16 findings and left 12 with a named next step. The second pass
went back through those 12 and closed the part of each one that does not need a Windows
host. **Six** are now fully fixed, **three** are partly fixed with the remainder stated,
and **three** are left open because closing them is a product decision, not a repair.
Each row below says which, and the per-module sections say what changed.

The rule applied: a logic error, an absent-vs-zero counter, a discarded exception, a
saturating counter or a missing list entry is a defect and was fixed. Deciding whether
`WINDOWS_TEST_PLAN.md` or the code is the intended contract, and whether the collector
may mount other users' `NTUSER.DAT` on a live host, is not the reviewer's call.

### The 11 empty `catch` blocks are intentional

PSScriptAnalyzer reports 11. Each one sits where a *single* artifact may be locked,
access-denied or absent on a live host, and where aborting would cost the operator the
rest of the collection — `Get-FileHash` on a locked binary, `fsutil usn queryjournal`
without admin, a per-user hive that is not loaded. That is the correct shape for a
best-effort collector and none were changed. They are counted, not fixed.

Two catches are *not* of that kind and are recorded as findings below: **N-2** (the
network fallback) and **SE-2** (the event-log message). Neither is an empty catch —
both have a body that reports the wrong thing.

### Severity

| | |
|---|---|
| **High** | wrong or missing evidence in an ordinary run, or a false High finding on a clean host |
| **Medium** | wrong evidence in a non-default but supported configuration, or analyst-visible noise |
| **Low** | cosmetic, or a documentation/implementation mismatch |

### One thing that is already right

There is **no `Get-WmiObject`, no `Win32_Product` and no `wmic`** anywhere in the file.
Every WMI query already goes through `Get-CimInstance`, and installed applications are
read from the `Uninstall` registry keys rather than `Win32_Product` — which would
trigger an MSI reconfiguration of every installed package on the machine under
investigation. The single occurrence of the string `wmic` is a *detection* pattern in
`Collect-Process`'s LOLBAS list, which is correct use. The deprecated-API axis of this
review found nothing to fix.

---

## Summary of findings

| # | Module | Finding | Severity | Fixed here |
|---|---|---|---|---|
| H-1 | `hashes` | unquoted service paths keep their arguments, so most service binaries are never hashed | **High** | yes |
| P-1 | `privesc` | `AlwaysInstallElevated` raises High when only one hive is set | **High** | yes |
| PE-1 | `persistence` | Winlogon `Userinit` default pinned to `C:\`, raising a false High off-C: | **High** | yes |
| TL-1 | `timeline` | `InstallDate` mixed into a `DateTime` column, silently destroying the sort order | **High** | yes |
| PV-1 | `privesc` | unquoted-path test looks at the whole command line, not the image path | Medium | yes |
| PV-2 | `privesc` | `^"` anchor misreads an ImagePath that begins with whitespace | Medium | yes |
| PV-3 | `privesc` | user-writable test matches a path named in an *argument* | Medium | yes |
| PV-4 | `privesc` | system-binary exclusion hardcodes `C:\Windows` | Medium | yes |
| U-1 | `users` | `Administrators` looked up by name — fails on every localised Windows | Medium | yes |
| I-1 | `indicators` | `%TEMP%` and `%LOCALAPPDATA%\Temp` counted twice | Medium | yes |
| H-2 | `hashes` | case-sensitive `HashSet` duplicates the same binary | Low | yes |
| N-1 | `network` | hosts file path hardcodes `C:\Windows` | Medium | yes |
| L-1 | `lateral` | PsExec path hardcodes `C:\Windows` | Medium | yes |
| F-1 | `fsartifacts` | Amcache and USN journal hardcode `C:` | Medium | yes |
| M-1 | `mft` | `fsutil` hardcodes `C:` | Medium | yes |
| TL-2 | `timeline` | Prefetch hardcodes `C:\Windows` | Medium | yes |
| N-2 | `network` | `netstat` fallback discards the reason and leaves two counters unset | Medium | **partly** (2nd pass) |
| SE-1 | `sessions` | `RecentFailedLogons` is capped at 15 and absent when the query fails | Medium | **partly** (2nd pass) |
| SE-2 | `sessions` | "no matching events" reported as "not available / access denied" | Medium | yes (2nd pass) |
| PE-2 | `persistence` | only the collecting user's `HKCU`; no `HKU\*` sweep | Medium | **partly** (2nd pass) |
| PE-3 | `persistence` | `HKCU` `RunOnce` and `Wow6432Node\RunOnce` not collected | Medium | yes (2nd pass) |
| PE-4 | `persistence` | scheduled tasks collected without their actions | Medium | yes (2nd pass) |
| D-1 | `drivers` | plan promises unsigned drivers flagged; no signature check exists | Medium | **no — open** |
| SH-1 | `shadow` | `vssadmin` text only, which is localised and unparseable | Medium | yes (2nd pass) |
| SS-1 | `shares` | plan promises share permissions; only name/path/description collected | Low | **no — open** |
| SI-1 | `sysinfo` | plan promises `systeminfo` and env; neither is collected | Low | **no — open** |
| FW-1 | `firewall` | no `netsh` fallback if the `NetSecurity` module is absent | Low | yes (2nd pass) |
| U-2 | `users` | `Accounts` stat absent when `Get-LocalUser` returns nothing | Low | yes (2nd pass) |

**22 fixed, 3 partly fixed, 3 open.** *Partly* always means the same thing here: the
mechanical half is in and the remaining half is named in the module's section — it is
never a euphemism for "mostly done". Nothing was found in `process` or `services` — see
those sections, which say so plainly.

The three open findings are open for one reason between them: **`WINDOWS_TEST_PLAN.md`
promises collection the code does not do, and nobody has said which document is the
contract.** D-1 (unsigned drivers), SS-1 (share ACLs) and SI-1 (`systeminfo` + env) are
the same question three times. Answering it is a product decision and is left to the
maintainer; the alternative — writing the collection to match the plan — silently makes
the plan authoritative and adds three unexercised code paths to a triage tool at once.

---

# Per-module review

## 1. `sysinfo` — `Collect-SysInfo`

**Collects.** `hostname`, `whoami /all`, `Win32_OperatingSystem` (caption, version,
build, architecture, boot/install time), `Win32_ComputerSystem` (make, model, RAM,
domain), the time zone, and `Get-HotFix`.

**Checked.** Deprecated classes; handle/dispose; null handling on the CIM results;
hardcoded paths; whether the artifacts match what `WINDOWS_TEST_PLAN.md` promises.

**Found.**

- **SI-1 (Low, documentation — STILL OPEN, product decision).** The plan's section F
  expects "OS build, hotfixes, **env**, **`systeminfo` output**". Neither the
  environment block nor `systeminfo` is collected. A tester following the plan will
  mark this module failed against code that is behaving as written.

  Still open after the second pass, and for the reason given under SS-1, not for lack
  of a Windows host: `Get-ChildItem Env:` would run anywhere. The open question is
  which document is the contract. There is a second reason to leave it to the owner
  here — a full environment block routinely carries credentials and tokens that
  processes were started with, so dumping it into `TATAR_Report_*.txt` changes what
  the output is safe to hand to a third party. That belongs in `SECURITY.md` and in
  someone's deliberate decision, not in a review's tidy-up.
- *(observation, not a defect)* The six calls run in sequence inside one `try`. If
  `Get-TimeZone` throws, `Get-HotFix` never runs. In practice `Get-TimeZone` does not
  throw on a supported Windows, so this is noted, not fixed.

`Get-HotFix` wraps `Win32_QuickFixEngineering`, which is present on Server Core.
No disposal problem: `Get-CimInstance` without `-CimSession` uses the shared session.

**Nothing else found.**

## 2. `network` — `Collect-Network`

**Collects.** TCP connections with owning PID and process name, listening/established
counters, ARP, routes, DNS cache, `ipconfig /all`, the hosts file, and a finding for
custom hosts entries.

**Found.**

- **N-1 (Medium, fixed).** `$hostsFile = 'C:\Windows\System32\drivers\etc\hosts'`. On a
  host whose `%SystemRoot%` is not `C:\Windows` the file is not read, `hosts.txt` is
  written empty, and the custom-entry check — one of the cheapest high-signal checks the
  tool has — silently passes. Now `Join-Path $script:SysRoot 'System32\drivers\etc\hosts'`.
- **N-2 (Medium, PARTLY fixed on the second pass).** The fallback is
  `catch { cmd /c "netstat -ano" | Out-File ... }`. Two problems, neither an empty catch:
  1. The exception is discarded. The operator sees `netstat` output and no statement
     that `Get-NetTCPConnection` failed or why — and the two shapes (not elevated
     enough vs. the module genuinely unavailable) mean different things for the
     evidence.
  2. `ListeningTcpPorts` and `EstablishedConnections` are set **inside** the `try`,
     after the loop. On the fallback path they are never set at all, so `summary.json`
     loses two counters that the README documents as the cross-platform pair, and a
     dashboard reads "no listening ports" rather than "not measured".

  **Second pass — (1) is fixed, (2) is not.** The catch now `Add-Note`s the exception
  message before falling back, so the report and `tatar.log` both say that
  `Get-NetTCPConnection` failed and why; that needed no Windows host, it only needed
  the variable not to be thrown away.

  (2) is deliberately still absent rather than zeroed. Writing `0` would have closed
  the row and been **wrong** — a dashboard would then read "no listening ports" off a
  host where the ports were never counted, which is the exact failure the finding
  objects to. What went in instead is a second `Add-Note` stating that the two
  counters were not measured, so the gap is visible in the evidence rather than only
  as a missing JSON key. Parsing the real numbers back out of `netstat -ano` is still
  the repair, and it still needs a non-English Windows first: `netstat` localises its
  state column, so `LISTENING` is not a literal to match on.

*(`cmd /c` is redundant — `netstat.exe` is directly invocable — but it is harmless and
was left alone.)*

## 3. `process` — `Collect-Process`

**Collects.** `Win32_Process` with PID/PPID/name/command line/path/creation time, a
LOLBAS command-line pattern sweep, a parent→child process tree, and a suspicious-lineage
check (Office or script host spawning a shell).

**Checked.** Recursion termination in `Write-ProcTree`; `.Count` on possibly-scalar
results; `Substring` on a short string; `-replace`/`ToLower` on a null `Name`;
hardcoded paths; deprecated classes.

**Nothing found.** Specifically, each of these is already correct:

- `Write-ProcTree` terminates: `$depth -lt 12` bounds it, and the
  `[int]$ch.ProcessId -ne [int]$proc.ProcessId` guard stops the PID-0/PID-4 self-parent
  loop that would otherwise recurse immediately.
- `$cl.Substring(0,200)` is guarded by `$cl.Length -gt 200`.
- `@($procs).Count` and `@($script:pcChild[...])` are array-wrapped, so a single-process
  result and a missing key both behave.
- `-replace '\.exe$'` is case-insensitive in PowerShell, so `.EXE` is handled before the
  `.ToLower()` comparison.
- `Get-CimInstance Win32_Process` is the non-deprecated form and needs no disposal.

*(`$script:pcChild[$xpid] += $xp` rebuilds an array per child, which is O(n²) in process
count. On a 400-process host that is not measurable, and changing it is a refactor, not
a fix.)*

## 4. `sessions` — `Collect-Sessions`

**Collects.** `quser`, `net session`, and the last 15 Security events 4624 and 4625,
plus a finding when 4625 hits the 15-event cap.

**Found.**

- **SE-1 (Medium, PARTLY fixed on the second pass).** `RecentFailedLogons` is
  `@($evts).Count` where `$evts` came from `-MaxEvents 15`. The counter therefore
  saturates at 15 and cannot express "4,000 failed logons", which is exactly the case
  an analyst is looking for. It is also never set when the query throws, so the key is
  *absent* from `summary.json` rather than `0` — indistinguishable from "no failures"
  for anything consuming the JSON.

  **Second pass.** The absent-vs-zero half is fixed, using SE-2's classification: a
  query that ran and matched nothing is a genuine zero and now sets the counter to
  `0`, while a query that actually *failed* leaves the key absent **and** writes a
  note saying it was not measured. Those are two different facts and the summary no
  longer collapses them into one missing key.

  The saturation half is not fixed, because an honest count needs a second, count-only
  `Get-WinEvent` query whose cost on a multi-gigabyte Security log has to be measured
  on Windows before it goes into a triage tool. What did change is that the cap stopped
  being invisible: `15` was written three times (`-MaxEvents`, the report heading and
  the `-ge 15` test) and is now one `$evtCap`, and hitting it writes a note that says
  the true 4625 count is that value *or higher*. The number in `summary.json` is still
  capped — a consumer must not treat it as a total — but nothing in the evidence now
  implies otherwise.
- **SE-2 (Medium, FIXED on the second pass).** The inner catch reported
  `"(event $id not available / access denied)"` for *every* failure. `Get-WinEvent
  -ErrorAction Stop` also throws when the log simply contains no matching events, which
  is a clean result. The operator was told they had an access problem when they did
  not — and the natural response to that message is to re-run the whole collection
  elevated, on a host where nothing was wrong.

  Split into two branches by a new pure helper, `Test-NoMatchingEvents`, which reads
  `$_.FullyQualifiedErrorId` for `NoMatchingEventsFound` and falls back to the
  exception text. **The error id is still unconfirmed** — there is no `Get-WinEvent`
  here to throw one — so the fix is built not to depend on the guess: the message test
  behind it catches a host whose id differs, and the other branch now prints the real
  exception message instead of inventing a cause. If the id is wrong the operator gets
  the truth; previously they got a fabrication either way.

  `Test-NoMatchingEvents` takes only an `ErrorRecord`, so unlike the module around it
  it is testable here. `tests/Test-StaticReviewFixes.ps1` drives it from
  `tests/fixtures/winevent-error-cases.tsv` with both shapes — the empty log, access
  denied, a different `Get-WinEvent` error id, an RPC failure, and a null record — and
  was checked against a copy of the collector with the old always-access-denied
  behaviour restored: **6 of 15 cases fail** there.

*(`quser` is absent on Windows Home editions; the surrounding `2>&1` keeps that from
aborting the module, and the text lands in the report. Left alone.)*

No handle problem: `Get-WinEvent -FilterHashtable` returns materialised records and
opens no reader the script has to dispose.

## 5. `services` — `Collect-Services`

**Collects.** `Win32_Service` — name, display name, state, start mode, logon account,
binary path — and the `RunningServices` counter.

**Checked.** Deprecated class; `.Count` on a scalar; `-ErrorAction` consistency; Server
Core availability.

**Nothing found.** `Win32_Service` is the current class and is present on Server Core.
`@($svcs | Where-Object ...).Count` is array-wrapped and yields `0`, not `1`, when
`$svcs` is null. The missing `-ErrorAction Stop` on the `Get-CimInstance` is harmless
here: the enclosing `try` is the only consumer, and a null `$svcs` degrades to an empty
table rather than an exception.

## 6. `users` — `Collect-Users`

**Collects.** `net user`, `net localgroup administrators`, `Get-LocalUser`, the
`Accounts` counter, a High finding for enabled accounts with no password required, and a
Review finding for non-built-in Administrators members.

**Found.**

- **U-1 (Medium, fixed).** `Get-LocalGroupMember -Group 'Administrators'`. The built-in
  group name is **localised** — *Administradores*, *Administrateurs*, *Администраторы*.
  On any non-English Windows this throws, the catch writes a note, and the check
  produces nothing: the tool reports silence on a host it never actually examined.
  The module already uses SIDs to recognise the RID-500 account three lines later, so
  only the group side was inconsistent. Now
  `Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544')`.
  **Windows confirmation required:** that `Get-LocalGroupMember` exposes the `-SID`
  parameter set on both PowerShell 5.1 and 7 — it is documented, but it was not run.
- **U-2 (Low, FIXED on the second pass).** `if ($lu) { $script:Stats['Accounts'] = ... }`
  left the key absent rather than `0` when `Get-LocalUser` yielded nothing. Same
  absent-vs-zero shape as SE-1 and fixed the same way, but the `users` case was worse
  than the summary row suggested: `-ErrorAction SilentlyContinue` turns a *failed*
  query into `$null` too, so the guard could not tell "this host has no local accounts"
  from "the query never ran". `Get-LocalUser` genuinely fails on a domain controller,
  so that is not hypothetical. Now `-ErrorAction Stop` inside its own `try`: a result
  that came back sets the counter, `0` included; a failure leaves it absent and writes
  a note saying `Accounts` was not measured. The two states are now distinguishable in
  `summary.json`, which is the whole point of the finding.

*(`net localgroup administrators` on the line above is localised too. It is a raw text
dump whose failure is visible in the report, and it drives no finding, so it was left
alone — but a reader of `TATAR_Report_*.txt` from a localised host should expect that
line to be an error message.)*

`Win32_UserAccount -Filter "LocalAccount=True"` is correctly filtered; without the
filter it would enumerate the domain.

## 7. `persistence` — `Collect-Persistence`

**Collects.** `Win32_StartupCommand`, four Run keys, non-Microsoft scheduled tasks, and
the IFEO / AppInit_DLLs / AppCertDlls / Winlogon / LSA / Print-monitor ASEPs.

**Found.**

- **PE-1 (High, fixed).** The Winlogon `Userinit` default was matched against
  `'(?i)^C:\\Windows\\system32\\userinit\.exe,?\s*$'`. On a host installed to another
  drive the *untouched* default value `D:\Windows\system32\userinit.exe,` does not match,
  and the module raises **High: "Winlogon Userinit is non-default"** on a clean machine.
  A false High in the Winlogon path is expensive — it is a credible ransomware-precursor
  signature and will start an escalation. The expected value is now built from
  `$script:SysRoot` via `[regex]::Escape`.
- **PE-2 (Medium, PARTLY fixed on the second pass — the rest is a PRODUCT DECISION).**
  Only `HKCU:` — the hive of whoever is running the collector — is read. Run under
  SYSTEM or as a responder's admin account, per-user persistence for the *compromised*
  user is invisible. The fix is an `HKU\*` sweep with the unloaded profiles mounted.

  **That sweep was not written, and should not be written by a reviewer.** Mounting
  another user's `NTUSER.DAT` on a live host writes to the hive, changes its
  timestamps, and can collide with a profile the OS is already loading — it is a
  deliberate trade of evidence integrity for coverage, and whoever owns this tool makes
  that call, not whoever happens to be reading the code. It also needs a Windows host
  to write at all.

  What *was* fixed is the part that misleads today: the report's HKCU block now names
  the collecting user and states outright that other users' `Run`/`RunOnce` keys were
  not collected. Before, an empty section read as "no per-user persistence" when it
  meant "one hive was looked at, possibly the wrong one". A stated limit is not the
  sweep, but it stops the evidence from overclaiming while the decision is pending.
- **PE-3 (Medium, FIXED on the second pass).** `$runKeys` covered HKCU Run, HKLM Run,
  HKLM RunOnce and HKLM `Wow6432Node` Run. It omitted **HKCU `RunOnce`** and **HKLM
  `Wow6432Node\RunOnce`**, both standard persistence locations — so two ASEPs produced
  no line in the report, and a blank report reads as "nothing there", not as "never
  looked". Both are now in the list, which is iterated under the existing
  `Test-PathSafe` guard, so a hive that does not exist is skipped exactly as before.

  Guarded by `tests/Test-StaticReviewFixes.ps1`, which reads the literal out of the
  collector source and asserts all six keys. Quoted-and-exact, so `Run` cannot be
  satisfied by the `RunOnce` entry that contains it as a prefix; against the pre-fix
  list, the two missing keys fail.
- **PE-4 (Medium, FIXED on the second pass).** Scheduled tasks were collected as
  `TaskName`, `TaskPath`, `State` only. Without the actions, a task named innocuously
  cannot be triaged from the report at all — the analyst has to go back to the host,
  which on someone else's network may mean going back the next day. An `Action` column
  is now projected from `$_.Actions`: `Execute` plus `Arguments` for an exec action,
  the `ClassId` for a ComHandler, and a literal `(non-exec action)` for the deprecated
  mail/message types, which have neither and would otherwise come out blank. Several
  actions on one task are joined with ` ; `. `Out-String -Width 4096` matches what the
  rest of the file already does for wide tables.

  **Windows confirmation required:** the output volume. This is the one second-pass fix
  whose risk is not correctness but size — a host with many non-Microsoft tasks carrying
  long command lines will grow this section, and nobody has seen it yet.
- *(Low, not fixed)* `$acn` filters AppCertDlls value names with `-notmatch '^PS'`,
  which is case-insensitive, so a real registry value named e.g. `psmon` would be
  filtered out with the `PSPath`/`PSDrive` noise. Vanishingly unlikely; recorded only.

`Win32_StartupCommand` is the current class. The 32-bit registry view is covered for
Run and the `Windows` (AppInit) key.

## 8. `shares` — `Collect-Shares`

**Collects.** `Get-SmbShare` (name, path, description) and `net share`.

**Found.**

- **SS-1 (Low, documentation — STILL OPEN, product decision).** The plan's section F
  expects "SMB shares **and permissions**". No ACL is collected; `Get-SmbShareAccess`
  is not called. Same document-vs-code mismatch as SI-1 and D-1.

  Deliberately not closed on the second pass. `Get-SmbShare | Get-SmbShareAccess` is
  one line and would have made the row go green, but it answers the wrong question:
  the open item is *which document is the contract*, and quietly adding the collection
  decides that in favour of the plan without anyone saying so. Either the plan is
  authoritative — in which case D-1, SS-1 and SI-1 are one piece of work, sized and
  exercised together on Windows — or the code is, and the plan's section F is the thing
  that needs the edit. **Owner's call.**

**Nothing else found.** `Get-SmbShare` failing on an old host degrades to `net share`,
which is present everywhere — the fallback is already correct.

## 9. `firewall` — `Collect-Firewall`

**Collects.** Profile state (`Get-NetFirewallProfile`) and all enabled rules to
`firewall_rules.txt`.

**Found.**

- **FW-1 (Low, FIXED on the second pass).** `Get-NetFirewallProfile` was called with no
  `-ErrorAction`, unlike `Get-NetFirewallRule` on the next line. If the `NetSecurity`
  module was unavailable the whole module aborted into `Add-Err` and **neither** the
  profiles nor the rules were collected, where `netsh advfirewall show allprofiles`
  would still have worked. On every currently-supported Windows `NetSecurity` is
  present, so this is a robustness gap, not a live defect.

  Both queries now sit in an inner `try` with a `netsh` fallback for each — profiles to
  the report, `firewall firewall show rule name=all` to `firewall_rules.txt`, the same
  file the cmdlet path writes. Note that adding `-ErrorAction` alone would have fixed
  nothing here: a missing module raises `CommandNotFoundException`, which is not a
  cmdlet error and which `-ErrorAction` does not suppress. `netsh` text is **localised**
  and that is why it is the fallback rather than the source — but localised text an
  analyst can read beats an empty section, which is the choice this module actually
  faces.

  **Windows confirmation required:** that `netsh advfirewall` still exists and accepts
  these arguments on the target build. It is deprecated in favour of `NetSecurity` and
  has been for years, which is the reverse of the situation this fallback assumes.

*(`Where-Object Enabled -eq 'True'` compares the `Enabled` enum against a string; that
coercion is valid and was verified as intentional, not a bug.)*

## 10. `drivers` — `Collect-Drivers`

**Collects.** Running `Win32_SystemDriver` entries — name, display name, binary path.

**Found.**

- **D-1 (Medium, STILL OPEN — needs a Windows host *and* a decision).** The plan's
  section F expects "driver list, **unsigned drivers flagged**". There is no signature
  check anywhere in the module and no finding is ever raised. Unsigned or revoked
  drivers are the point of collecting drivers at all (BYOVD), so this is the largest
  single capability gap found in the review. The fix is `Get-AuthenticodeSignature`
  over the resolved driver paths, which needs a Windows host both to write and to
  cost — it is hundreds of files per run.

  Nothing mechanical was available to fix here on the second pass. It is not one
  change but three, and each needs Windows: `Win32_SystemDriver.PathName` arrives in
  kernel forms (`\??\C:\...`, `\SystemRoot\...`) that have to be normalised before any
  file is opened; `Get-AuthenticodeSignature` has to be run to know what it costs over
  a few hundred drivers on a host already under investigation; and a new **High**
  finding has to be defined, which means a new `Get-Technique` branch and a new row in
  `docs/MITRE_ATTACK.md` that `check_docs_parity.py` will then hold everyone to.
  Writing any of that blind would put an unexercised High-severity finding into a
  triage tool — the one class of change this review exists to prevent.

**Nothing else found.** `Win32_SystemDriver` is current and present on Server Core.

## 11. `privesc` — `Collect-PrivEsc`

**Collects.** `whoami /priv`, unquoted service paths, service binaries in user-writable
locations, and `AlwaysInstallElevated`.

This module had the densest defects. All four are fixed.

- **P-1 (High, fixed).** `AlwaysInstallElevated` raised **High** when *either* HKLM or
  HKCU was `1`. The escalation requires **both**: the installer elevates only when the
  machine policy and the user policy agree. A half-configured policy grants nothing, and
  the finding said "is ENABLED", which is simply untrue. Now High only when both are 1,
  and a Review finding — with both values in the message — when exactly one is. The
  message keeps the literal `AlwaysInstallElevated` in both branches so
  `Get-Technique` still maps it to T1548.002 and `check_docs_parity.py` stays green
  (confirmed: it does). The Detail also now records that HKCU is read for the account
  running the collector, which is a real limitation of the check.
- **PV-1 (Medium, fixed).** The unquoted test was
  `$_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -match '\.exe'`.
  It tests the whole **command line**, so `C:\Apps\svc.exe -config "C:\Program Files\x.exe"`
  was reported as an unquoted service path although its image path contains no space and
  it is not vulnerable. Now the space is tested on the extracted image path.
- **PV-2 (Medium, fixed).** `-notmatch '^"'` anchors at position 0. A service ImagePath
  may legally begin with whitespace before its opening quote, and `  "C:\Windows\system32\alg.exe"`
  was therefore read as unquoted. Now `-notmatch '^\s*"'`. *(Both PV-1 and PV-2 are
  covered by named cases in `tests/fixtures/service-path-cases.tsv`.)*
- **PV-3 (Medium, fixed).** The user-writable test matched `\users\` etc. anywhere in the
  command line, so a service whose *argument* names a log file under `C:\Users\...`
  was reported as having a user-writable binary. Now the image path is tested. The
  report still shows the full `PathName`, which is the useful context.
- **PV-4 (Medium, fixed).** `-notmatch '(?i)^C:\\Windows'` excluded system binaries by a
  hardcoded drive. Off C:, the exclusion stops working and **every** OS service becomes
  a candidate finding. Now `$script:SysRoot`.

*(`users\\` in the PV-3 pattern has no leading separator, so `C:\BusinessUsers\app.exe`
matches. Left alone: tightening it changes what the check detects, and the finding is a
Review lead by design.)*

## 12. `lateral` — `Collect-Lateral`

**Collects.** `net use`, SMB mappings and sessions, PsExec traces, WMI
`root\subscription` persistence, and WinRM state.

**Found.**

- **L-1 (Medium, fixed).** `Test-PathSafe 'C:\Windows\PSEXESVC.exe'` — hardcoded. Off C:
  the check silently never fires, and PsExec traces are exactly what this module exists
  for. The path, the report line and the finding message are now all built from
  `$script:SysRoot`, so the finding names the file that was actually checked (which also
  keeps it reachable by `Get-PathCandidate`, and therefore by the allowlist).

**Nothing else found.** The `root\subscription` queries use `Get-CimInstance -Namespace`
correctly, and raising a finding only for `*Consumer*` classes — not for a bare
`__EventFilter` — is the right call: a filter alone executes nothing.

## 13. `fsartifacts` — `Collect-FsArtifacts`

**Collects.** `Recent` (which includes JumpLists via `-Recurse`), Amcache, the USN
journal header, volumes and disks.

**Found.**

- **F-1 (Medium, fixed).** Two hardcoded paths:
  `'C:\Windows\AppCompat\Programs\Amcache.hve'` → `Join-Path $script:SysRoot 'AppCompat\Programs\Amcache.hve'`,
  and `fsutil usn queryjournal C:` → `fsutil usn queryjournal $script:SysDrive`.
- *(noted, not a defect)* The `Recent` copy is `$env:APPDATA` — the collecting user only.
  Same class as PE-2 and recorded with it.

The `try { fsutil ... } catch {}` here is one of the 11 intentional empty catches:
`fsutil usn queryjournal` fails without admin, which is expected, and `2>$null` already
routes the text away.

## 14. `shadow` — `Collect-ShadowCopies`

**Collects.** `vssadmin list shadows`, appended to the report. One line.

**Found.**

- **SH-1 (Medium, FIXED on the second pass).** The module captured **localised console
  text and nothing else**. On a Mongolian, Russian or Japanese Windows the output is in
  that language, so no downstream tooling can read it, and the collector kept no
  structured record of which shadow copies existed — which matters, because shadow
  copies are often where the only clean copy of a tampered file lives. `Get-CimInstance
  Win32_ShadowCopy` returns `ID`, `InstallDate`, `VolumeName` and `DeviceObject` as
  structured, locale-independent data.

  Added, in its **own** `try` rather than inside the existing one, so neither source
  can take the other down: `vssadmin` failing still leaves the structured record, and
  a `Win32_ShadowCopy` failure degrades to a note instead of an error. `vssadmin` was
  kept — it reports things the CIM class does not, such as the provider — so this is an
  addition, not a replacement.

  **Windows confirmation required:** the output shape, which nobody has seen. The risk
  is presentational only; the query cannot fail the module.

**Nothing else found.** `vssadmin list shadows` (as opposed to `create`) is available on
client SKUs, so the command choice is right.

## 15. `mft` — `Collect-MFT`

**Collects.** `fsutil fsinfo ntfsinfo` and `fsutil fsinfo statistics`, plus a note that
real `$MFT` parsing is an offline job.

**Found.**

- **M-1 (Medium, fixed).** Both `fsutil` calls were pinned to `C:`, and the output
  filenames (`ntfsinfo_C.txt`) asserted a drive that was never checked. Now
  `$script:SysDrive`, with the filename derived from the drive actually queried, so the
  evidence says which volume it came from.

**Nothing else found.** Declining to parse `$MFT` in place is correct — the note says
so, and writing to the volume under investigation is what a triage tool must not do.

## 16. `indicators` — `Collect-Indicators`

**Collects.** Services with unusual binary paths, and executables written to temp and
appdata locations in the last 14 days, with the `ExecInTempDirs` counter.

**Found.**

- **I-1 (Medium, fixed).** The directory list was
  `@("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")`. For an interactive user
  `%TEMP%` **is** `%LOCALAPPDATA%\Temp` — the same directory, scanned twice. Every
  executable under it was counted twice in `ExecInTempDirs`, which `summary.json`
  publishes, and twice in the finding text. The two paths genuinely differ when running
  as SYSTEM (`C:\Windows\TEMP` vs the systemprofile), so neither can simply be dropped:
  the list is now de-duplicated through a case-insensitive `HashSet` (Windows paths are
  case-insensitive; the default ordinal comparer is not).

**Nothing else found.** `Get-ChildItem -Recurse -Include` is correct *because*
`-Recurse` is present — the well-known `-Include` gotcha only bites without it, and this
was checked rather than assumed. The `$tmpFirst` list correctly caps at 10 while
`$tmpCount` keeps the true total.

## 17. `hashes` — `Collect-Hashes`

**Collects.** SHA-256 of every running-process and service binary, written in
`sha256sum` format to `binary_hashes.txt` for IOC/VirusTotal ingestion.

**Found.**

- **H-1 (High, fixed).** This was the most consequential defect in the review.

  The extraction was `$p = ($_.PathName -replace '^"([^"]+)".*','$1')`, which strips
  *surrounding quotes only*. A service `PathName` is a **command line**, not a path, and
  the normal unquoted-with-arguments form is the majority case on Windows:

  ```
  input : C:\Windows\system32\svchost.exe -k netsvcs
  before: C:\Windows\system32\svchost.exe -k netsvcs   <- Test-Path fails, never hashed
  after : C:\Windows\system32\svchost.exe
  ```

  Every service in that form — `svchost` and most of the OS, plus the attacker-installed
  service that carries arguments — was silently dropped by the `Test-PathSafe` guard.
  The module reported a hash count that looked plausible while omitting the binaries the
  feed exists to cover. Verified against the real pre-fix code, not assumed: see the
  regression run below.

  Fixed by a new helper `Get-ServiceImagePath` (quoted path wins outright; otherwise the
  shortest leading run ending in `.exe` at a word boundary; `$null` when there is no
  `.exe`, which correctly drops driver `.sys` entries). It is the single definition now
  used by `hashes` and by both `privesc` checks, so PV-1, PV-2 and PV-3 are fixed by the
  same change.

- **H-2 (Low, fixed).** `New-Object System.Collections.Generic.HashSet[string]` uses the
  ordinal comparer, so `C:\Windows\System32\svchost.exe` and
  `C:\WINDOWS\system32\SVCHOST.EXE` — the same file, cased differently by
  `Win32_Process` and `Win32_Service` — were hashed twice and emitted as two identical
  lines to the IOC feed. Now constructed with `[StringComparer]::OrdinalIgnoreCase`
  (verified on Linux: 2 entries before, 1 after).

**No handle leak.** `[IO.File]::WriteAllText` closes its own handle, and the `catch {}`
around `Get-FileHash` is one of the intentional 11 — a locked or access-denied binary
must not abort the sweep.

## 18. `timeline` — `Collect-Timeline`

**Collects.** Process creation, Prefetch, Recent `.lnk` and application-install times,
merged and sorted into `timeline.csv`.

**Found.**

- **TL-1 (High, fixed).** The `Uninstall` key's `InstallDate` is a `REG_SZ` in
  `yyyyMMdd` form and was added to the `Time` column **raw**, alongside genuine
  `DateTime` values from CIM and from `LastWriteTime`. `Sort-Object` then compared a
  `String` against a `DateTime`. This does **not** throw — it fails quietly and yields a
  wrongly ordered file. Reproduced here on Linux with three rows:

  ```
  -> 6/1/2025   Prefetch
  -> 20231114   AppInstall   <- a 2023 date, sorted between 2025 and 2024
  -> 1/15/2024  Process
  ```

  A timeline that is not in time order is worse than no timeline: it is wrong in the one
  way the artifact is trusted for, and nothing in the output announces it. `InstallDate`
  is now parsed with `ParseExact('yyyyMMdd', InvariantCulture)`, falling back to an
  invariant `Parse`; a value that matches neither is dropped rather than left in to
  corrupt the ordering of every other row, and the drops are counted into a single
  `Add-Note` so the gap is visible without a line per entry. Dropping also keeps
  `TimelineEntries` consistent with the CSV row count.
- **TL-2 (Medium, fixed).** `'C:\Windows\Prefetch'` hardcoded, twice on one line. Now
  `Join-Path $script:SysRoot 'Prefetch'`.

**Nothing else found.** `Export-Csv -Encoding UTF8` writes a BOM under 5.1 and none
under 7; the manifest hashes whatever is produced, so this is a cosmetic
cross-edition difference, not a defect.

---

# The fixes

## The shared change

```powershell
$script:SysRoot  = if ($env:SystemRoot)  { $env:SystemRoot.TrimEnd('\') }  else { 'C:\Windows' }
$script:SysDrive = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd('\') } else { 'C:' }
```

Windows is not always installed on `C:`. **Nine** hardcoded sites were found across the
18 modules — `network` 1, `persistence` 1, `lateral` 1, `privesc` 1, `fsartifacts` 2,
`mft` 2, `timeline` 1 — and two of them (PE-1, PV-4) are *finding predicates*, which is
why this is not a tidiness fix: off C:, the collector reported High-severity tampering
on an untouched host.

**The literal fallbacks are load-bearing, not defensive padding.** Both variables are
empty on Linux, and `Join-Path` throws on a null `Path` (verified). Without the
fallback the cross-platform suite would break at 98/98.

## New helper and its test

`Get-ServiceImagePath` is a pure string function, so it is testable here even though
every module that calls it is not. `tests/Test-ServicePath.ps1` follows the existing
`Test-IocBoundary.ps1` pattern exactly — it lifts the function out of `Tatar.ps1` by
text rather than dot-sourcing (dot-sourcing would run a collection) and drives it from
`tests/fixtures/service-path-cases.tsv`. Wired into `.github/workflows/ci.yml` next to
the other two unit-test steps.

There is deliberately **no `.sh` counterpart**, unlike the IOC and allowlist tables: a
service ImagePath has no Linux equivalent, so a shared table would assert nothing.

The test was verified to have teeth by running it against a copy of the collector with
the original extraction restored — **5 of 14 cases fail**, including both `svchost`
forms. A test that cannot fail proves nothing, so this was checked rather than assumed.

## The second pass's helper and its test

`Test-NoMatchingEvents` (SE-2) is a pure predicate over an `ErrorRecord`, so like
`Get-ServiceImagePath` it is testable here even though the module that calls it is not.
`tests/Test-StaticReviewFixes.ps1` lifts it out of `Tatar.ps1` by text — dot-sourcing
would run a collection — and drives it from `tests/fixtures/winevent-error-cases.tsv`.
The same file also asserts the PE-3 Run-key list by reading the literal out of the
source, because a list of registry paths has no callable surface to test.

There is deliberately **no `.sh` counterpart**, for the same reason `Test-ServicePath.ps1`
has none: a `Get-WinEvent` error record and an `HKCU` path have no Linux equivalent, so
a shared table would assert nothing.

The test was verified to have teeth by running it against a copy of the collector with
both pre-fix behaviours restored — the always-access-denied classifier and the
four-entry Run-key list. **6 of 15 cases fail**, which is the four empty-log cases and
the two missing registry keys. A test that cannot fail proves nothing, so this was
checked rather than assumed.

## What is NOT fixed, and why

After the second pass, **six** findings are open or partly open:

1. **Needs a Windows host to finish** — N-2 (parse the two counters out of `netstat`;
   its state column is localised), SE-1 (an uncapped 4625 count needs a second query
   whose cost has to be measured), D-1 (driver signatures: path normalisation, runtime
   cost over hundreds of files, and a new High finding, all unexercised).
2. **Needs a product decision** — PE-2 (`HKU\*` sweep: loading other users'
   `NTUSER.DAT` on a live host trades evidence integrity for coverage), and the
   SI-1 / SS-1 / D-1 question of whether `WINDOWS_TEST_PLAN.md` or the code is the
   intended contract. D-1 appears in both groups because it needs both.

Six more were fixed on the second pass — SE-2, PE-3, PE-4, SH-1, FW-1, U-2 — and three
carry a named remainder: N-2, SE-1, PE-2.

None is blocked in the `BLOCKED.md` sense — each has a clear next step, named above.

**Four second-pass fixes still need Windows confirmation** even though they are counted
as fixed, and each says so in its own section: SE-2's error id, PE-4's output volume,
SH-1's output shape, FW-1's `netsh` argument forms. None of the four can produce a wrong
*finding* — the worst case is a cosmetic or presentational surprise — which is why they
went in rather than waiting. Nothing that could raise or suppress a finding was written
blind on this pass.

---

# Two notes for whoever runs the Windows pass

**1. `WINDOWS_TEST_PLAN.md` accounts for 29 of 30 modules.** It lists 11 as executing
without error and 18 as requiring Windows APIs. `deleted` (Recycle Bin) appears in
neither list. It does fail on Linux — `New-Object -ComObject` is unavailable — so the
"Windows APIs required" set is really **19**. `deleted` was outside this review's remit
and was not examined; it should be added to the plan's list and reviewed.

**2. ~~The same hardcoded-drive defect exists outside the 18 modules.~~ Closed.** This
note named two occurrences outside the review's scope — `Collect-Prefetch`'s
`$pf = 'C:\Windows\Prefetch'` and `Collect-Hives`'s `Get-ChildItem 'C:\Users'`. Both
were fixed in `d5010bd` ("stop `Join-Path` resolving drives, and finish the
hardcoded-`C:` sweep") and now read `Join-WinPath $script:SysRoot 'Prefetch'` and
`Join-WinPath $script:SysDrive 'Users'`. Re-checked on the second pass: the only
remaining `'C:` literals in `Tatar.ps1` are the two documented `$script:SysRoot` /
`$script:SysDrive` fallbacks, the `-OutputPath` default, and three comments.

`prefetch` and `hives` are both in the plan's "executed without error on Linux" list,
which is precisely why the defect survived as long as it did: the code path ran, found
nothing, and threw no error.
