# Windows verification plan — `Tatar.ps1`

## Why this file exists

`Tatar.ps1` is a Windows collector. Most of it can now be exercised on any
platform — PowerShell 7 runs the script, and `tests/Invoke-Tests.ps1` passes
**98/98 on Linux** — but a green suite on Linux does **not** mean the collector
works, because 18 of its 30 modules depend on Windows APIs that are absent
there. Those modules are proven only on Windows, and this file says exactly how.

Run everything below on Windows before tagging a release.

---

## What the cross-platform suite already covers

Verified automatically, on any OS, by `pwsh -NoProfile -File tests/Invoke-Tests.ps1`:

- argument parsing, including value-less flags and unknown options/modules
- `-DryRun` — the resolved plan, and that it writes nothing
- the `summary.json` output contract against `schema/summary.schema.json`
- allowlist suppression and IOC matching, including token-boundary behaviour
- exit codes, chain-of-custody and manifest generation
- finding id format, uniqueness, severity and confidence vocabularies

**These do not need re-testing by hand on Windows.** Re-run the suite there to
confirm it is green, and spend the manual effort on the sections below.

---

## Module coverage: what Linux cannot prove

`pwsh -File ./Tatar.ps1 -All -Silent -OutputPath <dir>` on Linux, 2026-09-30:

**Executed without error (11)** — `memory`, `apps`, `autoruns`, `browser`,
`eventlogs`, `hives`, `obfscan`, `prefetch`, `pshistory`, `rdp`, `usb`

> Read this narrowly: it means the code path ran and did not throw. Most of
> these find nothing on Linux (there is no `C:\Windows\Prefetch`, no registry),
> so their *collection* is unproven — only their error handling is.

**Failed on Linux, Windows APIs required (18)** — `sysinfo`, `network`,
`process`, `sessions`, `services`, `users`, `persistence`, `shares`,
`firewall`, `drivers`, `privesc`, `lateral`, `fsartifacts`, `shadow`, `mft`,
`indicators`, `hashes`, `timeline`

Causes seen: `Get-CimInstance`, `net`, `cmd`, `fsutil`, `vssadmin`,
`Get-WinEvent`, registry providers, `Get-Volume`.

---

## A. Smoke test — 10 minutes

On a throwaway Windows VM, as **Administrator**:

```powershell
# 1. help and module list render, exit 0
.\Tatar.ps1 -Help
.\Tatar.ps1 -List

# 2. dry run writes NOTHING
.\Tatar.ps1 -All -DryRun -OutputPath E:\Evidence
Test-Path E:\Evidence\*          # must be False

# 3. a real, narrow collection
.\Tatar.ps1 -Modules sysinfo,network,users -OutputPath E:\Evidence
```

Check: an output directory `<HOST>_<timestamp>` exists and contains
`summary.json`, `TATAR_Report_*.txt`, `tatar.log`, `chain_of_custody.txt`,
`manifest_sha256.txt`. `summary.json` must parse and validate against
`schema/summary.schema.json`.

Then run both suites and expect green:

```powershell
pwsh       -NoProfile -File tests\Invoke-Tests.ps1   # PowerShell 7
powershell -NoProfile -File tests\Invoke-Tests.ps1   # Windows PowerShell 5.1
```

**5.1 matters**: it is the only PowerShell present on a default Windows install,
which is the environment an incident responder actually has. The suite has only
ever been run under 7 here.

## B. Both PowerShell editions

| Check | 5.1 | 7.x |
|---|---|---|
| `.\Tatar.ps1 -All -DryRun` exits 0 | ☐ | ☐ |
| full collection produces valid `summary.json` | ☐ | ☐ |
| `tests\Invoke-Tests.ps1` green | ☐ | ☐ |
| `tests\Test-IocBoundary.ps1` green | ☐ | ☐ |
| `tests\Test-AllowlistPath.ps1` green | ☐ | ☐ |

## C. Privilege behaviour

1. Run **as a standard user**. Expect the "Not running as Administrator"
   warning, a completed run, and `summary.json` still written.
2. Run **as Administrator**. Expect strictly more artifacts — in particular
   `hives`, `shadow`, `mft`, `eventlogs` and `memory`.
3. Confirm no module aborts the whole run when a single artifact is locked;
   the collector is deliberately best-effort (the 12 empty `catch` blocks
   PSScriptAnalyzer reports are intentional for exactly this reason).

## D. Output-path handling — regression checks

These were fixed on 2026-09-30 after being found by running on Linux. Both need
confirming on the platform they actually matter for.

1. **UNC output path.** `.\Tatar.ps1 -Modules sysinfo -OutputPath \\fileserver\Evidence`
   A UNC path has no drive qualifier, and `Split-Path -Qualifier` throws on it.
   Writing triage output to a network share is an ordinary workflow, so this
   must complete and must **not** print the system-drive warning.
2. **System-drive warning still fires.** `-OutputPath C:\Evidence` must warn
   that evidence is going to the system drive.
3. **External drive is quiet.** `-OutputPath E:\Evidence` must not warn.
4. **Admin-check failure is survivable.** `$isAdmin` now defaults to `$false`
   when the identity check throws. Previously the exception left it empty,
   `Write-Summary -IsAdmin` failed to bind its `[bool]`, and **`summary.json`
   was never written** while the text report still appeared. Hard to provoke on
   Windows; confirm at least that a normal run reports `admin=True/False`
   correctly in `tatar.log`.

## E. Flag parity with the Linux collector

Aliases added 2026-09-30 so both editions accept the same spellings. Verify each
is accepted and has no "unknown option" warning:

```powershell
.\Tatar.ps1 -DryRun -Output E:\Ev    -Modules sysinfo
.\Tatar.ps1 -DryRun -o      E:\Ev    -Modules sysinfo
.\Tatar.ps1 -DryRun -Case   IR-2026-1 -Modules sysinfo
.\Tatar.ps1 -DryRun -Allow  .\allowlist.sample.json -Modules sysinfo
.\Tatar.ps1 -DryRun -IOCs   .\ioc.sample.json -Modules sysinfo
```

`-OutputPath`, `-CaseId`, `-Allowlist`, `-IOCFile`/`-IOC` must all still work —
they are what any existing script uses.

## F. The 18 Windows-only modules

For each, confirm the named artifact appears and is non-trivial:

| Module | Expect |
|---|---|
| `sysinfo` | OS build, hotfixes, env, `systeminfo` output |
| `network` | connections with owning PIDs, DNS cache, hosts file, ARP |
| `process` | process list with paths and command lines, parent PIDs |
| `sessions` | logon sessions, `query user` output |
| `services` | services with binary paths, non-standard paths flagged |
| `users` | local users and groups, admin membership |
| `persistence` | Run keys, scheduled tasks, WMI subscriptions, startup |
| `shares` | SMB shares and permissions |
| `firewall` | profile state and rules |
| `drivers` | driver list, unsigned drivers flagged |
| `privesc` | unquoted service paths, weak ACLs, AlwaysInstallElevated |
| `lateral` | PsExec traces, WMI/WinRM/RDP artifacts |
| `fsartifacts` | Recent, LNK, JumpLists, Amcache note |
| `shadow` | VSS listing (admin only) |
| `mft` | `$MFT`/USN journal info |
| `indicators` | findings raised, IOC matches when `-IOC` supplied |
| `hashes` | SHA-256 of running/service binaries |
| `timeline` | merged CSV across process/prefetch/recent/installs |

Also verify the gated operations do nothing unless asked:
`-CollectHives`, `-ExportEvtx`, `-MemoryDump`, `-Compress`.

## G. Evidence integrity

1. `manifest_sha256.txt` — recompute and compare every hash.
2. `chain_of_custody.txt` — records host, examiner, case id, start/end, tool version.
3. Re-run with the same `-CaseId`; confirm a separate timestamped directory and
   no overwriting of the previous collection.
4. Confirm the collector does not write inside the directory it is collecting
   *from* when `-OutputPath` is on the system drive.

---

## Reporting

File anything found as a GitHub issue with: Windows build, PowerShell edition
and version, the exact command, the relevant `tatar.log` lines, and
`summary.json` if it was produced. Do not attach real evidence from a live
incident.
