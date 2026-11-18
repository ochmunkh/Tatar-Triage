# Real-host validation protocol

The automated tests run on CI runners and on one workstation. This protocol is
the separate step that runs the collector on **real, different hosts**, writes
down what happened, and turns every disagreement into either a fix or a stated
limit. A result is only useful if someone else can repeat it, so every run
records the same things.

## Scope of a lab round

| Host | Why it matters |
|---|---|
| Windows 10/11 workstation (physical) | Real drivers, real user data, real AV |
| Windows VM, different build (for example Windows 10 22H2, or a Server evaluation image) | Different OS build, different default services |
| Kali Linux in VirtualBox | Debian family, desktop services, a VM environment |
| (later) a RHEL-family and an Ubuntu server host | Different package manager, init and log layout |
| (later) a domain-joined Windows host | Domain accounts, GPO, remote logon traffic |

A round with fewer hosts is still recorded; the table in "Results" says which
hosts it covered, so no result is read as wider than it is.

## Before each run

1. Use a host you are allowed to test. Snapshot a VM first.
2. Note: OS and build, physical or virtual, language, user and privilege level,
   security software, and whether the machine is "quiet" or in daily use.
3. Download the release and **verify it** before running:
   `SHA256SUMS.txt`, and `gh attestation verify <file> --repo ochmunkh/Tatar-Triage`.
4. Write the output to a folder you can inspect; note free disk space.

## Runs

Each host is run twice: once unprivileged, once elevated (Administrator / `sudo`).

| Edition | Command |
|---|---|
| Windows | `powershell -NoProfile -ExecutionPolicy Bypass -File .\Tatar.ps1 -All -OutputPath <dir>` |
| Linux | `bash tatar-linux.sh --all --output <dir>` |

On the same host also run the repository tests and keep their summary lines:

| Edition | Commands |
|---|---|
| Windows | `tests\Invoke-Tests.ps1`, `tests\Test-Security.ps1 -Quick`, `tests\Test-Fuzz.ps1`, `tests\Test-Containment.ps1` (elevated) |
| Linux | `bash tests/run-tests.sh`, `bash tests/test-security.sh` (needs `strace`), `python3 tests/fuzz.py` |

## What to record for every run

- Exit code, duration, `Errors` and the module list from `summary.txt`.
- Every `WARN` and `ERROR` line of `tatar.log`, and whether each one is true.
- Peak memory and slowest modules (`moduleStatus`).
- `manifest_sha256.txt` verified against the files (`sha256sum -c` / `Get-FileHash`).
- Whether anything outside the output folder changed (new files, new
  processes left running, new firewall or registry entries).

## Checks against the host itself

The collector's claims are compared with an independent source on the same host:

| Collector says | Compare with |
|---|---|
| Listening ports and connections | `ss -tulpen` / `netstat -ano` |
| Processes and command lines | `ps -eo pid,ppid,args` / `Get-Process` |
| Services and their paths | `systemctl list-units` / `Get-Service`, `sc qc` |
| Accounts and administrators | `getent passwd`, `net user`, `net localgroup administrators` |
| Scheduled tasks, run keys, cron | the native tools |
| Findings | read each one: true lead, expected software, or false positive |

For each finding write one of: **true lead**, **expected on this host**,
**false positive (defect)**, **missed something I know is there (gap)**. A false
positive or a gap is filed as an issue with the evidence line that caused it.

## Acceptance

A host passes when all of these hold:

- Exit code 0 or 2, no `FAILED` module, `summary.json` valid against the schema.
- No module slower than the budget in its header; peak memory under 500 MB.
- The manifest verifies; nothing changed outside the output folder.
- Every false positive and every gap is either fixed, or written down in the
  limits of that edition.
- No secret from the host (token, password, key) appears in any output file.

## Results

One row per host and run. Keep the raw `summary.json` and `tatar.log` of each
run; they are the evidence for the row.

| Date | Host (OS, build, physical/VM) | Edition, version | Privilege | Exit | Duration | Findings (true / expected / false positive / gap) | Notes |
|---|---|---|---|---|---|---|---|
| 2026-11-18 | Windows 11 Pro 10.0.26300, physical workstation | Windows 1.8.0 | not elevated | 0 | 58 s | 39 findings: 0 true leads confirmed, 1 expected (`Admin` has no password requirement flag), most `obfscan` / `indicators` rows expected on a developer machine, 5 defects found | AnyDesk UTF-16 log unreadable; signed-URL credentials in MOTW finding; Defender services reported as user-writable; own tests flagged; bare powershell.exe flagged. All fixed in 1.8.1 |
| 2026-11-18 | same host | Windows 1.8.0 | elevated | 0 | 41 s | 41 findings; same causes; failed logons were local lock-screen typing (type 2, 127.0.0.1) | Defender false positive reproduced with ACLs readable |
| 2026-11-18 | Kali Rolling 6.19, VirtualBox VM | Linux 1.8.1 | root | 0 | 60 s | 0 findings, 0 WARN | No journal collected (gap); SUID walk 38 s of 60 s; "Network artifacts saved" untrue. Fixed in 1.8.2 |
| 2026-11-18 | same host | Linux 1.8.1 | not root | 0 | 21 s | 0 findings, 1 generic WARN | `/etc/shadow`, `/etc/sudoers`, `btmp` skipped without saying so. Fixed in 1.8.2 |
| 2026-11-18 | Windows Sandbox (clean Windows 11 Enterprise 10.0.26100, offline) x2 | Windows 1.8.1 | elevated (the Sandbox account is an administrator; a non-elevated run is not possible there) | 0 | 20-25 s | 2 findings on a clean system: the stock WMI SCM binding (defect, fixed in 1.8.2), and "1 local Administrators member" (policy, kept) | Reports `container=True` for the Sandbox |
| 2026-11-18 | Windows Sandbox (clean Windows 11 Enterprise 10.0.26100, offline) x2 | Windows 1.9.0 | elevated (the Sandbox account is an administrator) | 0 | 17-23 s | 1 finding on a clean system: `WDAGUtilityAccount` is the Sandbox's own administrator (expected there). The stock WMI binding finding of 1.8.1 is gone | 0 errors, all 33 modules `ok`; two runs give the same fingerprint (`tatar-diff`: 0 new, 0 resolved, 0 changed); manifest verifies (40/40 files), both JSONs validate. Section 29/30 print after 33 (cosmetic) |
| 2026-11-18 | Kali Rolling 6.19, VirtualBox VM | Linux 1.9.0 | not root | 0 | 28 s | 0 findings | Journal extracts present; `btmp`, `/etc/shadow`, `/etc/sudoers` named as limitations in `summary.json`; manifest verifies; found: the run's own scratch directory appeared in `timeline.csv` (fixed, unreleased) |
| 2026-11-18 | same host | Linux 1.9.0 | root | 0 | 27 s | 0 findings | Journal extracts present, SUID/SGID listed, 78 binaries hashed; SUID walk 18 s of 27 s (cold disk) |
| 2026-11-18 | Windows 11 Pro 10.0.26300, physical developer workstation | Windows 1.9.0 | not elevated | 0 | 80 s | 34 findings: 18 `obfscan` (the collector's own tests, installer copies, third-party scripts: expected), 8 `useractivity` (own build scripts: expected; two MUICache entries for an `xmrig` miner `.bat` that is no longer on disk and one for a Nexpose service script: left to the owner to confirm), 2 `motw`, 2 `rmm` (AnyDesk from an earlier test), 1 hosts file (own anti-phishing entries), 1 `indicators` (29,202 executables under Temp from a .NET single-file app), 2 `users` (an account with no password-required flag; Administrators member) | 0 errors, all modules `ok`. Gaps named: prefetch, shadow copies, other users' activity. Slowest: `obfscan` 31 s, `indicators` 27 s (fixed after this run, unreleased) |
