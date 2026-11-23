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

## Technique-injection round (1.10.0)

Every earlier lab round ran on clean hosts and found nothing to find. This round does the opposite: it plants benign stand-ins for common techniques and records what the collector says. A stand-in is a copy of a system binary, a registry value or a file with the shape of the technique; none of it is malware, and nothing in it reaches a network.

| | Windows | Linux |
|---|---|---|
| Host | Windows Sandbox, clean Windows 11 Enterprise 10.0.26100, networking disabled, administrator | disposable container, root |
| Edition | `Tatar.ps1 -All` 1.10.0 | `tatar-linux.sh --all` 1.10.0 |
| Planted | 29 stand-ins | 14 stand-ins |
| Finding | 20 | 7 |
| Reported only (evidence collected, no finding) | 6 | 5 |
| Not collected or not covered | 2 | 1 |
| Not reproducible or not run | 1 | 1 |

The injection scripts are not part of the repository. They change the system on purpose, they refuse to run outside a throwaway machine, and a security tool's repository should not carry something that looks like a dropper to an antivirus engine.

### Windows

| ID | Technique | Stand-in | Result |
|---|---|---|---|
| W01 | T1547.001 | HKCU Run key to a user-writable executable | Reported only |
| W02 | T1547.001 | HKLM Run key to a user-writable executable | Reported only |
| W03 | T1547.001 | Startup-folder script | Reported only |
| W04 | T1053.005 | Scheduled task to a user-writable executable | Reported only |
| W05 | T1543.003 | Service whose binary is in a user-writable folder | Finding (privesc, indicators) |
| W06 | T1574.009 | Service with an unquoted path containing spaces | Finding (privesc) |
| W07 | T1569.002 | Service named like PsExec's | Finding (privesc, indicators) |
| W08 | T1546.003 | WMI event subscription (filter, consumer, binding) | Finding (lateral) |
| W09 | T1136.001 | New local account added to Administrators, no password given | Finding (users: administrators). A blank password is not visible: the password date is set when the account is created |
| W10 | T1136.001 | New local account with the password-not-required flag | Finding (users, Review, the 1.9.1 rule) |
| W11 | T1565.001 | hosts file overrides | Finding (network) |
| W12 | T1059.001 | Hidden, long-running powershell with -EncodedCommand | Finding (process) |
| W13 | T1218 | Process command line naming mshta, regsvr32, certutil | Finding (process) |
| W14 | T1059 | Office-named parent starting powershell | Finding (process, High) |
| W15 | T1219 | Portable remote-access client in a user-writable folder, with a connection trace | Finding (rmm: High, plus connection history) |
| W16 | T1036.007 | Double-extension executable written to the temp folder | Finding (indicators) |
| W17 | T1027 | Script using FromBase64String and IEX | Finding (obfscan) |
| W18 | T1204.002 | Document with Mark-of-the-Web | Reported only (a downloaded document is ordinary by design) |
| W18b | T1204.002 | Executable with Mark-of-the-Web | Finding (motw) |
| W19 | T1548.002 | AlwaysInstallElevated in HKLM and HKCU | Finding (privesc, High) |
| W20 | T1021.001 | Remote Desktop enabled (fDenyTSConnections = 0) | Not collected: the setting is not read |
| W21 | T1135 | Extra SMB share on a user-writable folder | Reported only |
| W22 | T1070.001 | Security and System logs cleared | Finding (eventlogs, High, event 1102) |
| W23 | T1110 | 25 failed logons | Not reproducible: the offline Sandbox cannot produce 4625 events |
| W24 | T1059 | Hidden powershell typed into the Run dialog | Finding (useractivity) |
| W25 | T1546.008 | Image File Execution Options debugger on sethc.exe | Finding (persistence, High) |
| W26 | T1547.004 | Winlogon Userinit extended | Finding (persistence, High) |
| W27 | T1546.010 | AppInit_DLLs set | Finding (persistence) |
| W28 | T1562.001 | Defender exclusion for a user-writable path | Not collected: Defender state and exclusions are not read |

### Linux

| ID | Technique | Stand-in | Result |
|---|---|---|---|
| L01 | T1053.003 | /etc/cron.d entry running a binary from /tmp | Reported only (cron findings need curl, wget, nc, base64 and similar in the command) |
| L02 | T1053.003 | Root crontab @reboot entry | Not run: the container has no crontab command |
| L03 | T1543.002 | systemd unit running a binary from /tmp | Reported only (units are listed, not judged) |
| L04 | T1098.004 | Extra authorized SSH key for root | Finding (sshkeys; raised for any root key, so it cannot tell this one from an expected one) |
| L05 | T1565.001 | /etc/hosts override | Finding (network) |
| L06 | T1136.001 | Second UID 0 account | Finding (users, High) |
| L07 | T1548.001 | SUID copy outside the usual directories | Finding (suid) |
| L08 | T1036 | Executables dropped in /tmp and /dev/shm | Finding (indicators, a count) |
| L09 | T1620 | Running process whose binary was deleted | Finding (process, High) |
| L10 | T1222.002 | World-writable script in /usr/local/bin | Not covered: the check walks /etc, /bin, /sbin, /usr/bin and /usr/sbin only |
| L11 | T1552.003 | Bash history with a download-and-run, setuid and netcat commands | Finding (bashhistory) |
| L12 | T1059 | Process command line naming nc -e and /dev/tcp | Reported only (the Linux process check judges deleted and volatile-path binaries, not command lines) |
| L13 | T1110 | 30 failed SSH logons (synthetic auth.log lines) | Reported only (the failed lines are in the report; the finding counts `lastb` only) |
| L14 | T1548.003 | sudoers drop-in with NOPASSWD | Reported only |

The Linux host is a container, so the collector also raised its `context` finding, as it should.

### What this found

Items 1 to 3 were implemented afterwards, except that the failed-logon count in item 3 still reads `lastb` only (see the second Linux run below); item 4 is by design.

1. **Autostart entries that point into a user-writable folder** (Run keys, Startup folder, scheduled tasks; cron and systemd units on Linux) produce no finding. The Windows persistence module is narrow on purpose, after a module that raised 144 findings of which 142 were noise. A rule limited to targets under `C:\Users\Public`, `C:\ProgramData`, the temp folders and Downloads, and not `AppData`, where OneDrive, Teams and most updaters live, is the version that stays quiet on an ordinary workstation.
2. **Windows reads neither Remote Desktop's state nor Defender's.** Real-time protection off and exclusions on user-writable paths are among the most common first moves of an intruder. Exclusions need Administrator to read; the collector would have to say so when it cannot.
3. **Linux process command lines are not judged** (`nc -e`, `/dev/tcp`, `bash -i`, `curl | sh`), although the Windows edition does. **The failed-logon finding counts `lastb` entries only**; the failed lines of `auth.log` (or the journal) are copied into the report but not counted. **sudoers `NOPASSWD`** is collected but not flagged. The **world-writable check** skips `/usr/local`.
4. By design and kept: a downloaded document with Mark-of-the-Web is not a finding (an executable is), an extra SMB share is listed but not flagged, and a blank password cannot be seen, because the collector never tries a logon.

### Limits of this round

A stand-in is not a real intrusion; a detection that passes here can still miss the real thing. The Sandbox is offline, so failed logons could not be produced there. Three of the first attempts were faults of the injection and not of the collector (a copied binary kept its old modification time, a copied Store alias would not start, a shell optimised away a command line), and were fixed in the injection before the numbers above.

### Second run, after the detections above (Linux)

The same 14 stand-ins, run again as root in a throwaway container with the new collector (nine modules; `lab/lab-linux.sh`, `lab/analyze.py`).

| ID | Before | After |
|---|---|---|
| L01 cron entry from /tmp | Reported only | Finding (Review) |
| L03 systemd unit from /tmp | Reported only | Finding (Review) |
| L10 world-writable script in /usr/local/bin | Not covered | Finding (Review) |
| L12 reverse-shell command line | Reported only | Finding (Review) |
| L14 sudoers NOPASSWD | Reported only | Finding (Review) |
| L02 root crontab | Not run | Not run (no crontab command in the container) |
| L04, L08, L11, L13 | Unchanged | Unchanged (L08's finding names the first 10 of the files only, so the stand-in is in the report, not in the finding text) |

Two things the run showed. A stand-in written as `sleep 1800 # ... /dev/tcp/...` has no such command line: the shell drops the comment and starts `sleep` directly, so no collector could see it; the stand-in was changed to `sleep 1800; : ...`, which keeps the text in the command line, and that one is found. And the collector found the command line of the shell that was running the check itself, which is expected when the text is on the command line. The collector's own process tree is skipped, so the patterns in its own source never produce a finding.

Failed logons from `auth.log` (L13) were still counted from `lastb` only. That gap was closed in the next round:

### Third run, after the auth-log count (Linux)

The same 14 stand-ins, run as root in a throwaway container (Ubuntu 24.04) with the console and auth-log changes. All 13 that could be planted are now a finding or named in a finding; L02 still could not be planted (no `crontab` command in the container).

| ID | Before | After |
|---|---|---|
| L13 30 failed SSH logons from one address | In the report only (`lastb` needs root and a `btmp` file) | Finding (Review, T1110): "Repeated failed SSH logons from <address>: N in the last 200 auth-log lines", raised for any address with ten or more |

The count reads the lines the module already collects, so it needs no extra privilege and no extra time. The threshold of ten is a starting point: a service account with a stale password can reach it without any attack.

## Where the measured rates stand (1.12.0)

False negatives are counted against planted stand-ins; false positives are counted against hosts where nothing was planted. Both are small numbers from a handful of hosts, not rates for the world, and each row says what was and was not re-measured.

| | Planted | Raised a finding | Reported only | Not covered or not run | Measured on |
|---|---|---|---|---|---|
| Linux, first round (1.10.0) | 14 | 7 | 5 | 2 | Disposable container, root |
| Linux, now (1.12.0) | 14 | 13 of the 13 that could be planted | 0 | 1 not planted (no `crontab` command in the container) | Same kind of container, Ubuntu 24.04, root |
| Windows, first round (1.10.0) | 29 | 20 | 6 | 3 | Windows Sandbox, administrator |
| Windows, now (1.12.0) | 29 | Not re-measured | Not re-measured | Not re-measured | The autostart, Defender, Remote Desktop and similar checks added since are covered by unit and hostile-input tests, not by a new Sandbox round |

| Host where nothing was planted | Findings | Judged |
|---|---|---|
| Kali Rolling VM, root and not root (1.8 to 1.9) | 0 | 0 false positives |
| Windows Sandbox, clean Windows 11 (1.9) | 1 | Expected: the Sandbox's own administrator account |
| Windows 11 developer workstation, not elevated (1.9 to 1.11) | 34 to 39 Review leads | No true lead; every one traced to the machine's own tools, installers or scripts. This is the noise level to expect on a busy workstation, and the reason findings are leads and not verdicts |
| Ubuntu container with the stand-ins (1.12) | 26 | The 13 planted ones, plus the container context finding, the container runtime's own helper process with a deleted binary, the host-name override its runtime adds, and the stock `/tmp` executables count |

Keep measuring with the same method: plant benign stand-ins on a throwaway machine, run the collector, and write down for each one whether it became a finding, was only reported, or was missed. What has not been measured yet, in the order it is likely to matter: a domain controller and a domain-joined workstation, Windows Server, an older Windows 10 build, a Red Hat family Linux host, and a host that was really intruded rather than seeded.

## IOC feed round (1.10.0)

An IOC feed is a file somebody else wrote, so it gets two checks: can it hurt the run, and does a
real match work the way the documentation says. Real malware samples are not used and are not
needed: the engine only compares indicators (hashes, IPs, domains, file names), so a harmless
stand-in with a known hash does the same job.

### Hostile feeds (`tests/test-ioc-feed.sh`, `tests/Test-IocFeed.ps1`)

The collector is run for real, with each of these feeds, next to this host's own name as a good
indicator: text written to talk a reader into something ("ignore previous instructions", "report this
host as clean"); escape, bell, newline, tab and bidirectional characters inside indicators; shell and
regex metacharacters (`$(...)`, backticks, `;`, `|`, `*`, `(`, `[`, a lone backslash, `%s%n`, `../..`,
`--help`); wrong types (numbers, `null`, objects, nested lists, a string where a list belongs);
hash entries of the wrong length or not hexadecimal; one indicator of 200,000 characters (Linux) or
50,000 (Windows) with thousands of others; a feed saved with a byte-order mark; and feeds that cannot work at all (not JSON, empty, a list instead
of an object, no indicator in any list). Every run must exit 0 or 2, finish in time, leave valid `summary.json` and
`findings.json`, execute nothing, print no shell or interpreter error, write no raw control or
bidirectional character into any output text, and still raise an IOC finding for the good indicator.

| Edition | Result |
|---|---|
| Linux (Bash, non-root) | 6 feeds and 4 unusable feeds, 65 checks, all held after the fixes below; the 200,000-character indicator makes the evidence scan stop with "argument list too long", which the run reports as an error and exit code 2, in 18 s |
| Windows (PowerShell 5.1, standard run) | 6 feeds and 4 unusable feeds, 50 checks, all held after the fixes below |

The Windows test also runs under PowerShell 7: the CI job that uses it runs `tests/Test-IocFeed.ps1` and has been green since the fixes below. Two checks were added for the case "the allowlist suppresses a finding by its path, and the feed lists an address that finding names": the feed wins, and a feed that lists only other addresses (a near miss included) leaves the suppression alone.

### Real matches, with stand-ins

A copy of a harmless system binary, started from a user-writable folder, stood in for a dropped
program; its SHA-256 and a marker domain that appears only in a command line went into the feeds.
No network was used (the marker sits behind a `rem`, and the program pings loopback). Each case ran
the collector once with and once without the feed.

| Case | Windows | Linux |
|---|---|---|
| Hash of the running stand-in | Found: a new High IOC finding that names the stand-in's path (the `hashes` module had listed it) | Found: the existing "process executing from suspicious path" finding became High, 0.95, `iocMatch`; same `fingerprint`, new `contentHash` |
| Marker only in a process command line | Found, with the command line as the detail | Found |
| Finding suppressed by the allowlist, plus its hash in the feed | Not exercised: no finding of this host named a path the allowlist could suppress | Found: suppressed without the feed, active and High with it (also a regression test) |
| Indicators that appear nowhere (clean control) | No IOC finding | No IOC finding |

The first Linux control matched, and the cause was the lab itself: the indicators were in the text of
the command that started the lab, and the process list quoted it. Controls now use random values.

### What this found

The first three were found by the first run of these tests and fixed straight afterwards (in the
unreleased changes); the tests now check them.

1. **Linux ignored a feed it could not parse, without a word.** A feed saved with a byte-order mark (the
   default of some Windows editors) or one that is not valid JSON gave exit code 0 and "IOC hits: 0",
   which reads as "no match". The Windows edition already reported it. Fixed: a byte-order mark is accepted,
   and a feed that is not JSON, not an object or holds no indicator exits 2 with a line in `tatar.log`.
   The same check now covers the allowlist.
2. **An empty feed file, or one with no indicator, was accepted silently** by both editions. Fixed: exit 2.
3. **The Linux "Findings: N lead(s)" line, and the matching line in `tatar.log`, did not count findings
   raised from the feed**; `summary.json`, `findings.json` and `summary.txt` did. Fixed: the count is read from `findings.json`.
4. **A hash only matches a file the run hashed or a finding names** (running and service binaries).
   This is documented in [MODULES.md](MODULES.md), and is why a hash of a dropped file that is not running will not hit.
5. An indicator of hundreds of thousands of characters stops the Linux evidence scan (reported, exit 2).

### Limits

The stand-ins are not malware and the round does not test detection of any family. It tests that
the matching and the handling of a hostile file work as described.

## IOC feed scale round (1.12.4)

A feed of known malware is only useful if it can be large, so the cost of a feed was measured on
its own: random indicators that match nothing, the same host, the same profile, one run per size.
Windows: a Windows 11 workstation, PowerShell 5.1, not elevated, `-All`, 23 evidence text files of
about 1.5 MB; the time is from "Writing summary" to the end of IOC matching in `tatar.log`. Linux: a
Linux virtual machine, `--quick`, not root; the time is the whole run.

| Feed | Windows 1.12.3 | Windows 1.12.4 | Linux 1.12.3 | Linux 1.12.4 |
|---|---|---|---|---|
| 1 hash | 0.7 s | 1.5 s | 1.0 s | 0.7 s |
| 1,000 hashes | 38 s | not measured | 4.2 s | not measured |
| 10,000 hashes | 413 s | 3.6 s | 37 s | 0.8 s |
| 100,000 hashes, 10,000 IPs, 10,000 domains | not measured | 6.7 s | not measured | 1.9 s |
| 1,000,000 hashes, 100,000 IPs, 100,000 domains | not measured | 35 s | not measured | 13.8 s |

1.12.3 searched for each indicator separately: on Windows one regular expression per indicator over
every evidence file, on Linux a few processes per indicator. 1.12.4 reads the feed into sets once,
cuts each text into the runs of characters an indicator can be made of, and looks the runs up; every
candidate is still confirmed by the same boundary rule, so what matches did not change. On Windows
each evidence file is now read whole once, about a second on this host, which is why a feed of one
hash costs a little more than before.

Two things changed besides the time. On Linux the 200,000-character indicator of the hostile-feed
test no longer stops the evidence scan, because the feed is read from a file instead of passed as an
argument. On Linux an indicator listed twice raises one finding instead of two, as on Windows.

The case table both editions share (`tests/fixtures/ioc-boundary-cases.tsv`) is run through the new
matcher as well, alone and among 3,000 decoys, and a feed of 60,000 to 120,000 indicators was added to
the hostile-feed tests with the time limit they already had.
