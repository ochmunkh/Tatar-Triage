# Modules and ATT&CK mapping

[Монгол](MODULES.mn.md) · [← README](../README.md)

## Modules

Order of volatility, top to bottom:

**Windows (33):** `memory` · `network` · `process` · `sessions` · `services` · `sysinfo` · `users` · `persistence` · `autoruns` · `shares` · `firewall` · `drivers` · `apps` · `prefetch` · `usb` · `pshistory` · `obfscan` · `rdp` · `lateral` · `privesc` · `browser` · `fsartifacts` · `deleted` · `shadow` · `eventlogs` · `hives` · `mft` · `indicators` · `rmm` · `useractivity` · `motw` · `hashes` · `timeline`

**Linux (18):** `sysinfo` · `network` · `process` · `sessions` · `users` · `services` · `persistence` · `apps` · `suid` · `sshkeys` · `bashhistory` · `kernelmods` · `indicators` · `hashes` · `logs` · `timeline` · `containers` · `integrity`

Coverage includes: system/user/network state, running processes with LOLBAS pattern flags, services & drivers, startup/Run-key/scheduled-task persistence, RDP activity, lateral-movement artifacts (SMB sessions, mapped drives, WMI persistence, PsExec), privilege-escalation indicators (unquoted service paths, `AlwaysInstallElevated`, token privileges), obfuscated-script scan, browser artifact metadata (all profiles, no decryption), Recent/Amcache/Prefetch, Recycle Bin, shadow copies, key Windows event IDs, optional registry hive & EVTX export, NTFS/MFT info, file hashing for IOC matching, remote-access/RMM presence **and connection history**, per-user execution evidence (UserAssist, MUICache, RunMRU, Jump Lists), crypto-stack download remnants, Mark-of-the-Web (which files came from the internet, and the URL), and a lightweight super-timeline CSV.

On Linux: cron / systemd persistence, SUID/SGID enumeration, SSH keys, container & cloud context, and a critical-file integrity baseline — see [`linux/README.md`](../linux/README.md).

Two parts say what the host could have recorded and whom it talked to. `eventlogs` (Windows) and `logs` (Linux) end with a **logging coverage** section: PowerShell script-block, module and transcription logging, the command line in event 4688, whether the Security log holds any 4688, Sysmon and the size, record count and oldest event of the key channels on Windows; auditd, a persistent or in-memory journal, a syslog daemon and an authentication log on Linux. Each gap is listed with the module limitations as "logging gap on this host", and counted in `stats.LoggingGaps`: a quiet event log on a host that writes few events is not a clean host. Nothing is switched on or changed. `network` writes `external_ips.txt`, the public remote addresses of established connections with the port and the process, for the analyst to look up afterwards (`stats.ExternalAddresses`); the collector looks nothing up.

## Where the IOC feed is checked

The IOC feed is not a module. It is applied once, after every module has finished, to the findings and to the text the run collected, so no module needs to know about it. A hit has two sources. **Against a finding:** an indicator (IP, domain or file name) found in the finding's text, or a SHA-256 that equals the hash of a file the finding names and that still exists. The finding keeps its identity but becomes High, confidence 0.95, `iocMatch: true`, with the indicator in `iocIndicator`, and an allowlist no longer hides it. **Against the evidence:** an indicator found anywhere in this run's `.txt`, `.csv` and `.log` files (not `summary.txt`), for example a command line in the process list or a line of `binary_hashes.txt`; this raises a new finding whose message names the indicator. A hash can only match a file the run hashed or a finding names (the running and service binaries), not every file on the disk. The text of the feed is never run or trusted: it is matched at word boundaries (`127.0.0.1` does not match `127.0.0.10`) and neutralised before it reaches an output file. A feed path that cannot be read is reported at the start and makes the run finish with exit code 2.

## Persistence and configuration checks that raise a finding

Windows: an autostart entry (Run key, Startup folder, scheduled task) that starts a program from `Users\Public`, `Windows\Temp`, a user Temp or Downloads folder or the Recycle Bin is raised for review (T1547.001, T1053.005); AppData and ProgramData are not, because ordinary software starts from there. The `firewall` module also reports Defender real-time protection and exclusions (exclusions need Administrator). The `rdp` module raises RDP enabled without network-level authentication (T1021.001). The `persistence` module raises BITS jobs that run a program on completion (T1197) and PowerShell profiles with download or decode patterns (T1546.013).

Linux: the `process` module raises command lines that look like a reverse shell or pipe-to-shell; `persistence` raises cron entries and systemd units that start from a temporary directory, a non-empty `/etc/ld.so.preload` (High, T1574.006) and suspicious lines in shell startup files; `indicators` raises `NOPASSWD` in sudoers (a note says so when the file is not readable without root).

## MITRE ATT&CK mapping

Each collector maps to the adversary techniques it helps **detect / investigate**. Full detail in [`docs/MITRE_ATTACK.md`](MITRE_ATTACK.md).

| Module / artifact | ATT&CK technique | Tactic |
|---|---|---|
| `process` (LOLBAS command lines) | T1059 · T1059.001 (PowerShell) | Execution |
| `persistence` (Run keys) | T1547.001 | Persistence |
| `persistence` (scheduled tasks) | T1053.005 | Persistence |
| `services` | T1543.003 | Persistence / Priv Esc |
| `rdp` | T1021.001 (RDP) | Lateral Movement |
| `lateral` (SMB shares / sessions) | T1021.002 | Lateral Movement |
| `lateral` (WMI event subscription) | T1546.003 · T1047 | Persistence / Execution |
| `lateral` (PsExec) | T1569.002 | Execution |
| `hives` (SAM / SECURITY / LSASS) | T1003.002 · T1003.001 | Credential Access |
| `privesc` (unquoted service path) | T1574.009 | Persistence / Priv Esc |
| `privesc` (AlwaysInstallElevated) | T1548 | Privilege Escalation |
| `obfscan` | T1027 · T1140 | Defense Evasion |
| `usb` | T1091 · T1200 | Initial Access / Exfil |
| `eventlogs` (ID 1102) | T1070.001 (clear event logs) | Defense Evasion |
| `shadow` | T1490 (inhibit recovery) | Impact |
| `network` (connections, DNS, `hosts` file) | T1071 · T1565.001 | C2 / Defense Evasion |
| `browser` | T1555.003 · T1539 | Credential Access |
