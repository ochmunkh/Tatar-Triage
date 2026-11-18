# Modules and ATT&CK mapping

[Монгол](MODULES.mn.md) · [← README](../README.md)

## Modules

Order of volatility, top to bottom:

**Windows (33):** `memory` · `network` · `process` · `sessions` · `services` · `sysinfo` · `users` · `persistence` · `autoruns` · `shares` · `firewall` · `drivers` · `apps` · `prefetch` · `usb` · `pshistory` · `obfscan` · `rdp` · `lateral` · `privesc` · `browser` · `fsartifacts` · `deleted` · `shadow` · `eventlogs` · `hives` · `mft` · `indicators` · `rmm` · `useractivity` · `motw` · `hashes` · `timeline`

**Linux (18):** `sysinfo` · `network` · `process` · `sessions` · `users` · `services` · `persistence` · `apps` · `suid` · `sshkeys` · `bashhistory` · `kernelmods` · `indicators` · `hashes` · `logs` · `timeline` · `containers` · `integrity`

Coverage includes: system/user/network state, running processes with LOLBAS pattern flags, services & drivers, startup/Run-key/scheduled-task persistence, RDP activity, lateral-movement artifacts (SMB sessions, mapped drives, WMI persistence, PsExec), privilege-escalation indicators (unquoted service paths, `AlwaysInstallElevated`, token privileges), obfuscated-script scan, browser artifact metadata (all profiles, no decryption), Recent/Amcache/Prefetch, Recycle Bin, shadow copies, key Windows event IDs, optional registry hive & EVTX export, NTFS/MFT info, file hashing for IOC matching, remote-access/RMM presence **and connection history**, per-user execution evidence (UserAssist, MUICache, RunMRU, Jump Lists), crypto-stack download remnants, Mark-of-the-Web (which files came from the internet, and the URL), and a lightweight super-timeline CSV.

On Linux: cron / systemd persistence, SUID/SGID enumeration, SSH keys, container & cloud context, and a critical-file integrity baseline — see [`linux/README.md`](../linux/README.md).

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
