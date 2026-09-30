# MITRE ATT&CK Mapping — TATAR Triage Toolkit

TATAR is a **detection / investigation** tool. The table below maps each collector
module to the ATT&CK techniques whose evidence it captures, so analysts and SOC teams
can pivot straight from an artifact to the technique it supports.

> Mapping is for triage guidance — presence of an artifact is not proof of the
> technique. Always corroborate.

Every technique id a collector can put in `summary.json` -> `findings[].technique`
appears below; CI fails otherwise (`.github/scripts/check_docs_parity.py`). The
reverse does not hold on purpose: a module can capture the *evidence* for a
technique without raising a finding for it.

## By tactic (Windows — `Tatar.ps1`)

### Execution
| Module | Evidence collected | Technique |
|---|---|---|
| `process` | Process tree + command lines; LOLBAS flags (`powershell`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `wmic`, `-enc`, `DownloadString`…) | T1059 Command and Scripting Interpreter · T1059.001 PowerShell |
| `process` | `cmd.exe` command lines | T1059.003 Windows Command Shell |
| `process` | `wscript` / `cscript` command lines | T1059.005 Visual Basic · T1059.007 JavaScript |
| `process` | Unexpected parent → child chain (e.g. Office → shell) | T1055 Process Injection |
| `process` | `certutil` / `bitsadmin` download command lines | T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode |
| `eventlogs` | 4688 process creation, 4104 PowerShell script block | T1059 |
| `lateral` | PsExec service artifacts (`PSEXESVC`) | T1569.002 Service Execution |
| `lateral` | WMI (`__EventFilter`, `CommandLineEventConsumer`) | T1047 Windows Management Instrumentation |

### Persistence
| Module | Evidence | Technique |
|---|---|---|
| `persistence` | HKCU/HKLM Run / RunOnce keys, Startup | T1547.001 Registry Run Keys / Startup Folder |
| `persistence` | Non-Microsoft scheduled tasks | T1053.005 Scheduled Task |
| `services` | Service name / binary / start mode | T1543.003 Windows Service |
| `lateral` | WMI event subscription persistence | T1546.003 WMI Event Subscription |
| `persistence` | Image File Execution Options (IFEO) debugger | T1546.012 IFEO Injection |
| `persistence` | `AppInit_DLLs` | T1546.010 AppInit DLLs |
| `persistence` | `AppCertDLLs` | T1546.009 AppCert DLLs |
| `persistence` | Winlogon `Shell` / `Userinit` | T1547.004 Winlogon Helper DLL |
| `persistence` | LSA authentication / notification packages | T1547.005 Security Support Provider · T1556.002 Password Filter DLL |
| `persistence` | Print Processors / Monitors | T1547.012 Print Processors |
| `autoruns` | Sysinternals Autoruns (all ASEPs) | multiple (T1547, T1037, …) |

### Privilege Escalation
| Module | Evidence | Technique |
|---|---|---|
| `privesc` | Unquoted service paths with spaces | T1574.009 Path Interception (unquoted path) |
| `privesc` | Service binary in a user-writable directory | T1574.010 Services File Permissions Weakness |
| `privesc` | `AlwaysInstallElevated` (HKLM/HKCU) | T1548 Abuse Elevation Control Mechanism · T1548.002 Bypass UAC |
| `privesc` | Other local privilege-escalation exposure | T1068 Exploitation for Privilege Escalation |
| `privesc` | Token privileges (`whoami /priv`) | T1134 Access Token Manipulation |

### Defense Evasion
| Module | Evidence | Technique |
|---|---|---|
| `obfscan` | Base64 / `-enc` / IEX / DownloadString in scripts | T1027 Obfuscated Files or Information · T1140 Deobfuscate/Decode |
| `eventlogs` | Event ID 1102 (Security log cleared) | T1070.001 Clear Windows Event Logs |
| `network` | `hosts` file tampering (`hosts.txt`, non-default entries flagged) | T1565.001 Stored Data Manipulation |
| `process` | `mshta` / `regsvr32` / `rundll32` proxy execution | T1218.005 Mshta · T1218.010 Regsvr32 · T1218.011 Rundll32 |
| `indicators` | Executables in temp/appdata; services in user-writable paths | T1036 Masquerading · T1574 Hijack Execution Flow · T1105 Ingress Tool Transfer |

### Credential Access
| Module | Evidence | Technique |
|---|---|---|
| `hives` | SAM / SECURITY hive save | T1003.002 Security Account Manager |
| `hives` | LSA secrets material | T1003.001 LSASS Memory (offline) |
| `browser` | Login Data / credential store metadata | T1555.003 Credentials from Web Browsers |
| `browser` | Cookies / session artifacts | T1539 Steal Web Session Cookie |
| `sessions` | 4625 failed-logon volume | T1110 Brute Force |
| `users` | Local accounts with no password required | T1078 Valid Accounts |

### Lateral Movement
| Module | Evidence | Technique |
|---|---|---|
| `rdp` | 4624 (LogonType 10), 4778/4779, TS Operational logs, client MRU | T1021.001 Remote Desktop Protocol |
| `lateral` | SMB sessions, mapped drives, admin shares | T1021.002 SMB / Windows Admin Shares |
| `lateral` | Other remote-service artifacts | T1021 Remote Services |

### Collection / C2 / Impact / Access
| Module | Evidence | Technique |
|---|---|---|
| `network` | Established connections, DNS cache | T1071 Application Layer Protocol (C2) |
| `usb` | USBSTOR device history | T1091 Replication Through Removable Media · T1200 Hardware Additions |
| `shadow` | Volume Shadow Copy state | T1490 Inhibit System Recovery |

## By tactic (Linux — `linux/tatar-linux.sh`)

The Linux edition raises findings from its own module set. Mapping lives in
`map_technique()`, the single source of truth for the Linux side.

| Module | Evidence / finding | Technique |
|---|---|---|
| `process` | Process executing from `/tmp`, `/dev/shm`, `/var/tmp`, `/run` | T1059 Command and Scripting Interpreter |
| `process` | Running process whose binary was DELETED on disk | T1620 Reflective Code Loading · T1070.004 File Deletion |
| `network` | `/etc/hosts` custom entries (static host overrides) | T1565.001 Stored Data Manipulation |
| `sessions` | `lastb` failed-logon volume, auth-log brute force | T1110 Brute Force |
| `users` | Second account with UID 0 | T1136 Create Account · T1078 Valid Accounts |
| `users` | Account with an EMPTY password in `/etc/shadow` | T1078 Valid Accounts |
| `persistence` | Suspicious `cron` / `cron.d` / user crontab command | T1053.003 Cron |
| `suid` | SUID/SGID binary outside the standard paths | T1548.001 Setuid and Setgid |
| `sshkeys` | `root` `authorized_keys`, `sshd_config` key settings | T1098.004 SSH Authorized Keys |
| `bashhistory` | Notable shell-history command (`curl`, `chattr`, `history -c`…) | T1552.003 Bash History |
| `indicators` | World-writable system file | T1222.002 Linux and Mac File and Directory Permissions Modification |
| `indicators` | Executables in `/tmp`, `/dev/shm`, `/var/tmp` | T1036 Masquerading |
| `containers` | TATAR is running INSIDE a container (finding category `context`) | T1610 Deploy Container |

Evidence-only Linux modules (no findings raised): `sysinfo`, `services`,
`apps`, `kernelmods`, `hashes`, `logs`, `timeline`, `integrity`.

### Raised by the IOC engine

When an `--ioc` feed is supplied, *Pass B* raises a finding for any indicator seen
in the collected evidence. That finding is not tied to a collector module, so its
technique follows the **kind of indicator** that matched:

| Indicator | Technique |
|---|---|
| `ips[]` | T1071 Application Layer Protocol |
| `domains[]` | T1071.004 Application Layer Protocol: DNS |
| `filenames[]` | T1204.002 User Execution: Malicious File |
| `hashes[]` | T1588.001 Obtain Capabilities: Malware |

Until v1.2.5 every one of these was tagged `T1071`, which is wrong for a filename
or a hash — a wrong mapping is worse than no mapping, so the type now decides.

## Evidence / execution-history sources (support many techniques)

| Module | Artifact | Use |
|---|---|---|
| `prefetch` | `*.pf` | Program execution history |
| `fsartifacts` | Amcache, Recent, LNK, JumpLists | Execution / file-access history |
| `deleted` | Recycle Bin ($I metadata) | Deleted-file recovery leads |
| `mft` | NTFS/MFT info | Timeline / anti-forensics context |
| `hashes` | SHA-256 of running/service binaries | IOC / VirusTotal matching |
| `timeline` | Merged CSV (process, prefetch, recent, installs) | Super-timeline lite |

---

*ATT&CK® is a registered trademark of The MITRE Corporation. Technique IDs are used here
for reference only.*
