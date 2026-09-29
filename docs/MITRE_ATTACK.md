# MITRE ATT&CK Mapping — TATAR Triage Toolkit

TATAR is a **detection / investigation** tool. The table below maps each collector
module to the ATT&CK techniques whose evidence it captures, so analysts and SOC teams
can pivot straight from an artifact to the technique it supports.

> Mapping is for triage guidance — presence of an artifact is not proof of the
> technique. Always corroborate.

## By tactic

### Execution
| Module | Evidence collected | Technique |
|---|---|---|
| `process` | Process tree + command lines; LOLBAS flags (`powershell`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `wmic`, `-enc`, `DownloadString`…) | T1059 Command and Scripting Interpreter · T1059.001 PowerShell |
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
| `autoruns` | Sysinternals Autoruns (all ASEPs) | multiple (T1547, T1037, …) |

### Privilege Escalation
| Module | Evidence | Technique |
|---|---|---|
| `privesc` | Unquoted service paths with spaces | T1574.009 Path Interception (unquoted path) |
| `privesc` | `AlwaysInstallElevated` (HKLM/HKCU) | T1548 Abuse Elevation Control Mechanism |
| `privesc` | Token privileges (`whoami /priv`) | T1134 Access Token Manipulation |

### Defense Evasion
| Module | Evidence | Technique |
|---|---|---|
| `obfscan` | Base64 / `-enc` / IEX / DownloadString in scripts | T1027 Obfuscated Files or Information · T1140 Deobfuscate/Decode |
| `eventlogs` | Event ID 1102 (Security log cleared) | T1070.001 Clear Windows Event Logs |
| `hosts` | `hosts` file tampering | T1565.001 Stored Data Manipulation |
| `indicators` | Executables in temp/appdata; services in user-writable paths | T1036 Masquerading · T1574 Hijack Execution Flow |

### Credential Access
| Module | Evidence | Technique |
|---|---|---|
| `hives` | SAM / SECURITY hive save | T1003.002 Security Account Manager |
| `hives` | LSA secrets material | T1003.001 LSASS Memory (offline) |
| `browser` | Login Data / credential store metadata | T1555.003 Credentials from Web Browsers |
| `browser` | Cookies / session artifacts | T1539 Steal Web Session Cookie |

### Lateral Movement
| Module | Evidence | Technique |
|---|---|---|
| `rdp` | 4624 (LogonType 10), 4778/4779, TS Operational logs, client MRU | T1021.001 Remote Desktop Protocol |
| `lateral` | SMB sessions, mapped drives, admin shares | T1021.002 SMB / Windows Admin Shares |

### Collection / C2 / Impact / Access
| Module | Evidence | Technique |
|---|---|---|
| `network` | Established connections, DNS cache | T1071 Application Layer Protocol (C2) |
| `usb` | USBSTOR device history | T1091 Replication Through Removable Media · T1200 Hardware Additions |
| `shadow` | Volume Shadow Copy state | T1490 Inhibit System Recovery |

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
