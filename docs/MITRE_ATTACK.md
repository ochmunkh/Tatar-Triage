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
| `persistence` | Run key, Startup folder or scheduled task starting from `Users\Public`, `Windows\Temp`, user Temp, Downloads, Recycle Bin | T1547.001 · T1053.005 Scheduled Task |
| `persistence` | BITS job that runs a program on completion | T1197 BITS Jobs |
| `persistence` | PowerShell profile with download or decode patterns | T1546.013 PowerShell Profile |
| `firewall` | Defender real-time protection off; exclusions on risky folders | T1562.001 Disable or Modify Tools |
| `persistence` | Non-Microsoft scheduled tasks | T1053.005 Scheduled Task |
| `services` | Service name / binary / start mode | T1543.003 Windows Service |
| `lateral` | WMI event subscription persistence | T1546.003 WMI Event Subscription |
| `persistence` | Image File Execution Options (IFEO) debugger | T1546.012 IFEO Injection |
| `persistence` | `AppInit_DLLs` | T1546.010 AppInit DLLs |
| `persistence` | `AppCertDLLs` | T1546.009 AppCert DLLs |
| `persistence` | Winlogon `Shell` / `Userinit` | T1547.004 Winlogon Helper DLL |
| `persistence` | LSA authentication / notification packages | T1547.005 Security Support Provider · T1556.002 Password Filter DLL |
| `persistence` | Print Processors / Monitors | T1547.012 Print Processors |
| `persistence` | COM hijack — a CLSID registered under **both** HKCU and HKLM | T1546.015 COM Hijacking |
| `persistence` | netsh helper DLL in a user-writable location | T1546.007 Netsh Helper DLL |
| `persistence` | Protocol handler / filter served from a user-writable location | T1546.015 COM Hijacking · T1112 Modify Registry |
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
| `obfscan` | Base64 / `-enc` / IEX / DownloadString in scripts; in `.vbs .vbe .js .jse .wsf .hta` also WinHttp / MSXML2.XMLHTTP / ADODB.Stream downloads and a URL written in hex or base64 | T1027 Obfuscated Files or Information · T1140 Deobfuscate/Decode |
| `process` | URL written in hex or base64 in a running command line, the PowerShell history or event 4688 | T1027 Obfuscated Files or Information · T1140 Deobfuscate/Decode |
| `eventlogs` | Event ID 1102 (Security log cleared) | T1070.001 Clear Windows Event Logs |
| `network` | `hosts` file tampering (`hosts.txt`, non-default entries flagged) | T1565.001 Stored Data Manipulation |
| `process` | `mshta` / `regsvr32` / `rundll32` proxy execution | T1218.005 Mshta · T1218.010 Regsvr32 · T1218.011 Rundll32 |
| `indicators` | Executables in temp/appdata; services in user-writable paths | T1036 Masquerading · T1574 Hijack Execution Flow · T1105 Ingress Tool Transfer |

### Credential Access
| Module | Evidence | Technique |
|---|---|---|
| `hives` | SAM / SECURITY hive save | T1003.002 Security Account Manager |
| `hives` | LSA secrets material | T1003.001 LSASS Memory (offline) |
| `process` | Credential dump by another program in a running command line, the PowerShell history or event 4688 (comsvcs.dll MiniDump, ProcDump against LSASS) | T1003.001 LSASS Memory |
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
| `rmm` | Remote monitoring & management agents present, and their connection history | T1219 Remote Access Software |
| `motw` | Executable or container carrying a Zone.Identifier from the internet, with the URL | T1189 Drive-by Compromise · T1566.001 Spearphishing Attachment |
| `motw` | Office document that carries a VBA macro, found from its bytes (never opened) | T1204.002 User Execution: Malicious File · T1566.001 Spearphishing Attachment |
| `useractivity` | Jump List items opened over a UNC path | T1021.002 SMB / Windows Admin Shares |

### Collection / C2 / Impact / Access
| Module | Evidence | Technique |
|---|---|---|
| `network` | Established connections, DNS cache | T1071 Application Layer Protocol (C2) |
| `usb` | USBSTOR device history | T1091 Replication Through Removable Media · T1200 Hardware Additions |
| `shadow` | Volume Shadow Copy state | T1490 Inhibit System Recovery |
| `useractivity` | Non-revocation URL cached by the crypto stack (`certutil -urlcache`) | T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode |
| `useractivity` | Command typed into the Run dialog | T1059 Command and Scripting Interpreter |
| `useractivity` | Script or double-extension file started from the shell | T1204.002 User Execution: Malicious File |

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
| `process` | Command line that looks like a reverse shell or pipe-to-shell | T1059.004 Unix Shell |
| `persistence` | Cron entry or systemd unit starting from `/tmp`, `/dev/shm`, `/var/tmp` | T1053.003 Cron · T1543.002 Systemd Service |
| `persistence` | Non-empty `/etc/ld.so.preload` | T1574.006 Dynamic Linker Hijacking |
| `persistence` | Download-and-run or reverse-shell line in a shell startup file | T1546.004 Unix Shell Configuration Modification |
| `users` | sudoers `NOPASSWD` | T1548.003 Sudo and Sudo Caching |
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
| `useractivity` | UserAssist, MUICache, RunMRU | Per-user execution history (current user only) |
| `useractivity` | Jump Lists (paths extracted, AppID not decoded) | Per-application file-access history |
| `useractivity` | CryptnetUrlCache | URLs fetched through the crypto stack |
| `rmm` | AnyDesk / TeamViewer connection logs | Who connected to this host, and when |
| `motw` | Zone.Identifier alternate data stream | Where a downloaded file came from (NTFS-only; absence proves nothing) |

---

*ATT&CK® is a registered trademark of The MITRE Corporation. Technique IDs are used here
for reference only.*

---

<a id="монгол"></a>

## 🇲🇳 Монгол хувилбар

TATAR бол **илрүүлэх / мөрдөн шалгах** хэрэгсэл. Доорх хүснэгт нь цуглуулагч
модуль бүрийг, тухайн модулийн барьж авдаг нотолгоо нь ямар ATT&CK техникийг
дэмжихтэй нь холбож харуулна. Ингэснээр шинжээч, SOC баг нь артефактаас шууд
техник рүү шилжиж чадна.

> Энэ зураглал нь triage-ийн **чиглүүлэг** — артефакт байгаа нь техник
> хэрэглэгдсэний нотолгоо БИШ. Үргэлж бусад эх сурвалжаар баталгаажуулаарай.

Цуглуулагчийн `summary.json` → `findings[].technique`-д бичиж чадах техникийн ID
бүр доор жагссан байх ёстой; эс бөгөөс CI унана
(`.github/scripts/check_docs_parity.py`). Урвуу нь зориудаар үнэн БИШ: модуль нь
finding үүсгэхгүйгээр техникийн *нотолгоог* л барьж болно.

Модулийн нэр ба ATT&CK-ийн ID/нэрийг англиар үлдээв — эдгээр нь орчуулагддаггүй
тодорхойлогч юм.

### Tactic-аар (Windows — `Tatar.ps1`)

#### Execution
| Модуль | Барьдаг нотолгоо | Техник |
|---|---|---|
| `process` | Процессийн мод + командын мөр; LOLBAS тэмдэглэгээ (`powershell`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `wmic`, `-enc`, `DownloadString`…) | T1059 Command and Scripting Interpreter · T1059.001 PowerShell |
| `process` | `cmd.exe`-ийн командын мөр | T1059.003 Windows Command Shell |
| `process` | `wscript` / `cscript`-ийн командын мөр | T1059.005 Visual Basic · T1059.007 JavaScript |
| `process` | Хүлээгдээгүй эцэг → хүүхэд гинж (ж: Office → shell) | T1055 Process Injection |
| `process` | `certutil` / `bitsadmin`-ийн татаж авах командын мөр | T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode |
| `eventlogs` | 4688 процесс үүсэлт, 4104 PowerShell script block | T1059 |
| `lateral` | PsExec-ийн service артефакт (`PSEXESVC`) | T1569.002 Service Execution |
| `lateral` | WMI (`__EventFilter`, `CommandLineEventConsumer`) | T1047 Windows Management Instrumentation |

#### Persistence
| Модуль | Нотолгоо | Техник |
|---|---|---|
| `persistence` | HKCU/HKLM Run / RunOnce түлхүүр, Startup | T1547.001 Registry Run Keys / Startup Folder |
| `persistence` | `Users\Public`, `Windows\Temp`, хэрэглэгчийн Temp, Downloads, Recycle Bin-аас эхлэх Run key, Startup folder, scheduled task | T1547.001 · T1053.005 Scheduled Task |
| `persistence` | Дууссаны дараа програм ажиллуулдаг BITS job | T1197 BITS Jobs |
| `persistence` | Татаж авах/декод хийх хэв маягтай PowerShell profile | T1546.013 PowerShell Profile |
| `firewall` | Defender бодит цагийн хамгаалалт унтраалттай; эрсдэлтэй хавтас дахь exclusion | T1562.001 Disable or Modify Tools |
| `persistence` | Microsoft-ийн бус төлөвлөгдсөн даалгавар | T1053.005 Scheduled Task |
| `services` | Service-ийн нэр / binary / эхлэх горим | T1543.003 Windows Service |
| `lateral` | WMI event subscription-ээр тогтвортой байх | T1546.003 WMI Event Subscription |
| `persistence` | Image File Execution Options (IFEO) debugger | T1546.012 IFEO Injection |
| `persistence` | `AppInit_DLLs` | T1546.010 AppInit DLLs |
| `persistence` | `AppCertDLLs` | T1546.009 AppCert DLLs |
| `persistence` | Winlogon `Shell` / `Userinit` | T1547.004 Winlogon Helper DLL |
| `persistence` | LSA-гийн authentication / notification package | T1547.005 Security Support Provider · T1556.002 Password Filter DLL |
| `persistence` | Print Processor / Monitor | T1547.012 Print Processors |
| `persistence` | COM hijack — HKCU **ба** HKLM хоёуланд бүртгэгдсэн CLSID | T1546.015 COM Hijacking |
| `persistence` | Хэрэглэгч бичих боломжтой байрлалын netsh helper DLL | T1546.007 Netsh Helper DLL |
| `persistence` | Хэрэглэгч бичих боломжтой байрлалаас үйлчилж буй protocol handler / filter | T1546.015 COM Hijacking · T1112 Modify Registry |
| `autoruns` | Sysinternals Autoruns (бүх ASEP) | олон (T1547, T1037, …) |

#### Privilege Escalation
| Модуль | Нотолгоо | Техник |
|---|---|---|
| `privesc` | Хашилтгүй, зайтай service зам | T1574.009 Path Interception (unquoted path) |
| `privesc` | Хэрэглэгч бичиж чадах хавтас дахь service binary | T1574.010 Services File Permissions Weakness |
| `privesc` | `AlwaysInstallElevated` (HKLM/HKCU) | T1548 Abuse Elevation Control Mechanism · T1548.002 Bypass UAC |
| `privesc` | Бусад локал эрх ахиулах эмзэг байдал | T1068 Exploitation for Privilege Escalation |
| `privesc` | Token-ий эрхүүд (`whoami /priv`) | T1134 Access Token Manipulation |

#### Defense Evasion
| Модуль | Нотолгоо | Техник |
|---|---|---|
| `obfscan` | Скрипт доторх Base64 / `-enc` / IEX / DownloadString; `.vbs .vbe .js .jse .wsf .hta`-д мөн WinHttp / MSXML2.XMLHTTP / ADODB.Stream татах үйлдэл ба hex эсвэл base64-ээр бичсэн URL | T1027 Obfuscated Files or Information · T1140 Deobfuscate/Decode |
| `process` | Ажиллаж буй command line, PowerShell history эсвэл 4688 event дэх hex эсвэл base64-ээр бичсэн URL | T1027 Obfuscated Files or Information · T1140 Deobfuscate/Decode |
| `eventlogs` | Event ID 1102 (Security лог цэвэрлэгдсэн) | T1070.001 Clear Windows Event Logs |
| `network` | `hosts` файлын өөрчлөлт (`hosts.txt`, стандарт бус бичлэг тэмдэглэгдэнэ) | T1565.001 Stored Data Manipulation |
| `process` | `mshta` / `regsvr32` / `rundll32`-оор дамжуулан ажиллуулах | T1218.005 Mshta · T1218.010 Regsvr32 · T1218.011 Rundll32 |
| `indicators` | temp/appdata доторх гүйцэтгэх файл; хэрэглэгч бичиж чадах зам дахь service | T1036 Masquerading · T1574 Hijack Execution Flow · T1105 Ingress Tool Transfer |

#### Credential Access
| Модуль | Нотолгоо | Техник |
|---|---|---|
| `hives` | SAM / SECURITY hive-ийн хуулбар | T1003.002 Security Account Manager |
| `hives` | LSA secret-ийн материал | T1003.001 LSASS Memory (offline) |
| `process` | Ажиллаж буй command line, PowerShell history эсвэл 4688 event дэх өөр програмын credential dump (comsvcs.dll MiniDump, LSASS-ийн эсрэг ProcDump) | T1003.001 LSASS Memory |
| `browser` | Login Data / нууц үгийн сангийн metadata | T1555.003 Credentials from Web Browsers |
| `browser` | Cookie / session-ийн артефакт | T1539 Steal Web Session Cookie |
| `sessions` | 4625 амжилтгүй нэвтрэлтийн хэмжээ | T1110 Brute Force |
| `users` | Нууц үг шаардахгүй локал бүртгэл | T1078 Valid Accounts |

#### Lateral Movement
| Модуль | Нотолгоо | Техник |
|---|---|---|
| `rdp` | 4624 (LogonType 10), 4778/4779, TS Operational лог, client MRU | T1021.001 Remote Desktop Protocol |
| `lateral` | SMB session, холбогдсон драйв, admin share | T1021.002 SMB / Windows Admin Shares |
| `lateral` | Бусад алсын үйлчилгээний артефакт | T1021 Remote Services |
| `rmm` | Remote monitoring & management агент оршин байгаа эсэх, холболтын түүх | T1219 Remote Access Software |
| `motw` | Интернетээс ирснийг заасан Zone.Identifier-тэй executable/контейнер, URL-тай нь | T1189 Drive-by Compromise · T1566.001 Spearphishing Attachment |
| `motw` | VBA macro агуулсан Office баримт, байтаар нь танисан (хэзээ ч нээгдэхгүй) | T1204.002 User Execution: Malicious File · T1566.001 Spearphishing Attachment |
| `useractivity` | Jump List-д UNC замаар нээсэн зүйл | T1021.002 SMB / Windows Admin Shares |

#### Collection / C2 / Impact / Access
| Модуль | Нотолгоо | Техник |
|---|---|---|
| `network` | Тогтсон холболт, DNS кэш | T1071 Application Layer Protocol (C2) |
| `usb` | USBSTOR төхөөрөмжийн түүх | T1091 Replication Through Removable Media · T1200 Hardware Additions |
| `shadow` | Volume Shadow Copy-ийн төлөв | T1490 Inhibit System Recovery |
| `useractivity` | Crypto stack-ийн кэшэд revocation биш URL (`certutil -urlcache`) | T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode |
| `useractivity` | Run цонхонд бичигдсэн команд | T1059 Command and Scripting Interpreter |
| `useractivity` | Shell-ээс ажиллуулсан скрипт эсвэл давхар өргөтгөлтэй файл | T1204.002 User Execution: Malicious File |

### Tactic-аар (Linux — `linux/tatar-linux.sh`)

Linux хувилбар нь өөрийн модулийн багцаас finding үүсгэнэ. Зураглал нь
`map_technique()` дотор — Linux талын цорын ганц эх сурвалж.

| Модуль | Нотолгоо / finding | Техник |
|---|---|---|
| `process` | `/tmp`, `/dev/shm`, `/var/tmp`, `/run`-аас ажиллаж буй процесс | T1059 Command and Scripting Interpreter |
| `process` | Дискнээс УСТГАГДСАН binary-тай ажиллаж буй процесс | T1620 Reflective Code Loading · T1070.004 File Deletion |
| `network` | `/etc/hosts`-ийн нэмэлт бичлэг (статик host даралт) | T1565.001 Stored Data Manipulation |
| `sessions` | `lastb` амжилтгүй нэвтрэлтийн хэмжээ, auth-log дахь brute force | T1110 Brute Force |
| `users` | UID 0-тэй хоёр дахь бүртгэл | T1136 Create Account · T1078 Valid Accounts |
| `users` | `/etc/shadow` дотор ХООСОН нууц үгтэй бүртгэл | T1078 Valid Accounts |
| `persistence` | Сэжигтэй `cron` / `cron.d` / хэрэглэгчийн crontab команд | T1053.003 Cron |
| `process` | Reverse shell эсвэл pipe-to-shell төст командын мөр | T1059.004 Unix Shell |
| `persistence` | `/tmp`, `/dev/shm`, `/var/tmp`-аас эхэлдэг cron бичлэг эсвэл systemd unit | T1053.003 Cron · T1543.002 Systemd Service |
| `persistence` | Хоосон биш `/etc/ld.so.preload` | T1574.006 Dynamic Linker Hijacking |
| `persistence` | Shell startup файл дахь татаж ажиллуулах эсвэл reverse shell мөр | T1546.004 Unix Shell Configuration Modification |
| `users` | sudoers `NOPASSWD` | T1548.003 Sudo and Sudo Caching |
| `suid` | Стандарт замаас гадуурх SUID/SGID binary | T1548.001 Setuid and Setgid |
| `sshkeys` | `root`-ийн `authorized_keys`, `sshd_config`-ийн түлхүүрийн тохиргоо | T1098.004 SSH Authorized Keys |
| `bashhistory` | Анхаарал татах shell-ийн түүхийн команд (`curl`, `chattr`, `history -c`…) | T1552.003 Bash History |
| `indicators` | Бүх хэрэглэгч бичиж чадах системийн файл | T1222.002 Linux and Mac File and Directory Permissions Modification |
| `indicators` | `/tmp`, `/dev/shm`, `/var/tmp` доторх гүйцэтгэх файл | T1036 Masquerading |
| `containers` | TATAR container ДОТОР ажиллаж байна (finding-ийн ангилал `context`) | T1610 Deploy Container |

Зөвхөн нотолгоо цуглуулдаг (finding үүсгэдэггүй) Linux модулиуд: `sysinfo`,
`services`, `apps`, `kernelmods`, `hashes`, `logs`, `timeline`, `integrity`.

#### IOC engine-ийн үүсгэдэг finding

`--ioc` feed өгөгдсөн үед *Pass B* нь цуглуулсан нотолгоо дотроос олдсон
индикатор бүрт finding үүсгэнэ. Тэр finding нь цуглуулагч модультай холбогдоогүй
тул техник нь таарсан **индикаторын төрлөөр** тодорхойлогдоно:

| Индикатор | Техник |
|---|---|
| `ips[]` | T1071 Application Layer Protocol |
| `domains[]` | T1071.004 Application Layer Protocol: DNS |
| `filenames[]` | T1204.002 User Execution: Malicious File |
| `hashes[]` | T1588.001 Obtain Capabilities: Malware |

v1.2.5 хүртэл эдгээр бүгд `T1071` гэж тэмдэглэгддэг байсан нь файлын нэр, hash-д
буруу — буруу зураглал нь зураглалгүй байхаас дор тул одоо төрөл нь шийднэ.

### Нотолгоо / гүйцэтгэлийн түүхийн эх сурвалж (олон техникийг дэмжинэ)

| Модуль | Артефакт | Хэрэглээ |
|---|---|---|
| `prefetch` | `*.pf` | Програм ажилласан түүх |
| `fsartifacts` | Amcache, Recent, LNK, JumpLists | Гүйцэтгэл / файлд хандсан түүх |
| `deleted` | Хогийн сав ($I metadata) | Устгагдсан файл сэргээх сэжүүр |
| `mft` | NTFS/MFT мэдээлэл | Timeline / anti-forensics контекст |
| `hashes` | Ажиллаж буй/service binary-ийн SHA-256 | IOC / VirusTotal тулгалт |
| `timeline` | Нэгтгэсэн CSV (процесс, prefetch, recent, суулгацууд) | Хөнгөн super-timeline |
| `useractivity` | UserAssist, MUICache, RunMRU | Хэрэглэгчийн гүйцэтгэлийн түүх (зөвхөн одоогийн хэрэглэгч) |
| `useractivity` | Jump List (замыг нь гаргана, AppID-г тайлахгүй) | Апп тус бүрийн файлд хандсан түүх |
| `useractivity` | CryptnetUrlCache | Crypto stack-аар татагдсан URL |
| `rmm` | AnyDesk / TeamViewer холболтын лог | Энэ хост руу хэн, хэзээ холбогдсон |
| `motw` | Zone.Identifier alternate data stream | Татсан файл хаанаас ирсэн (зөвхөн NTFS; байхгүй нь юу ч нотлохгүй) |

*ATT&CK® нь The MITRE Corporation-ы бүртгэлтэй барааны тэмдэг. Техникийн ID-г энд
зөвхөн лавлагаа болгон ашиглав.*
