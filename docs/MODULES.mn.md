# Модуль ба ATT&CK тэмдэглэгээ

[English](MODULES.md) · [← README](../README.mn.md)

## Модулиуд

**Windows (33):** memory · network · process · sessions · services · sysinfo · users · persistence · autoruns · shares · firewall · drivers · apps · prefetch · usb · pshistory · obfscan · rdp · lateral · privesc · browser · fsartifacts · deleted · shadow · eventlogs · hives · mft · indicators · rmm · useractivity · motw · hashes · timeline

**Linux (18):** sysinfo · network · process · sessions · users · services · persistence · apps · suid · sshkeys · bashhistory · kernelmods · indicators · hashes · logs · timeline · containers · integrity

Хамрах хүрээ: систем/хэрэглэгч/сүлжээний төлөв, LOLBAS command-line флагтай процессууд, process genealogy, persistence (Run keys, scheduled tasks, IFEO/AppInit/LSA/Winlogon ASEP-ууд), RDP/lateral movement, privilege-escalation индикатор, обфускаци скан, browser artifact мета, Recent/Amcache/Prefetch, shadow copy, чухал Windows event ID, NTFS/MFT, IOC-д зориулсан file hashing, remote access/RMM-ийн оршин байдал **ба холболтын түүх**, хэрэглэгчийн гүйцэтгэлийн нотолгоо (UserAssist, MUICache, RunMRU, Jump List), crypto stack-аар татсан файлын ул мөр, Mark-of-the-Web (аль файл интернетээс ирсэн, ямар URL-аас), super-timeline. Linux талд: cron/systemd persistence, SUID/SGID, SSH түлхүүр, container/cloud context, чухал файлын integrity baseline гэх мэт — дэлгэрэнгүйг [`linux/README.md`](../linux/README.md)-ийн монгол хэсгээс үз.

## IOC feed хаана шалгагддаг вэ

IOC feed нь модуль биш. Бүх модуль дууссаны дараа нэг удаа, finding болон энэ run-ийн цуглуулсан текст дээр хэрэглэгддэг тул модуль бүр feed-ийн талаар юу ч мэдэх шаардлагагүй. Таарах хоёр эх үүсвэр бий. **Finding-тэй:** finding-ийн текстэд indicator (IP, domain, файлын нэр) байх, эсвэл finding-ийн нэрлэсэн, одоо ч байгаа файлын SHA-256 нь feed-ийн hash-тай тэнцүү байх. Тэр finding өөрийн identity-гээ хадгалсан хэвээр High, confidence 0.95, `iocMatch: true` болж, indicator нь `iocIndicator`-д орно, allowlist үүнийг цаашид нуухгүй. **Evidence-тэй:** энэ run-ийн `.txt`, `.csv`, `.log` файлуудын (`summary.txt`-ээс бусад) аль нэг газарт indicator байх, жишээ нь process жагсаалтын command line эсвэл `binary_hashes.txt`-ийн мөр; энэ нь indicator-ийг нэрлэсэн шинэ finding үүсгэнэ. Hash нь зөвхөн run-ийн hash хийсэн (ажиллаж буй болон service-ийн binary) эсвэл finding-ийн нэрлэсэн файлтай таарна, диск дээрх бүх файлтай биш. Feed-ийн текстийг хэзээ ч ажиллуулдаггүй, итгэдэггүй: үгийн хилээр тулгана (`127.0.0.1` нь `127.0.0.10`-тай таарахгүй), гаралтын файлд орохын өмнө цэвэрлэнэ. Уншигдахгүй feed зам эхэнд мэдэгдэж, run exit code 2-оор дуусна.

## Finding үүсгэдэг persistence ба тохиргооны шалгалтууд

Windows: autostart бичлэг (Run key, Startup folder, scheduled task) нь `Users\Public`, `Windows\Temp`, хэрэглэгчийн Temp эсвэл Downloads хавтас, Recycle Bin-аас програм эхлүүлбэл шалгахаар тэмдэглэгдэнэ (T1547.001, T1053.005); AppData ба ProgramData-г оруулаагүй, учир нь жирийн програмууд эндээс эхэлдэг. `firewall` модуль Defender-ийн бодит цагийн хамгаалалт болон exclusion-ийг тайлагнана (exclusion унших нь Administrator эрх шаардана). `rdp` модуль сүлжээний түвшний нэвтрэлтгүй (NLA) идэвхтэй RDP-г тэмдэглэнэ (T1021.001). `persistence` модуль дууссаны дараа програм ажиллуулдаг BITS job (T1197) болон татаж авах/декод хийх хэв маягтай PowerShell profile-ийг тэмдэглэнэ (T1546.013).

Linux: `process` модуль reverse shell эсвэл pipe-to-shell төст командын мөрийг; `persistence` модуль түр хавтсаас эхэлдэг cron бичлэг ба systemd unit, хоосон биш `/etc/ld.so.preload` (High, T1574.006), shell startup файлын сэжигтэй мөрийг; `indicators` модуль sudoers дахь `NOPASSWD`-ийг тэмдэглэнэ (root-гүйгээр уншигдахгүй бол тэмдэглэл үлдээнэ).

## MITRE ATT&CK тэмдэглэгээ

Collector бүр нь халдагчийн аль техникийг **илрүүлэх / шинжлэхэд** туслах үүднээс ATT&CK-тай холбогдоно. Дэлгэрэнгүйг [`docs/MITRE_ATTACK.md`](MITRE_ATTACK.md)-аас үзнэ үү.

| Модуль / artifact | ATT&CK technique | Tactic |
|---|---|---|
| `process` (LOLBAS command line) | T1059 · T1059.001 (PowerShell) | Execution |
| `persistence` (Run key) | T1547.001 | Persistence |
| `persistence` (scheduled task) | T1053.005 | Persistence |
| `services` | T1543.003 | Persistence / Priv Esc |
| `rdp` | T1021.001 (RDP) | Lateral Movement |
| `lateral` (SMB share / session) | T1021.002 | Lateral Movement |
| `lateral` (WMI event subscription) | T1546.003 · T1047 | Persistence / Execution |
| `lateral` (PsExec) | T1569.002 | Execution |
| `hives` (SAM / SECURITY / LSASS) | T1003.002 · T1003.001 | Credential Access |
| `privesc` (хашилтгүй service зам) | T1574.009 | Persistence / Priv Esc |
| `privesc` (AlwaysInstallElevated) | T1548 | Privilege Escalation |
| `obfscan` | T1027 · T1140 | Defense Evasion |
| `usb` | T1091 · T1200 | Initial Access / Exfil |
| `eventlogs` (ID 1102) | T1070.001 (event log цэвэрлэх) | Defense Evasion |
| `shadow` | T1490 (сэргээлтийг хаах) | Impact |
| `network` (холболт, DNS, `hosts` файл) | T1071 · T1565.001 | C2 / Defense Evasion |
| `browser` | T1555.003 · T1539 | Credential Access |
