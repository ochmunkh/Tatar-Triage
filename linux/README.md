# TATAR Triage Toolkit — Linux edition

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2-blue" alt="v1.2">
  <img src="https://img.shields.io/badge/shell-bash%205.1%2B-4EAA25?logo=gnubash&logoColor=white" alt="Bash 5+">
  <img src="https://img.shields.io/badge/targets-Debian%2FUbuntu%20%C2%B7%20RHEL%2FCentOS-orange" alt="targets">
  <img src="https://img.shields.io/badge/modules-18-5eead4" alt="18 modules">
  <img src="https://img.shields.io/badge/read--only-first-14b8a6" alt="read-only first">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="MIT">
</p>

`tatar-linux.sh` is the Linux companion to the Windows `Tatar.ps1` collector. It performs a fast, single-file, read-only-first DFIR triage of a Linux host and produces the **same analyst-first outputs** as the Windows edition — including an identical `summary.json` schema, so findings from Windows and Linux hosts flow into the same SIEM / pipeline.

Single Bash file, no install, no dependencies beyond coreutils. Drop it on the host (or a USB), run it, done.

---

## Requirements

- Bash 4+ (5.x recommended) and standard coreutils
- Debian / Ubuntu **or** RHEL / CentOS / Fedora (other distros mostly work too)
- **root** recommended — some artifacts (`/etc/shadow`, full process/exe links, all logs) need privilege
- Optional: `python3` (only used to pretty-escape JSON; a `sed` fallback is built in)

---

## Usage

```bash
# make it executable once
chmod +x tatar-linux.sh

# run everything (order of volatility)
sudo ./tatar-linux.sh --all

# list available modules (no collection)
./tatar-linux.sh --list

# check the plan before touching the disk: output path, module order, armed
# gated operations, allowlist / IOC readability. Writes nothing.
sudo ./tatar-linux.sh --all --dry-run --output /mnt/usb/evidence --allowlist allowlist.json

# run selected modules only
sudo ./tatar-linux.sh --modules network,process,persistence,sshkeys

# full run to external media, with case metadata, compressed + hashed
sudo ./tatar-linux.sh --all --output /mnt/usb/evidence \
     --caseid IR-2026-014 --examiner "Enkhbat.O" --compress

# v1.2: cut noise with an allowlist and check the evidence against an IOC feed
sudo ./tatar-linux.sh --all --allowlist allowlist.json --ioc ioc.json --output /mnt/usb/evidence

# automated / remote run: no console output, check exit code
sudo ./tatar-linux.sh --all --silent --output /mnt/usb/evidence
if [ $? -ne 0 ]; then echo "TATAR finished with issues - check tatar.log"; fi
```

### Options

| Option | Description |
|--------|-------------|
| `--all` | Run all modules |
| `--modules a,b,c` | Run only the named modules |
| `--list` | List modules and exit |
| `--help` | Show help and exit |
| `--output <path>` | Output base dir (default `/tmp/forensic`; **prefer external media**) |
| `--caseid <id>` | Case / incident ID for chain of custody |
| `--examiner <name>` | Examiner name for chain of custody |
| `--compress` | `tar.gz` + SHA-256 the output at the end |
| `--silent` / `--quiet` | Suppress **all** console output (SSH / cron / remote runs) |
| `--dry-run` / `--preview` | Print the resolved output directory, the module list in run order, which gated operations are armed and whether the allowlist / IOC feeds can be read — then exit `0` **without creating or writing anything** |
| `--dump-deleted` | Recover deleted running binaries via `/proc/PID/exe` (opt-in; **off by default**, read-only-first) |
| `--allowlist <json>` | **v1.2** Suppress known-good findings by path glob, SHA-256 or dpkg/rpm package ownership (see below) |
| `--ioc <json>` | **v1.2** Match findings and collected evidence against an offline IOC feed (see below) |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Collection completed successfully |
| `1` | Fatal / usage error (nothing selected, a value-taking flag with no value, output dir cannot be created, no valid modules) |
| `2` | Collection completed, but one or more steps logged errors — check `tatar.log`. An unreadable `--allowlist` / `--ioc` path lands here, as does an unknown option or an unknown module name. |

---

## Modules (order of volatility)

`sysinfo` · `network` · `process` · `sessions` · `users` · `services` · `persistence` · `apps` · `suid` · `sshkeys` · `bashhistory` · `kernelmods` · `indicators` · `hashes` · `logs` · `timeline` · `containers` · `integrity`

Coverage: system/kernel info, network sockets & routing & DNS, process tree with **exe-from-/tmp and deleted-binary detection**, logins (`who`/`last`/`lastb`, auth log), users/groups/sudo (**UID-0 & empty-password checks**), systemd services & enabled units, persistence (cron, systemd timers, `rc.local`, profile scripts), installed packages (`dpkg`/`rpm`), **SUID/SGID** enumeration, SSH keys & `sshd_config`, shell history, kernel modules & taint, suspicious indicators (world-writable system files, execs in `/tmp`,`/dev/shm`,`/var/tmp`, recent `/etc` changes, immutable files), SHA-256 of running binaries, key-log copy, and a lightweight file-change timeline. **v1.1** adds container / cloud context (`containers`), a critical-file SHA-256 integrity baseline (`integrity`), established-connection counts, and opt-in recovery of deleted running binaries (`--dump-deleted`).

---

## Allowlist & IOC (v1.2)

Two optional JSON inputs, both offline. Sample files live in the repository root: [`allowlist.sample.json`](../allowlist.sample.json) and [`ioc.sample.json`](../ioc.sample.json).

**`--allowlist <json>`** marks known-good findings as `suppressed` — they stay in `summary.json` / `findings.json` with a `suppressReason` for audit, but leave the headline list. Matching is by `paths[]` (glob, e.g. `/usr/lib/*`), `hashes[]` (SHA-256 of the binary) or, when `"packageOwned": true`, by `dpkg -S` / `rpm -qf` ownership of the finding's binary (vendor-trusted). The Windows-only `publishers[]` key is ignored on Linux, so one allowlist file can serve both editions.

**`--ioc <json>`** is a known-bad feed: `hashes[]` (SHA-256 only), `ips[]`, `domains[]`, `filenames[]`. Pass A annotates existing findings with `iocMatch`; an IOC hit **overrides the allowlist** — a suppressed finding is re-activated and escalated to `High` / confidence `0.95`. Pass B raises new findings for IOCs seen anywhere in the collected evidence (processes, sockets, hashed binaries, timeline), de-duplicated against Pass A and tagged by indicator type — `T1071` for an IP, `T1071.004` for a domain, `T1204.002` for a filename, `T1588.001` for a hash.

Both paths are checked **before collection starts**. A path that cannot be read is never skipped in silence: it warns on the console, is logged as an error, and forces exit code `2`.

A finding is only suppressed when **every** path it names is known-good. Judging it by one token meant an aggregate about files in `/tmp` was hidden because `dpkg -S /tmp` answers `base-files`, and a directory now never satisfies the package-ownership rule.

Findings carry the v2 fields `id`, `confidence`, `suppressed`, `suppressReason`, `iocMatch`; summaries gain `activeFindingsCount` / `suppressedCount` (`schemaVersion 1.2`, backward compatible).

---
## Output

```
<output>/<host>_<YYYY-MM-DD_HH-MM-SS>/
├─ TATAR_Report_<host>_<stamp>.txt   # consolidated human-readable report
├─ summary.txt                       # analyst-first triage summary + findings
├─ summary.json                      # machine-readable (unified schema, SIEM/automation)
├─ findings.json                     # findings-only feed for SOAR / SIEM
├─ tatar.log                         # execution log: START/OK/WARN/FAILED (excluded from manifest)
│                                    # FAILED = that module's primary artifact is MISSING
├─ chain_of_custody.txt              # case / examiner / times / script SHA-256
├─ manifest_sha256.txt               # SHA-256 of every collected file
├─ binary_hashes.txt                 # SHA-256 of running binaries (VT/IOC)
├─ timeline.csv                      # recent file changes
└─ logs/                             # copied auth/syslog/wtmp/btmp where readable
```

The `summary.json` matches the Windows edition (`platform`, `host`, `os`, `stats`, `findings[]` with `severity/category/message/detail` plus the v2 fields `id/confidence/suppressed/suppressReason/iocMatch`), so a single parser ingests both: the `stats` keys and their numeric types are identical on the two platforms, and both editions write `manifest_sha256.txt`, `binary_hashes.txt` and `tatar.log` under the same names and in the same format. Schemas: [`schema/summary.schema.json`](../schema/summary.schema.json) and, for the SOAR feed, [`schema/findings.schema.json`](../schema/findings.schema.json).

---

## Findings are leads, not verdicts

The aggregated **Suspicious findings** list is built from heuristic pattern matches — UID-0 accounts, empty passwords, processes from `/tmp` or deleted binaries, SUID outside standard paths, suspicious cron/history commands, `root` `authorized_keys`, world-writable system files, and so on. Legitimate software and admin activity can trigger these. **Always validate each lead against the full report before drawing conclusions.**

---

## MITRE ATT&CK (selected)

| Module / artifact | Technique |
|---|---|
| `process` (exe in /tmp, deleted binary) | T1059 · T1620 (reflective/fileless) |
| `persistence` (cron / systemd / rc.local) | T1053.003 · T1053.006 · T1037 |
| `users` (UID 0 / empty password) | T1136 · T1078 |
| `suid` | T1548.001 (setuid/setgid) |
| `sshkeys` (authorized_keys) | T1098.004 |
| `bashhistory` | T1552.003 |
| `indicators` (world-writable, /tmp execs) | T1036 · T1222 |
| `network` / `/etc/hosts` | T1071 · T1565.001 |

---

## Handling notes

- **Prefer external media** (`--output /mnt/usb/evidence`). Writing to the host disk can overwrite deleted-file evidence.
- **Do not reboot** the host before collection finishes.
- Output can contain sensitive data (logs, keys, history). Encrypt and transfer securely.
- Transparent by design — review the script, publish its SHA-256, allow-list rather than disabling EDR/AV.

## Known limitations

- Core triage scope (18 modules); not yet a full super-timeline or memory acquisition.
- No `$MFT`-equivalent deep filesystem parsing (use dedicated tools for that).
- Domain / LDAP-joined hosts: local `/etc/passwd` only (no directory enumeration).
- RHEL log paths (`/var/log/secure`, `/var/log/messages`) and `rpm` are handled; very old/minimal distros may lack some tools (steps degrade gracefully and are logged).

## License

MIT (see repository `LICENSE`).

## Author

**Enkhbat.O** — Security Analyst

---

<a id="монгол"></a>

## 🇲🇳 Монгол хувилбар

> Хурдан, нэг файлтай, read-only-first Linux DFIR triage — Windows edition-тэй ижил гаралттай.

`tatar-linux.sh` бол Windows-ийн `Tatar.ps1` collector-ийн Linux хос. Linux хостыг хурдан, read-only-first байдлаар triage хийж, Windows edition-тэй **яг ижил, шинжээч-төвтэй гаралт** үүсгэнэ — `summary.json` schema нь ижил тул Windows, Linux хостын finding нэг л SIEM / pipeline руу ордог.

Ганц Bash файл, суулгах шаардлагагүй, coreutils-аас өөр хамааралгүй. Хост дээр (эсвэл USB-д) хуулж аваад шууд ажиллуулна.

---

## Шаардлага

- Bash 4+ (5.x зөвлөнө) ба стандарт coreutils
- Debian / Ubuntu **эсвэл** RHEL / CentOS / Fedora (бусад distro ихэвчлэн бас ажиллана)
- **root** зөвлөж байна — зарим artifact (`/etc/shadow`, процессын бүтэн exe link, бүх лог) эрх шаарддаг
- Сонголтоор: `python3` (зөвхөн JSON-ийг цэвэр escape хийхэд ашиглана; `sed` fallback дотор нь бий)

---

## Ашиглах

```bash
# нэг удаа executable болгоно
chmod +x tatar-linux.sh

# бүгдийг ажиллуулах (volatility-ийн дарааллаар)
sudo ./tatar-linux.sh --all

# модулиудыг харах (цуглуулга хийхгүй)
./tatar-linux.sh --list

# диск хүрэхээс өмнө төлөвлөгөөг шалгах: гаралтын зам, модулийн дараалал, аль
# gated үйлдэл асаалттай, allowlist / IOC уншигдаж байгаа эсэх. Юу ч бичихгүй.
sudo ./tatar-linux.sh --all --dry-run --output /mnt/usb/evidence --allowlist allowlist.json

# зөвхөн сонгосон модулиуд
sudo ./tatar-linux.sh --modules network,process,persistence,sshkeys

# гадаад зөөвөрлөгч рүү бүтэн run, case мета, шахаж хэшлэсэн
sudo ./tatar-linux.sh --all --output /mnt/usb/evidence \
     --caseid IR-2026-014 --examiner "Enkhbat.O" --compress

# v1.2: allowlist-ээр дуу чимээг тайрч, нотолгоог IOC feed-тэй тулгана
sudo ./tatar-linux.sh --all --allowlist allowlist.json --ioc ioc.json --output /mnt/usb/evidence

# автомат / алсын run: консол гаралтгүй, exit code-оор шалгана
sudo ./tatar-linux.sh --all --silent --output /mnt/usb/evidence
if [ $? -ne 0 ]; then echo "TATAR finished with issues - check tatar.log"; fi
```

### Флагууд

| Флаг | Тайлбар |
|--------|-------------|
| `--all` | Бүх модулийг ажиллуулна |
| `--modules a,b,c` | Зөвхөн нэрлэсэн модулиудыг ажиллуулна |
| `--list` | Модулиудыг жагсаагаад гарна |
| `--help` | Тусламж хэвлээд гарна |
| `--output <зам>` | Гаралтын үндсэн хавтас (default `/tmp/forensic`; **гадаад зөөвөрлөгчийг илүүд үз**) |
| `--caseid <id>` | Chain of custody-д бичих case / incident ID |
| `--examiner <нэр>` | Chain of custody-д бичих шинжээчийн нэр |
| `--compress` | Төгсгөлд нь гаралтыг `tar.gz` болгож SHA-256 авна |
| `--silent` / `--quiet` | Консолын **бүх** гаралтыг дарна (SSH / cron / алсын run-д) |
| `--dry-run` / `--preview` | Тодорхойлсон гаралтын хавтас, модулиудыг ажиллах дарааллаар нь, аль gated үйлдэл асаалттайг, allowlist / IOC feed уншигдаж байгаа эсэхийг хэвлээд `0`-ээр гарна — **юу ч үүсгэхгүй, юу ч бичихгүй** |
| `--dump-deleted` | Ажиллаж байгаа устгагдсан binary-г `/proc/PID/exe`-ээс сэргээнэ (opt-in; **default-оор унтраалттай**, read-only-first) |
| `--allowlist <json>` | **v1.2** Мэдэгдэж байгаа цэвэр finding-ийг зам, SHA-256, эсвэл dpkg/rpm багцын эзэмшлээр нууна (доор үз) |
| `--ioc <json>` | **v1.2** Finding болон цуглуулсан нотолгоог офлайн IOC feed-тэй тулгана (доор үз) |

### Exit code

| Code | Утга |
|------|---------|
| `0` | Цуглуулга амжилттай дууссан |
| `1` | Fatal / usage алдаа (юу ч сонгоогүй, утга шаардах флаг утгагүй, гаралтын хавтас үүсгэж чадаагүй, хүчинтэй модуль алга) |
| `2` | Цуглуулга дууссан ч нэг буюу хэд хэдэн алхам алдаа бүртгүүлсэн — `tatar.log`-ийг шалга. Уншигдахгүй `--allowlist` / `--ioc` зам, танигдахгүй флаг, байхгүй модулийн нэр энд унана. |

---

## Модулиуд (volatility-ийн дарааллаар)

`sysinfo` · `network` · `process` · `sessions` · `users` · `services` · `persistence` · `apps` · `suid` · `sshkeys` · `bashhistory` · `kernelmods` · `indicators` · `hashes` · `logs` · `timeline` · `containers` · `integrity`

Хамрах хүрээ: систем/kernel мэдээлэл, сүлжээний socket · routing · DNS, **`/tmp`-ээс ажиллаж буй ба устгагдсан binary-г илрүүлдэг** process tree, нэвтрэлт (`who`/`last`/`lastb`, auth лог), хэрэглэгч/бүлэг/sudo (**UID-0 ба хоосон нууц үгийн шалгалт**), systemd service ба enabled unit, persistence (cron, systemd timer, `rc.local`, profile скрипт), суулгасан багц (`dpkg`/`rpm`), **SUID/SGID** жагсаалт, SSH түлхүүр ба `sshd_config`, shell history, kernel модуль ба taint, сэжигтэй индикатор (бүгд бичиж чадах системийн файл, `/tmp`·`/dev/shm`·`/var/tmp` доторх exec, `/etc`-д саяхан орсон өөрчлөлт, immutable файл), ажиллаж буй binary-ийн SHA-256, чухал логийн хуулбар, файлын өөрчлөлтийн хөнгөн timeline. **v1.1**-д container / cloud context (`containers`), критикал файлын SHA-256 integrity baseline (`integrity`), established холболтын тоо, ажиллаж байгаа устгагдсан binary-г сэргээх сонголт (`--dump-deleted`) нэмэгдсэн.

---

## Allowlist ба IOC (v1.2)

Хоёр нэмэлт JSON оролт, хоёул офлайн. Жишээ файлууд repository-ийн үндсэн хавтсанд байна: [`allowlist.sample.json`](../allowlist.sample.json) ба [`ioc.sample.json`](../ioc.sample.json).

**`--allowlist <json>`** нь мэдэгдэж байгаа цэвэр finding-ийг `suppressed` гэж тэмдэглэнэ — тэдгээр нь `suppressReason`-тойгоо `summary.json` / `findings.json`-д аудитын төлөө үлдэх ба зөвхөн үндсэн жагсаалтаас гарна. Тулгалт нь `paths[]` (glob, жишээ нь `/usr/lib/*`), `hashes[]` (binary-ийн SHA-256), эсвэл `"packageOwned": true` үед finding-ийн binary-г `dpkg -S` / `rpm -qf` эзэмшдэг эсэхээр (vendor-д итгэсэн) явагдана. Windows-д л хамаарах `publishers[]` түлхүүрийг Linux дээр үл тоомсорлоно — тиймээс нэг allowlist файл хоёр edition-д хоёуланд нь тохирно.

**`--ioc <json>`** бол known-bad feed: `hashes[]` (зөвхөн SHA-256), `ips[]`, `domains[]`, `filenames[]`. *Pass A* нь одоо байгаа finding-уудыг `iocMatch`-аар тэмдэглэнэ; IOC таарвал **allowlist-ийг давж**, нууцалсан finding дахин идэвхжиж `High` / confidence `0.95` болно. *Pass B* нь цуглуулсан нотолгооны хаанаас ч (процесс, socket, хэшлэсэн binary, timeline) олдсон IOC-д зориулж шинэ finding үүсгэх ба Pass A-тай давхцуулахгүй, technique-ийг indicator-ийн төрлөөр тавина — IP → `T1071`, domain → `T1071.004`, filename → `T1204.002`, hash → `T1588.001`.

Хоёр замыг **цуглуулга эхлэхээс өмнө** шалгана. Уншигдахгүй замыг чимээгүй өнгөрөөхгүй: консол дээр сануулж, error бүртгэж, exit code-ийг `2` болгоно.

Finding нь өөрийн нэрлэсэн **бүх** зам цэвэр гэж батлагдсан үед л suppressed болно. Нэг л token-оор дүгнэдэг байсан үед `/tmp` доторх файлуудын тухай нэгтгэсэн finding далдлагдаж байсан — учир нь `dpkg -S /tmp` нь `base-files` гэж хариулдаг; одоо хавтас багцын эзэмшлийн дүрмийг хэзээ ч хангахгүй.

Finding-ууд v2 талбаруудыг (`id`, `confidence`, `suppressed`, `suppressReason`, `iocMatch`) авч явах ба summary-д `activeFindingsCount` / `suppressedCount` нэмэгдэнэ (`schemaVersion 1.2`, хуучинтайгаа нийцтэй).

---
## Гаралт

```
<output>/<host>_<YYYY-MM-DD_HH-MM-SS>/
├─ TATAR_Report_<host>_<stamp>.txt   # нэгдсэн, хүн уншихад зориулсан тайлан
├─ summary.txt                       # шинжээч-төвтэй triage дүгнэлт + findings
├─ summary.json                      # машин уншихуйц (нэгдсэн schema, SIEM/автоматжуулалт)
├─ findings.json                     # findings-only feed (SOAR / SIEM)
├─ tatar.log                         # гүйцэтгэлийн лог: START/OK/WARN/FAILED (manifest-д ороогүй)
│                                    # FAILED = тухайн модулийн үндсэн artifact ДУТУУ байна
├─ chain_of_custody.txt              # case / examiner / цаг / скриптийн SHA-256
├─ manifest_sha256.txt               # цуглуулсан файл бүрийн SHA-256
├─ binary_hashes.txt                 # ажиллаж буй binary-ийн SHA-256 (VT/IOC)
├─ timeline.csv                      # саяхны файлын өөрчлөлт
└─ logs/                             # уншигдахаар байсан auth/syslog/wtmp/btmp-ийн хуулбар
```

`summary.json` нь Windows edition-тэйгээ таарна (`platform`, `host`, `os`, `stats`, `severity/category/message/detail` ба v2 талбарууд `id/confidence/suppressed/suppressReason/iocMatch`-тай `findings[]`) — тиймээс нэг parser хоёуланг уншина: `stats`-ийн түлхүүрүүд болон тэдгээрийн тоон төрөл хоёр платформ дээр ижил, мөн хоёр edition `manifest_sha256.txt`, `binary_hashes.txt`, `tatar.log`-ийг ижил нэрээр, ижил форматаар бичнэ. Schema: [`schema/summary.schema.json`](../schema/summary.schema.json), SOAR feed-д нь [`schema/findings.schema.json`](../schema/findings.schema.json).

---

## Finding бол сэжүүр, эцсийн дүгнэлт биш

Нэгтгэсэн **сэжигтэй finding**-үүдийн жагсаалт нь эвристик pattern match дээр тогтдог — UID-0 account, хоосон нууц үг, `/tmp`-ээс эсвэл устгагдсан binary-аас ажиллаж буй процесс, стандарт замаас гадуурх SUID, сэжигтэй cron/history команд, `root`-ийн `authorized_keys`, бүгд бичиж чадах системийн файл гэх мэт. Хууль ёсны программ, админы ердийн ажил ч эдгээрийг мөн асааж болно. **Дүгнэлт гаргахаасаа өмнө сэжүүр бүрийг бүтэн тайлантай тулгаж үргэлж баталгаажуул.**

---

## MITRE ATT&CK (түүвэр)

| Модуль / artifact | Technique |
|---|---|
| `process` (`/tmp`-ээс ажиллаж буй, устгагдсан binary) | T1059 · T1620 (reflective/fileless) |
| `persistence` (cron / systemd / rc.local) | T1053.003 · T1053.006 · T1037 |
| `users` (UID 0 / хоосон нууц үг) | T1136 · T1078 |
| `suid` | T1548.001 (setuid/setgid) |
| `sshkeys` (authorized_keys) | T1098.004 |
| `bashhistory` | T1552.003 |
| `indicators` (бүгд бичиж чадах, `/tmp` доторх exec) | T1036 · T1222 |
| `network` / `/etc/hosts` | T1071 · T1565.001 |

---

## Анхаарах зүйлс

- **Гадаад зөөвөрлөгч рүү бичихийг зөвлөнө** (`--output /mnt/usb/evidence`). Хостын диск рүү бичвэл устсан файлын ул мөрийг дарж бичиж болзошгүй.
- Цуглуулга дуусахаас өмнө хостыг **restart хийхгүй**.
- Гаралт нь эмзэг мэдээлэл (лог, түлхүүр, history) агуулж болзошгүй. Шифрлэж, аюулгүй дамжуул.
- Ил тод байхаар зохиогдсон — скриптийг нь уншиж шалга, SHA-256-ийг нь нийтэл, EDR/AV-гаа унтраах биш allow-list хий.

## Хязгаарлалт

- Үндсэн triage хүрээ (18 модуль); бүрэн super-timeline, санах ойн acquisition хараахан биш.
- `$MFT`-тэй дүйцэхүйц гүн файлын системийн parse хийхгүй (түүнд тусгай хэрэгсэл ашигла).
- Domain / LDAP-д холбогдсон хост: зөвхөн локал `/etc/passwd` (directory enumeration хийхгүй).
- RHEL-ийн логийн зам (`/var/log/secure`, `/var/log/messages`) ба `rpm`-ийг дэмжинэ; маш хуучин / минимал distro дээр зарим хэрэгсэл байхгүй байж болно (тухайн алхам эвтэйхэн доройтож, лог дээр бүртгэгдэнэ).

## Лиценз

MIT (repository-ийн `LICENSE`-г үзнэ үү).

## Зохиогч

**Enkhbat.O** — Security Analyst
