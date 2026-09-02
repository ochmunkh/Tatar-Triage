<p align="center">
  <img src="banner.png" alt="TATAR Triage Toolkit" width="880">
</p>

<p align="center">
  <b>A fast, single-file Windows DFIR triage & artifact collector written in PowerShell.</b>
</p>
<p align="center">
  <b><a href="README.md">English</a> · <a href="#монгол">Монгол</a></b>
</p>

<p align="center">
  <img src="https://github.com/ochmunkh/Tatar-Triage/actions/workflows/ci.yml/badge.svg" alt="CI">
  <img src="https://img.shields.io/badge/version-1.2-blue" alt="v1.2">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/modules-30-5eead4" alt="30 modules">
  <img src="https://img.shields.io/badge/read--only-first-14b8a6" alt="read-only first">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="MIT">
</p>

---

When an endpoint shows signs of compromise (visited a malicious site, ran a suspicious file, unexplained slowness), you need to preserve evidence *quickly* — without installing or juggling a dozen separate tools. `Tatar.ps1` collects the important volatile and non-volatile artifacts from a Windows host in a single read-only-first pass and produces a consolidated report, an analyst-first **triage summary with aggregated findings**, a full **execution log**, and a SHA-256 manifest for chain of custody.

> Built for first responders and security analysts who need triage logs **fast**, on-scene, with minimal dependencies.

---

## Demo

Run everything with a single command:

<p align="center">
  <img src="docs/screenshot_terminal.png" alt="TATAR Triage Toolkit run" width="840">
</p>

Every run produces a self-contained, hashed evidence folder:

<p align="center">
  <img src="docs/sample_output_tree.png" alt="Output structure" width="840">
</p>

The v1.1 triage summary (`summary.txt`) gives the IR lead a one-page starting point:

<p align="center">
  <img src="docs/sample_summary.png" alt="Triage summary" width="840">
</p>

The consolidated report flags suspicious activity as it goes (sample):

<p align="center">
  <img src="docs/sample_report.png" alt="Sample report" width="840">
</p>

> Screenshots use sample/redacted data.

---

## Highlights

- **One script, no install.** Drop it on the host (or a USB), run it, done.
- **30 modules**, executed in **RFC 3227 order of volatility** (memory → network → processes → … → disk / registry / logs).
- **Analyst-first summary.** Every run writes `summary.txt` + `summary.json`: host/OS/case metadata, quick stats, and an aggregated **Suspicious findings** list — leads for review, *not* verdicts. The JSON feeds straight into SIEM / SOAR pipelines.
- **Execution log.** `Tatar.log` records every module with timestamps and `START / OK / WARN / FAILED` status — clean audit trail, easy troubleshooting.
- **Automation-friendly.** `-Silent` suppresses all console output (WinRM / scheduled / remote runs) and the script returns meaningful **exit codes** (see below).
- **Read-only first.** Destructive / heavy actions (memory dump, hive save, full EVTX) are **off by default** behind explicit switches.
- **Chain of custody.** Per-run metadata, examiner / case ID, and a SHA-256 manifest of every collected file.
- **Transparent by design.** No obfuscation, no AMSI/AV bypass. Meant to be code-signed and allow-listed on the forensic host.
- **Does NOT extract or decrypt passwords.**
- **Cross-platform.** Emits the shared [`summary.schema.json`](schema/summary.schema.json) contract; a [Linux edition](linux/) (`tatar-linux.sh`) produces identical `summary.json` outputs.

---

## Architecture

TATAR ships as two parity editions — `Tatar.ps1` (Windows, 30 modules) and `linux/tatar-linux.sh` (Linux, 18 modules) — behind a single output contract. Both emit the same JSON schema (`schemaVersion 1.2`), so a SIEM/SOAR pipeline ingests either platform identically.

```
                    TATAR Triage
                         │
          ┌──────────────┴──────────────┐
     Windows · Tatar.ps1           Linux · tatar-linux.sh
     (PowerShell, 30 modules)      (Bash, 18 modules)
          └──────────────┬──────────────┘
                         ▼
             Unified JSON schema  (summary.schema.json · v1.2)
                         ▼
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
     summary          findings         timeline
    (+ report)       (SOAR / SIEM)     (+ hashes)
        └────────────────┼────────────────┘
                         ▼
                DFIR investigation
```

### Data flow

1. Parse arguments, create the output folder and chain of custody.
2. Detect the runtime environment (virtualization / container / security module).
3. Run collectors in **order of volatility** (memory · network · process → disk · registry · logs). Each collector writes raw evidence to disk *and* a structured finding in memory.
4. The **allowlist engine** suppresses known-good findings — kept for audit, never deleted.
5. The **IOC engine** annotates known-bad findings, overrides the allowlist, and raises new findings from the collected evidence.
6. Sort into active vs suppressed, then write `summary.txt` / `summary.json`, `findings.json`, and the SHA-256 manifest.

### The findings model

Every finding is a single record, identical across platforms:

`id` · `severity` (High/Review) · `category` · `technique[]` (MITRE) · `message` · `detail` · `confidence` (0.7 High · 0.4 Review · 0.95 IOC-confirmed) · `suppressed` · `suppressReason` · `iocMatch`.

Suppressed findings stay in the report and JSON with a reason — they are only dropped from the active headline count, never from the record. (On Linux the findings pipeline is delimited with the ASCII Unit Separator `0x1F`, not TAB, because `read` collapses whitespace delimiters and would shift columns on empty fields.)

### Allowlist engine — signal over noise

Suppresses known-good findings by **path glob**, **Authenticode publisher** (Windows), **package ownership** via `dpkg`/`rpm` (Linux), or **SHA-256**. On a clean host this took a run from 11 raw findings to **4 active / 7 suppressed**.

### IOC engine — known-bad wins

Takes an offline feed of `hashes / ips / domains / filenames`. *Pass A* matches existing findings and a hit **overrides the allowlist** — it re-activates a suppressed finding and escalates it to High / 0.95. *Pass B* raises new findings for IOCs seen anywhere in the collected evidence (deduplicated against Pass A). The rule is simple: a known-bad indicator always beats a known-good allowlist entry.

### Trust boundaries

No network calls — allowlist and IOC feeds are local files and every hash is computed locally. Read-only first; root/Admin only widens what can be *read*, never what is changed. The script's own SHA-256 is recorded in the chain of custody, and EDR-sensitive actions (memory dump, hive save, deleted-binary carving) are opt-in and off by default.

---

## Requirements

- Windows 10 / 11 (Server 2016+ works too)
- PowerShell 5.1+ (PowerShell 7 supported)
- **Administrator** recommended (some artifacts are incomplete without it)

---

## Usage

```powershell
# Allow the script for the current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Run everything (single- or double-dash both work)
.\Tatar.ps1 -All
.\Tatar.ps1 --all

# List available modules (no collection, no folder created)
.\Tatar.ps1 -List

# Run specific modules only
.\Tatar.ps1 -Modules network,process,rdp,lateral,timeline

# Full run to an external drive, with case metadata, compressed + hashed
.\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Enkhbat.O" -Compress

# Automated / remote run: no console output, check the exit code
.\Tatar.ps1 -All -Silent -OutputPath E:\Evidence -CaseId IR-2026-014
if ($LASTEXITCODE -ne 0) { Write-Warning "TATAR finished with issues - check Tatar.log" }

# Cut the noise: suppress known-good findings with an allowlist
.\Tatar.ps1 -All -Allowlist allowlist.sample.json

# Confirm known-bad: match findings & evidence against an offline IOC feed
.\Tatar.ps1 -All -Allowlist allowlist.sample.json -IOCFile ioc.sample.json
```

### Options

| Option | Description |
|--------|-------------|
| `-All` / `--all` | Run all modules |
| `-Modules a,b,c` | Run only the named modules |
| `-List` | List modules and exit |
| `-Help` | Show help and exit |
| `-OutputPath <path>` | Output base directory (default `C:\Forensic`; **prefer an external drive**) |
| `-CaseId <id>` | Case / incident ID for chain of custody |
| `-Examiner <name>` | Examiner name for chain of custody |
| `-Compress` | Zip + SHA-256 the output at the end |
| `-CollectHives` | Save SAM/SECURITY/SYSTEM/SOFTWARE + NTUSER (credential material; may trigger EDR) |
| `-ExportEvtx` | Export full `.evtx` logs |
| `-MemoryDump` | Raw memory image via `tools\winpmem.exe` (may trigger EDR) |
| `-Silent` / `-Quiet` | Suppress **all** console output (banner, progress, status). Files, including `Tatar.log`, are still written. For WinRM / scheduled / automated runs |
| `-Allowlist <json>` | Suppress known-good findings by path glob, Authenticode publisher, or SHA-256. Suppressed findings are kept for audit, not deleted |
| `-IOCFile <json>` | Match findings & collected evidence against an offline IOC feed (hashes/ips/domains/filenames). A hit **overrides** the allowlist and escalates to High |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Collection completed successfully |
| `1` | Fatal / usage error (nothing selected, output dir cannot be created, no valid modules) |
| `2` | Collection completed, but one or more steps logged errors — check `Tatar.log` |

---

## Modules

Order of volatility, top to bottom:

`memory` · `network` · `process` · `sessions` · `services` · `sysinfo` · `users` · `persistence` · `autoruns` · `shares` · `firewall` · `drivers` · `apps` · `prefetch` · `usb` · `pshistory` · `obfscan` · `rdp` · `lateral` · `privesc` · `browser` · `fsartifacts` · `deleted` · `shadow` · `eventlogs` · `hives` · `mft` · `indicators` · `hashes` · `timeline`

Coverage includes: system/user/network state, running processes with LOLBAS pattern flags, services & drivers, startup/Run-key/scheduled-task persistence, RDP activity, lateral-movement artifacts (SMB sessions, mapped drives, WMI persistence, PsExec), privilege-escalation indicators (unquoted service paths, `AlwaysInstallElevated`, token privileges), obfuscated-script scan, browser artifact metadata (all profiles, no decryption), Recent/Amcache/Prefetch, Recycle Bin, shadow copies, key Windows event IDs, optional registry hive & EVTX export, NTFS/MFT info, file hashing for IOC matching, and a lightweight super-timeline CSV.

---

## Triage summary & findings

Every run ends with an analyst-first one-pager so the IR lead knows **what to look at first**:

- **`summary.txt`** — host / OS / case metadata, quick stats (process count, TCP connections, local users, hashed binaries, …) and the aggregated **Suspicious findings** list, sorted by severity.
- **`summary.json`** — the same data as structured JSON (`stats`, `findings[]` with `Severity/Category/Message/Detail`), ready for SIEM ingestion or scripted post-processing.

Findings come from the collectors themselves: LOLBAS-style command lines, obfuscated-script matches, PsExec artifacts, WMI event-subscription consumers, unquoted / user-writable service paths, `AlwaysInstallElevated`, security-log-cleared (1102) events, executables recently dropped in temp locations, and more.

> **Important:** findings are automated pattern matches — **leads for review, not verdicts**. Legitimate software (updaters, IT tooling) regularly appears; validate each lead against the full report before drawing conclusions.

## Execution log (`Tatar.log`)

Each run writes a timestamped execution log alongside the evidence:

```
[2026-07-10 22:26:16.693] [START ] module sysinfo (1/30)
[2026-07-10 22:26:17.721] [OK    ] module sysinfo finished in 1s
[2026-07-10 22:26:17.751] [START ] module hives (26/30)
[2026-07-10 22:26:17.995] [ERROR ] Hives failed: Access denied
[2026-07-10 22:26:17.996] [WARN  ] module hives finished in 0.2s with 1 error(s)
```

`Tatar.log` is an *operational* log (it keeps growing after the manifest is hashed), so it is deliberately **excluded from `manifest_sha256.csv`**. Evidence files are all hashed as usual.

---

## MITRE ATT&CK mapping

Each collector maps to the adversary techniques it helps **detect / investigate**. Full detail in [`docs/MITRE_ATTACK.md`](docs/MITRE_ATTACK.md).

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
| `network` / `hosts` | T1071 · T1565.001 | C2 / Defense Evasion |
| `browser` | T1555.003 · T1539 | Credential Access |

---

## Output

```
C:\Forensic\<HOST>_<YYYY-MM-DD_HH-mm-ss>\
├─ TATAR_Report_<HOST>_<stamp>.txt   # consolidated human-readable report
├─ summary.txt                       # analyst-first triage summary + findings  (NEW v1.1)
├─ summary.json                      # same, machine-readable (SIEM/automation) (NEW v1.1)
├─ findings.json                     # findings-only feed for SOAR / SIEM              (NEW)
├─ Tatar.log                         # execution log: START/OK/WARN/FAILED      (NEW v1.1)
├─ chain_of_custody.txt              # case/examiner/times/script hash
├─ manifest_sha256.csv               # SHA-256 of every collected file (Tatar.log excluded)
├─ timeline.csv                      # process / prefetch / recent / installs
├─ binary_hashes.csv                 # SHA-256 of running/service binaries (VT/IOC)
├─ recyclebin.csv
├─ arp.txt / routes.txt / dns_cache.txt / ipconfig.txt / hosts.txt
├─ firewall_rules.txt
├─ BrowserArtifacts\ · EventLogs\ · FsArtifacts\ · RDP\ · RegistryHives\ · MFT\
└─ (optional) ..\TATAR_<HOST>_<stamp>.zip (+ .sha256.txt)
```

---

## Handling & operational notes

- **Prefer an external drive** (`-OutputPath E:\Evidence`). Writing to the system drive can overwrite deleted-file evidence.
- **Do not reboot / shut down** the host before collection finishes.
- The output can contain **sensitive data** (registry hives, browser metadata). Encrypt the archive and transfer it securely.
- Some modules (`hives`, `memorydump`, `exportevtx`) are known to trigger EDR/AV. This is expected — **coordinate with your SOC and allow-list the tool in advance** rather than disabling EDR.

### Getting past AV without evading it

This tool is intentionally **transparent** (no obfuscation / AMSI bypass). To run it without AV interference the correct, auditable way:

1. **Code-sign** the script (`Set-AuthenticodeSignature`).
2. **Publish its SHA-256** so responders can verify and allow-list it.
3. On the forensic host, add a **scoped Defender/EDR exclusion** for the tool, and remove it afterward.

`SHA-256 (Tatar.ps1): A69F953AFCE102190DA9928869D380528F6E2BB7E203C66CF46E97187709219B`

---

## Known limitations

- Does **not** extract or decrypt saved passwords.
- Full `$MFT` parsing requires an offline tool (e.g. MFTECmd / RawCopy); the script records NTFS/MFT metadata only.
- Browser artifacts are **metadata only** (no DB execution, no decryption).
- Without Administrator, some artifacts (event logs, hives, protected processes) are incomplete.
- Findings in `summary.txt` / `summary.json` are heuristic pattern matches — expect false positives from legitimate software; always validate.
- `Compress-Archive` on PowerShell 5.1 struggles with very large outputs (e.g. memory images); use 7-Zip for those.

## Optional external tools (`tools\`)

- `winpmem.exe` — memory imaging (for `-MemoryDump`)
- `autoruns64.exe` — Sysinternals Autoruns (for the `autoruns` module)

If present in a `tools\` subfolder they are used automatically; otherwise those steps are skipped.

---

## Changelog

### v1.2.0 — noise reduction & IOC matching (current)
- **Allowlist engine** (`-Allowlist` / `--allowlist`): suppress known-good findings by path glob, Authenticode publisher (Windows), package ownership via `dpkg`/`rpm` (Linux), or SHA-256. Suppressed findings are **kept for audit** with a reason, not deleted. Clean-host testing went from 11 raw findings to **4 active / 7 suppressed**.
- **IOC engine** (`-IOCFile` / `--ioc`): offline `hashes/ips/domains/filenames` feed. *Pass A* annotates findings (`iocMatch`) and a hit **overrides the allowlist** — re-activates + escalates to High/0.95. *Pass B* raises new findings for IOCs seen anywhere in the collected evidence.
- **`findings.json` / `summary.json` schema 1.2**: findings gain `id`, `confidence`, `suppressed`, `suppressReason`, `iocMatch`; summaries gain `activeFindingsCount` / `suppressedCount`. Backward compatible (`schemaVersion` enum, new fields optional).
- **Linux correctness fix**: findings pipeline now uses the ASCII Unit Separator (0x1F) instead of TAB — `read` was collapsing empty fields and shifting columns.
- New **[Architecture](#architecture)** section in this README: system architecture, data flow, findings model, and the allowlist/IOC scoring model.

### Tier 1 hardening (current)
- **Persistence ASEPs**: IFEO Debugger hijack, AppInit_DLLs, AppCertDlls, Winlogon Shell/Userinit, LSA packages, Print monitors (read-only registry).
- **Process genealogy**: parent -> child tree + suspicious-lineage findings (Office/script host spawning a shell).
- **More event IDs**: 4698/4699 (task), 4719 (audit policy), 4648 (explicit creds), 4768/4769/4776 (Kerberos/NTLM), 5140 (share), 4627.
- **`findings.json`** findings-only output for SOAR/SIEM.
- **MITRE sub-techniques** in the mapper (e.g. T1059.001 vs T1059.003, T1218.x LOLBINs, T1546.x ASEPs).
- **Robustness**: winpmem HVCI/empty-image detection; manifest hashing tolerates locked files (`-ErrorAction SilentlyContinue`).
- **Exit-code accuracy**: expected live-system locks (Amcache.hve, active NTUSER.DAT) are now logged as NOTE/WARN (not errors), so a clean run returns exit 0 instead of 2.

### Schema 1.1 — cross-platform (current)
- **Unified `summary.json` schema** ([`schema/summary.schema.json`](schema/summary.schema.json)) now shared with the Linux edition; consumers key off `schemaVersion`.
- Findings carry a **MITRE ATT&CK `technique[]`** array (centralized mapping); the summary shows the IDs inline.
- New **`environment`** block: virtualization, container, security module.
- Field names unified across platforms: `privileged` (was `administrator`), `durationSeconds` (was `durationMinutes`); finding keys lowercased.
- Companion **[`linux/tatar-linux.sh`](linux/)** added — 16 modules, same analyst-first outputs.

### v1.1
- **Triage summary** (`summary.txt` + `summary.json`): metadata, quick stats, aggregated *Suspicious findings* (review leads, not verdicts); JSON for SIEM/automation.
- **Execution log** (`Tatar.log`): timestamped `START/OK/WARN/FAILED` per module, errors mirrored with reasons; excluded from the evidence manifest by design.
- **`-Silent` / `-Quiet`** mode for WinRM / scheduled / remote runs + **exit codes** (`0` ok, `1` fatal, `2` completed with errors).
- False-positive fixes: obfuscation scan skips the script itself; word-boundary matching for `nc.exe` / `ncat` / `iex` patterns (no more `AdobeCollabSync.exe` hits).
- Hostname fallback when `$env:COMPUTERNAME` is unset.

### v1.0
- Initial release: 30 collectors in RFC 3227 order of volatility, chain of custody, SHA-256 manifest, optional zip, hive/EVTX/memory switches.

---

## Legal

For **authorized** use only — on systems you own or have explicit written permission to examine. You are responsible for complying with applicable laws and organizational policy.

## Contact

**Author:** Enkhbat Oyunbayar — Security Analyst · Ulaanbaatar

[![Facebook](https://img.shields.io/badge/Facebook-Enkhbat%20Oyunbayar-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/enkhbat.o/)
[![GitHub](https://img.shields.io/badge/GitHub-ochmunkh-181717?logo=github&logoColor=white)](https://github.com/ochmunkh)

For **authorized use only** — on systems you own or have written permission to examine.

## License

MIT (see `LICENSE`).


---

<a id="монгол"></a>
## 🇲🇳 Монгол хувилбар

> Хурдан, нэг файлт, cross-platform DFIR triage — Windows (PowerShell) + Linux (Bash).

Халдлагад өртсөн шинж тэмдэг гарсан (хортой сайт зочилсон, сэжигтэй файл ажиллуулсан, тайлбаргүй удааширсан) үед нотлох баримтыг **хурдан** хамгаалж авах хэрэгтэй болдог — олон тусдаа хэрэгсэл суулгаж чирэгдэлгүйгээр. `Tatar.ps1` (Windows) болон `tatar-linux.sh` (Linux) нь системийн чухал volatile ба non-volatile artifact-уудыг **read-only-first** нэг дамжлагаар цуглуулж, шинжээчид зориулсан нэгдсэн тайлан, MITRE ATT&CK тэмдэглэгээ, chain-of-custody-тай SHA-256 manifest үүсгэнэ.

> Хээрийн нөхцөлд, минимал хамааралтайгаар triage лог хурдан гаргах шаардлагатай эхний хариу үзүүлэгч, security шинжээчдэд зориулав.

---

## Triage гэж юу вэ?

Triage гэдэг ойлголт эмнэлгээс гаралтай. Эмч өвчтөнд хамгийн эхний үнэлгээг хурдан хийж, ямар эрсдэл байж болох, цааш ямар гүнзгий шинжилгээ хэрэгтэйг тодорхойлдог. **Tatar Triage-ийн зорилго ч мөн адил** — бүх forensic хэрэгслийг орлох биш, Incident Response-ийн эхний шатанд чухал мэдээллийг хурдан цуглуулж, шинжээчид дараагийн алхмаа зөв тодорхойлоход туслах юм.

Энэ хэрэгсэл нь:
- Malware analyzer шиг sandbox-д malware **шинжилдэггүй**.
- Volatility шиг memory dump авч гүнзгий шинжилгээ **хийдэггүй**.
- Autopsy зэрэг full-disk forensic **хийдэггүй**.

Харин системийн одоогийн төлөв байдлыг хурдан үнэлж, хамгийн чухал мэдээлэл болон эрсдэлийг ялган харахад тусална.

---

## Онцлох боломжууд

- **Нэг скрипт, суулгах шаардлагагүй.** Хост дээр (эсвэл USB-д) хийгээд шууд ажиллуулна.
- **Windows 30 / Linux 18 модуль**, RFC 3227 order of volatility дарааллаар (санах ой → сүлжээ → процесс → … → диск / registry / лог).
- **Шинжээч-төвтэй тайлан.** Run бүр `summary.txt` + `summary.json` + `findings.json` гаргана — host/OS/case мета, quick stats, нэгтгэсэн **Сэжигтэй findings** жагсаалт. JSON нь SIEM/SOAR-т шууд ордог.
- **Гүйцэтгэлийн лог** (`Tatar.log`/`tatar.log`) — модуль бүрийн `START/OK/WARN/FAILED`.
- **Read-only-first.** Хүнд/эвдрэлтэй үйлдлүүд (memory dump, hive save, EVTX export) default-оор унтраалттай, тодорхой тугаар л асна.
- **Chain of custody.** Run бүрийн мета, examiner/case ID, файл бүрийн SHA-256 manifest.
- **Ил тод.** Обфускаци, AV/AMSI bypass үгүй. Гарын үсэг зурж, allow-list хийхэд зориулсан.
- **Cross-platform.** Windows, Linux хоёр нэг [`summary.schema.json`](schema/summary.schema.json) гэрээ гаргана — нэг parser хоёуланг уншина.
- **Нууц үг задалдаггүй.** Илэрсэн зүйлс нь **review хийх сэжүүр, эцсийн дүгнэлт биш.**

---

## Архитектур

TATAR бол ижил үүрэгтэй хоёр хувилбар — `Tatar.ps1` (Windows, 30 модуль), `tatar-linux.sh` (Linux, 18 модуль) — боловч хоёул нэг ижил гаралтын гэрээтэй. Адилхан JSON schema (`schemaVersion 1.2`) гаргадаг тул SIEM/SOAR аль ч платформын үр дүнг ялгалгүй уншина.

```
                    TATAR Triage
                         │
          ┌──────────────┴──────────────┐
     Windows · Tatar.ps1           Linux · tatar-linux.sh
     (PowerShell, 30 модуль)       (Bash, 18 модуль)
          └──────────────┬──────────────┘
                         ▼
             Нэгдсэн JSON schema  (summary.schema.json · v1.2)
                         ▼
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
     summary          findings         timeline
    (+ тайлан)        (SOAR / SIEM)    (+ hashes)
        └────────────────┼────────────────┘
                         ▼
              DFIR мөрдөн шинжилгээ
```

### Өгөгдлийн урсгал

1. Аргумент уншиж, гаралтын хавтас болон chain of custody-г бэлдэнэ.
2. Ажиллаж буй орчноо (виртуал / контейнер / хамгаалалт) тодорхойлно.
3. Модулиудаа **алдагдамтгай өгөгдлийн дарааллаар** ажиллуулна (санах ой · сүлжээ · процесс → диск · registry · лог). Модуль бүр түүхий нотолгоог диск рүү, бүтэцтэй finding-ийг санах ойд гаргана.
4. **Allowlist** нь урьдаас мэдэгдэж байгаа цэвэр зүйлсийг нууна — устгахгүй, аудитад үлдээнэ.
5. **IOC** нь мэдэгдэж байгаа мууг тэмдэглэж, allowlist-ийг давж, цуглуулсан нотолгооноос шинэ finding босгоно.
6. Идэвхтэй/нуугдсанаар нь эрэмбэлж `summary.txt` / `summary.json`, `findings.json`, SHA-256 manifest-ээ бичнэ.

### Finding загвар

Finding бүр нэг бичлэг, платформ хооронд адилхан: `id` · `severity` (High/Review) · `category` · `technique[]` (MITRE) · `message` · `detail` · `confidence` (0.7 High · 0.4 Review · 0.95 IOC-баталгаажсан) · `suppressed` · `suppressReason` · `iocMatch`. Нуугдсан finding нь тайлан болон JSON-д шалтгаантайгаа үлдэнэ — зөвхөн идэвхтэй жагсаалтаас хасагдана, бичлэгээс арилдаггүй.

### Allowlist — дуу чимээнээс дохиог ялгах

Мэдэгдэж байгаа цэвэр зүйлсийг зам, Authenticode нийтлэгч (Windows), `dpkg`/`rpm` багц эзэмшил (Linux), эсвэл SHA-256-аар нууна. Цэвэр хостод нэг run 11 finding-ээс **4 идэвхтэй / 7 нуугдсан** болж багассан.

### IOC — муу нь дийлнэ

Offline `hashes / ips / domains / filenames` жагсаалт авна. *Pass A* нь одоо байгаа finding-уудтай тааруулж, таарвал **allowlist-ийг давж** тухайн finding-ийг дахин идэвхжүүлэн High / 0.95 болгоно. *Pass B* нь цуглуулсан нотолгооноос олдсон IOC-д зориулж шинэ finding босгоно. Зарчим энгийн: мэдэгдэж байгаа муу индикатор үргэлж цэвэр allowlist-ийг дийлдэг.

### Итгэлийн хил

Сүлжээ рүү юу ч илгээхгүй — allowlist, IOC жагсаалт нь дотоод файл, хэш дотооддоо бодогдоно. Зөвхөн уншина; root/Admin нь уншиж болох хүрээг өргөтгөнө, өөрчлөх эрх нэмдэггүй. Скриптийн өөрийн SHA-256-г chain of custody-д бичих ба EDR-т мэдрэг үйлдлүүд (memory dump, hive save, устсан файл сэргээх) default-оор унтраалттай, тухайлан асаадаг.

---

## Нууцлал

Tatar Triage бүрэн **офлайн** ажиллана. Цуглуулсан мэдээлэл, scan үр дүн, хэрэглэгчийн өгөгдлийг ямар нэг сервер рүү **илгээдэггүй**.

---

## Шаардлага

- Windows 10 / 11 (Server 2016+ бас ажиллана) · PowerShell 5.1+ (PowerShell 7 дэмжинэ)
- Linux: Debian/Ubuntu эсвэл RHEL/CentOS/Fedora (bash 4+, coreutils)
- Бүрэн цуглуулгад **Administrator / root** зөвлөж байна.

---

## Ашиглах

```powershell
# Windows
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Enkhbat.O" -Compress
.\Tatar.ps1 -List          # модулиудыг харах
.\Tatar.ps1 -All -Silent   # автоматжуулалт (exit code буцаана)
```

```bash
# Linux
chmod +x tatar-linux.sh
sudo ./tatar-linux.sh --all --output /mnt/usb/evidence --caseid IR-2026-014 --examiner "Enkhbat.O"
./tatar-linux.sh --list
```

**Exit code:** `0` = амжилт · `1` = fatal/usage алдаа · `2` = алдаатай дууссан (лог шалга).

---

## Модулиуд

**Windows (30):** memory · network · process · sessions · services · sysinfo · users · persistence · autoruns · shares · firewall · drivers · apps · prefetch · usb · pshistory · obfscan · rdp · lateral · privesc · browser · fsartifacts · deleted · shadow · eventlogs · hives · mft · indicators · hashes · timeline

**Linux (18):** sysinfo · network · process · sessions · users · services · persistence · apps · suid · sshkeys · bashhistory · kernelmods · indicators · hashes · logs · timeline · containers · integrity

Хамрах хүрээ: систем/хэрэглэгч/сүлжээний төлөв, LOLBAS command-line флагтай процессууд, process genealogy, persistence (Run keys, scheduled tasks, IFEO/AppInit/LSA/Winlogon ASEP-ууд), RDP/lateral movement, privilege-escalation индикатор, обфускаци скан, browser artifact мета, Recent/Amcache/Prefetch, shadow copy, чухал Windows event ID, NTFS/MFT, IOC-д зориулсан file hashing, super-timeline. Linux талд: cron/systemd persistence, SUID/SGID, SSH түлхүүр, container/cloud context, критикал файлын integrity baseline гэх мэт.

---

## Гаралт

```
<OutputPath>/<HOST>_<YYYY-MM-DD_HH-mm-ss>/
├─ TATAR_Report_<HOST>_<stamp>.txt   # нэгдсэн, хүн уншихад зориулсан тайлан
├─ summary.txt                       # шинжээч-төвтэй triage дүгнэлт + findings
├─ summary.json                      # нэгдсэн schema (SIEM/автоматжуулалт)
├─ findings.json                     # findings-only feed (SOAR/SIEM)
├─ Tatar.log                         # гүйцэтгэлийн лог: START/OK/WARN/FAILED
├─ chain_of_custody.txt              # case/examiner/цаг/скриптийн hash
├─ manifest_sha256.csv               # файл бүрийн SHA-256
├─ timeline.csv · binary_hashes.csv · ...
└─ (optional) TATAR_<HOST>_<stamp>.zip (+ .sha256)
```

---

## Анхаарах зүйлс

- **Гадаад дискэнд бичихийг зөвлөнө** (`-OutputPath E:\Evidence`). Систем дискэнд бичвэл устсан файлын ул мөрийг дарж бичиж болзошгүй.
- Цуглуулга дуусахаас өмнө хостыг **унтраах/restart хийхгүй**.
- Гаралт нь **эмзэг мэдээлэл** агуулж болзошгүй (registry hive, browser мета) — шифрлэж, аюулгүй дамжуулна уу.
- Зарим модуль (`hives`, `memorydump`, `exportevtx`) EDR/AV-г идэвхжүүлж болзошгүй — SOC-той зөвшилцөж, tool-оо урьдчилан allow-list хий.

Дэлгэрэнгүй MITRE ATT&CK mapping: [`docs/MITRE_ATTACK.md`](docs/MITRE_ATTACK.md).

---

## Хязгаарлалт

- Хадгалагдсан нууц үг **задалдаггүй / тайлдаггүй**.
- Бүрэн `$MFT` parse хийхэд offline хэрэгсэл (MFTECmd / RawCopy) хэрэгтэй; скрипт зөвхөн NTFS/MFT мета бичнэ.
- Browser artifact бол **зөвхөн мета** (DB задлахгүй).
- Findings нь эвристик хэв тааралт — хууль ёсны программаас FP гарч болно, **үргэлж баталгаажуул**.

---

## Холбоо барих

**Зохиогч:** Enkhbat Oyunbayar — Security Analyst · Улаанбаатар

[![Facebook](https://img.shields.io/badge/Facebook-Enkhbat%20Oyunbayar-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/enkhbat.o/)
[![GitHub](https://img.shields.io/badge/GitHub-ochmunkh-181717?logo=github&logoColor=white)](https://github.com/ochmunkh)

Зөвхөн **зөвшөөрөлтэй** хэрэглээнд — өөрийн эзэмшлийн буюу бичгээр зөвшөөрөл авсан системд ашиглана уу.

## Лиценз

MIT (`LICENSE`-г үзнэ үү).
