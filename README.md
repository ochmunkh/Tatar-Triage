<p align="center">
  <img src="banner.png" alt="TATAR Triage Toolkit" width="880">
</p>

<p align="center">
  <b>Fast, single-file DFIR triage collector for Windows (PowerShell) and Linux (Bash).</b>
</p>
<p align="center">
  <b>English · <a href="README.mn.md">Монгол</a></b>
</p>

<p align="center">
  <img src="https://github.com/ochmunkh/Tatar-Triage/actions/workflows/ci.yml/badge.svg" alt="CI">
  <img src="https://img.shields.io/badge/version-1.12-blue" alt="v1.12">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-0078D6" alt="Windows and Linux">
  <img src="https://img.shields.io/badge/modules-33-5eead4" alt="33 modules">
  <img src="https://img.shields.io/badge/read--only-first-14b8a6" alt="read-only first">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="MIT">
</p>

---

When an endpoint shows signs of compromise you need to preserve evidence *quickly*, without installing a dozen tools. TATAR collects the volatile and persistent artifacts that matter, in order of volatility, into one hashed evidence folder, and writes a one-page summary of **leads for review** (not verdicts).

> Built for first responders and analysts who need triage logs **fast**, on-scene, with no dependencies.

## Quick start

**Windows** (PowerShell 5.1+, Administrator recommended):

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Name" -Compress
```

**Linux** (Bash, root recommended):

```bash
chmod +x linux/tatar-linux.sh
sudo ./linux/tatar-linux.sh --all --output /mnt/usb/evidence --caseid IR-2026-014
```

Add `-List` / `--list` to see the modules and `-DryRun` / `--dry-run` to check the plan without writing anything. Every run ends with an exit code (0 clean, 2 finished with issues) and a folder you can open with the offline [`viewer`](tools/viewer.html).

Have your own indicators? Put SHA-256 hashes, IPs, domains and file names in a JSON file shaped like [`ioc.sample.json`](ioc.sample.json) and add `-IOCFile feed.json` (Linux: `--iocfile feed.json`); the sample is a template to copy, and the collector reads it the same way. A match becomes a High finding marked IOC, even if your allowlist had cleared it. It is a lead to confirm, not a verdict; [how matching works](docs/MODULES.md).

## What you get

- **33 modules** on Windows and 18 on Linux, run in RFC 3227 order of volatility, behind one output contract (`schemaVersion 1.8`).
- **Read-only first.** Heavy or destructive actions (memory dump, hive save, full EVTX) are off unless you switch them on. It never extracts or decrypts passwords.
- **Standard user, offline, AV-safe.** No network calls, no obfuscation, no AV/AMSI bypass. Actions an EDR can notice (`-CollectHives`, `-ExportEvtx`, `-MemoryDump`) are off unless you ask. [What it does and does not do on a live host](docs/AV-SAFETY.md).
- **Evidence you can verify.** SHA-256 manifest of every file, chain of custody, release attestation.
- **Findings with identity.** Each finding has a stable `fingerprint`, so two scans of a host can be compared (see the tools below).

Not a sandbox, not a memory analyser, not full-disk forensics: it answers one question quickly, *what is wrong on this machine right now, and where should I look first?*

<p align="center">
  <img src="docs/sample_summary.png" alt="Triage summary" width="760">
</p>

## How it differs

Other free collectors mainly copy files; Tatar Triage also judges them ([comparison](docs/COMPARISON.md)):

| | Typical file collector | Tatar Triage |
|---|---|---|
| Result | Files for a second tool to parse | Findings with evidence, ATT&CK ids and a next step, plus the files |
| Privilege | Administrator or root, to read locked files | Standard user; privileged steps only when you ask |
| Host | May write drivers, executables or a large archive | Read-only, offline, nothing installed, SHA-256 manifest |
| Depth | Deep on the files it copies | Wide and shallow: it tells you whether the host is worth a deep look |

## Analysis tools

Run on the analyst's machine, standard library only, offline ([details](docs/TOOLS.md)):

| Tool | Answers |
|---|---|
| `tools/viewer.html` | Read a run in the browser, offline |
| `tools/tatar-diff.py` | What changed since the baseline scan? |
| `tools/tatar-timeline.py` | What happened, in what order? (Timesketch CSV) |
| `tools/tatar-aggregate.py` | Which host differs from the rest? |
| `tools/tatar-review.py` | Record what you decided about a finding, and hide what you already cleared |
| `tools/tatar-siem.py` | Send the findings to a SIEM as ECS-style NDJSON |
| `tools/tatar-navigator.py` | Show the findings' ATT&CK techniques as an ATT&CK Navigator layer |

## Documentation

| Read this | For |
|---|---|
| [Usage](docs/USAGE.md) | Requirements, every option, exit codes |
| [Modules and ATT&CK](docs/MODULES.md) | What each module collects, technique mapping |
| [Output](docs/OUTPUT.md) | Summary, findings, execution log, folder layout |
| [Analysing the evidence](docs/ANALYSIS.md) | Correlation, Sigma hand-off, what to do next |
| [What the evidence is](docs/EVIDENCE.md) | `artifactClass`, platform differences, known-answer checks |
| [Architecture](docs/ARCHITECTURE.md) | Data flow, findings model, allowlist and IOC engines |
| [Handling and limits](docs/OPERATIONS.md) | Operational notes, AV, known limitations |
| [Linux edition](linux/README.md) | The Bash collector on its own |
| [Changelog](CHANGELOG.md) | Every release |
| [Security testing](docs/SECURITY-TESTING.md) · [Validation](docs/VALIDATION.md) | How it is tested, lab results |
| [Coverage](docs/COVERAGE.md) · [After collection](docs/AFTER-COLLECTION.md) · [Comparison](docs/COMPARISON.md) | What is and is not collected, which tool reads which file, how it differs |

Most documents have a Mongolian twin (`.mn.md`); coverage, after-collection, comparison, AV-safety, ATT&CK, tools, security-testing and validation are English only.

## Legal

For **authorized** use only: systems you own or have explicit written permission to examine. You are responsible for complying with applicable law and policy.

The evidence folder holds sensitive information about the examined host (accounts, command lines, network connections, file names). Where a collection is part of a cyber security risk assessment or an information security audit in Mongolia, the Law on Cyber Security (articles 8.5 and 9.6) makes the resulting reports confidential. Treat the evidence folder the same way: keep it encrypted, pass it only to those entitled to it, and do not leave a copy on the examined host.

## Contact

**Author:** Enkhbat.O, Security Analyst ·
[Facebook](https://www.facebook.com/enkhbat.o/) · [GitHub](https://github.com/ochmunkh)

Found a security problem in the tool itself? See [`SECURITY.md`](SECURITY.md) and report it privately. Want to contribute? [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT (see `LICENSE`).
