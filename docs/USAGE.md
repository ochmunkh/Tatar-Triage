# Requirements and usage

[Монгол](USAGE.mn.md) · [← README](../README.md)

## Requirements

- Windows 10 / 11 (Server 2016+ works too)
- PowerShell 5.1+ (PowerShell 7 supported)
- **Administrator** recommended (some artifacts are incomplete without it)

## Usage

```powershell
# Allow the script for the current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Run everything (single- or double-dash both work)
.\Tatar.ps1 -All
.\Tatar.ps1 --all

# List available modules (no collection, no folder created)
.\Tatar.ps1 -List

# Check the plan before touching the disk: output path, module order, armed
# gated operations, allowlist / IOC readability. Writes nothing.
.\Tatar.ps1 -All -DryRun -OutputPath E:\Evidence -Allowlist allowlist.sample.json

# Run specific modules only
.\Tatar.ps1 -Modules network,process,rdp,lateral,timeline

# Full run to an external drive, with case metadata, compressed + hashed
.\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Enkhbat.O" -Compress

# Automated / remote run: no console output, check the exit code
.\Tatar.ps1 -All -Silent -OutputPath E:\Evidence -CaseId IR-2026-014
if ($LASTEXITCODE -ne 0) { Write-Warning "TATAR finished with issues - check tatar.log" }

# Cut the noise: suppress known-good findings with an allowlist
.\Tatar.ps1 -All -Allowlist allowlist.sample.json

# Confirm known-bad: match findings & evidence against an offline IOC feed
.\Tatar.ps1 -All -Allowlist allowlist.sample.json -IOCFile ioc.sample.json
```

Linux:

```bash
chmod +x tatar-linux.sh
sudo ./tatar-linux.sh --all --output /mnt/usb/evidence --caseid IR-2026-014 --examiner "Enkhbat.O"
./tatar-linux.sh --list
sudo ./tatar-linux.sh --all --dry-run   # check the plan, write nothing
```

### Options

| Option | Description |
|--------|-------------|
| `-Quick` / `--quick` | The highest-signal subset, ~10s. Answers *"is something wrong on this host"*; `-All` answers *"how did it get here"*. The membership is measured, not chosen by taste, and `-List` marks it — so there is one copy of the list, in the code |
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
| `-Silent` / `-Quiet` | Suppress **all** console output (banner, progress, status). Files, including `tatar.log`, are still written. For WinRM / scheduled / automated runs |
| `-DryRun` / `-Preview` | Print the resolved output directory, the module list in run order, which gated operations are armed and whether the allowlist / IOC feeds can be read — then exit `0` **without creating or writing anything** |
| `-Allowlist <json>` | Suppress known-good findings by path glob, Authenticode publisher, or SHA-256. Suppressed findings are kept for audit, not deleted |
| `-IOCFile <json>` | Match findings & collected evidence against an offline IOC feed (hashes = SHA-256 only, ips, domains, filenames). A hit **overrides** the allowlist and escalates to High |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Collection completed successfully |
| `1` | Fatal / usage error (nothing selected, a value-taking flag with no value, output dir cannot be created, no valid modules) |
| `2` | Collection completed, but one or more steps logged errors — check `tatar.log`. An unreadable `-Allowlist` / `-IOCFile` path lands here, as does an unknown option or an unknown module name. |
