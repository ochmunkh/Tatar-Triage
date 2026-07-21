# TATAR Triage Toolkit — Linux edition

<p align="center">
  <img src="https://img.shields.io/badge/version-1.1-blue" alt="v1.1">
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

# run selected modules only
sudo ./tatar-linux.sh --modules network,process,persistence,sshkeys

# full run to external media, with case metadata, compressed + hashed
sudo ./tatar-linux.sh --all --output /mnt/usb/evidence \
     --caseid IR-2026-014 --examiner "Enkhbat.O" --compress

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
| `--dump-deleted` | Recover deleted running binaries via `/proc/PID/exe` (opt-in; **off by default**, read-only-first) |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Collection completed successfully |
| `1` | Fatal / usage error (nothing selected, output dir cannot be created, no valid modules) |
| `2` | Collection completed, but one or more steps logged errors — check `tatar.log` |

---

## Modules (order of volatility)

`sysinfo` · `network` · `process` · `sessions` · `users` · `services` · `persistence` · `apps` · `suid` · `sshkeys` · `bashhistory` · `kernelmods` · `indicators` · `hashes` · `logs` · `timeline` · `containers` · `integrity`

Coverage: system/kernel info, network sockets & routing & DNS, process tree with **exe-from-/tmp and deleted-binary detection**, logins (`who`/`last`/`lastb`, auth log), users/groups/sudo (**UID-0 & empty-password checks**), systemd services & enabled units, persistence (cron, systemd timers, `rc.local`, profile scripts), installed packages (`dpkg`/`rpm`), **SUID/SGID** enumeration, SSH keys & `sshd_config`, shell history, kernel modules & taint, suspicious indicators (world-writable system files, execs in `/tmp`,`/dev/shm`,`/var/tmp`, recent `/etc` changes, immutable files), SHA-256 of running binaries, key-log copy, and a lightweight file-change timeline. **v1.1** adds container / cloud context (`containers`), a critical-file SHA-256 integrity baseline (`integrity`), established-connection counts, and opt-in recovery of deleted running binaries (`--dump-deleted`).

---

## Output

```
<output>/<host>_<YYYY-MM-DD_HH-MM-SS>/
├─ TATAR_Report_<host>_<stamp>.txt   # consolidated human-readable report
├─ summary.txt                       # analyst-first triage summary + findings
├─ summary.json                      # machine-readable (unified schema, SIEM/automation)
├─ findings.json                     # findings-only feed for SOAR / SIEM
├─ tatar.log                         # execution log: START/OK/WARN/FAILED (excluded from manifest)
├─ chain_of_custody.txt              # case / examiner / times / script SHA-256
├─ manifest_sha256.txt               # SHA-256 of every collected file
├─ binary_hashes.txt                 # SHA-256 of running binaries (VT/IOC)
├─ timeline.csv                      # recent file changes
└─ logs/                             # copied auth/syslog/wtmp/btmp where readable
```

The `summary.json` matches the Windows edition (`platform`, `host`, `os`, `stats`, `findings[]` with `severity/category/message/detail`), so a single parser ingests both.

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

## Known limitations (v1.0)

- Core triage scope (18 modules); not yet a full super-timeline or memory acquisition.
- No `$MFT`-equivalent deep filesystem parsing (use dedicated tools for that).
- Domain / LDAP-joined hosts: local `/etc/passwd` only (no directory enumeration).
- RHEL log paths (`/var/log/secure`, `/var/log/messages`) and `rpm` are handled; very old/minimal distros may lack some tools (steps degrade gracefully and are logged).

## License

MIT (see repository `LICENSE`).

## Author

**Enkhbat.O** — Security Analyst
