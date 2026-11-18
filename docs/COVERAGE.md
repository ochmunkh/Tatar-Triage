# Coverage against the ForensicArtifacts triage groups

[← README](../README.md) · [Validation](VALIDATION.md)

The [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) project keeps a
community list of the places on a host that hold evidence, and groups the ones most worth
collecting first into "triage" groups (`triage.yaml`). This page lays those groups beside
what Tatar Triage collects. It was made on 2026-11-18 from a shallow copy of that
repository (742 artifact definitions: 394 Windows, 252 Linux, 217 macOS, 16 ESXi), by
reading the group names and checking each against `Tatar.ps1` and `linux/tatar-linux.sh`.
It compares by artifact, not path by path, and it is a reading of the code, not a test.

Four words are used:

- **Judged**: the collector raises a finding from it.
- **Report**: the content is in the report or a listing file, so you can read it, but no finding is raised.
- **Copy**: the raw file is copied for an offline tool to parse.
- **No**: not collected.

Most of the **No** rows are decisions, not oversights. The collector runs as a standard
user, offline, read-only, and does not touch locked files, so anything that needs
Administrator, a shadow copy or a raw volume read is left for an acquisition tool.
[AFTER-COLLECTION.md](AFTER-COLLECTION.md) says what to use for those.

## Windows

| Triage group | Artifact | Tatar |
|---|---|---|
| Execution | Prefetch | Report: names, sizes and times for 60 days, and in the timeline; the `.pf` files are not copied; needs Administrator, and says so when it cannot read |
| Execution | Amcache.hve | Copy, best effort (locked on a live host); not parsed |
| Execution | SRUM database, SuperFetch, recent file cache, CCM RUA, crash dumps, Java cache, startup info | No (SRUM and Amcache are the admin and shadow-copy trade-off the project declined for the rest of this module) |
| Execution | CIM repository | No (WMI event subscriptions are read live and judged, which is the part of it that matters most) |
| Persistence | Scheduled tasks | Report: non-Microsoft tasks |
| Persistence | Startup folders, Run keys, autoruns | Report |
| Persistence | WMI event subscriptions | Judged |
| Persistence | IFEO, AppInit, Winlogon and similar ASEP values | Judged |
| Persistence | BITS queue database | No (the command line of a running process is judged for `bitsadmin`) |
| Persistence | Shim databases, `autoexec.bat`, `winstart.bat`, group-policy scripts, PowerShell profiles | No |
| Interactive activity | Jump Lists | Report per file, and Judged for items opened over the network; the application ID is not decoded |
| Interactive activity | Recent files | Copy |
| Interactive activity | Recycle Bin | Report (`recyclebin.csv`) |
| Interactive activity | UserAssist, MUICache, RunMRU, mark-of-the-web | Report, and Judged for the executables that came from the internet (current user only) |
| Interactive activity | Windows Timeline (activities cache), Search index, RDP bitmap cache, Office autosave | No |
| External media | USB device history (USBSTOR) | Report |
| External media | `setupapi` logs | No |
| File system | NTFS volume information, USN journal state | Report |
| File system | `$MFT` and `$LogFile` | No (an offline tool reads these from an image or a shadow copy) |
| Network | hosts file, firewall rules | Report, hosts overrides Judged |
| Network | Firewall log | No |
| Security agents | Defender and other antivirus logs and quarantine | No |
| System configuration | Registry hives (SAM, SECURITY, SYSTEM, SOFTWARE, NTUSER) | Copy, only with `-CollectHives` (credential material; may alert an EDR); transaction logs and backups not collected |
| System logs | Event logs | Report: selected event IDs in every run, and Judged for log clearing, failed logons and similar; full `.evtx` only with `-ExportEvtx` |
| System logs | User Access Logging | No |
| History | PowerShell history | Report |
| Browser | History, extensions | Report: metadata only, no decryption |
| Memory | (not a triage group) | Optional, `-MemoryDump`, with a `winpmem` you supply |

## Linux

| Triage group | Artifact | Tatar |
|---|---|---|
| Persistence | cron tables and `cron.d` | Report, and Judged only for commands with download-and-run patterns |
| Persistence | systemd services and timers | Report (listed, not judged) |
| Persistence | `rc.local`, shell profile scripts | Report (profile scripts: names and times, not content) |
| Persistence | `at` jobs, anacron, XDG autostart, SysV init | No |
| History | Shell history (bash, zsh, ash) | Report, and Judged for suspicious commands |
| History | viminfo, Python, MySQL and other tool histories | No |
| User configuration | `authorized_keys` | Report, and Judged for root |
| User configuration | `known_hosts`, ssh user config, shell configuration files | No |
| System configuration | passwd, group, sudoers, `sshd_config` | Report (sshd settings: the key ones only) |
| System configuration | shadow | Judged for empty passwords; not copied |
| System configuration | Kernel modules | Report (`lsmod`) |
| System configuration | `ld.so.preload`, PAM, sysctl, fstab, packages sources, kernel module restrictions | No |
| System configuration | Critical-file integrity | SHA-256 of passwd, shadow, group, sudoers, crontab, `sshd_config` |
| System logs | auth, secure, syslog, messages, wtmp, btmp, cron | Copy |
| System logs | systemd journal | Report: bounded extracts |
| System logs | utmp, lastlog, audit logs, kernel log | utmp and lastlog: not collected; audit and kernel logs: No |
| Network | hosts, resolver, sockets, routes, neighbours | Report, hosts overrides Judged |
| Network | firewall configuration (ufw, iptables), forwarding and redirect settings | No |
| Applications | Web server, database and container logs and configuration | Container and cloud context only |
| Other | SUID and SGID files | Judged |

## What this says

The collector answers "what is happening on this host now, and what would bring it back
after a reboot" well, and leaves "what happened over the past weeks" to the files it
copies or exports. The gaps that are worth closing, because they cost little and need no
privilege, are few:

1. Linux: `ld.so.preload`, `at` jobs, `known_hosts`, user shell configuration, firewall rules, and the `utmp` and `lastlog` records.
2. Windows: PowerShell profiles, group-policy startup scripts, the BITS job list (`Get-BitsTransfer` for the current user), and the firewall log path.
3. Judging what is already listed: autostart and task targets under a user-writable folder (see [VALIDATION.md](VALIDATION.md)).

None of these is implemented. Each needs its own false-positive check and the same change in both editions.
