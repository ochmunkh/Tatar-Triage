# What the evidence is

[Монгол](EVIDENCE.mn.md) · [← README](../README.md)

## What the evidence IS: `artifactClass`

`category` says which module raised a finding. `artifactClass` says what the
evidence **is** — and the difference is operational. `persistence` covers Run
keys, IFEO, Winlogon, the Startup folder, scheduled tasks and COM hijacks all
at once, so an allowlist or an IOC rule written against the category cannot aim
at one of them. HijackThis made exactly this distinction with its `O4` / `O20`
section codes, and it is why knowledge like *"O20 is almost always bad"* could
be written down and reused.

The vocabulary is **closed**: a collector refuses to emit a class nobody
declared, `unknown` is emitted rather than a guess, and `check_docs_parity.py`
fails the build if the shell edition declares a class the Windows edition has
never heard of. It is the same vocabulary `ARTIFACTS.md` uses for files,
applied to findings. Added in schema 1.5.

| | Windows | Linux |
|---|---|---|
| Classes declared | 46 | 18 |
| Derived by | `Get-ArtifactClass` | `map_artifact_class` |
| Unit-tested cases | 42 | 20 |

### Three more persistence techniques

`persistence` now also reads, all as plain registry lookups, all measured at
**+1.0 s**:

| Technique | ATT&CK | What is flagged |
|---|---|---|
| COM hijack | T1546.015 | a CLSID registered under **both** `HKCU\Software\Classes` and HKLM — the per-user copy shadows the machine one and needs no Administrator to plant |
| netsh helper DLL | T1546.007 | a helper whose DLL sits in a **user-writable** location |
| Protocol handler / filter | — (HijackThis `O18`) | a scheme served by a DLL in a **user-writable** location |

Each rule looks for the *shadowing* or the *deviation*, not for the key's mere
existence. The first drafts did the obvious thing — "not on my list of default
netsh helpers", "DLL outside `%SystemRoot%`" — and raised seven findings on a
clean workstation, every one of them Microsoft Office or Windows itself. The
shipped rules raise none there.

A note on cost, because it nearly went the other way: `Test-Path` against a key
that does **not** exist under `HKLM\Software\Classes\CLSID` takes about two
seconds, and twenty-two of those turned a 0.8 s module into a 22 s one.
`persistence` is in `-Quick`, so the lookups go through the .NET registry API
instead, which returns immediately on a miss.

### Known-answer verification

```powershell
powershell -NoProfile -File tests\Test-KnownAnswer.ps1
bash tests/test-known-answer.sh
```

Security and robustness tests: `bash tests/test-security.sh` (Linux) and `tests\Test-Security.ps1` (Windows); fuzz tests: `python3 tests/fuzz.py` and `tests\Test-Fuzz.ps1`. What they cover, how they map to OWASP and NIST, and what they do not cover: [docs/SECURITY-TESTING.md](SECURITY-TESTING.md).

Publishing `SHA256SUMS.txt` proves the file you hold is the file that was
released. It does not tell an operator whether **this build, on this machine,
behaves correctly**. This does: a recorded finding set replayed through the
real analysis code, checked against an answer worked out from the rules rather
than from what the code happens to do. Nothing is collected and nothing on the
host is touched, so a mismatch is the build and not the environment.

It is deliberately *not* a `--self-test` that plants suspicious-looking files
and checks they are found. The Linux contract suite does a version of that and
has already broken once on a host that refused to run its own probe; on Windows
the same idea is a Defender detection waiting to happen, and not tripping AV is
this tool's first constraint.

---

### Which platform collects what

The two editions share an output contract, not a module list — 33 modules on
Windows, 18 on Linux. That is not an oversight on the shell side: most of the
difference is Windows artifacts that have no Linux equivalent, and the shell
edition collects things Windows has nothing to collect.

| | Modules |
|---|---|
| **Both** (11) | `sysinfo` `network` `process` `sessions` `users` `services` `persistence` `apps` `indicators` `hashes` `timeline` |
| **Windows only** (22) | `memory` `autoruns` `shares` `firewall` `drivers` `prefetch` `usb` `pshistory` `obfscan` `rdp` `lateral` `privesc` `browser` `fsartifacts` `deleted` `shadow` `eventlogs` `hives` `mft` `rmm` `useractivity` `motw` |
| **Linux only** (7) | `suid` `sshkeys` `bashhistory` `kernelmods` `logs` `containers` `integrity` |

Most of the Windows-only column is the registry, NTFS and the Windows event
log — Prefetch, Shellbags, Mark-of-the-Web, UserAssist, shadow copies and
registry hives simply do not exist on Linux. What a Linux responder gives up
in return is real and worth naming: **no execution-evidence module**
(`prefetch` / `useractivity` have no counterpart), **no download-provenance**
(`motw`, which is why `COR-01` is Windows-only), and **no RMM detection**
(`rmm`). Those are the three gaps to be aware of, not the module count.
