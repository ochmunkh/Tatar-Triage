# Changelog

All notable changes to TATAR Triage Toolkit are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); versions use
[SemVer](https://semver.org/).

## [1.8.1] — 2026-11-18

Found by reading the output of real scans of a workstation, not by a test suite.

### Fixed
- **UTF-16 connection logs.** AnyDesk's `connection_trace.txt` is UTF-16; it was read as single-byte text, so every character was followed by a replacement character and the session history could not be read. A new reader detects a byte-order mark or the NUL pattern of BOM-less UTF-16 and falls back to UTF-8.
- **Credentials in download URLs.** The Mark-of-the-Web finding quoted the full `HostUrl`, including a signed link's `sig=` and token. Secrets in query strings (`sig`, `jwt`, `token`, `key`, `password`, `x-amz-signature`, ...) are replaced by `[redacted]`; host, path and other parameters stay. A trailing control character is cut.
- **False positive: Defender services.** `WinDefend`, `WdNisSvc` and `MDCoreSvc` were reported as service binaries in a user-writable location because they live under `C:\ProgramData`. For ProgramData the file's own ACL now decides; an unreadable ACL keeps the finding. Paths under a user profile or Temp are still always reported.
- **Noise: the collector's own files.** Its own tests and tools match its detection patterns by design. They remain in the report, marked as the collector's own, but raise no finding. A bare `powershell.exe` or `cmd.exe` process is no longer a lead by name; what it was told to run still is.

### Added
- Fuzz tests for both editions (`tests/fuzz.py`, `tests/Test-Fuzz.ps1`): random and mutated input for the JSON, CSV, hosts-line, path and control-character code, and mutated allowlist and IOC feeds. No defect found.
- Windows containment test with Windows Firewall (`tests/Test-Containment.ps1`): an outbound block rule for the collector host and the Windows Filtering Platform audit prove no connection is attempted. Skipped without elevation.
- `tests/Test-LogFixes.ps1`: unit tests for the four fixes above.
- Build-provenance attestation for release assets (`gh attestation verify`); effective from this release.

### Changed
- GitHub Actions are pinned to commit SHAs; Dependabot keeps them current.

## [1.8.0] — 2026-11-18

### Added
- **Security and robustness tests for both editions.** `tests/test-security.sh`
  (Linux, 65 checks) and `tests/Test-Security.ps1` (Windows, 55 checks) throw
  hostile arguments, output paths, allowlist and IOC feeds, host file names and
  process command lines at the collector. They check that evidence is private,
  that tampering with a file or the manifest is detected, that the host is left
  unchanged and nothing goes online, that no temp files remain, that a run needs
  no privilege, that output is strict UTF-8, that two runs agree, and that a
  full run stays inside its time and memory budget.
- **`docs/SECURITY-TESTING.md`** maps those tests to OWASP ASVS 4.0 / Top 10 2021
  and NIST SP 800-86 / 800-218, lists the defects found, and says what is not
  covered. It is a test map, not a compliance claim.
- Both test suites run in CI (Linux with `strace`; both Windows jobs with `-Quick`).

### Security
- **Evidence is private.** Linux: `umask 077` and a final `chmod -R go-rwx` on
  the evidence folder (also when a run is interrupted). Windows: the evidence
  folder gets a protected ACL (SYSTEM, Administrators, the current user).
- **No writing through links.** A symlink (Linux) or junction (Windows) as the
  output path is refused, and so is reusing an existing evidence folder (exit 1).
- **Terminal-safe reports.** Control, escape and bidi characters from host file
  names and command lines are replaced before they reach any generated text
  (U+FFFD on Windows, `<U+XXXX>` and stripped controls on Linux).
- **Temp files.** Linux keeps every temporary file in one private directory that
  is removed on exit, SIGINT, SIGTERM and SIGHUP.
- **No writes by the tools it runs.** `podman ps` creates its storage and lock files
  on first use, so the containers module now asks podman only when this user's
  container storage already exists (found by the strace test on a CI runner).

### Changed
- **Behaviour change (Linux):** evidence collected as root is no longer readable
  by other users. Read it with `sudo`, or `chown` it deliberately.
- AV-07 now states its one exception: the collector may take access *away* from
  its own evidence folder; any other `chmod` / `Set-Acl` still fails the build.

### Verified
- Windows contract 233/233, Windows unit suites all green, PSScriptAnalyzer 0
  errors; Windows security 55/55 (full `-All` run 127 s, collector peak 417 MB).
- Linux security 65/65; every CI gate green.

## [1.7.0] — 2026-11-18

### Added
- **`tools/viewer.html`** — one static file for reading `summary.json` or
  `findings.json` on the analyst's own machine. Confidence is shown by name
  (Review, High, Correlated, IOC) with its reason; ATT&CK links are built only
  from technique IDs that match `T####` or `T####.###`; every finding carries a
  short next step for its `artifactClass` (what to ask, where to look, what is
  often benign, when to escalate) for all 46 classes, with no link and nothing
  to run on the affected host. Skipped modules, modules that did not finish and
  the run's limitations are shown above the findings.
- The page is hardened rather than assumed safe: values are written with
  `textContent` only, control and bidirectional-override characters are
  replaced, field lengths and finding counts are capped, and the
  Content-Security-Policy is `default-src 'none'` with the script and style
  pinned by SHA-256.
- **`.github/scripts/check_viewer.py`** (CI): policy hashes match the file, no
  HTML-string sink, dynamic code, network call or storage in the script, no
  inline handler, style attribute or URL in the markup, ASCII-only with LF
  line endings, and guidance that matches the closed `artifactClass` set
  exactly (46 Windows, 18 of them also Linux). `--seal` refreshes the hashes
  after a deliberate edit.
- `tests/test-viewer.py` (needs Playwright, not part of CI): loads an ordinary
  document and a hostile one (markup in every field, a 2 MB string, a prototype
  name as a class, bidirectional characters, malformed fields) and asserts that
  no script runs, no element is injected, no request leaves the page and no
  policy violation is logged.
- The release attaches `viewer.html` and lists it in `SHA256SUMS.txt`.

### Changed
- `.gitattributes` pins `*.html` to LF: the policy hashes are computed over the
  file's exact text, so a CRLF checkout would break the page on Windows.
- Version `1.7.0` on both editions. The collectors are otherwise unchanged and
  `schemaVersion` stays `1.6`.

## [1.6.0] — 2026-11-18

### Added
- **`moduleStatus[]` in `summary.json` (schema 1.6).** One entry per requested
  module — `module`, `status` (`ok`, `warn`, `failed`, `skipped`), `seconds`,
  `errors`. Until now a module that crashed, or on Linux did not produce its
  primary artifact, was visible only in `tatar.log`; a pipeline reading
  `summary.json` saw an empty section and could not tell it from a clean one.
  Same shape on both editions; `modulesRun`, `modulesSkipped` and
  `moduleLimitations` are unchanged.
- **The manifest's own SHA-256.** `manifest_sha256.txt` cannot hash itself, so
  its digest is printed at the end of the run, logged, and written to
  `manifest_sha256.txt.sha256` in `sha256sum` format
  (`sha256sum -c manifest_sha256.txt.sha256`). The sidecar is, like the
  manifest, outside what the manifest covers, and the report says so.

### Changed
- `schemaVersion` is `1.6` in `summary.json` and `findings.json` on both
  editions; both schemas accept it. A 1.5 consumer keeps working: only an
  optional property was added.

### Not changed, on purpose
- The Windows hosts finding still has an empty `paths[]`. Naming
  `...\drivers\etc\hosts` there would make the sample allowlist's
  `C:\Windows\System32\*` rule suppress a hosts override silently, which is
  worse than an empty list.

## [1.5.3] — 2026-11-18

### Fixed
- **The hosts check was wrong in both directions on Linux.** It excluded any
  line containing `127.0.0.1`, `::1` or `127.0.1.1` *anywhere*. Measured against
  two sample files: a clean Debian / Ubuntu `/etc/hosts` was reported as **4**
  custom entries (the `ip6-localnet`, `ip6-mcastprefix`, `ip6-allnodes`,
  `ip6-allrouters` and `ip6-allhosts` lines are stock, and `::1` appears in
  none of the ones it excluded), so every clean Linux host raised a Review
  finding; and a file with four real overrides was reported as **1**, because
  `203.0.113.9 login.bank.example 127.0.0.1` and `fe80::1 attacker-router.example`
  merely *contain* the strings it was looking for. Either is a way to hide a
  redirect in plain sight.
- **A line is now stock only if its address and every name on it are ones the
  system ships.** Same table and same rule on both editions
  (`hosts_is_default` / `Test-HostsDefault`), pinned by 25 shared cases plus
  harness-specific ones in `tests/test-hosts-default.sh` and
  `tests/Test-HostsDefault.ps1`.
- On Windows the check anchored on the address only, so `127.0.0.1
  update.vendor.example` — a sinkhole that stops a machine reaching its own
  update server — was counted as stock. It is now reported.
- `127.0.1.1` is matched against the host's own name without any lookup:
  `hostname -f` can send a DNS query from the machine being examined.

### Changed
- A host that maps names to a loopback address (an ad-blocking hosts file, for
  instance) now raises the Review finding, because that is exactly what a
  sinkhole looks like. It is a lead, not a verdict, and a lab's own entries are
  an allowlist entry.

## [1.5.2] — 2026-11-16

### Changed
- **The hosts finding now names what was overridden.** It used to say only
  *"hosts file has 3 custom entries"*, which told the analyst to go and open
  another file before they knew whether to care. The detail now carries the
  first five overrides as `address -> name`, on both editions, in the same
  format:
  `First 2 of 2: 10.0.0.5 -> intranet.local ; 203.0.113.9 -> login.example.com | Review ...`
  Because the names are now in the finding, the IOC pass can match a domain or
  address indicator against a hosts override, which it could not reach before.
- The message is unchanged, so `artifactClass`, the technique and every
  allowlist rule written against it keep working.

### Security
- **Hosts entries are reduced to their legal characters before they are
  quoted.** A hosts line is text from the suspect host, and a finding's detail
  is read by the path extractor and the allowlist. A crafted line such as
  `1.2.3.4 C:\Windows\System32\svchost.exe` would otherwise have put a signed
  system binary into `paths[]`, where a publisher or path rule could suppress
  the finding that reports the tampering. `Format-HostsEntry` /
  `hosts_entry` keep hex digits, `:` and `.` in the address and letters,
  digits, `.`, `_`, `-` in a name; everything else becomes `?`. Entries are
  capped at 100 characters. Pinned by `tests/Test-HostsEntry.ps1` and
  `tests/test-hosts-entry.sh` over one shared case table, including the
  assertion that a crafted line yields no path candidate.

### Fixed
- The `[1.5.1]` heading below was dated 2026-11-16; the tag was cut on
  2026-11-15.

### Known limitation
- On Windows the hosts finding still has an empty `paths[]`: the hosts file has
  no extension and the path extractor only takes names that have one. Widening
  the extractor changes what every allowlist decision covers, so it is not a
  patch-release change. The Linux edition names `/etc/hosts` as before.

## [1.5.1] — 2026-11-15

### Fixed
- **`findings.json` declared schemaVersion 1.4 while carrying 1.5 fields.**
  v1.5.0 shipped with `summary.json` saying `1.5` and `findings.json` still
  saying `1.4`, so a consumer keying off the version was handed `artifactClass`
  by a document that promised it did not exist. Three guards each had a reason
  not to catch it, and all three are closed now: `check_docs_parity.py` used
  `re.search` and read only the **first** literal; the schema accepts 1.1
  through 1.5, so `1.4` validated cleanly; and both contract harnesses only
  ever looked at `summary.json`. The tool version has had a one-copy-only rule
  since 1.2.4 for exactly this reason - the schema version did not, and drifted
  the moment it was bumped.
- **A duplicate `## [1.5.0]` heading in this file.** Two sections carried the
  same version, so `release.yml`, which takes the notes from the first heading
  to the next one, would have cut the notes at the second. Merged.

### Added
- **AV-09: collected text cannot execute in the analyst's tools.** Every CSV
  this tool writes carries host-controlled text - file names, command lines,
  event messages - and a cell beginning with `=`, `+`, `@` or `-` is a
  **formula** in Excel, LibreOffice and Sheets. A file named
  `=cmd|'/c calc'!A1.txt` on the suspect host was enough to run code on the
  **analyst's** machine when they opened `timeline.csv`. It is the spreadsheet
  form of the separator injection the flat record already defends against, and
  it lands somewhere worse: the analyst is certain to open the file.

  All five Windows CSV writers go through one guard now, and the Linux timeline
  writer guards both of its columns. A negative *number* is left alone, because
  `-1` is not a formula and quoting it would corrupt real data. The Linux writer
  also doubles embedded quotes, which it never did - a file name containing `"`
  ended the field early and shifted every column after it.

  Mutation-tested against six planted violations, including one that unguarded
  only the *second* column and sailed past the first version of the check. 25
  unit cases over a table shared by both editions.

- **A platform-coverage table in both READMEs.** 33 modules against 18 is not a
  number a Linux reader should have to interpret alone. The table says what both
  editions have, what is Windows-only and why (registry, NTFS, the Windows event
  log), and names the three gaps that actually matter on Linux: no execution
  evidence, no download provenance, no RMM detection.

### Changed
- `docs/AV-SAFETY.md`'s Mongolian half edited for sense, the same pass the
  READMEs had: sentences rebuilt rather than words swapped.

## [1.5.0] — 2026-11-15

### Added
- **`artifactClass` on every finding (schema 1.5).** `category` says which
  module raised a finding; this says what the evidence *is*. The difference is
  operational: `persistence` covers Run keys, IFEO, Winlogon, the Startup
  folder, scheduled tasks and COM hijacks at once, so a suppression or IOC rule
  written against the category cannot aim at one of them. HijackThis made the
  same distinction with its `O4` / `O20` codes, and it is why knowledge like
  "O20 is almost always bad" could be written down and reused.

  The vocabulary is closed - 46 classes on Windows, 18 on Linux - and a
  collector refuses to emit one nobody declared, the same way it refuses an
  unknown severity. `unknown` is emitted rather than a guess. Derived centrally
  (`Get-ArtifactClass` / `map_artifact_class`) the way ATT&CK ids already were,
  so it did not have to be threaded through thirty call sites.
  `check_docs_parity.py` fails the build if the shell edition declares a class
  the Windows edition has never heard of; the relationship is subset, not
  equality, because there are no Run keys on Linux. 62 new unit cases over a
  table shared by both editions, and 10 new contract assertions.

- **Three more persistence techniques**, inside the existing module so the
  module count and every list that mentions it stay put. All plain registry
  reads: no new permission, nothing an EDR has reason to flag, **+1.0 s**
  measured.

  | Technique | ATT&CK | What is flagged |
  |---|---|---|
  | COM hijack | T1546.015 | a CLSID registered under **both** HKCU and HKLM - the per-user copy shadows the machine one and needs no Administrator |
  | netsh helper DLL | T1546.007 | a helper whose DLL sits in a user-writable location |
  | Protocol handler / filter | HijackThis `O18` | a scheme served by a DLL in a user-writable location |

  Two things had to be corrected before these could ship, and both are the
  reason the rules look the way they do:

  - The obvious rules were noise. "Not on my list of default netsh helpers"
    raised `dnsclient` and `netprofm`, both shipped by Windows and both missing
    from the list; "DLL outside `%SystemRoot%`" raised five Microsoft Office
    protocol handlers. Seven findings on a clean workstation, all of them
    wrong. Judging by **where the DLL is** - user-writable or not - raises none
    there, and a name list that cannot be kept correct is not maintained at all.
  - `Test-Path` against a key that does not exist under
    `HKLM\Software\Classes\CLSID` costs about **two seconds**, and twenty-two
    of them turned a 0.8 s module into a 22 s one. `persistence` is in
    `-Quick`, so that is not a trade this tool can make; the lookups go through
    the .NET registry API, which returns immediately on a miss. 22.1 s -> 1.9 s.

- **Known-answer verification** (`tests/Test-KnownAnswer.ps1`,
  `tests/test-known-answer.sh`). `SHA256SUMS.txt` proves the file you hold is
  the file that was released; it says nothing about whether *this build, on
  this machine, behaves correctly*. This replays a recorded finding set through
  the real analysis code lifted out of the collector and compares the result
  with an answer worked out from the **rules**, not from what the code happens
  to do. Nothing is collected and nothing on the host is touched, so a mismatch
  is the build and not the environment. 13 checks on Windows, 7 on Linux.

  Deliberately not a `--self-test` that plants suspicious-looking files and
  checks they are found: the Linux contract suite does a version of that and
  has already broken once on a host that refused to run its own probe, and on
  Windows the same idea is a Defender detection waiting to happen.


### Added
- **`ARTIFACTS.md`, `paste.txt`, `allowlist.suggested.json`** — one idea with
  three outputs, and the first new capability in a while that costs nothing at
  collection time: all three are written from the finished finding set, so the
  AV surface and the run time are unchanged.

  The hardest question a responder asks is not *what do I run*, it is *I have
  the folder, now what*. `ARTIFACTS.md` answers it per file: what this is, what
  question it answers, what opens it (`.evtx` -> Hayabusa/Chainsaw, `.lnk` ->
  LECmd, jump lists -> JLECmd, hives -> RegRipper). It is built from the files
  actually produced, so a non-Administrator run describes less because it
  collected less.

  `paste.txt` is the whole run in under 60 lines, for the ticket or the chat
  message that asks *is this normal?*. It is **stable on purpose**: no
  durations, no counters, process ids normalised, findings sorted by severity
  then category then message rather than by discovery order. Two lines differ
  between runs and the file says which. Proven by running twice in a row -
  the first attempt differed in three places, and the third was a PID, which is
  why they are normalised now.

  `allowlist.suggested.json` turns this host's finding paths into an allowlist
  draft in the format the collector already reads: take it from a build you
  trust, trim it, and the fleet then shows only its differences. It says in its
  own first field that a baseline from an unchecked host suppresses exactly the
  compromise you were looking for.

  **The dictionary behind `ARTIFACTS.md` is gated against a real run.** It is a
  hand-maintained list of names and this repo has shipped five stale ones, so
  the file ends with a machine-checkable `Uncatalogued: N` and CI fails on
  anything but `0`, in all three jobs that run a collector. A module that starts
  writing a file nobody described breaks the build.

### Fixed
- **A limitation raised before any module started was filed under an empty
  module name.** That is the "not running as root / as Administrator" note -
  the single most important thing a reader needs to know about a thin finding
  list - and it grouped under a blank key in `summary.json` and was dropped
  from `paste.txt` entirely. It is now filed under `(run)`. Found by reading
  the first `paste.txt` the Linux edition produced.
- **`@(...)` over a `List[object]` in the new writers** threw *Argument types
  do not match* on Windows PowerShell 5.1 - the third occurrence of this exact
  trap in this project, after `moduleLimitations` in 1.4 and the correlation
  pass in 1.5.

### Verified
- `Collect-Persistence`'s section header promises "startup, Run keys, scheduled
  tasks". It keeps the promise: `Get-ScheduledTask` is there. An earlier doubt
  about this came from a bad grep, not from the code.


### Fixed
Six defects, every one of them found by running the tool on a real workstation
rather than by reading it. Two runs of the same build, one as a normal user and
one as Administrator, did more for this release than any amount of re-reading.

- **Correlation rules named modules that raise no findings.** COR-01 named
  `prefetch` and COR-02 named `autoruns`; both collect into the report and
  neither calls `Add-Finding`, so those halves of both rules could never fire
  while the README documented them as working. `check_docs_parity.py` now
  refuses a correlation rule that names a module which raises no finding - the
  first version of that gate checked only that the module *existed*, which is
  what let this through.

- **The path extractor truncated at the first dotted segment.** A finding naming
  `C:\Users\A\AppData\Local\Temp\x4hwcywj.0p1\PrecheckTools\Setup.ps1` put only
  `...\Temp\x4hwcywj.0p1` into `paths[]` - a *directory* whose random name
  merely looks like a file. `paths[]` is what the allowlist, hash, publisher and
  IOC passes judge, and what correlation keys on, so every one of them was
  silently working on the wrong string. Directory segments are now matched
  greedily and only the file name lazily. Four cases added to the shared path
  fixture, including two paths in one message and a path followed by prose,
  which is what the greedy form had to be proven not to break.

- **Silent skips.** A non-Administrator run produced an empty Prefetch section
  with no error, no note and nothing in `moduleLimitations` - an analyst reads
  that as *nothing executed recently* when it means *we could not look*. Every
  gated or unavailable module now records why: `memory` (no `-MemoryDump`, or no
  `winpmem.exe`), `hives` (no `-CollectHives`), `autoruns` (no `autoruns64.exe`),
  `prefetch` (needs Administrator / prefetching disabled / empty window). The
  Linux edition does the same for a deleted binary left unrecovered without
  `--dump-deleted`. On the run that found this, `moduleLimitations` went from 5
  entries to 9.

- **`useractivity` told an Administrator run that it needed Administrator.**
  The note was emitted unconditionally. It is now stated only when true.

- **`obfscan` was 43 of 65 findings on an ordinary workstation.** 35 of them
  were one signed installer unpacking the same script into a fresh random temp
  directory every run. Findings are now grouped by pattern + **file name**;
  grouping by directory was the obvious key and the wrong one, since each copy
  had a distinct random parent. The report still lists every match. On the same
  host: obfscan 43 -> 6 findings, total 65 -> 29.

- **UTF-8 BOM on every text output.** The JSON documents were moved off
  `Out-File -Encoding UTF8` when the BOM made them unparseable; the report, the
  summary, the CSVs and `tatar.log` were left behind, so on PowerShell 5.1 each
  began with a stray U+FEFF - in the log that breaks the first record for
  `grep '^\['` and for any ingester anchoring at the line start. All ~70 call
  sites now go through one no-BOM writer.

- **Two collected files were missing from the manifest.** `Get-ChildItem` hides
  hidden and system files by default, so `FsArtifacts\Recent\desktop.ini` was
  written into the evidence folder and never hashed. A collected file that is
  not hashed is a hole in the chain of custody. The manifest now walks with
  `-Force`, and the report states the two files that cannot be covered by
  construction (the manifest itself, and `tatar.log`, still being appended).

### Added
- **`Resolve-KnownFolder`** - UserAssist records many entries behind a
  `{KNOWNFOLDERID}` prefix. The collector left them all raw on the reasoning
  that a wrong translation is worse than an untranslated one, which is right,
  and is why this resolves only the folder ids whose meaning is fixed by
  Windows, from this host's own environment, for the same user whose UserAssist
  is being read. Anything else is returned unchanged. The cost of leaving them
  raw was not visible until a live run: an unresolved entry carries no path, so
  it could never be allowlisted, matched or correlated.
- **RMM findings name the product's executable** when it is present in the
  install directory, instead of only a directory - a directory has no
  extension, so it never reached `paths[]`.

### Added
- **Evidence correlation** — the tool now says when two artifacts agree.

  One artifact is a lead. Two independent artifacts naming the *same path* is a
  different kind of statement, and the tool used to throw it away: an analyst
  had to notice by eye that the file Mark-of-the-Web says was downloaded is the
  file UserAssist says was run.

  Two named rules, and the count is the point — a generic "anything that
  co-occurs" pass would relabel coincidence as evidence, which is the failure
  this project keeps correcting for:

  | Rule | Fires when | Editions |
  |---|---|---|
  | `COR-01` download-then-execute | `motw` + (`useractivity` ∣ `prefetch`) on one path | Windows |
  | `COR-02` autorun-on-suspect-file | (`persistence` ∣ `autoruns`) + (`motw` ∣ `indicators`) on one path | both |

  It raises `confidence` to **0.85** and rewrites `confidenceReason` to name the
  rule, both modules, the shared path and the other finding's id. It does **not**
  touch severity, merge findings or invent one. The ladder is now `0.4` Review →
  `0.7` High → `0.85` correlated → `0.95` IOC. It runs last and skips suppressed
  findings — the allowlist already judged that path known-good, so correlating
  on it would re-raise the noise it removed — and IOC hits, which already
  outrank it.

  Three decisions worth recording:

  - **The two editions disagree about case on purpose.** `C:\Temp\X.EXE` and
    `c:\temp\x.exe` are the same file and must correlate; `/tmp/x` and `/Tmp/X`
    are different files and must not. The first Linux draft folded case, which
    would have correlated two unrelated files. Both cases are now asserted, on
    both platforms, as each other's mirror image.
  - **Measured before it was written.** A probe run of `motw`, `useractivity`,
    `persistence` and `indicators` on a clean host produced 11 findings, 0
    overlaps, and — the part that mattered — paths spelled identically by every
    module, because they all come from the same extractor the allowlist judges
    with. Zero correlations on a clean host is the correct result, which is why
    the rules are proven by unit tests rather than by a live run.
  - **No schema bump.** `confidence` was already `number, 0..1`, so no document
    shape changed and `schemaVersion` stays at 1.4. Only the field descriptions
    gained the 0.85 rung.

  50 new assertions: 26 in `tests/Test-Correlation.ps1`, 24 in
  `tests/test-correlation.sh`. Most of them assert the ways it must **not**
  fire. Two new contract rules in both harnesses, so
  `check_contract_parity.py` holds the editions to the same claims (36 shared
  rules now), and `check_docs_parity.py` fails the build if a rule names a
  module that no longer exists or if the editions' rule sets drift apart —
  mutation-tested against 6 planted violations.

- **`docs/AV-SAFETY.md` + `check_av_safety.py`** — the eight claims this tool
  is run on a live production endpoint on the strength of, each one gated.

  The claim that TATAR will not trip EDR has lived in prose since launch, and
  prose does not fail a build. One `Invoke-WebRequest` added for a "quick
  version check", one default flipped to `$true` for convenience, and the
  document becomes a lie that nobody notices until a customer's EDR notices for
  us. So each claim now has an ID — **AV-01 … AV-08**: no egress, no credential
  material, no AMSI/ETW tampering, no dynamic execution, EDR-sensitive
  operations off by default, no binary shipped, no host modification, no
  persistence — and each ID has a named function enforcing it on every push.

  Three details worth recording, because each was a wrong first attempt:

  - The checks run against a **comment- and string-stripped** view of the
    source. The collector *looks for* `Invoke-Expression` and
    `FromBase64String` — they are detection strings in the Windows edition.
    What is forbidden is executing them, not naming them.
  - **AV-02 and AV-03 are the exception** and read strings too. A real AMSI
    bypass hides its identifiers in exactly that place —
    `GetField("amsiInitFailed")` — and the first version of the gate missed a
    planted one for that reason. The collector has no reason to name LSASS or
    the AMSI internals at all, so for those two the ban is absolute.
  - **`rm` is not banned outright**, which would have been a lie in the other
    direction, since the Linux edition does clean up after itself. Every `rm`
    operand must be a variable assigned from `mktemp`. A literal path fails.

  The document and the script are cross-referenced **both ways**: a claim with
  no check fails the build, and a check with no claim fails it too — as does
  rewording a claim away from what is actually enforced. The gate was
  mutation-tested against 16 planted violations before being trusted.

- **Sigma handoff documented** (`README.md`, both halves) — and a misreading
  corrected in the process. The per-event-ID CSVs are capped at 50 events and
  are a triage preview, **not** a hunting corpus; Hayabusa and Chainsaw take
  **EVTX**, which is what `-ExportEvtx` produces. The README now says which
  output goes to which tool, with the commands.
- **`-Quick` / `--quick`** — a named high-signal profile, for the case this
  tool exists for: a responder on a host they want to be off again quickly.
  Membership was chosen by **measurement**, not by taste, and the two editions
  differ because the measurements do:

  | | Windows | Linux |
  |---|---|---|
  | Modules | 9 of 33 | 10 of 18 |
  | Measured | **10.1 s** | **under 1 s** |
  | Excluded, and why | `indicators` 16.9 s — walks temp/appdata for executables, more than the other nine together, and its finding is the noisiest the tool raises · `motw` 3.0 s — answers *how did it get here*, which is the `-All` question | `suid` 4.05 s — `find / -xdev`, against 0.10–0.27 s for everything else |

  It answers *"is something wrong on this host"*. `-All` answers *"how did it
  get here"*. Naming the question a profile answers is more useful than listing
  what it leaves out.

  The membership lives in **one place — the code**. `-List` marks it with
  `[quick]` rather than the README repeating it, because four hand-maintained
  lists in this repo have already gone stale (module list, version badge,
  README changelog, version literal), and `check_docs_parity.py` now fails if a
  profile names something that is not a module.

  Giving two module selectors at once (`-Quick -All`, `--quick --modules …`) is
  a **usage error, exit 1**, not a silent precedence rule — the same reasoning
  as a value-taking flag that consumes the next token: the run would look fine
  and collect something other than what was asked for.
- **CI now runs the suite on Windows PowerShell 5.1**, the version
  `#Requires -Version 5.1` declares and the one preinstalled on every Windows
  10/11 host. Every step of the existing Windows job uses pwsh 7, so the
  declared minimum had never been executed in CI — which is how `summary.json`
  shipped with a UTF-8 BOM for three releases, and how an array subexpression
  over a `List[object]` came to evaluate to empty on 5.1 alone. Both were found
  by hand, late.

  The job asserts it really is 5.x Desktop before doing anything (a silent
  fallback to pwsh would duplicate the other job while appearing to add
  coverage), and reads the first **bytes** of each document rather than only
  parsing it — `ConvertFrom-Json` on 5.1 accepts a BOM happily, so a parse-only
  check would have passed on the exact bug the job exists for.

### Fixed
- **`-Modules a,b` was broken when run from a PowerShell prompt.** Called that
  way PowerShell parses `a,b` in argument mode as an *array*, and
  `Read-ArgValue`'s `[string]` cast flattened it to `"a b"` — which then split
  on `,` into one bogus module name. The run failed loudly (`No valid modules
  were run`, exit 1) rather than collecting the wrong thing, but the invocation
  the README documents did not work from the shell a responder is most likely
  to be sitting in. Found while measuring for the correlation work.
- **`@(...)` over a `List[object]` in the correlation pass** threw *Argument
  types do not match* on Windows PowerShell 5.1 while working on pwsh 7 — the
  same 5.1 trap that silently emptied `moduleLimitations` in 1.4. Caught by the
  `windows-ps51` CI job added earlier in this cycle, which is exactly what it
  was built for.

- **A contract test blamed the collector for a host that would not run its own
  probe.** T9 raises a finding on purpose by copying the system `sleep` to
  `/tmp` and running it. On a distribution that builds coreutils as a single
  multi-call binary, `sleep` dispatches on `argv[0]`: copied to another name it
  prints `coreutils: unknown program` and exits at once. The probe never
  existed, so the assertion reported `NOFINDING` — which reads as *the
  collector missed it* and sends whoever is looking at the wrong component. A
  runner image change was enough to expose it.

  The probe is now a copy of `bash`, which does not dispatch on its own name
  (and is run as `-c 'sleep 300; :'`, because bash `exec`s a lone external
  command and would otherwise point `/proc/PID/exe` at `/bin/sleep`). The probe
  being **running** is its own assertion now: *"the allowlist engine is broken"*
  and *"this host would not run the probe"* are two findings that need two
  different people, and the suite says which one it has.

## [1.4.0] — 2026-10-26

### Added
- **`motw` module** (32 → 33): Mark-of-the-Web from the `Zone.Identifier`
  alternate data stream — which files arrived from outside the machine, and the
  URL they came from. Every other execution-evidence module answers *what ran*;
  this one answers *where it came from*, which is what turns a suspicious binary
  into a narrative. The stream is read with `-Stream`, so the file's own
  contents are never touched. Declared at **3.3 s measured** — the slowest
  module in the set, bounded at the 400 newest files per location, and it says
  so through a limitation when a location holds more.
  Stated in the output and as a limitation: MOTW lives in an NTFS stream, so a
  copy through FAT/exFAT, most archive tools, or `Unblock-File` drops it. A file
  *without* the stream is not evidence of local origin — presence is evidence,
  absence is not.
- **`summary.moduleLimitations`**: what each module could *not* do, as
  `{module, limitation}`. This is the field schema 1.3 considered putting on
  every finding and refused, because *"could not read /proc/N"* describes a
  module. On Windows it needed no call-site changes at all: every existing
  `Add-Note` — *"RecentFailedLogons was NOT measured"*, *"capped at N by
  -MaxEvents"*, *"fell back to netstat"* — was already a limitation statement
  readable only by whoever opened the log, and is now queryable. Linux gains the
  same `add_note`. **Absence of a finding means nothing until this array is
  read**: a module that collected less than its section header claims is the
  difference between "clean" and "not looked at".
- **Two Windows modules: `rmm` and `useractivity`** (30 → 32). Both answer a
  question the toolkit could not: *who else has hands on this host*, and
  *what did a person actually run*.

  | | `rmm` | `useractivity` |
  |---|---|---|
  | Time | 0.4 s measured | 0.9 s measured |
  | Admin | not required | not required, by design |
  | Output | metadata + the tail of a plain-text log | names, counts, timestamps, extracted paths |
  | AV risk | none — no executable is read, hashed or parsed | none |

  `rmm` detects 22 remote-access products by running process, service and
  install path, then reads the connection histories that are plain text and
  readable without admin (AnyDesk `connection_trace.txt`, TeamViewer
  `Connections_incoming.txt`). Presence is `Review` — this tooling is usually
  the IT team's. An RMM client running from a **user-writable** location is
  `High`: that is the portable-client pattern, dropped and run rather than
  installed. The product table is detection-by-presence, so a wrong path or a
  renamed process is a miss, never a false positive; it is not exhaustive.

  `useractivity` reads UserAssist (ROT13 names, run count, last-run FILETIME),
  MUICache, RunMRU, Jump Lists and CryptnetUrlCache — all from HKCU and the
  running user's own profile.

  **It therefore sees one user.** Another account's `NTUSER.DAT` is locked on a
  live host and would need Administrator plus a shadow copy, which is the trade
  this project already refused for SRUM and Amcache. The module says so in the
  report and raises a `NOTE`, because on a shared or service-account host
  "nothing found" and "nothing found *for this account*" are different answers.
- Both new modules are **Windows-only**, so the module counts are now 32 and 18.
  That is a deliberate widening: the output contract is what the two editions
  share, not the module list, and these artifacts have no Linux equivalent.
  Nothing in `schema/` or the contract harnesses changes shape.
- `tests/test-json-escape.sh` — twenty-nine inputs run through **every path**
  `json_escape` has, including the no-`python3` fallback, which the test forces
  by shadowing `python3`. The assertion is a round trip through a real JSON
  parser rather than a byte comparison, so it pins the contract and not one
  escaper's style. Wired into CI. Against the previous implementation it fails
  fourteen cases.
- `tests/Test-EncodedArg.ps1` and `tests/fixtures/encodedarg-cases.tsv` — fifteen
  cases that pin the pattern in both directions at once: the abbreviations must
  match, `-Encoding` and `-ExecutionPolicy` must not. Wired into CI.
- `CONTRIBUTING.md` now states the **architectural invariants** — the short list
  of properties that cannot be traded away, each with the failure it prevents —
  and the four things a new module must declare before it can be in the default
  set. Written because the project now takes outside contributions, and a forker
  needs to know which few things are not open to change.
- `.github/scripts/check_contract_parity.py` — the Win↔Linux parity gate
  described under **Changed**.
- **Output schema 1.3 — findings now carry their evidence.** Five properties,
  on every finding, on both editions:

  | Field | What it answers |
  |---|---|
  | `paths[]` | *Which files is this about?* Exactly the set the allowlist, publisher, hash and IOC passes can reach — so it is also the audit trail for a suppression: a finding with an empty `paths[]` can never be hidden by a path, publisher or hash rule. |
  | `confidenceReason` | *Why that number?* `confidence` was a magic constant the consumer had to look up. |
  | `iocIndicator` | *Which indicator matched?* Previously readable only by parsing the `IOC match: <indicator> \| ...` prefix of `detail` (still written, for human readers). |
  | `module` | *Which collector made this claim?* |
  | `collected_at` | *When within the run?* Not the same as `generated`. |

  Additive and optional: a 1.2 consumer keeps working against a 1.3 document.
  Both test harnesses nonetheless require all five on **every** finding —
  optional is a promise to the consumer, not a licence for the producer to
  skip them. A field that is present nine times out of ten is worse than no
  field, because a rule written against it fails on the tenth.

  Three fields that were proposed were **left out**, and the reasons are the
  point: `hashes[]` would hash files at finding time, which is extra I/O and,
  worse, reads executables — the behaviour most likely to wake an EDR, against
  the project's own constraint. `limitations[]` describes a *module* ("could
  not read /proc/N: permission denied"), not a finding, so putting it on each
  finding would have produced copy-pasted boilerplate; it belongs in the
  summary. `found_in[]` (de-duplication) was then **dropped entirely**, on
  evidence: see below.
- `tests/test-gs-array.sh` — the Linux findings pipeline is a flat
  separator-delimited record, and `paths[]` is the first array in it. Carrying
  an array there is only safe while a string collected from the suspect host
  cannot smuggle a separator into the record, so that defence is pinned by a
  test instead of a comment. Removing the sanitisation makes five of its
  assertions fail — including `module` reading back as `T1059` and
  `collected_at` as `0.4`, which is the column-shifting forgery it exists to
  stop.

### Changed
- **Both contract harnesses now assert the same rule set, and CI fails if they
  drift.** `tests/run-tests.sh` and `tests/Invoke-Tests.ps1` run in separate
  jobs on separate runners, so nothing had ever compared them: a rule dropped
  from one would leave the schema valid, both jobs green, and that edition
  quietly no longer held to the contract. `check_contract_parity.py` compares
  the rules each harness claims to prove and names any the other is missing.
  Four real gaps turned up on the first run, two of them silent-skip bugs:
  Windows wrapped its `stats` and `modulesSkipped` assertions in
  "if the key exists", so a producer that dropped either key would have made
  the assertions **disappear** rather than fail. Both are now unconditional.
- Both harnesses also assert that every contract check actually ran. A
  malformed PowerShell argument had made three assertions raise an error
  instead of run, and the suite still printed `0 failed` with a quietly
  smaller total — an assertion that vanishes is worse than one that fails.
- `paths[]` is carried between the Linux modules and the JSON writer as
  `0x1D`-separated elements inside the existing `0x1F` column, **not** as JSON
  in a column and not by moving the pipeline to NDJSON. The current design has
  modules write raw bytes with exactly one place turning them into JSON;
  NDJSON would have spread that one thing-that-must-never-be-wrong across all
  eighteen module emit sites. Both separators are now stripped from every
  collected string at the point it enters a finding.
- `json_escape` no longer forks for a string that contains nothing to escape —
  the overwhelmingly common case. It used to spawn a `python3` process per
  field (~13 ms each, six per finding), so a run producing 200 findings spent
  roughly 15 seconds escaping text that needed no escaping. Measured on the
  same host, 100 calls went from 1.27 s to 0.001 s. No output changes.
- The docs gate now holds the **version badges** to the collectors' own version
  constant, in both READMEs. The badge read `1.2` for the whole 1.3 line; a
  badge is the first thing a reader believes, so it is checked like the module
  counts are. The README changelog had also stopped at v1.2.5, still marked
  `(current)` — v1.3.0 is now recorded there.

### Removed
- **De-duplication (`found_in[]`) was cut after measuring, not after
  discussing.** The plan assumed several modules raise the *same* finding.
  They do not: all 13 Linux and all 22 Windows `Add-Finding` sites use
  distinct message templates, and a crafted probe (an executable in `/tmp`,
  running) produced two findings sharing one path with **no** duplicate
  `(category, message)` anywhere. What the probe showed is the opposite of a
  duplicate — `process` reporting *"executing from a suspicious path (PID 10)"*
  and `indicators` reporting *"2 executable file(s) in /tmp"* are two
  independent signals about one file, and merging them would have thrown away
  the PID, the aggregate's count, and the fact that two separate checks fired.
  Three weak signals agreeing is evidence; one merged record is not.
  The real need behind the item — "don't make me notice the same file three
  times" — is already met by `paths[]` from schema 1.3: grouping findings by
  shared path is now one line in any consumer. Adding a field for something a
  consumer can derive would be the schema bloat 1.3 was careful to avoid.

### Fixed
- **Every timestamp is now one format: ISO 8601 UTC, second precision, on both
  editions.** Windows wrote `2026-10-26T21:01:29.1909204+08:00` while Linux
  wrote `2026-10-26T13:01:29Z`, so output from the two editions could not be
  sorted together without a parser that normalises offsets — and a 1.3 document
  carried both shapes at once, `collected_at` in `Z` beside `generated` with an
  offset. One `Get-IsoUtc` now produces every timestamp the Windows edition
  writes, the shape is a `pattern` in both schemas from 1.4 on, and both
  harnesses assert it on the raw text rather than through a parser that would
  erase the very thing being checked.
- **`moduleLimitations` would have shipped empty, silently.** On Windows
  PowerShell 5.1 an array subexpression over a `List[object]` inside an
  `[ordered]@{}` literal throws *"Argument types do not match"* — and assigned
  to a variable first it evaluates to **empty with no error at all**. The first
  form broke `summary.json` outright, which is how it was caught; the second
  would have produced a well-formed document that simply never reported a single
  limitation. `.ToArray()` has neither behaviour.
- **`summary.json` and `findings.json` were written with a UTF-8 BOM on Windows
  PowerShell 5.1** — the version this tool declares as its minimum and the one
  most responders run it with. `Out-File -Encoding UTF8` means *with* a BOM on
  5.1 and *without* on PowerShell 7; a leading BOM is not valid JSON text to a
  strict parser, and Python's `json.load` refuses the file outright. CI runs
  pwsh 7, so for three releases the flagship producer shipped a machine
  contract that a standard parser rejected, on the edition it is most often
  used with, and nothing noticed. Both documents now go through one writer with
  an explicit BOM-less encoding, and **both harnesses assert the first three
  bytes** rather than trusting whichever PowerShell they happen to run under.
  Found while validating the two new modules' output — the second defect this
  month whose whole cause was CI exercising one PowerShell and users another.
  The first version of that assertion read the bytes with
  `Get-Content -Encoding Byte`, which exists only on 5.1 and throws on pwsh —
  the same edition split, in the opposite direction. CI caught it, and it caught
  it through the *"every contract check ran without an error"* guard added last
  week: the BOM check errored instead of running, and that guard is precisely
  what stops a vanished assertion from passing as a green suite. It now reads
  bytes with `[IO.File]::ReadAllBytes`, which has no edition.
- **The first draft of `useractivity` raised 142 false findings, and the fix is
  the interesting part.** The obvious rule — flag any execution record outside
  Program Files — was written first and then measured on a real workstation. It
  produced 144 findings: installers in `Downloads`, MSIs in `Package Cache`, an
  Electron app's `updater.exe`. On modern Windows, `AppData` and `Downloads`
  *are* where ordinary user software lives, so location alone carries almost no
  signal, and burying two real findings under 142 false ones is worse than
  raising none at all.

  What replaced it: a script host or an executable-by-another-name
  (`.hta`, `.scr`, `.pif`, `.vbs`, `.bat`, `.ps1`, …), a double extension
  (`invoice.pdf.exe`), or a launch from `Windows\Temp`, `Users\Public` or a
  UNC path. A `.lnk` is exempt from the directory rule, because a shortcut is
  a pointer and every installer drops one on the Public Desktop — judging
  shortcuts by where they live had flagged Acrobat, Wireshark and Steam.
  MUICache carries no timestamp and no run count, so on its own it is inventory,
  not a lead; it earns a finding only when the entry is both unusual in kind
  **and** no longer on disk. Same workstation, after: **10 findings**, and the
  one that matters is a crypto miner's `.bat` that is no longer there.
- **The same draft took 5.7 s, against a declared budget of 2.** 5 MB of Jump
  Lists were being decoded to UTF-16 and regexed in full. The module now reads
  newest-first under a 6 MB budget with a 512 KB per-file cap, and when it hits
  the budget it **says so** in the report and raises a `NOTE` — a module that
  quietly does less than its own section header claims is the silent-skip defect
  this project keeps finding. Measured after: **0.9 s**.
- Jump List and CryptnetUrlCache findings are now bounded aggregates rather than
  one-per-item: a per-file finding would scale with how many applications the
  user has, which is not the thing being measured.
- `useractivity` leaves `{GUID}`-prefixed UserAssist paths untranslated and
  explains why in the report. A guessed KNOWNFOLDERID or Jump List AppID mapping
  in a forensic record is worse than an untranslated one — the same reason the
  AppID is not decoded to an application name.
- The collectors stated their version **twice** — the comment header carried
  `TATAR Triage Toolkit v1.3.0` a few lines above the single version constant,
  the same trap the banner had before it was fixed: a second copy a bump
  leaves behind. The header no longer names a version, and the docs gate now
  fails if either collector mentions its version more than once.
- `.gitignore` now ignores **collector output** (`summary.json`,
  `findings.json`, `tatar.log`, the dated evidence folder, the manifest and
  the chain-of-custody file). These were ignored only in a local
  `.git/info/exclude`, which is not committed — so anyone who cloned the repo
  and ran the collector inside it could commit a real host's triage output:
  hostname, user list, process list, from a machine that may be under
  investigation. Ignoring them is part of the tool's read-only promise.
- README now says to hash the files **as downloaded from the release**:
  `Tatar.ps1` ships CRLF per `.gitattributes`, so a copy from a `git clone`
  on a system that rewrites line endings hashes differently while being the
  same source. Verified against v1.3.0 — the published asset is exactly the
  tagged blob with CRLF applied, and `SHA256SUMS.txt` matches it.
- **The Linux JSON escaper emitted invalid JSON on a host without `python3`.**
  `json_escape` escaped only `\` and `"` on its fallback path and passed every
  other control character through untouched, so a single `0x07` or `0x1B` byte
  in a filename on the suspect host — attacker-controlled input, on a forensic
  tool — was enough to make `summary.json` and `findings.json` unparseable for
  everything downstream. The fallback now escapes the whole C0 range (`\b \f
  \n \r \t` named, the rest as `\u00XX`) in `awk`, and is covered by tests.
- **`-EncodedCommand` was looked for in two places and both were wrong, in
  opposite directions.** `Collect-Process` matched the regex `'-enc '`, so every
  abbreviation and every form without a trailing space went unnoticed;
  `Collect-ObfScan` matched the literal `-enc` with `-SimpleMatch`, so it flagged
  `-Encoding utf8` in ordinary scripts — a false positive on a module whose whole
  job is to read the user's own Downloads and Desktop. Both now share one
  pattern (`$script:EncArgPattern`) that accepts the abbreviations
  powershell.exe accepts, at a token boundary, and stops before `-Encoding`.
- The passwordless-account finding said logon without a password "is possible".
  `PasswordRequired` is a policy flag, not proof that an account has no password
  or that it can be logged into; the detail now says **UNCONFIRMED** and what to
  confirm it against.

## [1.3.0] — 2026-10-12

Contributed by Yalguun Tumenkhuu ([@fg0x0](https://github.com/fg0x0)), reviewed
and merged by the maintainer. A minor version, not a patch: the output filenames
and several `stats` keys changed, so anything parsing a previous run's output
needs updating — see **Changed** below.

Closes the seams between the two editions. Nothing here changes what the
collectors look for — it changes what they *promise*: the "unified" summary.json
used six different key spellings for the same concepts, the Windows producer was
never validated against the schema it is the flagship of, an unknown flag was
swallowed by `-Silent`, and a value-less `--output` wrote the evidence tree to
`/`.

### Fixed
- **The evidence manifest never verified.** The consolidated report had its
  closing `=== Collection finished ===` line appended *after* the manifest had
  already hashed it, so one entry was wrong on every run, on both platforms.
  Found while checking that the new Windows manifest is `sha256sum -c`-clean;
  the trailer is now written before the manifest is built, and both suites
  assert that every manifest hash still matches its file.
- **A value-taking flag consumed the next token unguarded.** `--all --output`
  left the output base empty and built the evidence tree at the filesystem
  **root** of the suspect host — the one place the tool's own documentation says
  never to write — and `--output --caseid IR-1` silently dropped the case id
  from `chain_of_custody.txt` while the collection appeared to succeed. Both
  editions now reject a missing value with `[x] FATAL: <flag> requires a value`
  on stderr and exit `1`, the usage-error code the READMEs already document.
  Windows had the missing-token half of this guard but not the next-token-is-a-
  flag half: `-OutputPath -CaseId x` created a directory called `-CaseId`.
- **summary.json was not actually unified.** Five concepts were spelled
  differently per platform (`RecentFailedLogins`/`RecentFailedLogons`,
  `LocalUsers`/`Accounts`, `Services`/`RunningServices`,
  `RecentTempExecutables`/`ExecInTempDirs`, `TcpConnections` vs
  `ListeningTcpPorts`+`EstablishedConnections`), and Linux quoted every counter
  while Windows emitted native integers. One canonical key per concept now, a
  JSON **number** on both platforms, and the agreed keys are listed in the
  schema (`stats.x-canonicalStatKeys`) and asserted by both test suites, so a
  seventh spelling cannot be invented by accident. Windows `tool` and Linux
  `tool` are now the same string too — `platform` is the discriminator.
- **The Linux collector never emitted the `FAILED` log level** its own header,
  help text and `summary.txt` tell the analyst to grep for, and discarded every
  module's exit code. A module that produced none of its evidence read as a
  clean run, which turns missing evidence into apparent negative evidence. Every
  `m_*` function now returns a deliberate status and the dispatcher logs
  `FAILED` and counts an error when a module's primary artifact was not
  produced. (Two modules end on a `grep` whose "no match" is exit 1, so the
  naive version of this fix reported FAILED on every healthy host.)
- **Unknown options and unknown module names were console-only warnings.**
  `-Silent`/`--silent` exists for WinRM / cron runs where nobody is watching the
  console — exactly when a misspelled `--modules netwrok` needs to be
  discoverable. Both are now written to the execution log, counted as errors
  (exit `2`) and reported in `summary.json` as `modulesSkipped[]`.
- **The noisiest finding could not be reached by the allowlist.** The
  temp-executables aggregate named no file, so on Windows no rule could ever
  match it, and on Linux the only extracted token was the *directory* `/tmp` —
  which `dpkg -S` reports as owned by `base-files`, so the shipped
  `allowlist.sample.json` suppressed the whole finding for a reason that had
  nothing to do with the files it counted. Both editions now put the first ten
  real paths into `detail`, a finding is suppressed only when **every** path it
  names is known-good, and a directory never satisfies package ownership.
- Windows: `Get-LocalUser` was collected and never inspected, and the hosts file
  was written to `hosts.txt` and never read back, while `docs/MITRE_ATTACK.md`
  advertised a Windows hosts-tampering check and a non-existent `hosts` module.
  The same incident produced a High finding on a Linux host and silence on a
  Windows one.

### Added
- **`--dry-run` / `-DryRun`** (alias `--preview` / `-Preview`) on both editions:
  prints the resolved output directory, whether it is on the system drive / root
  filesystem, privilege status, the module list in run order, which gated
  operations are armed (`-CollectHives`, `-MemoryDump`, `--dump-deleted`, …) and
  whether the allowlist / IOC feeds can be read — then exits `0` **without
  creating or writing anything**. Every one of those inputs was already computed;
  it just ran after the output directory had been created, i.e. after the first
  write to the disk the collector exists to preserve.
- Windows findings for the two checks Linux already had: an enabled local
  account with **no password required** (High, T1078) and members of local
  **Administrators** other than the built-in RID-500 account (Review, T1078),
  plus the `/etc/hosts` analogue — non-default entries in the Windows hosts file
  (Review, T1565.001).
- `schema/findings.schema.json` for the SOAR / SIEM feed, whose only check used
  to be that it parses. Its `findings[]` definition is kept byte-identical to
  `summary.schema.json` (asserted by `tests/run-tests.sh`) so it validates
  standalone, and `activeFindingsCount` / `suppressedCount` are now *declared*
  in both schemas — the `active + suppressed == findings` invariant was enforced
  in four harnesses and documented in none.
- `.github/scripts/validate_summary.py`, used by **both** CI jobs: the Windows
  producer was previously only checked for being parseable JSON, so the flagship
  collector was never held to the schema it anchors.
- `docs-parity` CI job (`.github/scripts/check_docs_parity.py`): asserts the
  module-count badges against the two module registries, that the English and
  Mongolian module lists name the same modules, that every ATT&CK technique
  a collector can emit has a row in `docs/MITRE_ATTACK.md` (one-directional —
  the doc also maps evidence for techniques no finding raises, by design), and
  that every name in an ATT&CK **Module** column is a real module — the Linux
  table listed the finding *category* `context` as if it were a module while
  `containers`, which actually raises it, appeared nowhere, and a technique-id
  diff cannot see that.
- `tests/test-allowlist-path.sh` + `tests/Test-AllowlistPath.ps1` over a shared
  `tests/fixtures/allowlist-path-cases.tsv`: the path extractors decide which
  files an allowlist can reach at all, and nothing tested them. The table also
  locks in the warts it found (a URL, a cron schedule and a trailing period all
  yield tokens) so they cannot change unnoticed.
- Regression tests on both platforms for the value-less flag (exit 1, nothing
  written to `/`), the swallowed unknown option / module (exit 2, logged,
  `modulesSkipped[]`) and the dry run (exit 0, no directory created), plus
  assertions that a healthy run logs no `FAILED` module and that the manifest
  it wrote actually verifies.
- `tests/fixtures/allowlist-positive.json` and a Linux end-to-end test that
  **raises a finding on purpose** (a process running from `/tmp`) and requires
  the allowlist to suppress it. Every suppression assertion in the suite used to
  hold trivially while `suppressedCount` was 0, so the entire v1.2 allowlist
  engine could have degraded to a no-op with the suite still green.

### Changed
- **Windows output artifacts are renamed and reformatted for parity** — update
  any pipeline that globs them: `manifest_sha256.csv` → `manifest_sha256.txt`
  in `sha256sum` format (LF, no BOM, `<hash>  ./<relative path>`, so
  `sha256sum -c manifest_sha256.txt` now verifies a Windows evidence folder as
  well as a Linux one), `binary_hashes.csv` → `binary_hashes.txt`, and
  `Tatar.log` → `tatar.log` (the two spellings collided when an analyst merged
  a Windows and a Linux output folder).
- `Add-Finding` / `add_finding` now fail loudly on an unknown severity instead of
  silently assigning confidence `0.3` — a value no collector emits and both
  suites reject, which is why `0.3` is also gone from their allowed sets. `Info`
  stays in the schema enum as the consumer-facing contract, with a description
  saying the shipped collectors emit only `High` and `Review`.
- `docs/banner.src.svg` (was `banner.svg`, referenced by nothing) is documented
  in CONTRIBUTING as the editable source for `banner.png`.

## [1.2.5] — 2026-09-28

Fixes four ways the collector could quietly do less than it was asked to. Found
by reading the allowlist / IOC pipeline end to end before leaving the project
alone for a while — none of these crash, corrupt output or break the JSON
contract, which is exactly why the existing tests stayed green.

### Fixed
- **An unreadable `--allowlist` / `--ioc` path was skipped in silence.** A typo
  in the filename meant a full collection ran with no matching applied, no
  warning anywhere, and exit code 0. The analyst then reads *"No active
  findings"* believing their feed was applied. For a triage tool that is the
  worst possible failure: not a wrong answer, but false reassurance. Both paths
  are now checked up front — before any collector runs, so the run can be
  stopped and fixed — and an unreadable one prints a red warning, is logged as
  an error, and forces exit code `2`.
- **Windows: IOC Pass A hashed only the first path named in a finding.** A
  message like `x.exe launched from y.dll` had `y.dll` ignored, so a hash
  indicator for it never matched. Every path mentioned is now considered, and
  paths that are not on disk are skipped. This brings the pass in line with the
  allowlist loop directly above it (which already enumerated all candidates) and
  with the Linux `al_path_of` helper fixed in 1.2.3.
- **Pass B tagged every new IOC finding `T1071`** (Application Layer Protocol)
  on both editions, including filename and hash hits, where it is simply wrong —
  and a wrong ATT&CK mapping is worse than none. The technique now follows the
  indicator type: `T1071` for an IP, `T1071.004` for a domain, `T1204.002` for a
  filename, `T1588.001` for a hash.
- **Windows: Pass B could match the tool's own output.** Pass A writes
  `IOC match: <indicator>` into a finding and `Tatar.log` can quote an indicator
  back, so a second finding could be raised about TATAR rather than about the
  host. Those lines are now skipped, as the Linux edition already did.
- **Windows: `environment.container` and `containerRuntime` were never
  populated**, so every Windows run claimed it was not in a container while the
  Linux edition detected docker/podman/lxc. Windows containers exist; the
  documented signals (`cexecsvc`, `ContainerAdministrator`) are now checked.

### Added
- Test case T5 on both editions: a feed path that does not exist must produce
  exit code `2`, a logged error per file, and a log line naming each file as not
  applied. The contract tests already covered *malformed* feed files; nothing
  covered a *missing* one, which is how this class of defect survived.

## [1.2.4] — 2026-09-27

Detection fix found by a new unit-test layer. No new collectors, no schema change.

### Fixed
- **An IPv4 indicator could never match in the evidence that matters most.**
  v1.2.3 made IOC matching boundary-aware and treated a colon as part of an
  address, so that an IPv6 literal could not be cut in half. But `netstat`,
  `ss`, firewall logs and almost every other source write an address as
  `addr:port` — and with `:` counted as part of the address, `127.0.0.1` did not
  match `127.0.0.1:445`. The IPv4 and IPv6 rules are now separate: only a digit
  or a dot extends an IPv4 address, while an IPv6 literal keeps the stricter
  hex/dot/colon boundary. As a side effect an IPv4 inside an IPv4-mapped IPv6
  address (`::ffff:127.0.0.1`) is now correctly recognised as that address.
- **Linux: the IPv6 boundary only rejected decimal digits**, so `fe80::1` still
  matched inside `afe80::1`. It now rejects any hex digit, matching the Windows
  rule.

### Added
- `tests/Test-IocBoundary.ps1`, `tests/test-ioc-boundary.sh` and
  `tests/fixtures/ioc-boundary-cases.tsv` — unit tests that call the matchers
  (`Get-IocPattern`, `ioc_match`) directly, rather than inferring their
  behaviour from a full collection. Both editions run the *same* 23-case table,
  so a rule cannot hold on one platform and quietly differ on the other, and a
  regression names the exact case instead of a missing finding. Each matcher is
  lifted out of the collector by text, so no test ever runs a collection.
  CI runs them on Windows and Linux.

## [1.2.3] — 2026-09-22

Correctness pass, driven by a new test suite. No new collectors, no schema change.

### Fixed
- **IOC matching was substring-based on both editions**, so a partial indicator
  raised a false `High` / `0.95` finding: `127.0.0` matched `127.0.0.1` and
  `ocalhost` matched `localhost`. Indicators are now matched on a boundary — IP
  literals may not be flanked by a digit, dot or colon; domains and filenames may
  not be flanked by a word character, dot or dash, so `evil.example.com` no
  longer matches `notevil.example.com` or `evil.example.com.mn`. Both the
  annotate pass and the evidence-scan pass use the same rule: Windows via a
  lookaround regex (`Get-IocPattern`), Linux via a portable `awk` helper
  (`ioc_match`) — GNU `grep -P` is not available everywhere.
- **Linux: `activeFindingsCount` was derived arithmetically** while the
  suppressed tally was tracked by hand across two passes. It is now counted from
  the findings data, so `active + suppressed == findings` cannot drift.
- **Linux: `"packageOwned": false` was ignored without `python3`**, leaving
  package-ownership suppression silently on.
- **Windows: the allowlist hash check only inspected the first SHA-256** in a
  finding; every hash mentioned is now considered.
- **Linux: the IOC evidence scan only looked at the consolidated report**, while
  the Windows edition scans every collected text artifact. Linux now scans the
  whole output folder too (`*.txt`, `*.csv`, `*.log`, minus `summary.txt`), so an
  indicator that appears only in `timeline.csv` or under `logs/` is no longer
  missed.
- **Windows: allowlist and IOC path extraction was limited to seven extensions**
  (`exe|dll|sys|ps1|bat|scr|cmd`), so a finding about a `.vbs`, `.jse`, `.lnk` or
  `.dat` file could not be allowlisted or hashed. Any extension is accepted now.
- **Linux: `al_path_of` returned the first absolute path in a finding**, which
  hashed or globbed the wrong file when a message mentioned several ("/tmp/x runs
  from /usr/bin/foo"). It now prefers a path that exists on disk.
- **Windows: findings appended by IOC Pass B were dropped** if the IOC block then
  threw, because the re-sort lived inside the `try`. It now runs outside it.

### Changed
- `iocMatch` is documented for what it is: a boolean. The matched indicator is
  prefixed into `detail` as `IOC match: <indicator> | ...`. Schema description and
  both README languages say so now (carrying the indicator in its own field is a
  v1.3 candidate).
### Added
- `tests/` — black-box contract tests for both editions (`Invoke-Tests.ps1`,
  `run-tests.sh`, `fixtures/`). They assert the output contract only: schema
  version, SemVer tool version, `findings` never null, `active + suppressed ==
  findings`, unique well-formed ids, findings v2 fields, severity and confidence
  from the fixed sets, an IOC hit implying High/0.95/active, and a reason on
  every suppressed finding. Four cases: baseline, partial IOC tokens that must
  NOT match, a sentinel token that must match, malformed allowlist/IOC files that
  must warn and carry on. CI runs them on Windows and Linux.
## [1.2.2] — 2026-09-14

Docs and release-process patch. No collector, finding or schema changes.

### Changed
- The collector's SHA-256 is no longer hard-coded in the README. Every release
  ships `SHA256SUMS.txt`, which is now the single source of truth for hashes —
  the README points there and shows the verify command for each platform. (The
  hash printed in the README had gone stale at the v1.0 value.)
- **Release automation** (`.github/workflows/release.yml`): pushing a `v*` tag
  builds `SHA256SUMS.txt` in CI and attaches `Tatar.ps1`, `tatar-linux.sh` and
  both sample files to the GitHub release, taking the release notes from this
  file. Assets and hashes are no longer assembled by hand.
- Tool version is `1.2.2` on both editions, so tag, tool output and release agree.

### Fixed
- CONTRIBUTING: a stray control character in the Mongolian versioning section.

## [1.2.1] — 2026-09-07

Release-hygiene patch for 1.2.0 — no collector or schema changes.

### Fixed
- Tool version reported as `1.1` in `summary.json`, banner, help, summary,
  execution log and chain of custody on both editions. Version is now a single
  constant (`$script:ToolVersion` / `VERSION`) and reads `1.2.1`.
- `ioc.sample.json` shipped an MD5 hash; both IOC engines compare SHA-256 only,
  so the sample could never match. Replaced with the SHA-256 of the EICAR test
  file (safe to test a hit) and documented the SHA-256-only rule.
- Linux README was still at v1.1: badge, `--allowlist` / `--ioc` options and an
  Allowlist & IOC section added; line endings normalized to LF per
  `.gitattributes`.
- README: duplicate "(current)" label on the Schema 1.1 section.

### Changed
- CI now also runs both editions with `allowlist.sample.json` + `ioc.sample.json`
  and asserts `schemaVersion 1.2`, a SemVer tool version, findings v2 fields and
  `activeFindingsCount + suppressedCount == findings`.
## [1.2.0] — 2026-09-02

### Added
- **Allowlist engine** (`-Allowlist` / `--allowlist`): suppress known-good
  findings by path glob, Authenticode publisher (Windows), package ownership via
  `dpkg`/`rpm` (Linux), or SHA-256. Suppressed findings are kept for audit with a
  reason — never deleted.
- **IOC engine** (`-IOCFile` / `--ioc`): offline `hashes/ips/domains/filenames`
  feed. Pass A annotates findings (`iocMatch`) and a hit overrides the allowlist
  (re-activate + escalate to High/0.95); Pass B raises new findings for IOCs seen
  in the collected evidence, deduplicated against Pass A.
- Finding v2 fields: `id`, `confidence`, `suppressed`, `suppressReason`,
  `iocMatch`; summaries gain `activeFindingsCount` / `suppressedCount`.
- **Architecture** section in the README — system architecture, data flow, and the allowlist/IOC scoring model.
- `allowlist.sample.json` (`packageOwned` flag) and `ioc.sample.json` samples.

### Changed
- `summary.json` / `findings.json` bumped to `schemaVersion 1.2`. Backward
  compatible: `schemaVersion` is an enum and all v2 finding fields are optional.

### Fixed
- **Linux findings pipeline** now uses the ASCII Unit Separator (0x1F) instead of
  TAB. Bash `read` collapses consecutive whitespace-IFS delimiters, which
  silently dropped empty fields (empty detail/technique/suppressReason) and
  shifted every later column.

## [1.1.0]

### Added
- Cross-platform Linux edition (`linux/tatar-linux.sh`) sharing the unified
  `summary.json` schema.
- Triage summary (`summary.txt` + `summary.json`), findings-only `findings.json`
  for SOAR/SIEM, timestamped execution log, `-Silent` mode, and explicit exit
  codes (`0` ok, `1` fatal, `2` completed with errors).
- MITRE ATT&CK `technique[]` mapping (incl. sub-techniques), persistence ASEP
  coverage, process genealogy, expanded event-ID collection.

## [1.0.0]

### Added
- Initial release: 30 Windows collectors in RFC 3227 order of volatility, chain
  of custody, SHA-256 manifest, optional archive, and hive/EVTX/memory switches.

[1.4.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.4.0
[1.3.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.3.0
[1.2.5]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.5
[1.2.4]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.4
[1.2.3]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.3
[1.2.2]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.2
[1.2.1]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.1
[1.2.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.0
[1.1.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.1.0
[1.0.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.0.0
