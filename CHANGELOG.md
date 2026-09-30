# Changelog

All notable changes to TATAR Triage Toolkit are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); versions use
[SemVer](https://semver.org/).

## [Unreleased]

Closes the seams between the two editions. Nothing here changes what the
collectors look for — it changes what they *promise*: the "unified" summary.json
used six different key spellings for the same concepts, the Windows producer was
never validated against the schema it is the flagship of, an unknown flag was
swallowed by `-Silent`, and a value-less `--output` wrote the evidence tree to
`/`. Version numbers are deliberately left alone; bump them at release time.

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

[1.2.5]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.5
[1.2.4]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.4
[1.2.3]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.3
[1.2.2]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.2
[1.2.1]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.1
[1.2.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.0
[1.1.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.1.0
[1.0.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.0.0
