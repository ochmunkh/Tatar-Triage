# Changelog

All notable changes to TATAR Triage Toolkit are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); versions use
[SemVer](https://semver.org/).

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

[1.2.3]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.3
[1.2.2]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.2
[1.2.1]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.1
[1.2.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.0
[1.1.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.1.0
[1.0.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.0.0
