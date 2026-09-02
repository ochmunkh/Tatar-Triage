# Changelog

All notable changes to TATAR Triage Toolkit are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); versions use
[SemVer](https://semver.org/).

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

[1.2.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.0
[1.1.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.1.0
[1.0.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.0.0
