# Security and robustness testing

This document records what the Tatar Triage Toolkit is tested against, how to
re-run it, and what is **not** covered. It maps tests to requirements from OWASP
and NIST so a reviewer can see what each check is for.

It is a test map, **not a compliance claim**. The collector is a small offline
script, not a web application; only the ASVS and Top 10 items that make sense
for a local collector are listed, and each is matched to a concrete test.

## How to run

| Edition | Command | Time |
|---|---|---|
| Linux | `bash tests/test-security.sh` (needs `strace`; section S8 is SKIPPED without it) | about 2 min |
| Windows | `powershell -NoProfile -File tests\Test-Security.ps1` (`-Quick` skips the full `-All` timing run) | about 4 min, 10 with `-All` |
| Linux fixes | `bash tests/test-linux-fixes.sh` (SUID walk, journal extracts, named limitations) | seconds |
| Analysis tools and identity | `python3 tests/test-diff.py`, `test-timeline.py`, `test-aggregate.py`, `test-review.py`, `test-siem.py`; `bash tests/test-identity.sh`, `tests/test-recommendation.sh`; Windows: `tests\Test-Identity.ps1`, `Test-Recommendation.ps1` | seconds |
| Fuzz (Linux) | `python3 tests/fuzz.py [--iterations N]` | under 1 min |
| Fuzz (Windows) | `pwsh -File tests/Test-Fuzz.ps1` | under 1 min |
| Containment (Windows) | `tests\Test-Containment.ps1` in an elevated session; SKIP otherwise | about 3 min |
| Viewer | `python tests/test-viewer.py` (Playwright, not in CI) and `python .github/scripts/check_viewer.py` | seconds |
| Repo gates | the CI jobs: docs parity, contract parity, README parity, AV safety, viewer, schema validation, PSScriptAnalyzer, shellcheck | CI |

A test that cannot run is reported as `SKIP`, never as `PASS`.

## Result at v1.8.0

| Suite | Result |
|---|---|
| `tests/test-security.sh` (Linux) | 65 passed, 0 failed |
| `tests/Test-Security.ps1` (Windows) | 55 passed, 0 failed (full `-All` run 127 s, collector peak 417 MB) |
| Functional suites | Windows contract 233/233, Linux contract 45/45, all unit suites green |

## Requirement to test map

### OWASP ASVS 4.0 and Top 10 2021 (applicable subset)

| Reference | What it means for a collector | Tests |
|---|---|---|
| ASVS V5.1 / V5.3, A03 Injection | Arguments, output paths and feed files are data, never code | S1, S2, S3 / W1, W2, W3 |
| ASVS V5.3.3 output encoding | Host-supplied names and command lines cannot inject terminal escapes, bidi controls or spreadsheet formulas into reports | S4, S5 / W4 |
| ASVS V12.3 file execution, A03 | No file name on the examined host is ever executed | S4, S5 / W4 |
| ASVS V12.4 / V4.2, A01 Broken access control | Evidence is private to the examiner (mode 0700/0600; ACL without Everyone/Users) | S6 / W5 |
| A01, A05 | The collector refuses to write through a symlink or junction, and refuses to reuse an existing evidence folder | S7 / W6 |
| ASVS V10, A08 Integrity failures | Tampering with evidence or with the manifest is detected; the script that ran is recorded by hash | S9 / W7 |
| A02/A09 data handling and logging | Temp files are removed on normal exit and on signals; nothing is left in TEMP | S10, S11 / W9 |
| A05 Security misconfiguration | Runs unprivileged; no package, privilege or network program is started | S8, S12 / W8, W10 |
| ASVS V8 data protection | Strict UTF-8, no byte-order mark, Unicode round-trips | S13 / W11 |
| ASVS V13, A04 Insecure design | Budgets for time and memory; hostile feeds cannot hang or crash a run | S3, N1, N2 / W3, N1, N2 |

### NIST

| Reference | Requirement | Tests |
|---|---|---|
| SP 800-86 section 3.1 (collection) | Collection must not alter the host being examined | S8 (no writes outside the output folder), W8 (Run keys, startup, hosts, tasks, services, accounts unchanged) |
| SP 800-86 section 3.1.2, 3.3 | Integrity and chain of custody: hashes, tool identity, examiner and case recorded | S9 / W7 |
| SP 800-86 section 3.2 | Order of volatility is kept; results are repeatable | S14 / W12 determinism |
| SP 800-218 PW.7 / PW.8 (review, test) | Code is tested for security properties, with hostile input | all of the above |
| SP 800-218 PS.1 / PS.2 | Releases are verifiable: `SHA256SUMS.txt` and the viewer CSP hash gate | release workflow, `check_viewer.py` |
| SP 800-218 RV.1 | Defects found are fixed and recorded | see "Defects found" below |

## Fuzz tests

Random and mutated input goes to the code that parses text from the host or from
a feed file, and a property that must hold for every input is checked.

| ID | Target | Property |
|---|---|---|
| F1 | `json_escape` (Linux) | the output, quoted, parses and decodes to the exact input |
| F2 / Z2 | `csv_cell` / `Protect-CsvCell` | no cell begins a spreadsheet formula; quotes are doubled |
| F3 / Z3 | `hosts_entry` / `Format-HostsEntry` | only legal address and name characters survive; length is bounded |
| F4 / Z4 | `al_paths_of` / `Get-PathCandidate` | only absolute paths without forbidden characters are extracted |
| F5 / Z1 | `san_into` / `Remove-ControlChar` | no control, escape or bidi character survives |
| F6 / Z5 | mutated allowlist and IOC feeds | a run exits 0 or 2, `summary.json` stays valid, no shell error text |

The seed is fixed for reproducibility (`TATAR_FUZZ_SEED` varies it) and a failing
input is printed. At the time of writing the properties held for several seeds
and no new defect was found; fuzz input classes that fail are added as fixed
cases to the security tests.

## Supply chain

GitHub Actions are pinned to commit SHAs (the tag is kept in a comment) and
Dependabot proposes updates monthly. From the first release tagged after this
change, the release assets carry a build-provenance attestation. Verify a
download with:

    gh attestation verify Tatar.ps1 --repo ochmunkh/Tatar-Triage

## Defects found by these tests

The Linux suite was written first and made to fail against v1.7.0 before the fix.

| ID | Defect (edition) | Fix in 1.8.0 |
|---|---|---|
| A | Evidence was created world-readable (Linux) and with inherited ACLs (Windows) | Private permissions: umask 077 / protected ACL for SYSTEM, Administrators and the current user |
| B | A symlink or junction as output path, or an existing evidence folder, was followed or reused | Both refused with exit 1 |
| C | Terminal escapes and bidi controls from host file names and command lines reached summary, report and paste files verbatim | Replaced by U+FFFD at the write path; lone CR removed |
| D | Temporary files could survive an interrupted run (Linux) | Cleanup trap on EXIT, INT, TERM |
| E | `podman ps` created its storage and lock files on a host that had never run a container (Linux; found by the strace test on a CI runner) | podman is queried only when the user's container storage already exists |
| F | A signed download URL's credentials were copied into the Mark-of-the-Web finding (Windows, found in a real scan, fixed in 1.8.1) | Query-string secrets are redacted |

Behaviour change to be aware of: on Linux an evidence folder collected as root
is no longer readable by other users. Read it with `sudo`, or `chown` it
deliberately after collection.

## Not covered (honest limits)

- Windows has no `strace`. The offline claim is tested twice: W8 polls TCP
  connections and compares host state before and after (it can miss a very short
  connection), and W13 (`tests/Test-Containment.ps1`) blocks outbound traffic for
  the collector host with a Windows Firewall rule and reads the Windows Filtering
  Platform audit (events 5156/5157) for any attempt. W13 needs an elevated
  session and is SKIPPED without one. The Linux claim remains the stronger one
  (system-call trace).
- Signal-handling tests (SIGTERM, SIGINT) exist for Linux only.
- Fuzzing is property-based and time-boxed (fixed seed in CI); it is not a coverage-guided campaign. No third-party penetration test has been performed.
- The viewer test needs a browser and is run by hand, not in CI.
- Real-host validation on an isolated lab machine (`docs/VALIDATION.md`) is a
  separate step and remains open.
- Results describe the machine the tests ran on; a different Windows build or
  distribution can differ.
