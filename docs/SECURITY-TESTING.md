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
| New detections | `bash tests/test-linux-detections.sh` (privileged checks need root and `TATAR_LAB=disposable`); Windows: `tests\Test-AutostartTarget.ps1` | under 2 min |
| Hostile IOC feeds | `bash tests/test-ioc-feed.sh`; Windows: `tests\Test-IocFeed.ps1` (real runs with feeds built to cause trouble) | under 1 min |
| Fuzz (Linux) | `python3 tests/fuzz.py [--iterations N]` | under 1 min |
| Fuzz (Windows) | `pwsh -File tests/Test-Fuzz.ps1` | under 1 min |
| Containment (Windows) | `tests\Test-Containment.ps1` in an elevated session; SKIP otherwise | about 3 min |
| Viewer | `python tests/test-viewer.py` (Playwright, not in CI) and `python .github/scripts/check_viewer.py` | seconds |
| Repo gates | the CI jobs: docs parity, contract parity, README parity, AV safety, viewer, schema validation, PSScriptAnalyzer, shellcheck | CI |
| Release integrity | `python3 .github/scripts/check_release_integrity.py` and its proof, `python3 tests/test-release-integrity.py` (breaks 16 things one at a time and requires the gate to catch each) | seconds |

A test that cannot run is reported as `SKIP`, never as `PASS`.

## Result at v1.14 (CI run of commit 323fd57, the 1.14.0 code)

| Suite | Result |
|---|---|
| `tests/test-security.sh` (Linux) | 66 passed, 0 failed |
| `tests/Test-Security.ps1` (Windows) | 50 passed, 0 failed, 2 skipped on the CI runner (it runs elevated, so the unprivileged checks skip); with `-Quick` on a standard-user desktop, 53 passed, 1 skipped |
| Functional suites | Windows contract 233/233, Linux contract 45/45, IOC boundary 32/32, public addresses 40/40 (Linux) and 42/42 (Windows), text indicators 12/12 (Linux) and 26/26 (Windows), all unit suites green |

The heading names the current major.minor. `check_release_integrity.py` fails the build when it does not, so these numbers are re-recorded for every release line.
## Requirement to test map

### OWASP ASVS 4.0 and Top 10 2021 (applicable subset)

| Reference | What it means for a collector | Tests |
|---|---|---|
| ASVS V5.1 / V5.3, A03 Injection | Arguments, output paths and feed files are data, never code | S1, S2, S3 / W1, W2, W3 |
| ASVS V5.3.3 output encoding | Host-supplied names and command lines cannot inject terminal escapes, bidi controls or spreadsheet formulas into reports | S4, S5 / W4 |
| ASVS V12.3 file execution, A03 | No file name on the examined host is ever executed | S4, S5 / W4 |
| ASVS V8.1.2, A01 Broken access control | Evidence is private to the examiner (mode 0700/0600; ACL without Everyone/Users) | S6 / W5 |
| A01, A05 | The collector refuses to write through a symlink or junction, and refuses to reuse an existing evidence folder | S7 / W6 |
| ASVS V10.3.2, A08 Integrity failures | Tampering with evidence or with the manifest is detected; the script that ran is recorded by hash | S9 / W7 |
| A02/A09 data handling and logging | Temp files are removed on normal exit and on signals; nothing is left in TEMP | S10, S11 / W9 |
| A05 Security misconfiguration | Runs unprivileged; no package, privilege or network program is started | S8, S12 / W8, W10 |
| ASVS V5.1 input validation (no ASVS item names byte-order marks) | Strict UTF-8, no byte-order mark, Unicode round-trips | S13 / W11 |
| ASVS V12.1.1, A04 Insecure design | Budgets for time and memory; hostile feeds cannot hang or crash a run | S3, N1, N2 / W3, N1, N2 |

### OWASP Top 10:2025

The table above uses the 2021 numbering (A03 is Injection there). The 2025 list renumbers
the categories, so it is mapped here under its own numbers. The collectors are
command-line tools with no accounts, sessions or network service; where an item is
about web applications the answer says so instead of claiming a test.

| Item | What it means for a collector | Where it is held |
|---|---|---|
| A01 Broken Access Control | Evidence is private to the examiner; the collector refuses to write through a symlink or junction (the link-following weaknesses in this item) and leaves no temporary file behind | S6, S7, S10, S11 / W5, W6, W9 |
| A02 Security Misconfiguration | Runs unprivileged; no package, privilege or network program is started; EDR-sensitive actions are off unless asked; hosts are changed only in disposable labs | S8, S12 / W8, W10, AV-05 |
| A03 Software Supply Chain Failures | No third-party dependencies; actions pinned to commit SHAs; Dependabot; least-privilege token; `SHA256SUMS.txt` and build-provenance attestation on each release. No software bill of materials is generated | RI-06, RI-09, release workflow |
| A04 Cryptographic Failures | Hashes are SHA-256 only (MD5 and SHA-1 are not used or compared); nothing is sent, so there is no transport to protect. The tool does not encrypt the evidence folder; the examiner must (see README, Legal) | `docs/AV-SAFETY.md`, `docs/ARCHITECTURE.md` |
| A05 Injection | Arguments, output paths, feed files and host-supplied text are data, never code; terminal escapes and bidi controls are neutralised before they reach a report | S1-S5 / W1-W4 |
| A06 Insecure Design | Read-only by design; numbered claims AV-01 to AV-09 each have a check that fails the build; time and memory budgets | AV-SAFETY gate, S3, N1, N2 / W3 |
| A07 Authentication Failures | Not applicable: no login, session or stored credential. No password material is read (AV-02). No secret scanning is run on the repository | AV-02 |
| A08 Software or Data Integrity Failures | Tampering with evidence or the manifest is detected and the script that ran is recorded by hash; there is no auto-update; release assets are hashed and attested. Release tags are not signed | S9 / W7, release workflow |
| A09 Security Logging & Alerting Failures | The collector is not a monitor and raises no alerts. It records `tatar.log` and the chain of custody, and keeps host-supplied text from injecting into them. The evidence it gathers is sensitive by purpose | S1-S5 / W1-W4, README (Legal) |
| A10 Mishandling of Exceptional Conditions | A module that fails (or lacks privilege) is reported and the run goes on; an unreadable feed is never skipped silently and forces exit code 2; hostile input cannot hang or crash a run | S3, S12, N1, N2 / W3, W10, hostile-feed tests |

### NIST

| Reference | Requirement | Tests |
|---|---|---|
| SP 800-86 section 3.1 (collection) | Collection must not alter the host being examined | S8 (no writes outside the output folder), W8 (Run keys, startup, hosts, tasks, services, accounts unchanged) |
| SP 800-86 section 3.1.2 (acquiring the data) | Integrity (message digests) and chain of custody: hashes, tool identity, examiner and case recorded | S9 / W7 |
| SP 800-86 section 3.1.2 (volatile data first) | Memory, network and processes are collected ahead of files and logs | the order of the collector registry; not tested separately |
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

## Repository and release controls

Software that is run on a host under investigation is trusted on its release, so
the repository and the release are held to rules too. `check_release_integrity.py`
turns the ones that can be checked from the tree into a build failure; the rest
are stated here so they are not mistaken for tested.

| Check | What fails the build | Why it exists |
|---|---|---|
| RI-01 | The newest released CHANGELOG section differs from the version the two collectors carry, has no date, or is empty | `release.yml` builds the release notes from that section |
| RI-02 | `release.yml` copies a file that is not in the repository | A renamed file would give a release without it |
| RI-03 | A sample log line shows a module count other than the Windows module count | The sample said 30 after the tool had 33 |
| RI-04 | A document writes the summary fields with capitals | The schema and both collectors use lower case |
| RI-05 | The recorded test results are from another release line | Numbers older than the tool read as current |
| RI-06 | An action is not pinned to a commit, a workflow declares no token permissions, uses `pull_request_target`, or interpolates text an outsider controls into a `run:` step | A pipeline that builds the release is part of what is trusted |
| RI-07 | A tracked file or the newest commit message carries a name the maintainer keeps out of the repository | Maintainer rule |
| RI-08 | Hand-off notes, lab files, result folders or planning pages are tracked | They describe real hosts and work in progress |
| RI-09 | `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md` or `dependabot.yml` is missing | What a project is judged by |
| RI-10 | A script in `tools/` imports something outside the Python standard library | `docs/TOOLS.md` promises standard library only; the gate reads the syntax tree and runs nothing |

### Where this meets the standards

This is the author's own mapping; it is not an audit and not a claim of conformity
with any of them. A certificate under ISO/IEC 27001 is issued to an organisation's information security management system, never to a tool; the ISO rows show which controls the tool helps an organisation meet, not certification or conformity. On 2026-11-19 it was compared with the sources: the OWASP Top 10
CI/CD risk names (owasp.org), the SSDF practice names (SP 800-218 v1.1), the ISO/IEC
27001:2022 Annex A control names (a copy of the standard), the ASVS 4.0.3 chapter and
item titles, the section titles of SP 800-86, and the OpenSSF Scorecard check names.
The comparison corrected five rows of the OWASP and NIST tables above (ASVS V12.4, V4.2, V8 and
V13 did not fit what they were cited for; SP 800-86 section 3.3 is analysis, and the
order of volatility and chain of custody are in 3.1.2). Compared: ISO/IEC 27037:2016 (7.1.2.1 clock and volatile data, clauses 5.3.2-5.3.5 and 6.1).
The OWASP Top 10:2025 item names and background were compared with the text on owasp.org, and the CIS Controls v8.1 safeguard numbers and titles with the PDF. Not compared: the OWASP Top 10 2021 item names and the SLSA specification.

| Source | Control | What in this repository answers it |
|---|---|---|
| ISO/IEC 27001:2022 Annex A | 8.25 secure development life cycle, 8.28 secure coding | PSScriptAnalyzer and ShellCheck in CI, fuzz tests, review of every change through CI |
| | 8.26 application security requirements | The numbered claims in `docs/AV-SAFETY.md` (AV-01 to AV-09), each with a check that fails the build |
| | 8.29 security testing in development | `tests/test-security.sh`, `tests/Test-Security.ps1`, the hostile-feed tests |
| | 8.31 separation of environments | Detection tests that change a host run only with `TATAR_LAB=disposable` |
| | 8.32 change management | CHANGELOG, RI-01, protected `main` |
| | 8.33 test information | Fixtures hold no real host data; evidence folders are git-ignored; RI-08 |
| | 8.8 technical vulnerabilities, 8.9 configuration | Dependabot for pinned actions, `SECURITY.md`, `.gitattributes` line-ending rules |
| | 5.24 incident management planning and preparation, 5.26 response to information security incidents | The tool supplies first evidence for incident handling; plans, roles and exercises belong to the organisation |
| | 5.28 collection of evidence | Read-only collection, a SHA-256 manifest that checks itself, the hash of the script that ran and a chain of custody record (S8, S9, W7, W8). The control itself is the organisation's process |
| | 5.31 legal, statutory, regulatory and contractual requirements | The Law on Cyber Security of Mongolia (articles 8.5 and 9.6) is named in the README and `docs/ARCHITECTURE.md`, which call the evidence folder confidential |
| | 8.15 logging | `tatar.log` and the chain of custody record what ran, and host-supplied text is neutralised before it reaches them. The tool does not configure logging on the host |
| ISO/IEC 27037:2012 | Identification, collection, acquisition and preservation of digital evidence; auditability, repeatability, reproducibility | Read-only collection (S8, W8), hashes and a recorded chain of custody including the time zone and a note that the host clock was not verified against an outside source (S9, W7), deterministic output (S14, W12). The tool records these; it does not make the examiner's process conformant |
| NIST SP 800-218 (SSDF) | PO.1 requirements, PO.3 toolchain, PS.1 protect code, PS.2 release integrity, PS.3 archive releases | AV-SAFETY claims, CI, pinned actions, `SHA256SUMS.txt` and build-provenance attestation on each release, GitHub releases |
| | PW.7 code analysis, PW.8 testing, PW.9 secure defaults | Linters, the test suites, EDR-sensitive actions off unless asked (AV-05) |
| | RV.1 and RV.2 vulnerabilities | `SECURITY.md`, the defect table below |
| OWASP Top 10 CI/CD | CICD-SEC-3 dependency chain, SEC-4 poisoned pipeline execution, SEC-5 pipeline access control, SEC-9 artifact integrity | Pinned actions and Dependabot, RI-06, least-privilege token, `SHA256SUMS.txt` and attestation |
| OpenSSF Scorecard | Pinned-Dependencies, Token-Permissions, Dangerous-Workflow, Dependency-Update-Tool, Security-Policy, License | RI-06, RI-09. The Scorecard itself has not been run |
| CIS Controls v8.1 (cited by number and title only) | 1.1 asset inventory, 2.1 software inventory | The collectors record installed software, processes and network state as evidence; the repository does not keep an inventory |
| | 8.4 standardize time synchronization | `chain_of_custody.txt` records the time zone and says the host clock was not verified; the tool neither synchronises nor checks the clock |
| | 8.2 collect audit logs, 8.8 command-line audit logs | Event logs are collected as evidence (exported only with `-ExportEvtx`); the tool does not configure logging |
| | 10.1 anti-malware | The tool is built to run beside anti-malware without tripping it (AV-01 to AV-09); it is not one |
| | 17 incident response management | The tool supplies evidence for incident handling; roles, reporting and exercises belong to the organisation |
| Law on Cyber Security of Mongolia | 8.5 and 9.6: assessment and audit reports are confidential | Offline, read-only, nothing is sent anywhere; README and `docs/ARCHITECTURE.md` tell the examiner to treat the evidence folder as confidential |
| | 17.1.3 and 19.2.9: operation logs kept for the period the common rules set | Not provided. The tool collects logs as evidence; keeping them is the organisation's duty |
| | 17.1.2 and 19.2.14: tell the national centre about an attack | Out of scope for the tool; a process duty |
| | 9.3: no audit of an organisation the auditor served with IT services in the last two years | Out of scope for the tool; applies to the examiner's engagement |

### Not covered

- Branch protection and required reviews are repository settings. CI cannot read
  them, so nothing here proves they are on.
- No secret scanning, code scanning (SAST) or software bill of materials is run.
  The collectors have no third-party dependencies, so the bill would be short.
- Release tags are not signed; release assets carry a build-provenance
  attestation instead. No SLSA level is claimed.
- ISO/IEC 27041, 27042 and 27043 (suitability, analysis, investigation
  principles) concern the investigator's method, not the collector; the
  measured detection and false-positive rates are in `docs/VALIDATION.md`.