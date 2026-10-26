# Changelog

All notable changes to TATAR Triage Toolkit are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); versions use
[SemVer](https://semver.org/).

## [Unreleased]

### Added
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

[1.3.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.3.0
[1.2.5]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.5
[1.2.4]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.4
[1.2.3]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.3
[1.2.2]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.2
[1.2.1]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.1
[1.2.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.2.0
[1.1.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.1.0
[1.0.0]: https://github.com/ochmunkh/Tatar-Triage/releases/tag/v1.0.0
