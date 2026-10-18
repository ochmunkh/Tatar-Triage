# Contributing to Tatar-Triage

Thanks for your interest — contributions are very welcome! 🎉
Tatar-Triage is a lightweight, cross-platform **DFIR triage & artifact collector**
(Windows PowerShell + Linux Bash) that emits a unified JSON schema with MITRE ATT&CK tagging.

Монголоор: доод хэсгийг үзнэ үү.

## Design principles (please keep these)

- **Read-only first** — never modify the system under investigation. Collect, don't change.
- **Transparent** — every collected artifact is explainable; no hidden actions.
- **Unified schema** — all collectors write to the same JSON shape (`schema/`) so output stays
  consistent across Windows and Linux and is easy to feed into SOAR/SIEM.
- **Chain of custody** — preserve hashes/timestamps; don't break provenance.

## Architectural invariants

Most of this tool is open to change. The list below is not. Each item is a way
this collector could quietly stop being a triage tool — fast, privilege-light
and read-only on a host that may already be compromised.

1. **The host is evidence. Read-only first.** Nothing is written outside the
   output directory the operator chose: no config changes, no downloads onto the
   host, no exclusions added, no service installed. Change the host before
   collecting and the evidence you then collect is weaker — the analyst can no
   longer say whether a trace is the attacker's or the tool's.
2. **One file per platform.** `Tatar.ps1` and `linux/tatar-linux.sh` each stand
   alone. No module split, no package, no runtime to install. Triage happens on
   a machine you do not control, often offline, often with no right to install
   anything. The day this needs `pip install` it stops being usable in the
   situation it exists for.
3. **Offline. Nothing is sent, nothing is fetched.** Allowlist and IOC feeds are
   local files; hashes are computed locally. No reputation lookup, no rule
   update, no telemetry. One outbound request turns this into a way to move data
   off a sensitive host and makes it unusable on an air-gapped or
   legally-constrained network. An *optional* network feature is still in the
   code, so the promise is already broken.
4. **Privilege deepens, it does not gate.** Administrator / root widens what can
   be *read*; it is never required. A module without it says what it could not
   do and carries on — it never skips in silence. Make elevation mandatory and
   the first-responder case disappears, which is the main case.
5. **Seconds, not minutes.** Every module has a time budget. Anything that could
   be unbounded — walking a filesystem, recursing, hashing in bulk — is capped by
   depth, count and time, and says so when a cap is hit. "Triage" is a word about
   time: a collector that runs for forty minutes is not triage, whatever it
   collects.
6. **The output contract is the product.** `schema/summary.schema.json` holds
   both editions to one shape, so one parser reads both. Field names do not
   change silently, `schemaVersion` changes only when the contract does, and the
   output filenames are part of it. The collectors could be rewritten in a
   weekend; this agreement could not.
7. **A finding is a lead, not a verdict.** `severity` is `High` or `Review` —
   deliberately two. A five-level scale manufactures false precision, when the
   analyst's decision is binary: look now, or not. `confidence` comes from a
   fixed set. Nothing heuristic is ever labelled "CRITICAL".
8. **Suppressed is not deleted.** The allowlist marks a finding `suppressed`
   with a `suppressReason`; it never removes it.
   `activeFindingsCount + suppressedCount == findingsCount` is counted from the
   data, not derived. Somebody is entitled to ask what you hid and why, and the
   answer has to be in the output.
9. **Silent failure is a defect, not a convenience.** An unreadable feed file, a
   skipped module, a missing external tool, a swallowed exception — each must
   warn, be logged, and affect the exit code. The dangerous output of a security
   tool is not a wrong finding; it is **silence that reads as safe**. Until
   v1.2.5 a one-character typo in an `--ioc` path ran a full collection with no
   matching, no warning and exit 0, and the analyst read "no active findings"
   believing the feed had been applied. Everything in this clause comes from
   that.
10. **Transparent. No obfuscation, no AV/AMSI bypass.** The source stays
    readable so a defender can review it and allow-list it; that readability is
    the only thing that earns the privilege this tool asks for. It also must not
    behave like what it hunts — bulk file-walking, hiding, muting alerts are the
    shape of ransomware staging. Modules that are visible to EDR are named in
    the docs.
11. **Mongolian is a first-class output language**, not a translation pasted
    onto an English tool. The two halves of `README.md`, `linux/README.md` and
    `docs/MITRE_ATTACK.md` are parity-checked in CI. Technical terms (finding,
    allowlist, IOC, contract, pattern match, suppressed) stay in English in both
    languages — translating them cuts the reader off from the JSON field names.

### Adding a module

Declare four things up front: **time** (seconds), **whether it needs
Administrator** (not needing it is the default), **output size** (metadata, not
raw data) and **AV risk**. Fail any of them and it does not go in the default
set — it goes behind a switch that is off. No artefact is valuable enough to
buy an exemption.

Specifically never: `netsh wlan show profile key=clear` or anything else that
extracts a secret; touching lsass; `Invoke-Expression` or encoded commands;
downloading anything; an unbounded filesystem walk.

## Ways to contribute

- **New collectors / artifacts** — add a Windows (PowerShell) or Linux (Bash) collector for an
  artifact type that isn't covered yet.
- **MITRE ATT&CK tagging** — improve or add technique mappings on findings.
- **Schema improvements** — evolve the unified JSON / `findings.json` (keep it backward-compatible).
- **Cross-platform parity** — make sure a collector exists (or is documented as N/A) on both OSes.
- **Docs & translations** (English / Mongolian).

## Adding a collector

1. Windows: add the logic to `Tatar.ps1` (or a module it calls). Linux: add to `linux/`.
2. Write output using the **unified schema** in `schema/` — don't invent a new shape.
3. Tag findings with the relevant **MITRE ATT&CK** technique ID where applicable.
4. Keep it **read-only** — only read/collect, hash where relevant, never modify the host.
5. Test on the target OS and include a short sample of the JSON output in your PR.

## Workflow

1. **Fork** and create a branch: `feat/<name>` or `fix/<name>`.
2. Keep changes focused and read-only-safe.
3. Test the collector on the relevant OS (Windows PowerShell 5.1+/7, or a Linux shell).
4. Open a **Pull Request** describing what artifact it collects and the ATT&CK mapping.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Versioning & releases (maintainers)

- The tool version lives in **one place per edition**: `$script:ToolVersion` in `Tatar.ps1` and
  `VERSION` in `linux/tatar-linux.sh`. Banner, help, `summary.txt`, `summary.json`, the execution
  log and `chain_of_custody.txt` all read from it — never hard-code a version string elsewhere.
  Bump both together; CI asserts `summary.json.version` is SemVer.
- `schemaVersion` is separate and changes only when the JSON contract changes (add the new value to
  the enum in `schema/summary.schema.json`, keep new fields optional).
- Line endings are enforced by `.gitattributes` (`.sh`/`.md`/`.json` = LF, `.ps1` = CRLF). If
  `git status` shows a whole-file diff, run `git add --renormalize <file>`.
- `docs/banner.src.svg` is the **editable source** for the `banner.png` the README loads; re-export
  the PNG from it when the artwork changes, so the two never drift apart. (The SVG is not referenced
  by any page: GitHub renders the raster version, which is sharp at the README's width.)
- Documentation facts that are derivable from the code are checked, not proof-read: the `docs-parity`
  CI job asserts the module-count badges, the English/Mongolian module lists and the ATT&CK coverage
  in `docs/MITRE_ATTACK.md`. Run it locally with `python3 .github/scripts/check_docs_parity.py .`
- Release: update `CHANGELOG.md` + the README changelog → commit → annotated tag `vX.Y.Z` →
  push the branch, then push the tag. The `Release` workflow builds `SHA256SUMS.txt` and attaches
  both collectors and both sample JSONs to the release, taking its notes from the matching
  `CHANGELOG.md` section. If the tag has no release yet it creates a **draft** — review it and
  publish. Never hand-edit the hashes: `SHA256SUMS.txt` is the published source of truth.

## Reporting issues

Use the templates in `.github/ISSUE_TEMPLATE/`. For security-sensitive reports, contact the
maintainer privately at **nkhbat@yahoo.com** rather than opening a public issue.

---

## Монгол хэл дээр

Хувь нэмэр оруулах хүсэлд баярлалаа! 🎉 Tatar-Triage бол хөнгөн, cross-platform **DFIR triage
& artifact collector** (Windows PowerShell + Linux Bash) — нэгдсэн JSON schema, MITRE ATT&CK
mapping-тай.

**Гол зарчим:** Read-only first (шинжилж буй системийг хэзээ ч өөрчлөхгүй) · ил тод · нэгдсэн
schema · chain of custody (hash/timestamp хадгална).

**Архитектурын тогтвортой зарчим:** Fork хийх, PR явуулахын өмнө дээрх
*Architectural invariants* хэсгийг уншина уу. Энэ tool-ын ихэнх нь нээлттэй,
гэхдээ арван нэг зүйл нь биш — тус бүр нь энэ collector чимээгүйхэн triage
хэрэгсэл байхаа болих нэг арга юм: хурдан, эрх багатай, аль хэдийн халдлагад
өртсөн байж болох хост дээр зөвхөн уншдаг.

**Шинэ модуль нэмэх:** дөрвийг урьдчилж зарлана — хугацаа (секунд), admin
шаардах эсэх (шаардахгүй нь анхдагч), гаралтын хэмжээ (мета, түүхий өгөгдөл
биш), AV-ийн эрсдэл. Аль нэгэнд унавал default-д орохгүй, унтраалттай switch-ийн
ард. Ямар ч артефакт энэ хаалтыг давах эрх худалдаж авахгүй.

**Хувь нэмрийн чиглэл:** шинэ collector/artifact (Windows эсвэл Linux) · ATT&CK tagging ·
schema сайжруулах · хоёр OS-ийн parity · баримт/орчуулга.

**Collector нэмэх:** Windows → `Tatar.ps1`; Linux → `linux/`. Гаралтыг `schema/`-ийн нэгдсэн
хэлбэрээр бич, ATT&CK technique-ээр тэмдэглэ, **read-only** байлга, тухайн OS дээр турш.

**Урсгал:** fork → `feat/...` салбар → турших → Pull Request (ямар artifact цуглуулж, ямар
ATT&CK mapping хийснийг тайлбарла). Code of Conduct-ыг дагана уу.

**Хувилбар:** tool version нь `$script:ToolVersion` (Tatar.ps1) болон `VERSION` (tatar-linux.sh) гэсэн
ганц газар байдаг — хоёуланг нь хамт өсгө, өөр газар version бичихгүй. schemaVersion нь зөвхөн JSON
contract өөрчлөгдөхөд солигдоно. Release: CHANGELOG → commit → vX.Y.Z tag → push (branch, дараа tag).
Release workflow нь SHA256SUMS.txt-ийг CI дээр бодож, хоёр скрипт + хоёр sample-ыг release-д автоматаар
хавсаргана; tag дээр release байхгүй бол draft үүсгэнэ — хянаад publish хий. Хэшийг гараар бичихгүй. Аюулгүй байдлын нарийн
асуудлыг **nkhbat@yahoo.com** руу хувийн байдлаар мэдэгдэнэ үү.
