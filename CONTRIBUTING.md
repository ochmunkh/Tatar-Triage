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
- Release: update `CHANGELOG.md` + the README changelog → commit → annotated tag `vX.Y.Z` → push →
  wait for CI → GitHub release with `Tatar.ps1`, `tatar-linux.sh`, the two sample JSONs and a
  `SHA256SUMS.txt` attached (publish the hashes — that is how users allow-list the script).
## Reporting issues

Use the templates in `.github/ISSUE_TEMPLATE/`. For security-sensitive reports, contact the
maintainer privately at **nkhbat@yahoo.com** rather than opening a public issue.

---

## Монгол хэл дээр

Хувь нэмэр оруулах хүсэлд баярлалаа! 🎉 Tatar-Triage бол хөнгөн, кросс-платформ **DFIR triage
& artifact collector** (Windows PowerShell + Linux Bash), нэгдсэн JSON schema, MITRE ATT&CK
тагтай.

**Гол зарчим:** Read-only first (мөрдөж буй системийг хэзээ ч өөрчлөхгүй) · ил тод · нэгдсэн
schema · chain of custody (hash/timestamp хадгална).

**Хувь нэмрийн чиглэл:** шинэ collector/artifact (Windows эсвэл Linux) · ATT&CK tagging ·
schema сайжруулах · хоёр OS-ийн parity · баримт/орчуулга.

**Collector нэмэх:** Windows → `Tatar.ps1`; Linux → `linux/`. Гаралтыг `schema/`-ийн нэгдсэн
хэлбэрээр бич, ATT&CK technique-ээр тагла, **read-only** байлга, тухайн OS дээр турш.

**Урсгал:** fork → `feat/...` салбар → турших → Pull Request (ямар artifact цуглуулж, ямар
ATT&CK mapping хийснийг тайлбарла). Code of Conduct-ыг дагана уу.

**Хувилбар:** tool version нь $script:ToolVersion (Tatar.ps1) болон VERSION (	atar-linux.sh) гэсэн
ганц газар байдаг — хоёуланг нь хамт өсгө, өөр газар version бичихгүй. schemaVersion нь зөвхөн JSON
гэрээ өөрчлөгдөхөд солигдоно. Release: CHANGELOG → commit → X.Y.Z tag → push → CI → GitHub release
(скрипт + sample + SHA256SUMS.txt хавсаргах). Аюулгүй байдлын нарийн
асуудлыг **nkhbat@yahoo.com** руу хувийн байдлаар мэдэгдэнэ үү.
