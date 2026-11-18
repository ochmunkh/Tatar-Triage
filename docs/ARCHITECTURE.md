# Architecture

[Монгол](ARCHITECTURE.mn.md) · [← README](../README.md)

## Architecture

TATAR ships as two parity editions — `Tatar.ps1` (Windows, 33 modules) and `linux/tatar-linux.sh` (Linux, 18 modules) — behind a single output contract. Both emit the same JSON schema (`schemaVersion 1.7`), so a SIEM/SOAR pipeline ingests either platform identically.

```
                    TATAR Triage
                         │
          ┌──────────────┴──────────────┐
     Windows · Tatar.ps1           Linux · tatar-linux.sh
     (PowerShell, 33 modules)      (Bash, 18 modules)
          └──────────────┬──────────────┘
                         ▼
      Private evidence folder · terminal-safe generated text
                         ▼
             Unified JSON schema  (summary.schema.json · v1.7)
                         ▼
   ┌───────────────┬─────┴─────────┬───────────────────┐
   ▼               ▼               ▼                   ▼
 summary        findings        timeline        manifest + digest
(+ report)   (+ moduleStatus)  (+ hashes)       (sha256sum -c)
   └───────────────┴─────┬─────────┴───────────────────┘
                         ▼
      tools/viewer.html (offline)  ·  SIEM / SOAR
                         ▼
                DFIR investigation
```

### Data flow

1. Parse arguments, create the private output folder (a symlink or junction path, or an existing evidence folder, is refused) and the chain of custody.
2. Detect the runtime environment (virtualization / container / security module).
3. Run collectors in **order of volatility** (memory · network · process → disk · registry · logs). Each collector writes raw evidence to disk *and* a structured finding in memory.
4. The **allowlist engine** suppresses known-good findings — kept for audit, never deleted.
5. The **IOC engine** annotates known-bad findings, overrides the allowlist, and raises new findings from the collected evidence.
6. Sort into active vs suppressed, then write `summary.txt` / `summary.json` (with a `moduleStatus[]` per module), `findings.json`, neutralise control and bidi characters in the generated text, and write the SHA-256 manifest and its own digest. `tools/viewer.html` reads the JSON offline.

### The findings model

Every finding is a single record, identical across platforms:

`id` · `severity` (High/Review) · `category` · `technique[]` (MITRE) · `message` · `detail` · `confidence` (0.7 High · 0.4 Review · 0.95 IOC-confirmed) · `suppressed` · `suppressReason` · `iocMatch` (a boolean; the matched indicator itself is prefixed into `detail` as `IOC match: <indicator> | ...`).

Suppressed findings stay in the report and JSON with a reason — they are only dropped from the active headline count, never from the record. (On Linux the findings pipeline is delimited with the ASCII Unit Separator `0x1F`, not TAB, because `read` collapses whitespace delimiters and would shift columns on empty fields.)

### Allowlist engine — signal over noise

Suppresses known-good findings by **path glob**, **Authenticode publisher** (Windows), **package ownership** via `dpkg`/`rpm` (Linux), or **SHA-256**. On a clean host this took a run from 11 raw findings to **4 active / 7 suppressed**.

### IOC engine — known-bad wins

Takes an offline feed of `hashes / ips / domains / filenames` (`hashes` are SHA-256 — MD5/SHA-1 are not compared; see [`ioc.sample.json`](../ioc.sample.json)). *Pass A* matches existing findings and a hit **overrides the allowlist** — it re-activates a suppressed finding and escalates it to High / 0.95. *Pass B* raises new findings for IOCs seen anywhere in the collected evidence (deduplicated against Pass A), tagged by indicator type — `T1071` for an IP, `T1071.004` for a domain, `T1204.002` for a filename, `T1588.001` for a hash. The rule is simple: a known-bad indicator always beats a known-good allowlist entry.

Both feed paths are checked **before collection starts**. A path that cannot be read is never skipped in silence: it warns on the console, is logged as an error, and forces exit code `2` — so a typo in a filename can never leave you reading "no active findings" while the feed never ran.

### Trust boundaries

No network calls — allowlist and IOC feeds are local files and every hash is computed locally. Read-only first; root/Admin only widens what can be *read*, never what is changed. The script's own SHA-256 and tool version ("version" in summary.json, a single constant per edition) are recorded in the chain of custody, and EDR-sensitive actions (memory dump, hive save, deleted-binary carving) are opt-in and off by default. The evidence folder is private to the examiner, text taken from the host (file names, command lines) is neutralised before it reaches a report, and temporary files are removed; [docs/SECURITY-TESTING.md](SECURITY-TESTING.md) lists the tests that hold each of these.
