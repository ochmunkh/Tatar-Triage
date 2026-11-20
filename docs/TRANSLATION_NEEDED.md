# Translation needed — Mongolian

A worklist, not a translation. **Nothing here has been machine-translated**, and
nothing should be: the Mongolian in this repo is written, and a transliterated
stand-in would be worse than an honest gap.

Generated 2026-09-30 by classifying every tracked `.md` as entirely English,
bilingual (carrying a `Монгол хувилбар` half), or mixed. Revisited 2026-11-20:
the pages added since then are listed under *English-only pages added since*.

**Priority is about who reads it, and when.** This is an incident-response tool:
its documents get read under time pressure, by a responder on someone else's
network. That raises the value of the operator-facing ones well above their word
count.

---

## High — read by a responder mid-incident

| Section | File | Words | Note |
|---|---|---:|---|
| ~~*(whole file)*~~ | ~~`linux/README.md`~~ | ~~1,360~~ | **DONE — written 2026-09-30.** The file now carries a full `🇲🇳 Монгол хувилбар` half: requirements, usage, the flag table, exit codes, the module list, allowlist/IOC, the output tree, the leads-not-verdicts warning, the ATT&CK table, handling notes and limitations. Held to an **exact mirror** — no accepted delta — by `.github/scripts/check_readme_parity.py linux/README.md`, and its Mongolian module list is checked against `MOD_NAMES` by `check_docs_parity.py`. Both run in CI. |
| ~~*(whole file)*~~ | ~~`docs/MITRE_ATTACK.md`~~ | ~~940~~ | **DONE — written 2026-10-01.** Full `🇲🇳 Монгол хувилбар` half: the guidance-not-proof warning, every tactic table for both platforms, the IOC-engine mapping and the evidence sources. Module names and ATT&CK IDs stay English — they are identifiers, not prose. `check_docs_parity.py` now validates the Mongolian Module columns against the code too, so the two halves cannot drift apart from it. |

**Nothing high-priority remains.** Everything a responder reads mid-incident is
now in both languages.

## Medium — the recorded README backlog

~~`README.md` English-only backlog~~ **DONE — 1.9.0.** The README was split by
language and by topic: `README.md` / `README.mn.md` are short front pages, and
the reference material lives in `docs/` as seven pairs (`ARCHITECTURE`,
`USAGE`, `MODULES`, `OUTPUT`, `ANALYSIS`, `EVIDENCE`, `OPERATIONS`, each with a
`.mn.md` twin). Every pair is held to a structural mirror by
`.github/scripts/check_readme_parity.py --pairs`; the only recorded difference
is a Mongolian-only `Нууцлал` section in the architecture page. The per-version
history is `CHANGELOG.md` alone (English).

## Low — contributor-facing

| Section | File | Words | Note |
|---|---|---:|---|
| *(whole file)* | `tests/WINDOWS_STATIC_REVIEW.md` | 4,607 | A code review of the 18 Windows-only modules. Read by whoever fixes them. |
| *(whole file)* | `tests/WINDOWS_TEST_PLAN.md` | 1,005 | What to verify on a real Windows host. Same audience. |
| *(whole file)* | `CHANGELOG.md` | 2,982 | A historical record. Translating past entries has little value; new entries could be written bilingually from here on. |
| *(whole file)* | `CODE_OF_CONDUCT.md` | 313 | **Do not hand-translate.** Contributor Covenant v2.1 has an official Mongolian translation — use it rather than writing a second, divergent wording. |
| *(whole file)* | `.github/ISSUE_TEMPLATE/*.md`, `PULL_REQUEST_TEMPLATE.md` | 203 | Contributor-facing. |

---

## English-only pages added since

Each page below is English only and has no `Монгол хувилбар` half. Word counts
are from 2026-11-20. The operator-facing pages added in the same period
(`WALKTHROUGH`, `PLAYBOOKS`, `REPORTING`, `SECURITY-MODEL`) were written with a
`.mn.md` twin and are held to an exact mirror. `SECURITY-MODEL.mn.md` is the
Mongolian way in to the two security pages below.

| Priority | File | Words | Note |
|---|---|---:|---|
| Medium | `docs/AFTER-COLLECTION.md` | 508 | What to do once the run ends. Read by the responder. |
| Medium | `docs/TOOLS.md` | 956 | The analysis tools (`tatar-diff.py`, `tatar-review.py`, the viewer). Read by the analyst. |
| Low | `docs/AV-SAFETY.md` | 1,667 | The nine AV claims and how each is checked. Summarised in Mongolian in `SECURITY-MODEL.mn.md`. |
| Low | `docs/SECURITY-TESTING.md` | 3,393 | Security tests and the standards maps. Summarised in Mongolian in `SECURITY-MODEL.mn.md`. |
| Low | `docs/VALIDATION.md` | 4,264 | Measured runs on real and sandboxed hosts. A record, read by reviewers. |
| Low | `docs/COVERAGE.md` | 1,369 | What each edition collects, side by side. |
| Low | `docs/COMPARISON.md` | 598 | How the tool compares with other collectors. |
| Low | `docs/DESIGN-artifact-engine.md` | 520 | A design note for contributors. |

## Deliberately *not* a gap

- **`README.md`**, **`linux/README.md`** and **`CONTRIBUTING.md`** carry
  Mongolian halves already; the two READMEs' structure is gated in CI by
  `check_readme_parity.py`, which keeps a **per-file** baseline — `README.md`
  has a recorded surplus, `linux/README.md` must stay an exact mirror, and a
  bilingual file that is not listed is held to an exact mirror by default, so
  the next one cannot inherit a backlog it did not earn.
- **`SECURITY.md`** is already mixed Mongolian/English.
- **`Tatar.ps1` and `linux/tatar-linux.sh` code comments** are English
  throughout, consistently, and were left that way — changing the convention is
  a separate decision from filling a documentation gap.

## If you translate one thing

~~`linux/README.md`.~~ **Done, 2026-09-30.** The Windows collector had Mongolian
documentation and the Linux one had none, which left a Mongolian-speaking
responder on a Linux host as the only user of this toolkit with nothing in
their language. That is closed, and closed as an exact mirror rather than as a
second backlog.

~~Next: `docs/MITRE_ATTACK.md`.~~ **Done, 2026-10-01** (see the High table).

Next: **`docs/AFTER-COLLECTION.md`** and **`docs/TOOLS.md`** — what a responder
does with the evidence folder once the run ends. Every other operator-facing
page now has a Mongolian twin.
