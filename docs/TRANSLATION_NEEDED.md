# Translation needed — Mongolian

A worklist, not a translation. **Nothing here has been machine-translated**, and
nothing should be: the Mongolian in this repo is written, and a transliterated
stand-in would be worse than an honest gap.

Generated 2026-09-30 by classifying every tracked `.md` as entirely English,
bilingual (carrying a `Монгол хувилбар` half), or mixed.

**Priority is about who reads it, and when.** This is an incident-response tool:
its documents get read under time pressure, by a responder on someone else's
network. That raises the value of the operator-facing ones well above their word
count.

---

## High — read by a responder mid-incident

| Section | File | Words | Note |
|---|---|---:|---|
| *(whole file)* | `linux/README.md` | 1,360 | **The Linux collector has no Mongolian documentation at all.** The Windows side is covered by the README's `Монгол хувилбар` half; the Linux collector's usage, modules, flags and output contract exist only in English. This is the largest genuine gap in the repo. |
| *(whole file)* | `docs/MITRE_ATTACK.md` | 940 | The technique mapping an analyst consults to interpret a finding. Mostly tables of IDs and short descriptions, so it is smaller than the count suggests. |

**Subtotal ≈ 2,300 words**, and the first 1,360 are the ones that matter.

## Medium — the recorded README backlog

`README.md` carries a Mongolian half, but the two are **not** a mirror, and the
asymmetry is recorded rather than hidden:
`.github/scripts/check_readme_parity.py` holds an `ACCEPTED_DELTA` of

| | English-only |
|---|---:|
| sections | 18 |
| table rows | 38 |
| code blocks | 2 |

Those numbers are a backlog, not a target. The English half is the reference
documentation — the options table, exit codes, the module list — and the
Mongolian half is a shorter guide. Writing any of it in Mongolian is welcome;
when you do, **lower the matching number in `ACCEPTED_DELTA`**, or the check will
keep discounting it and stop noticing future drift.

## Low — contributor-facing

| Section | File | Words | Note |
|---|---|---:|---|
| *(whole file)* | `tests/WINDOWS_STATIC_REVIEW.md` | 4,607 | A code review of the 18 Windows-only modules. Read by whoever fixes them. |
| *(whole file)* | `tests/WINDOWS_TEST_PLAN.md` | 1,005 | What to verify on a real Windows host. Same audience. |
| *(whole file)* | `CHANGELOG.md` | 2,982 | A historical record. Translating past entries has little value; new entries could be written bilingually from here on. |
| *(whole file)* | `CODE_OF_CONDUCT.md` | 313 | **Do not hand-translate.** Contributor Covenant v2.1 has an official Mongolian translation — use it rather than writing a second, divergent wording. |
| *(whole file)* | `.github/ISSUE_TEMPLATE/*.md`, `PULL_REQUEST_TEMPLATE.md` | 203 | Contributor-facing. |

---

## Deliberately *not* a gap

- **`README.md`** and **`CONTRIBUTING.md`** carry Mongolian halves already; the
  README's structure is gated in CI by `check_readme_parity.py`.
- **`SECURITY.md`** is already mixed Mongolian/English.
- **`Tatar.ps1` and `linux/tatar-linux.sh` code comments** are English
  throughout, consistently, and were left that way — changing the convention is
  a separate decision from filling a documentation gap.

## If you translate one thing

`linux/README.md`. The Windows collector has Mongolian documentation and the
Linux one has none, so a Mongolian-speaking responder on a Linux host is the
only user of this toolkit with nothing in their language.
