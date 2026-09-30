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
| ~~*(whole file)*~~ | ~~`linux/README.md`~~ | ~~1,360~~ | **DONE — written 2026-09-30.** The file now carries a full `🇲🇳 Монгол хувилбар` half: requirements, usage, the flag table, exit codes, the module list, allowlist/IOC, the output tree, the leads-not-verdicts warning, the ATT&CK table, handling notes and limitations. Held to an **exact mirror** — no accepted delta — by `.github/scripts/check_readme_parity.py linux/README.md`, and its Mongolian module list is checked against `MOD_NAMES` by `check_docs_parity.py`. Both run in CI. |
| *(whole file)* | `docs/MITRE_ATTACK.md` | 940 | The technique mapping an analyst consults to interpret a finding. Mostly tables of IDs and short descriptions, so it is smaller than the count suggests. **Now the highest-value gap left**, since the Linux README is done. |

**Subtotal ≈ 940 words** remaining, down from ≈ 2,300.

## Medium — the recorded README backlog

`README.md` carries a Mongolian half, but the two are **not** a mirror, and the
asymmetry is recorded rather than hidden:
`.github/scripts/check_readme_parity.py` holds an `ACCEPTED_DELTA` of

| | English-only, was | English-only, now |
|---|---:|---:|
| sections | 18 | **10** |
| table rows | 38 | **0** |
| code blocks | 2 | **0** |

Those numbers are a backlog, not a target. Writing any of it in Mongolian is
welcome; when you do, **lower the matching number in `ACCEPTED_DELTA`**, or the
check will keep discounting it and stop noticing future drift.

**Written since this file was generated,** by hand and in the Mongolian half's
own voice: `Demo`, the options table, the exit-code table, `Triage дүгнэлт ба
finding`, `Гүйцэтгэлийн лог`, the full `MITRE ATT&CK тэмдэглэгээ` table, `AV-г
тойрч гарахгүйгээр ажиллуулах`, and `Нэмэлт гадаад хэрэгсэл`. The two counts
that reached **0** are the useful part: every table row and fenced block added
to one half from here on is reported the run it appears, instead of being
absorbed by a backlog that was never going to notice it.

**What the remaining 10 sections are.** `## Changelog` and its ten release
subsections, plus `## Legal`, whose text the Mongolian half already carries
inside `## Холбоо барих` — twelve, less the two sections the Mongolian half has
and the English one does not (`Triage гэж юу вэ?` and `Нууцлал`, both written
for a reader newer to DFIR). They are last in the queue on purpose: the same
reasoning that puts `CHANGELOG.md` under *Low* below applies to a condensed
copy of it, and `linux/README.md` is worth more than both.

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

Next: **`docs/MITRE_ATTACK.md`** — the document an analyst opens *after* a
finding fires, to decide what it means. Both READMEs now point at it in
Mongolian from a Mongolian sentence, and it answers in English.
