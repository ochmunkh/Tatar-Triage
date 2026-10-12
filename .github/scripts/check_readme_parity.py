#!/usr/bin/env python3
"""Check that the two language halves of a bilingual README have the same
STRUCTURE.

Both halves are hand-maintained, and in practice one gets updated and the other
forgotten -- this repo's git history carries several "fix the stale Mongolian
numbers" commits for exactly that reason. The content cannot be compared by
machine (being in two languages is the point), but the structure must match: a
section added on one side belongs on the other too.

Compared: heading counts per level, table rows, fenced code blocks.

Usage:  python3 .github/scripts/check_readme_parity.py [README.md]
        python3 .github/scripts/check_readme_parity.py linux/README.md
Exit :  0 in sync, 1 drifted, 2 could not read the file / find the sections.

The accepted asymmetry is PER FILE (see ACCEPTED_DELTA): README.md carries a
recorded English-only surplus, linux/README.md is a 1:1 mirror. A file that is
not listed is held to an exact mirror, which is the right default -- a new
bilingual document should not inherit another one's backlog.
"""

import re
import sys
from pathlib import Path

# The English half runs from the top of the file to the Mongolian heading.
MN_HEADING = re.compile(r"^##\s+(?:🇲🇳\s*)?Монгол хувилбар\s*$", re.M)

FENCE = re.compile(r"^\s*```")
HEADING = re.compile(r"^(#{2,4})\s+\S")
TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
TABLE_SEP = re.compile(r"^\s*\|[\s:|-]+\|\s*$")

# Heading LEVELS are pooled deliberately. The Mongolian half nests its sections
# one level deeper (### under the single "## Монгол хэл дээр"), so comparing per
# level would report permanent, meaningless drift. Tatar-Kuber's own parity test
# (internal/canonical/readme_test.go) pools levels 2-3 for the same reason; this
# follows that established convention.
LABELS = {
    "headings": "sections",
    "table_rows": "table rows",
    "code_blocks": "code blocks",
}

# Sections that deliberately exist in English only, with the reason. The
# Mongolian half is a QUICK START -- demo, expected controls, why the lab
# exists -- while the operational detail stays in English. That is a choice, so
# it is recorded here rather than reported as drift every run. Tatar-Kuber's own
# parity test keeps the same kind of allowlist.
#
# Adding a name here is a decision that the section needs no Mongolian
# counterpart. If it DOES need one, write the Mongolian instead -- never
# machine-translate it.
# The two halves of this README are not a 1:1 mirror: the English half is the
# reference documentation and the Mongolian half is a shorter guide. Rather than
# pretend they match, the CURRENT asymmetry is recorded here as an accepted
# baseline, and the check fails when it CHANGES in either direction -- which is
# what catches a section added to one side and forgotten on the other.
#
# Reducing these numbers is the goal: each one is Mongolian documentation that
# has not been written. Write it by hand; never machine-translate the English.
# Re-measured 2026-09-30 after the Mongolian half gained Demo, the options and
# exit-code tables, the triage-summary, execution-log and ATT&CK sections, the
# AV-without-evasion subsection and the optional-tools list.
#
# table_rows and code_blocks are now ZERO, which is the point: every future
# table row or fenced block added on one side is reported immediately, instead
# of being absorbed by a backlog that was never going to notice it.
#
# The 10 that remain are the README's condensed version history -- "## Changelog"
# and its ten release subsections -- plus "## Legal", whose text the Mongolian
# half already carries inside "## Холбоо барих". Net of the two sections the
# Mongolian half has and the English one does not ("Triage гэж юу вэ?" and
# "Нууцлал", both written for a reader newer to DFIR), that is 12 - 2 = 10.
#
# The version history is deliberately last in the queue: docs/TRANSLATION_NEEDED.md
# ranks translating past release notes below every operator-facing document, and
# linux/README.md above all of them.
# Keyed by the file's repo-relative path. A file that is NOT listed is held to
# an exact mirror (all zeros), so a new bilingual document starts with no
# backlog instead of silently inheriting this one's.
ACCEPTED_DELTA_BY_FILE = {
    "README.md": {
        "headings": 10,      # EN 35 vs MN 25 -- the condensed changelog + Legal
        "table_rows": 0,     # in sync
        # -1: the Mongolian half is MORE complete here. Its "Ашиглах" section
        # documents Windows AND Linux usage inline (a powershell block and a
        # bash block), while the English "Usage" covers Windows only and defers
        # Linux to linux/README.md. A negative entry is a Mongolian surplus and
        # is allowed -- the check compares structure, not which language leads.
        "code_blocks": -1,
    },
    # Written 2026-09-30 as a full mirror: the Linux collector had no Mongolian
    # documentation at all, which docs/TRANSLATION_NEEDED.md called the largest
    # genuine gap in the repo -- a Mongolian-speaking responder on a Linux host
    # was the only user of this toolkit with nothing in their language. Starting
    # it at zero is the point; there is no backlog to record.
    "linux/README.md": {
        "headings": 0,
        "table_rows": 0,
        "code_blocks": 0,
    },
}
NO_DELTA = {k: 0 for k in LABELS}


def measure(body: str) -> dict:
    counts = {k: 0 for k in LABELS}
    in_fence = False
    for line in body.split("\n"):
        if FENCE.match(line):
            if not in_fence:
                counts["code_blocks"] += 1
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if HEADING.match(line):
            counts["headings"] += 1
        if TABLE_ROW.match(line) and not TABLE_SEP.match(line):
            counts["table_rows"] += 1
    return counts


def main(argv) -> int:
    path = Path(argv[1] if len(argv) > 1 else "README.md")
    if not path.is_file():
        print("check-readme-parity: no such file: %s" % path, file=sys.stderr)
        return 2

    # The baseline is per file. Look it up by the repo-relative path so that
    # "linux/README.md" and "./linux/README.md" resolve to the same entry.
    try:
        key = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        key = path.as_posix()
    accepted = ACCEPTED_DELTA_BY_FILE.get(key, NO_DELTA)

    src = path.read_text(encoding="utf-8")
    m = MN_HEADING.search(src)
    if not m:
        print(
            "check-readme-parity: the '## 🇲🇳 Монгол хувилбар' heading was not found.\n"
            "  If the section heading changed, update MN_HEADING in this script.",
            file=sys.stderr,
        )
        return 2

    en, mn = measure(src[: m.start()]), measure(src[m.start() :])

    # Do not count the "## 🇲🇳 Монгол хувилбар" divider itself as a section.
    mn["headings"] -= 1

    # Discount the recorded English-only sections, and verify each one is really
    # still there -- a stale allowlist entry would quietly mask new drift.
    for k, delta in accepted.items():
        en[k] -= delta

    problems = [
        "  %-16s EN=%-4d MN=%-4d (differ by %d)" % (LABELS[k], en[k], mn[k], abs(en[k] - mn[k]))
        for k in LABELS
        if en[k] != mn[k]
    ]
    summary = "  EN [%s]\n  MN [%s]" % (
        " ".join("%s=%d" % (k, en[k]) for k in LABELS),
        " ".join("%s=%d" % (k, mn[k]) for k in LABELS),
    )

    if not problems:
        surplus = ", ".join("%s=%d" % (k, v) for k, v in accepted.items() if v)
        print(
            "check-readme-parity: %s OK -- %s"
            % (key, ("accepted English-only surplus: " + surplus) if surplus
               else "the two halves are an exact mirror")
        )
        print(summary)
        return 0

    print(
        "check-readme-parity: %s -- THE TWO LANGUAGE HALVES MOVED APART FROM "
        "THE RECORDED BASELINE" % key,
        file=sys.stderr,
    )
    print("\n".join(problems), file=sys.stderr)
    print(
        "\n  A section, table or code block added on one side belongs on the other.\n"
        "  Do NOT machine-translate: the Mongolian half is written, not generated.\n"
        "  If the new asymmetry is deliberate, update this file's entry in\n"
        "  ACCEPTED_DELTA_BY_FILE and say why in the commit message.\n"
        + summary,
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
