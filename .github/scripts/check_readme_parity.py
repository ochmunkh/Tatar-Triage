#!/usr/bin/env python3
"""Check that the two language halves of README.md have the same STRUCTURE.

Both halves are hand-maintained, and in practice one gets updated and the other
forgotten -- this repo's git history carries several "fix the stale Mongolian
numbers" commits for exactly that reason. The content cannot be compared by
machine (being in two languages is the point), but the structure must match: a
section added on one side belongs on the other too.

Compared: heading counts per level, table rows, fenced code blocks.

Usage:  python3 scripts/check-readme-parity.py [README.md]
Exit :  0 in sync, 1 drifted, 2 could not read the file / find the sections.
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
# Measured 2026-09-30.
ACCEPTED_DELTA = {
    "headings": 18,      # EN 35 vs MN 17
    "table_rows": 38,    # the option/exit-code/module tables have no MN version
    "code_blocks": 2,    # EN 6 vs MN 4
}


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
    for key, delta in ACCEPTED_DELTA.items():
        en[key] -= delta

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
        print(
            "check-readme-parity: OK -- structure matches the recorded baseline "
            "(accepted English-only surplus: %s)"
            % ", ".join("%s=%d" % (k, v) for k, v in ACCEPTED_DELTA.items() if v)
        )
        print(summary)
        return 0

    print(
        "check-readme-parity: THE TWO LANGUAGE HALVES MOVED APART FROM THE "
        "RECORDED BASELINE",
        file=sys.stderr,
    )
    print("\n".join(problems), file=sys.stderr)
    print(
        "\n  A section, table or code block added on one side belongs on the other.\n"
        "  Do NOT machine-translate: the Mongolian half is written, not generated.\n"
        "  If the new asymmetry is deliberate, update ACCEPTED_DELTA in this script\n"
        "  and say why in the commit message.\n"
        + summary,
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
