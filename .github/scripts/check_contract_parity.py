#!/usr/bin/env python3
"""Fail if the two editions are not held to the SAME output contract.

TATAR ships two collectors behind one schema. Each has its own contract
harness -- tests/run-tests.sh (Linux, Python assertions) and
tests/Invoke-Tests.ps1 (Windows, PowerShell assertions) -- and they run in
separate CI jobs on separate runners, so nothing has ever compared them.

That is the gap this closes. The schema says the two editions emit the same
shape; only these harnesses check that a real run does. If one of them stops
asserting a rule, the schema still validates, both jobs still go green, and
the edition that quietly dropped the rule is no longer held to the contract.
Drift here is invisible by construction -- which is exactly why it needs a
gate rather than a convention.

The comparison is on the RULES each harness asserts, taken from its own
assertion labels, not on the code that implements them: the two are written
in different languages and are expected to look different. What may not
differ is WHAT they claim to prove.

Platform-specific rules are listed in PLATFORM_RULES below. Anything else
present on one side only is a failure, naming the rule and the edition that
is missing it.

Usage:  python3 .github/scripts/check_contract_parity.py [repo_root]
Exit:   0 = the two harnesses assert the same contract, 1 = drift.
"""
import os
import re
import sys

# Rules that are legitimately per-edition. Each entry is the Linux spelling
# mapped to the Windows spelling; nothing else is allowed to differ.
PLATFORM_RULES = {
    "platform is linux": "platform is windows",
}

LINUX_HARNESS = os.path.join("tests", "run-tests.sh")
WIN_HARNESS = os.path.join("tests", "Invoke-Tests.ps1")

# check("%s : <rule>" % label, ...)
LINUX_RE = re.compile(r'check\("%s\s*:\s*([^"]+?)"\s*%\s*label')
# Check "$Label : <rule>" ...
WIN_RE = re.compile(r'Check\s+"\$Label\s*:\s*([^"]+?)"')


def rules(path, pattern):
    with open(path, encoding="utf-8-sig") as fh:
        return set(pattern.findall(fh.read()))


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    lin_path = os.path.join(root, LINUX_HARNESS)
    win_path = os.path.join(root, WIN_HARNESS)
    for p in (lin_path, win_path):
        if not os.path.isfile(p):
            print("check-contract-parity: harness not found: %s" % p)
            return 1

    lin = rules(lin_path, LINUX_RE)
    win = rules(win_path, WIN_RE)

    # A harness that suddenly asserts almost nothing is a broken extractor or a
    # gutted file, and an empty-vs-empty comparison would pass. Refuse both.
    if len(lin) < 10 or len(win) < 10:
        print("check-contract-parity: FAIL - implausibly few rules extracted "
              "(linux=%d, windows=%d). The harness or this parser is broken."
              % (len(lin), len(win)))
        return 1

    for lin_rule, win_rule in PLATFORM_RULES.items():
        missing = [r for r in (lin_rule, win_rule) if r not in lin | win]
        if missing:
            print("check-contract-parity: FAIL - a declared platform-specific "
                  "rule is not asserted anywhere: %s" % ", ".join(missing))
            return 1
        lin.discard(lin_rule)
        lin.discard(win_rule)
        win.discard(lin_rule)
        win.discard(win_rule)

    only_lin = sorted(lin - win)
    only_win = sorted(win - lin)

    if only_lin or only_win:
        print("check-contract-parity: FAIL - the two editions are not held to "
              "the same contract.")
        for r in only_lin:
            print("  Windows does NOT assert : %s" % r)
        for r in only_win:
            print("  Linux   does NOT assert : %s" % r)
        print("")
        print("Add the rule to the harness that is missing it, or - if it is "
              "genuinely per-edition - declare it in PLATFORM_RULES in this "
              "script, with a reason.")
        return 1

    print("OK: both contract harnesses assert the same %d rule(s), plus %d "
          "declared platform-specific one(s)." % (len(lin), len(PLATFORM_RULES)))
    for r in sorted(lin):
        print("  - %s" % r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
