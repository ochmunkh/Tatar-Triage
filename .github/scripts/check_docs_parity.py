#!/usr/bin/env python3
"""Fail when the docs disagree with the code they describe.

Every fact checked here is mechanically derivable from the collectors, and the
git history shows each one has already needed a dedicated repair commit:

  1. the module-count badges in README.md / linux/README.md vs the registries
     ($script:Collectors in Tatar.ps1, MOD_NAMES in linux/tatar-linux.sh)
  2. the module lists in the English "## Modules" section vs the Mongolian
     "## Модулиуд" section - the two halves of the bilingual README are mirrors
     and must name the same modules
  3. every ATT&CK technique a collector can emit appears in
     docs/MITRE_ATTACK.md, so an analyst holding a technique id in summary.json
     always has a row to pivot from
  4. every name in a **Module** column of docs/MITRE_ATTACK.md is a real module,
     and on the Linux side the findings table plus the "evidence-only" list
     account for every module in MOD_NAMES. Check 3 compares technique ids only,
     so it cannot see a *finding category* (e.g. `context`) sitting in a Module
     column, nor a module that fell out of the doc altogether

Check 3 is deliberately ONE-DIRECTIONAL: the doc maps evidence captured, not
findings raised, so rows for artifact-only modules (hives, browser, usb,
shadow, rdp) are correct by design and are not required to be emitted.

    python3 .github/scripts/check_docs_parity.py [repo_root]

Exit code: 0 = docs and code agree, 1 = at least one mismatch (listed).
"""
import io
import os
import re
import sys

FAILURES = []


def read(root, rel):
    with io.open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()


def fail(msg):
    FAILURES.append(msg)


def slice_block(text, start_marker, end_marker):
    """Text from start_marker up to the first end_marker after it."""
    i = text.find(start_marker)
    if i < 0:
        return ""
    j = text.find(end_marker, i + len(start_marker))
    return text[i:j if j >= 0 else len(text)]


def windows_modules(ps1):
    block = slice_block(ps1, "$script:Collectors = [ordered]@{", "\n}")
    return re.findall(r"^\s{4}([a-z][a-z0-9]*)\s*=\s*\$\{function:", block, re.M)


def linux_modules(sh):
    m = re.search(r'^MOD_NAMES="([^"]+)"', sh, re.M)
    return m.group(1).split() if m else []


def dotted_list(line):
    """'`a` · `b`' or 'a · b' -> ['a', 'b']"""
    return [t.strip().strip("`") for t in line.replace("*", "").split("·") if t.strip().strip("`")]


def first_list(section, where):
    """The first module list line of a section."""
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("`"):
            return dotted_list(line)
    fail("%s: no module list line found" % where)
    return None


def check_badge(name, text, pattern, expected):
    m = re.search(pattern, text)
    if not m:
        fail("%s: badge matching %r not found" % (name, pattern))
    elif int(m.group(1)) != expected:
        fail("%s: badge says %s modules, the code has %d" % (name, m.group(1), expected))


def main(argv):
    root = argv[1] if len(argv) > 1 else "."
    ps1 = read(root, "Tatar.ps1")
    sh = read(root, "linux/tatar-linux.sh")
    readme = read(root, "README.md")
    lreadme = read(root, "linux/README.md")
    mitre = read(root, "docs/MITRE_ATTACK.md")

    win = windows_modules(ps1)
    lin = linux_modules(sh)
    if not win:
        fail("Tatar.ps1: could not parse $script:Collectors")
    if not lin:
        fail("linux/tatar-linux.sh: could not parse MOD_NAMES")

    # 1. module-count badges
    check_badge("README.md", readme, r"badge/modules-(\d+)-", len(win))
    check_badge("linux/README.md", lreadme, r"badge/modules-(\d+)-", len(lin))

    # 2. bilingual module lists
    en = slice_block(readme, "\n## Modules\n", "\n---")
    mn = slice_block(readme, "\n## Модулиуд\n", "\n---")
    if not en:
        fail("README.md: the English '## Modules' section was not found")
    if not mn:
        fail("README.md: the Mongolian '## Модулиуд' section was not found")

    def listed(section, label, where):
        for line in section.splitlines():
            if label in line:
                return dotted_list(line.split(":", 1)[1] if ":" in line else line)
        fail("%s: no %r list found" % (where, label))
        return None

    en_win = None
    for line in en.splitlines():
        if line.startswith("`memory`") or "Windows (" in line:
            en_win = dotted_list(line.split(":", 1)[1] if ":" in line else line)
            break
    if en_win is None:
        fail("README.md '## Modules': the Windows module list was not found")
    en_lin = listed(en, "Linux (", "README.md '## Modules'")
    mn_win = listed(mn, "Windows (", "README.md '## Модулиуд'")
    mn_lin = listed(mn, "Linux (", "README.md '## Модулиуд'")

    for label, listed_mods, code_mods in (
        ("README.md '## Modules' Windows", en_win, win),
        ("README.md '## Modules' Linux", en_lin, lin),
        ("README.md '## Модулиуд' Windows", mn_win, win),
        ("README.md '## Модулиуд' Линукс", mn_lin, lin),
        ("linux/README.md '## Modules'", first_list(
            slice_block(lreadme, "\n## Modules (order of volatility)\n", "\nCoverage"),
            "linux/README.md '## Modules (order of volatility)'"), lin),
        # The Mongolian half of linux/README.md carries the same list, so it can
        # go stale exactly the way every other duplicated module list in this
        # repo already has. Checked from the day it was written rather than
        # after the first "fix the stale Mongolian list" commit.
        ("linux/README.md '## Модулиуд'", first_list(
            slice_block(lreadme, "\n## Модулиуд (volatility-ийн дарааллаар)\n", "\nХамрах"),
            "linux/README.md '## Модулиуд (volatility-ийн дарааллаар)'"), lin),
    ):
        if listed_mods is None:
            continue
        if listed_mods != code_mods:
            fail("%s lists %d module(s) %s, the code has %d %s"
                 % (label, len(listed_mods), listed_mods, len(code_mods), code_mods))

    if en_win is not None and mn_win is not None and en_win != mn_win:
        fail("README.md: the English and Mongolian Windows module lists differ")
    if en_lin is not None and mn_lin is not None and en_lin != mn_lin:
        fail("README.md: the English and Mongolian Linux module lists differ")

    # the counts written into the Mongolian labels, e.g. "Windows (30):"
    for label, code_mods in (("Windows", win), ("Linux", lin)):
        for m in re.finditer(r"\*\*%s \((\d+)\):\*\*" % label, readme):
            if int(m.group(1)) != len(code_mods):
                fail("README.md: '%s (%s)' but the code has %d modules"
                     % (label, m.group(1), len(code_mods)))

    # 3. every emitted technique has a row in docs/MITRE_ATTACK.md
    emitted = set()
    for block in (
        slice_block(ps1, "function Get-Technique", "\n}"),
        slice_block(sh, "map_technique() {", "\n}"),
        slice_block(sh, "ioc_technique() {", "\n}"),
    ):
        emitted.update(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", block))
    documented = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", mitre))
    missing = sorted(emitted - documented)
    if missing:
        fail("docs/MITRE_ATTACK.md is missing technique(s) a collector emits: %s" % ", ".join(missing))

    # 4. the Module columns name real modules, and the Linux side is complete.
    # `context` is a finding *category* raised by the `containers` module; it sat
    # in the Module column reading as a 19th Linux module while `containers`
    # itself appeared nowhere. Check 3 is blind to it - it only diffs ids.
    def module_cells(section):
        """The first cell of every table row that starts with a `backticked` name."""
        return sorted(set(re.findall(r"^\|\s*`([^`]+)`\s*\|", section, re.M)))

    # slice_block falls back to end-of-file when an end marker is gone, which would turn a
    # renamed heading into a confusing "Module column names 12 names" failure instead of
    # naming the real cause. Check the markers exist first and say so plainly.
    for marker in ("\n## By tactic (Linux", "\n### Raised by the IOC engine",
                   "\n## Evidence / execution-history sources"):
        if marker not in mitre:
            fail("docs/MITRE_ATTACK.md: the '%s' heading was renamed or removed, so the "
                 "Module-column checks below cannot be scoped correctly - update "
                 ".github/scripts/check_docs_parity.py to match." % marker.strip())

    win_sec = slice_block(mitre, "## By tactic (Windows", "\n## By tactic (Linux")
    lin_sec = slice_block(mitre, "## By tactic (Linux", "\n### Raised by the IOC engine")
    # The third Module-column table. It was previously unchecked, so a finding category or a
    # retired module could sit in it indefinitely - the same defect check 4 exists to catch.
    # Its artifacts (prefetch, Amcache/LNK, Recycle Bin, MFT) are all Windows-side.
    ev_sec = slice_block(mitre, "## Evidence / execution-history sources", "\n---")
    for where, section, code_mods in (("Windows", win_sec, win), ("Linux", lin_sec, lin),
                                      ("Evidence / execution-history sources", ev_sec, win)):
        if not section:
            fail("docs/MITRE_ATTACK.md: the '%s' section was not found"
                 % (("## " + where) if where.startswith("Evidence")
                    else "## By tactic (%s" % where))
            continue
        bogus = [m for m in module_cells(section) if m not in code_mods]
        if bogus:
            fail("docs/MITRE_ATTACK.md '%s': Module column names %s, which the "
                 "code has no module for - a finding category is not a module: %s"
                 % (where if where.startswith("Evidence") else "By tactic (%s)" % where,
                    "one name" if len(bogus) == 1 else "%d names" % len(bogus),
                    ", ".join(bogus)))

    # Linux only: the doc promises a complete split of MOD_NAMES into
    # "raises findings" and "evidence-only", so neither half may lose a module.
    if lin_sec:
        ev = slice_block(lin_sec, "Evidence-only Linux modules", "\n\n")
        if not ev:
            fail("docs/MITRE_ATTACK.md: the 'Evidence-only Linux modules' list was not found")
        else:
            accounted = set(module_cells(lin_sec)) | set(re.findall(r"`([^`]+)`", ev))
            absent = [m for m in lin if m not in accounted]
            if absent:
                fail("docs/MITRE_ATTACK.md 'By tactic (Linux)': module(s) in neither the "
                     "findings table nor the evidence-only list: %s" % ", ".join(absent))

    if FAILURES:
        for f in FAILURES:
            sys.stderr.write("FAIL  %s\n" % f)
        sys.stderr.write("%d docs-parity failure(s)\n" % len(FAILURES))
        return 1
    print("OK: docs and code agree - windows=%d modules, linux=%d modules, "
          "%d emitted technique(s) documented, every ATT&CK Module cell is a real module"
          % (len(win), len(lin), len(emitted)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
