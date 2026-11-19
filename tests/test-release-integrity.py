#!/usr/bin/env python3
"""Proof that check_release_integrity.py catches what it claims to catch.

A gate that has never failed proves nothing. This copies the tracked files into
a temporary folder, checks the clean copy passes, then breaks one thing at a
time and requires the gate to fail with the rule that owns that mistake.

    python3 tests/test-release-integrity.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GATE = os.path.join(ROOT, ".github", "scripts", "check_release_integrity.py")

# The names the gate keeps out, built from pieces so this file has none of them.
BAD = "cla" + "ude"

passed = failed = 0


def tracked():
    out = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if f]


def make_copy(files):
    tmp = tempfile.mkdtemp(prefix="ri-")
    for rel in files:
        src = os.path.join(ROOT, rel)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
    return tmp


def run_gate(tmp):
    p = subprocess.run([sys.executable, GATE, tmp], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def edit(tmp, rel, fn):
    path = os.path.join(tmp, rel)
    with open(path, encoding="utf-8", newline="") as fh:
        text = fh.read()
    new = fn(text)
    assert new != text, "mutation changed nothing in " + rel
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(new)


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  " + name)
    else:
        failed += 1
        print("  FAIL  " + name + ("  --  " + detail if detail else ""))


files = tracked()
base = make_copy(files)
code, out = run_gate(base)
check("the untouched copy passes", code == 0, out.strip()[:200])
shutil.rmtree(base, ignore_errors=True)


def mutation(rule, label, fn):
    tmp = make_copy(files)
    try:
        fn(tmp)
        code, out = run_gate(tmp)
        check("%s: %s" % (rule, label), code == 1 and rule in out, out.strip()[:160])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def bump_ps1(tmp):
    edit(tmp, "Tatar.ps1", lambda t: re.sub(r"(\$script:ToolVersion\s*=\s*')[0-9.]+(')", r"\g<1>9.9.9\2", t, 1))


def bump_sh(tmp):
    edit(tmp, "linux/tatar-linux.sh", lambda t: re.sub(r'^VERSION="[0-9.]+"', 'VERSION="9.9.9"', t, 1, re.M))


def no_date(tmp):
    edit(tmp, "CHANGELOG.md", lambda t: re.sub(r"^(## \[[0-9.]+\]) [\u2014-] \S+", r"\1", t, 1, re.M))


def empty_section(tmp):
    def f(t):
        m = re.search(r"^(## \[[0-9.]+\][^\n]*\n)(.*?)(?=^## \[)", t, re.M | re.S)
        return t[:m.start(2)] + "\n" + t[m.end(2):]
    edit(tmp, "CHANGELOG.md", f)


def missing_release_file(tmp):
    edit(tmp, ".github/workflows/release.yml", lambda t: t.replace("allowlist.sample.json ioc.sample.json", "allowlist.sample.json nothing-here.json", 1))


def stale_sample(tmp):
    edit(tmp, "docs/OUTPUT.md", lambda t: t.replace("(26/33)", "(26/30)", 1))


def capital_fields(tmp):
    edit(tmp, "docs/OUTPUT.md", lambda t: t.replace("`severity/category/message/detail`", "`Severity/Category/Message/Detail`", 1))


def old_result(tmp):
    edit(tmp, "docs/SECURITY-TESTING.md", lambda t: re.sub(r"^## Result at v[0-9.]+", "## Result at v1.8", t, 1, flags=re.M))


def unpinned(tmp):
    edit(tmp, ".github/workflows/ci.yml", lambda t: re.sub(r"actions/checkout@[0-9a-f]{40}", "actions/checkout@v4", t, 1))


def no_permissions(tmp):
    edit(tmp, ".github/workflows/ci.yml", lambda t: re.sub(r"^permissions:\n  contents: read\n", "", t, 1, flags=re.M))


def prt(tmp):
    edit(tmp, ".github/workflows/ci.yml", lambda t: t.replace("  pull_request:", "  pull_request_target:", 1))


def injection(tmp):
    edit(tmp, ".github/workflows/ci.yml", lambda t: t.replace("run: bash tests/run-tests.sh", "run: echo ${{ github.event.pull_request.title }}", 1))


def bad_name(tmp):
    edit(tmp, "docs/USAGE.md", lambda t: t + "\nWritten with " + BAD + ".\n")


def local_file(tmp):
    with open(os.path.join(tmp, "HANDOFF.md"), "w", encoding="utf-8") as fh:
        fh.write("local notes\n")


def outside_import(tmp):
    edit(tmp, "tools/tatar-diff.py", lambda t: t + "\nimport requests\n")


def drop_security(tmp):
    os.remove(os.path.join(tmp, "SECURITY.md"))


mutation("RI-01", "only the Windows edition is bumped", bump_ps1)
mutation("RI-01", "only the Linux edition is bumped", bump_sh)
mutation("RI-01", "the newest CHANGELOG section has no date", no_date)
mutation("RI-01", "the newest CHANGELOG section is empty", empty_section)
mutation("RI-02", "release.yml copies a file that is not there", missing_release_file)
mutation("RI-03", "a sample log counts 30 modules", stale_sample)
mutation("RI-04", "the docs write the finding fields with capitals", capital_fields)
mutation("RI-05", "the recorded results are from an old release line", old_result)
mutation("RI-06", "an action is pinned to a tag, not a commit", unpinned)
mutation("RI-06", "the workflow declares no token permissions", no_permissions)
mutation("RI-06", "a workflow runs on pull_request_target", prt)
mutation("RI-06", "a run step interpolates a pull request title", injection)
mutation("RI-07", "a document carries a name the repository keeps out", bad_name)
mutation("RI-08", "a local hand-off file is tracked", local_file)
mutation("RI-09", "SECURITY.md is missing", drop_security)
mutation("RI-10", "a tool imports a package outside the standard library", outside_import)

print("")
print("release integrity gate: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
