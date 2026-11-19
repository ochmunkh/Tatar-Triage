#!/usr/bin/env python3
"""Release integrity gate for the TATAR Triage Toolkit repository.

check_docs_parity.py holds the documents to the code (module counts, badges,
ATT&CK coverage).  This gate holds the release and the repository to their own
rules: the small mistakes that each needed a repair commit once and that no
test of the collectors can see.

  RI-01  The newest released CHANGELOG section is the version both collectors
         carry (full x.y.z), it has a date, and it is not empty.  release.yml
         builds the release notes from that section.
  RI-02  Every file release.yml copies into a release exists in the repository.
  RI-03  A sample log line "module NAME (n/N)" in the documents has N equal to
         the number of Windows modules, and n within 1..N.
  RI-04  The documents spell summary.json finding fields the way the schema
         does (lower case), not "Severity/Category/Message/Detail".
  RI-05  A "Result at vX.Y" heading in docs/SECURITY-TESTING.md names the
         current major.minor, so measured results are re-recorded for each line.
  RI-06  Workflows: every action is pinned to a full commit SHA, the token
         permissions are declared, nothing runs on pull_request_target, and no
         run: step interpolates text an outsider controls.
  RI-07  Nothing in a tracked text file, and nothing in the newest commit
         message, carries a tool or vendor name, an assistant attribution line
         or the organisation name.  (Maintainer rule for this repository.)
  RI-08  Local-only material (hand-off notes, lab files, result folders,
         planning pages) is not tracked.
  RI-09  The files a project is judged by exist: LICENSE, SECURITY.md,
         CODE_OF_CONDUCT.md, CONTRIBUTING.md, dependabot.yml.
  RI-10  The analysis tools in tools/ import only the Python standard library,
         as docs/TOOLS.md promises (checked on the syntax tree, nothing runs).

Exit 0 = every rule holds, 1 = at least one failed.  Run from the repo root:

    python3 .github/scripts/check_release_integrity.py [ROOT]
"""
import ast
import io
import os
import re
import subprocess
import sys

FAILS = []


def fail(rule, msg):
    FAILS.append("%s %s" % (rule, msg))


def read(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return ""
    with io.open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read().replace("\r\n", "\n")


def tracked_files(root):
    """Tracked files from git; a plain walk when there is no repository (the
    test copies the tree into a temporary folder)."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True,
                             text=True, check=True).stdout
        files = [f for f in out.splitlines() if f]
        if files:
            return files
    except Exception:
        pass
    files = []
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for n in names:
            files.append(os.path.relpath(os.path.join(dirpath, n), root).replace(os.sep, "/"))
    return files


def versions(root):
    ps1 = read(root, "Tatar.ps1")
    sh = read(root, "linux/tatar-linux.sh")
    w = re.search(r"\$script:ToolVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'", ps1)
    l = re.search(r'^VERSION="([0-9]+\.[0-9]+\.[0-9]+)"', sh, re.M)
    return (w.group(1) if w else None), (l.group(1) if l else None)


def ri01(root, win_v, lin_v):
    if not win_v or not lin_v:
        fail("RI-01", "could not read the full version from both collectors")
        return
    if win_v != lin_v:
        fail("RI-01", "the editions carry different versions: Windows %s, Linux %s" % (win_v, lin_v))
        return
    log = read(root, "CHANGELOG.md")
    heads = re.findall(r"^## \[([^\]]+)\](?: [\u2014-] (\S+))?", log, re.M)
    released = [(v, d) for v, d in heads if v.lower() != "unreleased"]
    if not released:
        fail("RI-01", "CHANGELOG.md has no released section")
        return
    top_v, top_d = released[0]
    if top_v != win_v:
        fail("RI-01", "the newest CHANGELOG section is %s but the collectors are %s" % (top_v, win_v))
    if not top_d or not re.match(r"^\d{4}-\d{2}-\d{2}$", top_d):
        fail("RI-01", "the %s section has no ISO date" % top_v)
    body = re.search(r"^## \[%s\][^\n]*\n(.*?)(?=^## \[|\Z)" % re.escape(top_v), log, re.M | re.S)
    if not body or len(body.group(1).strip()) < 40:
        fail("RI-01", "the %s section is empty; release.yml would publish a fallback note" % top_v)


def ri02(root):
    yml = read(root, ".github/workflows/release.yml")
    for line in yml.splitlines():
        m = re.match(r"\s*cp\s+(.+?)\s+dist/\s*$", line)
        if not m:
            continue
        for src in m.group(1).split():
            if not os.path.isfile(os.path.join(root, src)):
                fail("RI-02", "release.yml copies %s but it is not in the repository" % src)


def windows_module_count(root):
    ps1 = read(root, "Tatar.ps1")
    i = ps1.find("$script:Collectors = [ordered]@{")
    if i < 0:
        return None
    j = ps1.find("\n}", i)
    return len(re.findall(r"^\s{4}([a-z][a-z0-9]*)\s*=\s*\$\{function:", ps1[i:j], re.M))


def doc_files(files):
    return [f for f in files if f.endswith(".md") and f != "CHANGELOG.md"]


def ri03_04_05(root, files, win_v):
    n_mod = windows_module_count(root)
    for rel in doc_files(files):
        text = read(root, rel)
        if n_mod:
            for m in re.finditer(r"\bmodule\s+\w+\s+\((\d+)/(\d+)\)", text):
                n, total = int(m.group(1)), int(m.group(2))
                if total != n_mod or not 1 <= n <= total:
                    fail("RI-03", "%s: sample log shows (%d/%d), Windows has %d modules" % (rel, n, total, n_mod))
        if re.search(r"Severity/Category/Message/Detail", text):
            fail("RI-04", "%s: finding fields are written with capitals, the schema uses lower case" % rel)
    st = read(root, "docs/SECURITY-TESTING.md")
    m = re.search(r"^## Result at v(\d+\.\d+)", st, re.M)
    if st and win_v:
        if not m:
            fail("RI-05", "docs/SECURITY-TESTING.md has no 'Result at vX.Y' heading")
        elif m.group(1) != ".".join(win_v.split(".")[:2]):
            fail("RI-05", "docs/SECURITY-TESTING.md records results at v%s, the collectors are %s"
                 % (m.group(1), win_v))


def ri06(root, files):
    wfs = [f for f in files if re.match(r"\.github/workflows/[^/]+\.ya?ml$", f)]
    if not wfs:
        fail("RI-06", "no workflow files found")
    risky = re.compile(r"\$\{\{\s*(github\.event\.[^}]*(title|body|head_ref|label|message|name|ref)\b|github\.head_ref)")
    for rel in wfs:
        text = read(root, rel)
        for n, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            m = re.match(r"-?\s*uses:\s*([^\s#]+)", s)
            if m and not m.group(1).startswith("./"):
                if not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                    fail("RI-06", "%s:%d action not pinned to a commit SHA: %s" % (rel, n, m.group(1)))
            if re.match(r"on:\s*\[?.*pull_request_target", s) or s.startswith("pull_request_target"):
                fail("RI-06", "%s:%d uses pull_request_target" % (rel, n))
            if risky.search(line) and not s.startswith("if:") and not s.startswith("#"):
                fail("RI-06", "%s:%d interpolates attacker-controlled text: %s" % (rel, n, s[:80]))
        top = re.search(r"^permissions:", text, re.M)
        job_perm = len(re.findall(r"^    permissions:", text, re.M))
        jobs = len(re.findall(r"^  [A-Za-z0-9_-]+:\s*$", text.split("\njobs:", 1)[1], re.M)) if "\njobs:" in text else 0
        if not top and job_perm < jobs:
            fail("RI-06", "%s: token permissions are not declared (default token is broader than needed)" % rel)


def forbidden_pattern():
    # Built from fragments so this file does not contain what it forbids.
    parts = [r"\b" + "A" + "I" + r"\b", "p" + "ssa", "cla" + "ude", "anthr" + "opic",
             "co-auth" + "ored-by"]
    return re.compile("|".join(parts), re.I)


def ri07(root, files):
    pat = forbidden_pattern()
    skip = ("tests/test-release-integrity.py", ".github/scripts/check_release_integrity.py")
    binary = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".docx", ".woff", ".woff2")
    for rel in files:
        if rel in skip or rel.lower().endswith(binary):
            continue
        text = read(root, rel)
        m = pat.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            fail("RI-07", "%s:%d contains a name the repository keeps out (%r)" % (rel, line, m.group(0)))
    try:
        msg = subprocess.run(["git", "-C", root, "log", "-1", "--format=%B"], capture_output=True,
                             text=True, check=True).stdout
        m = pat.search(msg)
        if m:
            fail("RI-07", "the newest commit message contains %r" % m.group(0))
    except Exception:
        pass


def ri08(root, files):
    local_only = [r"^HANDOFF\.md$", r"^DEFENSE\.md$", r"^lab/", r"Final-Roadmap.*\.html$",
                  r"test-catalogue.*\.html$", r"^(kali|DESKTOP|00C1C264)[-_]", r"^backup[-_]"]
    for rel in files:
        for pat in local_only:
            if re.search(pat, rel):
                fail("RI-08", "%s is local-only material but is tracked" % rel)
                break


def ri09(root):
    for rel in ("LICENSE", "SECURITY.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", ".github/dependabot.yml"):
        if not os.path.isfile(os.path.join(root, rel)):
            fail("RI-09", "%s is missing" % rel)


def ri10(root, files):
    std = getattr(sys, "stdlib_module_names", None)
    if std is None:
        return  # Python older than 3.10 has no list to compare with
    for rel in sorted(f for f in files if re.match(r"tools/[^/]+\.py$", f)):
        try:
            tree = ast.parse(read(root, rel))
        except SyntaxError as exc:
            fail("RI-10", "%s does not parse: %s" % (rel, exc.msg))
            continue
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".")[0]
                if top not in std:
                    fail("RI-10", "%s:%d imports %s, which is not in the standard library" % (rel, node.lineno, top))


def main(argv):
    root = argv[1] if len(argv) > 1 else "."
    win_v, lin_v = versions(root)
    files = tracked_files(root)
    ri01(root, win_v, lin_v)
    ri02(root)
    ri03_04_05(root, files, win_v)
    ri06(root, files)
    ri07(root, files)
    ri08(root, files)
    ri09(root)
    ri10(root, files)
    if FAILS:
        for f in FAILS:
            print("FAIL: " + f)
        print("release integrity: %d problem(s)" % len(FAILS))
        return 1
    print("OK: release integrity - version %s in both editions and the CHANGELOG, workflows pinned "
          "and least-privilege, sample logs and field names match the code, nothing local-only "
          "tracked, the tools use only the standard library, no names kept out of the repository" % win_v)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
