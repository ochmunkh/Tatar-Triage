#!/usr/bin/env python3
"""tatar-diff tests: new / resolved / changed / unchanged, duplicates, suppression,
wrong-version input, exit codes. Fixture-free: documents are built here."""
import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "tatar-diff.py")
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok   " + name)
    else: bad += 1; print("  FAIL %s %s" % (name, extra))
def f(fp, ch, msg="m", sev="High", sup=False):
    return {"fingerprint": fp, "contentHash": ch, "message": msg, "severity": sev, "category": "c", "suppressed": sup, "confidence": 0.7, "detail": ch}
def doc(findings, host="h"):
    return {"schemaVersion": "1.7", "host": host, "generated": "2026-01-01T00:00:00Z", "findings": findings}
def run(a, b, *x):
    d = tempfile.mkdtemp()
    pa, pb = os.path.join(d, "a.json"), os.path.join(d, "b.json")
    json.dump(a, open(pa, "w")); json.dump(b, open(pb, "w"))
    r = subprocess.run([sys.executable, "-I", TOOL, pa, pb] + list(x), capture_output=True, text=True)
    return r
r = run(doc([f("a", "1"), f("b", "1"), f("c", "1")]), doc([f("a", "1"), f("b", "2"), f("d", "1")]), "--json")
j = json.loads(r.stdout)
check("counts new/resolved/changed/unchanged", j["counts"] == {"new": 1, "resolved": 1, "changed": 1, "unchanged": 1}, j["counts"])
check("new is d, resolved is c", j["new"][0]["fingerprint"] == "d" and j["resolved"][0]["fingerprint"] == "c")
check("changed is b", j["changed"][0]["after"]["contentHash"] == "2")
r = run(doc([f("a", "1"), f("a", "1")]), doc([f("a", "1")]), "--json")
j = json.loads(r.stdout)
check("duplicate fingerprints pair one to one", j["counts"] == {"new": 0, "resolved": 1, "changed": 0, "unchanged": 1}, j["counts"])
r = run(doc([f("a", "1", sup=True)]), doc([]), "--json")
check("suppressed ignored by default", json.loads(r.stdout)["counts"]["resolved"] == 0)
r = run(doc([f("a", "1", sup=True)]), doc([]), "--json", "--all")
check("suppressed counted with --all", json.loads(r.stdout)["counts"]["resolved"] == 1)
r = run(doc([]), doc([f("n", "1")]), "--fail-on-new")
check("--fail-on-new exits 2", r.returncode == 2)
r = run(doc([f("n", "1")]), doc([f("n", "1")]), "--fail-on-new")
check("--fail-on-new exits 0 when nothing is new", r.returncode == 0)
r = run(doc([f("a", "1")], "h1"), doc([f("a", "1")], "h2"))
check("different hosts produce a warning", "different hosts" in r.stdout)
r = run({"findings": [{"message": "x"}]}, doc([]))
check("a pre-1.7 scan is refused with exit 1", r.returncode == 1 and "fingerprint" in r.stderr)
print("RESULT  passed: %d  failed: %d" % (ok, bad))
sys.exit(1 if bad else 0)
