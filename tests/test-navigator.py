#!/usr/bin/env python3
"""tatar-navigator tests: layer shape, scores, suppression, reviews, bad ids,
escaping, exit codes. Fixture-free."""
import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
NAV = os.path.join(HERE, "..", "tools", "tatar-navigator.py")
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok   " + name)
    else: bad += 1; print("  FAIL %s %s" % (name, extra))
A, B, C = "a" * 16, "b" * 16, "c" * 16
def f(fp, i, tech, sev="High", sup=False, cat="persistence"):
    return {"id": i, "fingerprint": fp, "contentHash": "1" * 16, "message": "m", "severity": sev, "category": cat,
            "technique": tech, "suppressed": sup}
d = tempfile.mkdtemp()
def scan(name, findings):
    p = os.path.join(d, name); os.makedirs(p)
    json.dump({"schemaVersion": "1.8", "host": "h", "findings": findings}, open(os.path.join(p, "findings.json"), "w"))
    return p
def run(*a):
    return subprocess.run([sys.executable, "-I", NAV] + list(a), capture_output=True, text=True)
def tech(r): return {t["techniqueID"]: t for t in json.loads(r.stdout)["techniques"]}

print("N1  layer shape and scores")
p = scan("n1", [f(A, "1", ["T1547.001"]), f(B, "2", ["T1547.001", "T1053.005"], sev="Review", cat="tasks"),
                f(C, "3", ["T1053.005"], sev="Review", cat="tasks"), f("d" * 16, "4", ["T1059"], sup=True)])
r = run(p)
L = json.loads(r.stdout)
check("exit 0, Navigator domain and layer version", r.returncode == 0 and L["domain"] == "enterprise-attack" and L["versions"]["layer"] == "4.5", r.stderr)
t = tech(r)
check("a High finding makes the cell 100", t["T1547.001"]["score"] == 100)
check("only Review findings make it 50", t["T1053.005"]["score"] == 50)
check("suppressed findings are left out", "T1059" not in t)
check("comment counts findings and names categories", t["T1547.001"]["comment"] == "2 finding(s): persistence, tasks", t["T1547.001"]["comment"])
check("--all includes suppressed", "T1059" in tech(run(p, "--all")))
check("--name sets the layer name", json.loads(run(p, "--name", "Host 7").stdout)["name"] == "Host 7")

print("N2  reviews")
rv = os.path.join(d, "rev.json")
json.dump({"reviewed": [{"fingerprint": A, "verdict": "good"}, {"fingerprint": B, "verdict": "bad", "note": "x"}]}, open(rv, "w"))
r = run(p, "--reviews", rv); t = tech(r)
check("good is dropped; the cell keeps the other findings", t["T1547.001"]["score"] == 50 and t["T1547.001"]["comment"].startswith("1 finding(s)"), t)
check("bad is marked in the comment", "1 reviewed as bad" in t["T1547.001"]["comment"] and "1 reviewed as bad" in t["T1053.005"]["comment"])
check("--all keeps the good one", tech(run(p, "--reviews", rv, "--all"))["T1547.001"]["score"] == 100)
bad_rv = os.path.join(d, "bad.json"); json.dump({"reviewed": [{}]}, open(bad_rv, "w"))
check("a bad reviews file is exit 1", run(p, "--reviews", bad_rv).returncode == 1)

print("N3  ids, escaping, input errors")
p2 = scan("n3", [f(A, "1", ["T1547.001", "T9", "javascript:alert(1)", "T1059.00", 5]), f(B, "2", ["T1003"], cat="x\x1b[31m‮evil")])
r = run(p2)
check("only well-formed ids are kept, the rest are counted", sorted(tech(r)) == ["T1003", "T1547.001"] and "ignored 4" in r.stderr, r.stderr)
check("output is pure ASCII, no control or bidi characters", r.stdout.isascii() and "\x1b" not in r.stdout and "‮" not in r.stdout)
check("no techniques at all is exit 1", run(scan("n3b", [f(A, "1", [])])).returncode == 1)
check("a missing path is exit 1", run(os.path.join(d, "nope")).returncode == 1)
broken = os.path.join(d, "broken"); os.makedirs(broken); open(os.path.join(broken, "findings.json"), "w").write("{not json")
r = run(p, broken)
check("one unreadable scan: the rest is written, exit 2", r.returncode == 2 and "T1547.001" in tech(r), r.stderr)
out = os.path.join(d, "layer.json")
r = run(p, "-o", out)
check("-o writes the file", r.returncode == 0 and r.stdout == "" and json.load(open(out))["domain"] == "enterprise-attack")
r = run(d)
check("a folder of folders is walked, each scan once", r.returncode in (0, 2) and "T1547.001" in tech(r))
check("technique list is sorted", list(tech(run(p))) == sorted(tech(run(p))))
print("\n%d passed, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
