#!/usr/bin/env python3
"""tatar-aggregate tests: stacking by fingerprint and by path, latest scan per host."""
import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "tatar-aggregate.py")
ok = bad = 0
def check(n, c, x=""):
    global ok, bad
    if c: ok += 1; print("  ok   " + n)
    else: bad += 1; print("  FAIL %s %s" % (n, x))
def f(fp, paths=(), sup=False, sev="Review"):
    return {"fingerprint": fp, "paths": list(paths), "suppressed": sup, "severity": sev, "message": "m-" + fp, "category": "c"}
root = tempfile.mkdtemp()
def host(name, gen, findings, sub=None):
    d = os.path.join(root, sub or name); os.makedirs(d, exist_ok=True)
    json.dump({"host": name, "generated": gen, "findings": findings}, open(os.path.join(d, "findings.json"), "w"))
host("A", "2026-01-01T00:00:00Z", [f("common", ["/x"]), f("rare", ["/odd"], sev="High")])
host("B", "2026-01-01T00:00:00Z", [f("common", ["/x"])])
host("C", "2026-01-01T00:00:00Z", [f("common", ["/x"]), f("hidden", sup=True)])
host("C", "2025-12-01T00:00:00Z", [f("oldonly")], sub="C-old")
def run(*a):
    r = subprocess.run([sys.executable, "-I", TOOL, root] + list(a), capture_output=True, text=True)
    return r
j = json.loads(run("--format", "json").stdout)
check("three hosts, an older duplicate scan of C is ignored", j["hosts"] == ["A", "B", "C"] and all(i["key"] != "oldonly" for i in j["items"]), j["hosts"])
check("rarest first", j["items"][0]["key"] == "rare" and j["items"][0]["hosts"] == 1)
check("common is on 3 of 3", j["items"][-1]["key"] == "common" and j["items"][-1]["hosts"] == 3)
check("suppressed ignored by default", all(i["key"] != "hidden" for i in j["items"]))
check("suppressed counted with --all", any(i["key"] == "hidden" for i in json.loads(run("--format", "json", "--all").stdout)["items"]))
j = json.loads(run("--by", "path", "--format", "json", "--max-hosts", "1").stdout)
check("by path with --max-hosts 1 shows only /odd", [i["key"] for i in j["items"]] == ["/odd"], j["items"])
d = tempfile.mkdtemp(); json.dump({"findings": [{"message": "old"}]}, open(os.path.join(d, "findings.json"), "w"))
r = subprocess.run([sys.executable, "-I", TOOL, d], capture_output=True, text=True)
check("a pre-1.7 scan is skipped and the run fails with exit 1", r.returncode == 1 and "fingerprint" in r.stderr)
print("RESULT  passed: %d  failed: %d" % (ok, bad))
sys.exit(1 if bad else 0)
