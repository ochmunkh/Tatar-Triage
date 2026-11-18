#!/usr/bin/env python3
"""tatar-review tests: verdicts, stale reviews, add/update, malformed files, exit codes,
and the --reviews option of tatar-diff and tatar-aggregate. Fixture-free."""
import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.join(HERE, "..", "tools")
REV, DIFF, AGG = (os.path.join(T, n) for n in ("tatar-review.py", "tatar-diff.py", "tatar-aggregate.py"))
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok   " + name)
    else: bad += 1; print("  FAIL %s %s" % (name, extra))
A, B, C, D = "a" * 16, "b" * 16, "c" * 16, "d" * 16
H1, H2 = "1" * 16, "2" * 16
def f(fp, ch, msg="m", sev="High", sup=False, i="TTR-F-001"):
    return {"id": i, "fingerprint": fp, "contentHash": ch, "message": msg, "severity": sev, "category": "c", "suppressed": sup, "confidence": 0.7, "detail": ch}
def doc(findings, host="h", gen="2026-01-01T00:00:00Z"):
    return {"schemaVersion": "1.8", "host": host, "generated": gen, "findings": findings}
d = tempfile.mkdtemp()
def w(name, obj):
    p = os.path.join(d, name); json.dump(obj, open(p, "w")); return p
def run(tool, *a):
    return subprocess.run([sys.executable, "-I", tool] + list(a), capture_output=True, text=True)
def entry(fp, verdict, ch="", note=""):
    e = {"fingerprint": fp, "verdict": verdict, "note": note}
    if ch: e["contentHash"] = ch
    return e

print("V1  apply groups findings by verdict")
scan = w("scan.json", doc([f(A, H1, "good one", i="1"), f(B, H1, "bad one", i="2"), f(C, H1, "stale one", i="3"),
                           f(D, H1, "nobody looked", i="4"), f("e" * 16, H1, "sus", i="5"), f("f" * 16, H1, "hidden", sup=True, i="6")]))
rv = w("rev.json", {"schemaVersion": "1", "reviewed": [entry(A, "good", H1, "my own tool"), entry(B, "bad"), entry(C, "good", H2),
                                                         entry("e" * 16, "suspicious")]})
r = run(REV, "apply", scan, "--reviews", rv, "--json")
j = json.loads(r.stdout)
check("counts", j["counts"] == {"bad": 1, "suspicious": 1, "stale": 1, "unreviewed": 1, "good": 1}, j.get("counts"))
check("the good list is omitted without --all", "good" not in j)
check("stale = good review of an older contentHash", j["stale"][0]["finding"]["id"] == "3")
check("suppressed findings are ignored by default", all(x["finding"]["id"] != "6" for k in ("bad", "suspicious", "stale", "unreviewed") for x in j[k]))
r = run(REV, "apply", scan, "--reviews", rv, "--all", "--json")
j = json.loads(r.stdout)
check("--all lists good and suppressed ones", j["counts"]["good"] == 1 and j["counts"]["unreviewed"] == 2, j["counts"])
r = run(REV, "apply", scan, "--reviews", rv)
check("text shows the note and the reviewer", "bad 1 | suspicious 1 | stale 1 | unreviewed 1 | good 1" in r.stdout and r.returncode == 0, r.stdout)
check("--fail-on-bad exits 2", run(REV, "apply", scan, "--reviews", rv, "--fail-on-bad").returncode == 2)
check("--fail-on-unreviewed exits 2 (stale and unreviewed count)", run(REV, "apply", scan, "--reviews", rv, "--fail-on-unreviewed").returncode == 2)
clean = w("clean.json", doc([f(A, H1)]))
check("--fail-on-unreviewed exits 0 when all is reviewed", run(REV, "apply", clean, "--reviews", rv, "--fail-on-unreviewed").returncode == 0)

print("V2  add writes an atomic, sorted, valid file")
rp = os.path.join(d, "new-reviews.json")
r = run(REV, "add", rp, "--scan", scan, "--id", "2", "--verdict", "bad", "--note", "x\x1b[31mred‮", "--reviewer", "T", "--date", "2026-11-18")
saved = json.load(open(rp))
e = saved["reviewed"][0]
check("add --scan stores fingerprint, contentHash and a label", r.returncode == 0 and e["fingerprint"] == B and e["contentHash"] == H1 and e["message"] == "bad one", r.stderr)
check("control and bidi characters are stripped from the note", "\x1b" not in e["note"] and "‮" not in e["note"], e["note"])
r = run(REV, "add", rp, "--fingerprint", A.upper(), "--verdict", "good", "--date", "2026-11-18")
check("add --fingerprint accepts upper case, keeps the file sorted", [x["fingerprint"] for x in json.load(open(rp))["reviewed"]] == [A, B], r.stderr)
r = run(REV, "add", rp, "--fingerprint", A, "--verdict", "suspicious")
saved = json.load(open(rp))["reviewed"]
check("add on an existing fingerprint updates it in place", r.stdout.startswith("updated") and len(saved) == 2 and saved[0]["verdict"] == "suspicious")
check("no temp file is left behind", [n for n in os.listdir(d) if n.startswith(".reviews-")] == [])
check("an unknown verdict is refused", run(REV, "add", rp, "--fingerprint", A, "--verdict", "fine").returncode != 0)
check("a short fingerprint is refused", run(REV, "add", rp, "--fingerprint", "abc", "--verdict", "good").returncode == 1)
check("--scan without --id is refused", run(REV, "add", rp, "--scan", scan, "--verdict", "good").returncode == 1)
check("an unknown --id is refused", run(REV, "add", rp, "--scan", scan, "--id", "nope", "--verdict", "good").returncode == 1)

print("V3  malformed review files fail loudly")
for name, obj in (("dup", {"reviewed": [entry(A, "good"), entry(A, "bad")]}), ("noverdict", {"reviewed": [{"fingerprint": A}]}),
                  ("badfp", {"reviewed": [entry("zz", "good")]}), ("badch", {"reviewed": [entry(A, "good", "nothex")]}),
                  ("shape", {"reviewed": {"a": 1}})):
    r = run(REV, "apply", scan, "--reviews", w(name + ".json", obj))
    check("%s is refused with exit 1" % name, r.returncode == 1 and r.stderr.startswith("tatar-review:"), r.stderr)
check("a missing file is exit 1", run(REV, "apply", scan, "--reviews", os.path.join(d, "none.json")).returncode == 1)
check("a pre-1.7 scan is exit 1", run(REV, "apply", w("old.json", {"findings": [{"message": "x"}]}), "--reviews", rv).returncode == 1)

print("V4  tatar-diff --reviews")
before = w("b.json", doc([]))
after = w("a.json", doc([f(A, H1, "mine", i="1"), f(B, H1, "evil", i="2"), f(D, H1, "unknown", i="3"), f(C, H1, "changed since review", i="4")]))
r = run(DIFF, before, after, "--reviews", rv, "--json")
j = json.loads(r.stdout)
check("good is hidden from new and counted", j["counts"]["new"] == 3 and j["counts"]["reviewedGood"] == 1, j["counts"])
check("verdicts are attached to what remains", {x["fingerprint"]: x["verdict"] for x in j["new"]} == {B: "bad", D: "unreviewed", C: "stale"})
r = run(DIFF, before, after, "--reviews", rv)
check("text output tags bad and stale, not unreviewed", "{bad}" in r.stdout and "{stale}" in r.stdout and "{unreviewed}" not in r.stdout and "reviewed good 1 (hidden)" in r.stdout, r.stdout)
only_good = w("og.json", doc([f(A, H1)]))
check("--fail-on-new ignores a finding reviewed as good", run(DIFF, before, only_good, "--reviews", rv, "--fail-on-new").returncode == 0)
check("--fail-on-new still fires without --reviews", run(DIFF, before, only_good, "--fail-on-new").returncode == 2)
chg_before = w("cb.json", doc([f(A, H2)])); chg_after = w("ca.json", doc([f(A, H1)]))
j = json.loads(run(DIFF, chg_before, chg_after, "--reviews", rv, "--json").stdout)
check("a changed finding whose new content was reviewed good is hidden", j["counts"]["changed"] == 0 and j["counts"]["reviewedGood"] == 1, j["counts"])
check("a bad --reviews file stops the diff with exit 1", run(DIFF, before, after, "--reviews", w("bad.json", {"reviewed": [{}]})).returncode == 1)

print("V5  tatar-aggregate --reviews")
h1 = os.path.join(d, "h1"); h2 = os.path.join(d, "h2"); os.makedirs(h1); os.makedirs(h2)
json.dump(doc([f(A, H1, "mine"), f(B, H1, "evil")], "h1"), open(os.path.join(h1, "findings.json"), "w"))
json.dump(doc([f(A, H1, "mine"), f(D, H1, "odd")], "h2"), open(os.path.join(h2, "findings.json"), "w"))
r = run(AGG, h1, h2, "--format", "json", "--reviews", rv)
j = json.loads(r.stdout)
check("good is dropped, the rest carries a verdict", {x["key"]: x["verdict"] for x in j["items"]} == {B: "bad", D: "unreviewed"}, j)
j = json.loads(run(AGG, h1, h2, "--format", "json", "--reviews", rv, "--all").stdout)
check("--all keeps the good one", any(x["key"] == A and x["verdict"] == "good" for x in j["items"]))
r = run(AGG, h1, h2, "--format", "csv", "--reviews", rv)
check("csv gains a verdict column only with --reviews", r.stdout.splitlines()[0].endswith(",verdict") and "verdict" not in run(AGG, h1, h2, "--format", "csv").stdout.splitlines()[0])
check("a bad --reviews file stops the stack with exit 1", run(AGG, h1, h2, "--reviews", w("bad2.json", {"reviewed": [{}]})).returncode == 1)
print("RESULT  passed: %d  failed: %d" % (ok, bad))
sys.exit(1 if bad else 0)
