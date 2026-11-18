#!/usr/bin/env python3
"""tatar-siem tests: ECS shape, timestamps, suppression, reviews, bulk format, escaping,
exit codes. Fixture-free."""
import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
SIEM = os.path.join(HERE, "..", "tools", "tatar-siem.py")
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok   " + name)
    else: bad += 1; print("  FAIL %s %s" % (name, extra))
A, B = "a" * 16, "b" * 16
def f(fp, i, msg="m", sev="High", sup=False, ts="2026-11-18T10:00:00Z", **kw):
    d = {"id": i, "fingerprint": fp, "contentHash": "1" * 16, "message": msg, "severity": sev, "category": "persistence",
         "technique": ["T1053.003"], "detail": "d", "confidence": 0.7, "confidenceReason": "why", "suppressed": sup,
         "suppressReason": "", "iocMatch": False, "module": "persistence", "artifactClass": "cron", "paths": ["/etc/cron.d/x"],
         "evidence": [{"file": "r.txt", "section": "11 Persistence"}], "recommendation": "do this"}
    if ts: d["collected_at"] = ts
    d.update(kw); return d
d = tempfile.mkdtemp()
def scan(name, findings, host="h1", generated="2026-11-18T11:00:00Z", summary=True):
    p = os.path.join(d, name); os.makedirs(p)
    json.dump({"tool": "TATAR Triage Toolkit", "schemaVersion": "1.8", "platform": "linux", "host": host, "caseId": "C1",
               "generated": generated, "findings": findings}, open(os.path.join(p, "findings.json"), "w"))
    if summary:
        json.dump({"version": "1.10.0", "os": "Kali GNU/Linux Rolling", "osVersion": "6.19", "host": host, "findings": findings}, open(os.path.join(p, "summary.json"), "w"))
    return p
def run(*a):
    return subprocess.run([sys.executable, "-I", SIEM] + list(a), capture_output=True, text=True)
def docs(r): return [json.loads(x) for x in r.stdout.splitlines()]

print("S1  ECS shape")
p = scan("s1", [f(A, "TTR-F-001"), f(B, "TTR-F-002", sev="Review", sup=True)])
r = run(p)
ev = docs(r)
check("one line per active finding, exit 0", r.returncode == 0 and len(ev) == 1, r.stderr)
e = ev[0]
check("@timestamp is the finding's collected_at", e["@timestamp"] == "2026-11-18T10:00:00Z")
check("event fields", e["event"]["kind"] == "alert" and e["event"]["id"] == "TTR-F-001" and e["event"]["severity"] == 70 and e["event"]["dataset"] == "tatar.finding")
check("host name and os come from summary.json", e["host"]["name"] == "h1" and e["host"]["os"]["full"] == "Kali GNU/Linux Rolling 6.19", e["host"])
check("agent version comes from summary.json", e["agent"]["version"] == "1.10.0")
check("ATT&CK and file path", e["threat"]["technique"]["id"] == ["T1053.003"] and e["file"]["path"] == ["/etc/cron.d/x"] and e["threat"]["framework"] == "MITRE ATT&CK")
check("tatar namespace carries identity and the recommendation", e["tatar"]["fingerprint"] == A and e["tatar"]["recommendation"] == "do this" and e["tatar"]["caseId"] == "C1")
check("severity Review maps to 40", docs(run(p, "--all"))[1]["event"]["severity"] == 40)
check("--all includes suppressed ones, flagged", docs(run(p, "--all"))[1]["tatar"]["suppressed"] is True)
check("a bare findings.json file works (no summary)", len(docs(run(os.path.join(scan("s1b", [f(A, "1")], summary=False), "findings.json")))) == 1)

print("S2  timestamps")
p = scan("s2", [f(A, "1", ts=""), f(B, "2", ts="2026-11-18 10:00:00 +0300")], generated="2026-11-18T11:00:00Z")
ev = docs(run(p))
check("a missing collected_at falls back to the scan time", ev[0]["@timestamp"] == "2026-11-18T11:00:00Z")
check("a zone-ful but non-UTC time falls back too, never guessed", ev[1]["@timestamp"] == "2026-11-18T11:00:00Z")
p = scan("s2b", [f(A, "1", ts="")], generated="2026-11-18 11:00:00")
r = run(p)
check("no UTC time anywhere: skipped, nothing written, exit 1", r.returncode == 1 and "not guessing" in r.stderr, r.stderr)
p = scan("s2c", [f(A, "1"), f(B, "2", ts="")], generated="local time")
r = run(p)
check("some skipped: the rest is written and the exit code is 2", r.returncode == 2 and len(docs(r)) == 1)

print("S3  reviews")
rv = os.path.join(d, "rev.json")
json.dump({"reviewed": [{"fingerprint": A, "verdict": "good", "note": "mine"}, {"fingerprint": B, "verdict": "bad", "note": "evil", "reviewer": "T"}]}, open(rv, "w"))
p = scan("s3", [f(A, "1"), f(B, "2"), f("c" * 16, "3")])
ev = docs(run(p, "--reviews", rv))
check("good is dropped, bad and unreviewed carry a verdict", [x["tatar"]["review"]["verdict"] for x in ev] == ["bad", "unreviewed"], ev)
check("note and reviewer travel with a bad verdict", ev[0]["tatar"]["review"]["note"] == "evil" and ev[0]["tatar"]["review"]["reviewer"] == "T")
check("--all keeps the good one", len(docs(run(p, "--reviews", rv, "--all"))) == 3)
check("without --reviews there is no review object", "review" not in docs(run(p))[0]["tatar"])
bad_rv = os.path.join(d, "bad.json"); json.dump({"reviewed": [{}]}, open(bad_rv, "w"))
check("a bad reviews file is exit 1", run(p, "--reviews", bad_rv).returncode == 1)

print("S4  bulk, escaping, folders")
r = run(p, "--bulk", "tatar-findings")
lines = r.stdout.splitlines()
check("bulk: an action line before each document", len(lines) == 6 and json.loads(lines[0]) == {"index": {"_index": "tatar-findings", "_id": "h1-" + A}}, lines[:1])
check("bulk: an upper-case or odd index name is refused", run(p, "--bulk", "Bad Index").returncode == 1)
p2 = scan("s4", [f(A, "1", msg="x\x1b[31m‮evil", paths=["/tmp/\u0085z"])])
r = run(p2)
check("output is pure ASCII with control and bidi characters escaped", r.stdout.isascii() and "\x1b" not in r.stdout and "‮" not in r.stdout and json.loads(r.stdout)["message"].startswith("x\x1b"))
r = run(d)
check("a folder of folders is walked, each scan once", r.returncode in (0, 2) and len(docs(r)) >= 6)
out = os.path.join(d, "out.ndjson")
r = run(p, "-o", out)
check("-o writes a file and prints nothing", r.stdout == "" and len(open(out).read().splitlines()) == 3)
check("a missing path is exit 1", run(os.path.join(d, "nope")).returncode == 1)
print("RESULT  passed: %d  failed: %d" % (ok, bad))
sys.exit(1 if bad else 0)
