#!/usr/bin/env python3
"""tatar-timeline tests on a synthetic evidence folder (both timeline formats)."""
import csv, io, json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "tatar-timeline.py")
ok = bad = 0
def check(n, c, x=""):
    global ok, bad
    if c: ok += 1; print("  ok   " + n)
    else: bad += 1; print("  FAIL %s %s" % (n, x))
def run(d, *a):
    return subprocess.run([sys.executable, "-I", TOOL, d] + list(a), capture_output=True, text=True)
def mk(files):
    d = tempfile.mkdtemp()
    for k, v in files.items(): open(os.path.join(d, k), "w", encoding="utf-8").write(v)
    return d
fj = json.dumps({"host": "H1", "findings": [
    {"severity": "High", "category": "c", "message": "=cmd|' /C calc'!A0", "collected_at": "2026-05-01T10:00:00Z", "module": "process", "fingerprint": "ab", "suppressed": False}]})
win = "Time,Source,Detail\n2026-05-01T08:00:00Z,Process,=evil\n2026-05-01T09:00:00Z,Process,cmd.exe (PID 4)\n2026-05-01T11:00:00Z,Prefetch,A.pf\nnot a time,Process,x\n"
d = mk({"findings.json": fj, "timeline.csv": win})
r = run(d)
rows = list(csv.DictReader(io.StringIO(r.stdout)))
check("windows timeline + finding merged in time order", [x["datetime"] for x in rows] == ["2026-05-01T08:00:00Z", "2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z", "2026-05-01T11:00:00Z"], rows)
check("a formula-looking message is neutralised", rows[0]["message"] == "'=evil")
check("an unreadable time is counted, not guessed", "1 row(s) skipped" in r.stderr, r.stderr)
check("Timesketch columns present", list(rows[0].keys())[:4] == ["message", "datetime", "timestamp_desc", "data_type"])
lin = 'MTime,Path,Source\n"2026-05-01 12:00:00.123456789 +0300","/tmp/x","fs"\n'
d = mk({"findings.json": fj, "timeline.csv": lin})
r = run(d, "--format", "jsonl")
j = [json.loads(l) for l in r.stdout.splitlines()]
check("linux local time with offset is converted to UTC", j[0]["datetime"] == "2026-05-01T09:00:00Z", j)
r = run(d, "--since", "2026-05-01T09:30:00Z")
check("--since filters", len(list(csv.DictReader(io.StringIO(r.stdout)))) == 1)
r = run(tempfile.mkdtemp())
check("an empty folder is refused with exit 1", r.returncode == 1)
print("RESULT  passed: %d  failed: %d" % (ok, bad))
sys.exit(1 if bad else 0)
