#!/usr/bin/env python3
"""tatar-timeline - one time-ordered view of a TATAR evidence folder.

    python3 tools/tatar-timeline.py EVIDENCE_DIR [--out FILE] [--format timesketch|jsonl]
                                    [--since ISO] [--until ISO]

Merges timeline.csv (file and process activity, either edition) with the
findings of the same run (their collected_at time) into a single UTC-ordered
list. The default CSV has the columns Timesketch imports directly
(message, datetime, timestamp_desc, data_type) plus source and host.
Cells that start with = + - @ are prefixed with an apostrophe so a spreadsheet
never runs them. Rows whose time cannot be read are counted on stderr, not
guessed. Read-only, offline, standard library only.
Exit code: 0 = done, 1 = unreadable input.
"""
import argparse, csv, json, os, re, sys
from datetime import datetime, timezone


def parse_time(s):
    s = (s or "").strip()
    if not s:
        return None
    s = re.sub(r"\s+(?=[+-]\d\d:?\d\d$)", "", s)
    s = re.sub(r"Z$", "+00:00", s)
    s = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", s)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        d = datetime.fromisoformat(s.replace(" ", "T", 1) if " " in s and "T" not in s else s)
    except ValueError:
        return None
    if d.tzinfo is None:
        return None  # a time with no zone is ambiguous: do not guess
    return d.astimezone(timezone.utc)


def safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def find_dir(p):
    if os.path.isfile(os.path.join(p, "findings.json")) or os.path.isfile(os.path.join(p, "timeline.csv")):
        return p
    for d in sorted(os.listdir(p)):
        c = os.path.join(p, d)
        if os.path.isdir(c) and (os.path.isfile(os.path.join(c, "findings.json")) or os.path.isfile(os.path.join(c, "timeline.csv"))):
            return c
    raise OSError("no evidence folder found in %s" % p)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Unified timeline for a TATAR evidence folder.")
    ap.add_argument("evidence")
    ap.add_argument("--out"); ap.add_argument("--format", choices=("timesketch", "jsonl"), default="timesketch")
    ap.add_argument("--since"); ap.add_argument("--until")
    o = ap.parse_args(argv)
    try:
        d = find_dir(o.evidence)
    except OSError as e:
        print("tatar-timeline: %s" % e, file=sys.stderr); return 1
    host = ""; rows = []; skipped = 0
    fj = os.path.join(d, "findings.json")
    if os.path.isfile(fj):
        try:
            doc = json.load(open(fj, encoding="utf-8-sig"))
        except (OSError, ValueError) as e:
            print("tatar-timeline: findings.json: %s" % e, file=sys.stderr); return 1
        host = doc.get("host", "")
        for f in doc.get("findings", []):
            t = parse_time(f.get("collected_at"))
            if t is None:
                skipped += 1; continue
            flag = "suppressed" if f.get("suppressed") else "finding"
            rows.append((t, "[%s] (%s) %s" % (f.get("severity", "?"), f.get("category", "?"), f.get("message", "")),
                         "Finding raised", flag, f.get("module", ""), f.get("fingerprint", "")))
    tl = os.path.join(d, "timeline.csv")
    if os.path.isfile(tl):
        with open(tl, encoding="utf-8-sig", newline="") as fh:
            for r in csv.DictReader(fh):
                if "MTime" in r:
                    t, src, msg = parse_time(r.get("MTime")), r.get("Source") or "fs", r.get("Path", "")
                    desc = "File modified"
                else:
                    t, src, msg = parse_time(r.get("Time")), r.get("Source", ""), r.get("Detail", "")
                    desc = {"Process": "Process started", "Prefetch": "Prefetch last run", "RecentLnk": "Recent item opened",
                            "AppInstall": "Application installed"}.get(src, "Event")
                if t is None:
                    skipped += 1; continue
                rows.append((t, msg, desc, "timeline", src, ""))
    lo = parse_time(o.since) if o.since else None; hi = parse_time(o.until) if o.until else None
    rows = [r for r in rows if (lo is None or r[0] >= lo) and (hi is None or r[0] <= hi)]
    rows.sort(key=lambda r: (r[0], r[2], r[1]))
    out = open(o.out, "w", encoding="utf-8", newline="") if o.out else sys.stdout
    try:
        if o.format == "jsonl":
            for t, msg, desc, dtype, src, fp in rows:
                out.write(json.dumps({"datetime": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "timestamp_desc": desc, "message": msg,
                                      "data_type": dtype, "source": src, "host": host, "fingerprint": fp}, ensure_ascii=False) + "\n")
        else:
            w = csv.writer(out, lineterminator="\n")
            w.writerow(["message", "datetime", "timestamp_desc", "data_type", "source", "host"])
            for t, msg, desc, dtype, src, fp in rows:
                w.writerow([safe(msg), t.strftime("%Y-%m-%dT%H:%M:%SZ"), desc, dtype, safe(src), safe(host)])
    finally:
        if o.out: out.close()
    print("tatar-timeline: %d event(s)%s" % (len(rows), ", %d row(s) skipped (time unreadable or without a zone)" % skipped if skipped else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
