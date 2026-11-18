#!/usr/bin/env python3
"""tatar-review - record what an analyst decided about a finding, and apply it.

    python3 tools/tatar-review.py apply SCAN --reviews reviewed.json [--all] [--json]
                                     [--fail-on-bad] [--fail-on-unreviewed]
    python3 tools/tatar-review.py add reviewed.json --scan SCAN --id TTR-F-007
                                     --verdict good|suspicious|bad [--note TEXT]
                                     [--reviewer NAME] [--date YYYY-MM-DD]
    python3 tools/tatar-review.py add reviewed.json --fingerprint HEX16 --verdict ...

A review is keyed by the finding `fingerprint` (schema 1.7), so it carries over
to every later scan of the same host. Verdicts:
  good        looked at it, it is expected (your own software, a known admin tool)
  suspicious  not decided, needs more work
  bad         confirmed hostile or unwanted
  (no entry)  unreviewed - the finding is still a lead nobody has judged
`add --scan` also stores the finding's `contentHash`. If the finding later
changes (severity, confidence or detail) the review is reported as STALE and the
finding counts as unreviewed again, so a "good" never hides a finding that got
worse. Allowlist-suppressed findings are ignored unless --all is given.
reviewed.json is plain JSON you can keep in version control:
    {"schemaVersion": "1", "reviewed": [{"fingerprint": "...", "verdict": "good",
      "note": "...", "reviewer": "...", "date": "2026-11-18", "contentHash": "...",
      "message": "label for humans"}]}
Read-only on scans; `add` writes only the reviews file (atomic replace).
Offline, standard library only.
Exit code: 0 = done, 1 = unreadable input or bad arguments, 2 = a --fail-on-* test hit.
"""
import argparse, datetime, json, os, re, sys, tempfile

VERDICTS = ("good", "suspicious", "bad")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def load_reviews(path):
    """fingerprint -> entry. Raises ValueError on anything malformed (never guesses)."""
    with open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("reviewed"), list):
        raise ValueError("%s: expected an object with a reviewed[] array" % path)
    out = {}
    for i, e in enumerate(doc["reviewed"]):
        if not isinstance(e, dict):
            raise ValueError("%s: reviewed[%d] is not an object" % (path, i))
        fp = e.get("fingerprint")
        if not isinstance(fp, str) or not HEX16.match(fp):
            raise ValueError("%s: reviewed[%d] has no valid fingerprint" % (path, i))
        if e.get("verdict") not in VERDICTS:
            raise ValueError("%s: reviewed[%d] verdict must be one of %s" % (path, i, "/".join(VERDICTS)))
        ch = e.get("contentHash", "")
        if ch and not (isinstance(ch, str) and HEX16.match(ch)):
            raise ValueError("%s: reviewed[%d] has an invalid contentHash" % (path, i))
        if fp in out:
            raise ValueError("%s: fingerprint %s is reviewed twice" % (path, fp))
        out[fp] = e
    return out


def verdict_of(f, reviews):
    """-> (verdict, entry). verdict is good/suspicious/bad, 'stale' or 'unreviewed'."""
    e = reviews.get(f.get("fingerprint", ""))
    if e is None:
        return "unreviewed", None
    if e.get("contentHash") and e["contentHash"] != f.get("contentHash"):
        return "stale", e
    return e["verdict"], e


def load_scan(path):
    p = path
    if os.path.isdir(p):
        for n in ("findings.json", "summary.json"):
            if os.path.isfile(os.path.join(p, n)):
                p = os.path.join(p, n)
                break
        else:
            raise ValueError("%s: no findings.json or summary.json" % path)
    with open(p, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    if not isinstance(doc.get("findings"), list) or any("fingerprint" not in f for f in doc["findings"]):
        raise ValueError("%s: needs findings[] with fingerprints (schema 1.7, collector 1.9.0 or newer)" % path)
    return doc


def clean(s, n):
    return CTRL.sub(" ", str(s))[:n]


def cmd_apply(o):
    doc = load_scan(o.scan)
    reviews = load_reviews(o.reviews)
    buckets = {k: [] for k in ("bad", "suspicious", "stale", "unreviewed", "good")}
    for f in doc["findings"]:
        if f.get("suppressed") and not o.all:
            continue
        v, e = verdict_of(f, reviews)
        buckets[v].append((f, e))
    counts = {k: len(v) for k, v in buckets.items()}
    if o.json:
        out = {"scan": o.scan, "counts": counts}
        for k, v in buckets.items():
            if k != "good" or o.all:
                out[k] = [{"finding": f, "review": e} for f, e in v]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print("TATAR review  host %s  %s" % (doc.get("host", "?"), doc.get("generated", "?")))
        print("bad %(bad)d | suspicious %(suspicious)d | stale %(stale)d | unreviewed %(unreviewed)d | good %(good)d" % counts)
        titles = (("bad", "BAD"), ("suspicious", "SUSPICIOUS"), ("stale", "STALE (finding changed since it was reviewed)"),
                  ("unreviewed", "UNREVIEWED"), ("good", "GOOD (reviewed)"))
        for k, title in titles:
            if not buckets[k] or (k == "good" and not o.all):
                continue
            print("\n" + title)
            for f, e in buckets[k]:
                print("  [%s] (%s) %s  %s" % (f.get("severity", "?"), f.get("category", "?"), clean(f.get("message", ""), 140), f.get("fingerprint")))
                if e and e.get("note"):
                    print("      note: %s%s" % (clean(e["note"], 200), (" - " + clean(e["reviewer"], 60)) if e.get("reviewer") else ""))
    if o.fail_on_bad and counts["bad"]:
        return 2
    if o.fail_on_unreviewed and (counts["unreviewed"] or counts["stale"]):
        return 2
    return 0


def cmd_add(o):
    if bool(o.scan) == bool(o.fingerprint):
        raise ValueError("give either --scan with --id, or --fingerprint")
    ch = o.content_hash or ""
    label = ""
    if o.scan:
        if not o.id:
            raise ValueError("--scan needs --id")
        hit = [f for f in load_scan(o.scan)["findings"] if f.get("id") == o.id]
        if len(hit) != 1:
            raise ValueError("finding %s not found exactly once in %s" % (o.id, o.scan))
        fp, ch, label = hit[0]["fingerprint"], hit[0].get("contentHash", ""), hit[0].get("message", "")
    else:
        fp = o.fingerprint.lower()
    if not HEX16.match(fp):
        raise ValueError("fingerprint must be 16 hex characters")
    if ch and not HEX16.match(ch):
        raise ValueError("content hash must be 16 hex characters")
    if o.date and not re.match(r"^\d{4}-\d{2}-\d{2}$", o.date):
        raise ValueError("--date must be YYYY-MM-DD")
    entry = {"fingerprint": fp, "verdict": o.verdict, "note": clean(o.note or "", 500),
             "reviewer": clean(o.reviewer or "", 80),
             "date": o.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}
    if ch:
        entry["contentHash"] = ch
    if label:
        entry["message"] = clean(label, 200)
    reviews = {}
    if os.path.exists(o.reviews):
        reviews = load_reviews(o.reviews)
    replaced = fp in reviews
    reviews[fp] = entry
    doc = {"schemaVersion": "1", "reviewed": [reviews[k] for k in sorted(reviews)]}
    d = os.path.dirname(os.path.abspath(o.reviews))
    fd, tmp = tempfile.mkstemp(prefix=".reviews-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, o.reviews)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print("%s %s as %s in %s" % ("updated" if replaced else "added", fp, o.verdict, o.reviews))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Record and apply analyst verdicts on TATAR findings.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("apply", help="group a scan's findings by verdict")
    a.add_argument("scan"); a.add_argument("--reviews", required=True)
    a.add_argument("--all", action="store_true", help="also list good ones and allowlist-suppressed findings")
    a.add_argument("--json", action="store_true")
    a.add_argument("--fail-on-bad", action="store_true", help="exit 2 when a finding is reviewed bad")
    a.add_argument("--fail-on-unreviewed", action="store_true", help="exit 2 when a finding is unreviewed or stale")
    d = sub.add_parser("add", help="add or update one review")
    d.add_argument("reviews"); d.add_argument("--scan"); d.add_argument("--id"); d.add_argument("--fingerprint")
    d.add_argument("--content-hash"); d.add_argument("--verdict", required=True, choices=VERDICTS)
    d.add_argument("--note"); d.add_argument("--reviewer"); d.add_argument("--date")
    o = ap.parse_args(argv)
    try:
        return cmd_apply(o) if o.cmd == "apply" else cmd_add(o)
    except (OSError, ValueError) as e:
        print("tatar-review: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
