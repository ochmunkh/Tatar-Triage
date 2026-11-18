#!/usr/bin/env python3
"""tatar-diff - compare two TATAR scans of the same host (schema 1.7).

    python3 tools/tatar-diff.py BEFORE AFTER [--all] [--json] [--fail-on-new]

BEFORE and AFTER are an evidence folder, a summary.json or a findings.json.
Findings are matched by their stable `fingerprint`:
  new        in AFTER only          - what appeared since the baseline
  resolved   in BEFORE only         - what is gone
  changed    in both, contentHash differs (severity, confidence or detail moved)
  unchanged  in both, same contentHash (counted, listed only with --all)
Suppressed (allowlisted) findings are ignored unless --all is given.
Same fingerprint twice in one scan is handled (matched one to one).
Read-only, offline, standard library only.
Exit code: 0 = done, 1 = unreadable input, 2 = --fail-on-new and something is new.
"""
import argparse, json, os, sys
from collections import defaultdict


def load(path):
    p = path
    if os.path.isdir(p):
        for n in ("findings.json", "summary.json"):
            c = os.path.join(p, n)
            if os.path.isfile(c):
                p = c
                break
        else:
            subs = sorted(d for d in os.listdir(p) if os.path.isdir(os.path.join(p, d)))
            for d in subs:
                for n in ("findings.json", "summary.json"):
                    c = os.path.join(p, d, n)
                    if os.path.isfile(c):
                        p = c
                        break
                if p != path:
                    break
    with open(p, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    if not isinstance(doc.get("findings"), list):
        raise ValueError("%s: no findings[] array" % path)
    for f in doc["findings"]:
        if "fingerprint" not in f:
            raise ValueError("%s: findings carry no fingerprint (needs schemaVersion 1.7, collector 1.9.0 or newer)" % path)
    return doc, p


def index(doc, include_suppressed):
    groups = defaultdict(list)
    for f in doc["findings"]:
        if f.get("suppressed") and not include_suppressed:
            continue
        groups[f["fingerprint"]].append(f)
    return groups


def compare(a, b):
    new, resolved, changed, same = [], [], [], []
    for fp in sorted(set(a) | set(b)):
        la = sorted(a.get(fp, []), key=lambda f: f.get("contentHash", ""))
        lb = sorted(b.get(fp, []), key=lambda f: f.get("contentHash", ""))
        # pair identical content first, then the leftovers as changed
        ra, rb = list(la), list(lb)
        for x in list(ra):
            m = next((y for y in rb if y.get("contentHash") == x.get("contentHash")), None)
            if m is not None:
                ra.remove(x); rb.remove(m); same.append(m)
        while ra and rb:
            changed.append((ra.pop(0), rb.pop(0)))
        resolved.extend(ra)
        new.extend(rb)
    return new, resolved, changed, same


def line(f):
    return "[%s] (%s) %s" % (f.get("severity", "?"), f.get("category", "?"), f.get("message", ""))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare two TATAR scans by finding fingerprint.")
    ap.add_argument("before"); ap.add_argument("after")
    ap.add_argument("--all", action="store_true", help="include suppressed findings and list unchanged ones")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on-new", action="store_true", help="exit 2 when something is new")
    o = ap.parse_args(argv)
    try:
        da, pa = load(o.before); db, pb = load(o.after)
    except (OSError, ValueError) as e:
        print("tatar-diff: %s" % e, file=sys.stderr)
        return 1
    new, resolved, changed, same = compare(index(da, o.all), index(db, o.all))
    warn = []
    if da.get("host") != db.get("host"):
        warn.append("the two scans are from different hosts (%s, %s)" % (da.get("host"), db.get("host")))
    if o.json:
        out = {"before": pa, "after": pb, "warnings": warn,
               "counts": {"new": len(new), "resolved": len(resolved), "changed": len(changed), "unchanged": len(same)},
               "new": new, "resolved": resolved,
               "changed": [{"before": x, "after": y} for x, y in changed]}
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print("TATAR diff  %s -> %s" % (da.get("generated", "?"), db.get("generated", "?")))
        for w in warn:
            print("WARNING: " + w)
        print("new %d | resolved %d | changed %d | unchanged %d" % (len(new), len(resolved), len(changed), len(same)))
        for title, items in (("NEW", new), ("RESOLVED", resolved)):
            if items:
                print("\n" + title)
                for f in items:
                    print("  + " if title == "NEW" else "  - ", line(f), sep="")
        if changed:
            print("\nCHANGED")
            for x, y in changed:
                print("  ~ " + line(y))
                if x.get("severity") != y.get("severity"):
                    print("      severity %s -> %s" % (x.get("severity"), y.get("severity")))
                if x.get("confidence") != y.get("confidence"):
                    print("      confidence %s -> %s" % (x.get("confidence"), y.get("confidence")))
                if x.get("detail") != y.get("detail"):
                    print("      detail differs")
        if o.all and same:
            print("\nUNCHANGED")
            for f in same:
                print("    " + line(f))
    return 2 if (o.fail_on_new and new) else 0


if __name__ == "__main__":
    sys.exit(main())
