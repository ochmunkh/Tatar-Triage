#!/usr/bin/env python3
"""tatar-navigator - turn the ATT&CK technique ids of TATAR findings into a layer
for the MITRE ATT&CK Navigator.

    python3 tools/tatar-navigator.py PATH [PATH ...] [-o layer.json] [--name NAME]
                                     [--all] [--reviews reviewed.json]

Each PATH is an evidence folder, a findings.json / summary.json, or a folder
holding many evidence folders. Every technique id named by a finding becomes one
cell: score 100 when any finding for it is High, 50 when all are Review; the
comment says how many findings and which categories. Suppressed (allowlisted)
findings are left out unless --all. With --reviews, findings reviewed as good are
left out too (a stale review does not count) and bad ones are marked in the comment.
The layer shows what the scan POINTS AT, not what was proven: a finding is a lead.
Ids that are not of the form T1234 or T1234.567 are ignored and counted on stderr.
Output is pure ASCII JSON. Read-only, offline, standard library only.
Exit code: 0 = done, 1 = nothing readable or no technique found, 2 = some input skipped.
"""
import argparse, json, os, re, sys

TID = re.compile(r"^T\d{4}(\.\d{3})?$")
SCORE = {"High": 100, "Review": 50}


def reviews_module():
    import importlib.util
    sys.dont_write_bytecode = True
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tatar-review.py")
    spec = importlib.util.spec_from_file_location("tatar_review", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scans(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs.sort()
            for n in ("findings.json", "summary.json"):
                if n in files:
                    yield os.path.join(root, n)
                    dirs[:] = []
                    break


def clean(s, n=60):
    s = re.sub(r"[^\x20-\x7e]", "?", str(s))
    return s[:n]


def build(cells, name):
    techniques = []
    for tid in sorted(cells):
        c = cells[tid]
        cats = ", ".join(sorted(c["cats"])[:6])
        more = " +%d" % (len(c["cats"]) - 6) if len(c["cats"]) > 6 else ""
        comment = "%d finding(s): %s%s" % (c["n"], cats, more)
        if c["bad"]:
            comment += "; %d reviewed as bad" % c["bad"]
        techniques.append({"techniqueID": tid, "score": c["score"], "comment": comment})
    return {
        "name": clean(name, 80),
        "versions": {"layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques named by TATAR Triage findings. These are leads, not confirmed activity.",
        "sorting": 3,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Review", "color": "#ffe766"}, {"label": "High", "color": "#ff6666"}],
        "techniques": techniques,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build an ATT&CK Navigator layer from TATAR findings.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument("--name", default="TATAR findings", help="layer name")
    ap.add_argument("--all", action="store_true", help="include suppressed findings (and good ones with --reviews)")
    ap.add_argument("--reviews", help="reviewed.json: leave out findings reviewed as good")
    o = ap.parse_args(argv)
    rv = rev = None
    if o.reviews:
        try:
            rv = reviews_module(); rev = rv.load_reviews(o.reviews)
        except (OSError, ValueError) as e:
            print("tatar-navigator: %s" % e, file=sys.stderr); return 1
    cells, skipped, ignored, seen, read_ok = {}, 0, 0, set(), 0
    for fpath in scans(o.paths):
        key = os.path.realpath(fpath)
        if key in seen:
            continue
        seen.add(key)
        try:
            with open(fpath, encoding="utf-8-sig") as fh:
                doc = json.load(fh)
            if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
                raise ValueError("no findings[] array")
        except (OSError, ValueError) as e:
            print("skipped %s: %s" % (fpath, e), file=sys.stderr); skipped += 1; continue
        read_ok += 1
        for f in doc["findings"]:
            if not isinstance(f, dict):
                continue
            if f.get("suppressed") and not o.all:
                continue
            verdict = None
            if rev is not None and f.get("fingerprint"):
                verdict = rv.verdict_of(f, rev)[0]
                if verdict == "good" and not o.all:
                    continue
            tech = f.get("technique") or []
            if not isinstance(tech, list):
                continue
            for t in tech:
                if not isinstance(t, str) or not TID.match(t):
                    ignored += 1; continue
                c = cells.setdefault(t, {"score": 0, "n": 0, "cats": set(), "bad": 0})
                c["score"] = max(c["score"], SCORE.get(f.get("severity"), 50))
                c["n"] += 1
                c["cats"].add(clean(f.get("category", "?"), 24))
                if verdict == "bad":
                    c["bad"] += 1
    if ignored:
        print("ignored %d technique id(s) that are not T1234 or T1234.567" % ignored, file=sys.stderr)
    if not read_ok or not cells:
        print("tatar-navigator: no technique ids found", file=sys.stderr); return 1
    text = json.dumps(build(cells, o.name), ensure_ascii=True, indent=2) + "\n"
    if o.output:
        with open(o.output, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 2 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
