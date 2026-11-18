#!/usr/bin/env python3
"""tatar-siem - turn TATAR findings into ECS-style NDJSON for a SIEM.

    python3 tools/tatar-siem.py PATH [PATH ...] [-o FILE] [--bulk INDEX] [--all]
                                [--reviews reviewed.json]

Each PATH is an evidence folder, a findings.json / summary.json, or a folder
holding many evidence folders. One JSON object per line, one line per finding:
  @timestamp   the finding's collected_at (UTC); the scan's `generated` when the
               finding has none. A time that is not UTC ("...Z") is never guessed:
               that finding is skipped and counted on stderr.
  event.*      kind "alert", dataset tatar.finding, id = finding id,
               severity High = 70, Review = 40 (source-specific, as ECS allows)
  host.*       name, os (from summary.json when it sits next to findings.json)
  threat.*     MITRE ATT&CK framework and technique ids
  file.path    the paths the finding names
  tatar.*      everything else (fingerprint, contentHash, confidence, artifactClass,
               module, category, detail, recommendation, evidence, suppressed, iocMatch)
  tatar.review verdict/note/reviewer/date when --reviews is given
Suppressed (allowlisted) findings are left out unless --all is given; with --reviews,
findings reviewed as good are left out too unless --all (a stale review does not count).
--bulk INDEX writes the Elasticsearch bulk format (an action line before each document,
with the fingerprint and host as _id so re-importing a scan does not duplicate it).
Output is pure ASCII JSON (control and bidi characters arrive escaped). Read-only,
offline, standard library only.
Exit code: 0 = done, 1 = nothing readable or nothing written, 2 = some findings skipped.
"""
import argparse, json, os, re, sys

UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
SEV = {"High": 70, "Review": 40}


def reviews_module():
    """tatar-review.py next to this file (the hyphen in its name rules out a plain import)."""
    import importlib.util
    sys.dont_write_bytecode = True  # a pyc next to the tools would dirty the checkout
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tatar-review.py")
    spec = importlib.util.spec_from_file_location("tatar_review", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scans(paths):
    """yield (findings.json path, summary.json path or None)"""
    for p in paths:
        if os.path.isfile(p):
            yield p, (p if os.path.basename(p) == "summary.json" else None)
            continue
        for root, dirs, files in os.walk(p):
            dirs.sort()
            for n in ("findings.json", "summary.json"):
                if n in files:
                    yield os.path.join(root, n), (os.path.join(root, "summary.json") if "summary.json" in files else None)
                    dirs[:] = []
                    break


def read(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def event(f, doc, meta, rev_info, rv):
    ts = f.get("collected_at") or doc.get("generated") or ""
    if not UTC.match(ts):
        ts = doc.get("generated") or ""
        if not UTC.match(ts):
            return None
    host = {"name": doc.get("host") or meta.get("host") or ""}
    if meta.get("os"):
        host["os"] = {"full": " ".join(x for x in (meta.get("os"), meta.get("osVersion")) if x), "type": doc.get("platform") or meta.get("platform") or ""}
    e = {
        "@timestamp": ts,
        "message": f.get("message", ""),
        "event": {"kind": "alert", "category": ["host"], "type": ["info"], "dataset": "tatar.finding",
                  "module": "tatar", "id": f.get("id", ""), "severity": SEV.get(f.get("severity"), 40)},
        "host": host,
        "agent": {"type": "tatar", "name": "TATAR Triage Toolkit", "version": meta.get("version", "")},
        "rule": {"name": f.get("category", ""), "category": f.get("artifactClass", "")},
        "tatar": {"id": f.get("id", ""), "severity": f.get("severity", ""), "category": f.get("category", ""),
                  "module": f.get("module", ""), "artifactClass": f.get("artifactClass", ""),
                  "fingerprint": f.get("fingerprint", ""), "contentHash": f.get("contentHash", ""),
                  "confidence": f.get("confidence"), "confidenceReason": f.get("confidenceReason", ""),
                  "detail": f.get("detail", ""), "recommendation": f.get("recommendation", ""),
                  "evidence": f.get("evidence", []), "suppressed": bool(f.get("suppressed")),
                  "suppressReason": f.get("suppressReason", ""), "iocMatch": bool(f.get("iocMatch")),
                  "caseId": doc.get("caseId", "")},
    }
    if f.get("iocMatch") and f.get("iocIndicator"):
        e["tatar"]["iocIndicator"] = f["iocIndicator"]
    tech = [t for t in (f.get("technique") or []) if isinstance(t, str)]
    if tech:
        e["threat"] = {"framework": "MITRE ATT&CK", "technique": {"id": tech}}
    paths = [p for p in (f.get("paths") or []) if isinstance(p, str)]
    if paths:
        e["file"] = {"path": paths}
    if rev_info is not None:
        v, entry = rev_info
        e["tatar"]["review"] = {"verdict": v}
        if entry:
            for k in ("note", "reviewer", "date"):
                if entry.get(k):
                    e["tatar"]["review"][k] = entry[k]
    return e


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert TATAR findings to ECS-style NDJSON.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument("--bulk", metavar="INDEX", help="Elasticsearch bulk format with this index name")
    ap.add_argument("--all", action="store_true", help="include suppressed findings (and good ones with --reviews)")
    ap.add_argument("--reviews", help="reviewed.json: add tatar.review, leave out findings reviewed as good")
    o = ap.parse_args(argv)
    rv = rev = None
    if o.reviews:
        try:
            rv = reviews_module(); rev = rv.load_reviews(o.reviews)
        except (OSError, ValueError) as e:
            print("tatar-siem: %s" % e, file=sys.stderr); return 1
    if o.bulk and not re.match(r"^[a-z0-9][a-z0-9._-]{0,127}$", o.bulk):
        print("tatar-siem: --bulk INDEX must be lower-case letters, digits, dot, dash or underscore", file=sys.stderr); return 1
    lines, skipped, seen = [], 0, set()
    for fpath, spath in scans(o.paths):
        try:
            doc = read(fpath)
            if not isinstance(doc.get("findings"), list):
                raise ValueError("no findings[] array")
            meta = read(spath) if spath and spath != fpath else doc
        except (OSError, ValueError) as e:
            print("skipped %s: %s" % (fpath, e), file=sys.stderr); skipped += 1; continue
        key = os.path.realpath(fpath)
        if key in seen:
            continue
        seen.add(key)
        for f in doc["findings"]:
            if not isinstance(f, dict):
                continue
            if f.get("suppressed") and not o.all:
                continue
            info = rv.verdict_of(f, rev) if rev is not None and f.get("fingerprint") else (("unreviewed", None) if rev is not None else None)
            if info and info[0] == "good" and not o.all:
                continue
            e = event(f, doc, meta if isinstance(meta, dict) else {}, info, rv)
            if e is None:
                print("skipped finding %s of %s: no UTC timestamp (not guessing a time zone)" % (f.get("id", "?"), fpath), file=sys.stderr)
                skipped += 1; continue
            if o.bulk:
                _id = "%s-%s" % (e["host"]["name"], f.get("fingerprint") or f.get("id", ""))
                lines.append(json.dumps({"index": {"_index": o.bulk, "_id": _id}}))
            lines.append(json.dumps(e, ensure_ascii=True, separators=(",", ":")))
    if not lines:
        print("tatar-siem: nothing to write", file=sys.stderr); return 1
    text = "\n".join(lines) + "\n"
    if o.output:
        with open(o.output, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 2 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
