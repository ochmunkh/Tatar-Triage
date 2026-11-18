#!/usr/bin/env python3
"""tatar-aggregate - stack the findings of many hosts to see what is rare.

    python3 tools/tatar-aggregate.py PATH [PATH ...] [--by fingerprint|path]
                                     [--format text|csv|json] [--max-hosts N] [--all]

Each PATH is an evidence folder, a findings.json / summary.json, or a folder
that holds many evidence folders (one per host). Findings are stacked by
`fingerprint` (schema 1.7) or by each path they name; the fewer hosts carry an
item, the earlier it is listed - the standard way to find the one machine that
differs. A host that was scanned twice counts once (its newest scan wins).
Suppressed findings are ignored unless --all is given.
Read-only, offline, standard library only. Exit code: 0 = done, 1 = nothing readable.
"""
import argparse, csv, json, os, sys
from collections import defaultdict


def candidates(p):
    if os.path.isfile(p):
        yield p; return
    if not os.path.isdir(p):
        return
    for n in ("findings.json", "summary.json"):
        if os.path.isfile(os.path.join(p, n)):
            yield os.path.join(p, n); return
    for root, dirs, files in os.walk(p):
        dirs.sort()
        for n in ("findings.json", "summary.json"):
            if n in files:
                yield os.path.join(root, n); dirs[:] = []; break


def load_all(paths, need_fp):
    hosts = {}; skipped = []
    for p in paths:
        for c in candidates(p):
            try:
                doc = json.load(open(c, encoding="utf-8-sig"))
                fl = doc["findings"]
                if not isinstance(fl, list):
                    raise ValueError("no findings[]")
                if need_fp and any("fingerprint" not in f for f in fl):
                    raise ValueError("no fingerprint (schema 1.7 needed)")
            except (OSError, ValueError, KeyError) as e:
                skipped.append("%s: %s" % (c, e)); continue
            host = doc.get("host") or os.path.basename(os.path.dirname(c))
            gen = doc.get("generated", "")
            if host not in hosts or gen >= hosts[host][0]:
                hosts[host] = (gen, fl)
    return hosts, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stack TATAR findings across hosts.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--by", choices=("fingerprint", "path"), default="fingerprint")
    ap.add_argument("--format", choices=("text", "csv", "json"), default="text")
    ap.add_argument("--max-hosts", type=int, help="only items carried by at most N hosts")
    ap.add_argument("--all", action="store_true", help="include suppressed findings")
    o = ap.parse_args(argv)
    hosts, skipped = load_all(o.paths, o.by == "fingerprint")
    for s in skipped:
        print("skipped " + s, file=sys.stderr)
    if not hosts:
        print("tatar-aggregate: nothing readable", file=sys.stderr); return 1
    stack = defaultdict(lambda: {"hosts": set(), "sev": set(), "label": ""})
    for host, (_, fl) in hosts.items():
        for f in fl:
            if f.get("suppressed") and not o.all:
                continue
            keys = [f["fingerprint"]] if o.by == "fingerprint" else list(dict.fromkeys(f.get("paths") or []))
            for k in keys:
                e = stack[k]; e["hosts"].add(host); e["sev"].add(f.get("severity", "?"))
                if not e["label"]:
                    e["label"] = f.get("message", "") if o.by == "fingerprint" else "%s: %s" % (f.get("category", "?"), f.get("message", ""))
    n = len(hosts)
    items = sorted(stack.items(), key=lambda kv: (len(kv[1]["hosts"]), kv[0]))
    if o.max_hosts is not None:
        items = [kv for kv in items if len(kv[1]["hosts"]) <= o.max_hosts]
    rows = [{"key": k, "hosts": len(e["hosts"]), "of": n, "severity": "High" if "High" in e["sev"] else sorted(e["sev"])[0],
             "hostList": sorted(e["hosts"]), "example": e["label"]} for k, e in items]
    if o.format == "json":
        print(json.dumps({"hosts": sorted(hosts), "by": o.by, "items": rows}, indent=2, ensure_ascii=False))
    elif o.format == "csv":
        w = csv.writer(sys.stdout, lineterminator="\n")
        w.writerow(["key", "hosts", "of", "severity", "hostList", "example"])
        for r in rows:
            sf = lambda v: ("'" + v) if v[:1] in ("=", "+", "-", "@") else v
            w.writerow([sf(r["key"]), r["hosts"], r["of"], r["severity"], sf(";".join(r["hostList"])), sf(r["example"])])
    else:
        print("TATAR stack  %d host(s), by %s - rarest first" % (n, o.by))
        for r in rows:
            who = ",".join(r["hostList"]) if r["hosts"] <= 3 else "%d hosts" % r["hosts"]
            print("  %d/%d  [%s]  %s  (%s)\n        %s" % (r["hosts"], n, r["severity"], r["key"], who, r["example"][:110]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
