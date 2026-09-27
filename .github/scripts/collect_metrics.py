#!/usr/bin/env python3
"""Snapshot the repository traffic API into CSV.

GitHub keeps only a rolling 14-day window of traffic data, so any day that is
never snapshotted is lost for good. This script is run on a schedule and merges
each fetch into CSVs kept on the orphan `metrics` branch.

Rows are keyed by date and upserted, never appended: consecutive runs overlap by
design (a run every ~10 days re-reads the same days), and the most recent fetch
of a day is the authoritative one, because the current day is always partial.

Reads:  GITHUB_TOKEN, GITHUB_REPOSITORY, METRICS_DIR (default: metrics-data)
Writes: <METRICS_DIR>/traffic.csv, <METRICS_DIR>/releases.csv,
        <METRICS_DIR>/repo.csv
Stdlib only - no pip install step in the workflow.
"""

import csv
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
TRAFFIC_FIELDS = ["date", "clones", "clones_unique", "views", "views_unique"]
RELEASE_FIELDS = ["date", "tag", "asset", "downloads"]
REPO_FIELDS = ["date", "stars", "forks", "watchers", "open_issues"]


def get(path, token):
    req = urllib.request.Request(
        API + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "tatar-triage-metrics",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        if e.code == 403:
            sys.exit(
                "403 on %s. The traffic API needs push rights: the built-in "
                "GITHUB_TOKEN may not be enough - set a METRICS_TOKEN secret "
                "(fine-grained PAT, Administration: read). Body: %s" % (path, body)
            )
        sys.exit("HTTP %d on %s: %s" % (e.code, path, body))


def read_csv(path, fields):
    """Existing rows keyed by their identity columns. Missing file -> empty."""
    if not os.path.exists(path):
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if fields is RELEASE_FIELDS:
        key = lambda r: (r["date"], r["tag"], r["asset"])
    else:
        key = lambda r: r["date"]
    return {key(r): r for r in rows}


def write_csv(path, fields, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    ordered = sorted(rows.values(), key=lambda r: tuple(r[f] for f in fields[:3]))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(ordered)
    return len(ordered)


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    outdir = os.environ.get("METRICS_DIR", "metrics-data")
    if not token or not repo:
        sys.exit("GITHUB_TOKEN and GITHUB_REPOSITORY are required")

    clones = get("/repos/%s/traffic/clones" % repo, token)
    views = get("/repos/%s/traffic/views" % repo, token)

    # Merge both series by day. A day can be present in one and absent in the
    # other, so start from zeros and fill whatever each series reports.
    days = {}
    for series, ccol, ucol in ((clones.get("clones", []), "clones", "clones_unique"),
                               (views.get("views", []), "views", "views_unique")):
        for point in series:
            day = point["timestamp"][:10]
            row = days.setdefault(day, dict.fromkeys(TRAFFIC_FIELDS, "0"))
            row["date"] = day
            row[ccol] = str(point.get("count", 0))
            row[ucol] = str(point.get("uniques", 0))

    traffic_path = os.path.join(outdir, "traffic.csv")
    traffic = read_csv(traffic_path, TRAFFIC_FIELDS)
    fresh = sum(1 for d in days if d not in traffic)
    traffic.update(days)
    total = write_csv(traffic_path, TRAFFIC_FIELDS, traffic)
    print("traffic.csv: %d day(s) fetched, %d new, %d total"
          % (len(days), fresh, total))

    # Release asset downloads are cumulative, so they are snapshotted per run
    # date rather than per day. This is the cleanest signal we have against bot
    # clones: a download is somebody deliberately taking the file.
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rel_path = os.path.join(outdir, "releases.csv")
    releases = read_csv(rel_path, RELEASE_FIELDS)
    grabbed = 0
    for rel in get("/repos/%s/releases?per_page=100" % repo, token):
        for asset in rel.get("assets", []):
            row = {"date": today, "tag": rel.get("tag_name", ""),
                   "asset": asset.get("name", ""),
                   "downloads": str(asset.get("download_count", 0))}
            releases[(row["date"], row["tag"], row["asset"])] = row
            grabbed += 1
    total = write_csv(rel_path, RELEASE_FIELDS, releases)
    print("releases.csv: %d asset(s) snapshotted for %s, %d total"
          % (grabbed, today, total))

    # Stars, forks and watchers need no special rights and, unlike clone counts,
    # are not inflated by crawlers - a bot does not star a repository. They are
    # cumulative, so one row per run date.
    meta = get("/repos/%s" % repo, token)
    repo_path = os.path.join(outdir, "repo.csv")
    repo_rows = read_csv(repo_path, REPO_FIELDS)
    repo_rows[today] = {
        "date": today,
        "stars": str(meta.get("stargazers_count", 0)),
        "forks": str(meta.get("forks_count", 0)),
        "watchers": str(meta.get("subscribers_count", 0)),
        "open_issues": str(meta.get("open_issues_count", 0)),
    }
    total = write_csv(repo_path, REPO_FIELDS, repo_rows)
    print("repo.csv: stars=%s forks=%s watchers=%s, %d row(s) total"
          % (repo_rows[today]["stars"], repo_rows[today]["forks"],
             repo_rows[today]["watchers"], total))


if __name__ == "__main__":
    main()
