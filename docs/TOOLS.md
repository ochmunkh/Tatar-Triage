# Analysis tools

Five small command-line tools work on what the collectors write. They are
read-only, offline, use only the Python 3 standard library, and need nothing
installed on the suspect host - run them on the analyst's machine.

| Tool | Question it answers | Needs |
|---|---|---|
| `tools/tatar-diff.py` | What changed on this host since the baseline? | two scans, schema 1.7 |
| `tools/tatar-timeline.py` | What happened, in what order? | one evidence folder |
| `tools/tatar-aggregate.py` | Which host differs from the rest? | many scans, schema 1.7 |
| `tools/tatar-review.py` | What did I already decide about this finding? | a scan, schema 1.7, and a `reviewed.json` you keep |
| `tools/tatar-siem.py` | How do I get the findings into a SIEM? | one or more scans |

## Baseline diff

    python3 tools/tatar-diff.py BEFORE AFTER [--all] [--json] [--fail-on-new] [--reviews reviewed.json]

BEFORE and AFTER are an evidence folder, a `summary.json` or a `findings.json`.
Findings are matched by `fingerprint`, which is stable across runs: a process
ID or a count in the message does not change it, a different port or path does.
The result is four groups: new, resolved, changed (same fingerprint, different
`contentHash`: severity, confidence or detail moved) and unchanged.
`--fail-on-new` exits 2 when something is new, so a scheduled scan can alert.
Scans from collectors older than 1.9.0 carry no fingerprint and are refused
with a clear message rather than compared by guesswork.

## Unified timeline

    python3 tools/tatar-timeline.py EVIDENCE_DIR [--out FILE] [--format timesketch|jsonl] [--since ISO] [--until ISO]

Merges `timeline.csv` with the findings of the same run into one UTC-ordered
list. The CSV carries the columns Timesketch imports (`message`, `datetime`,
`timestamp_desc`, `data_type`). Cells that start with `=`, `+`, `-` or `@` are
prefixed with an apostrophe. A time with no zone is not guessed; such rows are
counted on stderr. The Windows `timeline.csv` writes ISO 8601 UTC from 1.9.0.

## Stacking across hosts

    python3 tools/tatar-aggregate.py PATH [PATH ...] [--by fingerprint|path] [--format text|csv|json] [--max-hosts N] [--reviews reviewed.json]

Counts how many hosts carry each finding (or each path a finding names) and
lists the rarest first. A host scanned twice counts once, with its newest scan.

## Reviewed verdicts

    python3 tools/tatar-review.py add reviewed.json --scan EVIDENCE_DIR --id TTR-F-007 --verdict good --note "my own scanner" --reviewer NAME
    python3 tools/tatar-review.py apply EVIDENCE_DIR --reviews reviewed.json [--all] [--json] [--fail-on-bad] [--fail-on-unreviewed]

A finding is a lead, not a verdict. This tool keeps the analyst's own answer next
to it, keyed by `fingerprint`, so it carries over to every later scan of the same host.
The verdicts are `good` (looked at it, it is expected), `suspicious` (not decided)
and `bad` (confirmed); a finding with no entry is *unreviewed*. `add --scan` also
records the finding's `contentHash`: if the finding later changes (severity,
confidence or detail), the review is reported as *stale* and the finding counts as
unreviewed again, so a `good` never hides a finding that got worse. `apply` groups a
scan by verdict; `--fail-on-bad` and `--fail-on-unreviewed` exit 2 for use in a
script. `reviewed.json` is plain JSON, sorted, written atomically, and safe to keep in
version control. A malformed file stops the run with exit 1 rather than being guessed at.

`tatar-diff.py --reviews` hides what you reviewed as good from *new* and *changed*
(counted as `reviewedGood`) and tags the rest `{bad}`, `{suspicious}` or `{stale}`;
`--fail-on-new` then ignores the cleared ones. `tatar-aggregate.py --reviews` drops
the good ones and adds a `verdict` column (the worst verdict wins).

## SIEM export

    python3 tools/tatar-siem.py PATH [PATH ...] [-o FILE] [--bulk INDEX] [--all] [--reviews reviewed.json]

One ECS-style JSON object per finding, one per line (NDJSON). `@timestamp` is the
finding's `collected_at`; a time that is not UTC is never guessed (the scan time is
used, and if that is not UTC either the finding is skipped and counted). `event.*`
carries id, dataset and severity (High 70, Review 40), `threat.*` the ATT&CK
technique ids, `file.path` the paths the finding names, and `tatar.*` everything
else: fingerprint, contentHash, confidence, artifact class, detail, recommendation,
evidence and, with `--reviews`, the verdict. `--bulk INDEX` writes the Elasticsearch
bulk format with the fingerprint and host as `_id`, so importing the same scan twice
does not duplicate it. The output is pure ASCII JSON: control and bidirectional
characters from the host arrive escaped. Exit 2 means some findings were skipped.

## Recommendation (schema 1.8)

Every finding carries `recommendation`: one static next step chosen by category, for
example "Hash the file, check where it came from and when it was created, and compare it
with your allowlist before treating it as hostile." It is a pointer for the analyst, not
a verdict, and it never uses the content of the finding. Both editions carry the same
text; `tests/fixtures/recommendations.tsv` is the shared reference the tests check.
The viewer shows it as "Recommendation".
