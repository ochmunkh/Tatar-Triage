# Analysis tools

Three small command-line tools work on what the collectors write. They are
read-only, offline, use only the Python 3 standard library, and need nothing
installed on the suspect host - run them on the analyst's machine.

| Tool | Question it answers | Needs |
|---|---|---|
| `tools/tatar-diff.py` | What changed on this host since the baseline? | two scans, schema 1.7 |
| `tools/tatar-timeline.py` | What happened, in what order? | one evidence folder |
| `tools/tatar-aggregate.py` | Which host differs from the rest? | many scans, schema 1.7 |

## Baseline diff

    python3 tools/tatar-diff.py BEFORE AFTER [--all] [--json] [--fail-on-new]

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

    python3 tools/tatar-aggregate.py PATH [PATH ...] [--by fingerprint|path] [--format text|csv|json] [--max-hosts N]

Counts how many hosts carry each finding (or each path a finding names) and
lists the rarest first. A host scanned twice counts once, with its newest scan.
