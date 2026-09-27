# metrics

Traffic snapshots for this repository. This branch holds data only - no code,
no history shared with `main`.

GitHub's traffic API serves a rolling **14-day** window, so any day that is not
snapshotted before it falls out of that window is lost permanently. The
`Metrics` workflow on `main` runs on the 1st, 11th and 21st of each month
(worst-case gap: 11 days) and merges each fetch into the files here.

| file | columns | notes |
|---|---|---|
| `traffic.csv` | `date, clones, clones_unique, views, views_unique` | one row per calendar day, upserted - the latest fetch of a day wins, because the current day is always partial |
| `releases.csv` | `date, tag, asset, downloads` | cumulative counters, so one snapshot per run date rather than per day |

`clones` counts every clone including CI and mirrors; `clones_unique` is the
number of distinct cloners. The gap between the two is the bot signal, and
release asset downloads are the cleanest human signal.