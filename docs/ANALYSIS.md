# Analysing the evidence

[Монгол](ANALYSIS.mn.md) · [← README](../README.md)

## Handing off to a Sigma hunter

The event-log module writes `EventLogs\evt_<ID>.csv` for 15 high-signal event
IDs, capped at 50 events each. That is a preview to read on the spot during
triage. It is deliberately small, and it is **not** a hunting corpus — a common
misreading worth stating plainly.

When you want Sigma rules run over the full history, add `-ExportEvtx`. That
writes `Security.evtx`, `System.evtx`, `Application.evtx` and, where Sysmon is
installed, `Sysmon.evtx` into the same `EventLogs\` folder. EVTX — not CSV — is
what [Hayabusa](https://github.com/Yamato-Security/hayabusa) and
[Chainsaw](https://github.com/WithSecureLabs/chainsaw) take as input, so the
folder can be handed to either one unchanged:

```bash
hayabusa csv-timeline -d EventLogs/ -o timeline.csv
chainsaw hunt EventLogs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

`-ExportEvtx` is off by default because exporting full logs is noisy and
occasionally flagged — see [AV / EDR safety](AV-SAFETY.md).

The division of labour is the point. TATAR answers *what is the state of this
host right now*; a Sigma engine answers *what matched across the whole log
history*. Those are different questions, and this folder is the seam between
them.

## Evidence correlation

One artifact is a lead. Two independent artifacts naming the **same path** is a
different kind of statement, and until 1.5.0 the tool threw it away: an analyst
had to notice by eye that the file Mark-of-the-Web says was downloaded is the
file UserAssist says was run.

The rules are deliberately **few and named**. A generic "anything that
co-occurs" pass would relabel coincidence as evidence, which is the failure this
project keeps correcting for — the first `useractivity` draft raised 144
findings, 142 of them noise. A rule fires only when two findings from
**different modules** name the same path, and it says in words what the
agreement means.

| Rule | Fires when | What it means |
|------|-----------|---------------|
| **COR-01** `download-then-execute` | `motw` and `useractivity` name the same path | a file that arrived from the internet was also executed |
| **COR-02** `autorun-on-suspect-file` | `persistence` and (`motw` or `indicators`) name the same path | an autorun entry points at a file that is itself suspect |

`prefetch` and `autoruns` were named in these rules when they shipped and have
since been removed: both collect into the report but neither raises a finding,
so those rule halves could never fire while this table said they did. The gate
now refuses a rule that names a module which raises no finding.

COR-01 is Windows-only: Mark-of-the-Web is an NTFS alternate data stream and
nothing on Linux records that a file came from the internet. That asymmetry is
declared in `check_docs_parity.py`, which also fails the build if a rule names a
module that no longer exists — a rule pointing at a retired module would quietly
stop firing, and an analyst would read the unraised confidence as *the artifacts
did not agree*.

**What correlation changes, and what it does not.** It raises `confidence` to
**0.85** and rewrites `confidenceReason` to name the rule, both modules, the
shared path and the other finding's id. It does **not** touch severity, does not
merge findings, and does not invent one: correlation makes an existing lead more
credible, it does not make a new claim. The ladder is `0.4` Review → `0.7` High
→ `0.85` correlated → `0.95` IOC-confirmed.

It runs **last**, after the allowlist and after IOC matching, and skips both a
suppressed finding — the allowlist already judged that path known-good, so
correlating on it would re-raise exactly the noise it was there to remove — and
an IOC hit, whose `0.95` already outranks `0.85`.

The two editions disagree about case **on purpose**: `C:\Temp\X.EXE` and
`c:\temp\x.exe` are the same file and must correlate, while `/tmp/x` and
`/Tmp/X` are different files and must not. Both cases are asserted, on both
platforms.

## Collected — now what?

The hardest question a first responder asks is not *what do I run*, it is
*I have the folder, now what*. Three outputs answer it, and none of them costs
anything at collection time.

| File | What it is for |
|---|---|
| `ARTIFACTS.md` | Every file this run produced, what question it answers, and what opens it — `.evtx` → Hayabusa/Chainsaw, `.lnk` → LECmd, jump lists → JLECmd, hives → RegRipper. Built from the files actually produced, so a run that collected less says less. |
| `paste.txt` | The whole run in under 60 lines, to paste into a ticket or a chat with *"is this normal?"*. |
| `allowlist.suggested.json` | This host's findings as an allowlist **draft**, in the format `-Allowlist` already reads. |

**`paste.txt` is deliberately stable.** Durations, counters and process ids are
left out, and the findings are sorted by severity, category and message rather
than by discovery order. Two lines differ between runs and say so. A diff of two
paste logs therefore shows what changed on the *host*, not what the clock did —
the property that kept HijackThis logs useful for a decade. Verified by running
twice in a row: exactly the two declared lines differ.

**The allowlist draft is a draft.** It lists every path this host's findings
named, with nothing judged. Take it from a build you trust, delete what you
cannot vouch for, and then run the fleet against it so only the differences
show. A baseline taken from a host nobody checked will suppress exactly the
compromise you were looking for, which is why the file says so in its own
first field.

**The artifact dictionary is gated.** It is a hand-maintained list of names, and
this repository has shipped five stale ones. So `ARTIFACTS.md` ends with a
machine-checkable `Uncatalogued: N`, and CI fails on anything but `0`: a module
that starts writing a file nobody described breaks the build rather than
quietly shipping an unexplained artifact.

## Viewing findings (`tools/viewer.html`)

A single static page for reading `summary.json` or `findings.json` on **your own analysis machine**: open it in a browser and drop the file on it. It makes no network request (its Content-Security-Policy is `default-src 'none'`), renders every value as text, and adds nothing to the collector — the collector, its speed and its AV surface are unchanged.

For each finding it shows the confidence by name (Review, High, Correlated, IOC) with the reason, ATT&CK links built only from validated technique IDs, the paths the finding names, and a short next step for its `artifactClass`: what to ask, where to look, what is often benign, when to escalate. The guidance covers all 46 classes, contains no link, and never asks you to run anything on the affected host. Above the findings it puts what the collector could **not** do — skipped modules, modules that did not finish (`moduleStatus`), limitations — because an empty list means nothing without them.

`.github/scripts/check_viewer.py` is a CI gate: the policy hashes must match the file, the script may use no HTML-string sink, network call or storage, the file must be plain ASCII, and guidance must exist for exactly the closed `artifactClass` set. `tests/test-viewer.py` (needs Playwright) loads hostile `findings.json` files. After a deliberate edit of the viewer's script or style, `python .github/scripts/check_viewer.py --seal` refreshes the policy hashes.
