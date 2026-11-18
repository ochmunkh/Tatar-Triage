# How Tatar Triage differs from other collectors

[← README](../README.md) · [Coverage](COVERAGE.md)

Tatar Triage is one of several free tools that gather evidence from a live host. They
are not rivals so much as different answers to "what do I need in the first ten minutes,
and what am I allowed to run?". This page describes the difference in plain terms. The
descriptions of the other tools are taken from their public documentation as we understand
it; each project changes, so check theirs before you rely on a row. We have not benchmarked
any of them.

| Tool | Platform | What it is mainly for |
|---|---|---|
| KAPE | Windows | Fast collection of files by "targets" and running parsers over them ("modules") |
| DFIR ORC | Windows | A configurable collector built for large fleets; you write the collection plan |
| CyLR | Windows, Linux, macOS | Copying a standard set of forensic files into one archive, quickly |
| FastIR Collector | Windows | Gathering artifacts into text and CSV files for review |
| IREC | Windows | A collector with a wizard, including disk-level and memory acquisition |
| UAC (Unix-like Artifacts Collector) | Linux, macOS and other Unix-like systems | Shell-based collection of files and command output, defined by artifact lists |
| unix_collector | Linux and other Unix-like systems | A single shell script gathering commands and files |
| **Tatar Triage** | Windows (PowerShell 5.1+), Linux (Bash) | Triage: collect, judge, and say what to look at first |

## The differences that matter

**It judges as well as collects.** Most of the tools above stop at gathering files and
leave reading them to you or a second tool. Tatar Triage also raises findings, each with
a stable fingerprint, the evidence it came from, an ATT&CK technique, a confidence with
its reason, and a recommended next step, so two scans of one host can be compared and what
you already cleared stays cleared ([TOOLS.md](TOOLS.md)). Findings are leads, not verdicts.

**It runs without privilege where it can.** Collectors that copy locked files or read the
disk raw need Administrator or root. Tatar Triage runs as a standard user, tells you in the
report and in `tatar.log` what that cost, and does the privileged parts only when you ask
(`-CollectHives`, `-ExportEvtx`, `-MemoryDump`).

**It is read-only and offline, and the evidence is hashed.** It makes no network
connection, changes nothing on the host, and writes a SHA-256 manifest of everything it
collected, with a chain-of-custody record.

**It is built to pass antivirus.** It is a script you can read, it parses nothing
dangerous, and it does not ship a driver or an executable by default
([AV-SAFETY.md](AV-SAFETY.md)).

**It is small and mostly shallow on purpose.** The collection is wide but not deep: it
does not copy the disk, parse the MFT, read SRUM or carve. Where a tool above collects a
file and Tatar Triage lists it, that is the trade ([COVERAGE.md](COVERAGE.md)).

## When to use something else

Use a raw-acquisition collector (KAPE, DFIR ORC, CyLR) when you are allowed to be
Administrator, the host is already known to be involved, and you need the files
themselves for deep analysis. Use Tatar Triage first when you do not yet know whether
the host matters, when you have an ordinary user session on a machine you may not
administer, or when you need to compare many hosts quickly. Many teams will use both:
Tatar Triage to decide, and a collector to acquire. What to do with each file afterwards
is in [AFTER-COLLECTION.md](AFTER-COLLECTION.md).
