# After collection: which file goes where

[← README](../README.md) · [Tools](TOOLS.md)

Tatar Triage collects and stops. It does not analyse the disk, parse the logs it
exports or look at memory. This page says which file in an evidence folder is the
input for which kind of tool, so the next step is obvious. Nothing here is built
into the collector: there is no coupling and no network call, and each tool is
something you already run on your own machine. Check each tool's own documentation
for how it is invoked; the commands for those tools are deliberately not repeated
here, because they change between versions.

| You have | You want to | Use |
|---|---|---|
| `findings.json`, `summary.json` | read the leads, mark what you decided | `tools/viewer.html`, `tools/tatar-review.py` |
| two scans of one host | see what changed | `tools/tatar-diff.py` |
| scans of many hosts | find the host that differs | `tools/tatar-aggregate.py` |
| `findings.json` | search and alert in a SIEM | `tools/tatar-siem.py` (ECS NDJSON, or Elasticsearch bulk with `--bulk`) |
| `timeline.csv` and the findings | one ordered story | `tools/tatar-timeline.py` (`--format timesketch` for Timesketch) |
| the technique ids in `findings.json` | see coverage on the ATT&CK matrix | `tools/tatar-navigator.py`, then load the layer in ATT&CK Navigator |
| `binary_hashes.txt` | check hashes against threat intelligence | a lookup service or your own hash list (the file is plain `hash  path`) |
| `external_ips.txt` | check the public addresses this host was talking to | a reputation service or your own lists (the file is `address<TAB>port<TAB>process (PID)`); agree any online lookup with the client first |
| `EventLogs\*.evtx` (from `-ExportEvtx`) | read, filter and hunt in the full logs | an EVTX parser, or Sigma rules run by a tool that reads EVTX |
| `RegistryHives\` (from `-CollectHives`) | registry analysis | a registry viewer or a registry parser |
| `MFT\` | file-system timeline | an MFT parser |
| a memory image (from `-MemoryDump`) | memory analysis | a memory-forensics framework |
| your own indicators (hashes, IPs, domains, file names) | confirm known-bad on the next run | `-IOCFile` with a file shaped like `ioc.sample.json` |

## Order that works

1. Open `summary.txt` and `findings.json` in the viewer. Mark each finding with
   `tatar-review.py`; what you call `good` stays hidden on the next scan of the host.
2. Run `tatar-timeline.py` on the evidence folder and read the findings in time order.
3. Only then reach for the heavy inputs (EVTX, hives, MFT, memory). The collected
   files tell you which of those are worth the time.

## Keep the evidence honest

Work on a copy. Check `manifest_sha256.txt` before you start and after you finish
(`sha256sum -c manifest_sha256.txt`), and check the manifest itself against
`manifest_sha256.txt.sha256`. `tatar.log` is not in the manifest on purpose, it
keeps growing; it also lists what was not collected, which you should read before
you say a host is clean.

## What is not here

No disk imaging, no live acquisition of locked files, no memory analysis and no
log parsing. Those are the jobs of the tools in the table, and Tatar Triage keeps
to the part that needs no installation and no administrator rights on the host.
