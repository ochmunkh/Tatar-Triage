# Feeds of known malware

[Монгол](IOC-FEEDS.mn.md) · [← README](../README.md)

Tatar Triage never looks anything up online. To recognise malware that is already known, give it a feed: a JSON file of indicators that you prepare on your own machine and pass with `-IOCFile` (Windows) or `--iocfile` (Linux). A hit becomes a High finding with confidence 0.95 that names the indicator.

## What a feed can and cannot do

- **It recognises the exact file.** A SHA-256 identifies one build of a program, and a rebuilt sample has a new hash. Large public collections hold many builds of common families, so known commodity malware is often caught; a sample built for one target is not.
- **Network indicators last longer than hashes.** A command-and-control domain or address often stays the same while the binary changes, so put domains and IPs in the feed, not only hashes.
- **Hashes are compared for the files the run hashes:** the running programs and, on Windows, the services, which are listed in `binary_hashes.txt`, and any file a finding names. A file that sits on disk and never ran is not hashed.
- **Only SHA-256 is compared.** MD5 and SHA-1 entries are ignored.
- **New malware has no indicator yet.** The behaviour checks (persistence, remote-access tools, Mark-of-the-Web, unusual parent and child processes, correlation) are what catch something new.

## How large a feed can be

Measured on 2026-11-23 with random indicators that match nothing, so the time is the cost of the feed alone. Windows: a Windows 11 workstation, PowerShell 5.1, not elevated, `-All`, 23 evidence text files of about 1.5 MB; the time is the summary and IOC step. Linux: a Linux virtual machine, `--quick`, not root; the time is the whole run.

| Feed | Windows | Linux |
|---|---|---|
| 1 hash | 1.5 s | 0.7 s |
| 10,000 hashes | 3.6 s | 0.8 s |
| 100,000 hashes, 10,000 IPs, 10,000 domains | 6.7 s | 1.9 s |
| 1,000,000 hashes, 100,000 IPs, 100,000 domains | 35 s | 13.8 s |

Before version 1.12.4 every indicator was searched for separately, and 10,000 hashes took 413 s on Windows and 37 s on Linux. A feed of the most recent weeks of a public source fits comfortably. A full archive of millions of entries works, but adds tens of seconds and makes a large file: the 1.2 million entries above are 72 MB of JSON.

## Preparing a feed

1. On an analyst machine with internet access, download recent exports from sources you trust: for example abuse.ch MalwareBazaar (sample hashes), ThreatFox (indicators with the malware family) and URLhaus (malware hosts), your national CERT, or a MISP export. Read each source's terms of use.
2. Put the values into four text files, one value per line: `hashes.txt` (SHA-256), `ips.txt`, `domains.txt` and `filenames.txt`. Lines that start with `#` are ignored.
3. Convert them with the snippet below. It uses only the Python standard library and keeps hashes that are SHA-256.
4. Copy `ioc.json` to the responder's media next to the tool. A dry run (`-DryRun` or `--dry-run`) says whether the feed can be read, before anything is collected.
5. Refresh the feed before each engagement. An old feed misses what has appeared since.

```python
import json, re

def load(name):
    try:
        with open(name, encoding="utf-8-sig") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []

hashes = [h.lower() for h in load("hashes.txt")]
good = sorted({h for h in hashes if re.fullmatch(r"[0-9a-f]{64}", h)})
feed = {"hashes": good, "ips": sorted(set(load("ips.txt"))),
        "domains": sorted(set(load("domains.txt"))), "filenames": sorted(set(load("filenames.txt")))}
with open("ioc.json", "w", encoding="utf-8") as f:
    json.dump(feed, f)
print("hashes kept:", len(good), "- not SHA-256, skipped:", len(hashes) - len(good))
```

Then run the tool with it:

```powershell
.\Tatar.ps1 -All -IOCFile ioc.json
sudo ./tatar-linux.sh --all --iocfile ioc.json
```

## Keep it offline and private

- **The feed is read, never sent anywhere.** The run stays offline whatever the feed holds.
- **An online lookup is a separate step.** Looking up hashes from the evidence in an online service such as VirusTotal happens on the analyst machine, after the collection. It sends the client's hashes to a third party, so agree it with the client first.
