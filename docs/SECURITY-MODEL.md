# Security model

[Монгол](SECURITY-MODEL.mn.md) · [← README](../README.md)

One page that says what Tatar Triage promises, what it does not, and where each promise is checked. The detail lives in the pages linked here; this page is the way in.

## What it promises

| Property | What it means | Held by |
|---|---|---|
| No network | No network calls, no telemetry, no update check, no account | AV-01 ([AV-SAFETY.md](AV-SAFETY.md)) |
| No credential material | Nothing in the collector reads passwords or dumps credentials | AV-02 |
| No tampering with defences | No AMSI, ETW or antivirus tampering | AV-03 |
| Readable, not obfuscated | No dynamic or encoded execution; everything that runs is in the file | AV-04 |
| Risky actions are opt-in | Hive copy, full event-log export and memory dump are off unless asked for | AV-05 |
| Nothing shipped | No driver or binary in the repository | AV-06 |
| Host unchanged | No deletion, permission change, service control or registry write on the examined host | AV-07, S8 and W8 ([SECURITY-TESTING.md](SECURITY-TESTING.md)) |
| Nothing installed | No service, scheduled task, cron entry or Run key | AV-08 |
| Collected text cannot run in your tools | A cell that starts like a spreadsheet formula is neutralised | AV-09 |
| Evidence is private | The folder is writable and readable by the examiner only | S6 and W5 |
| Tampering is visible | A changed file or manifest is detected; the script that ran is recorded by hash | S9 and W7 |
| Hostile input is data | Arguments, paths and feed files are never run; an unreadable feed forces exit code 2 | S1 to S5, W1 to W4, hostile-feed tests |

Every AV claim has a check that fails the build when it breaks. The tests run on every change, and the release-integrity gate keeps the documents and the code from drifting apart.

## What it does not promise

- **It is visible to an EDR.** A default run reads process, network and account state and runs a few built-in utilities. What an EDR may notice is listed in [AV-SAFETY.md](AV-SAFETY.md).
- **It does not encrypt the evidence.** It hashes and compresses; encryption is the examiner's job ([EVIDENCE.md](EVIDENCE.md)).
- **It does not check the clock.** It records the time zone and says the host clock was not compared with an outside source.
- **A finding is a lead, not a verdict,** and a clean result does not prove a clean host. Read the "not collected" part of `tatar.log`.
- **It is not a certified or audited product.** The standards pages in [SECURITY-TESTING.md](SECURITY-TESTING.md) are the author's own mapping, with the limits written next to them.
- **It collects from a running host, not from a disk image or a memory dump** ([USAGE.md](USAGE.md)).

## Trust boundaries

Three places, three levels of trust.

- **The examined host is not trusted.** File names, command lines and registry values on it may have been written by an attacker. Text from the host is neutralised before it reaches a report or a CSV file.
- **The evidence folder is the examiner's and is confidential.** It is private to the examiner, it holds sensitive information about the host, and it should be handled like the reports of a risk assessment or an audit (see the Legal section of the [README](../README.md)).
- **The analyst's machine runs the analysis tools.** They use only the Python standard library, work offline and read the evidence as data. The viewer is one sealed file with no network access.

## Third-party code

The repository contains no third-party code and no binary. The Python tools import only the standard library, and a release-integrity rule fails the build otherwise. The collectors use the operating system's own utilities. The one outside component is the `winpmem` program that you supply yourself if you ask for a memory dump; the project does not distribute it. The build workflows use a few GitHub Actions, each pinned to a commit.

## Check it yourself

```bash
python3 .github/scripts/check_av_safety.py .
python3 .github/scripts/check_release_integrity.py .
sha256sum -c SHA256SUMS.txt
```

The first two read the repository and report whether the claims above still hold. The third checks a downloaded release against its published digests. A run can be previewed without writing anything with `-DryRun` or `--dry-run`.

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
