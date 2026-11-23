# From findings to a report

[Монгол](REPORTING.mn.md) · [← README](../README.md)

Tatar Triage does not write your report. It gives you evidence you can trace back, and this page says what to cite, where each kind of finding usually belongs and how to state the limits. The mapping to report sections is the author's suggestion, not a standard.

## What to cite

| Item | Where it is | Why cite it |
|---|---|---|
| Case, examiner, start and finish times, time zone, hash of the script that ran | `chain_of_custody.txt` | Shows who collected what, when, and with which build |
| Hash of every collected file and of the manifest itself | `manifest_sha256.txt`, `manifest_sha256.txt.sha256` | Lets a reader confirm the files are untouched |
| Tool version | `version` in `summary.json` | Tells a reader which rules produced the findings |
| Finding id (`TTR-F-NNN`) | `summary.txt`, `findings.json` | Names a finding inside one run; it is not stable between runs |
| `fingerprint` | `findings.json` | Names what the finding is; the same on the same host in every scan |
| `contentHash` | `findings.json` | Changes when severity, confidence or detail moves |
| `evidence[]` | `findings.json` | The report file and the section the finding came from |
| What was not collected | `tatar.log` | States the limits of the collection |

## Where findings usually go

| Finding category | Report section it usually supports |
|---|---|
| `process` | Running software |
| `persistence` | Persistence |
| `privesc` | Privilege escalation weaknesses |
| `lateral`, `sessions` | Lateral movement and logons |
| `rmm` | Remote-access tools |
| `useractivity`, `motw` | User activity and downloads |
| `obfscan`, `indicators` | Suspicious files and scripts |
| `network` | Network configuration |
| `users` | Accounts |
| `eventlogs` | Logging and tampering |
| `ioc` | Matches against your indicator list |
| `suid`, `sshkeys`, `bashhistory`, `context` (Linux) | Linux-specific findings |

## How to write one finding

State the finding, point to the evidence and give your own judgement separately, so a reader can see which part came from the tool and which part is yours:

```text
Finding TTR-F-007, fingerprint 0123456789abcdef, severity Review (tool 1.12.2).
Evidence: TATAR_Report_HOST_2026-11-19_10-00-00.txt, the section named in the finding.
Observation: the hosts file maps a login address to an unexpected IP address.
Assessment (analyst): not approved by the owner; reason for escalation.
```

The line with the fingerprint is what lets a later report say "the same finding is still present" without describing it again.

## State the limits

- A finding is a lead for review, not a verdict. Write "the collector reported" and "I assessed", not "the host was compromised" unless you have shown it.
- Say whether the run was privileged. A run without Administrator or root cannot read everything, and the summary says so.
- Say what was not collected, and the logging gaps, from `tatar.log`. A clean result does not prove a clean host.
- Say the clock note: `chain_of_custody.txt` records the time zone and states that the host clock was not compared with an outside time source. Write down the difference you measured yourself.

## Chain of custody

Copy the items from `chain_of_custody.txt` into the report, add your own entries (who copied the folder, when, to where) and record the manifest check you made before and after you worked on the copy. These are the kinds of items ISO/IEC 27037 expects a chain-of-custody record to carry. The tool records them; it does not make your process conformant ([SECURITY-TESTING.md](SECURITY-TESTING.md)). The finished report is confidential in the same way as the evidence folder (see the Legal section of the [README](../README.md)).
