# A first investigation, step by step

[Монгол](WALKTHROUGH.mn.md) · [← README](../README.md)

This takes about thirty minutes on a machine you can throw away, and it walks the whole path once: a baseline, a change, a second scan, reading the result and comparing the two runs. By the end you will have read a finding, followed it back to its evidence and seen the difference between two runs of the same host.

## Before you start

- Use a Windows machine you can change and discard: Windows Sandbox, or a virtual machine you can reset. The collector changes nothing on a host. The two stand-ins below do change the system, on purpose, so never plant them on a machine you care about.
- You need PowerShell 5.1 or later, the folder with `Tatar.ps1`, and Python 3 for the comparison step (the analysis tools use only the standard library).
- Nothing here is malicious and no script is shipped. You make two small, harmless changes by hand.

## 1. Take a baseline

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Tatar.ps1 -Modules sysinfo,network,indicators -OutputPath E:\Evidence -CaseId LAB-1 -Examiner "Name"
```

`-Modules` runs only the named modules, so this finishes in seconds. `-Quick` is not used here because it does not include `indicators`. The run creates a folder named after the host and the time. Open `summary.txt` in it: on a clean machine expect few findings or none (in the Sandbox, the Sandbox's own administrator account can appear). Keep this folder; it is your BEFORE.

## 2. Plant two stand-ins

Open PowerShell as Administrator and run:

```powershell
Add-Content C:\Windows\System32\drivers\etc\hosts "203.0.113.7 login.example.test"
Copy-Item C:\Windows\System32\notepad.exe "$env:TEMP\invoice.pdf.exe"
```

The first line adds a hosts-file override. The address and the name are reserved for documentation and tests, so nothing real is redirected. The second line copies a harmless system program into the temp folder under a double extension, the shape of a common disguise. They correspond to W11 and W16 in [VALIDATION.md](VALIDATION.md).

## 3. Scan again

Run the same command as in step 1. A second folder appears next to the first. This is your AFTER.

## 4. Read the result

- Open the new `summary.txt`. Findings are sorted by severity, and each has a message, a detail and a recommendation. Look for the hosts-file entry (module `network`) and the file in the temp folder (module `indicators`).
- Each finding names the report section it came from. Open `TATAR_Report_<HOST>_<stamp>.txt` at that section to see the raw evidence behind the sentence.
- To see the run in a browser, open `tools/viewer.html` and load `summary.json`. The page works offline and sends nothing anywhere.
- Open `tatar.log` and read what was not collected before you say anything is clean.

In the recorded round ([VALIDATION.md](VALIDATION.md), version 1.10.0, Windows Sandbox) the same two stand-ins were findings. Versions since then have changed details, and the collector now also counts executables in temp folders, so you may see more than two findings. What you see is the result for your build, and a difference from this page is worth a note, not a worry. A finding is a lead for review, not a verdict.

## 5. Compare the two runs

```powershell
python3 tools/tatar-diff.py E:\Evidence\<BEFORE-FOLDER> E:\Evidence\<AFTER-FOLDER>
```

The result has four groups: new, resolved, changed and unchanged. The two stand-ins should be in new, and nearly everything else in unchanged. Findings are matched by `fingerprint`, which does not change between runs of the same host, so a process ID or a count in the message does not make an old finding look new. `--fail-on-new` makes the command exit with 2 when something is new, which is how a scheduled scan can raise an alert ([TOOLS.md](TOOLS.md)).

## 6. Decide and write it down

Pick one finding and follow its playbook in [PLAYBOOKS.md](PLAYBOOKS.md). Then record your own answer next to it so it carries over to later scans:

```powershell
python3 tools/tatar-review.py add reviewed.json --scan E:\Evidence\<AFTER-FOLDER> --id TTR-F-001 --verdict good --note "lab stand-in" --reviewer NAME
```

Use the finding id from your own `summary.txt` instead of `TTR-F-001`. For how to carry a finding into a report, see [REPORTING.md](REPORTING.md).

## 7. Clean up

Remove the added line from the hosts file and delete the copied file from the temp folder, or discard the machine. Keep the two evidence folders if you want to practise the later steps again.

## What this does not show

A stand-in is not an intrusion. Seeing both stand-ins here does not prove that a real attack would be seen, and the limits of the lab rounds are listed in [VALIDATION.md](VALIDATION.md). Treat this page as a way to learn the workflow, not as a measurement.
