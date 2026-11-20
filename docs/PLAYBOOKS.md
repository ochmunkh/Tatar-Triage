# Analyst playbooks: what to do with a finding

[Монгол](PLAYBOOKS.mn.md) · [← README](../README.md)

Every finding carries a `recommendation`: one sentence chosen by its category ([TOOLS.md](TOOLS.md)). This page takes the same categories and turns each sentence into a short routine. It is the author's working practice, not a standard, and a finding is always a lead for review, not a verdict.

## How to use a playbook

1. Read the finding in `summary.txt`: its message, its detail and the report section it names. Open `TATAR_Report_<HOST>_<stamp>.txt` at that section to see the evidence itself.
2. Follow the playbook for its category below. Work on a copy of the evidence folder.
3. Widen the question before you decide: has this fingerprint been seen on other hosts (`tools/tatar-aggregate.py`), did it exist in an earlier scan (`tools/tatar-diff.py`), what else happened at the same time (`tools/tatar-timeline.py`)?
4. Record your answer with `tools/tatar-review.py` (`good`, `suspicious` or `bad`) so it carries over to later scans.
5. Read `tatar.log` before you call a host clean: it lists what was not collected.

Escalate when the same finding is on more than one host, when the file or entry appeared inside the time window you are investigating, or when the owner cannot explain it. Close a lead as `good` only when you know why it is there.

## Windows and Linux

### process
1. Note the image path, the signature, the parent process and the network connections shown in the finding.
2. Hash the binary (on Windows `binary_hashes.txt` lists the hashes of running binaries) and look the hash up in your own sources before ending the process.
3. Check whether the same fingerprint is on other hosts. An unsigned binary in a user-writable folder with an unknown parent and an outbound connection is a reason to escalate.

### persistence
1. Find who created the entry and when, from the report section and from `timeline.csv` around that time.
2. Hash what it launches and compare it with a known-good build.
3. Record the entry before you remove anything; removing it destroys the evidence of when it ran.

### privesc
1. Confirm that a standard user can write to the path or the setting named in the finding.
2. Fix the permissions or quote the path, then scan again and confirm the finding is gone.
3. Escalate when the path belongs to a service that runs with high privileges and the file was written recently.

### lateral
1. Identify the source host and the account from the matching logon events at the same time.
2. Look for the same tool or artifact on other hosts with `tools/tatar-aggregate.py`.
3. Escalate when two or more hosts show it.

### rmm
1. Ask the owner whether this remote-management tool is approved.
2. If it is not, record when and by which account it was installed, using the connection history in the finding, before you remove it.
3. An unapproved remote-access tool with a connection trace is a reason to escalate.

### useractivity
1. Ask the user whether they ran it.
2. Check where the file came from and when it first appeared (see `motw` below).
3. A command typed into the Run dialog that hides a window deserves a second opinion before you close it.

### obfscan
1. Copy the script to a safe place and decode it without running it.
2. Look for download commands, encoded payloads and the address they point to.
3. Record the file hash and where the file came from before you delete anything.

### indicators
1. Hash the file and check where it came from and when it was created.
2. Compare it with your allowlist before you treat it as hostile; installers and updaters also write to temp folders.
3. A double extension such as `.pdf.exe` is a classic disguise; treat it as high interest until explained.

### motw
1. Check where the download came from.
2. Check whether it was opened or run afterwards (`useractivity` and `prefetch` on Windows).
3. A downloaded executable that was then run is worth more attention than a document that was only saved.

### network
1. Compare the entry with what this host is meant to use; a hosts-file override or a changed resolver can redirect traffic.
2. Read `hosts.txt`, `dns_cache.txt` and `ipconfig.txt` together.
3. Escalate when an entry names a login, update or banking address that the owner did not add.

### sessions
1. List the source addresses and the target accounts in the logon events.
2. Check whether any attempt later succeeded.
3. Escalate on a success that follows many failures from one address.

### users
1. Confirm the account is expected, who created it and when.
2. Set a password or disable the account if it is not needed.
3. A new administrator you did not create is a reason to escalate.

### eventlogs
1. Check whether the log was cleared or stopped on purpose.
2. Compare it with a copy forwarded to a collector, if one exists.
3. A cleared security log is high interest on its own; look at what happened just before the clearing time.

### ioc
1. A match from your own indicator list: confirm it is not a coincidence.
2. Search the other hosts for the same indicator.
3. Keep the feed version you matched against, so the result can be repeated.

### other categories
Review the evidence section named in the finding and confirm with the owner whether it is expected.

## Linux only

### suid
1. Verify the file against the package manager.
2. Confirm it is meant to carry the setuid bit.
3. A setuid file in a user-writable path that no package owns is a reason to escalate.

### sshkeys
1. Confirm each key belongs to a known person or system.
2. Check when `authorized_keys` last changed.
3. A key nobody can name is a reason to escalate.

### bashhistory
1. Read the surrounding commands and timestamps for downloads, credential use and cleanup.
2. Remember that history is the user's own record and can be edited or turned off.

### context
1. Confirm whether this host is meant to run containers or is inside one.
2. Review the mounted paths and the privileges.
3. Read the other findings from this host as findings about the container, not about the physical machine.
