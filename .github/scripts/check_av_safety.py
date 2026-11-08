#!/usr/bin/env python3
"""Fail if the collector stops matching what docs/AV-SAFETY.md claims about it.

TATAR's reason to exist is that a first responder can run it on a live,
production endpoint without an argument with the security team first. That
only holds while the tool keeps behaving the way the document says it does:
no egress, no credential dumping, no AMSI or ETW tampering, no obfuscation,
nothing EDR-sensitive on by default, nothing written to host state.

Those are easy promises to make in a README and easy to break in a commit --
one Invoke-WebRequest added for a "quick version check", one default flipped
to $true for convenience, and the document is a lie that nobody notices
until a customer's EDR notices for us. So the document does not carry the
claims on its own: each claim has an ID, and each ID has a check here.

The checks run against a comment- and string-stripped view of each source
file, because the collector LOOKS for these very patterns -- 'FromBase64String'
and 'Invoke-Expression' are detection strings in the PowerShell edition, and
must not be confused with calls. What is forbidden is executing them, not
naming them.

The document and this script are cross-checked both ways: a claim in
AV-SAFETY.md with no check here fails, and a check here with no claim in the
document fails. Neither half can drift ahead of the other.

Usage:  python3 .github/scripts/check_av_safety.py [repo_root]
Exit:   0 = every claim still holds, 1 = a claim was broken or went undocumented.
"""
import os
import re
import sys

PS = "Tatar.ps1"
SH = os.path.join("linux", "tatar-linux.sh")
DOC = os.path.join("docs", "AV-SAFETY.md")


# ---------------------------------------------------------------------------
#  Code-only views: comments and string literals removed, offsets preserved
# ---------------------------------------------------------------------------
def strip_powershell(src, keep_strings=False):
    """Blank out comments and string literals, keeping every other byte in place.

    Offsets are preserved (removed spans become spaces, newlines kept) so that
    a match in the stripped text reports the line number of the real source.
    """
    out = list(src)
    n = len(src)
    i = 0

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        # block comment
        if src.startswith("<#", i):
            j = src.find("#>", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        # line comment (a '#' that is not part of a token)
        if c == "#" and (i == 0 or not re.match(r"[\w$]", src[i - 1])):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        # here-strings
        if not keep_strings and (src.startswith("@'", i) or src.startswith('@"', i)):
            term = "'@" if src[i + 1] == "'" else '"@'
            j = src.find("\n" + term, i)
            j = n if j < 0 else j + len(term) + 1
            blank(i, j)
            i = j
            continue
        # single-quoted string ('' escapes a quote)
        if c == "'" and not keep_strings:
            j = i + 1
            while j < n:
                if src[j] == "'":
                    if j + 1 < n and src[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        # double-quoted string (backtick escapes, "" escapes a quote)
        if c == '"' and not keep_strings:
            j = i + 1
            while j < n:
                if src[j] == "`":
                    j += 2
                    continue
                if src[j] == '"':
                    if j + 1 < n and src[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        i += 1
    return "".join(out)


def strip_bash(src, keep_strings=False):
    """Same idea for the shell edition."""
    out = list(src)
    n = len(src)
    i = 0

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        # here-document: blank the body, which is data, not code
        m = re.match(r"<<-?\s*(['\"]?)(\w+)\1", src[i:])
        if m:
            delim = m.group(2)
            nl = src.find("\n", i)
            if nl < 0:
                break
            end = re.search(r"^\s*%s\s*$" % re.escape(delim), src[nl:], re.M)
            j = n if not end else nl + end.end()
            blank(nl, j)
            i = j
            continue
        # '#' starts a comment only at the start of a word
        if c == "#" and (i == 0 or src[i - 1] in " \t\n;&|()"):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "'" and not keep_strings:
            j = src.find("'", i + 1)
            j = n if j < 0 else j + 1
            blank(i, j)
            i = j
            continue
        if c == '"' and not keep_strings:
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        i += 1
    return "".join(out)


def hits(text, pattern):
    """Every (line_number, line_text) where pattern matches the stripped view."""
    found = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        line = text.count("\n", 0, m.start()) + 1
        found.append((line, m.group(0).strip()))
    return found


def forbid(errors, claim, label, text, pattern, where):
    for line, snippet in hits(text, pattern):
        errors.append(
            "%s: %s -- %s:%d executes '%s'" % (claim, label, where, line, snippet)
        )


def require(errors, claim, label, raw, pattern, where):
    if not re.search(pattern, raw, re.MULTILINE):
        errors.append(
            "%s: %s -- %s no longer contains the expected declaration (/%s/)"
            % (claim, label, where, pattern)
        )


# ---------------------------------------------------------------------------
#  The claims. Each ID here must appear in docs/AV-SAFETY.md, and vice versa.
# ---------------------------------------------------------------------------
def claim_av01(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """No network egress from either edition."""
    forbid(errors, "AV-01", "network call", ps,
           r"\b(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|"
           r"New-Object\s+Net\.WebClient|System\.Net\.WebClient|"
           r"System\.Net\.Http|DownloadString|DownloadFile|"
           r"Resolve-DnsName|Test-NetConnection|Send-MailMessage)\b", PS)
    forbid(errors, "AV-01", "network call", sh,
           r"(^|[;&|(\s])(curl|wget|nc|ncat|telnet|ftp|scp|sftp|ssh|"
           r"dig|nslookup|host)\s+-?[\w/.-]", SH)
    forbid(errors, "AV-01", "network call", sh, r"/dev/tcp/", SH)


def claim_av02(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """No credential material is read: no LSASS access, no password hashes."""
    forbid(errors, "AV-02", "credential access", ps_s,
           r"\b(lsass|MiniDumpWriteDump|comsvcs|sekurlsa|procdump|"
           r"LsaOpenPolicy|CredEnumerate|Get-Credential)\b", PS)
    forbid(errors, "AV-02", "credential access", sh_s,
           r"\b(unshadow|john|hashcat|getent\s+shadow)\b", SH)
    # /etc/shadow may be read ONLY to list accounts whose password field is
    # empty. The awk program below prints field 1 (the username) and never
    # field 2 (the hash). If that shape changes, the claim stops holding.
    if "/etc/shadow" in raw_sh:
        require(errors, "AV-02", "shadow read is username-only", raw_sh,
                r"awk -F: '\(\$2==\"\"\)\{print \$1\}' /etc/shadow", SH)


def claim_av03(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """No AMSI, ETW or AV tampering."""
    forbid(errors, "AV-03", "AV/telemetry tampering", ps_s,
           r"\b(AmsiUtils|amsiInitFailed|AmsiScanBuffer|"
           r"Set-MpPreference|Add-MpPreference|EtwEventWrite|"
           r"Disable-WindowsOptionalFeature)\b", PS)
    forbid(errors, "AV-03", "AV/telemetry tampering", sh_s,
           r"\b(setenforce|aa-disable|auditctl\s+-[ed])\b", SH)


def claim_av04(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """No dynamic or obfuscated code execution."""
    forbid(errors, "AV-04", "dynamic execution", ps,
           r"(\bInvoke-Expression\b|(?<![\w-])\biex\b|"
           r"\[scriptblock\]::Create|FromBase64String|-Enc\w*\s+\$|"
           r"\[char\[\]\]\s*\$|-join\s*\(\s*\$\w+\s*\|\s*%\s*\{)", PS)
    forbid(errors, "AV-04", "dynamic execution", sh,
           r"(\beval\b|base64\s+-d|\bbase64\s+--decode\b|\bxxd\s+-r\b)", SH)


def claim_av05(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """Every EDR-sensitive operation is off unless the operator asks for it."""
    for var in ("CollectHives", "ExportEvtx", "MemoryDump"):
        require(errors, "AV-05", "%s defaults to off" % var, raw_ps,
                r"\$%s\s*=\s*\$false" % var, PS)
        # and the module must actually honour the flag before doing anything
        require(errors, "AV-05", "%s is enforced at the module entry" % var,
                raw_ps, r"if \((-not )?\$%s\)" % var, PS)
    require(errors, "AV-05", "DUMP_DELETED defaults to off", raw_sh,
            r"DUMP_DELETED=0", SH)


def claim_av06(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """The repository ships no driver, no binary and no packed payload."""
    bad = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in (
                ".exe", ".sys", ".dll", ".so", ".bin", ".msi", ".scr"
            ):
                bad.append(os.path.relpath(os.path.join(dirpath, fn), root))
    for p in sorted(bad):
        errors.append("AV-06: binary shipped -- %s" % p)
    # memory acquisition must stay an operator-supplied, out-of-tree tool
    require(errors, "AV-06", "winpmem is sourced from the operator's tools\\ dir",
            raw_ps, r"Join-Path \$PSScriptRoot 'tools\\winpmem\.exe'", PS)


def check_rm_targets(errors, sh, raw_sh):
    """`rm` may only delete scratch files the script itself made with mktemp.

    The collector does clean up after itself, so a blanket ban on rm would be
    a lie in the other direction. What it must never do is delete anything on
    the host. So every rm operand has to be a variable reference, and every
    such variable has to be assigned from mktemp somewhere in the script. A
    literal path -- or a variable that points at collected evidence -- fails.
    """
    scratch = set(re.findall(r"(\w+)=\"?\$\(mktemp\)", raw_sh))
    raw_lines = raw_sh.splitlines()
    for line_no, _ in hits(sh, r"(^|[;&|(\s])rm\s"):
        line = raw_lines[line_no - 1] if line_no <= len(raw_lines) else ""
        for call in re.findall(r"(?:^|[;&|(\s])rm\s+([^;&|)]*)", line):
            operands = [t for t in call.split() if not t.startswith("-")
                        and not t.startswith("2>")]
            for t in operands:
                var = re.match(r"^\"?\$\{?(\w+)\}?\"?$", t)
                if not var:
                    errors.append(
                        "AV-07: host modification -- %s:%d removes a literal "
                        "path (%s); rm is only allowed on mktemp scratch"
                        % (SH, line_no, t))
                elif var.group(1) not in scratch:
                    errors.append(
                        "AV-07: host modification -- %s:%d removes $%s, which "
                        "is not assigned from mktemp"
                        % (SH, line_no, var.group(1)))


def claim_av07(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """The collector does not modify host state."""
    forbid(errors, "AV-07", "host modification", ps,
           r"\b(Remove-Item|Remove-ItemProperty|Set-ItemProperty|"
           r"New-ItemProperty|Clear-EventLog|Stop-Process|Stop-Service|"
           r"Set-Service|Restart-Service|Set-ExecutionPolicy|"
           r"Set-Acl|Rename-Item)\b", PS)
    forbid(errors, "AV-07", "host modification", sh,
           r"(^|[;&|(\s])(rmdir|unlink|shred|chmod|chown|chattr|"
           r"kill|pkill|killall|truncate|dd)\s+-?[\w/.$-]", SH)
    check_rm_targets(errors, sh, raw_sh)
    forbid(errors, "AV-07", "host modification", sh,
           r"systemctl\s+(start|stop|restart|enable|disable|mask)\b", SH)


def claim_av08(errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root):
    """The collector installs no persistence of its own."""
    forbid(errors, "AV-08", "persistence", ps,
           r"\b(New-Service|Register-ScheduledTask|New-ScheduledTask|"
           r"schtasks|Set-MpPreference|New-ItemProperty.*Run)\b", PS)
    forbid(errors, "AV-08", "persistence", sh,
           r"(crontab\s+-|systemctl\s+enable|\bupdate-rc\.d\b|"
           r">>?\s*/etc/(cron|rc\.local|systemd))", SH)


CLAIMS = {
    "AV-01": ("No network egress", claim_av01),
    "AV-02": ("No credential material is read", claim_av02),
    "AV-03": ("No AMSI, ETW or AV tampering", claim_av03),
    "AV-04": ("No dynamic or obfuscated execution", claim_av04),
    "AV-05": ("EDR-sensitive operations are off by default", claim_av05),
    "AV-06": ("No driver or binary is shipped", claim_av06),
    "AV-07": ("Host state is not modified", claim_av07),
    "AV-08": ("No persistence is installed", claim_av08),
}


# ---------------------------------------------------------------------------
#  Document <-> check cross-reference
# ---------------------------------------------------------------------------
def check_document(errors, root):
    """Every claim must be written down, and every written claim must be checked."""
    path = os.path.join(root, DOC)
    if not os.path.isfile(path):
        errors.append("DOC: %s is missing -- the claims have nowhere to live" % DOC)
        return
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    documented = set(re.findall(r"\bAV-\d{2}\b", text))
    implemented = set(CLAIMS)

    for cid in sorted(implemented - documented):
        errors.append(
            "DOC: %s (%s) is enforced in CI but not stated in %s -- "
            "a check nobody can read is not a claim" % (cid, CLAIMS[cid][0], DOC)
        )
    for cid in sorted(documented - implemented):
        errors.append(
            "DOC: %s is claimed in %s but nothing here enforces it -- "
            "remove the claim or add the check" % (cid, DOC)
        )
    # the document must state each claim next to its ID, not just cite the ID
    for cid in sorted(implemented & documented):
        title = CLAIMS[cid][0]
        if title.lower() not in text.lower():
            errors.append(
                "DOC: %s is cited in %s but its wording has drifted -- "
                "expected the claim to read '%s'" % (cid, DOC, title)
            )


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    errors = []

    try:
        with open(os.path.join(root, PS), encoding="utf-8-sig") as fh:
            raw_ps = fh.read()
        with open(os.path.join(root, SH), encoding="utf-8") as fh:
            raw_sh = fh.read()
    except IOError as exc:
        print("AV-SAFETY: cannot read a collector -- %s" % exc)
        return 1

    ps = strip_powershell(raw_ps)
    sh = strip_bash(raw_sh)
    # Comments gone, string literals kept. AV-02 and AV-03 use this view: the
    # collector has no reason to NAME lsass or the AMSI internals at all, and
    # a bypass hides them in strings -- GetField("amsiInitFailed") -- exactly
    # where the code-only view cannot see them.
    ps_s = strip_powershell(raw_ps, keep_strings=True)
    sh_s = strip_bash(raw_sh, keep_strings=True)

    for cid in sorted(CLAIMS):
        CLAIMS[cid][1](errors, ps, sh, ps_s, sh_s, raw_ps, raw_sh, root)
    check_document(errors, root)

    if errors:
        print("AV-SAFETY: %d claim(s) no longer hold\n" % len(errors))
        for e in errors:
            print("  [x] %s" % e)
        print(
            "\nTATAR is run on live production endpoints on the strength of "
            "these claims.\nEither restore the behaviour or change the claim "
            "in %s -- do not\nweaken the check to make the build pass." % DOC
        )
        return 1

    print(
        "AV-SAFETY: all %d claims hold (%s)"
        % (len(CLAIMS), ", ".join(sorted(CLAIMS)))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
