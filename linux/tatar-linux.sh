#!/usr/bin/env bash
#
# TATAR Triage Toolkit (Linux) - tatar-linux.sh
# ---------------------------------------------------------------------------
# Lightweight, single-file DFIR triage / artifact collector for Linux hosts.
# Companion to Tatar.ps1 (Windows). Produces the SAME analyst-first outputs:
#   * summary.txt / summary.json  (unified schema across platforms)
#   * tatar.log                   (timestamped START/OK/WARN/FAILED per module)
#                                 FAILED = the module's primary artifact is MISSING
#   * manifest_sha256.txt         (SHA-256 of every collected file)
#   * chain_of_custody.txt
#
# Design principles (same as the Windows edition):
#   * Read-only first. No system modification, no package installs.
#   * Order of volatility: network/process -> sessions -> ... -> disk/logs.
#   * Transparent, not evasive. Meant to be reviewed, signed, and allow-listed.
#   * Findings are LEADS FOR REVIEW, not verdicts.
#
# Targets: Debian/Ubuntu and RHEL/CentOS/Fedora (bash 4+, coreutils).
# Run as root for complete collection (some artifacts need privilege).
#
# Exit codes:  0 = success | 1 = fatal / usage error | 2 = completed with errors
#
# Author: Enkhbat.O (Security Analyst) | TATAR Triage Toolkit - Linux
# ---------------------------------------------------------------------------

# Do NOT 'set -e': a failing collector must never abort the whole run.
set -o pipefail 2>/dev/null || true

VERSION="1.10.0"
# 'tool' in summary.json MUST be identical on every platform: 'platform' is the
# discriminator, so a "(Linux)" suffix here breaks grouping by tool name in any
# dashboard that ingests both editions. The edition stays visible to humans via
# TOOL_DISPLAY (banner, help, report and chain of custody).
TOOL="TATAR Triage Toolkit"
TOOL_DISPLAY="$TOOL (Linux)"

# Field separator for the findings pipeline. MUST be non-whitespace: bash 'read'
# collapses consecutive whitespace-IFS delimiters, which would drop empty fields
# (empty detail/technique/suppressReason) and shift every column after them.
FSEP="$(printf '\037')"   # ASCII Unit Separator (0x1F)
# Separator for the elements INSIDE one array-valued column (paths). A finding
# record stays one flat line, so an array needs a second level of separation.
# Deliberately not JSON-in-a-column: modules write raw bytes and exactly one
# place turns them into JSON (_emit_findings_json). Moving escaping into the
# modules would spread the one thing that must never be wrong across all of
# them. Both separators are stripped from every collected string in
# add_finding, so host data cannot inject a column or an array element.
GSEP="$(printf '\035')"   # ASCII Group Separator (0x1D)

# Evidence correlation rules: ruleId|name|modulesA|modulesB|what the agreement
# means. Deliberately FEW and NAMED -- a generic "anything that co-occurs" pass
# would relabel coincidence as evidence. A rule fires only when two findings
# from DIFFERENT modules name the SAME path. The Windows edition also carries
# COR-01 (download-then-execute); Mark-of-the-Web has no Linux equivalent, so
# there is nothing here to mirror, and that asymmetry is declared in
# .github/scripts/check_docs_parity.py rather than left to be discovered.
CORRELATION_RULES="COR-02|autorun-on-suspect-file|persistence|indicators|an autorun entry points at a file that is itself suspect"

# The module currently running, recorded on every finding it raises so an
# analyst can tell which collector made the claim. Set by the dispatch loop.
CURRENT_MODULE=""

# --quick: the highest-signal subset, for the case this tool exists for - a
# responder on a host they want to be off again quickly. Chosen by MEASUREMENT
# on this edition, not by taste:
#
#   every module below          0.10 - 0.27s each   (~1.3s for the whole set)
#   suid                        4.05s               excluded: find / -xdev
#
# It answers "is something wrong on this host". It does NOT answer "how did it
# get here" - that is what --all is for. Saying which question a profile
# answers is more useful than listing what it leaves out.
#
# NOTE the asymmetry with the Windows edition, which excludes `indicators`:
# there that module walks temp and appdata for executables and costs 16.9s,
# while here the same name costs 0.27s. The profiles are per-platform because
# the measurements are.
QUICK_MODULES="sysinfo network process sessions users services persistence indicators bashhistory sshkeys"

# ---------------------------------------------------------------------------
# Argument parsing  (-flag / --flag, case-insensitive-ish)
# ---------------------------------------------------------------------------
ALL=0; LIST=0; HELP=0; COMPRESS=0; SILENT=0; DUMP_DELETED=0; DRYRUN=0; QUICK=0
OUTPUT_BASE="/tmp/forensic"; CASE_ID=""; EXAMINER=""
MODULES=""; UNKNOWN=""; ALLOWLIST=""; IOCFILE=""

# A value-taking flag must be followed by an actual value. Without this guard
# 'shift; VAR="$1"' swallowed the NEXT FLAG (or nothing at all): `--all --output`
# left OUTPUT_BASE empty and wrote the evidence tree to "/" on the suspect host,
# and `--output --caseid IR-1` silently dropped the case id. A usage error is
# printed to stderr even under --silent: a cron/SSH run must not exit 1 mutely.
need_val() {  # need_val FLAG_AS_TYPED [NEXT_TOKEN]
    case "${2-}" in
        ''|-*) printf '%s\n' "[x] FATAL: $1 requires a value" >&2; exit 1 ;;
    esac
}

while [ $# -gt 0 ]; do
    raw="$1"
    key="$(printf '%s' "$raw" | sed 's/^--*//' | tr '[:upper:]' '[:lower:]')"
    case "$key" in
        all)         ALL=1 ;;
        quick|fast)  QUICK=1 ;;
        list)        LIST=1 ;;
        help|h|\?)   HELP=1 ;;
        compress)    COMPRESS=1 ;;
        silent|quiet|q) SILENT=1 ;;
        dry-run|dryrun|preview) DRYRUN=1 ;;
        dump-deleted|dumpdeleted) DUMP_DELETED=1 ;;
        modules)     need_val "$raw" "${2-}"; shift; MODULES="$(printf '%s' "$1" | tr ',' ' ')" ;;
        output|outputpath|o) need_val "$raw" "${2-}"; shift; OUTPUT_BASE="$1" ;;
        caseid|case) need_val "$raw" "${2-}"; shift; CASE_ID="$1" ;;
        examiner)    need_val "$raw" "${2-}"; shift; EXAMINER="$1" ;;
        allowlist|allow) need_val "$raw" "${2-}"; shift; ALLOWLIST="$1" ;;
        ioc|iocfile|iocs) need_val "$raw" "${2-}"; shift; IOCFILE="$1" ;;
        *)           UNKNOWN="$UNKNOWN $raw" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Globals / helpers
# ---------------------------------------------------------------------------
ERROR_COUNT=0
OUTDIR=""
REPORT=""
EXECLOG=""
FINDINGS_FILE=""      # FSEP-separated; see add_finding for the column list
LIMITS_FILE=""        # FSEP-separated: module | limitation (see add_note)
STATS_FILE=""         # key \t value

# ---------------------------------------------------------------------------
# Evidence is private; text from the host is data
# ---------------------------------------------------------------------------
# The evidence set holds process command lines, shell histories and key
# metadata. With the default umask it was world-readable (755 / 644), so any
# other account on the machine could read what the collector had gathered.
# Everything this run creates is owner-only; a folder the tool creates is 700.
umask 077

# A terminal acts on control characters: an ESC sequence in a file name can
# clear the screen or rewrite a line of summary.txt while an analyst reads it,
# and a bidirectional override reorders what they see. Anything this tool
# GENERATES has them replaced - '?' inside a finding, the visible form \xNN or
# <U+202E> in the report and the other generated text files. Verbatim copies of
# host files (hosts.txt, histories, configs) are evidence and stay as collected.
san_into() {  # san_into VAR VALUE
    local LC_ALL=C v="$2"
    v=${v//[[:cntrl:]]/?}
    v=${v//$'\xe2\x80\xaa'/?}; v=${v//$'\xe2\x80\xab'/?}; v=${v//$'\xe2\x80\xac'/?}
    v=${v//$'\xe2\x80\xad'/?}; v=${v//$'\xe2\x80\xae'/?}
    v=${v//$'\xe2\x81\xa6'/?}; v=${v//$'\xe2\x81\xa7'/?}; v=${v//$'\xe2\x81\xa8'/?}; v=${v//$'\xe2\x81\xa9'/?}
    printf -v "$1" '%s' "$v"
}
SAN_SED=""
for _c in 01 02 03 04 05 06 07 08 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 7f; do
    SAN_SED="${SAN_SED}s/\\x${_c}/\\\\x${_c}/g;"
done
for _c in 80,aa,202A 80,ab,202B 80,ac,202C 80,ad,202D 80,ae,202E 81,a6,2066 81,a7,2067 81,a8,2068 81,a9,2069; do
    _b1="${_c%%,*}"; _rest="${_c#*,}"; _b2="${_rest%%,*}"; _cp="${_rest#*,}"
    SAN_SED="${SAN_SED}s/\\xe2\\x${_b1}\\x${_b2}/<U+${_cp}>/g;"
done
unset _c _b1 _b2 _rest _cp
sanitize_stream() { LC_ALL=C tr -d '\000' | LC_ALL=C sed -e "$SAN_SED"; }
sanitize_file() {  # sanitize_file PATH : in place, keeps the file's mode
    local f="$1" t
    [ -f "$f" ] || return 0
    t="$(mktmp)"
    if sanitize_stream < "$f" > "$t" 2>/dev/null; then cat "$t" > "$f"; fi
    rm -f "$t"
}

# Every temporary file lives in ONE private directory that is removed on exit
# and on SIGINT / SIGTERM / SIGHUP. Before this, a run left a temp file behind
# in /tmp every time and an interrupted run left all of them.
TATAR_TMP=""
mktmp() { mktemp "${TATAR_TMP:-${TMPDIR:-/tmp}}/t.XXXXXX"; }
cleanup_tmp() {
    [ -n "${TATAR_TMP:-}" ] && rm -rf "$TATAR_TMP" 2>/dev/null
    # an interrupted run still leaves partial evidence: keep it private
    [ -n "${OUTDIR:-}" ] && [ -d "$OUTDIR" ] && chmod -R go-rwx "$OUTDIR" 2>/dev/null
    return 0
}

c_out() {   # console output, suppressed by --silent
    [ "$SILENT" -eq 1 ] && return 0
    local _m; san_into _m "$1"
    printf '%s\n' "$_m"
}

now() { date '+%Y-%m-%d %H:%M:%S'; }
now_ms() { date '+%Y-%m-%d %H:%M:%S.%3N' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S'; }
iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

execlog() {  # execlog LEVEL MESSAGE
    [ -z "$EXECLOG" ] && return 0
    local _lm; san_into _lm "$2"
    printf '[%s] [%-6s] %s\n' "$(now_ms)" "$1" "$_lm" >> "$EXECLOG"
}

report() { printf '%s\n' "$1" >> "$REPORT"; }
section() { printf '\n===== %s =====\n\n' "$1" >> "$REPORT"; }

# A NOTE is an expected condition that means the module did LESS than its
# section header claims - not an error, so it must not change the exit code,
# but not invisible either. The Windows edition has carried these as Add-Note
# for releases; recording them in one place makes the whole set machine-readable
# through summary.moduleLimitations. Schema 1.3 refused to put this on every
# finding because it describes a MODULE, not a finding; this is that field at
# the level it belongs to.
add_note() {  # add_note MESSAGE
    local msg; san_into msg "$1"
    execlog "WARN" "$msg"
    # A note raised before any module starts - "not running as root" is the
    # big one - used to be filed under an EMPTY module name. It then grouped
    # under a blank key in summary.json and was dropped entirely from
    # paste.txt, which is the one place a reader most needs to see it.
    [ -n "${LIMITS_FILE:-}" ] && printf '%s\037%s\n' "${CURRENT_MODULE:-(run)}" "$(printf '%s' "$msg" | tr '\t\n\035\037' '    ')" >> "$LIMITS_FILE"
    return 0
}

add_err() {  # add_err MESSAGE
    ERROR_COUNT=$((ERROR_COUNT+1))
    local _em; san_into _em "$1"
    printf '[%s] ERROR: %s\n' "$(now)" "$_em" >> "$REPORT"
    execlog "ERROR" "$_em"
}

add_stat() { printf '%s\t%s\n' "$1" "$2" >> "$STATS_FILE"; }

# Centralized MITRE ATT&CK mapping - keep all technique logic in ONE place.
map_technique() {  # map_technique CATEGORY MESSAGE -> space-separated technique IDs
    local c="$1" m="$2"
    case "$c" in
        network)     echo "T1565.001" ;;
        process)     case "$m" in *DELETED*) echo "T1620 T1070.004";; *) echo "T1059";; esac ;;
        sessions)    echo "T1110" ;;
        users)       case "$m" in *"UID 0"*) echo "T1136 T1078";; *) echo "T1078";; esac ;;
        persistence) echo "T1053.003" ;;
        suid)        echo "T1548.001" ;;
        sshkeys)     echo "T1098.004" ;;
        bashhistory) echo "T1552.003" ;;
        indicators)  case "$m" in *writable*) echo "T1222.002";; *) echo "T1036";; esac ;;
        context)     echo "T1610" ;;
        *)           echo "" ;;
    esac
}

# Artifact classes: `category` says which module raised a finding, artifactClass
# says what the evidence IS. Different axes - `persistence` covers cron, systemd
# units, rc files and shell profiles at once, so a rule written against the
# category cannot aim at one of them. Same vocabulary the Windows edition uses,
# held to it by check_docs_parity.py; the list is closed so a typo cannot invent
# a class no rule will ever match.
ARTIFACT_CLASSES="account admin-group bash-history cron deleted-binary dns-cache hosts-file ioc-match logon-failure network-connection package process-commandline service ssh-key suid temp-executable unknown writable-path"

recommendation_for() {  # recommendation_for CATEGORY -> one static next step (schema 1.8)
    # Same text as Get-Recommendation in Tatar.ps1; tests/fixtures/recommendations.tsv is the shared reference.
    case "$1" in
        process) printf '%s' "Check the image path, signature, parent process and network connections; hash the binary and look it up before ending the process." ;;
        persistence) printf '%s' "Find who created the entry and when, hash what it launches, and compare it with a known-good build before removing it." ;;
        privesc) printf '%s' "Confirm a standard user can write to the path or setting; fix the permissions or quote the path, then re-scan to confirm it is gone." ;;
        lateral) printf '%s' "Identify the source host and account, check the matching logon events from the same time, and look for the same tool on other hosts." ;;
        rmm) printf '%s' "Ask the owner whether this remote-management tool is approved; if not, record when and by which account it was installed before removing it." ;;
        useractivity) printf '%s' "Ask the user whether they ran it; check where the file came from and when it first appeared." ;;
        obfscan) printf '%s' "Decode the script in a safe place without running it; look for download commands, encoded payloads and where the file came from." ;;
        indicators) printf '%s' "Hash the file, check where it came from and when it was created, and compare it with your allowlist before treating it as hostile." ;;
        motw) printf '%s' "Check where the download came from and whether it was opened or run afterwards." ;;
        network) printf '%s' "Compare the entry with what this host is meant to use; unexpected overrides can redirect traffic." ;;
        sessions) printf '%s' "List the source addresses and target accounts in the logon events and check whether any attempt later succeeded." ;;
        users) printf '%s' "Confirm the account is expected, who created it and when; set a password or disable the account if it is not needed." ;;
        eventlogs) printf '%s' "Check whether the log was cleared or stopped on purpose and compare it with a copy forwarded to a collector." ;;
        suid) printf '%s' "Verify the file against the package manager and confirm it is meant to carry the setuid bit." ;;
        sshkeys) printf '%s' "Confirm each key belongs to a known person or system and check when authorized_keys last changed." ;;
        bashhistory) printf '%s' "Read the surrounding commands and timestamps for downloads, credential use and cleanup." ;;
        context) printf '%s' "Confirm whether this host is meant to run containers or is inside one; review mounted paths and privileges." ;;
        ioc) printf '%s' "A match from your own indicator list; confirm it is not a coincidence, then search other hosts for the same indicator." ;;
        *) printf '%s' "Review the evidence section named in this finding and confirm with the owner whether it is expected." ;;
    esac
}

map_artifact_class() {  # map_artifact_class CATEGORY "MESSAGE DETAIL"
    local c="$1" t="$2"
    case "$c" in
        persistence) case "$t" in *cron*|*Cron*) echo "cron";; *) echo "service";; esac ;;
        process)     case "$t" in *DELETED*|*deleted*) echo "deleted-binary";; *) echo "process-commandline";; esac ;;
        users)       case "$t" in *sudo*|*wheel*|*admin*) echo "admin-group";; *) echo "account";; esac ;;
        network)     case "$t" in *hosts*) echo "hosts-file";; *DNS*|*resolv*) echo "dns-cache";; *) echo "network-connection";; esac ;;
        indicators)  case "$t" in *writable*) echo "writable-path";; *) echo "temp-executable";; esac ;;
        sessions)    echo "logon-failure" ;;
        suid)        echo "suid" ;;
        sshkeys)     echo "ssh-key" ;;
        bashhistory) echo "bash-history" ;;
        packages)    echo "package" ;;
        ioc)         echo "ioc-match" ;;
        *)           echo "unknown" ;;
    esac
}

FIND_SEQ=0
add_finding() {  # add_finding SEVERITY CATEGORY MESSAGE DETAIL [TECHNIQUE(s)]
    local sev="$1" cat="$2" msg="$3" det="$4" tech="${5:-}"
    # Strip both record separators as well as tab/newline: these strings come
    # from the suspect host, so a crafted filename must not be able to add a
    # column or an array element to the record.
    msg=$(printf '%s' "$msg" | tr '\t\n\035\037' '    ')
    det=$(printf '%s' "$det" | tr '\t\n\035\037' '    ')
    # control and bidirectional characters from the host: see san_into
    san_into msg "$msg"; san_into det "$det"
    [ -z "$tech" ] && tech="$(map_technique "$cat" "$msg")"
    local id conf
    # An unknown severity used to become confidence 0.3 in silence - a value no
    # collector emits and both test suites reject. Fail at the call site instead
    # of shipping a finding the contract does not allow.
    case "$sev" in
        High)   conf=0.7 ;;
        Review) conf=0.4 ;;
        *)      printf "add_finding: unknown severity '%s' (expected High or Review)\n" "$sev" >&2; return 1 ;;
    esac
    FIND_SEQ=$((FIND_SEQ+1))
    id=$(printf 'TTR-F-%03d' "$FIND_SEQ")
    # columns (FSEP-delimited):
    #   id | sev | cat | msg | det | tech | conf | module | collected_at | class
    local acls
    acls="$(map_artifact_class "$cat" "$msg $det")"
    # Closed vocabulary, same reason the severity above is closed: a class
    # nobody declared is a class no allowlist or IOC rule will ever match, and
    # it would reach a SIEM before anyone noticed.
    case " $ARTIFACT_CLASSES " in
        *" $acls "*) : ;;
        *) printf "add_finding: unknown artifactClass '%s'\n" "$acls" >&2; acls="unknown" ;;
    esac
    printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
        "$id" "$sev" "$cat" "$msg" "$det" "$tech" "$conf" "$CURRENT_MODULE" "$(iso)" "$acls" >> "$FINDINGS_FILE"
}

# Why a finding carries the confidence it does. The number is derived, so the
# reason is derived with it - stating it in the record is what makes the number
# auditable instead of a magic constant the consumer has to look up.
conf_reason() {  # $1 = confidence
    case "$1" in
        0.95) printf '%s' "an indicator from the supplied IOC feed matched this finding (see iocIndicator)" ;;
        0.85) printf '%s' "two independent artifacts named the same path (the correlation pass overwrites this with the rule that fired)" ;;
        0.7)  printf '%s' "severity High: a strong lead on its own, but the tool did not confirm it" ;;
        0.4)  printf '%s' "severity Review: the pattern also occurs in benign configurations" ;;
        *)    printf '%s' "" ;;
    esac
}

# --- Allowlist helpers (Linux trust signals: path glob, sha256, package owner) ---
al_extract_items() {  # $1=json key -> newline-separated values from $ALLOWLIST
    [ -n "$ALLOWLIST" ] && [ -r "$ALLOWLIST" ] || return 0
    if have python3; then
        python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8-sig"))  # utf-8-sig: a file saved with a BOM is still JSON
    for x in d.get(sys.argv[2],[]):
        print(x)
except Exception:
    pass' "$ALLOWLIST" "$1" 2>/dev/null
    else
        # crude fallback: pull quoted strings from the "key": [ ... ] array
        sed -n "/\"$1\"[[:space:]]*:[[:space:]]*\[/,/]/p" "$ALLOWLIST" 2>/dev/null \
          | grep -oE '"[^"]*"' | sed 's/^"//; s/"$//' | grep -vx "$1"
    fi
}

pkg_owns() {  # $1=path -> 0 if the file belongs to an installed system package
    local p="$1"
    [ -n "$p" ] && [ -e "$p" ] || return 1
    if have dpkg-query && dpkg-query -S "$p" >/dev/null 2>&1; then return 0; fi
    if have dpkg && dpkg -S "$p" >/dev/null 2>&1; then return 0; fi
    if have rpm && rpm -qf "$p" >/dev/null 2>&1; then return 0; fi
    return 1
}

al_paths_of() {  # $1=msg $2=detail -> EVERY absolute path token, one per line
    # The suppression pass has to see all of them: judging a finding by a single
    # token let `dpkg -S /tmp` allowlist an aggregate about files in /tmp.
    printf '%s %s' "$1" "$2" | grep -oE '/[A-Za-z0-9_.+-][A-Za-z0-9_./+-]*' | awk '!seen[$0]++'
}

al_path_of() {  # $1=msg $2=detail -> best absolute path token
    # A finding can mention several paths ("/tmp/x runs from /usr/bin/foo"). Taking
    # the first one blindly hashed or globbed the wrong file, so prefer a token
    # that exists on disk and fall back to the first one.
    local toks first p
    toks="$(al_paths_of "$1" "$2")"
    [ -n "$toks" ] || return 0
    first="$(printf '%s\n' "$toks" | head -n1)"
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if [ -e "$p" ]; then printf '%s' "$p"; return 0; fi
    done <<EOF
$toks
EOF
    printf '%s' "$first"
}

feed_problem() {  # feed_problem FILE KIND -> a reason on stdout when the file cannot work, nothing when it can
    have python3 || return 0
    python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8-sig"))
except Exception:
    print("not valid JSON"); sys.exit()
if not isinstance(d,dict):
    print("the top level is not a JSON object"); sys.exit()
if sys.argv[2]=="IOC file":
    n=0
    for k in ("hashes","ips","domains","filenames"):
        v=d.get(k)
        if isinstance(v,list): n+=sum(1 for x in v if isinstance(x,str) and x.strip())
    if n==0: print("it holds no indicator in hashes, ips, domains or filenames")' "$1" "$2" 2>/dev/null
}
json_array_items() {  # $1=file $2=key -> newline-separated array values
    [ -n "$1" ] && [ -r "$1" ] || return 0
    if have python3; then
        python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8-sig"))  # utf-8-sig: a file saved with a BOM is still JSON
    for x in d.get(sys.argv[2],[]):
        print(x)
except Exception:
    pass' "$1" "$2" 2>/dev/null
    else
        sed -n "/\"$2\"[[:space:]]*:[[:space:]]*\[/,/]/p" "$1" 2>/dev/null \
          | grep -oE '"[^"]*"' | sed 's/^"//; s/"$//' | grep -vx "$2"
    fi
}

# Evidence correlation. One artifact is a lead; two independent artifacts
# naming the SAME path is a different statement, and the tool used to throw it
# away. A top-level function rather than inline code so tests/test-correlation.sh
# can lift and exercise it against synthetic findings without running a
# collection -- the same technique tests/test-json-escape.sh uses.
#
# Input : $1 = the augmented findings file (F2), 15 FSEP-separated columns.
# Output: the number of findings raised, on stdout. The file is rewritten in
#         place; only columns 7 (confidence) and 14 (confidenceReason) change.
#
# Runs LAST, after the allowlist (column 8) and after IOC matching (column 10),
# skipping both: a suppressed path was already judged known-good, so correlating
# on it would re-raise exactly the noise the allowlist removed, and an IOC hit
# already carries 0.95. Severity is the analyst's scale and is never touched,
# nothing is merged away, and nothing is invented -- correlation makes an
# existing lead more credible, it does not make a new claim.
correlate_findings() {
    local f2="$1" count=0
    if [ -s "$f2" ]; then
        local CORR_HIT; CORR_HIT="$(mktmp)"
        awk -F"$FSEP" -v GS="$GSEP" -v RULES="$CORRELATION_RULES" -v OFS="$FSEP" '
            {
                if ($8 == "true" || $10 == "true") next
                n = split($13, P, GS)
                for (i = 1; i <= n; i++) {
                    if (P[i] == "") continue
                    # NOT lowercased: Linux paths are case-sensitive, so
                    # /tmp/x and /Tmp/X are different files and folding them
                    # would correlate two unrelated findings. The Windows
                    # edition lowercases for the opposite reason.
                    k = P[i]; cnt[k]++
                    pid[k, cnt[k]] = $1; pmod[k, cnt[k]] = $11; pn[k] = cnt[k]
                }
            }
            END {
                nrules = split(RULES, RL, "\n")
                for (r = 1; r <= nrules; r++) {
                    if (RL[r] == "") continue
                    split(RL[r], Fld, "|")
                    na = split(Fld[3], A, " "); nb = split(Fld[4], B, " ")
                    for (k in pn) {
                        for (a = 1; a <= pn[k]; a++) {
                            oka = 0; for (x = 1; x <= na; x++) if (pmod[k, a] == A[x]) oka = 1
                            if (!oka) continue
                            for (b = 1; b <= pn[k]; b++) {
                                okb = 0; for (y = 1; y <= nb; y++) if (pmod[k, b] == B[y]) okb = 1
                                if (!okb) continue
                                # different findings from different modules: a
                                # module agreeing with itself is one artifact
                                # seen twice, not two artifacts agreeing.
                                if (pid[k, a] == pid[k, b]) continue
                                if (pmod[k, a] == pmod[k, b]) continue
                                print pid[k,a], Fld[1], Fld[2], pmod[k,a], pmod[k,b], pid[k,b], k, Fld[5]
                                print pid[k,b], Fld[1], Fld[2], pmod[k,b], pmod[k,a], pid[k,a], k, Fld[5]
                            }
                        }
                    }
                }
            }
        ' "$f2" > "$CORR_HIT"
        if [ -s "$CORR_HIT" ]; then
            local F2d CORR_DONE; F2d="$(mktmp)"; CORR_DONE="$(mktmp)"
            awk -F"$FSEP" -v OFS="$FSEP" -v DONE="$CORR_DONE" '
                NR == FNR {
                    if (!($1 in seen)) {
                        seen[$1] = 1; rid[$1] = $2; rnm[$1] = $3
                        ma[$1] = $4; mb[$1] = $5; oid[$1] = $6; pk[$1] = $7; rsn[$1] = $8
                    }
                    next
                }
                {
                    if (($1 in seen) && ($7 + 0 < 0.85)) {
                        # counted HERE, not from the candidate list: a second
                        # run still produces candidates but changes nothing, and
                        # reporting those as raised would make the execution log
                        # lie about what the pass did.
                        print $1 > DONE
                        $7 = "0.85"
                        $14 = rnm[$1] " (" rid[$1] "): " rsn[$1] " - " ma[$1] " and " mb[$1] \
                              " name the same path " pk[$1] " (see " oid[$1] ")"
                    }
                    print
                }
            ' "$CORR_HIT" "$f2" > "$F2d"
            mv "$F2d" "$f2"
            count=$( [ -s "$CORR_DONE" ] && sort -u "$CORR_DONE" | wc -l | tr -d ' ' || echo 0 )
            rm -f "$CORR_DONE" 2>/dev/null
        fi
        rm -f "$CORR_HIT" 2>/dev/null
    fi

    printf '%s' "$count"
}

# ---------------------------------------------------------------------------
#  Artifact dictionary  (parity with the Windows edition's $script:Artifacts)
# ---------------------------------------------------------------------------
# What each output IS, what question it answers, and what opens it. A responder
# who has just run the tool asks "collected - now what?", and the evidence
# folder did not answer that. Format: glob|class|question|next tool.
#
# Hand-maintained, so it is gated against a REAL RUN: write_artifact_index
# matches every produced file against these globs and prints the count it could
# not place. CI fails on a non-zero count, which means a module that starts
# writing a new file breaks the build rather than shipping it unexplained.
ARTIFACT_INDEX='summary.json|triage summary (structured)|what the run found, machine-readable|SIEM / SOAR ingest; schema/summary.schema.json
findings.json|findings only (structured)|the leads, without the rest of the summary|SIEM / SOAR ingest; schema/findings.schema.json
summary.txt|triage summary (human)|the same findings, to read now|read directly - start here
TATAR_Report_*.txt|full collection report|everything every module collected, in order|read directly; grep by section number
tatar.log|execution log|what the collector did, and what it could NOT do|read directly - check this before trusting an empty section
ARTIFACTS.md|this index|what is in this folder and what opens it|you are reading it
paste.txt|pasteable summary|the whole run in under 60 lines, to show someone|paste into a ticket or chat. Stable between runs, so diff two of them to see what changed on the host
allowlist.suggested.json|allowlist draft|what a baseline for this host would look like|review EVERY line, delete what you cannot vouch for, then pass it to --allowlist
manifest_sha256.txt|integrity manifest|has anything in this folder changed since collection|sha256sum -c manifest_sha256.txt
chain_of_custody.txt|chain of custody|who collected this, where and when|read directly; attach to the case file
timeline.csv|timeline|what happened in what order|any CSV viewer
binary_hashes.txt|binary hashes|which binaries were running, by SHA-256|an internal hash reputation service (offline: compare to a known-good baseline)
logs/*|copied system logs|the raw login and system logs as they were on the host|last/lastb for wtmp/btmp; read the text logs directly
extracted_binaries/*|recovered deleted binary|the on-disk image of a process whose file was unlinked|a sandbox or a static analyser - treat as live malware'

# paste.txt: the whole run in under 60 lines, to paste into a ticket or chat.
# Written to be STABLE between runs on an unchanged host - sorted by severity
# then category then message, no durations, no counters, and process ids
# normalised, because a pid changes on every reboot and would make a diff of
# two paste logs report a restart as a change on the host. Two lines differ by
# design and say so. Parity with the Windows edition's Write-PasteLog.
write_paste_log() {  # $1 = F2
    local f2="$1" out="$OUTDIR/paste.txt" act hi
    act=$(awk -F"$FSEP" '$8 != "true"' "$f2" 2>/dev/null | wc -l | tr -d ' ')
    hi=$(awk -F"$FSEP" '$8 != "true" && $2 == "High"' "$f2" 2>/dev/null | wc -l | tr -d ' ')
    {
        printf 'TATAR %s | %s | %s | root=%s\n' "$VERSION" "$(hostname 2>/dev/null)" \
               "$( ( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-linux}" ) )" \
               "$( [ "$(id -u)" -eq 0 ] && echo true || echo false )"
        printf 'collected %s\n' "$(iso)"
        printf '(two lines differ between runs by design: this one and the sha256 at the end -\n'
        printf ' everything between them is stable, so a diff of two paste logs shows what\n'
        printf ' changed on the HOST, not what the clock did)\n'
        [ -n "$CASE_ID$EXAMINER" ] && printf 'case=%s examiner=%s\n' "$CASE_ID" "$EXAMINER"
        printf '\nFINDINGS: %s active (%s High) - leads for review, NOT verdicts\n\n' "$act" "$hi"
        awk -F"$FSEP" -v OFS='' '
            $8 != "true" {
                tag = ($2 == "High") ? "H" : "R"
                sev = ($2 == "High") ? 0 : 1
                msg = $4
                gsub(/\(PID [0-9]+\)/, "(PID n)", msg)
                gsub(/\(pid [0-9]+\)/, "(pid n)", msg)
                if (length(msg) > 150) msg = substr(msg, 1, 150) "..."
                printf "%d\t%s\t%s\t%s [%-12s] %s\n", sev, $3, msg, tag, $3, msg
            }' "$f2" 2>/dev/null | sort -t"$(printf '\t')" -k1,1n -k2,2 -k3,3 | cut -f4- | head -n 45
        local total
        total=$(awk -F"$FSEP" '$8 != "true"' "$f2" 2>/dev/null | wc -l | tr -d ' ')
        [ "${total:-0}" -gt 45 ] && printf '... and %s more - see summary.txt\n' "$((total-45))"
        # Counted first: a LIMITS_FILE holding only a blank line printed the
        # header with nothing under it, which reads as "nothing was missed"
        # followed by silence - the opposite of what this section is for.
        if [ "$(grep -c . "$LIMITS_FILE" 2>/dev/null || echo 0)" -gt 0 ]; then
            printf '\nNOT COLLECTED (so absence of evidence here is not evidence of absence):\n'
            while IFS="$FSEP" read -r lmod llim; do
                [ -n "$lmod" ] || continue
                printf '  - %s: %s\n' "$lmod" "$(printf '%s' "$llim" | cut -c1-110)"
            done < "$LIMITS_FILE"
        fi
        printf '\n'
        [ -f "$OUTDIR/findings.json" ] && printf 'sha256(findings.json) = %s\n' \
            "$(sha256sum "$OUTDIR/findings.json" 2>/dev/null | cut -d' ' -f1)"
        printf 'Full evidence folder: see ARTIFACTS.md for what each file is.\n'
    } > "$out" 2>/dev/null
    execlog "INFO" "paste.txt written"
    return 0
}

# allowlist.suggested.json: this host's finding paths as an allowlist DRAFT, in
# the format --allowlist already reads. Nothing is judged; the comment says so.
write_suggested_allowlist() {  # $1 = F2
    local f2="$1" out="$OUTDIR/allowlist.suggested.json" first=1
    {
        printf '{\n  "_comment": "%s",\n  "paths": [' \
            "$(json_escape "DRAFT generated by TATAR $VERSION from $(hostname 2>/dev/null) on $(iso). NOT an allowlist yet: it lists every path this host's findings named, with nothing judged. Review every line and delete what you cannot vouch for BEFORE using it with --allowlist - a baseline taken from a host nobody checked will suppress exactly the compromise you were looking for. Intended use: take it from a known-good build, trim it, and run the fleet against it so only the differences show.")"
        awk -F"$FSEP" -v GS="$GSEP" '$8 != "true" { n = split($13, P, GS); for (i=1;i<=n;i++) if (P[i] != "") print P[i] }' "$f2" 2>/dev/null \
            | sort -u | while read -r pth; do
                [ -n "$pth" ] || continue
                [ "$first" -eq 1 ] && first=0 || printf ','
                printf '\n    "%s"' "$(json_escape "$pth")"
            done
        printf '\n  ],\n  "publishers": [],\n  "hashes": [],\n  "packageOwned": false\n}\n'
    } > "$out" 2>/dev/null
    execlog "INFO" "allowlist.suggested.json written"
    return 0
}

# Writes ARTIFACTS.md from the files ACTUALLY produced, so it describes this run
# rather than the tool in general. The last line is machine-checkable on purpose.
write_artifact_index() {
    local idx="$OUTDIR/ARTIFACTS.md" rel cls q nx line hit uncat=0 n
    local tmp; tmp="$(mktmp)"
    {
        printf '# Artifacts in this folder\n\n'
        printf 'Host: %s  |  Collected: %s  |  TATAR %s\n\n' "$(hostname 2>/dev/null)" "$(iso)" "$VERSION"
        printf 'Start with `summary.txt`. If a section looks empty, read `tatar.log` before\n'
        printf 'concluding that nothing was there - it records what the collector could not reach.\n\n'
        printf '| What | Files | Answers | Open it with |\n|---|---|---|---|\n'
    } > "$tmp"
    ( cd "$OUTDIR" 2>/dev/null && find . -type f 2>/dev/null | sed 's|^\./||' | sort ) > "$tmp.files"
    # one row per class, counted - first glob wins, so the table is ordered
    # specific-before-general exactly as the Windows table is.
    printf '%s\n' "$ARTIFACT_INDEX" | while IFS='|' read -r glob cls q nx; do
        [ -n "$glob" ] || continue
        n=0
        while read -r rel; do
            [ -n "$rel" ] || continue
            grep -qxF "$rel" "$tmp.claimed" 2>/dev/null && continue
            case "$rel" in
                $glob) printf '%s\n' "$rel" >> "$tmp.claimed"; n=$((n+1)); last="$rel" ;;
            esac
        done < "$tmp.files"
        if [ "$n" -gt 0 ]; then
            if [ "$n" -eq 1 ]; then printf '| %s | `%s` | %s | %s |\n' "$cls" "$last" "$q" "$nx" >> "$tmp"
            else printf '| %s | %s files | %s | %s |\n' "$cls" "$n" "$q" "$nx" >> "$tmp"; fi
        fi
    done
    uncat=0
    if [ -s "$tmp.files" ]; then
        comm -23 "$tmp.files" <(sort -u "$tmp.claimed" 2>/dev/null || true) > "$tmp.uncat" 2>/dev/null || cp "$tmp.files" "$tmp.uncat"
        uncat=$(wc -l < "$tmp.uncat" | tr -d ' ')
    fi
    {
        printf '\nWritten before `manifest_sha256.txt` and the tail of `tatar.log`, so those two\n'
        printf 'are described above but may not yet have existed when this index was built.\n'
        if [ "${uncat:-0}" -gt 0 ]; then
            printf '\n## Uncatalogued\n\nThese files were produced but no entry in the artifact dictionary claims them.\nThat is a gap in the tool'"'"'s documentation, not in the evidence:\n\n'
            head -n 40 "$tmp.uncat" | while read -r rel; do printf -- '- `%s`\n' "$rel"; done
        fi
        printf '\nUncatalogued: %s\n' "${uncat:-0}"
    } >> "$tmp"
    cp "$tmp" "$idx" 2>/dev/null
    execlog "INFO" "Artifact index written: ${uncat:-0} uncatalogued"
    [ "${uncat:-0}" -gt 0 ] && add_note "${uncat} produced file(s) are not described in the artifact dictionary - see ARTIFACTS.md"
    rm -f "$tmp" "$tmp.files" "$tmp.claimed" "$tmp.uncat" 2>/dev/null
    return 0
}

# Makes one CSV cell safe to open in a spreadsheet. Two separate problems:
#
#   1. A cell beginning with =, +, @ or - is a FORMULA in Excel, LibreOffice
#      and Google Sheets. A file named  =cmd|'/c calc'!A1.txt  on the suspect
#      host becomes code that runs on the ANALYST's machine when they open
#      timeline.csv. A leading apostrophe is the documented fix.
#   2. A double quote inside a quoted field must be doubled, or the field ends
#      early and every column after it shifts. The previous printf did not do
#      this, so a file name containing " silently corrupted the rest of the row.
#
# A negative NUMBER is left alone: -1 is not a formula and quoting it would
# corrupt real data.
csv_cell() {
    local v="$1"
    case "$v" in
        [=+@]*|"	"*) v="'$v" ;;
        -*) case "$v" in
                -[0-9]*) case "$v" in *[!0-9.,-]*) v="'$v" ;; esac ;;
                *) v="'$v" ;;
            esac ;;
    esac
    printf '%s' "$(printf '%s' "$v" | sed 's/"/""/g')"
}

hosts_entry() {  # hosts_entry LINE -> "address -> name [name ...]"
    # The line is text from the suspect host and lands in a finding's detail,
    # which the path extractor, the allowlist and the IOC pass all read. A
    # crafted line naming /usr/sbin/sshd would otherwise put a trusted binary
    # into paths[] and let an allowlist rule suppress the finding that reports
    # the tampering. Each field is reduced to the characters it can legally
    # contain, so no slash, backslash, quote or control character survives.
    # Same rule and same output as Format-HostsEntry in the Windows edition.
    local line="${1%%#*}" addr rest s
    line="${line%$'\r'}"
    read -r addr rest <<EOF
$line
EOF
    [ -n "$addr" ] || return 0
    addr=$(printf '%s' "$addr" | LC_ALL=C tr -c '0-9A-Fa-f:.' '?')
    rest=$(printf '%s' "$rest" | tr '\t' ' ' | tr -s ' ' | LC_ALL=C tr -c 'A-Za-z0-9._ -' '?')
    [ -n "$rest" ] || rest="(no name)"
    s="$addr -> $rest"
    # A hosts line may carry hundreds of aliases; the report has the full file.
    if [ "${#s}" -gt 100 ]; then s="${s:0:100}..."; fi
    printf '%s' "$s"
}

hosts_is_default() {  # hosts_is_default LINE OWNNAME -> exit 0 if LINE is a stock entry
    # A line is stock only if its ADDRESS is one of the well-known ones AND
    # every name on it is a name that address ships with. The previous test was
    # a grep for the loopback addresses ANYWHERE on the line, which counted a
    # clean Debian/Ubuntu file as four custom entries (the ip6-* lines) and, in
    # the other direction, hid `203.0.113.9 login.bank.example 127.0.0.1` and
    # `fe80::1 attacker-router.example` because they merely CONTAIN "127.0.0.1"
    # and "::1". Anchoring on the address alone would still hide
    # `127.0.0.1 update.vendor.example` - a sinkhole that stops a machine
    # reaching its own update server - so the names are checked as well.
    #
    # Names for 127.0.1.1 are matched against THIS host's own name with no
    # lookup: `hostname -f` can send a DNS query from the machine under
    # examination. Same rule, same table, as Test-HostsDefault on Windows.
    local line="${1%%#*}" own="${2:-}" addr rest n allowed
    local -a names=()
    line="${line%$'\r'}"
    read -r addr rest <<EOF
$line
EOF
    [ -n "$addr" ] || return 0
    addr=$(printf '%s' "$addr" | tr 'A-Z' 'a-z')
    own=$(printf '%s' "$own" | tr 'A-Z' 'a-z')
    read -r -a names <<EOF
$(printf '%s' "$rest" | tr 'A-Z' 'a-z')
EOF
    [ "${#names[@]}" -gt 0 ] || return 1
    if [ "$addr" = "127.0.1.1" ]; then
        [ -n "$own" ] || return 1
        for n in "${names[@]}"; do
            case "$n" in "$own"|"$own".*) : ;; *) return 1 ;; esac
        done
        return 0
    fi
    case "$addr" in
        127.0.0.1)    allowed=" localhost localhost.localdomain localhost4 localhost4.localdomain4 " ;;
        ::1)          allowed=" localhost localhost.localdomain localhost6 localhost6.localdomain6 ip6-localhost ip6-loopback " ;;
        fe00::0|fe00::) allowed=" ip6-localnet " ;;
        ff00::0|ff00::) allowed=" ip6-mcastprefix " ;;
        ff02::1)      allowed=" ip6-allnodes " ;;
        ff02::2)      allowed=" ip6-allrouters " ;;
        ff02::3)      allowed=" ip6-allhosts " ;;
        *)            return 1 ;;
    esac
    for n in "${names[@]}"; do
        case "$allowed" in *" $n "*) : ;; *) return 1 ;; esac
    done
    return 0
}

# Boundary-aware IOC match. Plain substring matching used to let "127.0.0" match
# 127.0.0.1 and "ocalhost" match localhost, raising false High findings. awk keeps
# this portable: GNU grep -P is not available everywhere.
ioc_match() {  # ioc_match TEXT TOKEN -> exit 0 on a boundary-aligned hit
    [ -n "$2" ] || return 1
    printf '%s' "$1" | awk -v tok="$2" '
    function isdig(c) { return (c >= "0" && c <= "9") }
    function isw(c)   { return ((c >= "0" && c <= "9") || (c >= "a" && c <= "z") || c == "_") }
    function ishex(c) { return (isdig(c) || (c >= "a" && c <= "f")) }
    {
        text = tolower($0); t = tolower(tok); n = length(t)
        ipv4 = (t ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
        ipv6 = (!ipv4 && t ~ /^[0-9a-f:]+$/ && index(t, ":") > 0)
        start = 1
        while ((p = index(substr(text, start), t)) > 0) {
            p = p + start - 1
            before = (p > 1) ? substr(text, p - 1, 1) : ""
            after  = substr(text, p + n, 1)
            ok = 1
            if (ipv4) {
                # Only a digit or a dot can extend an IPv4 address. A colon must
                # NOT block the match: netstat and most logs write addr:port, so
                # treating ":" as part of the address made IPv4 unmatchable.
                if (before != "" && (isdig(before) || before == ".")) ok = 0
                if (after  != "" && (isdig(after)  || after  == ".")) ok = 0
            } else if (ipv6) {
                if (before != "" && (ishex(before) || before == "." || before == ":")) ok = 0
                if (after  != "" && (ishex(after)  || after  == "." || after  == ":")) ok = 0
            } else {
                if (before != "" && (isw(before) || before == "." || before == "-")) ok = 0
                if (after  != "" && (isw(after)  || after  == "-")) ok = 0
                if (after == "." && isw(substr(text, p + n + 1, 1))) ok = 0
            }
            if (ok) { found = 1; exit }
            start = p + 1
        }
    }
    END { exit(found ? 0 : 1) }'
}

# An IOC's ATT&CK technique depends on WHAT matched. Tagging a filename or a
# hash hit as T1071 (application layer protocol) was simply wrong, and a wrong
# mapping is worse than no mapping at all.
ioc_technique() {  # ioc_technique INDICATOR -> ATT&CK id
    if   printf '%s\n' "${IOC_IPS:-}"   | grep -qxF -- "$1"; then printf 'T1071'
    elif printf '%s\n' "${IOC_DOMS:-}"  | grep -qxF -- "$1"; then printf 'T1071.004'
    elif printf '%s\n' "${IOC_FILES:-}" | grep -qxF -- "$1"; then printf 'T1204.002'
    else printf 'T1588.001'
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }
bounded() {  # bounded SECONDS COMMAND... : run with a time limit when timeout exists
    local secs="$1"; shift
    if have timeout; then timeout "$secs" "$@"; else "$@"; fi
}

# Execution-context detection (container / virtualization / LSM). Best-effort.
ENV_VIRT="unknown"; ENV_CONTAINER=false; ENV_RUNTIME="none"; ENV_SECMOD="none"
detect_environment() {
    have systemd-detect-virt && ENV_VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
    [ -f /.dockerenv ] && { ENV_CONTAINER=true; ENV_RUNTIME="docker"; }
    if grep -qaE 'kubepods' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; ENV_RUNTIME="kubernetes"
    elif grep -qaE 'libpod' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; ENV_RUNTIME="podman"
    elif grep -qaE 'docker|containerd' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; [ "$ENV_RUNTIME" = none ] && ENV_RUNTIME="docker"
    elif grep -qaE '/lxc/' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; ENV_RUNTIME="lxc"; fi
    case "$ENV_VIRT" in
        docker) ENV_CONTAINER=true; ENV_RUNTIME="docker" ;;
        podman) ENV_CONTAINER=true; ENV_RUNTIME="podman" ;;
        lxc|lxc-libvirt) ENV_CONTAINER=true; ENV_RUNTIME="lxc" ;;
    esac
    if have getenforce; then ENV_SECMOD="selinux-$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    elif have aa-status || [ -d /sys/kernel/security/apparmor ]; then ENV_SECMOD="apparmor"; fi
}

# JSON string escaper (arg -> escaped, no surrounding quotes).
#
# Three paths, in cost order:
#   1. nothing needs escaping  -> return the string, no fork at all
#   2. python3 present         -> json.dumps, the reference implementation
#   3. no python3              -> awk, which must be correct on its own
#
# Path 1 exists because this used to fork a python3 per field (~13ms each,
# six per finding): a run with 200 findings spent ~15s escaping strings that
# contained nothing to escape.
#
# Path 3 used to be a sed/tr pipeline that escaped only \ and " and passed
# every other control character through untouched. A 0x07 or 0x1B byte in a
# filename on the suspect host - attacker-controlled input, on a forensic
# tool - was therefore enough to emit INVALID JSON and break every downstream
# parser. It now escapes the whole C0 range.
#
# Note: every call site is "$(json_escape ...)", and command substitution
# strips trailing newlines, so a trailing newline cannot survive on any path.
# Embedded newlines are escaped correctly.
json_escape() {
    case "$1" in
        *\\*|*\"*|*[[:cntrl:]]*) : ;;
        *) printf '%s' "$1"; return 0 ;;
    esac
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null && return 0
    printf '%s' "$1" | LC_ALL=C awk '
        function esc(s,   i, n, c, o) {
            n = length(s); o = ""
            for (i = 1; i <= n; i++) {
                c = substr(s, i, 1)
                if      (c == "\\") o = o "\\\\"
                else if (c == "\"") o = o "\\\""
                else if (c == "\t") o = o "\\t"
                else if (c == "\r") o = o "\\r"
                else if (c == "\b") o = o "\\b"
                else if (c == "\f") o = o "\\f"
                else if (index(CTRL, c)) o = o sprintf("\\u%04x", ORD[c])
                else o = o c
            }
            return o
        }
        BEGIN {
            ORS = ""; first = 1
            for (i = 1; i < 32; i++) { c = sprintf("%c", i); ORD[c] = i; CTRL = CTRL c }
        }
        { if (!first) printf "\\n"; first = 0; printf "%s", esc($0) }
    '
}

banner() {
    [ "$SILENT" -eq 1 ] && return 0
    # The ASCII art keeps its quoted heredoc so the backslashes stay literal;
    # the title line is printed separately so it follows $TOOL_DISPLAY and
    # $VERSION. It used to hard-code both "(Linux)" and "v1.2.5", which made
    # the banner the one header in this script a version bump leaves stale.
    cat <<'EOF'

   _____  _    _____  _    ____
  |_   _|/ \  |_   _|/ \  |  _ \
    | | / _ \   | | / _ \ | |_) |
    | |/ ___ \  | |/ ___ \|  _ <
    |_/_/   \_\ |_/_/   \_\_| \_\

+==============================================================+
EOF
    printf '|   %-59s|\n' "${TOOL_DISPLAY^^}   v$VERSION"
    cat <<'EOF'
|   Fast DFIR triage / artifact collector                      |
|   Transparent - review, sign & allow-list; do not evade      |
+==============================================================+
EOF
}

show_help() {
cat <<EOF
$TOOL_DISPLAY v$VERSION

USAGE:
  sudo ./tatar-linux.sh --quick                   Highest-signal subset, seconds (see --list)
  sudo ./tatar-linux.sh --all                     Run all modules (order of volatility)
  sudo ./tatar-linux.sh --modules network,process Run selected modules
  sudo ./tatar-linux.sh --all --dry-run           Preview the plan; write nothing
  ./tatar-linux.sh --list                         List available modules
  ./tatar-linux.sh --help                         Show this help

OPTIONS:
  --output <path>   Output base dir (default /tmp/forensic; PREFER external media)
  --caseid <id>     Case / incident id for chain of custody
  --examiner <name> Examiner name for chain of custody
  --compress        tar.gz + SHA-256 the output at the end
  --silent|--quiet  No console output (for SSH/cron/remote runs)
  --dry-run         Show output dir, module order, gated ops and feed verdicts,
                    then exit 0 without creating or writing anything. Alias: --preview
  --allowlist <json> Suppress known-good findings (paths[], hashes[], packageOwned)
  --ioc <json>      Match findings/evidence vs IOCs (hashes[], ips[], domains[], filenames[])
  --dump-deleted    Recover deleted running binaries via /proc/PID/exe (opt-in; off by default)

OUTPUT (always written):
  summary.txt / summary.json   Analyst-first triage summary + aggregated findings
  tatar.log                    Timestamped execution log (START/OK/WARN/FAILED)
  manifest_sha256.txt          SHA-256 of every collected file
  chain_of_custody.txt

EXIT CODES:  0 = success | 1 = fatal / usage error | 2 = completed with errors

NOTES:
  * A value-taking flag rejects a missing value: --output with no path exits 1.
  * Run as root for complete collection.
  * Do NOT reboot the host before collection finishes.
  * Findings are review LEADS, not verdicts - validate against the full report.
EOF
}

# ---------------------------------------------------------------------------
# Collector modules  (order of volatility)
# ---------------------------------------------------------------------------

m_sysinfo() {
    section "01 System information"
    { echo "Hostname : $(hostname 2>/dev/null)"
      echo "Date     : $(date)"
      echo "Uptime   : $(uptime 2>/dev/null)"
      echo "Kernel   : $(uname -a)"
      echo "TimeZone : $( (timedatectl 2>/dev/null | grep -i 'time zone') || cat /etc/timezone 2>/dev/null)"
    } >> "$REPORT"
    if [ -r /etc/os-release ]; then echo "--- /etc/os-release ---" >> "$REPORT"; cat /etc/os-release >> "$REPORT" 2>/dev/null; fi
    have lscpu && { echo "--- lscpu ---" >> "$REPORT"; lscpu >> "$REPORT" 2>/dev/null; }
    free -h >> "$REPORT" 2>/dev/null
    df -h  >> "$REPORT" 2>/dev/null
    return 0
}

m_network() {
    section "02 Network (connections, listening, routes, DNS)"
    local rc=0
    if have ss; then
        echo "--- ss -tunap (all sockets, with PID) ---" >> "$REPORT"
        ss -tunap >> "$REPORT" 2>/dev/null
        local lc; lc=$(ss -tlnp 2>/dev/null | grep -c LISTEN)
        add_stat "ListeningTcpPorts" "${lc:-0}"
        local ec; ec=$(ss -tuna 2>/dev/null | grep -c ESTAB)
        add_stat "EstablishedConnections" "${ec:-0}"
    elif have netstat; then
        echo "--- netstat -tunap ---" >> "$REPORT"; netstat -tunap >> "$REPORT" 2>/dev/null
    elif have lsof; then
        echo "--- lsof -i -nP (network connections) ---" >> "$REPORT"; lsof -i -nP >> "$REPORT" 2>/dev/null
    else
        report "No ss/netstat/lsof available - the socket table was NOT collected."
        rc=1
    fi
    { echo "--- ip addr ---"; ip addr 2>/dev/null || ifconfig -a 2>/dev/null; } >> "$REPORT"
    { echo "--- ip route ---"; ip route 2>/dev/null || route -n 2>/dev/null; } >> "$REPORT"
    { echo "--- arp / neighbours ---"; ip neigh 2>/dev/null || arp -a 2>/dev/null; } >> "$REPORT"
    for f in /etc/resolv.conf /etc/hosts; do
        [ -r "$f" ] && { echo "--- $f ---" >> "$REPORT"; cat "$f" >> "$REPORT" 2>/dev/null; }
    done
    if [ -r /etc/hosts ]; then
        local hx=0 hl hn=0 hsum="" hown
        hown="$(hostname 2>/dev/null)"
        # The count alone made the analyst open the report to learn anything.
        # Name the first few overrides in the finding itself, so the address and
        # the host name it captures are visible in the summary and reachable by
        # the IOC pass. What counts as "custom" is decided by hosts_is_default.
        while IFS= read -r hl || [ -n "$hl" ]; do
            hosts_is_default "$hl" "$hown" && continue
            hx=$((hx+1))
            if [ "$hn" -lt 5 ]; then hsum="${hsum:+$hsum ; }$(hosts_entry "$hl")"; hn=$((hn+1)); fi
        done < /etc/hosts
        if [ "$hx" -gt 0 ]; then
            add_finding "Review" "network" "/etc/hosts has $hx custom entries" "First $hn of $hx: $hsum | Review /etc/hosts in report - static host overrides can redirect traffic (T1565.001)"
        fi
    fi
    report "Sockets, addresses, routes, neighbours, resolver and hosts are in this report (no separate files)."
    return $rc
}

m_process() {
    section "03 Processes (+ suspicious execution locations)"
    ps auxww >> "$REPORT" 2>/dev/null
    local pc; pc=$(ps -e --no-headers 2>/dev/null | wc -l); add_stat "Processes" "${pc:-0}"
    echo "" >> "$REPORT"; echo "-- Process tree --" >> "$REPORT"
    (ps -ejH 2>/dev/null || ps axf 2>/dev/null) >> "$REPORT"
    echo "" >> "$REPORT"; echo "-- /proc exe analysis --" >> "$REPORT"
    local pid exe cmd
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
        [ -z "$exe" ] && continue
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        case "$exe" in
            *"(deleted)"*)
                echo "[!] PID $pid deleted-binary exe: $exe | cmd: $cmd" >> "$REPORT"
                add_finding "High" "process" "Running process from a DELETED binary (PID $pid)" "$exe | cmd: $cmd"
                # Parity with the Windows edition's gated modules: what was NOT
                # collected has to reach moduleLimitations, not only the report.
                # A deleted running binary is the one artifact that disappears
                # the moment the process exits, so "we did not take a copy"
                # is exactly the kind of gap an analyst must be told about.
                if [ "$DUMP_DELETED" -ne 1 ]; then
                    add_note "the deleted binary behind PID $pid was NOT recovered: --dump-deleted was not supplied, and it is gone once the process exits"
                fi
                if [ "$DUMP_DELETED" -eq 1 ]; then
                    dd_dir="$OUTDIR/extracted_binaries"; mkdir -p "$dd_dir" 2>/dev/null
                    if cp "/proc/$pid/exe" "$dd_dir/pid_${pid}_recovered" 2>/dev/null; then
                        echo "[i] Recovered deleted binary -> extracted_binaries/pid_${pid}_recovered" >> "$REPORT"
                        execlog "INFO" "Recovered deleted binary from PID $pid (--dump-deleted)"
                    fi
                fi
                ;;
            /tmp/*|/dev/shm/*|/var/tmp/*|/run/*)
                echo "[!] PID $pid exe in volatile/world-writable path: $exe | cmd: $cmd" >> "$REPORT"
                add_finding "High" "process" "Process executing from suspicious path (PID $pid)" "$exe | cmd: $cmd" ;;
        esac
    done
    echo "" >> "$REPORT"; echo "-- Command lines that look like a shell or a pipe-to-shell --" >> "$REPORT"
    # Read from /proc/PID/cmdline with shell matching, not from `ps | grep`: a grep
    # would match its own command line. The collector's own process tree is skipped
    # so the patterns in this file can never produce a finding about themselves.
    local cpid cppid hop skip cl rsdev='/dev/'
    for cpid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        [ "$cpid" -eq "$$" ] 2>/dev/null && continue
        skip=0; cppid="$cpid"; hop=0
        while [ "$hop" -lt 12 ] && [ -n "$cppid" ] && [ "$cppid" -gt 1 ] 2>/dev/null; do
            [ "$cppid" -eq "$$" ] && { skip=1; break; }
            cppid=$(awk '/^PPid:/ {print $2; exit}' "/proc/$cppid/status" 2>/dev/null)
            hop=$((hop + 1))
        done
        [ "$skip" -eq 1 ] && continue
        cl=$(tr '\0' ' ' < "/proc/$cpid/cmdline" 2>/dev/null) || continue
        [ -n "$cl" ] || continue
        if [[ "$cl" == *"${rsdev}tcp/"* || "$cl" == *"${rsdev}udp/"* ]] || [[ "$cl" =~ (^|[[:space:]/])(nc|ncat|netcat)[[:space:]].*-e[[:space:]] ]] \
           || [[ "$cl" =~ bash[[:space:]]+-i[[:space:]]*\>\& ]] || [[ "$cl" =~ (curl|wget)[^\|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh([[:space:]]|$) ]] \
           || [[ "$cl" =~ base64[[:space:]]+(-d|--decode).*\|[[:space:]]*(ba|z|da)?sh([[:space:]]|$) ]] || [[ "$cl" =~ mkfifo.*(nc|ncat)[[:space:]] ]]; then
            echo "[!] PID $cpid command line: $cl" >> "$REPORT"
            add_finding "Review" "process" "Process command line looks like a reverse shell or pipe-to-shell (PID $cpid)" "cmd: $cl" "T1059.004"
        fi
    done
    echo "" >> "$REPORT"; echo "-- Suspicious command-line patterns (ps) --" >> "$REPORT"
    local pat
    for pat in 'nc -e' 'ncat' '/dev/tcp/' 'bash -i' 'python -c' 'perl -e' 'base64 -d' 'xmrig' 'kinsing' 'kdevtmpfsi'; do
        ps auxww 2>/dev/null | grep -iE "$pat" | grep -v 'grep' >> "$REPORT" 2>/dev/null
    done
    # "no suspicious pattern" is grep exit 1: return the module's status, not it.
    return 0
}

m_sessions() {
    section "04 Logins & sessions (who, last, failed)"
    { echo "-- who --"; who 2>/dev/null; echo "-- w --"; w 2>/dev/null; } >> "$REPORT"
    { echo "-- last (recent logins) --"; last -n 50 2>/dev/null; } >> "$REPORT"
    echo "-- lastb (failed logins) --" >> "$REPORT"
    local fb; fb=$(lastb -n 200 2>/dev/null)
    printf '%s\n' "$fb" >> "$REPORT"
    local fc; fc=$(printf '%s\n' "$fb" | grep -cE 'tty|pts|ssh')
    add_stat "RecentFailedLogons" "${fc:-0}"
    [ "${fc:-0}" -ge 50 ] && add_finding "Review" "sessions" "High volume of failed logins: ${fc}+ in lastb" "Possible brute force - review source IPs in report section 04"
    local al=""
    [ -r /var/log/auth.log ] && al=/var/log/auth.log
    [ -z "$al" ] && [ -r /var/log/secure ] && al=/var/log/secure
    if [ -n "$al" ]; then
        echo "-- $al (accepted/failed/sudo, last 200) --" >> "$REPORT"
        grep -iE 'accepted|failed password|sudo:|new user|useradd' "$al" 2>/dev/null | tail -n 200 >> "$REPORT"
    elif have journalctl; then
        echo "-- journalctl sshd (last 200) --" >> "$REPORT"
        journalctl _COMM=sshd -n 200 --no-pager 2>/dev/null >> "$REPORT"
    fi
    return 0
}

m_users() {
    section "05 Users, groups, sudo"
    for f in /etc/passwd /etc/group; do [ -r "$f" ] && { echo "--- $f ---" >> "$REPORT"; cat "$f" >> "$REPORT"; }; done
    echo "--- sudoers ---" >> "$REPORT"
    cat /etc/sudoers 2>/dev/null >> "$REPORT"
    cat /etc/sudoers.d/* 2>/dev/null >> "$REPORT"
    if [ -r /etc/passwd ]; then
        local uc; uc=$(wc -l < /etc/passwd); add_stat "Accounts" "${uc:-0}"
        awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | while read -r u; do
            [ "$u" != "root" ] && add_finding "High" "users" "Non-root account with UID 0: $u" "Second UID-0 account = full root privileges (backdoor account)"
        done
        echo "--- accounts with login shell ---" >> "$REPORT"
        awk -F: '($7 ~ /(bash|sh|zsh|ksh)$/){print $1" "$7}' /etc/passwd >> "$REPORT" 2>/dev/null
    fi
    if [ -r /etc/shadow ]; then
        awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do
            add_finding "High" "users" "Account with EMPTY password: $u" "Login with no password possible - see /etc/shadow"
        done
    else
        report "(/etc/shadow not readable - run as root for empty-password check)"
    fi
    return 0
}

m_services() {
    section "06 Services / units"
    if have systemctl; then
        echo "-- running services --" >> "$REPORT"
        systemctl list-units --type=service --state=running --no-pager --no-legend >> "$REPORT" 2>/dev/null
        echo "-- enabled unit files --" >> "$REPORT"
        systemctl list-unit-files --state=enabled --no-pager --no-legend >> "$REPORT" 2>/dev/null
        local sc; sc=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l)
        add_stat "RunningServices" "${sc:-0}"
    elif have service; then
        service --status-all >> "$REPORT" 2>/dev/null
    else
        ls -la /etc/init.d 2>/dev/null >> "$REPORT"
    fi
    return 0
}

m_persistence() {
    section "07 Persistence (cron, systemd timers, rc, profiles)"
    echo "-- system crontab & cron dirs --" >> "$REPORT"
    for f in /etc/crontab /etc/cron.d/* ; do [ -r "$f" ] && { echo "[$f]" >> "$REPORT"; cat "$f" >> "$REPORT"; }; done
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] && { echo "[$d]" >> "$REPORT"; ls -la "$d" >> "$REPORT" 2>/dev/null; }
    done
    echo "-- per-user crontabs --" >> "$REPORT"
    for cdir in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$cdir" ] && find "$cdir" -type f 2>/dev/null | while read -r cf; do echo "[$cf]" >> "$REPORT"; cat "$cf" >> "$REPORT" 2>/dev/null; done
    done
    grep -rhiE 'curl|wget|/dev/tcp/|base64|nc |ncat|python -c|bash -i' /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null | while read -r line; do
        add_finding "Review" "persistence" "Suspicious cron command" "$line"
    done
    # Cron entries and systemd units that start something from a folder anyone can write to.
    local cl tdir ufile
    grep -rhE '(^|[[:space:]=])(/tmp/|/dev/shm/|/var/tmp/)' /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n 20 | while read -r cl; do
        add_finding "Review" "persistence" "Cron entry runs a program from a temporary directory" "$cl"
    done
    for tdir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /root/.config/systemd/user /home/*/.config/systemd/user; do
        [ -d "$tdir" ] || continue
        grep -rHE '^(ExecStart|ExecStartPre|ExecStartPost)=[-@+!]*[^#]*(/tmp/|/dev/shm/|/var/tmp/)' "$tdir" 2>/dev/null | head -n 20 | while read -r ufile; do
            add_finding "Review" "persistence" "systemd unit starts a program from a temporary directory" "$ufile" "T1543.002"
        done
    done
    echo "-- at jobs --" >> "$REPORT"
    have atq && bounded 10 atq >> "$REPORT" 2>/dev/null
    ls -la /var/spool/at /var/spool/cron/atjobs 2>/dev/null >> "$REPORT"
    echo "-- ld.so.preload --" >> "$REPORT"
    if [ -r /etc/ld.so.preload ]; then
        cat /etc/ld.so.preload >> "$REPORT" 2>/dev/null
        local lp; lp=$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')
        [ -n "$lp" ] && add_finding "High" "persistence" "/etc/ld.so.preload loads a library into every program" "$lp| a preload entry is a classic rootkit hook (T1574.006); confirm the library belongs to a package" "T1574.006"
    else
        report "(/etc/ld.so.preload does not exist or is not readable)"
    fi
    echo "-- shell startup files (patterns) --" >> "$REPORT"
    local sf
    for sf in /etc/bash.bashrc /etc/profile /etc/profile.d/* /root/.bashrc /root/.profile /root/.bash_profile /root/.zshrc /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.zshrc; do
        [ -f "$sf" ] && [ -r "$sf" ] || continue
        grep -HniE '(curl|wget)[^|#]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+(-d|--decode)|/dev/tcp/|(nc|ncat)[[:space:]].*-e[[:space:]]' "$sf" 2>/dev/null | head -n 5 | while read -r cl; do
            echo "[!] $cl" >> "$REPORT"
            add_finding "Review" "persistence" "Suspicious command in a shell startup file" "$cl" "T1546.004"
        done
    done
    echo "-- known_hosts (count per home) --" >> "$REPORT"
    for sf in /root/.ssh/known_hosts /home/*/.ssh/known_hosts; do
        [ -r "$sf" ] && echo "$sf: $(grep -c . "$sf" 2>/dev/null) entries" >> "$REPORT"
    done
    echo "-- systemd timers --" >> "$REPORT"
    have systemctl && systemctl list-timers --all --no-pager --no-legend >> "$REPORT" 2>/dev/null
    echo "-- rc.local / init --" >> "$REPORT"
    for f in /etc/rc.local /etc/rc.d/rc.local; do [ -r "$f" ] && { echo "[$f]" >> "$REPORT"; cat "$f" >> "$REPORT"; }; done
    echo "-- shell profile scripts --" >> "$REPORT"
    for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do [ -r "$f" ] && echo "[$f] ($(stat -c '%y' "$f" 2>/dev/null))" >> "$REPORT"; done
    return 0
}

m_apps() {
    section "08 Installed packages"
    if have dpkg; then dpkg -l >> "$REPORT" 2>/dev/null
    elif have rpm; then rpm -qa >> "$REPORT" 2>/dev/null
    else
        report "No dpkg/rpm found - the installed-package list was NOT collected."
        return 1
    fi
    return 0
}

m_suid() {
    section "09 SUID / SGID binaries"
    # ONE walk of the file system, not two: the walk is what takes the time, and a
    # host with a large tree paid for it twice. Only the matching files are stat'ed.
    local all mode path list="" sgid=""
    all=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec stat -c '%a %n' {} + 2>/dev/null)
    while IFS=' ' read -r mode path; do
        [ -n "$path" ] || continue
        case "$mode" in *[!0-7]*) continue ;; esac
        [ $(( 8#$mode & 8#4000 )) -ne 0 ] && list="${list}${path}"$'\n'
        [ $(( 8#$mode & 8#2000 )) -ne 0 ] && sgid="${sgid}${path}"$'\n'
    done <<< "$all"
    list="${list%$'\n'}"; sgid="${sgid%$'\n'}"
    echo "-- SUID --" >> "$REPORT"
    printf '%s\n' "$list" >> "$REPORT"
    echo "-- SGID --" >> "$REPORT"
    printf '%s\n' "$sgid" >> "$REPORT"
    printf '%s\n' "$list" | grep -vE '^/(usr/bin|bin|usr/sbin|sbin|usr/lib|lib|usr/libexec)/' | grep -E '.' | while read -r s; do
        [ -n "$s" ] && add_finding "Review" "suid" "SUID binary outside standard paths: $s" "Unusual SUID location can indicate privilege-escalation backdoor (T1548.001)"
    done
    return 0
}

m_sshkeys() {
    section "10 SSH keys & config"
    echo "-- sshd_config (key settings) --" >> "$REPORT"
    grep -iE 'permitrootlogin|passwordauthentication|authorizedkeysfile|^port |permitemptypasswords' /etc/ssh/sshd_config 2>/dev/null >> "$REPORT"
    echo "-- authorized_keys across homes --" >> "$REPORT"
    local ak
    for h in /root /home/*; do
        ak="$h/.ssh/authorized_keys"
        if [ -r "$ak" ]; then
            echo "[$ak] ($(wc -l < "$ak" 2>/dev/null) keys, modified $(stat -c '%y' "$ak" 2>/dev/null))" >> "$REPORT"
            cat "$ak" >> "$REPORT" 2>/dev/null
            [ "$h" = "/root" ] && add_finding "Review" "sshkeys" "root has authorized_keys ($(wc -l < "$ak" 2>/dev/null) entries)" "Verify these keys are expected - unexpected key = remote backdoor (T1098.004)"
        fi
    done
    return 0
}

m_bashhistory() {
    section "11 Shell history"
    local hf
    for h in /root /home/*; do
        for hf in "$h/.bash_history" "$h/.zsh_history" "$h/.ash_history"; do
            if [ -r "$hf" ]; then
                echo "[$hf]" >> "$REPORT"; cat "$hf" >> "$REPORT" 2>/dev/null; echo "" >> "$REPORT"
                grep -hiE 'wget|curl|nc |ncat|/dev/tcp/|base64|chmod \+x|chattr|history -c|useradd|passwd ' "$hf" 2>/dev/null | while read -r line; do
                    add_finding "Review" "bashhistory" "Notable history command in ${hf##*/}" "$line"
                done
            fi
        done
    done
    return 0
}

m_kernelmods() {
    section "12 Kernel modules"
    have lsmod && lsmod >> "$REPORT" 2>/dev/null
    echo "-- tainted state --" >> "$REPORT"
    cat /proc/sys/kernel/tainted 2>/dev/null >> "$REPORT"
    return 0
}

m_indicators() {
    section "13 Suspicious indicators"
    echo "-- world-writable files in system dirs --" >> "$REPORT"
    find /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/local/lib -xdev -type f -perm -0002 2>/dev/null | while read -r f; do
        echo "[!] world-writable: $f" >> "$REPORT"
        add_finding "Review" "indicators" "World-writable system file: $f" "System binaries/config should not be world-writable"
    done
    echo "-- sudoers NOPASSWD --" >> "$REPORT"
    local sdf sdn=0 sdl
    for sdf in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$sdf" ] || continue
        if [ -r "$sdf" ]; then
            sdn=$((sdn + 1))
            grep -E 'NOPASSWD' "$sdf" 2>/dev/null | grep -vE '^[[:space:]]*#' | while read -r sdl; do
                echo "[$sdf] $sdl" >> "$REPORT"
                add_finding "Review" "users" "sudoers grants NOPASSWD in ${sdf##*/}" "$sdl" "T1548.003"
            done
        fi
    done
    [ "$sdn" -eq 0 ] && add_note "sudoers was NOT readable (needs root): NOPASSWD rules were not checked"
    echo "-- firewall rules --" >> "$REPORT"
    # Every external command below is bounded: lastlog walks a sparse file that is
    # enormous on hosts with very large user ids, and the firewall tools can wait on a lock.
    if have nft; then bounded 20 nft list ruleset 2>&1 | head -n 200 >> "$REPORT"; fi
    if have iptables; then bounded 20 iptables -S 2>&1 | head -n 200 >> "$REPORT"; fi
    if have ufw; then bounded 20 ufw status 2>&1 | head -n 100 >> "$REPORT"; fi
    echo "-- last logins (lastlog) --" >> "$REPORT"
    have lastlog && bounded 20 lastlog 2>/dev/null | grep -v 'Never logged in' | head -n 200 >> "$REPORT"
    echo "-- executables in /tmp /dev/shm /var/tmp --" >> "$REPORT"
    local tc=0 d tl tfirst="" shown
    for d in /tmp /dev/shm /var/tmp; do
        [ -d "$d" ] || continue
        # one find per directory, not two: the report listing, the counter and
        # the finding detail all come from the same result set.
        tl="$(find "$d" -xdev -type f -perm -111 ! -path "$OUTPUT_BASE/*" ! -path "$OUTDIR/*" ! -path "$TATAR_TMP/*" 2>/dev/null)"
        [ -n "$tl" ] || continue
        printf '%s\n' "$tl" >> "$REPORT"
        tc=$((tc + $(printf '%s\n' "$tl" | grep -c '^/')))
        tfirst="$(printf '%s\n%s\n' "$tfirst" "$tl" | grep -E '^/' | head -n 10)"
    done
    add_stat "ExecInTempDirs" "${tc:-0}"
    if [ "${tc:-0}" -gt 0 ]; then
        # The paths have to be INSIDE the finding: the allowlist and IOC engines
        # only ever see message+detail, so an aggregate that named no file could
        # not be matched by a path glob, a hash or package ownership.
        shown="$(printf '%s' "$tfirst" | grep -c '^/')"
        add_finding "Review" "indicators" "${tc} executable file(s) in /tmp,/dev/shm,/var/tmp" \
            "First ${shown} of ${tc}: $(printf '%s' "$tfirst" | tr '\n' ' ')| see report section 13 for all - legitimate installers also appear; validate"
    fi
    echo "-- recently modified files in /etc (7 days) --" >> "$REPORT"
    find /etc -xdev -type f -mtime -7 2>/dev/null | head -n 200 >> "$REPORT"
    echo "-- immutable files (chattr +i) in /etc /root --" >> "$REPORT"
    have lsattr && lsattr -R /etc /root 2>/dev/null | grep -E '^....i' >> "$REPORT"
    # "no immutable files" is grep exit 1: return the module's status, not it.
    return 0
}

m_hashes() {
    section "14 Hash collection (running binaries)"
    local outf="$OUTDIR/binary_hashes.txt"
    : > "$outf"
    local pid exe seen="|"
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
        case "$exe" in ""|*"(deleted)"*) continue;; esac
        case "$seen" in *"|$exe|"*) continue;; esac
        seen="$seen$exe|"
        [ -r "$exe" ] && sha256sum "$exe" 2>/dev/null >> "$outf"
    done
    local hc; hc=$(wc -l < "$outf" 2>/dev/null); add_stat "HashedBinaries" "${hc:-0}"
    report "Hashed ${hc:-0} running binaries -> binary_hashes.txt (feed to VirusTotal / IOC matching)."
    return 0
}

# journalctl, bounded in time: a damaged or huge journal must not stall a run.
jc() { if have timeout; then timeout 40 journalctl "$@"; else journalctl "$@"; fi; }
# jextract FILE ARGS... : the output of journalctl, made safe to read, written only
# when it has content. Returns 1 when there was nothing to write.
jextract() {
    local dest="$1" body; shift
    body=$(jc --no-pager "$@" 2>/dev/null)
    [ -n "$body" ] || return 1
    [ "$body" = "-- No entries --" ] && return 1
    printf '%s\n' "$body" | sanitize_stream > "$dest"
    return 0
}

m_logs() {
    section "15 Key log copy"
    local ld="$OUTDIR/logs"; mkdir -p "$ld" 2>/dev/null
    local f skipped=""
    for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/wtmp /var/log/btmp /var/log/cron; do
        if [ -r "$f" ]; then cp -p "$f" "$ld/" 2>/dev/null
        elif [ -e "$f" ]; then skipped="${skipped:+$skipped }$f"; fi
    done
    [ -n "$skipped" ] && add_note "logs: present but unreadable without root, NOT copied: $skipped"
    report "Copied available key logs to logs/."
    # Distributions that log to the systemd journal only (Kali, current Debian,
    # Ubuntu and Fedora installs) have no auth.log: without these extracts a run
    # on them would hold no sudo, su, login or cron history at all.
    if have journalctl; then
        local jn=0
        jextract "$ld/journal_auth.txt" -o short-iso --since "14 days ago" -n 5000 \
            _COMM=sshd + _COMM=sudo + _COMM=su + _COMM=login + _COMM=systemd-logind + _COMM=cron + _COMM=CRON && jn=$((jn+1))
        jextract "$ld/journal_warnings.txt" -o short-iso -p warning --since "7 days ago" -n 3000 && jn=$((jn+1))
        jextract "$ld/journal_boots.txt" --list-boots && jn=$((jn+1))
        if [ "$jn" -gt 0 ]; then
            report "systemd journal extracts (14 days of auth, 7 days of warnings, boot list): $jn file(s) in logs/."
        elif [ "$IS_ROOT" = false ]; then
            add_note "logs: the systemd journal gave nothing for this user (needs root, or membership of systemd-journal or adm)"
        fi
    fi
    return 0
}

m_timeline() {
    section "16 Timeline (recent file changes, super-timeline lite)"
    local tf="$OUTDIR/timeline.csv"
    echo "MTime,Path,Source" > "$tf"
    find /etc /root /home /usr/local/bin /tmp /var/tmp /dev/shm -xdev -type f -mtime -14 ! -path "$OUTPUT_BASE/*" ! -path "$TATAR_TMP/*" 2>/dev/null | head -n 5000 | while read -r f; do
        printf '"%s","%s","fs"\n' "$(csv_cell "$(stat -c '%y' "$f" 2>/dev/null)")" "$(csv_cell "$f")" >> "$tf"
    done
    local n; n=$(( $(wc -l < "$tf" 2>/dev/null) - 1 )); [ "$n" -lt 0 ] && n=0
    add_stat "TimelineEntries" "$n"
    report "Timeline entries: $n -> timeline.csv"
    return 0
}

m_containers() {
    section "17 Containers & cloud context"
    if [ "$ENV_CONTAINER" = "true" ]; then
        add_finding "Review" "context" "TATAR is running INSIDE a container ($ENV_RUNTIME)" "Collected artifacts reflect the container, not necessarily the host - correlate with host-level triage (T1610)"
    fi
    if have docker; then
        echo "-- docker ps -a --" >> "$REPORT"; docker ps -a --no-trunc >> "$REPORT" 2>/dev/null
        echo "-- docker images --" >> "$REPORT"; docker images >> "$REPORT" 2>/dev/null
        echo "-- docker networks --" >> "$REPORT"; docker network ls >> "$REPORT" 2>/dev/null
        local dc; dc=$(docker ps -q 2>/dev/null | wc -l); add_stat "RunningContainers" "${dc:-0}"
    else
        report "Docker CLI not present / daemon not reachable."
    fi
    if have podman; then
        # podman creates its storage and lock files on first use. Asking a host that
        # never ran a container would write to the host, so only query storage that exists.
        if [ -d "${XDG_DATA_HOME:-$HOME/.local/share}/containers/storage" ] || { [ "$(id -u)" -eq 0 ] && [ -d /var/lib/containers/storage ]; }; then
            echo "-- podman ps -a --" >> "$REPORT"; podman ps -a >> "$REPORT" 2>/dev/null
        else
            report "podman is installed but has no container storage for this user: not queried (querying would create it on the host)."
        fi
    fi
    # No docker/podman on the host is an expected condition, not a failure.
    return 0
}

m_integrity() {
    section "18 Critical file integrity (SHA-256 baseline)"
    local f h skipped=""
    for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/ssh/sshd_config; do
        if [ -r "$f" ]; then
            h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            printf '%s  %s\n' "$h" "$f" >> "$REPORT"
        elif [ -e "$f" ]; then
            skipped="${skipped:+$skipped }$f"
        fi
    done
    if [ -n "$skipped" ]; then
        report "NOT hashed (unreadable without root): $skipped"
        add_note "integrity: not hashed, unreadable without root: $skipped"
    fi
    report "Critical-file hashes recorded (compare across runs to detect tampering)."
    return 0
}

# ---------------------------------------------------------------------------
# Module registry (order of volatility)
# ---------------------------------------------------------------------------
MOD_NAMES="sysinfo network process sessions users services persistence apps suid sshkeys bashhistory kernelmods indicators hashes logs timeline containers integrity"

run_module() {
    case "$1" in
        sysinfo) m_sysinfo ;;
        network) m_network ;;
        process) m_process ;;
        sessions) m_sessions ;;
        users) m_users ;;
        services) m_services ;;
        persistence) m_persistence ;;
        apps) m_apps ;;
        suid) m_suid ;;
        sshkeys) m_sshkeys ;;
        bashhistory) m_bashhistory ;;
        kernelmods) m_kernelmods ;;
        indicators) m_indicators ;;
        hashes) m_hashes ;;
        logs) m_logs ;;
        timeline) m_timeline ;;
        containers) m_containers ;;
        integrity) m_integrity ;;
        *) return 99 ;;
    esac
}

# ---------------------------------------------------------------------------
# Summary writer (unified schema with the Windows edition)
# ---------------------------------------------------------------------------
write_summary() {
    local start_iso="$1" end_iso="$2" mods="$3" is_root="$4" dur="$5" skipped="${6:-}"
    local hn os osv usr fcount TAB
    TAB="$(printf '\t')"
    hn="$(hostname 2>/dev/null)"
    os="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-$(uname -s)}" )"
    osv="$(uname -r)"
    usr="$(id -un 2>/dev/null)"
    fcount=$( [ -s "$FINDINGS_FILE" ] && wc -l < "$FINDINGS_FILE" || echo 0 )

    # ---- Apply allowlist suppression -> augmented findings file F2 ----------
    # F2 columns: id \t sev \t cat \t msg \t det \t tech \t conf \t suppressed \t reason
    local F2; F2="$(mktmp)"
    local sup_count=0
    local AL_PATHS AL_HASHES AL_PKGOWN
    AL_PATHS="$(al_extract_items paths)"
    AL_HASHES="$(al_extract_items hashes | tr 'A-F' 'a-f')"
    AL_PKGOWN=1
    if [ -n "$ALLOWLIST" ] && [ -r "$ALLOWLIST" ] && have python3; then
        AL_PKGOWN="$(python3 -c 'import json,sys
try: print(1 if json.load(open(sys.argv[1],encoding="utf-8-sig")).get("packageOwned",True) else 0)
except Exception: print(1)' "$ALLOWLIST" 2>/dev/null || echo 1)"
    elif [ -n "$ALLOWLIST" ] && [ -r "$ALLOWLIST" ]; then
        # no python3: still honour an explicit "packageOwned": false
        if grep -qE '"packageOwned"[[:space:]]*:[[:space:]]*false' "$ALLOWLIST" 2>/dev/null; then AL_PKGOWN=0; fi
    fi
    if [ -s "$FINDINGS_FILE" ]; then
        local fid fs fc fm fd ft fconf fmod fts facls supp reason paths pathsj path h g
        local tok_ok tok_reason all_ok first_reason
        while IFS="$FSEP" read -r fid fs fc fm fd ft fconf fmod fts facls; do
            supp=false; reason=""
            # The paths a finding names are recorded whether or not an
            # allowlist was supplied: they are the first thing an analyst
            # wants and, when a rule did fire, the only way to audit WHICH
            # files the suppression decision covered. Same extractor the
            # allowlist engine judges with, so the two can never disagree.
            paths="$(al_paths_of "$fm" "$fd")"
            pathsj="$(printf '%s' "$paths" | tr '\n' "$GSEP" | sed "s/${GSEP}*\$//")"
            if [ -n "$ALLOWLIST" ] && [ -r "$ALLOWLIST" ]; then
                # EVERY path the finding names has to be known-good before the
                # finding is hidden. Judging it by one token meant an aggregate
                # naming /tmp was suppressed as "owned by system package"
                # (dpkg -S /tmp -> base-files) no matter what was in /tmp.
                all_ok=0; first_reason=""
                if [ -n "$paths" ]; then
                    all_ok=1
                    while IFS= read -r path; do
                        [ -n "$path" ] || continue
                        tok_ok=0; tok_reason=""
                        # 1) sha256 of the referenced binary
                        if [ -n "$AL_HASHES" ] && [ -r "$path" ] && [ ! -d "$path" ]; then
                            h="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
                            if [ -n "$h" ] && printf '%s\n' "$AL_HASHES" | grep -qix "$h"; then
                                tok_ok=1; tok_reason="allowlist sha256"
                            fi
                        fi
                        # 2) path glob
                        if [ "$tok_ok" = 0 ] && [ -n "$AL_PATHS" ]; then
                            while IFS= read -r g; do
                                [ -n "$g" ] || continue
                                # shellcheck disable=SC2254
                                case "$path" in $g) tok_ok=1; tok_reason="allowlist path: $g"; break ;; esac
                            done <<EOF
$AL_PATHS
EOF
                        fi
                        # 3) owned by an installed system package (Linux trust
                        #    signal). A DIRECTORY never qualifies: every distro
                        #    ships /tmp, /usr/bin and friends, so accepting one
                        #    would trust the container instead of the file.
                        if [ "$tok_ok" = 0 ] && [ "$AL_PKGOWN" = 1 ] && [ ! -d "$path" ]; then
                            if pkg_owns "$path"; then tok_ok=1; tok_reason="owned by system package"; fi
                        fi
                        if [ "$tok_ok" = 0 ]; then all_ok=0; break; fi
                        [ -n "$first_reason" ] || first_reason="$tok_reason"
                    done <<EOF
$paths
EOF
                fi
                if [ "$all_ok" = 1 ]; then supp=true; reason="$first_reason"; fi
            fi
            [ "$supp" = true ] && sup_count=$((sup_count+1))
            # Augmented record, 15 columns. 8-10 (suppressed | suppressReason |
            # iocMatch) keep their positions: the suppressed count is read with
            # awk $8 and every reader below is positional.
            #   1 id   2 sev  3 cat   4 msg          5 det
            #   6 tech 7 conf 8 supp  9 supReason   10 iocMatch
            #  11 module 12 collected_at 13 paths(GSEP) 14 confReason 15 iocIndicator
            #  16 artifactClass
            printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
                "$fid" "$fs" "$fc" "$fm" "$fd" "$ft" "$fconf" "$supp" "$reason" "false" \
                "$fmod" "$fts" "$pathsj" "$(conf_reason "$fconf")" "" "${facls:-unknown}" >> "$F2"
        done < "$FINDINGS_FILE"
    fi

    # ---- IOC matching -----------------------------------------------------
    # Known-bad wins over allowlist: an IOC hit forces High + un-suppresses.
    local ioc_hits=0
    if [ -n "$IOCFILE" ] && [ -r "$IOCFILE" ]; then
        local IOC_HASHES IOC_STR
        IOC_HASHES="$(json_array_items "$IOCFILE" hashes | tr 'A-F' 'a-f' | grep -E '.')"
        # ips + domains + filenames matched as case-insensitive substrings
        IOC_IPS="$(json_array_items "$IOCFILE" ips       | grep -E '.')"
        IOC_DOMS="$(json_array_items "$IOCFILE" domains   | grep -E '.')"
        IOC_FILES="$(json_array_items "$IOCFILE" filenames | grep -E '.')"
        IOC_STR="$( { printf '%s\n' "$IOC_IPS"; printf '%s\n' "$IOC_DOMS"; printf '%s\n' "$IOC_FILES"; } | grep -E '.' )"

        # Pass A: annotate/override existing findings
        local F2b IOC_HIT; F2b="$(mktmp)"; IOC_HIT="$(mktmp)"
        local xid xs xc xm xd xt xconf xsup xreason xioc xmod xts xpaths xcr xind
        local hit path h ind
        while IFS="$FSEP" read -r xid xs xc xm xd xt xconf xsup xreason xioc xmod xts xpaths xcr xind xacls; do
            hit=""
            # string IOCs (ip/domain/filename) in message or detail
            if [ -n "$IOC_STR" ]; then
                while IFS= read -r ind; do
                    [ -n "$ind" ] || continue
                    if ioc_match "$xm $xd" "$ind"; then hit="$ind"; break; fi
                done <<EOF
$IOC_STR
EOF
            fi
            # hash IOC: sha256 of the referenced binary
            if [ -z "$hit" ] && [ -n "$IOC_HASHES" ]; then
                path="$(al_path_of "$xm" "$xd")"
                if [ -n "$path" ] && [ -r "$path" ]; then
                    h="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
                    if [ -n "$h" ] && printf '%s\n' "$IOC_HASHES" | grep -qix "$h"; then hit="$h"; fi
                fi
            fi
            if [ -n "$hit" ]; then
                ioc_hits=$((ioc_hits+1))
                printf '%s\n' "$hit" >> "$IOC_HIT"
                # IOC beats allowlist: re-activate, escalate
                [ "$xsup" = true ] && sup_count=$((sup_count-1))
                xs="High"; xconf="0.95"; xsup="false"; xreason=""; xioc="true"
                # The indicator gets its own column. It stays prefixed into
                # detail as well, because summary.txt and the report are read
                # by humans and only findings.json gains the field.
                xind="$hit"; xcr="$(conf_reason 0.95)"
                xd="IOC match: $hit | $xd"
            fi
            printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
                "$xid" "$xs" "$xc" "$xm" "$xd" "$xt" "$xconf" "$xsup" "$xreason" "$xioc" \
                "$xmod" "$xts" "$xpaths" "$xcr" "$xind" "${xacls:-unknown}" >> "$F2b"
        done < "$F2"
        mv "$F2b" "$F2"

        # Pass B: raise NEW findings for IOCs seen anywhere in the collected report
        # The scan shells out to find/xargs/grep. If that toolchain cannot run at
        # all (a broken PATH entry, a missing or unresolvable grep - plausible on
        # the compromised host this tool is pointed at), a discarded stderr would
        # make the scan report ZERO hits, which is indistinguishable from "no
        # indicators present". T5 exists to stop exactly that class of silent
        # skip for unreadable feeds; the same rule has to hold here. Stderr from
        # the scan is therefore captured, and any of it forces the error exit.
        local val ln bmsg bdet bpaths SCAN_ERR SCAN_BAD
        SCAN_ERR="$(mktmp)"; SCAN_BAD="$(mktmp)"; : > "$SCAN_BAD"
        # Scope parity with the Windows edition: scan every text artifact in the
        # output folder, not just the consolidated report (summary.txt excluded -
        # it is written later and would echo our own findings back).
        if [ -d "$OUTDIR" ]; then
            { printf '%s\n' "$IOC_STR"; printf '%s\n' "$IOC_HASHES"; } | while IFS= read -r val; do
                [ -n "$val" ] || continue
                # skip IOCs already tied to a specific finding in Pass A
                grep -qxF -- "$val" "$IOC_HIT" 2>/dev/null && continue
                # grep pre-filters, ioc_match confirms the hit sits on a boundary
                ln="$(find "$OUTDIR" -type f \( -name '*.txt' -o -name '*.csv' -o -name '*.log' \) \
                        ! -name 'summary.txt' -print0 2>/dev/null \
                      | xargs -0 -r grep -ihF -- "$val" 2>>"$SCAN_ERR" | grep -viE 'IOC match' \
                      | while IFS= read -r cand; do
                            if ioc_match "$cand" "$val"; then printf '%s' "$cand"; break; fi
                        done)"
                if [ -n "$ln" ]; then
                    FIND_SEQ=$((FIND_SEQ+1))
                    bmsg="IOC observed in collected evidence: $val"
                    bdet="$(printf '%s' "$ln" | tr '\t\035\037' '   ' | cut -c1-160)"
                    bpaths="$(al_paths_of "$bmsg" "$bdet" | tr '\n' "$GSEP" | sed "s/${GSEP}*\$//")"
                    printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
                        "$(printf 'TTR-F-%03d' "$FIND_SEQ")" "High" "ioc" \
                        "$bmsg" "$bdet" \
                        "$(ioc_technique "$val")" "0.95" "false" "" "true" \
                        "ioc" "$(iso)" "$bpaths" "$(conf_reason 0.95)" "$val" "ioc-match" >> "$F2"
                fi
            done
        fi
        if [ -s "$SCAN_ERR" ]; then
            add_err "IOC evidence scan could not run, so its result is NOT trustworthy: $(head -n1 "$SCAN_ERR" | cut -c1-160)"
        fi
        rm -f "$IOC_HIT" "$SCAN_ERR" "$SCAN_BAD" 2>/dev/null
    fi

    # ---- evidence correlation (links findings; never merges or creates them) --
    local corr_count=0
    corr_count="$(correlate_findings "$F2")"
    if [ "${corr_count:-0}" -gt 0 ] 2>/dev/null; then
        execlog "INFO" "Evidence correlation: $corr_count finding(s) raised to confidence 0.85"
    fi

    fcount=$( [ -s "$F2" ] && wc -l < "$F2" || echo 0 )
    # Count the suppressed column instead of tracking it arithmetically: the JSON
    # contract (active + suppressed == findings) has to come from the data itself.
    if [ -s "$F2" ]; then
        sup_count=$(awk -F"$FSEP" '$8 == "true"' "$F2" | wc -l | tr -d ' ')
    else
        sup_count=0
    fi
    local active_count=$(( fcount - sup_count ))
    [ "$active_count" -lt 0 ] && active_count=0
    execlog "INFO" "Allowlist: $sup_count suppressed | IOC hits: $ioc_hits | active: $active_count / $fcount"

    local S="$OUTDIR/summary.txt"
    {
        echo "=============================================================="
        echo " $TOOL_DISPLAY v$VERSION - TRIAGE SUMMARY"
        echo "=============================================================="
        echo "Host       : $hn"
        echo "OS         : $os ($osv)"
        echo "User       : $usr"
        echo "Case ID    : $CASE_ID"
        echo "Examiner   : $EXAMINER"
        echo "Started    : $start_iso"
        echo "Finished   : $end_iso"
        echo "Duration   : ${dur}s"
        echo "Privileged : $is_root"
        echo "Environment: virt=$ENV_VIRT container=$ENV_CONTAINER runtime=$ENV_RUNTIME secmod=$ENV_SECMOD"
        echo "Modules    : $mods"
        [ -n "$skipped" ] && echo "SKIPPED    :$skipped (not a module name - NOTHING was collected for it)"
        echo "Errors     : $ERROR_COUNT (see tatar.log)"
        echo ""
        echo "-------------------- QUICK STATS ----------------------------"
        if [ -s "$STATS_FILE" ]; then
            while IFS="$TAB" read -r k v; do printf '  %-24s : %s\n' "$k" "$v"; done < "$STATS_FILE"
        else
            echo "  (no stats collected)"
        fi
        echo ""
        echo "---------- SUSPICIOUS FINDINGS: $active_count active, $sup_count allowlisted (leads, NOT verdicts) ----------"
        if [ -s "$F2" ] && [ "$active_count" -gt 0 ]; then
            for sev in High Review; do
                while IFS="$FSEP" read -r fid fs fc fm fd ft fconf fsup freason fioc fmod fts fpaths fcr find_ facls; do
                    [ "$fs" = "$sev" ] || continue
                    [ "$fsup" = true ] && continue
                    local tag=""; [ "$fioc" = true ] && tag="[IOC] "
                    if [ -n "$ft" ]; then printf '  %s [%s] (%s) [%s] %s%s\n' "$fid" "$fs" "$fc" "$ft" "$tag" "$fm"
                    else printf '  %s [%s] (%s) %s%s\n' "$fid" "$fs" "$fc" "$tag" "$fm"; fi
                    [ -n "$fd" ] && printf '        %s\n' "$fd"
                done < "$F2"
            done
            echo ""
            echo "  NOTE: entries above are automated pattern matches. Legitimate software"
            echo "  and admin activity can appear. Validate each lead against the full"
            echo "  report before drawing conclusions."
        elif [ -s "$F2" ]; then
            echo "  All findings were suppressed by the allowlist (see below). This does"
            echo "  NOT prove the host is clean - review the full report and artifacts."
        else
            echo "  No automatic findings were flagged. This does NOT prove the host is"
            echo "  clean - review the full report and collected artifacts."
        fi
        if [ "$sup_count" -gt 0 ]; then
            echo ""
            echo "-------- SUPPRESSED BY ALLOWLIST: $sup_count (kept for audit) --------"
            while IFS="$FSEP" read -r fid fs fc fm fd ft fconf fsup freason fioc fmod fts fpaths fcr find_ facls; do
                [ "$fsup" = true ] || continue
                printf '  %s [%s] (%s) %s  <- %s\n' "$fid" "$fs" "$fc" "$fm" "$freason"
            done < "$F2"
        fi
        echo ""
        echo "-------------------- NEXT STEPS ------------------------------"
        echo "  1. Review findings against the full report .txt"
        echo "  2. Check tatar.log for FAILED/WARN steps (missing evidence)."
        echo "  3. Submit binary_hashes.txt to VirusTotal / IOC matching."
        echo "  4. Pivot on timeline.csv around confirmed finding timestamps."
    } > "$S"

    local J="$OUTDIR/summary.json"
    {
        printf '{\n'
        printf '  "tool": "%s",\n' "$(json_escape "$TOOL")"
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "schemaVersion": "1.8",\n'
        printf '  "platform": "linux",\n'
        printf '  "host": "%s",\n' "$(json_escape "$hn")"
        printf '  "os": "%s",\n' "$(json_escape "$os")"
        printf '  "osVersion": "%s",\n' "$(json_escape "$osv")"
        printf '  "user": "%s",\n' "$(json_escape "$usr")"
        printf '  "caseId": "%s",\n' "$(json_escape "$CASE_ID")"
        printf '  "examiner": "%s",\n' "$(json_escape "$EXAMINER")"
        printf '  "started": "%s",\n' "$start_iso"
        printf '  "finished": "%s",\n' "$end_iso"
        printf '  "durationSeconds": %s,\n' "${dur:-0}"
        printf '  "privileged": %s,\n' "$is_root"
        printf '  "environment": {"virtualization":"%s","container":%s,"containerRuntime":"%s","securityModule":"%s"},\n' "$(json_escape "$ENV_VIRT")" "$ENV_CONTAINER" "$(json_escape "$ENV_RUNTIME")" "$(json_escape "$ENV_SECMOD")"
        printf '  "errorsLogged": %s,\n' "$ERROR_COUNT"
        # What each module could not do. Written by add_note, so every NOTE the
        # log already carried is now queryable instead of only readable.
        printf '  "moduleLimitations": ['
        local lfirst=1 lmod ltext
        if [ -s "${LIMITS_FILE:-/nonexistent}" ]; then
            while IFS="$FSEP" read -r lmod ltext; do
                [ -n "$ltext" ] || continue
                [ $lfirst -eq 1 ] && lfirst=0 || printf ', '
                printf '{"module":"%s","limitation":"%s"}' "$(json_escape "$lmod")" "$(json_escape "$ltext")"
            done < "$LIMITS_FILE"
        fi
        printf '],\n'
        printf '  "modulesRun": ['
        local first=1 m
        for m in $mods; do [ $first -eq 1 ] && first=0 || printf ', '; printf '"%s"' "$m"; done
        printf '],\n'
        # Requested but never run (unknown module name). Visible to the pipeline,
        # not only to whoever reads the log.
        printf '  "modulesSkipped": ['
        first=1
        for m in $skipped; do [ $first -eq 1 ] && first=0 || printf ', '; printf '"%s"' "$(json_escape "$m")"; done
        printf '],\n'
        # How each requested module ended: ok, warn (it logged errors), failed
        # (its primary artifact was not produced) or skipped (never ran).
        printf '  "moduleStatus": ['
        first=1
        local ms_e ms_m ms_s ms_t ms_n
        for ms_e in ${MODSTATUS:-}; do
            IFS=: read -r ms_m ms_s ms_t ms_n <<EOMS
$ms_e
EOMS
            [ $first -eq 1 ] && first=0 || printf ', '
            printf '{"module":"%s","status":"%s","seconds":%s,"errors":%s}' "$(json_escape "$ms_m")" "$ms_s" "${ms_t:-0}" "${ms_n:-0}"
        done
        printf '],\n'
        printf '  "stats": {'
        if [ -s "$STATS_FILE" ]; then
            first=1
            while IFS="$TAB" read -r k v; do
                [ $first -eq 1 ] && first=0 || printf ','
                # Type parity with the Windows edition, which emits native ints:
                # a counter must not be a JSON string here and a number there or
                # every consumer has to coerce per platform. The sign is part of
                # the number, so the shape test runs on the magnitude: emitting a
                # negative counter as the string "-1" is the one form BOTH gates
                # reject (tests/run-tests.sh and validate_summary.py each fail a
                # quoted integer, sign stripped), so it must go out unquoted.
                case "${v#-}" in
                    ''|*[!0-9]*) printf '"%s": "%s"' "$(json_escape "$k")" "$(json_escape "$v")" ;;
                    0|[1-9]*)    printf '"%s": %s'   "$(json_escape "$k")" "$v" ;;
                    *)           printf '"%s": "%s"' "$(json_escape "$k")" "$(json_escape "$v")" ;;
                esac
            done < "$STATS_FILE"
        fi
        printf '},\n'
        printf '  "findingsCount": %s,\n' "$fcount"
        printf '  "activeFindingsCount": %s,\n' "$active_count"
        printf '  "suppressedCount": %s,\n' "$sup_count"
        printf '  "findings": ['
        _emit_findings_json "$F2"
        printf ']\n'
        printf '}\n'
    } > "$J"

    # findings-only file for SOAR / SIEM ingestion (parity with the Windows edition)
    local JF="$OUTDIR/findings.json"
    {
        printf '{\n'
        printf '  "tool": "%s",\n' "$(json_escape "$TOOL")"
        printf '  "schemaVersion": "1.8",\n'
        printf '  "platform": "linux",\n'
        printf '  "host": "%s",\n' "$(json_escape "$hn")"
        printf '  "caseId": "%s",\n' "$(json_escape "$CASE_ID")"
        printf '  "generated": "%s",\n' "$end_iso"
        printf '  "findingsCount": %s,\n' "$fcount"
        printf '  "activeFindingsCount": %s,\n' "$active_count"
        printf '  "suppressedCount": %s,\n' "$sup_count"
        printf '  "findings": ['
        _emit_findings_json "$F2"
        printf ']\n'
        printf '}\n'
    } > "$JF"

    write_paste_log "$F2"
    write_suggested_allowlist "$F2"

    rm -f "$F2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Finding identity (schema 1.7). Same canon as Get-FindingIdentity in
# Tatar.ps1; tests/fixtures/identity-vectors.tsv holds the shared vectors.
#   fingerprint = sha256(module US class US category US masked-message US
#                        sorted-paths joined by RS), first 16 hex
#   contentHash = sha256(severity US confidence US detail), first 16 hex
# Masking is deliberately narrow (a PID, and a count before a counted noun):
# over-masking would merge two different findings and hide a new one.
# ---------------------------------------------------------------------------
_hash16() { # stdin -> first 16 hex of SHA-256
    if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-16
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -c1-16
    else printf '0000000000000000'; fi
}
mask_message() {
    printf '%s' "$1" | sed -E \
        -e 's/\b[Pp][Ii][Dd][ =:]*[0-9]+/PID N/g' \
        -e 's/\b[0-9]+( (files?|entries|items|connections?|processes|accounts?|users?|rules?|tasks?|services?|hits?|matches|events?)\b)/N\1/g'
}
finding_fingerprint() { # module class category message paths(GSEP-separated)
    local m pl
    m="$(mask_message "$4")"
    pl="$(printf '%s' "$5" | tr "$GSEP" '\n' | grep -v '^$' | LC_ALL=C sort | awk 'NR>1{printf "\036"} {printf "%s",$0}')"
    printf '%s\037%s\037%s\037%s\037%s' "$1" "$2" "$3" "$m" "$pl" | _hash16
}
finding_contenthash() { # severity confidence detail
    printf '%s\037%s\037%s' "$1" "$2" "$3" | _hash16
}
evidence_section() { # module -> report section title (static)
    case "$1" in
        sysinfo) echo "01 System information" ;;
        network) echo "02 Network (connections, listening, routes, DNS)" ;;
        process) echo "03 Processes (+ suspicious execution locations)" ;;
        sessions) echo "04 Logins & sessions (who, last, failed)" ;;
        users) echo "05 Users, groups, sudo" ;;
        services) echo "06 Services / units" ;;
        persistence) echo "07 Persistence (cron, systemd timers, rc, profiles)" ;;
        apps) echo "08 Installed packages" ;;
        suid) echo "09 SUID / SGID binaries" ;;
        sshkeys) echo "10 SSH keys & config" ;;
        bashhistory) echo "11 Shell history" ;;
        kernelmods) echo "12 Kernel modules" ;;
        indicators) echo "13 Suspicious indicators" ;;
        hashes) echo "14 Hash collection (running binaries)" ;;
        logs) echo "15 Key log copy" ;;
        timeline) echo "16 Timeline (recent file changes, super-timeline lite)" ;;
        containers) echo "17 Containers & cloud context" ;;
        integrity) echo "18 Critical file integrity (SHA-256 baseline)" ;;
        *) echo "" ;;
    esac
}

# Emit the findings[] array items (schema 1.3) from an augmented findings file.
_emit_findings_json() {  # $1 = F2 path
    local f2="$1" first=1 fid fs fc fm fd ft fconf fsup freason fioc techjson
    local fmod fts fpaths fcr find_ facls pathsjson fpr fch evj evsec evfile
    evfile="$(basename "$REPORT")"
    [ -s "$f2" ] || return 0
    while IFS="$FSEP" read -r fid fs fc fm fd ft fconf fsup freason fioc fmod fts fpaths fcr find_ facls; do
        [ $first -eq 1 ] && first=0 || printf ','
        if [ -n "$ft" ]; then
            techjson=$(printf '%s' "$ft" | awk '{printf "[";for(i=1;i<=NF;i++)printf "%s\"%s\"",(i>1?",":""),$i;printf "]"}')
        else techjson="[]"; fi
        [ -n "$fconf" ] || fconf=0.3
        case "$fioc" in true|false) : ;; *) fioc=false ;; esac
        # paths[] is one column holding GSEP-separated elements. Split here and
        # escape each element with the same escaper every other string uses:
        # the array never becomes a second serialisation format.
        if [ -n "$fpaths" ]; then
            pathsjson="["
            _pfirst=1
            while IFS= read -r _p; do
                [ -n "$_p" ] || continue
                [ $_pfirst -eq 1 ] && _pfirst=0 || pathsjson="$pathsjson,"
                pathsjson="$pathsjson\"$(json_escape "$_p")\""
            done <<EOF
$(printf '%s' "$fpaths" | tr "$GSEP" '\n')
EOF
            pathsjson="$pathsjson]"
        else pathsjson="[]"; fi
        fpr="$(finding_fingerprint "$fmod" "${facls:-unknown}" "$fc" "$fm" "$fpaths")"
        fch="$(finding_contenthash "$fs" "$fconf" "$fd")"
        evsec="$(evidence_section "$fmod")"
        if [ -n "$evsec" ] && [ -n "$evfile" ]; then
            evj="[{\"file\":\"$(json_escape "$evfile")\",\"section\":\"$(json_escape "$evsec")\"}]"
        else evj="[]"; fi
        printf '{"id":"%s","severity":"%s","category":"%s","technique":%s,"message":"%s","detail":"%s","confidence":%s,"confidenceReason":"%s","suppressed":%s,"suppressReason":"%s","iocMatch":%s,"iocIndicator":"%s","module":"%s","artifactClass":"%s","collected_at":"%s","paths":%s,"fingerprint":"%s","contentHash":"%s","evidence":%s,"recommendation":"%s"}' \
            "$(json_escape "$fid")" "$(json_escape "$fs")" "$(json_escape "$fc")" "$techjson" \
            "$(json_escape "$fm")" "$(json_escape "$fd")" "$fconf" "$(json_escape "$fcr")" \
            "${fsup:-false}" "$(json_escape "$freason")" "$fioc" "$(json_escape "$find_")" \
            "$(json_escape "$fmod")" "$(json_escape "${facls:-unknown}")" "$(json_escape "$fts")" "$pathsjson" "$fpr" "$fch" "$evj" "$(json_escape "$(recommendation_for "$fc")")"
    done < "$f2"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
banner
# Console hint now, so --help/--list users see it too; the durable record (log +
# error count) is written further down, once the exec log exists.
for u in $UNKNOWN; do c_out "[!] Unknown option: $u"; done

if [ "$HELP" -eq 1 ]; then show_help; exit 0; fi
if [ "$LIST" -eq 1 ]; then
    echo "Available modules (order of volatility):"; echo ""
    for m in $MOD_NAMES; do
        case " $QUICK_MODULES " in *" $m "*) echo "  $m   [quick]" ;; *) echo "  $m" ;; esac
    done
    echo ""
    echo "Total: $(echo $MOD_NAMES | wc -w) modules | --quick runs the $(echo $QUICK_MODULES | wc -w) marked [quick]"
    exit 0
fi

TO_RUN=""
# Two module selectors at once is a usage error, not a silent precedence rule.
# Quietly picking one would be the same class of defect as a value-less flag
# consuming the next token: the run looks fine and collected something other
# than what was asked for.
SEL=0
[ "$ALL" -eq 1 ] && SEL=$((SEL+1))
[ "$QUICK" -eq 1 ] && SEL=$((SEL+1))
[ -n "$MODULES" ] && SEL=$((SEL+1))
if [ "$SEL" -gt 1 ]; then
    printf '[x] FATAL: use only one of --all, --quick or --modules\n' >&2
    exit 1
fi
if [ "$ALL" -eq 1 ]; then TO_RUN="$MOD_NAMES"
elif [ "$QUICK" -eq 1 ]; then TO_RUN="$QUICK_MODULES"
elif [ -n "$MODULES" ]; then TO_RUN="$MODULES"
else
    [ "$SILENT" -eq 0 ] && { show_help; echo ""; echo "[i] Nothing selected. Use --quick, --all or --modules."; }
    exit 1
fi

IS_ROOT=false; [ "$(id -u)" -eq 0 ] && IS_ROOT=true
[ "$IS_ROOT" = false ] && c_out "[!] Not running as root - some artifacts will be incomplete."

HOSTN="$(hostname 2>/dev/null | tr ' /' '__')"
STAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
OUTDIR="$OUTPUT_BASE/${HOSTN}_${STAMP}"

# Parity with the Windows edition, which warns when evidence lands on the system
# drive: writing to the root filesystem of the suspect host can overwrite the
# deleted-file evidence this collector exists to preserve.
ROOT_FS_ANCHOR=""   # the nearest EXISTING ancestor on_root_fs actually tested
on_root_fs() {  # 0 = the output base sits on the root filesystem
    local b="$OUTPUT_BASE"
    # An --output whose leaf does not exist yet - a mount point with nothing
    # mounted on it, typically - still resolves through its nearest EXISTING
    # parent, and that is the filesystem the evidence would really land on. The
    # message has to name that parent: told only "prefer external media
    # (--output /mnt/usb/evidence)" after typing exactly that, an operator
    # cannot tell the warning is about the USB not being mounted.
    while [ -n "$b" ] && [ "$b" != "/" ] && [ ! -d "$b" ]; do b="$(dirname "$b")"; done
    [ -n "$b" ] || return 1
    ROOT_FS_ANCHOR="$b"
    [ "$(stat -c '%d' "$b" 2>/dev/null)" = "$(stat -c '%d' / 2>/dev/null)" ]
}

# One wording for all three warning sites, and only as specific as it can honestly
# be: naming the anchor is what the operator needs when the target is an unmounted
# mount point, and pure noise when the anchor is the output base itself.
root_fs_note() {  # only meaningful immediately after on_root_fs returned 0
    if [ "$ROOT_FS_ANCHOR" = "$OUTPUT_BASE" ]; then
        printf '%s is on the ROOT filesystem' "$OUTPUT_BASE"
    else
        printf '%s does not exist yet and resolves onto the ROOT filesystem through its nearest existing parent %s' \
            "$OUTPUT_BASE" "$ROOT_FS_ANCHOR"
    fi
}

# --dry-run: every input an operator wants to check first - the resolved output
# path, the module order, the armed gated operations, the feed verdicts - is
# already known here. It used to be printed only AFTER the output directory had
# been created, i.e. after the first write to the disk being preserved. Print it
# and stop, touching nothing. Not silenced by --silent: a preview nobody can see
# has no purpose.
if [ "$DRYRUN" -eq 1 ]; then
    _n=0; _unknown_mods=""
    for m in $TO_RUN; do
        _n=$((_n+1))
        echo " $MOD_NAMES " | grep -q " $m " || _unknown_mods="$_unknown_mods $m"
    done
    printf '\n=== TATAR DRY RUN - nothing is collected and nothing is written ===\n'
    printf '  %-14s: %s v%s\n' "Tool"        "$TOOL_DISPLAY" "$VERSION"
    printf '  %-14s: %s\n'     "Host"        "$HOSTN"
    printf '  %-14s: %s (root)\n' "Privileged" "$IS_ROOT"
    printf '  %-14s: %s\n'     "Output dir"  "$OUTDIR"
    on_root_fs && printf '  %-14s: %s; prefer external media that is already mounted\n' "WARNING" "$(root_fs_note)"
    printf '  %-14s: %s\n'     "Case ID"     "${CASE_ID:-(none)}"
    printf '  %-14s: %s\n'     "Examiner"    "${EXAMINER:-(none)}"
    printf '  %-14s: %s module(s) in this order: %s\n' "Modules" "$_n" "$TO_RUN"
    [ -n "$_unknown_mods" ] && printf '  %-14s: NOT a module, nothing would be collected for it:%s\n' "WARNING" "$_unknown_mods"
    printf '  %-14s: --dump-deleted=%s --compress=%s --silent=%s\n' "Gated ops" "$DUMP_DELETED" "$COMPRESS" "$SILENT"
    for _spec in "Allowlist:$ALLOWLIST" "IOC file:$IOCFILE"; do
        _name="${_spec%%:*}"; _path="${_spec#*:}"
        if [ -z "$_path" ]; then printf '  %-14s: (none supplied)\n' "$_name"
        elif [ -r "$_path" ]; then
            _why="$(feed_problem "$_path" "$_name")"
            if [ -n "$_why" ]; then printf '  %-14s: readable but NOT USABLE (%s), would NOT be applied: %s\n' "$_name" "$_why" "$_path"
            else printf '  %-14s: readable, WILL be applied: %s\n' "$_name" "$_path"; fi
        else printf '  %-14s: NOT READABLE, would NOT be applied: %s\n' "$_name" "$_path"; fi
    done
    for u in $UNKNOWN; do printf '  %-14s: unknown option, would be ignored: %s\n' "WARNING" "$u"; done
    printf '\nRe-run without --dry-run to collect.\n\n'
    unset _n _unknown_mods _spec _name _path
    exit 0
fi

# The evidence is written where it is told to, and nowhere else. A symlink at the
# output base would send a root run's evidence wherever the link points (the
# default base is under the world-writable /tmp, where another account can plant
# one), and mkdir -p silently accepts a symlink at the evidence folder's own
# predictable name. Refuse the first, and create the folder with a plain mkdir
# so an existing name - a link included - is an error.
if [ -L "$OUTPUT_BASE" ]; then
    printf '%s\n' "[x] FATAL: output base $OUTPUT_BASE is a symbolic link; evidence is not written through links. Pass the real path." >&2
    exit 1
fi
if [ ! -e "$OUTPUT_BASE" ]; then
    mkdir -p "$OUTPUT_BASE" 2>/dev/null || { printf '%s\n' "[x] FATAL: cannot create output base $OUTPUT_BASE" >&2; exit 1; }
elif [ "$OUTPUT_BASE" = "/tmp/forensic" ] && [ "$(stat -c %u "$OUTPUT_BASE" 2>/dev/null)" != "$(id -u)" ]; then
    printf '%s\n' "[x] FATAL: $OUTPUT_BASE exists and is owned by another account; refusing to write evidence there. Use --output." >&2
    exit 1
fi
TATAR_TMP="$(mktemp -d 2>/dev/null)" || { printf '%s\n' "[x] FATAL: cannot create a temporary directory" >&2; exit 1; }
trap cleanup_tmp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
if ! mkdir "$OUTDIR" 2>/dev/null; then
    printf '%s\n' "[x] FATAL: cannot create output dir $OUTDIR (it may already exist)" >&2
    exit 1
fi
REPORT="$OUTDIR/TATAR_Report_${HOSTN}_${STAMP}.txt"
EXECLOG="$OUTDIR/tatar.log"
FINDINGS_FILE="$(mktmp)"; STATS_FILE="$(mktmp)"; LIMITS_FILE="$(mktmp)"

execlog "INFO" "$TOOL_DISPLAY v$VERSION starting on $HOSTN as $(id -un) (root=$IS_ROOT, silent=$SILENT)"
execlog "INFO" "CaseId='$CASE_ID' Examiner='$EXAMINER' OutDir=$OUTDIR"
execlog "INFO" "Modules selected: $TO_RUN"
[ "$IS_ROOT" = false ] && add_note "Not running as root: every module that needs privilege collected less than its section header claims."

{
    echo "$TOOL_DISPLAY v$VERSION - Collection Report"
    echo "Host        : $HOSTN"
    echo "Case ID     : $CASE_ID"
    echo "Examiner    : $EXAMINER"
    echo "Started     : $(iso)"
    echo "Root        : $IS_ROOT"
    echo "Modules     : $TO_RUN"
    echo "OutputDir   : $OUTDIR"
} > "$REPORT"

START_ISO="$(iso)"; START_EPOCH="$(date +%s)"
detect_environment
execlog "INFO" "Environment: virt=$ENV_VIRT container=$ENV_CONTAINER runtime=$ENV_RUNTIME secmod=$ENV_SECMOD"
# An allowlist / IOC path that cannot be read used to be skipped in silence.
# That is the worst failure mode a triage tool has: the analyst reads "no active
# findings" believing their feed was applied, when it never ran. Say so loudly,
# before the collection, and make it count towards the exit code.
for _spec in "Allowlist:$ALLOWLIST" "IOC file:$IOCFILE"; do
    _name="${_spec%%:*}"; _path="${_spec#*:}"
    [ -n "$_path" ] || continue
    if [ -r "$_path" ]; then
        execlog "INFO" "$_name will be applied: $_path"
        # A feed or allowlist that is readable but unusable (not JSON, not an object, or an
        # IOC feed holding no indicator) used to apply nothing without a word: the same silent
        # no-op as an unreadable path, most often a half-written file. Say so and count it
        # towards the exit code.
        _why="$(feed_problem "$_path" "$_name")"
        if [ -n "$_why" ]; then
            c_out "[!] $_name NOT USABLE: $_why: $_path"
            c_out "    It will NOT be applied. Fix the file and re-run."
            add_err "$_name is not usable ($_why), so it was NOT applied: $_path"
        fi
    else
        c_out "[!] $_name NOT READABLE: $_path"
        c_out "    It will NOT be applied. Fix the path and re-run."
        add_err "$_name not readable, so it was NOT applied: $_path"
    fi
done
unset _spec _name _path _why

# Same class of quiet no-op: an unknown option was a console-only warning, which
# --silent swallowed completely - a cron run with a misspelled flag looked
# identical to a clean one and still exited 0. Log it and make it count.
for u in $UNKNOWN; do add_err "Unknown option ignored: $u"; done

if on_root_fs; then
    c_out "[!] WARNING: $(root_fs_note). Writing evidence there can overwrite deleted-file evidence. Prefer external media that is already mounted."
    add_note "$(root_fs_note); prefer external media that is already mounted."
fi

c_out ""; c_out "[i] Output: $OUTDIR"
c_out "[i] Env: virt=$ENV_VIRT container=$ENV_CONTAINER runtime=$ENV_RUNTIME secmod=$ENV_SECMOD"
c_out ""

I=0; N=$(echo $TO_RUN | wc -w); RAN=0; SKIPPED=""; MODSTATUS=""
for m in $TO_RUN; do
    I=$((I+1))
    if ! echo " $MOD_NAMES " | grep -q " $m "; then
        # A misspelled module name must never read as "collected and empty".
        c_out "[!] Unknown module: $m"
        SKIPPED="$SKIPPED $m"
        MODSTATUS="$MODSTATUS $m:skipped:0:0"
        add_err "Unknown module requested, nothing was collected for it: $m"
        continue
    fi
    c_out "[$I/$N] $m"
    execlog "START" "module $m ($I/$N)"
    CURRENT_MODULE="$m"
    err_before=$ERROR_COUNT; mstart=$(date +%s)
    run_module "$m"; rc=$?; RAN=$((RAN+1))
    secs=$(( $(date +%s) - mstart ))
    # summary.txt tells the analyst to grep tatar.log for FAILED. Until now no
    # FAILED line could ever be written on Linux, so a module that produced none
    # of its evidence read as a clean run. Every m_* returns a deliberate status
    # (0 = artifact produced, 1 = primary artifact NOT produced), 99 = no such
    # module, which the check above already handled.
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 99 ]; then
        execlog "FAILED" "module $m exited $rc after ${secs}s - its primary artifact was NOT collected"
        add_err "module $m did not produce its primary artifact (exit $rc)"
    elif [ "$ERROR_COUNT" -gt "$err_before" ]; then
        execlog "WARN" "module $m finished in ${secs}s with $((ERROR_COUNT-err_before)) error(s)"
    else
        execlog "OK" "module $m finished in ${secs}s"
    fi
    # How the module ended, for summary.json moduleStatus. Entries are
    # name:status:seconds:errors, space separated (module names have no colon).
    mstat=ok
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 99 ]; then mstat=failed
    elif [ "$ERROR_COUNT" -gt "$err_before" ]; then mstat=warn; fi
    MODSTATUS="$MODSTATUS $m:$mstat:$secs:$((ERROR_COUNT-err_before))"
done

if [ "$RAN" -eq 0 ]; then c_out "[x] No valid modules were run."; execlog "FATAL" "No valid modules were run."; exit 1; fi

c_out ""; c_out "[i] Finalizing (summary, metadata, manifest)..."
END_ISO="$(iso)"; DUR=$(( $(date +%s) - START_EPOCH ))

SELF="$0"; SELF_HASH="$(sha256sum "$SELF" 2>/dev/null | awk '{print $1}')"
{
    echo "=== CHAIN OF CUSTODY ==="
    echo "Case ID      : $CASE_ID"
    echo "Examiner     : $EXAMINER"
    echo "Host         : $HOSTN"
    echo "Started      : $START_ISO"
    echo "Finished     : $END_ISO"
    echo "Duration     : ${DUR}s"
    echo "Script       : $SELF"
    echo "Script SHA256: $SELF_HASH"
    echo "Tool         : $TOOL_DISPLAY v$VERSION"
} > "$OUTDIR/chain_of_custody.txt"

execlog "INFO" "Writing summary.txt / summary.json"
write_summary "$START_ISO" "$END_ISO" "$TO_RUN" "$IS_ROOT" "$DUR" "$SKIPPED"

# The report trailer has to be written BEFORE the manifest hashes the report:
# appending to an already-hashed file left one entry permanently wrong, so
# `sha256sum -c manifest_sha256.txt` failed on every single run.
printf '\n=== Collection finished: %s ===\n' "$END_ISO" >> "$REPORT"

# Before the manifest, so ARTIFACTS.md is itself hashed.
write_artifact_index

# Text the tool generated is made safe to read in a terminal, and the whole set
# is made private, BEFORE the manifest hashes it. Verbatim host files stay as is.
for _f in "$REPORT" "$OUTDIR/summary.txt" "$OUTDIR/paste.txt" "$OUTDIR/ARTIFACTS.md" "$OUTDIR/timeline.csv" "$OUTDIR/chain_of_custody.txt"; do
    sanitize_file "$_f"
done
unset _f
chmod -R go-rwx "$OUTDIR" 2>/dev/null

MANIFEST="$OUTDIR/manifest_sha256.txt"
( cd "$OUTDIR" && find . -type f ! -name 'manifest_sha256.txt' ! -name 'tatar.log' -exec sha256sum {} \; ) > "$MANIFEST" 2>/dev/null
execlog "INFO" "Manifest written: $MANIFEST"
# The manifest cannot hash itself, so its own digest is the one number an
# analyst has to carry out of band: print it, log it, and leave it beside the
# manifest in sha256sum format (`sha256sum -c manifest_sha256.txt.sha256`).
MH="$(sha256sum "$MANIFEST" 2>/dev/null | awk '{print $1}')"
if [ -n "$MH" ]; then
    printf '%s  manifest_sha256.txt\n' "$MH" > "$OUTDIR/manifest_sha256.txt.sha256"
    execlog "INFO" "Manifest SHA-256: $MH"
    c_out "[i] Manifest SHA-256: $MH"
else
    add_err "Could not hash manifest_sha256.txt"
fi

if [ "$IS_ROOT" = true ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    c_out "[i] The evidence folder is private to root. To read it as $SUDO_USER: sudo chown -R $SUDO_USER \"$OUTDIR\""
fi

if [ "$COMPRESS" -eq 1 ]; then
    ARCHIVE="$OUTPUT_BASE/TATAR_${HOSTN}_${STAMP}.tar.gz"
    if tar -czf "$ARCHIVE" -C "$OUTPUT_BASE" "${HOSTN}_${STAMP}" 2>/dev/null; then
        sha256sum "$ARCHIVE" 2>/dev/null | awk '{print $1}' > "${ARCHIVE}.sha256.txt"
        execlog "INFO" "Archive created + hashed: $ARCHIVE"
        c_out "[i] Archive: $ARCHIVE"
    else
        add_err "Compression failed"; c_out "[!] Compression failed"
    fi
fi

EXIT_CODE=0; [ "$ERROR_COUNT" -gt 0 ] && EXIT_CODE=2
# Read back from findings.json: FINDINGS_FILE holds what the modules raised and misses what the
# IOC feed and the correlation added afterwards.
FCOUNT="$(sed -n 's/^  "findingsCount": \([0-9][0-9]*\),.*/\1/p' "$OUTDIR/findings.json" 2>/dev/null | head -n1)"
[ -n "$FCOUNT" ] || FCOUNT=$( [ -s "$FINDINGS_FILE" ] && wc -l < "$FINDINGS_FILE" || echo 0 )
execlog "INFO" "Run complete. Findings: $FCOUNT | Errors: $ERROR_COUNT | Exit code: $EXIT_CODE"

rm -f "$FINDINGS_FILE" "$STATS_FILE" 2>/dev/null

c_out ""
c_out "[+] Done. Report  : $REPORT"
c_out "[+] Summary : $OUTDIR/summary.txt"
c_out "[+] Findings: $FCOUNT lead(s) for review | Errors logged: $ERROR_COUNT | Exit code: $EXIT_CODE"
c_out "[i] Findings are review leads, not verdicts. Encrypt & handle output per policy."
exit $EXIT_CODE
