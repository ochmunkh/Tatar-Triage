#!/usr/bin/env bash
#
# TATAR Triage Toolkit - contract tests (Linux edition).
#
# Black-box: runs the collector with controlled allowlist / IOC fixtures and
# asserts the OUTPUT CONTRACT (summary.json). Nothing here depends on the
# collector's internals, so the tests survive refactors.
#
# Run from the repo root:   bash tests/run-tests.sh
# Exit code: 0 = all assertions passed, 1 = at least one failed.

set -o pipefail 2>/dev/null || true

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${COLLECTOR:-$HERE/../linux/tatar-linux.sh}"
FIXTURES="$HERE/fixtures"
MODULES="${MODULES:-sysinfo,network,users}"
EXITFILE="/tmp/tatar-test-exit-$$"   # run_collector runs in a subshell, so the exit code travels via this file

PASS=0
FAIL=0

check() {  # check NAME CONDITION_RESULT [DETAIL]
    if [ "$2" = "1" ]; then
        PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
    else
        FAIL=$((FAIL+1)); printf '  FAIL  %s  %s\n' "$1" "${3:-}"
    fi
}

check_exit() {  # check_exit LABEL CODE
    case "$2" in
        0|2) check "$1 : exit code is 0 or 2" 1 ;;
        *)   check "$1 : exit code is 0 or 2" 0 "got ${2:-<none>}" ;;
    esac
}

have_python() { command -v python3 >/dev/null 2>&1; }

run_collector() {  # run_collector LABEL [extra args...] -> echoes the output dir
    local label="$1"; shift
    local root="/tmp/tatar-test-$label-$$"
    rm -rf "$root"
    bash "$COLLECTOR" --modules "$MODULES" --silent --output "$root" "$@" >/dev/null 2>&1
    printf '%s' "$?" > "$EXITFILE"
    find "$root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n1
}

# ---- the output contract every run must satisfy ------------------------------
assert_contract() {  # assert_contract SUMMARY_JSON LABEL
    local j="$1" label="$2"
    if [ ! -s "$j" ]; then check "$label : summary.json exists" 0 "missing"; return; fi
    check "$label : summary.json exists" 1

    python3 - "$j" "$label" <<'PY'
import json, sys
path, label = sys.argv[1], sys.argv[2]
ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    if cond: ok += 1; print("  PASS  %s" % name)
    else:    fail += 1; print("  FAIL  %s  %s" % (name, detail))

try:
    s = json.load(open(path, encoding="utf-8"))
except Exception as e:
    print("  FAIL  %s : summary.json parses  %s" % (label, e))
    sys.exit(1)

check("%s : summary.json parses" % label, True)
check("%s : schemaVersion is 1.2" % label, s.get("schemaVersion") == "1.2", s.get("schemaVersion"))
import re
check("%s : version is SemVer" % label, bool(re.match(r"^\d+\.\d+\.\d+$", str(s.get("version")))), s.get("version"))
check("%s : platform is linux" % label, s.get("platform") == "linux", s.get("platform"))

f = s.get("findings")
check("%s : findings is a list, never null" % label, isinstance(f, list), type(f).__name__)
if not isinstance(f, list):
    sys.exit(1 if fail else 0)

a, sup = s.get("activeFindingsCount"), s.get("suppressedCount")
check("%s : counts add up (active + suppressed = findings)" % label,
      isinstance(a, int) and isinstance(sup, int) and a + sup == len(f),
      "active=%s suppressed=%s findings=%d" % (a, sup, len(f)))
check("%s : findingsCount matches array" % label, s.get("findingsCount") == len(f),
      "%s vs %d" % (s.get("findingsCount"), len(f)))

if f:
    ids = [x.get("id") for x in f]
    check("%s : finding ids unique" % label, len(set(ids)) == len(ids), ",".join(map(str, ids)))
    check("%s : finding ids well formed" % label,
          all(re.match(r"^TTR-F-\d{3,}$", str(i)) for i in ids))
    required = ("id", "severity", "category", "message", "confidence", "suppressed", "iocMatch")
    missing = ["%s:%s" % (x.get("id"), k) for x in f for k in required if k not in x]
    check("%s : v2 fields on every finding" % label, not missing, ",".join(missing))
    bad_sev = [x.get("severity") for x in f if x.get("severity") not in ("High", "Review")]
    check("%s : severity is High or Review" % label, not bad_sev, ",".join(map(str, bad_sev)))
    bad_conf = ["%s=%s" % (x.get("id"), x.get("confidence")) for x in f
                if float(x.get("confidence", -1)) not in (0.3, 0.4, 0.7, 0.95)]
    check("%s : confidence from the fixed set" % label, not bad_conf, ",".join(bad_conf))
    bad_ioc = [x.get("id") for x in f if x.get("iocMatch") not in (False, "false", None)
               and (x.get("severity") != "High" or float(x.get("confidence", 0)) != 0.95
                    or x.get("suppressed") in (True, "true"))]
    check("%s : IOC hit implies High/0.95/active" % label, not bad_ioc, ",".join(map(str, bad_ioc)))
    bad_sup = [x.get("id") for x in f if x.get("suppressed") in (True, "true")
               and not str(x.get("suppressReason", "")).strip()]
    check("%s : suppressed findings carry a reason" % label, not bad_sup, ",".join(map(str, bad_sup)))

sys.exit(1 if fail else 0)
PY
    if [ $? -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
}

ioc_finding_count() {  # ioc_finding_count SUMMARY_JSON
    python3 -c '
import json,sys
try: s=json.load(open(sys.argv[1],encoding="utf-8"))
except Exception: print(-1); raise SystemExit
f=s.get("findings") or []
print(sum(1 for x in f if x.get("category")=="ioc" or x.get("iocMatch") in (True,"true")))' "$1" 2>/dev/null || echo -1
}

printf '\nTATAR Triage - Linux contract tests\n'
printf 'collector: %s\n\n' "$COLLECTOR"

if ! have_python; then
    printf 'python3 is required for the assertions (the collector itself does not need it).\n'
    exit 1
fi

# T1 - baseline run
printf 'T1  baseline run (no allowlist, no IOC)\n'
D1="$(run_collector t1)"; E1="$(cat "$EXITFILE" 2>/dev/null)"
check_exit T1 "$E1"
assert_contract "$D1/summary.json" "T1"
N1="$(ioc_finding_count "$D1/summary.json")"
[ "$N1" = "0" ] && check "T1 : no IOC findings without an IOC feed" 1 || check "T1 : no IOC findings without an IOC feed" 0 "got $N1"

# T2 - partial IOC tokens must NOT match:
#      127.0.0  is a prefix of 127.0.0.1 ; ocalhost is inside localhost ; ystemd inside systemd
printf '\nT2  IOC feed with partial tokens (must not match)\n'
D2="$(run_collector t2 --ioc "$FIXTURES/ioc-negative.json")"; E2="$(cat "$EXITFILE" 2>/dev/null)"
check_exit T2 "$E2"
assert_contract "$D2/summary.json" "T2"
N2="$(ioc_finding_count "$D2/summary.json")"
[ "$N2" = "0" ] && check "T2 : partial IOC tokens raise no finding" 1 || check "T2 : partial IOC tokens raise no finding" 0 "got $N2"

# T3 - a whole token that is certainly present
printf '\nT3  IOC feed with a whole token (must match)\n'
D3="$(run_collector t3 --ioc "$FIXTURES/ioc-positive.json" --caseid TATAR-IOC-PROBE-4711)"
assert_contract "$D3/summary.json" "T3"
N3="$(ioc_finding_count "$D3/summary.json")"
[ "$N3" -ge 1 ] 2>/dev/null && check "T3 : whole IOC token is detected" 1 || check "T3 : whole IOC token is detected" 0 "got $N3"

# T4 - malformed inputs: warn and carry on, never crash
printf '\nT4  malformed allowlist and IOC files\n'
D4="$(run_collector t4 --allowlist "$FIXTURES/allowlist-malformed.json" --ioc "$FIXTURES/ioc-malformed.json")"; E4="$(cat "$EXITFILE" 2>/dev/null)"
check_exit T4 "$E4"
assert_contract "$D4/summary.json" "T4"

rm -rf /tmp/tatar-test-t1-$$ /tmp/tatar-test-t2-$$ /tmp/tatar-test-t3-$$ /tmp/tatar-test-t4-$$ "$EXITFILE" 2>/dev/null

printf '\nRESULT  passed: %d  failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
