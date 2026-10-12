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

    python3 - "$j" "$label" "$HERE/../schema/summary.schema.json" <<'PY'
import json, sys
path, label, schema_path = sys.argv[1], sys.argv[2], sys.argv[3]
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

# A requested module that never ran must be visible to the pipeline, not only
# to whoever reads the log.
skipped = s.get("modulesSkipped")
check("%s : modulesSkipped is a list, never null" % label, isinstance(skipped, list), type(skipped).__name__)
check("%s : nothing was skipped for a valid module list" % label, skipped == [], ",".join(map(str, skipped or [])))

# summary.json is the cross-platform contract: a counter is a NUMBER on every
# platform and uses the one canonical key the schema names for that concept.
st = s.get("stats")
check("%s : stats is an object" % label, isinstance(st, dict), type(st).__name__)
if isinstance(st, dict):
    quoted = sorted(k for k, v in st.items() if isinstance(v, str) and v.strip().lstrip("-").isdigit())
    check("%s : stats counters are JSON numbers, not strings" % label, not quoted, ",".join(quoted))
    canon = None
    try:
        canon = json.load(open(schema_path, encoding="utf-8"))["properties"]["stats"]["x-canonicalStatKeys"]
    except Exception as e:
        check("%s : the schema declares x-canonicalStatKeys" % label, False, str(e))
    if canon:
        drifted = sorted(k for k in st if k not in canon)
        check("%s : every stats key is the canonical cross-platform spelling" % label, not drifted, ",".join(drifted))

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
                if float(x.get("confidence", -1)) not in (0.4, 0.7, 0.95)]
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

# T0 - findings.json is a published integration surface. If its schema and
#      summary.json's schema describe different finding shapes, a SOAR
#      integration and a dashboard are held to different contracts.
printf 'T0  the two published schemas describe the same finding\n'
python3 - "$HERE/../schema/summary.schema.json" "$HERE/../schema/findings.schema.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1], encoding="utf-8"))
b = json.load(open(sys.argv[2], encoding="utf-8"))
if json.dumps(a["properties"]["findings"], sort_keys=True) != json.dumps(b["properties"]["findings"], sort_keys=True):
    print("  FAIL  T0 : the findings[] definition differs between the two schemas")
    sys.exit(1)
for k in ("findingsCount", "activeFindingsCount", "suppressedCount"):
    for name, sch in (("summary", a), ("findings", b)):
        if k not in sch["properties"]:
            print("  FAIL  T0 : %s is not declared in %s.schema.json" % (k, name))
            sys.exit(1)
print("  PASS  T0 : both schemas declare the same findings[] and the same counts")
PY
if [ $? -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# T1 - baseline run
printf '\nT1  baseline run (no allowlist, no IOC)\n'
D1="$(run_collector t1)"; E1="$(cat "$EXITFILE" 2>/dev/null)"
check_exit T1 "$E1"
assert_contract "$D1/summary.json" "T1"
N1="$(ioc_finding_count "$D1/summary.json")"
[ "$N1" = "0" ] && check "T1 : no IOC findings without an IOC feed" 1 || check "T1 : no IOC findings without an IOC feed" 0 "got $N1"
# summary.txt tells the analyst to grep the log for FAILED. A module that ends
# on a grep with no match must not be reported as a failed collection.
NF1="$(grep -c 'FAILED' "$D1/tatar.log" 2>/dev/null)"
[ "${NF1:-0}" = "0" ] && check "T1 : a healthy run logs no FAILED module" 1 || check "T1 : a healthy run logs no FAILED module" 0 "got $NF1"
NOK1="$(grep -c '\[OK' "$D1/tatar.log" 2>/dev/null)"
[ "${NOK1:-0}" -ge 3 ] 2>/dev/null && check "T1 : every selected module logged its status" 1 || check "T1 : every selected module logged its status" 0 "OK lines: $NOK1"
# The manifest is the chain-of-custody artifact: if a standard tool cannot
# verify it, it is decoration. It used to hash the report BEFORE the collector
# appended its last line, so this check failed on every run.
if [ -s "$D1/manifest_sha256.txt" ] && command -v sha256sum >/dev/null 2>&1; then
    if ( cd "$D1" && sha256sum -c manifest_sha256.txt >/dev/null 2>&1 ); then
        check "T1 : the manifest verifies with sha256sum -c" 1
    else
        check "T1 : the manifest verifies with sha256sum -c" 0 "$( cd "$D1" && sha256sum -c manifest_sha256.txt 2>&1 | grep -v ': OK$' | head -n2 | tr '\n' ' ' )"
    fi
else
    check "T1 : the manifest verifies with sha256sum -c" 0 "manifest missing or sha256sum unavailable"
fi

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

# T5 - a path that does not exist must NOT be skipped in silence. Reading "no
# active findings" while the IOC feed never ran is the failure mode this whole
# test file exists to prevent, so it is asserted, not assumed.
printf '\nT5  missing allowlist and IOC paths are reported, not ignored\n'
D5="$(run_collector t5 --allowlist "$FIXTURES/does-not-exist.json" --ioc "$FIXTURES/also-missing.json")"; E5="$(cat "$EXITFILE" 2>/dev/null)"
if [ "$E5" = "2" ]; then check "T5 : unreadable feed paths force the error exit code" 1
else check "T5 : unreadable feed paths force the error exit code" 0 "got $E5"; fi
assert_contract "$D5/summary.json" "T5"
N5="$(grep -c 'NOT applied' "$D5/tatar.log" 2>/dev/null || echo 0)"
if [ "${N5:-0}" -ge 2 ]; then check "T5 : the log names both files as NOT applied" 1
else check "T5 : the log names both files as NOT applied" 0 "got $N5"; fi

# T6 - a value-taking flag whose value is missing used to consume the NEXT FLAG
#      (or nothing): `--all --output` left the output base empty and wrote the
#      evidence tree to the filesystem root of the suspect host.
printf '\nT6  a value-taking flag with no value is a usage error\n'
bash "$COLLECTOR" --modules "$MODULES" --silent --output >/dev/null 2>&1
E6a=$?
[ "$E6a" = "1" ] && check "T6 : --output with no value exits 1" 1 || check "T6 : --output with no value exits 1" 0 "got $E6a"
bash "$COLLECTOR" --modules "$MODULES" --silent --output --caseid IR-T6 >/dev/null 2>&1
E6b=$?
[ "$E6b" = "1" ] && check "T6 : --output followed by another flag exits 1" 1 || check "T6 : --output followed by another flag exits 1" 0 "got $E6b"
bash "$COLLECTOR" --all --silent --modules >/dev/null 2>&1
E6c=$?
[ "$E6c" = "1" ] && check "T6 : --modules with no value exits 1" 1 || check "T6 : --modules with no value exits 1" 0 "got $E6c"
HOSTN_T="$(hostname 2>/dev/null | tr ' /' '__')"
if ls -d "/${HOSTN_T}_"* >/dev/null 2>&1; then
    check "T6 : no evidence folder was written to the filesystem root" 0 "found /${HOSTN_T}_*"
else
    check "T6 : no evidence folder was written to the filesystem root" 1
fi

# T7 - an unknown option used to be a console-only warning that --silent
#      swallowed, and an unknown module name only warned: both exited 0, so a
#      run that collected a quarter of what was asked looked clean.
printf '\nT7  unknown option and unknown module are recorded, not swallowed\n'
D7="$(run_collector t7 --tatar-bogus-flag --modules "sysinfo,notamodule")"; E7="$(cat "$EXITFILE" 2>/dev/null)"
if [ "$E7" = "2" ]; then check "T7 : unknown option / module force the error exit code" 1
else check "T7 : unknown option / module force the error exit code" 0 "got $E7"; fi
if grep -q 'tatar-bogus-flag' "$D7/tatar.log" 2>/dev/null; then check "T7 : the log names the unknown option" 1
else check "T7 : the log names the unknown option" 0 "not in tatar.log"; fi
if grep -q 'notamodule' "$D7/tatar.log" 2>/dev/null; then check "T7 : the log names the unknown module" 1
else check "T7 : the log names the unknown module" 0 "not in tatar.log"; fi
S7="$(python3 -c '
import json,sys
try: s=json.load(open(sys.argv[1],encoding="utf-8"))
except Exception: print("ERR"); raise SystemExit
print(",".join(s.get("modulesSkipped") or []))' "$D7/summary.json" 2>/dev/null)"
if [ "$S7" = "notamodule" ]; then check "T7 : summary.json reports the skipped module" 1
else check "T7 : summary.json reports the skipped module" 0 "modulesSkipped=$S7"; fi

# T8 - the preview has to resolve the plan WITHOUT touching the disk: on a
#      forensic collector the first write is itself evidence-destroying.
printf '\nT8  --dry-run resolves the plan and writes nothing\n'
T8ROOT="/tmp/tatar-test-t8-$$"
rm -rf "$T8ROOT"
OUT8="$(bash "$COLLECTOR" --all --dry-run --output "$T8ROOT" --allowlist "$FIXTURES/does-not-exist.json" 2>&1)"; E8=$?
[ "$E8" = "0" ] && check "T8 : --dry-run exits 0" 1 || check "T8 : --dry-run exits 0" 0 "got $E8"
[ ! -e "$T8ROOT" ] && check "T8 : --dry-run creates no output directory" 1 || check "T8 : --dry-run creates no output directory" 0 "$T8ROOT exists"
printf '%s' "$OUT8" | grep -q "$T8ROOT/" && check "T8 : the preview names the resolved output dir" 1 || check "T8 : the preview names the resolved output dir" 0
printf '%s' "$OUT8" | grep -qE '[0-9]+ module\(s\) in this order' && check "T8 : the preview names the module count and order" 1 || check "T8 : the preview names the module count and order" 0
printf '%s' "$OUT8" | grep -q 'NOT READABLE' && check "T8 : the preview reports an unreadable feed before collecting" 1 || check "T8 : the preview reports an unreadable feed before collecting" 0

# T9 - the allowlist engine itself. Every suppression assertion above holds
#      trivially while nothing is suppressed, so nothing proved that a VALID
#      allowlist suppresses anything at all - the whole v1.2 engine could
#      degrade to a no-op and the suite would stay green. Raise a finding on
#      purpose (a process running from /tmp) and require the fixture rule to
#      hide it, with a reason.
printf '\nT9  a valid allowlist actually suppresses a finding\n'
BAIT="/tmp/tatar-allowlist-probe"
BAIT_SRC="$(command -v sleep 2>/dev/null)"
BAIT_PID=""
if [ -n "$BAIT_SRC" ] && cp "$BAIT_SRC" "$BAIT" 2>/dev/null && chmod +x "$BAIT" 2>/dev/null; then
    "$BAIT" 300 & BAIT_PID=$!
    sleep 1
    D9="$(run_collector t9 --modules process --allowlist "$FIXTURES/allowlist-positive.json")"; E9="$(cat "$EXITFILE" 2>/dev/null)"
    check_exit T9 "$E9"
    assert_contract "$D9/summary.json" "T9"
    R9="$(python3 - "$D9/summary.json" "$BAIT" <<'PY'
import json, sys
try:
    s = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print("UNREADABLE:%s" % e); raise SystemExit
bait = sys.argv[2]
hits = [f for f in (s.get("findings") or []) if bait in "%s %s" % (f.get("message") or "", f.get("detail") or "")]
if not hits:
    print("NOFINDING")          # the probe was never flagged: the test itself is broken
elif all(f.get("suppressed") in (True, "true") and str(f.get("suppressReason", "")).strip() for f in hits):
    print("SUPPRESSED:%d" % s.get("suppressedCount", 0))
else:
    print("NOTSUPPRESSED:" + ";".join("%s suppressed=%s reason=%r" % (f.get("id"), f.get("suppressed"), f.get("suppressReason")) for f in hits))
PY
)"
    case "$R9" in
        SUPPRESSED:*) check "T9 : the allowlist path rule suppresses the probe finding, with a reason" 1 ;;
        *)            check "T9 : the allowlist path rule suppresses the probe finding, with a reason" 0 "$R9" ;;
    esac
    case "$R9" in
        SUPPRESSED:0) check "T9 : suppressedCount is at least 1" 0 "got 0" ;;
        SUPPRESSED:*) check "T9 : suppressedCount is at least 1" 1 ;;
        *)            check "T9 : suppressedCount is at least 1" 0 "$R9" ;;
    esac
    [ -n "$BAIT_PID" ] && kill "$BAIT_PID" 2>/dev/null
    rm -f "$BAIT" 2>/dev/null
else
    check "T9 : the probe binary could be staged in /tmp" 0 "could not copy ${BAIT_SRC:-sleep} to $BAIT"
fi

# T10 - the IOC evidence scan shells out to find/xargs/grep. If that toolchain
#       cannot run (a broken PATH entry on the suspect host), stderr used to be
#       discarded and the scan reported ZERO hits - indistinguishable from "no
#       indicators present". Same silent-skip failure mode T5 guards for feeds.
printf '\nT10  a broken scan toolchain is reported, not silently read as "no IOCs"\n'
T10BIN="/tmp/tatar-test-t10-bin-$$"
rm -rf "$T10BIN"; mkdir -p "$T10BIN"
# a self-referential symlink: grep resolves to itself -> ELOOP, exactly the
# shape a stale/hostile PATH entry takes in the wild.
ln -s grep "$T10BIN/grep" 2>/dev/null
if [ -L "$T10BIN/grep" ]; then
    T10D="/tmp/tatar-test-t10-$$"; rm -rf "$T10D"
    PATH="$T10BIN:$PATH" bash "$COLLECTOR" --modules "$MODULES" --silent --output "$T10D" \
        --ioc "$FIXTURES/ioc-positive.json" --caseid TATAR-IOC-PROBE-4711 >/dev/null 2>&1
    E10="$?"
    if [ "$E10" = "2" ]; then check "T10 : a broken scan toolchain forces the error exit code" 1
    else check "T10 : a broken scan toolchain forces the error exit code" 0 "got $E10"; fi
    D10="$(find "$T10D" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n1)"
    N10="$(grep -c 'IOC evidence scan could not run' "$D10/tatar.log" 2>/dev/null || echo 0)"
    if [ "${N10:-0}" -ge 1 ]; then check "T10 : the log says the IOC scan result is not trustworthy" 1
    else check "T10 : the log says the IOC scan result is not trustworthy" 0 "got ${N10:-0}"; fi
    rm -rf "$T10D" 2>/dev/null
else
    check "T10 : the broken-PATH probe could be staged" 0 "could not create $T10BIN/grep"
fi
rm -rf "$T10BIN" 2>/dev/null

rm -rf /tmp/tatar-test-t1-$$ /tmp/tatar-test-t2-$$ /tmp/tatar-test-t3-$$ /tmp/tatar-test-t4-$$ /tmp/tatar-test-t5-$$ /tmp/tatar-test-t7-$$ /tmp/tatar-test-t9-$$ /tmp/tatar-test-t10-$$ "$T8ROOT" "$EXITFILE" 2>/dev/null

printf '\nRESULT  passed: %d  failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
