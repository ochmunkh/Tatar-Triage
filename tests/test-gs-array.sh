#!/usr/bin/env bash
# TATAR Triage Toolkit - flat-record array unit tests (Linux edition).
#
# The Linux findings pipeline is a FLAT, separator-delimited record: modules
# write raw bytes and exactly one place (_emit_findings_json) turns them into
# JSON. Schema 1.3 added paths[], the first array-valued column, carried as
# GSEP-separated (0x1D) elements inside one FSEP-separated (0x1F) column.
#
# That buys a single JSON choke point instead of eighteen, at the cost of one
# property that now has to hold absolutely:
#
#   strings collected from the SUSPECT HOST must never be able to add a
#   column or an array element to the record.
#
# A filename is attacker-controlled input on a compromised machine. If a
# crafted one could carry a 0x1F or 0x1D byte into a finding, it could forge
# a suppressReason, flip iocMatch, or inject a path that was never seen. This
# file pins that defence and the round trip that depends on it.
#
# There is no Windows counterpart on purpose: that edition builds a native
# object with a real array, so it has no flat record to inject into.
#
# Run from the repo root:
#     bash tests/test-gs-array.sh
#
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"

[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable: $COLLECTOR"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL  python3 is required to verify the results"; exit 1; }

# Lift the functions under test by text: sourcing the collector would run a
# collection. Same approach as test-ioc-boundary.sh / test-json-escape.sh.
lift() {  # lift FUNCNAME
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(\\) \\{" { grab = 1 }
        grab { print }
        grab && /^\}/ { exit }' "$COLLECTOR"
}
for fn in json_escape iso map_technique add_finding conf_reason _emit_findings_json al_paths_of; do
    code="$(lift "$fn")"
    case "$code" in
        *"$fn()"*) eval "$code" ;;
        *) echo "FAIL  $fn not found in $COLLECTOR"; exit 1 ;;
    esac
done
echo "Lifted 7 functions from $(basename "$COLLECTOR")"
echo

FSEP="$(printf '\037')"
GSEP="$(printf '\035')"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0

check() {  # check NAME CONDITION [DETAIL]
    if [ "$2" = "1" ]; then pass=$((pass+1)); printf '  PASS  %s\n' "$1"
    else fail=$((fail+1)); printf '  FAIL  %s  %s\n' "$1" "${3:-}"; fi
}

# ---- 1. add_finding strips both separators from host-controlled strings -----
printf '1  a crafted string cannot add a column or an array element\n'

FINDINGS_FILE="$WORK/findings"; : > "$FINDINGS_FILE"
FIND_SEQ=0; CURRENT_MODULE="process"

EVIL_MSG="$(printf 'evil\037forged-sev\037forged-cat')"
EVIL_DET="$(printf 'detail\035/injected/path\035/second')"
add_finding Review process "$EVIL_MSG" "$EVIL_DET" >/dev/null 2>&1

COLS="$(awk -F"$FSEP" '{print NF}' "$FINDINGS_FILE")"
check "the record still has exactly 9 columns" "$([ "$COLS" = "9" ] && echo 1 || echo 0)" "got $COLS"
if grep -q "$(printf '\037forged-sev')" "$FINDINGS_FILE"; then
    check "the injected FSEP is gone from the message" 0 "forged column survived"
else
    check "the injected FSEP is gone from the message" 1
fi
if grep -q "$GSEP" "$FINDINGS_FILE"; then
    check "the injected GSEP is gone from the detail" 0 "array separator survived"
else
    check "the injected GSEP is gone from the detail" 1
fi
MODCOL="$(awk -F"$FSEP" '{print $8}' "$FINDINGS_FILE")"
check "column 8 is the module, not attacker text" "$([ "$MODCOL" = "process" ] && echo 1 || echo 0)" "got '$MODCOL'"
TSCOL="$(awk -F"$FSEP" '{print $9}' "$FINDINGS_FILE")"
case "$TSCOL" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) check "column 9 is an ISO 8601 UTC timestamp" 1 ;;
    *) check "column 9 is an ISO 8601 UTC timestamp" 0 "got '$TSCOL'" ;;
esac

# ---- 2. a multi-element paths[] survives the flat record --------------------
printf '\n2  a multi-element paths column round-trips to a JSON array\n'

emit_one() {  # emit_one PATHS_COLUMN -> findings.json fragment
    local rec="$WORK/rec"
    printf 'TTR-F-001\037Review\037process\037msg\037det\037T1059\0370.4\037false\037\037false\037process\0372026-10-18T00:00:00Z\037%s\037why\037\n' "$1" > "$rec"
    _emit_findings_json "$rec"
}

P3="$(printf '/usr/bin/a\035/opt/My App/b.sh\035/tmp/c')"
OUT="$(emit_one "$P3")"
printf '%s' "$OUT" > "$WORK/one.json"
R="$(python3 - "$WORK/one.json" <<'PY'
import json, sys
f = json.loads("[" + open(sys.argv[1], encoding="utf-8").read() + "]")[0]
want = ["/usr/bin/a", "/opt/My App/b.sh", "/tmp/c"]
print("OK" if f.get("paths") == want else "GOT:%r" % (f.get("paths"),))
PY
)"
check "three elements become three JSON strings, in order" "$([ "$R" = "OK" ] && echo 1 || echo 0)" "$R"

OUT="$(emit_one "")"
printf '%s' "$OUT" > "$WORK/empty.json"
R="$(python3 - "$WORK/empty.json" <<'PY'
import json, sys
f = json.loads("[" + open(sys.argv[1], encoding="utf-8").read() + "]")[0]
print("OK" if f.get("paths") == [] else "GOT:%r" % (f.get("paths"),))
PY
)"
check "an empty column becomes [], never null and never ['']" "$([ "$R" = "OK" ] && echo 1 || echo 0)" "$R"

OUT="$(emit_one "/only/one")"
printf '%s' "$OUT" > "$WORK/one1.json"
R="$(python3 - "$WORK/one1.json" <<'PY'
import json, sys
f = json.loads("[" + open(sys.argv[1], encoding="utf-8").read() + "]")[0]
print("OK" if f.get("paths") == ["/only/one"] else "GOT:%r" % (f.get("paths"),))
PY
)"
check "a single element is still an array of one" "$([ "$R" = "OK" ] && echo 1 || echo 0)" "$R"

# A path with a quote or a backslash must go through the same escaper every
# other string uses - the array must not become a second serialisation format.
PQ="$(printf '/tmp/say "hi"\035/tmp/back\\slash')"
OUT="$(emit_one "$PQ")"
printf '%s' "$OUT" > "$WORK/q.json"
R="$(python3 - "$WORK/q.json" <<'PY'
import json, sys
f = json.loads("[" + open(sys.argv[1], encoding="utf-8").read() + "]")[0]
want = ['/tmp/say "hi"', '/tmp/back\\slash']
print("OK" if f.get("paths") == want else "GOT:%r" % (f.get("paths"),))
PY
)"
check "quotes and backslashes in a path are escaped, not broken" "$([ "$R" = "OK" ] && echo 1 || echo 0)" "$R"

# ---- 3. paths[] is what the allowlist engine sees ---------------------------
printf '\n3  paths[] is the same set the allowlist engine judges\n'
EXTRACTED="$(al_paths_of "process /usr/bin/evil (PID 42)" "launched from /opt/tool/run.sh, see /usr/bin/evil again")"
N="$(printf '%s\n' "$EXTRACTED" | grep -c .)"
check "duplicate paths are collapsed" "$([ "$N" = "2" ] && echo 1 || echo 0)" "got $N: $(printf '%s' "$EXTRACTED" | tr '\n' ' ')"

echo
echo "flat-record arrays: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
