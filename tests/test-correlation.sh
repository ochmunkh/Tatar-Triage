#!/usr/bin/env bash
# TATAR Triage Toolkit - evidence correlation unit tests (Linux edition).
#
# correlate_findings() is the pass that turns "two artifacts happen to name the
# same path" into a stated, auditable claim. It is the one place in the tool
# that RAISES the confidence of a finding on the strength of another finding,
# so the ways it must NOT fire matter at least as much as the way it must:
#
#   - a module agreeing with itself is one artifact seen twice, not two
#     agreeing, and must not raise anything
#   - a suppressed finding was already judged known-good by the allowlist;
#     correlating on it would re-raise exactly the noise the allowlist removed
#   - an IOC hit already carries 0.95 and must not be demoted to 0.85
#   - Linux paths are CASE-SENSITIVE: /tmp/x and /Tmp/X are different files and
#     must never be treated as agreement (the Windows edition folds case for the
#     opposite reason, and an earlier draft of this pass wrongly folded it here)
#   - nothing but columns 7 and 14 may change: severity is the analyst's scale,
#     and correlation makes an existing lead more credible, it does not make a
#     new claim
#
# The function is lifted out of the collector rather than sourced, the same way
# tests/test-json-escape.sh lifts json_escape: sourcing tatar-linux.sh would run
# a collection.
#
# Run from the repo root:
#     bash tests/test-correlation.sh
#
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable: $COLLECTOR"; exit 1; }

FSEP="$(printf '\037')"
GSEP="$(printf '\035')"

# Lift correlate_findings() and the rule table it reads. The rules are lifted
# from the collector too, deliberately: a test carrying its own copy would pass
# while the shipped rules were broken.
FN="$(awk '/^correlate_findings\(\) \{/ { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in
    *'correlate_findings()'*) : ;;
    *) echo "FAIL  correlate_findings not found in $COLLECTOR"; exit 1 ;;
esac
eval "$FN"
CORRELATION_RULES="$(grep -m1 '^CORRELATION_RULES=' "$COLLECTOR" | sed 's/^CORRELATION_RULES="//; s/"$//')"
[ -n "$CORRELATION_RULES" ] || { echo "FAIL  CORRELATION_RULES not found in $COLLECTOR"; exit 1; }
echo "Lifted correlate_findings from $(basename "$COLLECTOR") ($(printf '%s\n' "$FN" | wc -l | tr -d ' ') lines)"
echo "Rules under test: $CORRELATION_RULES"
echo

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

check() {  # check LABEL CONDITION [DETAIL]
    if [ "$2" -eq 1 ]; then
        printf '  ok   %s\n' "$1"; pass=$((pass+1))
    else
        printf '  FAIL %s\n' "$1"; [ $# -ge 3 ] && printf '       %s\n' "$3"
        fail=$((fail+1))
    fi
}

# row ID SEV CAT MSG MOD PATHS CONF SUPPRESSED IOC -> one 15-column F2 record
row() {
    printf '%s' "$1"; printf '%s' "$FSEP"; printf '%s' "$2"; printf '%s' "$FSEP"
    printf '%s' "$3"; printf '%s' "$FSEP"; printf '%s' "$4"; printf '%s' "$FSEP"
    printf 'detail'; printf '%s' "$FSEP"; printf 'T1059'; printf '%s' "$FSEP"
    printf '%s' "$7"; printf '%s' "$FSEP"; printf '%s' "$8"; printf '%s' "$FSEP"
    printf '%s' ""; printf '%s' "$FSEP"; printf '%s' "$9"; printf '%s' "$FSEP"
    printf '%s' "$5"; printf '%s' "$FSEP"; printf '2026-01-01T00:00:00Z'; printf '%s' "$FSEP"
    printf '%s' "$6"; printf '%s' "$FSEP"; printf 'original reason'; printf '%s' "$FSEP"
    printf '%s' ""; printf '\n'
}

col() { cut -d"$FSEP" -f"$2" <<< "$(grep -m1 "^$1$FSEP" "$3")"; }

# ---------------------------------------------------------------------------
echo "-- COR-02 fires when persistence and indicators name the same path --"
F="$WORK/a"
row TTR-F-001 Review persistence 'cron entry' persistence '/tmp/evil.sh' 0.4 false false  > "$F"
row TTR-F-002 High   indicators  'exec in tmp' indicators  '/tmp/evil.sh' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T1 : both sides were raised (count = 2)" "$([ "$n" = 2 ] && echo 1 || echo 0)" "got '$n'"
check "T2 : persistence confidence is 0.85" "$([ "$(col TTR-F-001 7 "$F")" = 0.85 ] && echo 1 || echo 0)" "got '$(col TTR-F-001 7 "$F")'"
check "T3 : indicators confidence is 0.85"  "$([ "$(col TTR-F-002 7 "$F")" = 0.85 ] && echo 1 || echo 0)" "got '$(col TTR-F-002 7 "$F")'"
r="$(col TTR-F-001 14 "$F")"
check "T4 : the reason names the rule id"    "$(case "$r" in *COR-02*) echo 1;; *) echo 0;; esac)" "got '$r'"
check "T5 : the reason names the rule"       "$(case "$r" in *autorun-on-suspect-file*) echo 1;; *) echo 0;; esac)" "got '$r'"
check "T6 : the reason names BOTH modules"   "$(case "$r" in *persistence*indicators*) echo 1;; *) echo 0;; esac)" "got '$r'"
check "T7 : the reason names the other finding" "$(case "$r" in *TTR-F-002*) echo 1;; *) echo 0;; esac)" "got '$r'"
check "T8 : the reason names the shared path"   "$(case "$r" in */tmp/evil.sh*) echo 1;; *) echo 0;; esac)" "got '$r'"
check "T9 : severity was NOT changed"        "$([ "$(col TTR-F-001 2 "$F")" = Review ] && echo 1 || echo 0)" "got '$(col TTR-F-001 2 "$F")'"
check "T10: no finding was added or removed" "$([ "$(wc -l < "$F" | tr -d ' ')" = 2 ] && echo 1 || echo 0)"

echo "-- only columns 7 and 14 may change --"
F2="$WORK/b"; cp "$F" "$F2"
row TTR-F-001 Review persistence 'cron entry' persistence '/tmp/evil.sh' 0.4 false false  > "$WORK/pre"
row TTR-F-002 High   indicators  'exec in tmp' indicators  '/tmp/evil.sh' 0.7 false false >> "$WORK/pre"
diffcols=""
for c in 1 2 3 4 5 6 8 9 10 11 12 13 15; do
    a="$(cut -d"$FSEP" -f$c "$WORK/pre" | tr '\n' '|')"
    b="$(cut -d"$FSEP" -f$c "$F2" | tr '\n' '|')"
    [ "$a" = "$b" ] || diffcols="$diffcols $c"
done
check "T11: every column except 7 and 14 is byte-identical" "$([ -z "$diffcols" ] && echo 1 || echo 0)" "changed:$diffcols"

echo "-- the ways it must NOT fire --"
F="$WORK/c"
row TTR-F-001 Review persistence 'a' persistence '/tmp/evil.sh' 0.4 false false  > "$F"
row TTR-F-002 Review persistence 'b' persistence '/tmp/evil.sh' 0.4 false false >> "$F"
n="$(correlate_findings "$F")"
check "T12: a module agreeing with ITSELF raises nothing" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"

F="$WORK/d"
row TTR-F-001 Review persistence 'a' persistence '/tmp/evil.sh' 0.4 true  false  > "$F"
row TTR-F-002 High   indicators  'b' indicators  '/tmp/evil.sh' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T13: a SUPPRESSED finding does not correlate" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"
check "T14: and the other side keeps its confidence" "$([ "$(col TTR-F-002 7 "$F")" = 0.7 ] && echo 1 || echo 0)"

F="$WORK/e"
row TTR-F-001 High persistence 'a' persistence '/tmp/evil.sh' 0.95 false true   > "$F"
row TTR-F-002 High indicators  'b' indicators  '/tmp/evil.sh' 0.7  false false >> "$F"
n="$(correlate_findings "$F")"
check "T15: an IOC hit is not demoted to 0.85" "$([ "$(col TTR-F-001 7 "$F")" = 0.95 ] && echo 1 || echo 0)" "got '$(col TTR-F-001 7 "$F")'"
check "T16: and it does not correlate" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"

F="$WORK/f"
row TTR-F-001 Review persistence 'a' persistence '/tmp/evil.sh'  0.4 false false  > "$F"
row TTR-F-002 High   indicators  'b' indicators  '/tmp/other.sh' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T17: different paths raise nothing" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"

F="$WORK/g"
row TTR-F-001 Review persistence 'a' persistence '/tmp/evil.sh' 0.4 false false  > "$F"
row TTR-F-002 High   indicators  'b' indicators  '/Tmp/Evil.sh' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T18: Linux paths are case-sensitive - /tmp/x and /Tmp/X are NOT agreement" \
      "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n' - case folding would correlate two unrelated files"

F="$WORK/h"
row TTR-F-001 Review users    'a' users    '/tmp/evil.sh' 0.4 false false  > "$F"
row TTR-F-002 High   sshkeys  'b' sshkeys  '/tmp/evil.sh' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T19: modules no rule names raise nothing" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"

F="$WORK/i"
row TTR-F-001 Review persistence 'a' persistence '' 0.4 false false  > "$F"
row TTR-F-002 High   indicators  'b' indicators  '' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T20: findings with no path raise nothing" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"

echo "-- an empty findings file and a second run --"
: > "$WORK/empty"
n="$(correlate_findings "$WORK/empty")"
check "T21: an empty findings file returns 0, not an error" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"

F="$WORK/j"
row TTR-F-001 Review persistence 'a' persistence '/tmp/evil.sh' 0.4 false false  > "$F"
row TTR-F-002 High   indicators  'b' indicators  '/tmp/evil.sh' 0.7 false false >> "$F"
correlate_findings "$F" >/dev/null
before="$(cat "$F")"
n="$(correlate_findings "$F")"
check "T22: a second run is idempotent (raises nothing more)" "$([ "$n" = 0 ] && echo 1 || echo 0)" "count '$n'"
check "T23: and leaves the file unchanged" "$([ "$before" = "$(cat "$F")" ] && echo 1 || echo 0)"

echo "-- multiple paths in one finding --"
F="$WORK/k"
row TTR-F-001 Review persistence 'a' persistence "/tmp/clean.sh${GSEP}/tmp/evil.sh" 0.4 false false  > "$F"
row TTR-F-002 High   indicators  'b' indicators  '/tmp/evil.sh' 0.7 false false >> "$F"
n="$(correlate_findings "$F")"
check "T24: agreement on ANY of a finding's paths is enough" "$([ "$n" = 2 ] && echo 1 || echo 0)" "count '$n'"

echo
echo "-------------------------------------------"
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ] || exit 1
