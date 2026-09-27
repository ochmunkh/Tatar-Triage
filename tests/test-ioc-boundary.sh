#!/usr/bin/env bash
# TATAR Triage Toolkit - IOC boundary unit tests (Linux edition).
#
# Exercises ioc_match directly against the same case table the Windows tests
# use, so a rule that holds on one edition cannot quietly differ on the other.
# The function is extracted from the collector by text rather than sourced:
# sourcing tatar-linux.sh would run a collection.
#
# Run from the repo root:
#     bash tests/test-ioc-boundary.sh
#
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="$HERE/fixtures/ioc-boundary-cases.tsv"

[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable: $COLLECTOR"; exit 1; }
[ -r "$CASES" ]     || { echo "FAIL  case table not readable: $CASES"; exit 1; }

# Lift ioc_match(): from its definition line to the first closing brace that
# starts at column 0.
FN="$(awk '/^ioc_match\(\) \{/ { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in
    *'ioc_match()'*) : ;;
    *) echo "FAIL  ioc_match not found in $COLLECTOR"; exit 1 ;;
esac
eval "$FN"
echo "Lifted ioc_match from $(basename "$COLLECTOR") ($(printf '%s\n' "$FN" | wc -l | tr -d ' ') lines)"
echo

pass=0
fail=0
while IFS=$'\t' read -r token text expect note; do
    case "$token" in ''|'#'*) continue ;; esac
    [ -n "${expect:-}" ] || continue

    if ioc_match "$text" "$token"; then got=match; else got=nomatch; fi

    if [ "$got" = "$expect" ]; then
        pass=$((pass + 1))
        printf '  PASS  %-18s in %s\n' "$token" "$text"
    else
        fail=$((fail + 1))
        printf '  FAIL  %-18s in %s\n' "$token" "$text"
        printf '        expected %s, got %s  --  %s\n' "$expect" "$got" "${note:-}"
    fi
done < "$CASES"

echo
echo "IOC boundary: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
