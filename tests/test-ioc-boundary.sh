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

# ioc_scan is how a whole feed is matched in one pass. It carries its own copy
# of ioc_match's rule, so every case is run through it too: alone, and among a
# few thousand decoys that occur in no case text, in both of its modes.
SFN="$(awk '/^ioc_scan\(\) \{/ { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR")"
case "$SFN" in
    *'ioc_scan()'*) : ;;
    *) echo "FAIL  ioc_scan not found in $COLLECTOR"; exit 1 ;;
esac
eval "$SFN"
FSEP="$(printf '\037')"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
awk 'BEGIN { srand(7); for (k = 0; k < 1000; k++) {
        printf "decoy%d.example.invalid\n198.18.%d.%d\n", k, int(k / 250), k % 250
        h = ""; for (j = 0; j < 64; j++) h = h substr("0123456789abcdef", int(rand() * 16) + 1, 1); print h } }' > "$W/decoys"
echo "Lifted ioc_scan; $(wc -l < "$W/decoys" | tr -d ' ') decoys"
echo

pass=0
fail=0
while IFS=$'\t' read -r token text expect note; do
    case "$token" in ''|'#'*) continue ;; esac
    [ -n "${expect:-}" ] || continue

    if ioc_match "$text" "$token"; then got=match; else got=nomatch; fi

    # the one-pass matcher: records mode reads fields 4 and 5, lines mode the line
    printf '%s\n' "$token" > "$W/alone"; { cat "$W/decoys"; printf '%s\n' "$token"; } > "$W/crowd"
    printf 'id%ss%sc%s%s%s\n' "$FSEP" "$FSEP" "$FSEP" "$text" "$FSEP" > "$W/rec"
    : > "$W/hits"
    for feed in alone crowd; do
        r="$(ioc_scan records "$W/$feed" < "$W/rec")"
        l="$(printf '%s\n' "$text" | ioc_scan lines "$W/$feed" "$W/hits" | cut -f1)"
        if [ "$r" = "$token" ]; then rg=match; else rg=nomatch; fi
        if [ "$l" = "$token" ]; then lg=match; else lg=nomatch; fi
        if [ "$rg" != "$expect" ] || [ "$lg" != "$expect" ]; then
            got="ioc_scan $feed: records=$rg lines=$lg"
        fi
    done

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
