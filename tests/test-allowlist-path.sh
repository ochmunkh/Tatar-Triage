#!/usr/bin/env bash
# TATAR Triage Toolkit - allowlist path-extraction unit tests (Linux edition).
#
# The allowlist, hash and package-ownership passes can only ever match files the
# extractor found in a finding's message + detail. So whatever these two
# functions return IS the set of files an operator's allowlist can reach - a
# finding whose paths are not extracted is structurally unsuppressible, and a
# finding whose only extracted token is a DIRECTORY gets suppressed for a reason
# that has nothing to do with the files it counted.
#
# The functions are extracted from the collector by text rather than sourced:
# sourcing tatar-linux.sh would run a collection. Same technique, same shared
# case table shape as tests/test-ioc-boundary.sh.
#
# Run from the repo root:
#     bash tests/test-allowlist-path.sh
#
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="$HERE/fixtures/allowlist-path-cases.tsv"

[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable: $COLLECTOR"; exit 1; }
[ -r "$CASES" ]     || { echo "FAIL  case table not readable: $CASES"; exit 1; }

# Lift al_paths_of() and al_path_of(): from each definition line to the first
# closing brace that starts at column 0.
lift() {  # lift FUNCTION_NAME
    awk -v fn="$1" '$0 ~ "^"fn"\\(\\) \\{" { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR"
}
FN="$(lift al_paths_of)
$(lift al_path_of)"
case "$FN" in
    *'al_paths_of()'*) : ;;
    *) echo "FAIL  al_paths_of not found in $COLLECTOR"; exit 1 ;;
esac
case "$FN" in
    *'al_path_of()'*) : ;;
    *) echo "FAIL  al_path_of not found in $COLLECTOR"; exit 1 ;;
esac
eval "$FN"
echo "Lifted al_paths_of + al_path_of from $(basename "$COLLECTOR") ($(printf '%s\n' "$FN" | wc -l | tr -d ' ') lines)"
echo

pass=0
fail=0
while IFS=$'\t' read -r platform message detail expect_all expect_best note; do
    case "$platform" in ''|'#'*) continue ;; linux) : ;; *) continue ;; esac
    [ -n "${expect_all:-}" ] || continue
    # "-" is the placeholder for an empty column (see the header of the table).
    [ "$detail" = '-' ] && detail=''

    got_all="$(al_paths_of "$message" "$detail" | tr '\n' ' ' | sed 's/ *$//')"
    [ -n "$got_all" ] || got_all='-'

    if [ "$got_all" = "$expect_all" ]; then
        pass=$((pass + 1)); printf '  PASS  all   %s\n' "$message"
    else
        fail=$((fail + 1))
        printf '  FAIL  all   %s\n' "$message"
        printf '        expected [%s], got [%s]  --  %s\n' "$expect_all" "$got_all" "${note:-}"
    fi

    [ "${expect_best:--}" = '-' ] && continue
    got_best="$(al_path_of "$message" "$detail")"
    [ -n "$got_best" ] || got_best='-'
    if [ "$got_best" = "$expect_best" ]; then
        pass=$((pass + 1)); printf '  PASS  best  %s -> %s\n' "$message" "$got_best"
    else
        fail=$((fail + 1))
        printf '  FAIL  best  %s\n' "$message"
        printf '        expected [%s], got [%s]  --  %s\n' "$expect_best" "$got_best" "${note:-}"
    fi
done < "$CASES"

echo
echo "Allowlist path extraction: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
