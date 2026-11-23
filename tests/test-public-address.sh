#!/usr/bin/env bash
# TATAR Triage Toolkit - public address unit tests (Linux edition).
#
# external_ips.txt lists the public addresses of established connections, for
# the analyst to look up afterwards. A private, documentation or loopback
# address in it is noise; a public one missing from it is a lead lost. This
# runs public_addr_filter against the case table the Windows tests use, so both
# editions hold the same rule. The function is lifted out of the collector by
# text: sourcing tatar-linux.sh would run a collection.
#
# Run from the repo root:  bash tests/test-public-address.sh
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="$HERE/fixtures/public-address-cases.tsv"
FN="$(awk '/^public_addr_filter\(\) \{/ { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in *'public_addr_filter()'*) : ;; *) echo "FAIL  public_addr_filter not found in $COLLECTOR"; exit 1 ;; esac
eval "$FN"
echo "Lifted public_addr_filter from $(basename "$COLLECTOR")"
echo
pass=0; fail=0
while IFS=$'\t' read -r addr expect note; do
    case "$addr" in '#'*) continue ;; esac
    [ -n "${expect:-}" ] || continue
    if [ -n "$(printf '%s\tx\n' "$addr" | public_addr_filter)" ]; then got=public; else got=not; fi
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); printf '  PASS  %-28s %s\n' "$addr" "$note"
    else fail=$((fail+1)); printf '  FAIL  %-28s expected %s, got %s  --  %s\n' "$addr" "$expect" "$got" "$note"; fi
done < "$CASES"
echo
echo "public addresses: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
