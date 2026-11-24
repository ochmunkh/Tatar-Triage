#!/usr/bin/env bash
# TATAR Triage Toolkit - text indicator unit tests (Linux edition).
#
# The process and shell-history checks flag a command line that carries a URL
# written in hex or base64. This runs encoded_url_label against the case table
# the Windows tests use; rows marked "windows" (credential dumps) are skipped,
# because the Linux edition does not look for them. The function is lifted out
# of the collector by text: sourcing tatar-linux.sh would run a collection.
#
# Run from the repo root:  bash tests/test-text-indicator.sh
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="$HERE/fixtures/text-indicator-cases.tsv"
FN="$(awk '/^encoded_url_label\(\) \{/ { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in *'encoded_url_label()'*) : ;; *) echo "FAIL  encoded_url_label not found in $COLLECTOR"; exit 1 ;; esac
eval "$FN"
echo "Lifted encoded_url_label from $(basename "$COLLECTOR")"
echo
pass=0; fail=0
while IFS=$'\t' read -r text expect editions note; do
    case "$text" in '#'*|'') continue ;; esac
    [ "$editions" = "both" ] || continue
    if l="$(encoded_url_label "$text")"; then
        case "$l" in *base64*) got=base64 ;; *hex*) got=hex ;; *) got=other ;; esac
    else got=none; fi
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); printf '  PASS  %-8s %s\n' "$expect" "$note"
    else fail=$((fail+1)); printf '  FAIL  expected %s, got %s  --  %s\n' "$expect" "$got" "$note"; fi
done < "$CASES"
echo
echo "text indicators: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
