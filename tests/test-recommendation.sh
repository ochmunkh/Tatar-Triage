#!/usr/bin/env bash
# TATAR Triage Toolkit - recommendation tests (Linux edition, schema 1.8).
# recommendation_for is lifted from linux/tatar-linux.sh and compared with the
# shared reference tests/fixtures/recommendations.tsv, which Test-Recommendation.ps1
# checks for the Windows edition, so the two editions cannot drift apart.
#   bash tests/test-recommendation.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
REF="$HERE/fixtures/recommendations.tsv"
body="$(awk '$0 ~ "^recommendation_for\\(\\) \\{" { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
case "$body" in *"recommendation_for()"*) eval "$body" ;; *) echo "FAIL  recommendation_for not found"; exit 1 ;; esac
pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then pass=$((pass+1)); printf '  ok   %s\n' "$1"; else fail=$((fail+1)); printf '  FAIL %s : expected [%s] got [%s]\n' "$1" "$3" "$2"; fi; }
echo "R1  shared reference"
while IFS=$'\t' read -r cat txt; do
    [ -n "$cat" ] || continue
    probe="$cat"; [ "$cat" = "*" ] && probe="no-such-category"
    ck "category $cat" "$(recommendation_for "$probe")" "$txt"
done < "$REF"
echo "R2  every text is short, ASCII and free of quotes"
while IFS=$'\t' read -r cat txt; do
    ok=1; [ "${#txt}" -le 400 ] || ok=0
    case "$txt" in *\"*|*\'*|*\\*|*'$'*) ok=0 ;; esac
    printf '%s' "$txt" | LC_ALL=C grep -q '[^ -~]' && ok=0
    ck "text for $cat is clean" "$ok" 1
done < "$REF"
echo "R3  emitted JSON carries it"
for fn in json_escape _hash16 mask_message finding_fingerprint finding_contenthash evidence_section _emit_findings_json; do
    b="$(awk -v n="$fn" '$0 ~ "^"n"\\(\\) \\{" { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
    eval "$b"
done
GSEP="$(printf '\035')"; FSEP="$(printf '\037')"; REPORT="/o/TATAR_Report_h.txt"
row="$(printf 'TTR-F-001\037High\037suid\037odd setuid file\037d\037T1548.001\0370.7\037false\037\037false\037suid\0372026-01-01T00:00:00Z\037/usr/bin/x\037why\037\037suid')"
f2="$(mktemp)"; printf '%s\n' "$row" > "$f2"
js="$(_emit_findings_json "$f2")"; rm -f "$f2"
got="$(python3 -c 'import json,sys; print(json.loads("["+sys.argv[1]+"]")[0].get("recommendation",""))' "$js")"
ck "suid finding carries the suid text" "$got" "$(recommendation_for suid)"
echo; echo "recommendation tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
