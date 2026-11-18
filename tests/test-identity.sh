#!/usr/bin/env bash
# TATAR Triage Toolkit - finding identity tests (Linux edition, schema 1.7).
# Functions are lifted from linux/tatar-linux.sh. The shared golden vectors in
# tests/fixtures/identity-vectors.tsv are also checked by Test-Identity.ps1 and
# tests/identity_ref.py, so the two editions cannot drift apart.
#   bash tests/test-identity.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
VEC="$HERE/fixtures/identity-vectors.tsv"
GSEP="$(printf '\035')"; FSEP="$(printf '\037')"
for fn in _hash16 mask_message finding_fingerprint finding_contenthash evidence_section json_escape _emit_findings_json; do
    body="$(awk -v n="$fn" '$0 ~ "^"n"\\(\\) \\{" { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
    case "$body" in *"$fn()"*) eval "$body" ;; *) echo "FAIL  $fn not found"; exit 1 ;; esac
done
pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then pass=$((pass+1)); printf '  ok   %s\n' "$1"; else fail=$((fail+1)); printf '  FAIL %s : expected [%s] got [%s]\n' "$1" "$3" "$2"; fi; }
echo "I1  golden vectors"
while IFS="$FSEP" read -r mod cls cat msg det sev conf paths efp ech; do
    case "$mod" in ''|'#'*) continue ;; esac
    p="$(printf '%s' "$paths" | sed "s/;;/$GSEP/g")"
    ck "fingerprint  ${msg:0:48}" "$(finding_fingerprint "$mod" "$cls" "$cat" "$msg" "$p")" "$efp"
    ck "contentHash  ${msg:0:48}" "$(finding_contenthash "$sev" "$conf" "$det")" "$ech"
done < <(tr '\t' '\037' < "$VEC")
echo "I2  properties"
a="$(finding_fingerprint m c k 'Process PID 1 started' '/a')"; b="$(finding_fingerprint m c k 'Process PID 99999 started' '/a')"
ck "a PID does not change the fingerprint" "$a" "$b"
a="$(finding_fingerprint m c k 'Listener 8080' '/a')"; b="$(finding_fingerprint m c k 'Listener 8081' '/a')"
[ "$a" != "$b" ] && ck "a port number is NOT masked (different finding)" 1 1 || ck "a port number is NOT masked (different finding)" same different
a="$(finding_fingerprint m c k 'x' "/a${GSEP}/b")"; b="$(finding_fingerprint m c k 'x' "/b${GSEP}/a")"
ck "path order does not matter" "$a" "$b"
a="$(finding_fingerprint m c k 'x' '/a')"; b="$(finding_fingerprint m2 c k 'x' '/a')"
[ "$a" != "$b" ] && ck "module is part of the identity" 1 1 || ck "module is part of the identity" same different
echo "I3  emitted JSON"
REPORT="/o/TATAR_Report_h.txt"
row="$(printf 'TTR-F-001\037High\037Process\037Suspicious process PID 4 in temp\037d\037T1059\0370.7\037false\037\037false\037process\0372026-01-01T00:00:00Z\037/tmp/x\037why\037\037process')"
f2="$(mktemp)"; printf '%s\n' "$row" > "$f2"
js="$(_emit_findings_json "$f2")"; rm -f "$f2"
python3 - "$js" <<'PY' || fail=$((fail+1))
import json,sys,re
d=json.loads('['+sys.argv[1]+']')[0]
ok=re.fullmatch(r'[0-9a-f]{16}',d['fingerprint']) and re.fullmatch(r'[0-9a-f]{16}',d['contentHash']) and d['evidence']==[{"file":"TATAR_Report_h.txt","section":"03 Processes (+ suspicious execution locations)"}]
print('  ok   fingerprint, contentHash and evidence are emitted' if ok else '  FAIL emitted fields: %r'%d)
sys.exit(0 if ok else 1)
PY
echo; echo "RESULT  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
