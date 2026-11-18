#!/usr/bin/env bash
# TATAR Triage Toolkit (Linux) - tests for the fixes found by reading real scans (1.8.2).
#   K1  SUID / SGID come from ONE file-system walk and equal two independent walks
#   K2  journal extracts: bounded, sanitised, written only when they have content
#   K3  an unprivileged run names what it could not read (integrity, logs)
# Run from the repo root:  bash tests/test-linux-fixes.sh
COLLECTOR="${1:-$(dirname "$0")/../linux/tatar-linux.sh}"
pass=0; fail=0
ok() { pass=$((pass+1)); echo "  PASS  $1"; }
no() { fail=$((fail+1)); echo "  FAIL  $1  $2"; }
chk() { if eval "$2"; then ok "$1"; else no "$1" "${3:-}"; fi; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

echo; echo "K1  SUID / SGID: one walk, same answer as two walks"
OUT="$W/k1"; bash "$COLLECTOR" --modules suid --output "$OUT" --silent >/dev/null 2>&1
R="$(ls "$OUT"/*/TATAR_Report_*.txt 2>/dev/null | head -1)"
chk "K1 : the report was written" '[ -f "$R" ]'
rep_suid="$(sed -n '/^-- SUID --$/,/^-- SGID --$/p' "$R" | grep '^/' | sort)"
rep_sgid="$(sed -n '/^-- SGID --$/,$p' "$R" | grep '^/' | sort)"
ref_suid="$(find / -xdev -perm -4000 -type f 2>/dev/null | sort)"
ref_sgid="$(find / -xdev -perm -2000 -type f 2>/dev/null | sort)"
chk "K1 : SUID list equals an independent walk" '[ "$rep_suid" = "$ref_suid" ]' "report $(echo "$rep_suid" | wc -l) vs walk $(echo "$ref_suid" | wc -l)"
chk "K1 : SGID list equals an independent walk" '[ "$rep_sgid" = "$ref_sgid" ]' "report $(echo "$rep_sgid" | wc -l) vs walk $(echo "$ref_sgid" | wc -l)"
m=$(awk '/^m_suid\(\)/,/^}/' "$COLLECTOR" | grep -c 'find / -xdev')
chk "K1 : the module walks the tree once" '[ "$m" -eq 1 ]' "$m walks"

echo; echo "K2  journal extracts"
# lift the two helpers; stub journalctl so the test does not depend on the host's journal
have() { command -v "$1" >/dev/null 2>&1; }
SAN_SED=""
eval "$(awk '/^san_into\(\)/,/^unset _c _b1 _b2 _rest _cp/' "$COLLECTOR")" 2>/dev/null
eval "$(awk '/^sanitize_stream\(\)/{print; exit}' "$COLLECTOR")"
eval "$(awk '/^jc\(\)/,/^}/' "$COLLECTOR")"
eval "$(awk '/^jextract\(\)/,/^}/' "$COLLECTOR")"
mkdir -p "$W/bin"
cat > "$W/bin/journalctl" <<'STUB'
#!/usr/bin/env bash
case "$STUBMODE" in
  data)  printf '2026-11-18T10:00:00+0000 host sudo[1]: user : cmd=\033[31mowned\033[0m\n2026-11-18T10:00:01+0000 host sshd[2]: ok\n' ;;
  none)  echo "-- No entries --" ;;
  empty) : ;;
esac
STUB
chmod +x "$W/bin/journalctl"; PATH="$W/bin:$PATH"
export STUBMODE=data;  jextract "$W/j1.txt" -o short-iso; rc=$?
chk "K2 : an extract with content is written (exit 0)" '[ $rc -eq 0 ] && [ -s "$W/j1.txt" ]'
chk "K2 : the extract has no escape or control character" '! grep -qP "[\x00-\x08\x0b-\x1f\x7f]" "$W/j1.txt"'
chk "K2 : the content is kept" 'grep -q "sshd\[2\]: ok" "$W/j1.txt"'
export STUBMODE=none;  jextract "$W/j2.txt" -o short-iso; rc=$?
chk "K2 : '-- No entries --' writes nothing (exit 1)" '[ $rc -eq 1 ] && [ ! -e "$W/j2.txt" ]'
export STUBMODE=empty; jextract "$W/j3.txt" -o short-iso; rc=$?
chk "K2 : empty output writes nothing (exit 1)" '[ $rc -eq 1 ] && [ ! -e "$W/j3.txt" ]'

echo; echo "K3  an unprivileged run names what it could not read"
if [ "$(id -u)" -eq 0 ]; then
  echo "  SKIP  K3 : run as a normal user"
else
  OUT="$W/k3"; bash "$COLLECTOR" --modules integrity,logs --output "$OUT" --silent >/dev/null 2>&1
  L="$(ls "$OUT"/*/tatar.log 2>/dev/null | head -1)"
  if [ -e /etc/shadow ] && [ ! -r /etc/shadow ]; then
    chk "K3 : integrity names the files it could not hash" 'grep -q "integrity: not hashed, unreadable without root:.*/etc/shadow" "$L"'
  else echo "  SKIP  K3 : /etc/shadow is readable here"; fi
  chk "K3 : the run still finishes with exit 0 or 2" 'grep -q "Run complete" "$L"'
fi
echo; echo "RESULT  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
