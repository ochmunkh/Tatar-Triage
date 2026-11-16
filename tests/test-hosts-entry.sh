#!/usr/bin/env bash
# TATAR Triage Toolkit - hosts entry unit tests (Linux edition).
#
# The hosts finding quotes the first few overrides into its detail so the
# analyst sees what was redirected without opening another file. That text
# comes from the suspect host, and a finding's detail is read by the path
# extractor and the allowlist. A crafted line such as
#   1.2.3.4 /usr/sbin/sshd
# would otherwise put a trusted binary into paths[], and an allowlist rule
# could then suppress the very finding that reports the tampering.
#
# Case table shared with tests/Test-HostsEntry.ps1 so both editions are held to
# the same rule. Run from the repo root:  bash tests/test-hosts-entry.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="${2:-$HERE/fixtures/hosts-entry-cases.tsv}"
FN="$(awk '/^hosts_entry\(\) \{/ { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in *'hosts_entry()'*) eval "$FN" ;; *) echo "FAIL  hosts_entry not found"; exit 1 ;; esac
echo "Lifted hosts_entry from $(basename "$COLLECTOR")"; echo
pass=0; fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
while IFS=$'\t' read -r inp exp note; do
    case "$inp" in ''|'#'*) continue ;; esac
    got="$(hosts_entry "$inp")"
    if [ "$got" = "$exp" ]; then ok "$note"
    else bad "$note : [$inp] expected [$exp] got [$got]"; fi
    # the property the table exists for, checked on every row rather than
    # trusted to the expected column: nothing path-shaped may come out
    case "$got" in
        */*|*\\*) bad "$note : output still carries a path separator [$got]" ;;
    esac
done < "$CASES"

got="$(hosts_entry "$(printf '10.0.0.5\ta.local\tb.local')")"
if [ "$got" = '10.0.0.5 -> a.local b.local' ]; then ok "TAB-separated fields read like space-separated ones"
else bad "TAB-separated: got [$got]"; fi

got="$(hosts_entry "$(printf '10.0.0.5 a.local\r')")"
if [ "$got" = '10.0.0.5 -> a.local' ]; then ok "a CRLF hosts file does not leave a stray character on the name"
else bad "CRLF: got [$got]"; fi

long="1.2.3.4"; i=0
while [ "$i" -lt 40 ]; do i=$((i+1)); long="$long alias$i.example"; done
got="$(hosts_entry "$long")"
if [ "${#got}" -eq 103 ] && [ "${got: -3}" = "..." ]; then ok "a line with many aliases is capped at 100 characters"
else bad "cap: length ${#got}"; fi

echo
echo "hosts entry: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
