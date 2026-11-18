#!/usr/bin/env bash
# TATAR Triage Toolkit - hosts "stock line" unit tests (Linux edition).
#
# The hosts finding counts custom entries. What counts as custom was a grep for
# the loopback addresses anywhere on a line, which got it wrong both ways: a
# clean Debian / Ubuntu file produced four false entries (the ip6-* lines), and
#   203.0.113.9 login.bank.example 127.0.0.1
#   fe80::1 attacker-router.example
# were hidden because they merely contain "127.0.0.1" or "::1". A line is now
# stock only if its address AND every name on it are ones the system ships.
#
# Case table shared with tests/Test-HostsDefault.ps1 so both editions are held
# to the same rule. Run from the repo root:  bash tests/test-hosts-default.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="${2:-$HERE/fixtures/hosts-default-cases.tsv}"
FN="$(awk '/^hosts_is_default\(\) \{/ { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in *'hosts_is_default()'*) eval "$FN" ;; *) echo "FAIL  hosts_is_default not found"; exit 1 ;; esac
echo "Lifted hosts_is_default from $(basename "$COLLECTOR")"; echo
pass=0; fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
while IFS=$'\t' read -r line exp note; do
    case "$line" in ''|'#'*) continue ;; esac
    if hosts_is_default "$line" "myhost"; then got=default; else got=custom; fi
    if [ "$got" = "$exp" ]; then ok "$note"
    else bad "$note : [$line] expected $exp, got $got"; fi
done < "$CASES"

# blank lines and comment-only lines are never entries
for l in '' '   ' '# 127.0.0.1 localhost' '   # a comment'; do
    if hosts_is_default "$l" "myhost"; then ok "not an entry: [$l]"; else bad "[$l] was counted as an entry"; fi
done
if hosts_is_default "$(printf '127.0.0.1 localhost\r')" "myhost"; then ok "a CRLF file does not turn a stock line into a custom one"
else bad "CRLF stock line counted as custom"; fi
if hosts_is_default "$(printf '127.0.0.1\tlocalhost')" "myhost"; then ok "TAB-separated fields read like space-separated ones"
else bad "TAB-separated stock line counted as custom"; fi
# a name that is a shell glob must be compared as text, never expanded
if hosts_is_default '127.0.0.1 *' "myhost"; then bad "a glob name was accepted"; else ok "a glob character in a name is compared as text"; fi
# with no host name, 127.0.1.1 cannot be vouched for
if hosts_is_default "127.0.1.1 myhost" ""; then bad "127.0.1.1 accepted with no host name"; else ok "127.0.1.1 is custom when the host name is unknown"; fi

echo
echo "hosts stock lines: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
