#!/usr/bin/env bash
# TATAR Triage Toolkit - json_escape unit tests (Linux edition).
#
# json_escape is the single choke point where raw bytes collected from the
# suspect host become JSON. Everything downstream - summary.json,
# findings.json, every SIEM/SOAR integration - is only as correct as this one
# function, and until now it had no test at all.
#
# It has three paths and ALL THREE are exercised here:
#   fast   - the string needs no escaping, returned without forking
#   python - json.dumps, the reference implementation
#   awk    - the no-python3 fallback, which has to be correct on its own
#
# The assertion is semantic, not textual: wrapping the result in quotes must
# produce JSON that parses and decodes back to the exact input. Two correct
# escapers may legitimately differ (raw UTF-8 vs \uXXXX), so comparing bytes
# would test a style, not a contract.
#
# The case table is inline rather than a fixture file: these inputs contain
# control characters, which no plain-text table can carry unambiguously.
#
# Run from the repo root:
#     bash tests/test-json-escape.sh
#
# Exit code: 0 = all cases passed, 1 = at least one failed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"

[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable: $COLLECTOR"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL  python3 is required to verify the results"; exit 1; }

# Lift json_escape(): from its definition line to the first closing brace that
# starts at column 0. Sourcing tatar-linux.sh would run a collection.
FN="$(awk '/^json_escape\(\) \{/ { grab = 1 } grab { print } grab && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in
    *'json_escape()'*) : ;;
    *) echo "FAIL  json_escape not found in $COLLECTOR"; exit 1 ;;
esac
eval "$FN"
echo "Lifted json_escape from $(basename "$COLLECTOR") ($(printf '%s\n' "$FN" | wc -l | tr -d ' ') lines)"
echo

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0

# verify NAME PATH INPUT ESCAPED
verify() {
    local name="$1" path="$2" input="$3" escaped="$4" verdict
    printf '%s' "$input"   > "$WORK/orig"
    printf '%s' "$escaped" > "$WORK/esc"
    verdict="$(python3 - "$WORK/orig" "$WORK/esc" <<'PY'
import json, sys
orig = open(sys.argv[1], "rb").read().decode("utf-8", "surrogateescape")
esc  = open(sys.argv[2], "rb").read().decode("utf-8", "surrogateescape")
try:
    got = json.loads('"' + esc + '"')
except Exception as e:
    print("UNPARSEABLE: %s" % e); raise SystemExit
print("OK" if got == orig else "MISMATCH: %r != %r" % (got, orig))
PY
)"
    if [ "$verdict" = "OK" ]; then
        pass=$((pass + 1))
        printf '  PASS  %-28s %s\n' "$name" "$path"
    else
        fail=$((fail + 1))
        printf '  FAIL  %-28s %s\n' "$name" "$path"
        printf '        %s\n' "$verdict"
    fi
}

# case NAME INPUT  - runs the input through every path json_escape has
case_both() {
    local name="$1" input="$2"
    verify "$name" "default" "$input" "$(json_escape "$input")"
    # Shadow python3 with a failing function so the awk fallback is the path
    # taken. A function beats PATH lookup, so the lifted code finds this one.
    verify "$name" "awk-fallback" "$input" "$(python3() { return 127; }; json_escape "$input")"
}

printf 'json_escape - round-trip through a real JSON parser\n\n'

# --- strings that must survive untouched (the fork-free fast path) ----------
case_both "plain path"            '/usr/bin/sleep'
case_both "path with spaces"      '/opt/My App/run.sh'
case_both "shell metacharacters"  '$(whoami) `id` ${HOME} | & ;'
case_both "percent and format"    '100% done %s %d %%'
case_both "utf-8 cyrillic"        'Монгол хэрэглэгч'
case_both "utf-8 emoji-free wide" '日本語ファイル名'
case_both "empty string"          ''
case_both "single quote"          "it's here"

# --- the two characters the old fallback did handle ------------------------
case_both "double quote"          'say "hello"'
case_both "backslash"             'C:\Windows\System32'
case_both "backslash then quote"  'a\"b'
case_both "trailing backslash"    'ends with \'
case_both "json-looking text"     '{"id":"TTR-F-001","x":1}'

# --- the C0 range the old fallback silently passed through -----------------
# Each of these produced invalid JSON before: a filename on the suspect host
# is enough to reach them, so they are the reason this test exists.
case_both "bell 0x07"             $'alert\x07bell'
case_both "escape 0x1b ansi"      $'\x1b[31mred\x1b[0m'
case_both "null-adjacent 0x01"    $'soh\x01here'
case_both "vertical tab 0x0b"     $'vt\x0bhere'
case_both "form feed 0x0c"        $'ff\x0chere'
case_both "backspace 0x08"        $'bs\x08here'
case_both "unit separator 0x1f"   $'field\x1fsep'
case_both "group separator 0x1d"  $'arr\x1delem'
case_both "tab"                   $'col1\tcol2'
case_both "embedded newline"      $'line1\nline2'
case_both "crlf"                  $'line1\r\nline2'
case_both "every C0 byte"         $'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

# --- combinations ----------------------------------------------------------
case_both "quote plus control"    $'say "hi"\x07now'
case_both "utf-8 plus quote"      'Монгол "хэрэглэгч"'
case_both "utf-8 plus control"    $'Монгол\x1bхэрэглэгч'
case_both "del 0x7f"              $'del\x7fhere'

echo
echo "json_escape: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
