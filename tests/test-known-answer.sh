#!/usr/bin/env bash
# TATAR Triage Toolkit - known-answer verification (Linux edition).
#
# The question a forensic tool should be able to answer before it touches
# evidence: does THIS build, on THIS machine, behave correctly on data whose
# correct answer is already known? Every other test here proves something about
# a run on the machine it runs on; this one replays a RECORDED finding set
# through the real analysis code lifted out of the collector and compares the
# result with an answer worked out from the rules.
#
# Nothing is collected and nothing on the host is touched, so the outcome
# cannot drift with the machine: a mismatch is the build, not the environment.
#
# Deliberately NOT a --self-test that plants suspicious files and checks they
# are found. tests/run-tests.sh T9 does a version of that and has already
# broken once on a host that would not run its own probe; on Windows the same
# idea is a Defender detection waiting to happen, and not tripping AV is this
# tool's first constraint.
#
# Run from the repo root:  bash tests/test-known-answer.sh
# Exit: 0 the build agrees with the known answer, 1 it does not.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
F2SRC="${2:-$HERE/fixtures/known-answer/findings-linux.f2}"
[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable"; exit 1; }
[ -r "$F2SRC" ]     || { echo "FAIL  fixture not readable"; exit 1; }

FSEP="$(printf '\037')"; GSEP="$(printf '\035')"
FN="$(awk '/^correlate_findings\(\) \{/ { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
# the lifted function takes its scratch files from the collector's mktmp helper
mktmp() { mktemp; }
case "$FN" in *'correlate_findings()'*) eval "$FN" ;; *) echo "FAIL  correlate_findings not found"; exit 1 ;; esac
CORRELATION_RULES="$(grep -m1 '^CORRELATION_RULES=' "$COLLECTOR" | sed 's/^CORRELATION_RULES="//; s/"$//')"
ARTIFACT_CLASSES="$(grep -m1 '^ARTIFACT_CLASSES=' "$COLLECTOR" | sed 's/^ARTIFACT_CLASSES="//; s/"$//')"
[ -n "$CORRELATION_RULES" ] && [ -n "$ARTIFACT_CLASSES" ] || { echo "FAIL  rules/vocabulary not found"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp "$F2SRC" "$WORK/f2"
echo "Replaying $(wc -l < "$WORK/f2" | tr -d ' ') recorded findings through $(basename "$COLLECTOR")"
echo
pass=0; fail=0
check() { if [ "$2" -eq 1 ]; then printf '  ok   %s\n' "$1"; pass=$((pass+1));
          else printf '  FAIL %s\n' "$1"; [ $# -ge 3 ] && printf '       %s\n' "$3"; fail=$((fail+1)); fi; }
conf_of() { awk -F"$FSEP" -v id="$1" '$1==id{print $7}' "$WORK/f2"; }
class_of() { awk -F"$FSEP" -v id="$1" '$1==id{print $16}' "$WORK/f2"; }

n="$(correlate_findings "$WORK/f2")"
raised="$(awk -F"$FSEP" '$7=="0.85"{printf "%s ", $1}' "$WORK/f2" | sed 's/ $//')"

# The known answer, from the RULES:
#   COR-02 is persistence + indicators on one path.
#   001 + 002 share /tmp/evil.sh        -> both rise
#   003 is suppressed, so 004 has no partner that may take part
#   005 is an IOC hit at 0.95, which outranks 0.85
#   006 names no path
check "correlation raises exactly TTR-F-001 TTR-F-002" \
      "$([ "$raised" = "TTR-F-001 TTR-F-002" ] && echo 1 || echo 0)" "got '$raised'"
check "the count it reports equals the number it changed" "$([ "$n" = 2 ] && echo 1 || echo 0)" "got '$n'"
check "TTR-F-003 stays suppressed and takes no part" \
      "$([ "$(conf_of TTR-F-003)" = "0.4" ] && echo 1 || echo 0)" "got $(conf_of TTR-F-003)"
check "TTR-F-004 does not rise - its only path-partner is suppressed" \
      "$([ "$(conf_of TTR-F-004)" = "0.7" ] && echo 1 || echo 0)" "got $(conf_of TTR-F-004)"
check "TTR-F-005 keeps 0.95 - an IOC hit outranks a correlation" \
      "$([ "$(conf_of TTR-F-005)" = "0.95" ] && echo 1 || echo 0)" "got $(conf_of TTR-F-005)"
check "TTR-F-006 does not rise - it names no path" \
      "$([ "$(conf_of TTR-F-006)" = "0.4" ] && echo 1 || echo 0)" "got $(conf_of TTR-F-006)"

bad=0
while IFS="$FSEP" read -r a b c d e f g h i j k l m nn o cls; do
    case " $ARTIFACT_CLASSES " in *" ${cls} "*) : ;; *) bad=$((bad+1)); echo "       $a -> $cls" ;; esac
    case " 0.4 0.7 0.85 0.95 " in *" $g "*) : ;; *) bad=$((bad+1)); echo "       $a confidence $g" ;; esac
    case "$b" in High|Review) : ;; *) bad=$((bad+1)); echo "       $a severity $b" ;; esac
done < "$WORK/f2"
check "every class is in the vocabulary, every confidence on the ladder, every severity a collector severity" \
      "$([ "$bad" -eq 0 ] && echo 1 || echo 0)" "$bad violation(s)"

echo
echo "known answer: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
