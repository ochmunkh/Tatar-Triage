#!/usr/bin/env bash
# TATAR Triage Toolkit - artifact-class mapping unit tests (Linux edition).
#
# artifactClass is the axis a suppression or IOC rule aims at: `category` is
# module-grained, so "persistence" covers cron, systemd units and shell
# profiles at once and a rule written against it cannot target one of them. A
# finding filed under the wrong class is therefore a finding the right rule
# will never match - a silent miss, which is the failure shape this project
# keeps correcting for.
#
# The case table is shared with tests/Test-ArtifactClass.ps1 so the two
# editions are held to one vocabulary and the rows that apply to both
# platforms are asserted on both.
#
# Run from the repo root:  bash tests/test-artifact-class.sh
# Exit: 0 all passed, 1 at least one failed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="${2:-$HERE/fixtures/artifact-class-cases.tsv}"
[ -r "$COLLECTOR" ] || { echo "FAIL  collector not readable"; exit 1; }
[ -r "$CASES" ]     || { echo "FAIL  cases not readable"; exit 1; }

FN="$(awk '/^map_artifact_class\(\) \{/ { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in *'map_artifact_class()'*) eval "$FN" ;; *) echo "FAIL  map_artifact_class not found"; exit 1 ;; esac
VOCAB="$(grep -m1 '^ARTIFACT_CLASSES=' "$COLLECTOR" | sed 's/^ARTIFACT_CLASSES="//; s/"$//')"
[ -n "$VOCAB" ] || { echo "FAIL  ARTIFACT_CLASSES not found"; exit 1; }
echo "Lifted map_artifact_class and $(printf '%s\n' $VOCAB | wc -l | tr -d ' ') classes from $(basename "$COLLECTOR")"
echo

pass=0; fail=0
while IFS=$'\t' read -r plat cat msg det expect note; do
    case "$plat" in ''|'#'*) continue ;; linux) : ;; *) continue ;; esac
    [ "$det" = "-" ] && det=""
    got="$(map_artifact_class "$cat" "$msg $det")"
    if [ "$got" = "$expect" ]; then
        printf '  ok   %s -> %s\n' "$cat" "$expect"; pass=$((pass+1))
    else
        printf '  FAIL %s : expected %s, got %s\n' "$cat" "$expect" "$got"; fail=$((fail+1))
    fi
    # whatever it returns must be in the closed vocabulary, always
    case " $VOCAB " in
        *" $got "*) pass=$((pass+1)) ;;
        *) printf '  FAIL %s : %s is not in ARTIFACT_CLASSES\n' "$cat" "$got"; fail=$((fail+1)) ;;
    esac
done < "$CASES"

echo
echo "artifact class mapping: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
