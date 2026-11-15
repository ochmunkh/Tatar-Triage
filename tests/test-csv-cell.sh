#!/usr/bin/env bash
# TATAR Triage Toolkit - CSV cell safety unit tests (Linux edition).
#
# Every CSV this tool writes carries host-controlled text: file names,
# command lines, event messages. A cell that begins with = + @ or - is a
# FORMULA in Excel, LibreOffice and Google Sheets, so a file named
#   =cmd|'/c calc'!A1.txt
# on the suspect host becomes code that runs on the ANALYST's machine the
# moment they open timeline.csv. This is the spreadsheet version of the
# separator injection the flat record already defends against, and it lands
# somewhere worse: the analyst is certain to open the file.
#
# The quoting half matters too - an unescaped " ends the field early and
# shifts every column after it, which the previous printf did not handle.
#
# Case table shared with tests/Test-CsvCell.ps1 so both editions are held to
# the same rule. Run from the repo root:  bash tests/test-csv-cell.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
CASES="${2:-$HERE/fixtures/csv-cell-cases.tsv}"
FN="$(awk '/^csv_cell\(\) \{/ { g = 1 } g { print } g && /^\}/ { exit }' "$COLLECTOR")"
case "$FN" in *'csv_cell()'*) eval "$FN" ;; *) echo "FAIL  csv_cell not found"; exit 1 ;; esac
echo "Lifted csv_cell from $(basename "$COLLECTOR")"; echo
pass=0; fail=0
while IFS=$'\t' read -r inp exp note; do
    case "$inp" in ''|'#'*) continue ;; esac
    got="$(csv_cell "$inp")"
    if [ "$got" = "$exp" ]; then printf '  ok   %s\n' "$inp"; pass=$((pass+1))
    else printf '  FAIL %s : expected [%s] got [%s]\n' "$inp" "$exp" "$got"; fail=$((fail+1)); fi
done < "$CASES"
# the quoting half, which has no column in the shared table because a literal
# quote cannot survive one unambiguously
q='say "hi".txt'; got="$(csv_cell "$q")"
if [ "$got" = 'say ""hi"".txt' ]; then printf '  ok   a double quote is doubled, so the field cannot end early\n'; pass=$((pass+1))
else printf '  FAIL quote doubling: got [%s]\n' "$got"; fail=$((fail+1)); fi
echo
echo "csv cell safety: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
