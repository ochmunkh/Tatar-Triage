<#
    TATAR Triage Toolkit - CSV cell safety unit tests (Windows edition).

    Every CSV this tool writes carries host-controlled text: file names,
    command lines, event messages. A cell that begins with = + @ or - is a
    FORMULA in Excel, LibreOffice and Google Sheets, so a file named

        =cmd|'/c calc'!A1.txt

    on the suspect host becomes code that runs on the ANALYST's machine the
    moment they open timeline.csv. It is the spreadsheet version of the
    separator injection the findings pipeline already defends against, and it
    lands somewhere worse: the analyst is certain to open the file.

    Case table shared with tests/test-csv-cell.sh, so both editions are held to
    the same rule. Protect-CsvCell is lifted out of the collector by text.

    Run from the repo root: powershell -NoProfile -File tests\Test-CsvCell.ps1
#>
#Requires -Version 5.1
param(
    [string]$Collector = (Join-Path $PSScriptRoot '..\Tatar.ps1'),
    [string]$Cases     = (Join-Path $PSScriptRoot 'fixtures\csv-cell-cases.tsv')
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$src = [IO.File]::ReadAllText($Collector)
foreach ($fn in 'function Protect-CsvCell','function ConvertTo-SafeCsv') {
    $st = $src.IndexOf($fn)
    if ($st -lt 0) { Write-Host "FAIL  $fn not found" -ForegroundColor Red; exit 1 }
    $d = 0; $i = $src.IndexOf('{', $st)
    while ($i -lt $src.Length) { if ($src[$i] -eq '{') { $d++ } elseif ($src[$i] -eq '}') { $d--; if ($d -eq 0) { break } }; $i++ }
    Invoke-Expression $src.Substring($st, $i - $st + 1)
}
Write-Host ("Lifted Protect-CsvCell and ConvertTo-SafeCsv from {0}" -f (Split-Path $Collector -Leaf))
Write-Host ''
function Check { param([string]$L,[bool]$Ok,[string]$D='')
    if ($Ok) { Write-Host "  ok   $L"; $script:pass++ }
    else { Write-Host "  FAIL $L" -ForegroundColor Red; if ($D) { Write-Host "       $D" -ForegroundColor DarkYellow }; $script:fail++ } }

foreach ($line in (Get-Content $Cases)) {
    if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
    $c = $line -split "`t"
    if ($c.Count -lt 2) { continue }
    $got = [string](Protect-CsvCell $c[0])
    Check $c[0] ($got -eq $c[1]) "expected [$($c[1])] got [$got]"
}

# end to end: the whole writer, not just the cell helper
$rows = @([pscustomobject]@{ Time = '2026-01-01'; Path = "=cmd|'/c calc'!A1.txt"; Source = 'fs' })
$csv = @($rows | ConvertTo-SafeCsv)
Check "ConvertTo-SafeCsv neutralises a formula in a real row" (($csv -join "`n") -match "'=cmd") ($csv -join ' | ')
Check "and keeps the header and the ordinary columns" (($csv[0] -match 'Time') -and (($csv -join "`n") -match '2026-01-01'))

Write-Host ''
Write-Host ("csv cell safety: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
