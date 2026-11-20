param([switch]$Install)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
$taskPython = Join-Path $taskRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) { throw 'Create a Python 3.10+ venv first: python -m venv .venv' }
function Invoke-LabPython {
    param([string[]]$LabArguments)
    & $taskPython @LabArguments
    if ($LASTEXITCODE -ne 0) { throw "Lab command failed with exit code $LASTEXITCODE" }
}
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'
if ($Install) { Invoke-LabPython -LabArguments @('-m','pip','install','-r','requirements.txt') }
Invoke-LabPython -LabArguments @('-m','pip','check')
Invoke-LabPython -LabArguments @('-m','pytest','tests/smoke','tests/regression','-q')
Invoke-LabPython -LabArguments @('src/main.py','--part','2')
Invoke-LabPython -LabArguments @('src/main.py','--part','3')
Invoke-LabPython -LabArguments @('src/main.py','--part','4')
Invoke-LabPython -LabArguments @('-m','pytest','tests/public','-q')
Invoke-LabPython -LabArguments @('scripts/grade.py','--submission-dir','.','--out','outputs/grade_report.json')
Write-Host 'CP1-CP5 commands finished. Review outputs/lab_report.md and confirm CP4 has a real Red leak before submission.'