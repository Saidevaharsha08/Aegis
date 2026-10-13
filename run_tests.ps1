# PowerShell helper to run backend tests
Set-StrictMode -Version Latest
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $RepoDir
try {
    Push-Location "$RepoDir\backend"
    if (-not (Test-Path -Path ".venv\Scripts\Activate.ps1")) {
        python -m venv .venv
    }
    & ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    & ".venv\Scripts\python.exe" -m pytest -q
    Pop-Location
}
finally { Pop-Location }
