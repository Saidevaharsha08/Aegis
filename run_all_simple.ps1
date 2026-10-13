<#
Simple PowerShell runner to start backend, frontend, and worker.
Uses `Start-Process` with explicit working directories to avoid CMD quoting issues.
Usage: open PowerShell in repo root and run `.
un_all_simple.ps1`
#>
Set-StrictMode -Version Latest
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Write-Host "Repo directory: $RepoDir"

Push-Location $RepoDir
try {
    # Create venv if missing
    $venvActivate = Join-Path $RepoDir "backend\.venv\Scripts\Activate.ps1"
    $venvPython = Join-Path $RepoDir "backend\.venv\Scripts\python.exe"
    if (-not (Test-Path -Path $venvActivate)) {
        Write-Host "Creating Python virtual environment..."
        python -m venv (Join-Path $RepoDir "backend\.venv")
    }

    # Install backend requirements using venv python
    Write-Host "Installing backend requirements..."
    & $venvPython -m pip install -r (Join-Path $RepoDir "backend\requirements.txt")

    # Ensure frontend deps
    if (-not (Test-Path -Path (Join-Path $RepoDir "frontend\node_modules"))) {
        Write-Host "Installing frontend dependencies (npm)..."
        Push-Location (Join-Path $RepoDir "frontend")
        npm ci
        Pop-Location
    }

    # Start backend in new PowerShell window
    $backendCmd = "Set-Location '$RepoDir\backend'; & '$venvActivate'; python -m uvicorn main:app --host 0.0.0.0 --port 8000"
    Start-Process -FilePath powershell -ArgumentList '-NoExit','-Command',$backendCmd -WorkingDirectory (Join-Path $RepoDir 'backend')

    # Start frontend
    $frontendCmd = "Set-Location '$RepoDir\frontend'; npm run dev"
    Start-Process -FilePath powershell -ArgumentList '-NoExit','-Command',$frontendCmd -WorkingDirectory (Join-Path $RepoDir 'frontend')

    # Start worker
    $workerCmd = "Set-Location '$RepoDir\backend'; & '$venvActivate'; python ingest_worker.py"
    Start-Process -FilePath powershell -ArgumentList '-NoExit','-Command',$workerCmd -WorkingDirectory (Join-Path $RepoDir 'backend')

    Write-Host "Launched backend, frontend, and worker in new PowerShell windows."
}
finally {
    Pop-Location
}
