# PowerShell helper to start backend, frontend, and worker
Set-StrictMode -Version Latest
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Write-Host "Repo directory: $RepoDir"

Push-Location $RepoDir
try {
    # Backend venv
    if (-not (Test-Path -Path "$RepoDir\backend\.venv\Scripts\Activate.ps1")) {
        Write-Host "Creating Python virtual environment..."
        python -m venv "$RepoDir\backend\.venv"
    }
    # Install backend requirements
    Write-Host "Installing backend requirements..."
    & "$RepoDir\backend\.venv\Scripts\python.exe" -m pip install -r "$RepoDir\backend\requirements.txt"

    # Frontend dependencies
    if (-not (Test-Path -Path "$RepoDir\frontend\node_modules")) {
        Write-Host "Installing frontend dependencies..."
        Push-Location "$RepoDir\frontend"
        npm install
        Pop-Location
    }

    # Start backend in new PowerShell window
    Start-Process -FilePath powershell -ArgumentList '-NoExit','-Command',"Set-Location '$RepoDir\backend'; . .\.venv\Scripts\Activate.ps1; python -m uvicorn main:app --host 0.0.0.0 --port 8000"

    # Start frontend
    Start-Process -FilePath powershell -ArgumentList '-NoExit','-Command',"Set-Location '$RepoDir\frontend'; npm run dev"

    # Start worker
    Start-Process -FilePath powershell -ArgumentList '-NoExit','-Command',"Set-Location '$RepoDir\backend'; . .\.venv\Scripts\Activate.ps1; python ingest_worker.py"

    Write-Host "Launched backend, frontend, and worker in new PowerShell windows."
}
finally {
    Pop-Location
}
