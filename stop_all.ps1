# PowerShell helper to stop backend/frontend/worker processes
Set-StrictMode -Version Latest
Write-Host "Stopping Aegis windows and processes..."

# Kill PowerShell windows started by run_all.ps1 (match by command line)
$patterns = @('uvicorn', 'npm run dev', 'ingest_worker.py')
foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
	if ($p.CommandLine) { $cmd = $p.CommandLine.ToLower() } else { $cmd = '' }
	foreach ($pat in $patterns) {
		if ($cmd -like "*${pat}*") {
			try {
				Write-Host "Stopping process pid=$($p.ProcessId) matching '$pat'"
				Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
			} catch {}
		}
	}
}

# Also stop node and python processes (fallback)
Get-Process -Name node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Stop attempt complete."
