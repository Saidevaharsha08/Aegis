@echo off
REM Run backend, frontend, and worker from repo root
SETLOCAL
pushd "%~dp0"
set "REPO_DIR=%CD%"
echo Repo directory: %REPO_DIR%

REM Prepare Python venv and install backend deps
pushd "%REPO_DIR%\backend"
if not exist .venv (
	echo Creating Python virtual environment...
	python -m venv .venv
)
call .venv\Scripts\activate.bat
echo Installing Python backend requirements...
python -m pip install -r requirements.txt
popd

REM Ensure frontend dependencies installed
if not exist "%REPO_DIR%\frontend\node_modules" (
	echo Installing frontend dependencies...
	pushd "%REPO_DIR%\frontend"
	call npm install
	popd
)

REM Start backend in new window
start "Aegis - Backend" /D "%REPO_DIR%\backend" cmd /k "call .venv\Scripts\activate.bat && python -m uvicorn main:app --host 0.0.0.0 --port 8000"

REM Start frontend in new window
start "Aegis - Frontend" /D "%REPO_DIR%\frontend" cmd /k "call npm run dev"

REM Start ingest worker in new window
start "Aegis - Worker" /D "%REPO_DIR%\backend" cmd /k "call .venv\Scripts\activate.bat && python ingest_worker.py"

echo Launched backend, frontend, and worker in separate windows.
echo Use stop_all.bat to stop processes.
popd
ENDLOCAL
