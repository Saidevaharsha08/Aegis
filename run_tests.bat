@echo off
REM Run backend tests from repo root
SETLOCAL
pushd "%~dp0backend"
if not exist .venv (
  echo Creating Python virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
echo Installing requirements (if needed)...
python -m pip install -r requirements.txt
echo Running pytest...
python -m pytest -q
popd
ENDLOCAL
