@echo off
REM Stop common development processes (node and python)
SETLOCAL
echo Stopping Node.js and Python processes used by this project...
tasklist /FI "IMAGENAME eq node.exe" 2>NUL | find /I "node.exe" >NUL
if %ERRORLEVEL%==0 (
  echo Killing node.exe instances...
  taskkill /IM node.exe /F 2>NUL
)
tasklist /FI "IMAGENAME eq python.exe" 2>NUL | find /I "python.exe" >NUL
if %ERRORLEVEL%==0 (
  echo Killing python.exe instances...
  taskkill /IM python.exe /F 2>NUL
)
echo Done.
ENDLOCAL
