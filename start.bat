@echo off
REM NetShield-GNN one-click start for Windows: installs everything, trains if
REM needed, starts the servers and opens the console in your browser.
cd /d "%~dp0"
where py >nul 2>nul && (py -3 launch.py %*) || (python launch.py %*)
if errorlevel 1 (
  echo.
  echo Setup failed. Install Python 3.10+ from https://www.python.org/downloads/ and run start.bat again.
  pause
)
