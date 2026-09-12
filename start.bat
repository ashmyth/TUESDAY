@echo off
echo ===================================================
echo   TUESDAY - Launching Dual Air-Gapped Ecosystem
echo ===================================================
echo.
echo [1/2] Starting TUESDAY Sentinel (SOC Defense) on Port 8090...
start "TUESDAY Sentinel (SOC)" cmd /k "cd /d %~dp0\sentinel && node server.js"

echo [2/2] Starting TUESDAY RedTeam (Attack Suite) on Port 8095...
start "TUESDAY RedTeam (Simulator)" cmd /k "cd /d %~dp0\redteam && node server.js"

echo.
echo ===================================================
echo   Both services initialized!
echo   - Sentinel Defense Dashboard: http://localhost:8090
echo   - RedTeam Attack Simulator:  http://localhost:8095
echo ===================================================
timeout /t 3 >nul
start http://localhost:8090
start http://localhost:8095
