@echo off
echo ===================================================
echo   TUESDAY - Launching Autonomous Agentic Cluster
echo ===================================================
echo.
echo [1/3] Starting TUESDAY Python Agent Swarm Core on Port 8092...
start "TUESDAY Python Swarm" cmd /k "cd /d %~dp0 && python -m uvicorn engine.server:app --host 0.0.0.0 --port 8092"

echo [2/3] Starting TUESDAY Sentinel (SOC Defense) on Port 8090...
start "TUESDAY Sentinel (SOC)" cmd /k "cd /d %~dp0\sentinel && node server.js"

echo [3/3] Starting TUESDAY RedTeam (Attack Suite) on Port 8095...
start "TUESDAY RedTeam (Simulator)" cmd /k "cd /d %~dp0\redteam && node server.js"

echo.
echo ===================================================
echo   Services initialized!
echo   - Python Agent Swarm:        http://localhost:8092/health
echo   - Sentinel Defense UI:       http://localhost:8090
echo   - RedTeam Attack Simulator:  http://localhost:8095
echo ===================================================
timeout /t 3 >nul
start http://localhost:8090
start http://localhost:8095

