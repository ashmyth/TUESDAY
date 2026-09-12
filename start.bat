@echo off
echo ===================================================
echo   TUESDAY - Launching Autonomous Agentic Cluster
echo ===================================================
echo.
echo [1/2] Starting TUESDAY Python FastAPI Agent Swarm on Port 8090...
start "TUESDAY Python FastAPI Swarm" cmd /k "cd /d %~dp0 && python -m uvicorn engine.server:app --host 0.0.0.0 --port 8090"

echo [2/2] Starting TUESDAY RedTeam (Attack Suite) on Port 8095...
start "TUESDAY RedTeam (Simulator)" cmd /k "cd /d %~dp0 && python -m uvicorn redteam.server:app --host 0.0.0.0 --port 8095"

echo.
echo ===================================================
echo   Services initialized!
echo   - Sentinel Defense (Python FastAPI): http://localhost:8090
echo   - RedTeam Attack Simulator (Python): http://localhost:8095
echo ===================================================
timeout /t 3 >nul
start http://localhost:8090
start http://localhost:8095
