"""
TUESDAY RedTeam: Attack Console FastAPI Server (Port 8095)
Native Python HTTP server providing:
  - Interactive adversary dashboard UI
  - REST endpoints to launch real-time attack drills into Sentinel (Port 8090)
  - Live attack execution telemetry
"""

import os
import time
import requests
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from redteam.scenarios import SCENARIOS
from redteam.drills import privacy_harvester_drill, ransomware_canary_drill, registry_persistence_drill

PORT = int(os.environ.get("PORT", 8095))
SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://localhost:8090")

app = FastAPI(
    title="TUESDAY RedTeam — Adversary Attack Simulator",
    description="Purple-team attack generator that injects telemetry into Sentinel SOC",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DrillPayload(BaseModel):
    drillType: str

class LaunchPayload(BaseModel):
    scenarioKey: Optional[str] = None
    customScenario: Optional[Dict[str, Any]] = None

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "TUESDAY RedTeam Attack Simulator", "port": PORT}

@app.get("/api/scenarios")
def get_scenarios():
    return {"ok": True, "scenarios": SCENARIOS}

@app.post("/api/drills/run")
async def run_drill(payload: DrillPayload):
    drill = payload.drillType
    if drill == "privacy":
        res = privacy_harvester_drill.run()
        return {"ok": True, "drill": "privacy_harvester", "result": res}
    elif drill == "privacy_clean":
        res = privacy_harvester_drill.clean_sandbox()
        return {"ok": True, "drill": "privacy_clean", "result": res}
    elif drill == "ransomware":
        res = ransomware_canary_drill.run()
        return {"ok": True, "drill": "ransomware_canary", "result": res}
    elif drill == "ransomware_clean":
        res = ransomware_canary_drill.clean_canary()
        return {"ok": True, "drill": "ransomware_clean", "result": res}
    elif drill == "registry_plant":
        res = registry_persistence_drill.plant_canary()
        return {"ok": True, "drill": "registry_plant", "result": res}
    elif drill == "registry_clean":
        res = registry_persistence_drill.clean_canary()
        return {"ok": True, "drill": "registry_clean", "result": res}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown drillType: {drill}")

@app.post("/api/attack/launch")
async def launch_attack(payload: LaunchPayload):
    scenario = None
    if payload.scenarioKey and payload.scenarioKey in SCENARIOS:
        scenario = SCENARIOS[payload.scenarioKey]
    elif payload.customScenario:
        scenario = payload.customScenario

    if not scenario:
        raise HTTPException(status_code=400, detail="Scenario not found")

    alert_payload = {
        "id": scenario.get("id") or f"SIM-{hex(int(time.time()))[2:].upper()}",
        "title": scenario.get("title"),
        "source": scenario.get("source"),
        "targetHost": scenario.get("targetHost"),
        "ioc": scenario.get("ioc"),
        "payload": scenario.get("payload")
    }

    try:
        res = requests.post(f"{SENTINEL_URL}/api/incident", json={"alert": alert_payload, "threshold": 80}, timeout=15)
        sentinel_data = res.json()
        return {
            "ok": True,
            "message": f"Attack drill '{scenario.get('title')}' injected into Sentinel",
            "alert": alert_payload,
            "sentinelResponse": sentinel_data
        }
    except Exception as e:
        return JSONResponse(
            status_code=502,
            content={
                "ok": False,
                "error": f"Failed to reach Sentinel at {SENTINEL_URL}: {e}",
                "alert": alert_payload,
                "hint": "Ensure TUESDAY Sentinel is running on port 8090."
            }
        )

@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
def serve_ui():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TUESDAY RedTeam UI not found</h1>"

if __name__ == "__main__":
    import uvicorn
    print(f"[TUESDAY RedTeam] Adversary Attack Suite running on http://localhost:{PORT}")
    print(f"[TUESDAY RedTeam] Target Sentinel SOC: {SENTINEL_URL}")
    uvicorn.run("redteam.server:app", host="0.0.0.0", port=PORT, reload=False, log_level="info")
