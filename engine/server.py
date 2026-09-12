import os
import json
import asyncio
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from engine.orchestrator import SwarmOrchestrator
from engine.store import store

app = FastAPI(title="Project TUESDAY Python Agent Core", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = SwarmOrchestrator()
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENTINEL_DIR = os.path.join(ROOT_DIR, "sentinel")

class SecurityAlert(BaseModel):
    id: Optional[str] = "alert-001"
    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "HIGH"
    source: Optional[str] = "edr"
    host: Optional[str] = "DESKTOP-TUESDAY"
    targetHost: Optional[str] = "DESKTOP-TUESDAY"
    process: Optional[str] = None
    pid: Optional[int] = None
    ioc: Optional[str] = None
    payload: Optional[str] = None

class FeedbackPayload(BaseModel):
    agent: str
    type: str

@app.get("/api/status")
@app.get("/api/health")
def api_status():
    return {
        "status": "ok",
        "backend": "online",
        "engine": "llm",
        "model": "gemini-2.5-flash",
        "ollama": {
            "ok": True,
            "provider": "gemini",
            "model": "gemini-2.5-flash",
            "present": True,
            "available": ["gemini-2.5-flash"]
        },
        "stats": store.memory["stats"],
        "agents": 5
    }

@app.get("/api/memory")
def api_memory():
    return {
        "episodicMemory": store.memory["episodicMemory"],
        "auditLog": store.memory["auditLog"],
        "agentWeights": store.memory["agentWeights"],
        "stats": store.memory["stats"]
    }

@app.get("/api/audit")
def api_audit():
    return store.memory["auditLog"]

@app.post("/api/feedback")
def api_feedback(payload: FeedbackPayload):
    delta = 0.05 if payload.type == "up" else -0.05
    store.adjust_weight(payload.agent, delta)
    store.add_audit("REINFORCEMENT_LEARNING", f"Agent {payload.agent} weight adjusted {payload.type} -> {store.get_weight(payload.agent):.2f}")
    return {"agent": payload.agent, "weight": store.get_weight(payload.agent)}

@app.post("/api/incident")
@app.post("/api/investigate")
def investigate(alert_data: Dict[str, Any]):
    alert = alert_data.get("alert") or alert_data
    res = orchestrator.run_investigation(alert)
    store.memory["stats"]["incidents"] += 1
    store.memory["stats"]["llmRuns"] += 1
    store.save()
    return res

@app.post("/api/incident/stream")
@app.post("/api/investigate/stream")
async def investigate_stream(req: Request):
    body = await req.json()
    alert = body.get("alert") or body
    queue = asyncio.Queue()

    def sync_emitter(agent: str, message: str, level: str = "info"):
        payload = {
            "event": "log",
            "agent": agent,
            "message": message,
            "type": level
        }
        asyncio.run_coroutine_threadsafe(queue.put(payload), loop)

    loop = asyncio.get_event_loop()

    async def run_in_bg():
        try:
            result = await loop.run_in_executor(None, orchestrator.run_investigation, alert, sync_emitter)
            
            # Format UI event frames
            for v in result.get("votes", []):
                await queue.put({
                    "event": "vote",
                    "agentName": v["agent"],
                    "vote": v["vote"],
                    "confidence": v["confidence"],
                    "color": v["color"],
                    "key": v["key"]
                })

            if result.get("critic"):
                await queue.put({"event": "critic", "critic": result["critic"]})

            await queue.put({"event": "result", "result": result})
            store.memory["stats"]["incidents"] += 1
            store.memory["stats"]["llmRuns"] += 1
            store.save()
        except Exception as e:
            await queue.put({"event": "error", "message": str(e)})
        finally:
            await queue.put(None)

    asyncio.create_task(run_in_bg())

    async def event_generator():
        while True:
            item = await queue.get()
            if item is None:
                break
            ev_type = item.get("event", "log")
            yield f"event: {ev_type}\ndata: {json.dumps(item)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Direct Static UI Serving on Port 8092
@app.get("/")
def serve_index():
    return FileResponse(os.path.join(SENTINEL_DIR, "index.html"))

if os.path.exists(SENTINEL_DIR):
    app.mount("/", StaticFiles(directory=SENTINEL_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("engine.server:app", host="0.0.0.0", port=8092, reload=False)
