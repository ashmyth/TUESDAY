"""
Project TUESDAY: FastAPI Python Agent Swarm Server
Exposes SSE real-time reasoning streams and REST investigation endpoints.
"""

import json
import asyncio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any

from engine.orchestrator import SwarmOrchestrator

app = FastAPI(title="Project TUESDAY Python Agent Core", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = SwarmOrchestrator()

class SecurityAlert(BaseModel):
    id: Optional[str] = "alert-001"
    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "HIGH"
    source: Optional[str] = "edr"
    host: Optional[str] = "DESKTOP-TUESDAY"
    process: Optional[str] = None
    pid: Optional[int] = None
    ioc: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "ok", "engine": "python-agentic", "model": "gemini-2.5-flash", "agents": 5}

@app.post("/api/investigate")
def investigate(alert: SecurityAlert):
    """Run complete investigation synchronously and return full telemetry."""
    res = orchestrator.run_investigation(alert.model_dump())
    return res

@app.post("/api/investigate/stream")
async def investigate_stream(alert: SecurityAlert):
    """Streams live multi-agent reasoning, tool executions, and consensus via SSE."""
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
            result = await loop.run_in_executor(None, orchestrator.run_investigation, alert.model_dump(), sync_emitter)
            await queue.put({"event": "complete", "result": result})
        except Exception as e:
            await queue.put({"event": "error", "error": str(e)})
        finally:
            await queue.put(None)

    asyncio.create_task(run_in_bg())

    async def event_generator():
        while True:
            item = await queue.get()
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("engine.server:app", host="0.0.0.0", port=8092, reload=False)
