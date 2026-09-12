"""
Project TUESDAY: FastAPI Server
Primary REST + SSE API consumed by the Sentinel UI and RedTeam console.
Includes cluster worker endpoints, approval gate API, containment rollback, and incident history.
"""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from engine.orchestrator import SwarmOrchestrator
from engine.store import store
from engine.cluster import cluster_manager
from engine.inference import inference_engine


# =============================================================================
# LIFESPAN — startup/shutdown
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: start cluster discovery. Shutdown: stop it cleanly."""
    print("[TUESDAY] Starting cluster discovery...")
    cluster_manager.start()
    yield
    print("[TUESDAY] Shutting down cluster discovery...")
    cluster_manager.stop()


# =============================================================================
# APP INIT
# =============================================================================

app = FastAPI(
    title="Project TUESDAY — Tactical Edge AI",
    description="Multi-agent autonomous incident response for air-gapped tactical edge environments",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = SwarmOrchestrator()
host_event_queues: List[asyncio.Queue] = []


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class AlertPayload(BaseModel):
    id:         Optional[str] = None
    title:      Optional[str] = None
    source:     Optional[str] = None
    targetHost: Optional[str] = None
    ioc:        Optional[str] = None
    payload:    Optional[str] = None
    timestamp:  Optional[str] = None

class AgentRunPayload(BaseModel):
    agent_key:    str
    alert:        Dict[str, Any]
    past_episodes: List[Dict[str, Any]] = []
    peer_findings: Dict[str, str]       = {}

class CriticRunPayload(BaseModel):
    alert:        Dict[str, Any]
    verdicts:     Dict[str, Any]
    consensus_pct: int

class ApprovalDecision(BaseModel):
    decision: str   # "approve" | "reject"
    operator: Optional[str] = "Human SOC Operator"

class RollbackPayload(BaseModel):
    rule_name: str

class ModePayload(BaseModel):
    mode: str
    local_url: Optional[str] = None
    local_model: Optional[str] = None


# =============================================================================
# HEALTH & INFERENCE MODE
# =============================================================================

@app.get("/api/engine/mode")
def get_engine_mode():
    """Return current inference engine mode, active tier, and configuration."""
    return inference_engine.get_status()

@app.post("/api/engine/mode")
async def set_engine_mode(payload: ModePayload):
    """Set the inference mode: HYBRID, FULL_OFFLINE, or DETERMINISTIC_ONLY."""
    inference_engine.set_mode(
        mode=payload.mode,
        local_url=payload.local_url,
        local_model=payload.local_model
    )
    status_data = inference_engine.get_status()
    # Broadcast mode update to connected Sentinel UIs
    for q in list(host_event_queues):
        try:
            q.put_nowait({"event": "engine_mode_changed", "data": status_data})
        except Exception:
            pass
    return status_data

@app.get("/api/health")
def health():
    """Health check — also used by cluster nodes to verify peer availability."""
    return {
        "status":    "ok",
        "service":   "TUESDAY Tactical Edge AI",
        "version":   "2.0.0",
        "engine":    "gemini-2.5-flash",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

@app.get("/api/status")
def status():
    """Full system status: engine, memory, cluster, stats."""
    mem   = store.memory
    nodes = cluster_manager.get_healthy_nodes()
    inf_status = inference_engine.get_status()
    return {
        "ok":    True,
        "engine": inf_status.get("lastActiveTier", "llm"),
        "model":  inf_status.get("cloudConfig", {}).get("model", "gemini-2.5-flash"),
        "inference": inf_status,
        "stats":  mem.get("stats", {}),
        "cluster": {
            "size":           len(nodes) + 1,
            "workerNodes":    len(nodes),
            "distributedMode": len(nodes) > 0
        },
        "episodicMemorySize":   len(mem.get("episodicMemory", [])),
        "pendingApprovals":     len([a for a in mem.get("approvals", []) if a.get("status") == "PENDING"]),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

@app.get("/api/memory")
def memory():
    """Return episodic memory, agent weights, and audit log."""
    return {
        "episodicMemory": store.memory.get("episodicMemory", []),
        "agentWeights":   store.memory.get("agentWeights",   {}),
        "auditLog":       store.memory.get("auditLog",       [])[-30:],
        "stats":          store.memory.get("stats",          {})
    }


# =============================================================================
# INVESTIGATION — Sync + SSE Stream
# =============================================================================

@app.post("/api/incident")
@app.post("/api/investigate")
async def investigate(request: Request):
    """
    Sync investigation endpoint.
    Stats are incremented by store.commit_episode() inside the orchestrator — not here.
    """
    body  = await request.json()
    alert = body.get("alert") or body
    # Normalize host field
    if not alert.get("host"):
        alert["host"] = alert.get("targetHost", alert.get("target", "DESKTOP-TUESDAY"))

    # Broadcast initial detection to live Sentinel UIs immediately
    for q in list(host_event_queues):
        try:
            q.put_nowait({"event": "threat_detected", "data": alert})
        except Exception:
            pass

    loop = asyncio.get_running_loop()
    def live_broadcast(agent: str, msg: str, lvl: str):
        payload = {
            "type":      "log",
            "agent":     agent,
            "message":   msg,
            "level":     lvl,
            "timestamp": time.strftime("%H:%M:%S")
        }
        for q in list(host_event_queues):
            try:
                loop.call_soon_threadsafe(q.put_nowait, {"event": "agent_log", "data": payload})
            except Exception:
                pass

    result = await asyncio.to_thread(orchestrator.run_investigation, alert, live_broadcast)

    # Broadcast completed investigation results to all connected Sentinel UIs
    for q in list(host_event_queues):
        try:
            q.put_nowait({"event": "incident_result", "data": result})
        except Exception:
            pass

    return result


@app.post("/api/investigate/stream")
@app.post("/api/incident/stream")
async def investigate_stream(request: Request):
    """
    SSE streaming investigation endpoint.
    Opens a server-sent events stream that delivers real-time agent log lines
    as the investigation progresses. Used by the Sentinel UI for live animation.
    """
    body  = await request.json()
    alert = body.get("alert") or body
    if not alert.get("host"):
        alert["host"] = alert.get("targetHost", alert.get("target", "DESKTOP-TUESDAY"))

    queue: asyncio.Queue = asyncio.Queue()
    # Capture running loop to bridge sync orchestrator -> async SSE
    loop = asyncio.get_running_loop()

    def sync_emitter(agent: str, message: str, level: str):
        payload = {
            "type":      "log",
            "agent":     agent,
            "message":   message,
            "level":     level,
            "timestamp": time.strftime("%H:%M:%S")
        }
        asyncio.run_coroutine_threadsafe(queue.put(payload), loop)

    async def run_in_bg():
        try:
            result = await loop.run_in_executor(
                None, orchestrator.run_investigation, alert, sync_emitter
            )
            await queue.put({"type": "result", "data": result})
        except Exception as e:
            await queue.put({"type": "error", "message": str(e)})
        finally:
            await queue.put({"type": "done"})

    asyncio.create_task(run_in_bg())

    async def event_generator():
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=120)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") in ("done", "error"):
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# =============================================================================
# INCIDENT HISTORY
# =============================================================================

@app.get("/api/incidents")
def incidents_history():
    """Return all past incidents from episodic memory (for the history table in the UI)."""
    return {
        "incidents": store.memory.get("episodicMemory", []),
        "total":     len(store.memory.get("episodicMemory", [])),
        "stats":     store.memory.get("stats", {})
    }


# =============================================================================
# HUMAN-IN-THE-LOOP (HITL) APPROVAL GATE
# =============================================================================

@app.get("/api/approvals")
def get_approvals():
    """Return the HITL approval queue for the operator dashboard."""
    return {
        "approvals": store.memory.get("approvals", []),
        "pending":   [a for a in store.memory.get("approvals", []) if a.get("status") == "PENDING"]
    }

@app.post("/api/approvals/{approval_id}/decide")
async def decide_approval(approval_id: str, decision: ApprovalDecision):
    """Approve or reject a queued HITL containment action."""
    approvals = store.memory.get("approvals", [])
    entry = next((a for a in approvals if a.get("id") == approval_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id} not found")

    entry["status"]    = "APPROVED" if decision.decision == "approve" else "REJECTED"
    entry["operator"]  = decision.operator
    entry["decidedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    store.save()

    result = {"approval_id": approval_id, "status": entry["status"], "operator": entry["operator"]}

    if decision.decision == "approve":
        # Execute the deferred containment
        from engine.tools import isolate_host
        alert     = entry.get("alert", {})
        host      = alert.get("host", alert.get("targetHost", "unknown"))
        reason    = f"HITL-approved by {decision.operator} | Risk: {entry.get('riskScore')}/100"
        containment = isolate_host(host, reason)
        entry["containment"] = containment
        store.save()
        store.add_audit("HITL_APPROVED",
            f"Operator {decision.operator} approved containment of [{host}] | Status: {containment.get('status')}")
        result["containment"] = containment

    return result


# =============================================================================
# CONTAINMENT ROLLBACK
# =============================================================================

@app.post("/api/containment/rollback")
def containment_rollback(payload: RollbackPayload):
    """Remove a TUESDAY firewall isolation rule — rolls back host containment."""
    from engine.tools import unblock_host
    result = unblock_host(payload.rule_name)
    store.add_audit("CONTAINMENT_ROLLBACK", f"Rolled back rule: {payload.rule_name} | Status: {result.get('status')}")
    return result


# =============================================================================
# CLUSTER ENDPOINTS
# =============================================================================

@app.get("/api/cluster/status")
def cluster_status():
    """Return current cluster topology, node list, and distribution mode."""
    return cluster_manager.get_status()

@app.post("/api/cluster/refresh")
def cluster_refresh():
    """Trigger a new UDP discovery broadcast to find newly connected nodes."""
    cluster_manager.refresh()
    return {"message": "Discovery broadcast sent", "nodes": cluster_manager.node_count()}

# --- Worker endpoints (called by orchestrator on remote cluster nodes) ---

@app.post("/api/agent/run")
def run_remote_agent(payload: AgentRunPayload):
    """
    Worker endpoint: run a single agent investigation and return verdict.
    The orchestrator on the master node dispatches agents here.
    """
    from engine.agents import create_swarm
    swarm = create_swarm()
    agent = swarm.get(payload.agent_key)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Unknown agent key: {payload.agent_key}")
    result = agent.investigate(
        alert=payload.alert,
        peer_findings=payload.peer_findings,
        past_episodes=payload.past_episodes
    )
    return result

@app.post("/api/critic/run")
def run_remote_critic(payload: CriticRunPayload):
    """
    Worker endpoint: run the adversarial critic on this node.
    Provides genuinely independent validation (different hardware).
    """
    from engine.critic import AdversarialCritic
    critic = AdversarialCritic()
    result = critic.evaluate(
        alert=payload.alert,
        verdicts=payload.verdicts,
        consensus_pct=payload.consensus_pct,
        emit_log=None
    )
    return result


# =============================================================================
# SETTINGS
# =============================================================================

@app.post("/api/settings/provider")
async def set_provider(request: Request):
    """
    LLM provider settings endpoint.
    Currently Gemini only. Ollama support planned for future local-first mode.
    """
    body = await request.json()
    provider = body.get("provider", "gemini")
    return {"provider": provider, "status": "acknowledged",
            "note": "Gemini is the active provider. Ollama local mode coming soon."}


# =============================================================================
# TOOLS & COMPATIBILITY ENDPOINTS
# =============================================================================

@app.get("/api/tools/sigma")
def get_sigma_rules():
    """Expose Python Sigma rules to frontend."""
    from engine.tools import SIGMA_RULES
    return {"rules": SIGMA_RULES, "count": len(SIGMA_RULES)}

@app.get("/api/tools/ioc/{ioc_value}")
def get_ioc_intel(ioc_value: str):
    """Expose Python threat intelligence lookup to frontend."""
    from engine.tools import query_threat_intel
    return query_threat_intel(ioc_value)

@app.post("/api/incident/approve")
async def incident_approve_alias(request: Request):
    """Legacy alias for /api/approvals/{id}/decide with approve."""
    body = await request.json()
    approval_id = body.get("id")
    if not approval_id:
        raise HTTPException(status_code=400, detail="Missing approval id")
    return await decide_approval(approval_id, ApprovalDecision(decision="approve"))

@app.post("/api/incident/reject")
async def incident_reject_alias(request: Request):
    """Legacy alias for /api/approvals/{id}/decide with reject."""
    body = await request.json()
    approval_id = body.get("id")
    reason = body.get("reason", "Rejected by operator")
    if not approval_id:
        raise HTTPException(status_code=400, detail="Missing approval id")
    return await decide_approval(approval_id, ApprovalDecision(decision="reject", operator=reason))


# =============================================================================
# PRIVILEGED HOST EDR & SENSORS TELEMETRY
# =============================================================================

class HostUnblockPayload(BaseModel):
    ip: Optional[str] = None
    rule_name: Optional[str] = None

@app.get("/api/host/telemetry")
def get_host_telemetry():
    """Returns live Windows/Linux host sockets, autostart registry keys, and running processes."""
    from engine.tools import socket_inspect, registry_inspect, process_inspect
    sockets_res = socket_inspect()
    registry_res = registry_inspect()
    procs_res = process_inspect()

    rules = []
    for ep in store.memory.get("episodicMemory", []):
        c = ep.get("containment", {})
        if c and c.get("rule"):
            rules.append({
                "rule": c.get("rule"),
                "target": c.get("target", "DESKTOP-TUESDAY"),
                "mode": c.get("mode", "LIVE_NETSH"),
                "timestamp": c.get("timestamp"),
                "status": c.get("status", "ACTIVE")
            })

    return {
        "ok": True,
        "telemetry": {
            "host": "DESKTOP-TUESDAY",
            "os": "Windows 11 (Host Watchdog Active)",
            "sockets": {
                "totalActiveSockets": len(sockets_res.get("sockets", [])),
                "sockets": sockets_res.get("sockets", [])
            },
            "registry": {
                "entriesCount": len(registry_res.get("entries", [])),
                "entries": registry_res.get("entries", [])
            },
            "processes": {
                "count": len(procs_res.get("processes", [])),
                "processes": procs_res.get("processes", [])
            },
            "rules": rules
        }
    }

@app.get("/api/host/firewall/rules")
def get_host_firewall_rules():
    """Returns active firewall block rules created by TUESDAY."""
    rules = []
    for ep in store.memory.get("episodicMemory", []):
        c = ep.get("containment", {})
        if c and c.get("rule"):
            rules.append({
                "rule": c.get("rule"),
                "target": c.get("target", "DESKTOP-TUESDAY"),
                "mode": c.get("mode", "LIVE_NETSH"),
                "timestamp": c.get("timestamp"),
                "status": c.get("status", "ACTIVE")
            })
    return {"ok": True, "rules": rules}

@app.post("/api/host/firewall/unblock")
def post_host_firewall_unblock(payload: HostUnblockPayload):
    """Revokes a host firewall isolation rule."""
    from engine.tools import unblock_host
    rule_name = payload.rule_name
    if not rule_name:
        for ep in reversed(store.memory.get("episodicMemory", [])):
            c = ep.get("containment", {})
            if c.get("rule"):
                rule_name = c.get("rule")
                break
    if not rule_name:
        rule_name = "TUESDAY_ISOLATE_ACTIVE"

    result = unblock_host(rule_name)
    store.add_audit("FIREWALL_UNBLOCK", f"Revoked rule {rule_name} | Status: {result.get('status')}")
    return {"ok": True, "result": result}

@app.post("/api/host/daemon/toggle")
async def toggle_host_daemon(request: Request):
    """Toggle background host EDR watchdog state."""
    body = await request.json()
    enabled = body.get("enabled", True)
    return {"ok": True, "daemon": enabled, "status": "active" if enabled else "paused"}

@app.get("/api/host/stream")
async def host_stream():
    """
    Live SSE Event Stream:
    Pushes host telemetry updates and real-time threat_detected / incident_result
    events directly to all open Sentinel dashboards whenever an attack occurs.
    """
    queue: asyncio.Queue = asyncio.Queue()
    host_event_queues.append(queue)

    async def event_generator():
        try:
            # Emit immediate initial telemetry frame
            initial = get_host_telemetry()["telemetry"]
            yield f"event: telemetry\ndata: {json.dumps(initial)}\n\n"

            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=5)
                    ev_type = item.get("event", "message")
                    ev_data = item.get("data", {})
                    yield f"event: {ev_type}\ndata: {json.dumps(ev_data)}\n\n"
                except asyncio.TimeoutError:
                    # Periodic heartbeat with live telemetry update
                    tel = get_host_telemetry()["telemetry"]
                    yield f"event: telemetry\ndata: {json.dumps(tel)}\n\n"
        finally:
            if queue in host_event_queues:
                host_event_queues.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# =============================================================================
# STATIC FILES (Sentinel UI)
# =============================================================================

import os
from fastapi.staticfiles import StaticFiles

_sentinel_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel")
if os.path.exists(_sentinel_dir):
    app.mount("/", StaticFiles(directory=_sentinel_dir, html=True), name="sentinel")


# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("engine.server:app", host="0.0.0.0", port=8090, reload=False, log_level="info")

