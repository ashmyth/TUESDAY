"""
Project TUESDAY: Persistent Store (JSON-file backed) in Python
Stores episodic memory, agent RL weights, audit trail, and human approval queue.
"""

import os
import json
from typing import Dict, Any, List, Optional

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel", "data", "store.json")

class Store:
    def __init__(self, file_path: str = DATA_PATH):
        self.file_path = file_path
        self.memory = {
            "episodicMemory": [],
            "agentWeights": {
                "log": 1.0,
                "threatintel": 1.0,
                "malware": 1.0,
                "cloud": 1.0,
                "critic": 1.0
            },
            "auditLog": [],
            "approvals": [],
            "stats": {"incidents": 0, "llmRuns": 0, "rulesRuns": 0, "totalToolCalls": 0}
        }
        self.load()

    def load(self):
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.memory.update(data)
        except Exception as e:
            print(f"[Store] Error loading store: {e}")

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            tmp_path = self.file_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.memory, f, indent=2)
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
            os.rename(tmp_path, self.file_path)
        except Exception as e:
            print(f"[Store] Error saving store: {e}")

    def get_weight(self, agent_key: str) -> float:
        return self.memory["agentWeights"].get(agent_key, 1.0)

    def set_weight(self, agent_key: str, weight: float):
        self.memory["agentWeights"][agent_key] = max(0.1, min(3.0, weight))
        self.save()

    def adjust_weight(self, agent_key: str, delta: float):
        cur = self.get_weight(agent_key)
        self.set_weight(agent_key, cur + delta)

    def add_audit(self, action: str, details: str):
        import time
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": action,
            "details": details
        }
        self.memory["auditLog"].insert(0, entry)
        if len(self.memory["auditLog"]) > 100:
            self.memory["auditLog"] = self.memory["auditLog"][:100]
        self.save()

    def recall_similar(self, alert: Dict[str, Any], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Episodic memory retrieval: TTP-weighted + keyword matching.
        TTP overlap scores higher than keyword match — same attack family = same TTPs.
        """
        title    = (alert.get("title")   or "").lower()
        ioc      = (alert.get("ioc")     or "").lower()
        process  = (alert.get("process") or "").lower()
        payload  = (alert.get("payload") or "").lower()

        query_keywords = set(
            w for w in (title + " " + ioc + " " + process + " " + payload).split()
            if len(w) > 3
        )
        # Extract TTPs from alert payload via quick sigma scan
        alert_ttps: set = set()
        if payload or title:
            try:
                from engine.tools import sigma_scan
                scan_result = sigma_scan(payload or title)
                alert_ttps = set(scan_result.get("ttpsDetected", []))
            except Exception:
                pass

        scored = []
        for ep in self.memory["episodicMemory"]:
            ep_text = " ".join([
                ep.get("title",   ""),
                ep.get("ioc",     ""),
                ep.get("process", ""),
                ep.get("status",  ""),
            ]).lower()
            ep_ttps = set(ep.get("ttpsDetected", []))

            # TTP overlap = high relevance (same attack family)
            ttp_overlap = len(alert_ttps & ep_ttps)
            kw_score    = sum(1 for w in query_keywords if w in ep_text)
            score       = (ttp_overlap * 5) + kw_score  # TTP match worth 5x keyword

            if score > 0:
                scored.append((score, ep))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [ep for _, ep in scored[:top_k]]

    def commit_episode(self, alert: Dict[str, Any], result: Dict[str, Any]):
        """Save a completed investigation as an episodic memory record."""
        import time
        ep = {
            "id": alert.get("id", f"ep-{int(time.time())}"),
            "title": alert.get("title", "Unknown"),
            "host": alert.get("host", ""),
            "ioc": alert.get("ioc", ""),
            "process": alert.get("process", ""),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": result.get("status", "UNKNOWN"),
            "riskScore": result.get("riskScore", 0),
            "consensusPct": result.get("consensusPct", 0),
            "ttpsDetected": result.get("ttpsDetected", []),
            "critic": result.get("critic", {}).get("criticVerdict", ""),
            "latencySec": result.get("latencySec", 0)
        }
        self.memory["episodicMemory"].insert(0, ep)
        if len(self.memory["episodicMemory"]) > 50:
            self.memory["episodicMemory"] = self.memory["episodicMemory"][:50]
        self.memory["stats"]["incidents"] += 1
        self.save()

store = Store()
