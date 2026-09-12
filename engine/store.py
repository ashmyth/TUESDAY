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

store = Store()
