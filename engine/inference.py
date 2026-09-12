"""
Project TUESDAY: 3-Tier Tactical Inference Engine
Handles multi-tier fallback and air-gapped sovereign execution:
  - Tier 1: Cloud API (Gemini 2.5 Flash / OpenAI-compatible endpoint)
  - Tier 2: Local Offline SLM (Ollama / vLLM on local port 11434)
  - Tier 3: On-Host Deterministic Forensics Engine (zero-network, tool-grounded rule engine)

Modes:
  - "HYBRID" (Default): Tier 1 -> Tier 2 -> Tier 3
  - "FULL_OFFLINE": Tier 2 -> Tier 3 (Never calls external cloud API)
  - "DETERMINISTIC_ONLY": Tier 3 only (Instant on-host execution, zero token usage)
"""

import os
import time
import json
import requests
from typing import Dict, Any, List, Optional, Callable

# Load environment
def _load_env():
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() not in os.environ:
                        os.environ[k.strip()] = v.strip()

_load_env()

# Config Defaults
DEFAULT_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
DEFAULT_LOCAL_URL  = "http://localhost:11434/v1/chat/completions"
DEFAULT_LOCAL_MODEL = "llama3"

class InferenceEngine:
    def __init__(self):
        self.mode = os.getenv("INFERENCE_MODE", "HYBRID").upper()
        if self.mode not in ("HYBRID", "FULL_OFFLINE", "DETERMINISTIC_ONLY"):
            self.mode = "HYBRID"

        self.cloud_url   = os.getenv("GEMINI_URL", DEFAULT_GEMINI_URL)
        self.cloud_key   = os.getenv("GEMINI_API_KEY", "")
        self.cloud_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

        self.local_url   = os.getenv("LOCAL_LLM_URL", DEFAULT_LOCAL_URL)
        self.local_model = os.getenv("LOCAL_LLM_MODEL", DEFAULT_LOCAL_MODEL)

        self.last_active_tier = "TIER_3_DETERMINISTIC"
        self.last_tier_reason = "System initialized in default state"

        # Fast Circuit Breakers (prevent repeated timeout stall across multi-agent turns)
        self.cloud_quota_exhausted = False
        self.cloud_exhausted_time = 0.0

        self.local_unavailable = False
        self.local_unavailable_time = 0.0

    def set_mode(self, mode: str, local_url: Optional[str] = None, local_model: Optional[str] = None):
        """Update runtime inference mode and local model endpoints."""
        mode_upper = mode.upper()
        if mode_upper in ("HYBRID", "FULL_OFFLINE", "DETERMINISTIC_ONLY"):
            self.mode = mode_upper
        if local_url:
            self.local_url = local_url
        if local_model:
            self.local_model = local_model
        # Reset circuit breakers on manual configuration change
        self.cloud_quota_exhausted = False
        self.local_unavailable = False

    def get_status(self) -> Dict[str, Any]:
        """Return current inference settings, active tier, and health status."""
        return {
            "mode": self.mode,
            "availableModes": ["HYBRID", "FULL_OFFLINE", "DETERMINISTIC_ONLY"],
            "lastActiveTier": self.last_active_tier,
            "lastTierReason": self.last_tier_reason,
            "cloudConfig": {
                "configured": bool(self.cloud_key),
                "model": self.cloud_model,
                "endpoint": self.cloud_url.split("//")[-1].split("/")[0] if "//" in self.cloud_url else self.cloud_url,
                "quotaExhausted": self.cloud_quota_exhausted and (time.time() - self.cloud_exhausted_time < 60)
            },
            "localConfig": {
                "endpoint": self.local_url,
                "model": self.local_model,
                "available": not (self.local_unavailable and (time.time() - self.local_unavailable_time < 30))
            }
        }

    def call_chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        emit_log: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes inference following the configured mode hierarchy:
        - In HYBRID: Tier 1 (Cloud) -> Tier 2 (Local SLM) -> Tier 3 (Fails to caller for Deterministic)
        - In FULL_OFFLINE: Tier 2 (Local SLM) -> Tier 3
        - In DETERMINISTIC_ONLY: Immediately raises to trigger Tier 3
        """
        now = time.time()

        # Mode check: DETERMINISTIC_ONLY bypasses all LLM attempts
        if self.mode == "DETERMINISTIC_ONLY":
            self.last_active_tier = "TIER_3_DETERMINISTIC"
            self.last_tier_reason = "Operating in forced DETERMINISTIC_ONLY mode."
            if emit_log:
                emit_log("coordinator", "INFERENCE: Operating in DETERMINISTIC_ONLY mode (0-latency on-host forensics).", "info")
            raise RuntimeError("DETERMINISTIC_ONLY mode selected.")

        # Tier 1: Cloud API (if in HYBRID mode and not in active cooldown)
        if self.mode == "HYBRID":
            if self.cloud_quota_exhausted and (now - self.cloud_exhausted_time < 60):
                if emit_log:
                    emit_log("coordinator", "INFERENCE: Cloud API quota circuit breaker active. Fast-skipping to Tier 2/3...", "info")
            elif self.cloud_key:
                try:
                    if emit_log:
                        emit_log("coordinator", f"INFERENCE: Trying Tier 1 Cloud API ({self.cloud_model})...", "info")
                    
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.cloud_key}"
                    }
                    payload: Dict[str, Any] = {
                        "model": self.cloud_model,
                        "messages": messages,
                        "temperature": temperature
                    }
                    if tools:
                        payload["tools"] = [{"type": "function", "function": t} for t in tools]

                    resp = requests.post(self.cloud_url, headers=headers, json=payload, timeout=4)
                    if resp.status_code == 429:
                        self.cloud_quota_exhausted = True
                        self.cloud_exhausted_time = now
                        raise RuntimeError("Cloud API quota exhausted (HTTP 429)")
                    resp.raise_for_status()
                    
                    result = resp.json()["choices"][0]["message"]
                    self.last_active_tier = "TIER_1_CLOUD"
                    self.last_tier_reason = f"Served by Cloud API ({self.cloud_model})"
                    self.cloud_quota_exhausted = False
                    return result
                except Exception as e:
                    err_msg = str(e)
                    if "429" in err_msg or "quota" in err_msg.lower():
                        self.cloud_quota_exhausted = True
                        self.cloud_exhausted_time = now
                    if emit_log:
                        emit_log("coordinator", f"INFERENCE: Tier 1 Cloud failed ({err_msg}). Falling back to Tier 2 (Local SLM)...", "warning")
            else:
                if emit_log:
                    emit_log("coordinator", "INFERENCE: No cloud API key configured. Bypassing Tier 1...", "info")

        # Tier 2: Local Offline SLM (Ollama / vLLM / llama.cpp)
        if self.local_unavailable and (now - self.local_unavailable_time < 30):
            if emit_log:
                emit_log("coordinator", "INFERENCE: Local SLM cooldown active. Fast-skipping to Tier 3 (On-Host Forensics)...", "info")
        else:
            try:
                if emit_log:
                    endpoint_host = self.local_url.split("//")[-1].split("/")[0]
                    emit_log("coordinator", f"INFERENCE: Trying Tier 2 Local Offline SLM ({self.local_model} @ {endpoint_host})...", "info")

                payload = {
                    "model": self.local_model,
                    "messages": messages,
                    "temperature": temperature
                }
                if tools:
                    payload["tools"] = [{"type": "function", "function": t} for t in tools]

                # Fast 1.5-second timeout for local endpoint
                resp = requests.post(self.local_url, json=payload, timeout=1.5)
                resp.raise_for_status()
                result = resp.json()["choices"][0]["message"]
                self.last_active_tier = "TIER_2_LOCAL_SLM"
                self.last_tier_reason = f"Served by Local Offline SLM ({self.local_model})"
                self.local_unavailable = False
                if emit_log:
                    emit_log("coordinator", f"INFERENCE: Success with Tier 2 Local SLM ({self.local_model}).", "success")
                return result
            except Exception as e:
                self.local_unavailable = True
                self.local_unavailable_time = now
                if emit_log:
                    emit_log("coordinator", f"INFERENCE: Tier 2 Local SLM unavailable ({str(e)[:60]}). Falling back to Tier 3 (On-Host Forensics)...", "warning")

        # Tier 3: Caller catches this and executes real On-Host Deterministic Forensics
        self.last_active_tier = "TIER_3_DETERMINISTIC"
        self.last_tier_reason = "Fallback: Cloud & Local SLMs unavailable; On-Host Forensics Engine active"
        raise RuntimeError("All LLM tiers exhausted — activating on-host tactical edge forensics engine.")

# Global Singleton Instance
inference_engine = InferenceEngine()
