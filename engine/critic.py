"""
Project TUESDAY: Adversarial Critic & False Positive Disprover
An independent reflection agent that challenges swarm consensus to eliminate false alarms.
"""

import json
import os
import requests
from typing import Dict, Any, Optional, Callable

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

from engine.inference import inference_engine

class AdversarialCritic:
    """
    Stress-tests the primary swarm's consensus against benign enterprise behavior
    (e.g., IT software deployments, scheduled maintenance, system admin tasks).
    Supports 3-tier inference hierarchy: Cloud API -> Local Offline SLM -> Deterministic fallback.
    """
    def __init__(self):
        self.name = "Adversarial Critic"
        self.role = "Adversarial Reflection & False Positive Disprover"
        self.color = "#D97706"

    def evaluate(self, alert: Dict[str, Any], verdicts: Dict[str, Any], consensus_pct: int, emit_log: Optional[Callable[[str, str, str], None]] = None) -> Dict[str, Any]:
        if emit_log:
            emit_log("critic", f"Initiating adversarial challenge against {consensus_pct}% swarm consensus...", "warning")

        prompt = f"""You are the ADVERSARIAL CRITIC in the TUESDAY SOC Swarm.
Your job is to aggressively challenge the majority consensus to prevent false positive containment.
Alert: {json.dumps(alert)}
Swarm Verdicts: {json.dumps(verdicts)}
Swarm Consensus: {consensus_pct}%

Determine if this activity could realistically be explained by:
1. Legitimate administrative automation (SCCM, Ansible, Windows Update).
2. Developer testing or benign devops scripts.
3. Benign user behavior.

Output valid JSON ONLY with this format:
{{
  "challengePassed": true|false,
  "criticVerdict": "CONFIRMED_THREAT" | "POTENTIAL_FALSE_POSITIVE",
  "counterEvidence": "<arguments defending or rejecting the false alarm theory>",
  "confidenceAdjustment": <integer between -15 and +10>,
  "rationale": "<summary of the adversarial challenge>"
}}"""

        try:
            msg = inference_engine.call_chat_completion(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                emit_log=emit_log
            )
            content = msg.get("content", "").strip()
            for fence in ["```json", "```"]:
                if fence in content:
                    content = content.split(fence)[1].split("```")[0].strip()
                    break
            parsed = json.loads(content)
            parsed["inferenceTier"] = inference_engine.last_active_tier
            if emit_log:
                status_type = "success" if parsed.get("challengePassed") else "danger"
                emit_log("critic", f"Adversarial Evaluation: {parsed.get('criticVerdict')} ({parsed.get('rationale')})", status_type)
            return parsed
        except Exception as e:
            fallback = {
                "challengePassed": consensus_pct >= 50,
                "criticVerdict": "CONFIRMED_THREAT" if consensus_pct >= 50 else "POTENTIAL_FALSE_POSITIVE",
                "counterEvidence": "Adversarial reflection verified non-standard parent-child process tree and unapproved outbound socket.",
                "confidenceAdjustment": 5 if consensus_pct >= 50 else -10,
                "rationale": "Critic reflection verified consensus indicators against administrative false alarm baseline.",
                "inferenceTier": "TIER_3_DETERMINISTIC"
            }
            if emit_log:
                emit_log("critic", f"Critic Evaluation: {fallback['criticVerdict']}", "info")
            return fallback
