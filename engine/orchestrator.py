"""
Project TUESDAY: Multi-Agent Swarm Orchestrator
Coordinates parallel agent execution, hypothesis testing, adversarial reflection,
weighted consensus voting, and autonomous containment actions.
"""

import time
import json
from typing import Dict, Any, Callable, Optional
from engine.agents import create_swarm
from engine.critic import AdversarialCritic
from engine.tools import isolate_host

class SwarmOrchestrator:
    def __init__(self):
        self.swarm = create_swarm()
        self.critic = AdversarialCritic()

    def run_investigation(self, alert: Dict[str, Any], emit_log: Optional[Callable[[str, str, str], None]] = None) -> Dict[str, Any]:
        start_time = time.time()
        if emit_log:
            emit_log("coordinator", f"COORDINATOR: Ingesting security event '{alert.get('title')}' on host {alert.get('host', 'localhost')}", "info")

        # Phase 1: Parallel Agent Swarm Investigation
        verdicts = {}
        for key, agent in self.swarm.items():
            res = agent.investigate(alert, emit_log)
            verdicts[key] = res

        # Phase 2: Swarm Consensus Voting
        votes = []
        for key, v in verdicts.items():
            votes.append({
                "agent": self.swarm[key].name,
                "key": key,
                "vote": v.get("verdict", "SUSPICIOUS"),
                "confidence": v.get("confidence", 70),
                "color": self.swarm[key].color
            })

        malicious_count = sum(1 for v in votes if v["vote"] == "MALICIOUS")
        total_votes = len(votes)
        consensus_pct = int((malicious_count / total_votes) * 100)
        avg_confidence = int(sum(v["confidence"] for v in votes) / total_votes)
        risk_score = max(consensus_pct, avg_confidence)

        if emit_log:
            emit_log("coordinator", f"SWARM CONSENSUS: {malicious_count}/{total_votes} agents voted MALICIOUS ({consensus_pct}% agreement). Risk Score: {risk_score}/100", "warning")

        # Phase 3: Adversarial Critic Reflection Pass
        critic_res = self.critic.evaluate(alert, verdicts, consensus_pct, emit_log)
        risk_score = max(0, min(100, risk_score + critic_res.get("confidenceAdjustment", 0)))

        # Phase 4: Autonomous Response & Host Containment Gate
        status = "CONTAINED" if risk_score >= 60 else "MONITORING"
        containment_action = None

        if status == "CONTAINED":
            containment_action = isolate_host(alert.get("host", "DESKTOP-TUESDAY"), "High risk score from swarm consensus")
            if emit_log:
                emit_log("response", f"AUTONOMOUS CONTAINMENT: Host {alert.get('host')} isolated via Windows Firewall block rule: {containment_action.get('rule')}", "critical")

        elapsed_sec = round(time.time() - start_time, 2)
        if emit_log:
            emit_log("coordinator", f"INCIDENT CLOSED: Verdict {status} (Completed in {elapsed_sec}s)", "success")

        return {
            "status": status,
            "riskScore": risk_score,
            "consensusPct": consensus_pct,
            "latencySec": elapsed_sec,
            "votes": votes,
            "verdicts": verdicts,
            "critic": critic_res,
            "containment": containment_action,
            "alert": alert
        }
