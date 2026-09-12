"""
Project TUESDAY: Full Multi-Agent Swarm Orchestrator — Agentic Pipeline
Implements the complete 7-phase investigation pipeline:
  Phase 1: Coordinator planning + episodic memory recall
  Phase 2: TRUE PARALLEL agent swarm execution (ThreadPoolExecutor)
  Phase 3: Weighted consensus voting with RL-calibrated agent weights
  Phase 4: Formal ACH (Analysis of Competing Hypotheses) H1 vs H2
  Phase 5: Adversarial Critic reflection pass (false positive challenge)
  Phase 6: Dynamic playbook synthesis from evidence
  Phase 7: Autonomous containment + episodic memory commit
"""

import time
import json
import os
import sys
import requests
from typing import Dict, Any, Callable, Optional, List

# Force UTF-8 output on Windows to avoid cp1252 encode errors
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from engine.agents import create_swarm, run_swarm_parallel
from engine.critic import AdversarialCritic
from engine.hypotheses import run_ach
from engine.store import store
from engine.tools import isolate_host

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
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"


def _synthesize_playbook(
    alert: Dict[str, Any],
    verdicts: Dict[str, Any],
    risk_score: int,
    ach_result: Dict[str, Any],
    past_episodes: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Generate a dynamic, evidence-grounded incident response playbook via LLM."""
    all_ttps = []
    kill_chain_stages = []
    for v in verdicts.values():
        all_ttps.extend(v.get("ttpsDetected", []))
        kill_chain_stages.extend(v.get("killChainStages", []))

    memory_hint = ""
    if past_episodes:
        memory_hint = f"\nSIMILAR PAST INCIDENTS: {json.dumps([ep.get('title') for ep in past_episodes[:2]])}"

    prompt = f"""You are the TUESDAY Incident Response Commander generating an autonomous response playbook.

ALERT: {json.dumps(alert)}
RISK SCORE: {risk_score}/100
PREFERRED HYPOTHESIS: {ach_result.get('preferredHypothesis', 'H1')} — {ach_result.get('diagnosticSummary', '')}
MITRE ATT&CK TTPs: {', '.join(sorted(set(all_ttps))) or 'Unknown'}
KILL CHAIN STAGES ACTIVE: {json.dumps(kill_chain_stages[:4])}{memory_hint}

Generate a dynamic, specific incident response playbook. Output valid JSON ONLY:
{{
  "playbookName": "<PLAYBOOK-NAME>",
  "priority": "P1-CRITICAL" | "P2-HIGH" | "P3-MEDIUM",
  "estimatedMTTR": "<estimated mean time to remediate>",
  "immediateActions": [
    "<step 1: immediate network isolation command>",
    "<step 2: kill malicious process>",
    "<step 3: block C2 IP on perimeter>"
  ],
  "forensicActions": [
    "<collect memory dump>",
    "<preserve disk image>",
    "<export SIEM logs for IOC>"
  ],
  "preventionActions": [
    "<patch vector>",
    "<update detection rules>",
    "<harden endpoint>"
  ],
  "notificationTargets": ["CISO", "SOC Tier 2", "Legal/Compliance"],
  "confidenceNote": "<why this playbook was chosen for this specific incident>"
}}"""

    try:
        resp = requests.post(
            GEMINI_URL,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {GEMINI_API_KEY}"},
            json={"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1},
            timeout=20
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        for fence in ["```json", "```"]:
            if fence in content:
                content = content.split(fence)[1].split("```")[0].strip()
                break
        return json.loads(content)
    except Exception as e:
        # Deterministic playbook fallback
        return {
            "playbookName": f"TUESDAY-AUTO-PB-{alert.get('id', 'UNKNOWN').upper()}",
            "priority": "P1-CRITICAL" if risk_score >= 80 else "P2-HIGH",
            "estimatedMTTR": "15-30 minutes",
            "immediateActions": [
                f"Isolate host {alert.get('host', 'target')} from network segment immediately.",
                f"Terminate suspicious process {alert.get('process', 'unknown')} via EDR API.",
                f"Block IOC {alert.get('ioc', 'unknown')} on perimeter firewall and DNS sinkhole.",
            ],
            "forensicActions": [
                "Collect full memory dump before process termination.",
                "Preserve disk image and SIEM event logs for forensic analysis.",
                "Export all network connections and DNS queries for the last 4 hours."
            ],
            "preventionActions": [
                "Apply endpoint hardening policy to affected subnet.",
                "Update Sigma/YARA signatures with new IOC indicators.",
                "Review and revoke any compromised credentials or tokens."
            ],
            "notificationTargets": ["CISO", "SOC Tier 2", "Legal/Compliance"],
            "confidenceNote": f"Auto-generated from {len(all_ttps)} TTPs and {risk_score}/100 risk score."
        }


class SwarmOrchestrator:
    def __init__(self):
        self.swarm = create_swarm()
        self.critic = AdversarialCritic()

    def run_investigation(
        self,
        alert: Dict[str, Any],
        emit_log: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        alert_title = alert.get("title", "Unknown Alert")
        alert_host = alert.get("host", "DESKTOP-TUESDAY")

        # =====================================================================
        # PHASE 1: Coordinator Planning + Episodic Memory Recall
        # =====================================================================
        if emit_log:
            emit_log("coordinator",
                f"COORDINATOR: Alert received — '{alert_title}' on host [{alert_host}]. "
                "Initiating autonomous agentic investigation pipeline.", "info")

        past_episodes = store.recall_similar(alert, top_k=3)
        store.add_audit("ALERT_INGEST", f"[{alert.get('id', '?')}] {alert_title}")

        if emit_log:
            if past_episodes:
                ep_titles = [ep.get("title", "?") for ep in past_episodes]
                emit_log("coordinator",
                    f"EPISODIC MEMORY: {len(past_episodes)} similar past incidents recalled: {ep_titles}", "info")
            else:
                emit_log("coordinator",
                    "EPISODIC MEMORY: No similar past incidents found — treating as novel threat.", "info")

        # =====================================================================
        # PHASE 2: TRUE PARALLEL Agent Swarm Execution
        # =====================================================================
        if emit_log:
            emit_log("coordinator",
                f"DISPATCHING {len(self.swarm)} PARALLEL AGENTS: "
                f"{[a.name for a in self.swarm.values()]} -- each running independent ReAct reasoning loops.",
                "info")

        verdicts = run_swarm_parallel(
            swarm=self.swarm,
            alert=alert,
            past_episodes=past_episodes,
            emit_log=emit_log
        )

        # =====================================================================
        # PHASE 3: Weighted Consensus Voting (RL-calibrated agent weights)
        # =====================================================================
        votes = []
        all_ttps = []
        kill_chain_stages = {}
        total_tool_calls = 0

        for key, v in verdicts.items():
            weight = store.get_weight(key)
            votes.append({
                "agent": self.swarm[key].name,
                "key": key,
                "vote": v.get("verdict", "SUSPICIOUS"),
                "confidence": v.get("confidence", 70),
                "color": self.swarm[key].color,
                "weight": weight,
                "h1Score": v.get("h1Score", 50),
                "h2Score": v.get("h2Score", 50),
                "reasoning": v.get("reasoning", ""),
                "summary": v.get("summary", ""),
                "ttpsDetected": v.get("ttpsDetected", []),
                "toolCallCount": v.get("toolCallCount", 0)
            })
            all_ttps.extend(v.get("ttpsDetected", []))
            total_tool_calls += v.get("toolCallCount", 0)
            for stage in v.get("killChainStages", []):
                if stage.get("stage"):
                    kill_chain_stages[stage["stage"]] = stage.get("evidence", "")

        malicious_count = sum(1 for v in votes if v["vote"] == "MALICIOUS")
        total_votes = len(votes)
        consensus_pct = int((malicious_count / max(total_votes, 1)) * 100)

        # Weighted confidence: higher-weight agents count more
        total_weight = sum(v["weight"] for v in votes)
        weighted_confidence = int(
            sum(v["confidence"] * v["weight"] for v in votes) / max(total_weight, 0.001)
        )
        risk_score = max(consensus_pct, weighted_confidence)
        unique_ttps = sorted(set(all_ttps))

        if emit_log:
            emit_log("coordinator",
                f"WEIGHTED CONSENSUS: {malicious_count}/{total_votes} agents voted MALICIOUS "
                f"({consensus_pct}% agreement). Weighted confidence: {weighted_confidence}%. "
                f"Risk score: {risk_score}/100. Total tool calls: {total_tool_calls}. "
                f"TTPs: {', '.join(unique_ttps[:5]) or 'none'}.",
                "warning")

        # =====================================================================
        # PHASE 4: Formal ACH — Analysis of Competing Hypotheses
        # =====================================================================
        if emit_log:
            emit_log("coordinator",
                "RUNNING FORMAL ACH: Evaluating H1 (Active Attack) vs H2 (Benign/False Positive)...",
                "info")

        ach_result = run_ach(alert, verdicts)

        if emit_log:
            emit_log("coordinator",
                f"ACH RESULT: Preferred hypothesis {ach_result.get('preferredHypothesis')} "
                f"(H1={ach_result.get('h1', {}).get('evidenceScore', '?')}/100 vs "
                f"H2={ach_result.get('h2', {}).get('evidenceScore', '?')}/100). "
                f"{ach_result.get('diagnosticSummary', '')}",
                "info")

        # =====================================================================
        # PHASE 5: Adversarial Critic Reflection Pass
        # =====================================================================
        critic_res = self.critic.evaluate(alert, verdicts, consensus_pct, emit_log)
        risk_score = max(0, min(100, risk_score + critic_res.get("confidenceAdjustment", 0)))

        if emit_log:
            emit_log("critic",
                f"ADVERSARIAL CHALLENGE COMPLETE: {critic_res.get('criticVerdict')} | "
                f"Adjustment: {critic_res.get('confidenceAdjustment', 0):+d} pts -> Final risk: {risk_score}/100",
                "success" if critic_res.get("challengePassed") else "warning")

        # =====================================================================
        # PHASE 6: Dynamic Playbook Synthesis
        # =====================================================================
        if emit_log:
            emit_log("response",
                "SYNTHESIZING DYNAMIC INCIDENT RESPONSE PLAYBOOK from evidence corpus...", "info")

        playbook = _synthesize_playbook(alert, verdicts, risk_score, ach_result, past_episodes)

        if emit_log:
            emit_log("response",
                f"PLAYBOOK GENERATED: [{playbook.get('playbookName')}] | "
                f"Priority: {playbook.get('priority')} | "
                f"Est. MTTR: {playbook.get('estimatedMTTR')} | "
                f"Steps: {len(playbook.get('immediateActions', []))} immediate + "
                f"{len(playbook.get('forensicActions', []))} forensic",
                "success")

        # =====================================================================
        # PHASE 7: Autonomous Containment + Episodic Memory Commit
        # =====================================================================
        AUTO_CONTAIN_THRESHOLD = 60
        status = "CONTAINED" if risk_score >= AUTO_CONTAIN_THRESHOLD else "MONITORING"
        containment_action = None

        if status == "CONTAINED":
            containment_action = isolate_host(
                alert_host,
                f"Risk score {risk_score}/100 — {ach_result.get('preferredHypothesis', 'H1')} confirmed by adversarial critic"
            )
            if emit_log:
                emit_log("response",
                    f"AUTONOMOUS CONTAINMENT EXECUTED: Host [{alert_host}] isolated via "
                    f"Windows Firewall rule [{containment_action.get('rule')}]. "
                    f"Reason: risk score {risk_score}/100 exceeds auto-contain threshold {AUTO_CONTAIN_THRESHOLD}.",
                    "critical")
        else:
            if emit_log:
                emit_log("coordinator",
                    f"MONITORING MODE: Risk score {risk_score}/100 below auto-contain threshold "
                    f"{AUTO_CONTAIN_THRESHOLD}. Alert escalated to human review queue.",
                    "warning")

        elapsed_sec = round(time.time() - start_time, 2)
        store.add_audit("INVESTIGATION_COMPLETE",
            f"[{alert.get('id', '?')}] Status={status} Risk={risk_score}/100 "
            f"Consensus={consensus_pct}% Latency={elapsed_sec}s TTPs={unique_ttps}")

        result = {
            "status": status,
            "riskScore": risk_score,
            "consensusPct": consensus_pct,
            "weightedConfidence": weighted_confidence,
            "latencySec": elapsed_sec,
            "votes": votes,
            "verdicts": verdicts,
            "ach": ach_result,
            "critic": critic_res,
            "playbook": playbook,
            "containment": containment_action,
            "killChainState": kill_chain_stages,
            "ttpsDetected": unique_ttps,
            "totalToolCalls": total_tool_calls,
            "recalledEpisodes": past_episodes,
            "alert": alert
        }

        # Commit this incident to episodic memory for future recall
        store.commit_episode(alert, result)

        if emit_log:
            emit_log("coordinator",
                f"INVESTIGATION COMPLETE in {elapsed_sec}s | Status: {status} | "
                f"Risk: {risk_score}/100 | {malicious_count}/{total_votes} agents MALICIOUS | "
                f"ACH: {ach_result.get('preferredHypothesis')} | {total_tool_calls} total tool calls | "
                f"Episode committed to memory.",
                "success")

        return result
