"""
Project TUESDAY: Multi-Agent Swarm Orchestrator
7-Phase agentic investigation pipeline with cluster distribution and HITL gate.

Phase 1: Coordinator planning + TTP-weighted episodic memory recall
Phase 2: Two-phase parallel swarm (fast intel -> deep analysis with peer injection)
Phase 3: RL-weighted consensus voting
Phase 4: Formal ACH (Analysis of Competing Hypotheses) H1 vs H2
Phase 5: Adversarial Critic — local OR dispatched to remote cluster node
Phase 6: Dynamic LLM-synthesized incident response playbook
Phase 7: HITL gate check -> Autonomous containment -> Episodic memory commit
"""

import time
import json
import os
import sys
import requests
from typing import Dict, Any, Callable, Optional, List

# Force UTF-8 output on Windows
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
from engine.inference import inference_engine

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
GEMINI_URL     = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

# Hosts matching these patterns require HUMAN approval before autonomous containment
# (Critical infrastructure, domain controllers, SCADA systems)
PROTECTED_HOST_PATTERNS = [
    "DC-", "DC01", "DC02", "PDC", "DOMAIN-CONTROLLER",
    "ADFS", "CA-SERVER", "PKI", "SCADA", "HMI", "PLC",
    "ROUTER", "FIREWALL", "CORE-SWITCH", "CRITICAL"
]

AUTO_CONTAIN_THRESHOLD = 60  # Risk score >= this triggers autonomous containment


def _is_protected_host(host: str) -> bool:
    """Check if a host requires human approval before automated containment."""
    h = host.upper()
    return any(pat in h for pat in PROTECTED_HOST_PATTERNS)


def _synthesize_playbook(
    alert: Dict[str, Any],
    verdicts: Dict[str, Any],
    risk_score: int,
    ach_result: Dict[str, Any],
    past_episodes: List[Dict[str, Any]],
    emit_log: Optional[Callable[[str, str, str], None]] = None
) -> Dict[str, Any]:
    """Generate a dynamic, evidence-grounded incident response playbook via multi-tier inference."""
    all_ttps, kill_chain_stages = [], []
    for v in verdicts.values():
        all_ttps.extend(v.get("ttpsDetected", []))
        kill_chain_stages.extend(v.get("killChainStages", []))

    mem_hint = ""
    if past_episodes:
        mem_hint = f"\nSIMILAR PAST INCIDENTS: {[ep.get('title') for ep in past_episodes[:2]]}"

    prompt = f"""You are the TUESDAY Incident Response Commander generating an autonomous response playbook.

ALERT: {json.dumps(alert)}
RISK SCORE: {risk_score}/100
PREFERRED HYPOTHESIS: {ach_result.get('preferredHypothesis','H1')} — {ach_result.get('diagnosticSummary','')}
MITRE ATT&CK TTPs: {', '.join(sorted(set(all_ttps))) or 'Unknown'}
KILL CHAIN ACTIVE: {json.dumps(kill_chain_stages[:4])}{mem_hint}

Generate a specific, evidence-grounded incident response playbook. Output valid JSON ONLY:
{{
  "playbookName": "<PLAYBOOK-ID>",
  "priority": "P1-CRITICAL" | "P2-HIGH" | "P3-MEDIUM",
  "estimatedMTTR": "<time estimate>",
  "immediateActions": ["<step 1>", "<step 2>", "<step 3>"],
  "forensicActions":  ["<collect memory>", "<preserve logs>", "<export IOCs>"],
  "preventionActions": ["<patch>", "<update rules>", "<harden>"],
  "notificationTargets": ["CISO", "SOC Tier 2"],
  "confidenceNote": "<why this playbook for this incident>"
}}"""

    try:
        msg = inference_engine.call_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            emit_log=emit_log
        )
        content = msg.get("content", "").strip()
        for fence in ["```json", "```"]:
            if fence in content:
                content = content.split(fence)[1].split("```")[0].strip()
                break
        return json.loads(content)
    except Exception:
        return {
            "playbookName":       f"TUESDAY-PB-{alert.get('id','UNKNOWN').upper()}",
            "priority":           "P1-CRITICAL" if risk_score >= 80 else "P2-HIGH",
            "estimatedMTTR":      "15-30 minutes",
            "immediateActions":   [
                f"Isolate host {alert.get('host','target')} from network segment immediately.",
                f"Terminate suspicious process {alert.get('process','unknown')} via EDR API.",
                f"Block IOC {alert.get('ioc','unknown')} on perimeter firewall and DNS sinkhole."
            ],
            "forensicActions":    [
                "Collect full memory dump before process termination.",
                "Preserve disk image and SIEM event logs.",
                "Export all network connections and DNS queries for last 4 hours."
            ],
            "preventionActions":  [
                "Apply endpoint hardening policy to affected subnet.",
                "Update Sigma/YARA signatures with new IOC indicators.",
                "Review and revoke compromised credentials or tokens."
            ],
            "notificationTargets": ["CISO", "SOC Tier 2", "Legal/Compliance"],
            "confidenceNote":     f"Auto-generated from {len(all_ttps)} TTPs and {risk_score}/100 risk via {inference_engine.last_active_tier}."
        }


class SwarmOrchestrator:
    def __init__(self):
        self.swarm  = create_swarm()
        self.critic = AdversarialCritic()

    def run_investigation(
        self,
        alert: Dict[str, Any],
        emit_log: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        start_time  = time.time()
        alert_title = alert.get("title", "Unknown Alert")
        alert_host  = alert.get("host", "DESKTOP-TUESDAY")

        # =========================================================
        # PHASE 1: Coordinator Planning + TTP-weighted Memory Recall
        # =========================================================
        if emit_log:
            emit_log("coordinator",
                f"COORDINATOR: Alert ingested -- '{alert_title}' on [{alert_host}]. "
                "Initiating autonomous 7-phase investigation pipeline.", "info")

        past_episodes = store.recall_similar(alert, top_k=3)
        store.add_audit("ALERT_INGEST", f"[{alert.get('id','?')}] {alert_title}")

        if emit_log:
            if past_episodes:
                emit_log("coordinator",
                    f"EPISODIC MEMORY (TTP-weighted recall): {len(past_episodes)} similar past incidents: "
                    f"{[ep.get('title','?') for ep in past_episodes]}", "info")
            else:
                emit_log("coordinator",
                    "EPISODIC MEMORY: No similar past incidents -- treating as novel threat.", "info")

        # =========================================================
        # PHASE 2: Two-Phase Parallel Swarm Execution
        # =========================================================
        if emit_log:
            emit_log("coordinator",
                f"DISPATCHING SWARM -- Phase 1 (fast intel): log, threatintel | "
                f"Phase 2 (deep analysis with Phase 1 results): malware, cloud", "info")

        verdicts = run_swarm_parallel(
            swarm=self.swarm,
            alert=alert,
            past_episodes=past_episodes,
            emit_log=emit_log
        )

        # =========================================================
        # PHASE 3: RL-Weighted Consensus Voting
        # =========================================================
        votes, all_ttps, kill_chain_stages = [], [], {}
        total_tool_calls = 0

        for key, v in verdicts.items():
            weight = store.get_weight(key)
            votes.append({
                "agent":        self.swarm[key].name,
                "key":          key,
                "vote":         v.get("verdict", "SUSPICIOUS"),
                "confidence":   v.get("confidence", 70),
                "color":        self.swarm[key].color,
                "weight":       weight,
                "h1Score":      v.get("h1Score", 50),
                "h2Score":      v.get("h2Score", 50),
                "reasoning":    v.get("reasoning", ""),
                "summary":      v.get("summary", ""),
                "ttpsDetected": v.get("ttpsDetected", []),
                "toolCallCount":v.get("toolCallCount", 0)
            })
            all_ttps.extend(v.get("ttpsDetected", []))
            total_tool_calls += v.get("toolCallCount", 0)
            for stage in v.get("killChainStages", []):
                if stage.get("stage"):
                    kill_chain_stages[stage["stage"]] = stage.get("evidence", "")

        malicious_count   = sum(1 for v in votes if v["vote"] == "MALICIOUS")
        total_votes       = len(votes)
        consensus_pct     = int((malicious_count / max(total_votes, 1)) * 100)
        total_weight      = sum(v["weight"] for v in votes)
        weighted_conf     = int(sum(v["confidence"] * v["weight"] for v in votes) / max(total_weight, 0.001))
        risk_score        = max(consensus_pct, weighted_conf)
        unique_ttps       = sorted(set(all_ttps))

        if emit_log:
            emit_log("coordinator",
                f"WEIGHTED CONSENSUS: {malicious_count}/{total_votes} MALICIOUS "
                f"({consensus_pct}% agreement) | Weighted conf: {weighted_conf}% | "
                f"Risk: {risk_score}/100 | Tool calls: {total_tool_calls} | "
                f"TTPs: {', '.join(unique_ttps[:5]) or 'none'}",
                "warning")

        # =========================================================
        # PHASE 4: Formal ACH -- H1 vs H2
        # =========================================================
        if emit_log:
            emit_log("coordinator",
                "FORMAL ACH: Evaluating H1 (Active Attack) vs H2 (Benign/False Positive)...", "info")

        ach_result = run_ach(alert, verdicts)

        if emit_log:
            emit_log("coordinator",
                f"ACH: Preferred {ach_result.get('preferredHypothesis')} | "
                f"H1={ach_result.get('h1',{}).get('evidenceScore','?')} vs "
                f"H2={ach_result.get('h2',{}).get('evidenceScore','?')} | "
                f"{ach_result.get('diagnosticSummary','')}",
                "info")

        # =========================================================
        # PHASE 5: Adversarial Critic (local or dispatched to cluster node)
        # =========================================================
        critic_res = None
        cluster_node_used = None

        # Try to dispatch critic to a remote cluster node for genuine independence
        try:
            from engine.cluster import cluster_manager
            worker_nodes = cluster_manager.get_healthy_nodes()
            if worker_nodes:
                node = worker_nodes[0]
                if emit_log:
                    emit_log("coordinator",
                        f"CLUSTER: Dispatching adversarial critic to remote node [{node.ip}] "
                        f"for physically independent validation", "info")
                critic_res = node.run_critic(alert, verdicts, consensus_pct)
                cluster_node_used = node.ip
                if emit_log:
                    emit_log("critic",
                        f"REMOTE CRITIC [{node.ip}]: {critic_res.get('criticVerdict')} | "
                        f"Adjustment: {critic_res.get('confidenceAdjustment', 0):+d} pts",
                        "success" if critic_res.get("challengePassed") else "warning")
        except Exception:
            pass

        if critic_res is None:
            critic_res = self.critic.evaluate(alert, verdicts, consensus_pct, emit_log)

        risk_score = max(0, min(100, risk_score + critic_res.get("confidenceAdjustment", 0)))

        if emit_log and cluster_node_used is None:
            emit_log("critic",
                f"ADVERSARIAL CRITIC: {critic_res.get('criticVerdict')} | "
                f"Adjustment: {critic_res.get('confidenceAdjustment', 0):+d} pts -> Final risk: {risk_score}/100",
                "success" if critic_res.get("challengePassed") else "warning")

        # =========================================================
        # PHASE 6: Dynamic Playbook Synthesis
        # =========================================================
        if emit_log:
            emit_log("response", "SYNTHESIZING DYNAMIC INCIDENT RESPONSE PLAYBOOK...", "info")

        playbook = _synthesize_playbook(alert, verdicts, risk_score, ach_result, past_episodes, emit_log)

        if emit_log:
            emit_log("response",
                f"PLAYBOOK: [{playbook.get('playbookName')}] | "
                f"Priority: {playbook.get('priority')} | MTTR: {playbook.get('estimatedMTTR')} | "
                f"{len(playbook.get('immediateActions',[]))} immediate + "
                f"{len(playbook.get('forensicActions',[]))} forensic steps",
                "success")

        # =========================================================
        # PHASE 7: HITL Gate -> Containment -> Memory Commit
        # =========================================================
        status = "MONITORING"
        containment_action = None
        hitl_queued = False

        if risk_score >= AUTO_CONTAIN_THRESHOLD:
            if _is_protected_host(alert_host):
                # HITL Gate: critical infrastructure requires human approval
                approval_entry = {
                    "id":        f"APPROVAL-{int(time.time())}",
                    "alert":     alert,
                    "riskScore": risk_score,
                    "ach":       {"preferredHypothesis": ach_result.get("preferredHypothesis")},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status":    "PENDING"
                }
                store.memory["approvals"].insert(0, approval_entry)
                store.save()
                status      = "PENDING_APPROVAL"
                hitl_queued = True
                if emit_log:
                    emit_log("response",
                        f"HITL GATE TRIGGERED: Protected host [{alert_host}] matches critical "
                        f"infrastructure pattern. Autonomous containment BLOCKED. "
                        f"Queued for human approval as [{approval_entry['id']}].",
                        "warning")
            else:
                # Autonomous containment
                containment_action = isolate_host(
                    alert_host,
                    f"Risk {risk_score}/100 -- {ach_result.get('preferredHypothesis','H1')} confirmed"
                )
                status = containment_action.get("status", "CONTAINED")
                if emit_log:
                    emit_log("response",
                        f"AUTONOMOUS CONTAINMENT: Host [{alert_host}] isolated via netsh rule "
                        f"[{containment_action.get('rule')}] | "
                        f"Status: {containment_action.get('status')} | "
                        f"Risk: {risk_score}/100 >= threshold {AUTO_CONTAIN_THRESHOLD}",
                        "critical")
        else:
            if emit_log:
                emit_log("coordinator",
                    f"MONITORING MODE: Risk {risk_score}/100 < threshold {AUTO_CONTAIN_THRESHOLD}. "
                    "Escalated to human review queue.", "warning")

        elapsed_sec = round(time.time() - start_time, 2)
        store.add_audit("INVESTIGATION_COMPLETE",
            f"[{alert.get('id','?')}] Status={status} Risk={risk_score} "
            f"Consensus={consensus_pct}% Latency={elapsed_sec}s TTPs={unique_ttps} Tier={inference_engine.last_active_tier}")

        result = {
            "status":            status,
            "riskScore":         risk_score,
            "consensusPct":      consensus_pct,
            "weightedConfidence":weighted_conf,
            "latencySec":        elapsed_sec,
            "inferenceTier":     inference_engine.last_active_tier,
            "inferenceMode":     inference_engine.mode,
            "inferenceReason":   inference_engine.last_tier_reason,
            "votes":             votes,
            "verdicts":          verdicts,
            "ach":               ach_result,
            "critic":            critic_res,
            "playbook":          playbook,
            "containment":       containment_action,
            "hitlQueued":        hitl_queued,
            "clusterNode":       cluster_node_used,
            "killChainState":    kill_chain_stages,
            "ttpsDetected":      unique_ttps,
            "totalToolCalls":    total_tool_calls,
            "recalledEpisodes":  past_episodes,
            "alert":             alert
        }

        # Commit to episodic memory for future TTP-weighted recall
        store.commit_episode(alert, result)

        if emit_log:
            cluster_info = f"Critic on node [{cluster_node_used}]" if cluster_node_used else "Single-node"
            emit_log("coordinator",
                f"INVESTIGATION COMPLETE in {elapsed_sec}s | Status: {status} | "
                f"Risk: {risk_score}/100 | {malicious_count}/{total_votes} MALICIOUS | "
                f"ACH: {ach_result.get('preferredHypothesis')} | "
                f"{total_tool_calls} tool calls | {cluster_info} | "
                "Episode committed to memory.",
                "success")

        return result
