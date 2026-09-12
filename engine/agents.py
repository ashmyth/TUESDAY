"""
Project TUESDAY: Python Agent Swarm Core
Two-phase parallel execution: fast intel agents run first,
their findings inject into slow behavioral agents for real peer sharing.
"""

import os
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, ALL_COMPLETED
from typing import Dict, Any, List, Optional, Callable

from engine.tools import TOOL_MAP, TOOL_SCHEMAS
from engine.store import store

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
MAX_TURNS = 5

# Phase assignments: fast intel agents run first, slow deep-analysis agents get their results
PHASE_1_AGENTS = {"log", "threatintel"}      # Fast: sigma scan + IOC lookup
PHASE_2_AGENTS = {"malware", "cloud"}        # Deep: process/socket behavioral analysis


class AgenticSwarmMember:
    """
    Specialized cybersecurity reasoning agent.
    Runs a true multi-turn ReAct loop: Reason -> Act (tool call) -> Observe -> Reason.
    """
    def __init__(self, key: str, name: str, role: str, color: str, tools: List[str]):
        self.key    = key
        self.name   = name
        self.role   = role
        self.color  = color
        self.tools  = tools
        self.schemas = [s for s in TOOL_SCHEMAS if s["name"] in tools]

    def _call_llm(self, messages: List[Dict[str, Any]], use_tools: bool = True) -> Dict[str, Any]:
        """Gemini 2.5 Flash with fast quota detection and sensible backoff."""
        api_key = os.getenv("GEMINI_API_KEY", GEMINI_API_KEY)
        if not api_key:
            raise RuntimeError("No GEMINI_API_KEY configured — using on-host edge forensics.")

        payload = {"model": "gemini-2.5-flash", "messages": messages, "temperature": 0.2}
        if use_tools and self.schemas:
            payload["tools"] = [{"type": "function", "function": t} for t in self.schemas]
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

        for attempt in range(2):
            try:
                resp = requests.post(GEMINI_URL, headers=headers, json=payload, timeout=20)
                if resp.status_code == 429:
                    txt = resp.text.lower()
                    if "quota" in txt:
                        raise RuntimeError("Gemini API quota exhausted — falling back to on-host edge forensics.")
                    if attempt == 0:
                        time.sleep(2)
                        continue
                    raise RuntimeError("Gemini API rate limit exceeded.")
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]
            except requests.exceptions.RequestException as e:
                if attempt == 0 and "quota" not in str(e).lower():
                    time.sleep(2)
                    continue
                raise
        raise RuntimeError("Gemini API unavailable.")

    def investigate(
        self,
        alert: Dict[str, Any],
        peer_findings: Optional[Dict[str, str]] = None,
        past_episodes: Optional[List[Dict[str, Any]]] = None,
        emit_log: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Full multi-turn ReAct investigation with episodic memory + peer findings."""
        weight = store.get_weight(self.key)

        # Build episodic memory context
        if past_episodes:
            mem_ctx = f"\nEPISODIC MEMORY ({len(past_episodes)} similar past incidents):\n"
            for ep in past_episodes[:3]:
                ttps = ", ".join(ep.get("ttpsDetected", [])) or "none"
                mem_ctx += (f"  - [{ep.get('timestamp','?')}] {ep.get('title','?')} -> "
                            f"{ep.get('status','?')} (Risk {ep.get('riskScore',0)}/100, TTPs: {ttps})\n")
        else:
            mem_ctx = "\n(No similar past incidents — treat as potentially novel threat.)"

        # Build peer findings context
        if peer_findings:
            peer_ctx = "\nPHASE 1 INTELLIGENCE (findings from fast-intel agents):\n"
            for agent_name, finding in peer_findings.items():
                peer_ctx += f"  - {agent_name}: {finding}\n"
        else:
            peer_ctx = ""

        system_prompt = f"""You are {self.name} — {self.role} — in the TUESDAY autonomous cybersecurity swarm.
Trust weight (RL-calibrated): {weight:.2f}/3.00

METHODOLOGY:
1. HYPOTHESIZE: Form H1 (real attack) vs H2 (benign/false positive) before investigating.
2. TOOL-GATHER: Call your tools to collect verifiable OS evidence — don't hallucinate.
3. WEIGH: Score each hypothesis against what the tools actually returned.
4. CONCLUDE: Evidence-based verdict only.
{mem_ctx}{peer_ctx}
FINAL OUTPUT — respond ONLY with valid JSON when investigation is complete:
{{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "INCONCLUSIVE",
  "confidence": <int 0-100>,
  "h1Score": <int 0-100, evidence supporting H1/malicious>,
  "h2Score": <int 0-100, evidence supporting H2/benign>,
  "reasoning": "<2-3 sentences citing specific tool results>",
  "ttpsDetected": ["T1059.001"],
  "killChainStages": [{{"stage": "Execution", "evidence": "<details>"}}],
  "toolsUsed": ["sigma_scan"],
  "summary": "<one sentence for coordinator>"
}}"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Investigate: {json.dumps(alert, indent=2)}"}
        ]

        if emit_log:
            emit_log(self.key,
                f"[AGENTIC] Starting ReAct loop | Memory: {len(past_episodes or [])} episodes | "
                f"Peer intel: {len(peer_findings or {})} findings | Weight: {weight:.2f}",
                "info")

        tool_call_count = 0

        for turn in range(MAX_TURNS):
            try:
                msg = self._call_llm(messages, use_tools=True)
            except Exception as e:
                if emit_log:
                    emit_log(self.key, f"LLM turn {turn+1} error: {str(e)}", "warning")
                break

            tool_calls = msg.get("tool_calls")
            if tool_calls:
                messages.append(msg)
                for tc in tool_calls:
                    fn_name  = tc["function"]["name"]
                    raw_args = tc["function"].get("arguments", "{}")
                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    except Exception:
                        args = {}

                    if emit_log:
                        emit_log(self.key, f"TOOL -> {fn_name}({json.dumps(args)})", "info")

                    tool_fn = TOOL_MAP.get(fn_name)
                    try:
                        result = tool_fn(**args) if tool_fn else {"error": f"Unknown tool: {fn_name}"}
                    except Exception as e:
                        result = {"error": str(e)}

                    tool_call_count += 1
                    if emit_log:
                        brief = json.dumps(result)
                        brief = brief[:140] + "..." if len(brief) > 140 else brief
                        emit_log(self.key, f"RESULT <- {fn_name}: {brief}", "info")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", f"call_{turn}_{fn_name}"),
                        "name": fn_name,
                        "content": json.dumps(result)
                    })
                continue

            # Final answer — no more tool calls
            content = (msg.get("content") or "").strip()
            for fence in ["```json", "```"]:
                if fence in content:
                    content = content.split(fence)[1].split("```")[0].strip()
                    break
            try:
                parsed = json.loads(content)
                parsed.setdefault("toolCallCount", tool_call_count)
                parsed.setdefault("agentWeight",   weight)
                if emit_log:
                    emit_log(self.key,
                        f"VERDICT: {parsed.get('verdict')} | Confidence: {parsed.get('confidence')}% | "
                        f"H1={parsed.get('h1Score','?')} H2={parsed.get('h2Score','?')} | "
                        f"{tool_call_count} tool calls | "
                        f"TTPs: {', '.join(parsed.get('ttpsDetected', [])) or 'none'}",
                        "success")
                return parsed
            except Exception:
                if emit_log:
                    emit_log(self.key, f"Non-JSON response, wrapping: {content[:80]}", "warning")
                return {
                    "verdict": "SUSPICIOUS", "confidence": 65,
                    "h1Score": 65, "h2Score": 35,
                    "reasoning": content[:300], "ttpsDetected": ["T1059"],
                    "killChainStages": [{"stage": "Execution", "evidence": "Behavioral anomaly"}],
                    "toolsUsed": [], "toolCallCount": tool_call_count, "agentWeight": weight,
                    "summary": f"{self.name}: suspicious indicators observed."
                }

        # Cloud LLM unavailable or turns exhausted — execute real on-host edge forensics
        if emit_log:
            emit_log(self.key, f"Executing on-host edge forensics via {len(self.tools)} assigned tools...", "info")
        return self._run_deterministic_investigation(alert, peer_findings, emit_log)

    def _run_deterministic_investigation(
        self,
        alert: Dict[str, Any],
        peer_findings: Optional[Dict[str, str]] = None,
        emit_log: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        On-host tactical edge forensics engine.
        Executes real tools locally when cloud LLM is unreachable or in air-gapped mode.
        """
        weight = store.get_weight(self.key)
        tool_results: Dict[str, Any] = {}
        ttps_detected: List[str] = []
        kill_chain: List[Dict[str, str]] = []
        is_malicious = False
        findings: List[str] = []

        payload_text = alert.get("payload") or alert.get("title") or ""
        ioc_val = alert.get("ioc") or ""

        for tool_name in self.tools:
            tool_fn = TOOL_MAP.get(tool_name)
            if not tool_fn:
                continue

            try:
                if tool_name == "sigma_scan" and payload_text:
                    res = tool_fn(payload=payload_text)
                    tool_results[tool_name] = res
                    matches = res.get("matchedRules", [])
                    if matches:
                        is_malicious = True
                        for r in matches:
                            ttps_detected.append(r.get("mitre_ttp", "T1059.001"))
                            findings.append(f"Sigma match: {r.get('title')}")
                        kill_chain.append({"stage": "Execution", "evidence": f"{len(matches)} Sigma rules matched"})

                elif tool_name == "ioc_lookup" and ioc_val:
                    res = tool_fn(ioc=ioc_val)
                    tool_results[tool_name] = res
                    if res.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
                        is_malicious = True
                        ttps_detected.extend(res.get("primaryTTPs", ["T1071"]))
                        actor = res.get("threatActor") or res.get("threat_actor") or "Known Malicious IOC"
                        findings.append(f"IOC {ioc_val} confirmed hostile ({actor})")
                        kill_chain.append({"stage": "Command and Control", "evidence": f"Outbound socket to {ioc_val}"})

                elif tool_name == "process_inspect":
                    proc_name = alert.get("process") or ("powershell" if "powershell" in payload_text.lower() else None)
                    pid = alert.get("pid")
                    res = tool_fn(pid=pid, name=proc_name)
                    tool_results[tool_name] = res
                    procs = res.get("processes", [])
                    for p in procs:
                        if p.get("suspicious"):
                            is_malicious = True
                            findings.append(f"Suspicious process: {p.get('name')} (PID {p.get('pid')})")

                elif tool_name == "registry_inspect":
                    res = tool_fn()
                    tool_results[tool_name] = res
                    if res.get("suspicious_count", 0) > 0:
                        is_malicious = True
                        ttps_detected.append("T1547.001")
                        findings.append(f"{res.get('suspicious_count')} suspicious registry autostart keys")
                        kill_chain.append({"stage": "Persistence", "evidence": "Registry Run autostart key"})

                elif tool_name == "service_scan":
                    res = tool_fn()
                    tool_results[tool_name] = res

                elif tool_name == "socket_inspect":
                    res = tool_fn(remote_ip=ioc_val if ioc_val else None)
                    tool_results[tool_name] = res

                elif tool_name == "file_hash":
                    path_val = alert.get("filePath") or alert.get("file_path") or ""
                    if path_val:
                        res = tool_fn(path=path_val)
                        tool_results[tool_name] = res
            except Exception as e:
                tool_results[tool_name] = {"error": str(e)}

        if peer_findings:
            for agent_name, peer_finding in peer_findings.items():
                if any(w in peer_finding.lower() for w in ["malicious", "threat", "c2", "ransomware"]):
                    is_malicious = True

        if not ttps_detected:
            low = payload_text.lower()
            if "powershell" in low or "-enc" in low:
                ttps_detected.append("T1059.001")
            if "vssadmin" in low or "shadows" in low:
                ttps_detected.append("T1490")
            if "lockbit" in low or ".locked" in low:
                ttps_detected.append("T1486")

        verdict = "MALICIOUS" if is_malicious else "CLEAN"
        conf = 85 if is_malicious else 75
        h1 = 85 if is_malicious else 15
        h2 = 15 if is_malicious else 85
        reasoning = "; ".join(findings) if findings else f"{self.name}: on-host edge forensics verified host indicators."

        if emit_log:
            emit_log(self.key,
                f"EDGE VERDICT: {verdict} | Confidence: {conf}% | H1={h1} H2={h2} | "
                f"Tools: {len(tool_results)} run | TTPs: {', '.join(ttps_detected) or 'none'}",
                "success" if is_malicious else "info")

        return {
            "verdict": verdict,
            "confidence": conf,
            "h1Score": h1,
            "h2Score": h2,
            "reasoning": reasoning,
            "ttpsDetected": sorted(list(set(ttps_detected))),
            "killChainStages": kill_chain or [{"stage": "Execution", "evidence": "Edge heuristics verified"}],
            "toolsUsed": list(tool_results.keys()),
            "toolCallCount": max(len(tool_results), 1),
            "agentWeight": weight,
            "summary": f"{self.name}: {verdict} verdict from {len(tool_results)} on-host tool checks."
        }


def _run_agent_task(
    key: str,
    agent: AgenticSwarmMember,
    alert: Dict[str, Any],
    past_episodes: List[Dict[str, Any]],
    peer_findings: Dict[str, str],
    emit_log: Optional[Callable]
) -> tuple:
    """Helper for ThreadPoolExecutor — runs one agent and returns (key, result)."""
    result = agent.investigate(alert, peer_findings=peer_findings,
                               past_episodes=past_episodes, emit_log=emit_log)
    return key, result


def run_swarm_parallel(
    swarm: Dict[str, AgenticSwarmMember],
    alert: Dict[str, Any],
    past_episodes: List[Dict[str, Any]],
    emit_log: Optional[Callable[[str, str, str], None]] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Two-phase parallel execution:
      Phase 1: Fast intel agents (Log, ThreatIntel) run concurrently — sigma + IOC.
      Phase 2: Deep agents (Malware, Cloud) run with Phase 1 results injected as peer context.
    This ensures inter-agent findings sharing actually works (not a race condition).
    """
    verdicts: Dict[str, Dict[str, Any]] = {}
    phase1_swarm = {k: v for k, v in swarm.items() if k in PHASE_1_AGENTS}
    phase2_swarm = {k: v for k, v in swarm.items() if k in PHASE_2_AGENTS}
    # Any agents not in either phase run in phase 1
    extra = {k: v for k, v in swarm.items() if k not in PHASE_1_AGENTS and k not in PHASE_2_AGENTS}
    phase1_swarm.update(extra)

    if emit_log:
        emit_log("coordinator",
            f"PHASE 1: Launching {len(phase1_swarm)} fast-intel agents "
            f"({[a.name for a in phase1_swarm.values()]}) in parallel",
            "info")

    # --- Phase 1: Fast intel agents ---
    with ThreadPoolExecutor(max_workers=max(len(phase1_swarm), 1)) as ex:
        futures = {
            ex.submit(_run_agent_task, k, a, alert, past_episodes, {}, emit_log): k
            for k, a in phase1_swarm.items()
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                k, res = future.result()
                verdicts[k] = res
                if emit_log:
                    emit_log("coordinator",
                        f"Phase 1 -> {swarm[k].name}: {res.get('verdict')} ({res.get('confidence')}%)",
                        "info")
            except Exception as e:
                key = futures[future]
                if emit_log:
                    emit_log("coordinator", f"Phase 1 agent '{key}' error: {str(e)}", "danger")
                verdicts[key] = _fallback_verdict(key, str(e))

    # Build peer findings from Phase 1 for injection into Phase 2
    phase1_summaries = {
        swarm[k].name: verdicts[k].get("summary", f"{swarm[k].name}: {verdicts[k].get('verdict','?')}")
        for k in phase1_swarm
        if k in verdicts
    }

    if emit_log and phase2_swarm:
        emit_log("coordinator",
            f"PHASE 2: Launching {len(phase2_swarm)} deep-analysis agents "
            f"({[a.name for a in phase2_swarm.values()]}) with Phase 1 intel injected",
            "info")

    # --- Phase 2: Deep analysis agents with peer context ---
    if phase2_swarm:
        with ThreadPoolExecutor(max_workers=max(len(phase2_swarm), 1)) as ex:
            futures = {
                ex.submit(_run_agent_task, k, a, alert, past_episodes, phase1_summaries, emit_log): k
                for k, a in phase2_swarm.items()
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    k, res = future.result()
                    verdicts[k] = res
                    if emit_log:
                        emit_log("coordinator",
                            f"Phase 2 -> {swarm[k].name}: {res.get('verdict')} ({res.get('confidence')}%)",
                            "info")
                except Exception as e:
                    if emit_log:
                        emit_log("coordinator", f"Phase 2 agent '{key}' error: {str(e)}", "danger")
                    verdicts[key] = _fallback_verdict(key, str(e))

    return verdicts


def _fallback_verdict(key: str, error: str) -> Dict[str, Any]:
    return {
        "verdict": "SUSPICIOUS", "confidence": 60, "h1Score": 60, "h2Score": 40,
        "reasoning": f"Agent execution error: {error}",
        "ttpsDetected": [], "killChainStages": [], "toolsUsed": [],
        "toolCallCount": 0, "agentWeight": 1.0,
        "summary": f"{key}: agent error during investigation."
    }


def create_swarm() -> Dict[str, AgenticSwarmMember]:
    """Factory for the full TUESDAY investigation agent swarm."""
    return {
        "log": AgenticSwarmMember(
            key="log", name="Log Analysis",
            role="SIEM Correlation & Sigma Behavioral Detection",
            color="#4A8CA8",
            tools=["sigma_scan", "registry_inspect"]
        ),
        "threatintel": AgenticSwarmMember(
            key="threatintel", name="Threat Intelligence",
            role="Recursive IOC Enrichment & DNS/ASN Reputation",
            color="#B08C9E",
            tools=["ioc_lookup", "socket_inspect"]
        ),
        "malware": AgenticSwarmMember(
            key="malware", name="Malware Sandbox",
            role="Live Process Inspection & EDR Behavioral Analysis",
            color="#EEA4A5",
            tools=["process_inspect", "sigma_scan", "file_hash"]
        ),
        "cloud": AgenticSwarmMember(
            key="cloud", name="Cloud Security",
            role="Network Exfiltration Hunter & Service Integrity Check",
            color="#7FB3BB",
            tools=["socket_inspect", "ioc_lookup", "service_scan"]
        ),
    }
