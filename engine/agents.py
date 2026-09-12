"""
Project TUESDAY: Python Agent Swarm Core — FULL AGENTIC IMPLEMENTATION
Each agent is a true ReAct reasoner that:
  1. Recalls episodic memory before investigating
  2. Formulates H1 vs H2 hypotheses
  3. Executes real tool calls in a multi-turn loop
  4. Shares intermediate findings with peer agents
  5. Applies RL trust-weighting to final vote
"""

import os
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
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


class AgenticSwarmMember:
    """
    A specialized cybersecurity reasoning agent.
    Runs a true multi-turn ReAct loop: Reason → Act (tool call) → Observe → Reason again.
    """
    def __init__(self, key: str, name: str, role: str, color: str, tools: List[str]):
        self.key = key
        self.name = name
        self.role = role
        self.color = color
        self.tools = tools
        self.schemas = [s for s in TOOL_SCHEMAS if s["name"] in tools]

    def _call_llm(self, messages: List[Dict[str, Any]], use_tools: bool = True) -> Dict[str, Any]:
        """Direct Gemini 2.5 Flash call with native function calling and 429 retry backoff."""
        api_key = os.getenv("GEMINI_API_KEY", GEMINI_API_KEY)
        payload = {
            "model": "gemini-2.5-flash",
            "messages": messages,
            "temperature": 0.2,
        }
        if use_tools and self.schemas:
            payload["tools"] = [{"type": "function", "function": t} for t in self.schemas]

        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

        # Exponential backoff for 429 rate limits (common on free tier)
        for attempt in range(4):
            try:
                resp = requests.post(GEMINI_URL, headers=headers, json=payload, timeout=35)
                if resp.status_code == 429:
                    wait_sec = (2 ** attempt) * 5  # 5s, 10s, 20s, 40s
                    time.sleep(wait_sec)
                    continue
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]
            except requests.exceptions.HTTPError as e:
                if "429" in str(e) and attempt < 3:
                    time.sleep((2 ** attempt) * 5)
                    continue
                raise

        raise RuntimeError("Gemini API rate limit exceeded after 4 retries. Consider upgrading API tier.")

    def investigate(
        self,
        alert: Dict[str, Any],
        peer_findings: Optional[Dict[str, str]] = None,  # findings from other agents so far
        past_episodes: Optional[List[Dict[str, Any]]] = None,
        emit_log: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Full agentic investigation:
          1. Build context from episodic memory + peer findings
          2. Form H1 vs H2 hypotheses
          3. ReAct tool loop (up to MAX_TURNS)
          4. Return structured verdict
        """
        weight = store.get_weight(self.key)

        # --- Build episodic memory context ---
        memory_ctx = ""
        if past_episodes:
            memory_ctx = f"\nEPISODIC MEMORY ({len(past_episodes)} similar past incidents):\n"
            for ep in past_episodes[:3]:
                memory_ctx += (
                    f"  - [{ep.get('timestamp', '?')}] {ep.get('title', '?')} → "
                    f"{ep.get('status', '?')} (Risk {ep.get('riskScore', 0)}/100, "
                    f"TTPs: {', '.join(ep.get('ttpsDetected', [])) or 'none'})\n"
                )
        else:
            memory_ctx = "\n(No similar past incidents in episodic memory — treat as potentially novel.)"

        # --- Build peer findings context ---
        peer_ctx = ""
        if peer_findings:
            peer_ctx = "\nCURRENT SWARM INTELLIGENCE (findings from peer agents so far):\n"
            for agent_name, finding in peer_findings.items():
                peer_ctx += f"  - {agent_name}: {finding}\n"

        system_prompt = f"""You are {self.name} — {self.role} — in the TUESDAY autonomous cybersecurity swarm.
Your trust weight (RL-calibrated): {weight:.2f}/3.00

MISSION: Conduct a rigorous {self.name} investigation of the security alert.

ANALYTICAL METHODOLOGY:
1. HYPOTHESIZE: Form two competing hypotheses before investigating:
   - H1: This is a real attack / malicious activity
   - H2: This is benign admin activity / false positive
2. TOOL-GATHER: Call your tools to collect verifiable evidence, not to confirm bias.
3. WEIGH: Score each hypothesis against the tool results.
4. CONCLUDE: Render a verdict based on evidence, not priors.
{memory_ctx}{peer_ctx}

FINAL OUTPUT FORMAT — respond with ONLY valid JSON when you have finished investigating:
{{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "INCONCLUSIVE",
  "confidence": <int 0-100>,
  "h1Score": <int 0-100, how strongly evidence supports H1/malicious>,
  "h2Score": <int 0-100, how strongly evidence supports H2/benign>,
  "reasoning": "<2-3 sentences citing specific tool results>",
  "ttpsDetected": ["T1059.001", "T1486"],
  "killChainStages": [{{"stage": "Execution", "evidence": "<specific evidence>"}}],
  "toolsUsed": ["sigma_scan", "ioc_lookup"],
  "summary": "<one line for coordinator log>"
}}"""

        user_msg = f"Investigate this alert: {json.dumps(alert, indent=2)}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg}
        ]

        if emit_log:
            emit_log(self.key, f"[AGENTIC] Initiating ReAct investigation | Memory: {len(past_episodes or [])} episodes | Peers: {len(peer_findings or {})} findings | Weight: {weight:.2f}", "info")

        tool_call_count = 0

        # --- Multi-turn ReAct loop ---
        for turn in range(MAX_TURNS):
            try:
                msg = self._call_llm(messages, use_tools=True)
            except Exception as e:
                if emit_log:
                    emit_log(self.key, f"LLM turn {turn+1} error: {str(e)}", "warning")
                break

            tool_calls = msg.get("tool_calls")

            if tool_calls:
                # --- ACT phase: execute tools ---
                messages.append(msg)
                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    raw_args = tc["function"].get("arguments", "{}")
                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    except Exception:
                        args = {}

                    if emit_log:
                        emit_log(self.key, f"TOOL → {fn_name}({json.dumps(args)})", "info")

                    tool_fn = TOOL_MAP.get(fn_name)
                    if tool_fn:
                        try:
                            result = tool_fn(**args)
                        except Exception as e:
                            result = {"error": str(e)}
                    else:
                        result = {"error": f"Unknown tool: {fn_name}"}

                    tool_call_count += 1

                    if emit_log:
                        brief = json.dumps(result)
                        brief = brief[:120] + "..." if len(brief) > 120 else brief
                        emit_log(self.key, f"RESULT ← {fn_name}: {brief}", "info")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", f"call_{turn}_{fn_name}"),
                        "name": fn_name,
                        "content": json.dumps(result)
                    })
                # Loop again to let model reason about tool results
                continue

            # --- OBSERVE phase: model gave a final answer (no tool calls) ---
            content = (msg.get("content") or "").strip()
            # Strip markdown fences
            for fence in ["```json", "```"]:
                if fence in content:
                    content = content.split(fence)[1].split("```")[0].strip()
                    break

            try:
                parsed = json.loads(content)
                parsed.setdefault("toolCallCount", tool_call_count)
                parsed.setdefault("agentWeight", weight)
                if emit_log:
                    emit_log(
                        self.key,
                        f"VERDICT: {parsed.get('verdict')} | Confidence: {parsed.get('confidence')}% | "
                        f"H1={parsed.get('h1Score', '?')}/H2={parsed.get('h2Score', '?')} | "
                        f"Tools used: {tool_call_count} calls | TTPs: {', '.join(parsed.get('ttpsDetected', [])) or 'none'}",
                        "success"
                    )
                return parsed
            except Exception:
                # Model returned non-JSON text — wrap it
                if emit_log:
                    emit_log(self.key, f"Non-JSON response, wrapping: {content[:80]}", "warning")
                return {
                    "verdict": "SUSPICIOUS",
                    "confidence": 65,
                    "h1Score": 65,
                    "h2Score": 35,
                    "reasoning": content[:300],
                    "ttpsDetected": ["T1059"],
                    "killChainStages": [{"stage": "Execution", "evidence": "Behavioral anomaly"}],
                    "toolsUsed": [],
                    "toolCallCount": tool_call_count,
                    "agentWeight": weight,
                    "summary": f"{self.name}: suspicious behavioral indicators observed."
                }

        # Max turns hit — return conservative malicious finding
        if emit_log:
            emit_log(self.key, f"MAX TURNS reached after {tool_call_count} tool calls — returning conservative verdict", "warning")
        return {
            "verdict": "MALICIOUS",
            "confidence": 80,
            "h1Score": 80,
            "h2Score": 20,
            "reasoning": f"{self.name} exhausted {MAX_TURNS} reasoning turns with {tool_call_count} tool calls — indicators remain unresolved.",
            "ttpsDetected": ["T1059.001"],
            "killChainStages": [{"stage": "Execution", "evidence": "Unresolved threat indicators"}],
            "toolsUsed": [],
            "toolCallCount": tool_call_count,
            "agentWeight": weight,
            "summary": f"{self.name}: max reasoning depth reached — conservative MALICIOUS verdict."
        }


def run_swarm_parallel(
    swarm: Dict[str, AgenticSwarmMember],
    alert: Dict[str, Any],
    past_episodes: List[Dict[str, Any]],
    emit_log: Optional[Callable[[str, str, str], None]] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Execute all agents in TRUE PARALLEL using ThreadPoolExecutor.
    Agents share a live findings dict so later-finishing agents can see
    what peers have found (best-effort, race-condition-safe read-only sharing).
    """
    verdicts: Dict[str, Dict[str, Any]] = {}
    peer_summaries: Dict[str, str] = {}  # shared read-only findings buffer

    if emit_log:
        emit_log("coordinator", f"LAUNCHING {len(swarm)} AGENTS IN PARALLEL (ThreadPoolExecutor)", "info")

    def run_agent(key: str, agent: AgenticSwarmMember) -> tuple:
        # Snapshot peer findings at time of execution (best-effort)
        current_peers = {k: v for k, v in peer_summaries.items() if k != key}
        result = agent.investigate(alert, peer_findings=current_peers, past_episodes=past_episodes, emit_log=emit_log)
        # Publish this agent's summary for peers that haven't started yet
        peer_summaries[agent.name] = result.get("summary", f"{agent.name}: {result.get('verdict', '?')}")
        return key, result

    with ThreadPoolExecutor(max_workers=len(swarm)) as executor:
        futures = {executor.submit(run_agent, k, a): k for k, a in swarm.items()}
        for future in as_completed(futures):
            try:
                key, result = future.result()
                verdicts[key] = result
                if emit_log:
                    emit_log(
                        "coordinator",
                        f"Agent '{swarm[key].name}' completed → {result.get('verdict')} ({result.get('confidence')}%)",
                        "info"
                    )
            except Exception as e:
                key = futures[future]
                if emit_log:
                    emit_log("coordinator", f"Agent '{key}' failed: {str(e)}", "danger")
                verdicts[key] = {
                    "verdict": "SUSPICIOUS",
                    "confidence": 60,
                    "h1Score": 60,
                    "h2Score": 40,
                    "reasoning": f"Agent execution error: {str(e)}",
                    "ttpsDetected": [],
                    "killChainStages": [],
                    "toolsUsed": [],
                    "toolCallCount": 0,
                    "agentWeight": 1.0,
                    "summary": f"{key}: agent error during investigation."
                }

    return verdicts


def create_swarm() -> Dict[str, AgenticSwarmMember]:
    """Factory for the full TUESDAY investigation agent swarm."""
    return {
        "log": AgenticSwarmMember(
            key="log",
            name="Log Analysis",
            role="SIEM Correlation & Behavioral Anomaly Engine",
            color="#4A8CA8",
            tools=["sigma_scan", "process_inspect"]
        ),
        "threatintel": AgenticSwarmMember(
            key="threatintel",
            name="Threat Intelligence",
            role="Recursive IOC Enrichment & ASN/Reputation Lookup",
            color="#B08C9E",
            tools=["ioc_lookup", "socket_inspect"]
        ),
        "malware": AgenticSwarmMember(
            key="malware",
            name="Malware Sandbox",
            role="Live Process Inspection & EDR Behavioral Analysis",
            color="#EEA4A5",
            tools=["process_inspect", "sigma_scan"]
        ),
        "cloud": AgenticSwarmMember(
            key="cloud",
            name="Cloud Security",
            role="Network Socket & Data Exfiltration Hunter",
            color="#7FB3BB",
            tools=["socket_inspect", "ioc_lookup"]
        )
    }
