"""
Project TUESDAY: Formal Analysis of Competing Hypotheses (ACH) Engine
Implements structured analytical intelligence tradecraft:
  - H1: Malicious Attack / Active Threat Actor
  - H2: Benign Administrative Activity / False Positive
Each hypothesis is scored against real tool evidence gathered by each agent.
"""

import os
import json
import requests
from typing import Dict, Any, List

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

def run_ach(alert: Dict[str, Any], verdicts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formal ACH: Evaluate H1 (Malicious) vs H2 (Benign) using collected agent evidence.
    Returns structured hypothesis comparison with diagnostic scores.
    """
    # Collect all evidence from agent verdicts
    evidence_lines = []
    all_ttps = []
    for key, v in verdicts.items():
        evidence_lines.append(f"- [{key.upper()}] Verdict: {v.get('verdict')} ({v.get('confidence')}%): {v.get('reasoning', '')}")
        all_ttps.extend(v.get("ttpsDetected", []))

    evidence_block = "\n".join(evidence_lines)
    ttps_block = ", ".join(sorted(set(all_ttps))) or "None detected"

    prompt = f"""You are an intelligence analyst running formal Analysis of Competing Hypotheses (ACH).

ALERT: {json.dumps(alert)}

AGENT EVIDENCE:
{evidence_block}

MITRE ATT&CK TTPs Detected: {ttps_block}

Evaluate two competing hypotheses:
H1: This is a REAL ATTACK — a malicious actor is actively exploiting the host.
H2: This is a FALSE ALARM — benign administrative, maintenance, or automated activity.

For each hypothesis, score how well the evidence supports or contradicts it (Strongly Supports / Supports / Neutral / Contradicts / Strongly Contradicts).

Output valid JSON ONLY:
{{
  "h1": {{
    "hypothesis": "Active Malicious Attack",
    "evidenceScore": <int 0-100 where 100 = all evidence strongly supports>,
    "keyEvidence": "<top 2-3 pieces of evidence supporting H1>",
    "weaknesses": "<what evidence is missing or could undermine H1>"
  }},
  "h2": {{
    "hypothesis": "Benign Administrative Activity / False Positive",
    "evidenceScore": <int 0-100>,
    "keyEvidence": "<arguments for H2 being true>",
    "weaknesses": "<what rules out H2>"
  }},
  "preferredHypothesis": "H1" | "H2",
  "confidence": <int 0-100>,
  "diagnosticSummary": "<2-3 sentence intelligence judgment>"
}}"""

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GEMINI_API_KEY}"
    }
    payload = {
        "model": "gemini-2.5-flash",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        resp = requests.post(GEMINI_URL, headers=headers, json=payload, timeout=20)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        return json.loads(content)
    except Exception as e:
        # Deterministic fallback from evidence
        malicious_count = sum(1 for v in verdicts.values() if v.get("verdict") == "MALICIOUS")
        total = len(verdicts)
        h1_score = int((malicious_count / max(total, 1)) * 100)
        return {
            "h1": {
                "hypothesis": "Active Malicious Attack",
                "evidenceScore": h1_score,
                "keyEvidence": f"{malicious_count}/{total} agents confirmed malicious indicators. TTPs: {ttps_block}.",
                "weaknesses": "No baseline behavioral data for comparison."
            },
            "h2": {
                "hypothesis": "Benign Administrative Activity / False Positive",
                "evidenceScore": 100 - h1_score,
                "keyEvidence": "Activity could match scheduled maintenance or IT automation scripts.",
                "weaknesses": "No IT change management ticket or authorized maintenance window correlated."
            },
            "preferredHypothesis": "H1" if h1_score >= 50 else "H2",
            "confidence": h1_score,
            "diagnosticSummary": f"ACH deterministic fallback: {malicious_count}/{total} agents voted MALICIOUS, strongly supporting H1 over H2."
        }
