"""Live test of the full agentic pipeline."""
from engine.orchestrator import SwarmOrchestrator

def emit(agent, msg, level):
    print(f"  [{level.upper()}][{agent}] {msg}")

orch = SwarmOrchestrator()
res = orch.run_investigation({
    "id": "LIVE-TEST-001",
    "title": "Ransomware Canary File Deletion + Encoded PowerShell Downloader",
    "host": "DESKTOP-TUESDAY",
    "process": "powershell.exe",
    "pid": 4820,
    "ioc": "185.220.101.5",
    "severity": "CRITICAL",
    "source": "edr"
}, emit_log=emit)

print()
print("=" * 60)
print(f"STATUS:         {res['status']}")
print(f"RISK SCORE:     {res['riskScore']}/100")
malicious = sum(1 for v in res["votes"] if v["vote"] == "MALICIOUS")
print(f"CONSENSUS:      {res['consensusPct']}%  ({malicious}/{len(res['votes'])} agents)")
print(f"WEIGHTED CONF:  {res['weightedConfidence']}%")
h1 = res["ach"]["h1"]["evidenceScore"]
h2 = res["ach"]["h2"]["evidenceScore"]
pref = res["ach"]["preferredHypothesis"]
print(f"ACH:            Preferred {pref} (H1={h1} vs H2={h2})")
print(f"CRITIC:         {res['critic']['criticVerdict']}")
print(f"TTPS:           {res['ttpsDetected']}")
print(f"TOOL CALLS:     {res['totalToolCalls']} total")
print(f"PLAYBOOK:       {res['playbook']['playbookName']}")
print(f"LATENCY:        {res['latencySec']}s")
print(f"MEMORY RECALL:  {len(res['recalledEpisodes'])} past episodes")
