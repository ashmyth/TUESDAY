# TUESDAY 🛡️
> **Threat Unification Engine for Security Defense And Your SOC**  
> *An Autonomous, Local-First, Air-Gapped Cybersecurity Platform Powered by Deep Agents*

### 💡 What is TUESDAY?
**TUESDAY** is an autonomous, on-device AI cybersecurity ecosystem built for zero-trust, privacy-critical environments. Traditional cloud-based security tools leak confidential logs, system metadata, and proprietary code to third-party LLMs. TUESDAY fundamentally rethinks this by running entirely air-gapped on local Small Language Models (SLMs) via Ollama. 

The platform operates as a decoupled **two-app architecture**:
1. **TUESDAY Sentinel (The Defensive SOC & Host EDR):** An elevated watchdog system with deep OS-level access (managing Windows `netsh` / Linux `iptables`, terminating malicious PIDs, and inspecting network sockets). Powered by a swarm of **Deep Agents** that conduct multi-turn recursive ReAct loops, Sentinel doesn't guess; it queries local **episodic memory** to learn from past incidents, designs dynamic playbooks, and quarantines hostile actors in real time.
2. **TUESDAY RedTeam (The Adversary Attack Suite):** A dedicated purple-teaming generator designed to stress-test Sentinel. It orchestrates realistic, multi-stage cyber campaigns—from stealthy privacy telemetry scrapers and DNS exfiltration tunnels to simulated LockBit ransomware and cloud STS role hijacking—delivering real-time telemetry into Sentinel to validate its detection and containment efficacy.

---

## 🔒 Track Alignment: Cybersecurity & Privacy
Modern digital defense requires an uncompromising posture: **assume the network is already hostile, and keep sensitive telemetry strictly on-device.**

1. **Local-First Air-Gapped Privacy:** Zero telemetry leaves the machine. Investigations, memory retrieval, and payload analysis run on-device via quantized SLMs (Qwen 2.5 / DeepSeek via Ollama). No private logs, credentials, or network topologies ever reach cloud APIs.
2. **Untrusted-by-Default Defense & Host Sandboxing:** The agent swarm possesses elevated access to local networking and host firewalls (`netsh`/`iptables`), actively monitoring sockets and terminating unverified, malicious processes in real time.
3. **Surveillance & Exfiltration Spotlight:** Hunts covert data-harvesting software, shadow telemetry, clipboard/token scrapers, and unauthorized C2 beacons attempting to siphon private data.

---

## 🏛️ System Architecture: The Two-App Ecosystem

TUESDAY is decoupled into two purpose-built engines:

```
┌──────────────────────────────────────────────────────────┐       ┌──────────────────────────────────────────────────────────┐
│                APP 1: TUESDAY SENTINEL                   │       │                 APP 2: TUESDAY REDTEAM                   │
│              (Autonomous SOC & Host EDR)                 │       │               (Adversary Attack Suite)                   │
├──────────────────────────────────────────────────────────┤       ├──────────────────────────────────────────────────────────┤
│ • Local Deep Agent swarm with recursive ReAct loops      │       │ • Interactive Adversary Simulation Console               │
│ • Elevated host access: Windows netsh / Linux iptables   │       │ • Attack Arsenal & Realistic Drills:                     │
│ • Real-time process termination & interface isolation    │       │    - Stealthy Data Harvester (Privacy track demo)         │
│ • Local episodic memory & dynamic playbook generation    │◄──────┼──  - Ransomware vssadmin shadow copy deletion attempt      │
│ • Human-in-the-loop governance for critical assets       │ Live  │  - Covert DNS & C2 tunneling                             │
│ • Live SSE agent thought-trace & threat matrix UI        │ Attack│  - Cloud STS credential abuse simulation                 │
└──────────────────────────────────────────────────────────┘ Events└──────────────────────────────────────────────────────────┘
```

---

## 🔍 Deep Dive: The Two Applications

### 🛡️ App 1: TUESDAY Sentinel (Defensive Core)
- **Recursive Multi-Turn Deep Agents:** Specialist agents (Log Analysis, Threat Intel, Malware Detonation, Cloud Auditing) don't stop at one shallow tool call. They generate competing hypotheses, investigate across multiple steps (e.g. `sigma_scan` → flag suspicious IP → `ioc_lookup` → check domain reputation → `ttp_lookup`), and perform self-reflective critic passes.
- **Autonomous Episodic Memory Retrieval:** Before taking action, Sentinel queries its persistent local episodic store. It recalls past incident vectors, checks which mitigation strategies succeeded or failed previously, and dynamically synthesizes tailored containment playbooks.
- **Direct Host Enforcement (Elevated Privileges):** Possesses root/admin hooks to dynamically inject firewall rules, sever unauthorized outbound TCP/UDP connections, terminate malicious process trees (`taskkill` / `kill -9`), and quarantine infected host interfaces.
- **Human-in-the-Loop Governance:** High-impact actions affecting mission-critical infrastructure (e.g., Domain Controllers, primary databases) automatically route to an operator queue with complete evidence chains.

### ⚔️ App 2: TUESDAY RedTeam (Attack Simulator)
- **Adversary Campaign Orchestrator:** Provides a unified command deck to trigger, monitor, and script realistic attacks against local or network endpoints.
- **Privacy & Surveillance Track Demonstrator:** Features a dedicated **Spyware / Telemetry Harvester** scenario that simulates background scrapers hunting for browser cookies, session tokens, and `.env` credentials, proving Sentinel's ability to expose invisible data harvesting.
- **Advanced Attack Scenarios:**
  - *LockBit 3.0 Ransomware:* Simulates shadow copy wipe (`vssadmin delete shadows`) and canary file encryption.
  - *Covert DNS Tunneling:* Simulates data exfiltration through base64-encoded subdomains bypassing standard port-based firewalls.
  - *Cloud STS Privilege Escalation:* Simulates compromised AWS IAM keys executing unauthorized S3 exfiltration.
- **Direct Live Ingestion Stream:** Directly fires structured EDR, syslog, and network alert streams into Sentinel's ingestion pipeline.

---

## 🚀 Hackathon Roadmap & Progress

- [x] **Core Foundation:** Local runtime, configuration schema, and local model connector
- [x] **Store & Cache:** Persistent episodic memory store and tool stubs
- [ ] **Sentinel Engine:** Deep Agent multi-turn investigation loop & memory synthesis *(In Progress)*
- [ ] **Host Enforcer:** Elevated firewall rule injection & process containment handler *(In Progress)*
- [ ] **RedTeam Simulator:** Purple-team attack generator with privacy-harvester & ransomware drills *(Next)*
- [ ] **Command Center UI:** Live agent thought-stream terminal, MITRE ATT&CK matrix, and digital twin canvas *(Next)*

---

## 💻 Prerequisites & Setup

- **Node.js 20+**
- **Ollama** running locally

```bash
# Pull local air-gapped model
ollama pull qwen2.5:7b

# Run Sentinel Defense Core (Port 8090)
node sentinel/server.js

# Run RedTeam Attack Simulator (Port 8095)
node redteam/server.js
```

---

## 📜 License
Released under the [MIT License](LICENSE).
