# Project TUESDAY: Python Agentic AI Core
This directory contains the production-grade Python multi-agent cybersecurity swarm.

Architecture:
- `tools.py`: OS-level Windows telemetry inspection (psutil, sockets, registry, sigma, yara, vector memory)
- `agents.py`: Deep ReAct agent classes using Google Gemini 2.5 Flash / Ollama with native tool-calling
- `hypotheses.py`: Formal Analysis of Competing Hypotheses (ACH) evaluator (H1 vs H2)
- `critic.py`: Adversarial Critic reflection agent that stress-tests consensus to eliminate false alarms
- `orchestrator.py`: Multi-agent pipeline coordinating parallel swarm execution, voting, human governance, and containment
- `server.py`: FastAPI service providing REST endpoints and Server-Sent Events (SSE) stream for real-time telemetry
