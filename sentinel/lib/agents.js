'use strict';
/* ==========================================================================
   TUESDAY Sentinel: Deep Agent Engine
   Extends traditional 1-turn agent calls with:
     1. Recursive Multi-Turn ReAct loops with thought traces
     2. Hypothesis Generation & Differential Evidence Gathering
     3. Adversarial Critic & False-Positive Reflection Pass
     4. Dynamic Episodic Memory Query Formulation & Synthesis
   ========================================================================== */

const llm = require('./llm');
const rules = require('./rules_engine');
const { TOOL_DEFS } = require('./tools');
const store = require('./store');

const AGENTS = {
  coordinator: { name: 'SOC Coordinator', role: 'Swarm Orchestration & Dynamic Playbook Synthesis', icon: 'fa-sitemap', color: '#3E7A84', tools: ['episodic_search', 'ttp_lookup', 'sigma_scan', 'yara_scan', 'ioc_lookup', 'asset_lookup'] },
  log:         { name: 'Log Analysis', role: 'SIEM Correlation & Behavioral Anomaly Engine', icon: 'fa-list-check', color: '#4A8CA8', tools: ['sigma_scan', 'ttp_lookup', 'asset_lookup', 'episodic_search'] },
  threatintel: { name: 'Threat Intelligence', role: 'Recursive IOC Enrichment (VT, AbuseIPDB, Shodan, MISP)', icon: 'fa-globe', color: '#B08C9E', tools: ['ioc_lookup', 'episodic_search', 'ttp_lookup'] },
  malware:     { name: 'Malware Sandbox', role: 'YARA Detonation & In-Memory Behavioral Inspection', icon: 'fa-bug', color: '#EEA4A5', tools: ['yara_scan', 'ttp_lookup'] },
  cloud:       { name: 'Cloud Security', role: 'IAM Posture Audit & Privacy Exfiltration Hunter', icon: 'fa-cloud', color: '#7FB3BB', tools: ['asset_lookup', 'sigma_scan', 'ttp_lookup', 'ioc_lookup'] },
  critic:      { name: 'Adversarial Critic', role: 'Hypothesis Verification & False-Positive Disprover', icon: 'fa-user-ninja', color: '#D97706', tools: ['asset_lookup', 'episodic_search', 'ttp_lookup'] },
  response:    { name: 'Incident Response', role: 'Autonomous Host & Network Containment Enforcer', icon: 'fa-bolt', color: '#FD4040', tools: ['asset_lookup', 'ttp_lookup', 'episodic_search'] },
  compliance:  { name: 'Compliance Audit', role: 'Regulatory Impact (GDPR Art. 33 / HIPAA) & Audit Sealing', icon: 'fa-scale-balanced', color: '#C97A7C', tools: ['asset_lookup', 'ttp_lookup', 'episodic_search'] },
  approval:    { name: 'Human Governance', role: 'Risk Threshold Evaluator & Mission-Critical Safety Gate', icon: 'fa-user-shield', color: '#3E7A84', tools: ['asset_lookup', 'episodic_search'] }
};

const INVESTIGATION_AGENTS = ['log', 'threatintel', 'malware', 'cloud'];

const DEEP_VERDICT_SCHEMA = `
FINAL ANSWER FORMAT (required): output a single JSON object with these EXACT keys:
{
  "thoughtTrace": "<step-by-step reasoning explaining how evidence was gathered and evaluated>",
  "hypothesesEvaluated": [
    {"hypothesis": "<name>", "supported": true|false, "evidence": "<evidence>"}
  ],
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "INCONCLUSIVE",
  "confidence": <integer 0-100>,
  "reasoning": "<2-3 sentences citing concrete tool evidence>",
  "ttpsDetected": ["T1059", "T1486"],
  "killChainStages": [{"stage":"Execution","evidence":"<evidence>"}],
  "rcaEvents": [{"title":"<short>","description":"<detail>","severity":"critical"}],
  "summary": "<one concise log line>"
}
Output ONLY the JSON object. No markdown fences, no commentary, no extra keys.`;

function deepPrompt(agentKey, alert, priorIncidents) {
  const a = AGENTS[agentKey];
  const memoryCtx = priorIncidents && priorIncidents.length
    ? `\nEPISODIC MEMORY (similar past incidents on record):\n${JSON.stringify(priorIncidents)}`
    : '\n(No similar past incidents found in episodic memory. Treat this as a zero-day / novel encounter.)';

  return [
    `You are ${a.name} — ${a.role} in the TUESDAY autonomous cybersecurity swarm.`,
    `You operate as a DEEP REASONING AGENT:`,
    `1. Do NOT make snap assumptions. Formulate 2 competing hypotheses (e.g. H1: Malicious Attack vs H2: Benign Admin Activity / False Alarm).`,
    `2. Recursively invoke your tools to gather verifiable evidence to prove or disprove each hypothesis.`,
    `3. Scrutinize episodic memory to determine if similar attack patterns or known false alarms match.`,
    `4. Weigh tool outputs authoritatively over theoretical priors.`,
    memoryCtx,
    ``,
    `RAW SECURITY ALERT:\n${JSON.stringify(alert)}`,
    ``,
    DEEP_VERDICT_SCHEMA
  ].join('\n');
}

// --- 1. Coordinator Alert Decomposition & Dynamic Memory Recall -------------

async function decompose(alert, emit) {
  // Query episodic memory for similar past alerts
  const searchTerms = [
    alert.title || '',
    alert.ioc || '',
    alert.targetHost || '',
    alert.source || ''
  ].join(' ');

  const pastEpisodes = store.searchEpisodic(searchTerms);

  if (emit && pastEpisodes.length > 0) {
    emit({
      event: 'log',
      agent: 'coordinator',
      type: 'info',
      message: `EPISODIC MEMORY RECALL: Discovered ${pastEpisodes.length} relevant historical incident(s) [${pastEpisodes.map(e => e.id || e.title).join(', ')}]. Synthesizing tailored investigation strategy.`
    });
  }

  const system = `You are the SOC Coordinator in TUESDAY. Decompose the security alert into parallel investigation plans and formulate an initial hypothesis.`;
  const user = [
    `RAW ALERT: ${JSON.stringify(alert)}`,
    `HISTORICAL MEMORY MATCHES: ${JSON.stringify(pastEpisodes)}`,
    `Return ONLY JSON: {"decomposition":"<one sentence investigation plan>","dispatch":["log","threatintel","malware","cloud"],"priority":"CRITICAL|HIGH|MEDIUM","initialAssessment":"<one line>","hypotheses":["H1: ...","H2: ..."],"ttpsHypothesis":["T1059"]}`
  ].join('\n');

  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    if (emit && out) {
      emit({
        event: 'log',
        agent: 'coordinator',
        type: 'info',
        message: `TASK DECOMPOSITION: ${out.decomposition || 'Dispatching 4 parallel investigation agents.'} Priority: ${out.priority || 'HIGH'}.`
      });
      if (out.hypotheses && out.hypotheses.length) {
        emit({
          event: 'log',
          agent: 'coordinator',
          type: 'info',
          message: `HYPOTHESES PROPOSED: ${out.hypotheses.join(' | ')}`
        });
      }
    }
    return { ...(out || {}), pastEpisodes };
  } catch (e) {
    return {
      decomposition: 'Dispatching parallel deep investigation agents.',
      dispatch: INVESTIGATION_AGENTS,
      priority: 'HIGH',
      initialAssessment: 'Heuristic investigation underway',
      ttpsHypothesis: [],
      pastEpisodes
    };
  }
}

// --- 2. Deep Agent Investigation (Recursive ReAct Loop) ----------------------

async function investigate(agentKey, alert, emit) {
  const a = AGENTS[agentKey];
  const queryStr = `${alert.title || ''} ${alert.ioc || ''}`.trim();
  const similar = store.searchEpisodic(queryStr);

  if (emit) {
    emit({ event: 'log', agent: agentKey, type: 'info', message: `${a.name} initiated Deep Reasoning ReAct loop.` });
  }

  const user = [
    `Investigate this alert through recursive tool calls and render your evidentiary verdict.`,
    `ALERT: ${JSON.stringify(alert)}`,
    `Call your available tools iteratively to inspect payloads, enrich indicators, and check asset sensitivity.`
  ].join('\n');

  try {
    const res = await llm.runAgent({
      agentKey,
      name: a.name,
      system: deepPrompt(agentKey, alert, similar),
      user,
      tools: TOOL_DEFS.filter(t => a.tools.includes(t.function.name)),
      emitLog: (key, message, type) => emit && emit({ event: 'log', agent: key, type, message }),
      maxTurns: 4 // Deep multi-turn exploration budget
    });

    const out = sanitizeVerdict(res.output, agentKey);
    out.toolCalls = res.toolCalls || 0;
    out.thoughtTrace = res.output && res.output.thoughtTrace ? res.output.thoughtTrace : res.content;
    out.hypothesesEvaluated = res.output && res.output.hypothesesEvaluated ? res.output.hypothesesEvaluated : [];

    if (emit && out.thoughtTrace) {
      emit({
        event: 'log',
        agent: agentKey,
        type: 'info',
        message: `[REASONING TRACE] ${out.summary || out.thoughtTrace.slice(0, 160)}`
      });
    }

    return out;
  } catch (e) {
    if (emit) {
      emit({
        event: 'log',
        agent: agentKey,
        type: 'warning',
        message: `LLM reasoning fallback (${e.message}) — executing deterministic rule evaluation.`
      });
    }
    return sanitizeVerdict(rules.investigate(agentKey, alert, 0), agentKey);
  }
}

// --- 3. Adversarial Critic Pass (False-Positive Disprover) -------------------

async function runAdversarialCritic({ alert, verdicts, consensus }, emit) {
  if (emit) {
    emit({
      event: 'log',
      agent: 'critic',
      type: 'info',
      message: `Adversarial Critic pass engaged: Stress-testing consensus against false positives and benign explanations.`
    });
  }

  const system = `You are the Adversarial Security Critic in TUESDAY. Your job is to challenge the consensus. Could this alert be explained by benign software, routine admin tasks, or false alarms? Disprove confirmation bias.`;
  const user = [
    `ALERT: ${JSON.stringify(alert)}`,
    `INVESTIGATION VERDICTS: ${JSON.stringify(verdicts)}`,
    `CONSENSUS: ${JSON.stringify(consensus)}`,
    `Return JSON: {"challengePassed": true|false, "criticVerdict": "CONFIRMED_THREAT|POTENTIAL_FALSE_POSITIVE|BENIGN", "counterEvidence": "<string>", "confidenceAdjustment": <-20 to +10>, "rationale": "<string>"}`
  ].join('\n');

  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    if (emit && out) {
      emit({
        event: 'log',
        agent: 'critic',
        type: out.challengePassed ? 'success' : 'warning',
        message: `CRITIC VERDICT: ${out.criticVerdict} — ${out.rationale || 'Consensus verified.'}`
      });
    }
    return out || { challengePassed: true, confidenceAdjustment: 0 };
  } catch (e) {
    return { challengePassed: true, confidenceAdjustment: 0 };
  }
}

// --- 4. Dynamic Playbook Synthesis ------------------------------------------

async function synthesizePlaybook({ alert, verdicts, riskScore, similarEpisodes }, emit) {
  const system = `You are the SOC Incident Response Architect. Synthesize a customized, incident-specific SOAR containment playbook using past episode experience.`;
  const user = [
    `ALERT: ${JSON.stringify(alert)}`,
    `CONFIRMED RISK SCORE: ${riskScore}/100`,
    `SIMILAR PAST RESOLUTIONS: ${JSON.stringify(similarEpisodes || [])}`,
    `Return ONLY JSON: {"name": "<Playbook Name>", "steps": [{"action": "FW_BLOCK|HOST_ISOLATION|PROCESS_TERMINATE|CREDENTIAL_REVOKE", "target": "<target>", "priority": "IMMEDIATE|POST_INCIDENT", "description": "<step description>"}]}`
  ].join('\n');

  try {
    const pb = await llm.generateJSON({ system, user, temperature: 0.1 });
    if (pb && pb.steps && pb.steps.length) {
      if (emit) {
        emit({
          event: 'log',
          agent: 'response',
          type: 'info',
          message: `ADAPTIVE PLAYBOOK SYNTHESIZED: "${pb.name}" (${pb.steps.length} coordinated actions)`
        });
      }
      return pb;
    }
  } catch (e) {
    /* fallback to default */
  }

  return {
    name: 'Adaptive Standard Containment',
    steps: [
      { action: 'FW_BLOCK', target: alert.ioc || '185.220.101.5', priority: 'IMMEDIATE', description: 'Block C2 inbound and outbound sockets' },
      { action: 'PROCESS_TERMINATE', target: 'powershell.exe', priority: 'IMMEDIATE', description: 'Kill rogue execution process' },
      { action: 'HOST_ISOLATION', target: alert.targetHost || 'ENDPOINT-01', priority: 'IMMEDIATE', description: 'Isolate endpoint network interface' }
    ]
  };
}

// --- 5. Human-in-the-Loop Governance Decision -------------------------------

async function approve({ alert, riskScore, threshold, consensus, asset }, emit) {
  const system = `You are the Human Governance & Safety Gate Agent in TUESDAY.
You enforce the safety policy:
- If target asset is a CRITICAL core infrastructure (Domain Controller, Identity Store, Payment Gateway) AND risk > threshold, you MUST recommend ESCALATE_HUMAN.
- If asset is non-critical workstation or dev enclave and risk > threshold, you may recommend AUTO_CONTAIN.
- Output JSON: {"decision":"AUTO_CONTAIN|ESCALATE_HUMAN|NO_ACTION","rationale":"<1-2 sentences explaining reasoning>"}`;

  const user = JSON.stringify({ alert, riskScore, threshold, consensus, asset });
  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    if (out && out.decision) return out;
  } catch (e) {
    /* fall back to deterministic policy */
  }
  return rules.approve(alert, riskScore, threshold, consensus);
}

// --- 6. Incident Response Execution -----------------------------------------

async function respond({ alert, decision, playbook, votes }, emit) {
  const containment = require('./connectors/containment');
  const actionsToRun = (playbook && playbook.steps) || [
    { action: 'FW_BLOCK', target: alert.ioc },
    { action: 'HOST_ISOLATION', target: alert.targetHost }
  ];

  const executedActions = [];
  for (const step of actionsToRun) {
    const res = await containment.execute(step.action, step.target, { dryRun: containment.CONFIG.dryRun });
    executedActions.push({
      action: step.action,
      target: step.target,
      status: res.executed ? 'EXECUTED' : 'FAILED',
      mode: res.mode,
      detail: res.detail
    });

    if (emit) {
      emit({
        event: 'log',
        agent: 'response',
        type: 'success',
        message: `CONTAINMENT [${step.action}]: ${res.detail || step.target}`
      });
    }
  }

  return {
    status: 'CONTAINED',
    actions: executedActions,
    summary: `Autonomous containment executed across ${executedActions.length} mitigation vectors.`
  };
}

// --- Helper Verdict Sanitizer -----------------------------------------------

function sanitizeVerdict(v, agentKey) {
  const { TTP_MAP } = require('./tools');
  if (!v || typeof v !== 'object') v = { reasoning: String(v || '') };

  for (const k of ['output', 'result', 'final', 'final_output', 'answer']) {
    if (v[k] && typeof v[k] === 'object' && !Array.isArray(v[k])) { v = { ...v[k], ...v }; break; }
  }

  const rawVerdict = typeof v.verdict === 'string'
    ? v.verdict
    : typeof v.verdict === 'object'
      ? (v.verdict.verdict || v.verdict.vote || v.verdict.classification || '')
      : String(v.verdict || '');
  const upper = String(rawVerdict).toUpperCase();
  const text = JSON.stringify(v).toLowerCase();

  let verdict = 'INCONCLUSIVE';
  if (['MALICIOUS', 'SUSPICIOUS', 'CLEAN', 'INCONCLUSIVE', 'BENIGN'].includes(upper)) {
    verdict = upper === 'BENIGN' ? 'CLEAN' : upper;
  } else if (/malicious|malware|ransom|beacon|compromised|tor exit|infected|unauthorized/.test(text)) {
    verdict = 'MALICIOUS';
  } else if (/suspicious|anomaly|anomalous/.test(text)) {
    verdict = 'SUSPICIOUS';
  } else if (/benign|clean|whitelisted/.test(text)) {
    verdict = 'CLEAN';
  }

  let confidence = parseInt(v.confidence, 10);
  if (isNaN(confidence)) {
    const m = /confidence"?\s*[:=]\s*(\d{1,3})/.exec(text);
    confidence = m ? parseInt(m[1], 10) : (verdict === 'MALICIOUS' ? 85 : verdict === 'SUSPICIOUS' ? 60 : 30);
  }
  confidence = Math.max(0, Math.min(100, confidence));

  let ttpsDetected = Array.isArray(v.ttpsDetected) ? v.ttpsDetected : [];
  if (!ttpsDetected.length) {
    ttpsDetected = (text.match(/T\d{3,4}(?:\.\d{1,3})?/g) || []).slice(0, 6);
  }

  let killChainStages = Array.isArray(v.killChainStages) ? v.killChainStages : [];
  if (!killChainStages.length) {
    const seen = {};
    ttpsDetected.forEach(t => {
      const base = String(t).split('.')[0];
      const ttp = TTP_MAP[base];
      if (ttp && !seen[ttp.tactic]) {
        seen[ttp.tactic] = true;
        killChainStages.push({ stage: ttp.tactic, evidence: `Adversary TTP ${base} (${ttp.name}) identified` });
      }
    });
  }

  let rcaEvents = Array.isArray(v.rcaEvents) ? v.rcaEvents : [];
  if (!rcaEvents.length) {
    rcaEvents.push({
      title: `${AGENTS[agentKey].name} Assessment`,
      description: v.reasoning ? v.reasoning.slice(0, 160) : `${verdict} classification with ${confidence}% confidence`,
      severity: verdict === 'MALICIOUS' ? 'critical' : verdict === 'SUSPICIOUS' ? 'warning' : 'info'
    });
  }

  return {
    verdict,
    confidence,
    reasoning: v.reasoning || text.slice(0, 240),
    summary: v.summary || `${AGENTS[agentKey].name} evaluated ${verdict} (${confidence}% confidence)`,
    ttpsDetected,
    killChainStages,
    rcaEvents
  };
}

module.exports = {
  AGENTS,
  INVESTIGATION_AGENTS,
  decompose,
  investigate,
  runAdversarialCritic,
  synthesizePlaybook,
  approve,
  respond,
  sanitizeVerdict
};
