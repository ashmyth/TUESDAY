'use strict';
/* ==========================================================================
   TUESDAY: LLM Agent Definitions
   Each specialized agent has a role, a system prompt, and a set of tools it
   may invoke. Agents run a ReAct loop (think → call tool → observe → decide)
   and emit a strict JSON verdict. On any LLM failure the orchestrator falls
   back to the deterministic rule engine for that agent.
   ========================================================================== */

const llm = require('./llm');
const rules = require('./rules_engine');
const { TOOL_DEFS } = require('./tools');

const AGENTS = {
  coordinator: { name: 'SOC Coordinator', role: 'Swarm Orchestration & Task Decomposition', icon: 'fa-sitemap', color: '#3E7A84', tools: ['episodic_search', 'ttp_lookup', 'sigma_scan', 'yara_scan', 'ioc_lookup', 'asset_lookup'] },
  log:         { name: 'Log Analysis', role: 'SIEM Correlation & Sigma Rules Engine', icon: 'fa-list-check', color: '#4A8CA8', tools: ['sigma_scan', 'ttp_lookup', 'asset_lookup', 'episodic_search'] },
  threatintel: { name: 'Threat Intelligence', role: 'IOC Enrichment (VT, AbuseIPDB, Shodan, MISP)', icon: 'fa-globe', color: '#B08C9E', tools: ['ioc_lookup', 'episodic_search', 'ttp_lookup'] },
  malware:     { name: 'Malware Sandbox', role: 'YARA + Behavioral Sandbox Analysis', icon: 'fa-bug', color: '#EEA4A5', tools: ['yara_scan', 'ttp_lookup'] },
  cloud:       { name: 'Cloud Security', role: 'AWS/Azure IAM & CSPM Posture Audit', icon: 'fa-cloud', color: '#7FB3BB', tools: ['asset_lookup', 'sigma_scan', 'ttp_lookup'] },
  response:    { name: 'Incident Response', role: 'Autonomous Containment & SOAR Playbooks', icon: 'fa-bolt', color: '#FD4040', tools: ['asset_lookup', 'ttp_lookup', 'episodic_search'] },
  compliance:  { name: 'Compliance Audit', role: 'Regulatory Impact & Cryptographic Audit Trail', icon: 'fa-scale-balanced', color: '#C97A7C', tools: ['asset_lookup', 'ttp_lookup', 'episodic_search'] },
  approval:    { name: 'Human Governance', role: 'Risk Threshold Gate & Override Control', icon: 'fa-user-shield', color: '#3E7A84', tools: ['asset_lookup', 'episodic_search'] }
};

const INVESTIGATION_AGENTS = ['log', 'threatintel', 'malware', 'cloud'];

const VERDICT_SCHEMA = `
FINAL ANSWER FORMAT (required): output a single JSON object with these EXACT keys:
{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "INCONCLUSIVE",
  "confidence": <integer 0-100>,
  "reasoning": "<2-3 sentences citing concrete tool evidence>",
  "ttpsDetected": ["T1059", "T1486"],
  "killChainStages": [{"stage":"Execution","evidence":"<evidence>"}],
  "rcaEvents": [{"title":"<short>","description":"<detail>","severity":"critical"}],
  "summary": "<one concise log line>"
}
Output ONLY the JSON object. No markdown fences, no commentary, no extra keys.`;

function investigationPrompt(agentKey, alert, priorIncidents) {
  const a = AGENTS[agentKey];
  const memoryCtx = priorIncidents && priorIncidents.length
    ? `\nEPISODIC MEMORY (past incidents retrieved so far):\n${JSON.stringify(priorIncidents)}`
    : '\n(No similar past incidents in episodic memory yet — this is a first-seen case.)';
  return [
    `You are ${a.name} — ${a.role} in the TUESDAY autonomous multi-agent security platform.`,
    `Your job: rigorously investigate the alert below, call the tools you need to gather evidence, and render a verdict.`,
    `Be decisive but evidence-driven. Use tool results in your reasoning. Never fabricate detections — if tools return CLEAN/benign, say so.`,
    `Remember: tool results are authoritative; your own priors are secondary.`,
    memoryCtx,
    ``,
    `RAW SIEM ALERT: ${JSON.stringify(alert)}`,
    ``,
    VERDICT_SCHEMA
  ].join('\n');
}

// --- decomposition (coordinator) --------------------------------------------

async function decompose(alert, emit) {
  const system = `You are the SOC Coordinator in the TUESDAY multi-agent security platform. Given an incoming SIEM alert, plan the investigation.`;
  const user = [
    `RAW SIEM ALERT: ${JSON.stringify(alert)}`,
    `Return ONLY JSON: {"decomposition":"<one sentence on investigation plan>","dispatch":["log","threatintel","malware","cloud"],"priority":"CRITICAL|HIGH|MEDIUM","initialAssessment":"<one line>","ttpsHypothesis":["T1059"]}`,
    `All 4 investigation agents dispatch: log, threatintel, malware, cloud.`
  ].join('\n');
  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    if (emit && out) {
      emit({ event: 'log', agent: 'coordinator', type: 'info', message: `TASK DECOMPOSITION: ${out.decomposition || 'Dispatching 4 parallel investigation agents.'} Priority: ${out.priority || 'HIGH'}.` });
    }
    return out || {};
  } catch (e) {
    return { decomposition: 'Dispatching 4 parallel investigation agents.', dispatch: INVESTIGATION_AGENTS, priority: 'HIGH', initialAssessment: '', ttpsHypothesis: [] };
  }
}

// --- per-agent ReAct investigation ------------------------------------------

async function investigate(agentKey, alert, emit) {
  const a = AGENTS[agentKey];
  const similar = require('./tools').episodic_search({ query: (alert.title || '').split(' ')[0] }).incidents;

  if (emit) emit({ event: 'log', agent: agentKey, type: 'info', message: `Agent ${a.name} began investigation.` });

  const user = `Investigate this alert and render your verdict.\nRAW SIEM ALERT: ${JSON.stringify(alert)}\n\nCall the appropriate tools (e.g. sigma_scan/yara_scan/ioc_lookup/asset_lookup/episodic_search) to gather evidence before deciding. Then produce the final JSON verdict.`;
  try {
    const res = await llm.runAgent({
      agentKey,
      name: a.name,
      system: investigationPrompt(agentKey, alert, similar),
      user,
      tools: TOOL_DEFS.filter(t => a.tools.includes(t.function.name)),
      emitLog: (key, message, type) => emit && emit({ event: 'log', agent: key, type, message })
    });
    const out = sanitizeVerdict(res.output, agentKey);
    out.toolCalls = res.toolCalls || 0;
    return out;
  } catch (e) {
    if (emit) emit({ event: 'log', agent: agentKey, type: 'warning', message: `LLM reasoning failed (${e.message}) — falling back to rule engine.` });
    return sanitizeVerdict(rules.investigate(agentKey, alert, 0), agentKey);
  }
}

function sanitizeVerdict(v, agentKey) {
  const { TTP_MAP } = require('./tools');
  if (!v || typeof v !== 'object') v = { reasoning: String(v || '') };

  // Unwrap common wrapper keys some models emit (final/output/result/...)
  for (const k of ['output', 'result', 'final', 'final_output', 'answer']) {
    if (v[k] && typeof v[k] === 'object' && !Array.isArray(v[k])) { v = { ...v[k], ...v }; break; }
  }

  const rawVerdict = typeof v.verdict === 'string'
    ? v.verdict
    : typeof v.verdict === 'object'
      ? (v.verdict.verdict || v.verdict.vote || v.verdict.classification || v.verdict.label || '')
      : String(v.verdict || '');
  const upper = String(rawVerdict).toUpperCase();
  const text = JSON.stringify(v).toLowerCase();

  let verdict;
  if (['MALICIOUS', 'SUSPICIOUS', 'CLEAN', 'INCONCLUSIVE', 'BENIGN'].includes(upper)) {
    verdict = upper === 'BENIGN' ? 'CLEAN' : upper;
  } else if (/malicious|malware|ransom|beacon|compromised|tor exit|infected|suspected attack/.test(text)) {
    verdict = 'MALICIOUS';
  } else if (/suspicious|anomaly|anomalous|unusual/.test(text)) {
    verdict = 'SUSPICIOUS';
  } else if (/benign|clean|whitelisted|no (malicious|threat|ioc)/.test(text)) {
    verdict = 'CLEAN';
  } else {
    verdict = 'INCONCLUSIVE';
  }

  let confidence = parseInt(v.confidence, 10);
  if (isNaN(confidence)) {
    const m = /confidence"?\s*[:=]\s*(\d{1,3})/.exec(text);
    confidence = m ? parseInt(m[1], 10) : 0;
  }
  if (!confidence) {
    confidence = verdict === 'MALICIOUS' ? 85 : verdict === 'SUSPICIOUS' ? 55 : verdict === 'CLEAN' ? 20 : 0;
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
      if (ttp && !seen[ttp.tactic]) { seen[ttp.tactic] = true; killChainStages.push({ stage: ttp.tactic, evidence: `TTP ${base} ${ttp.name} detected` }); }
    });
  }

  let rcaEvents = Array.isArray(v.rcaEvents) ? v.rcaEvents : [];
  if (!rcaEvents.length && verdict === 'MALICIOUS') {
    rcaEvents.push({ title: 'Investigation Agent Confirmed Malicious Activity', description: String(v.reasoning || v.summary || 'Evidence gathered via tool calls.').slice(0, 160), severity: 'critical' });
  }

  const summary = String(v.summary || '').slice(0, 200) || `${AGENTS[agentKey]?.name} verdict: ${verdict}.`;
  return {
    verdict,
    confidence,
    reasoning: String(v.reasoning || summary).slice(0, 500),
    ttpsDetected,
    killChainStages,
    rcaEvents,
    summary
  };
}

// --- approval gate -----------------------------------------------------------

async function approve(ctx, emit) {
  const { alert, riskScore, threshold, consensus, asset } = ctx;
  const system = [
    `You are the Human Governance Agent in the TUESDAY platform. You are the safety gate between autonomous action and human authorization.`,
    `POLICY: If the weighted risk score EXCEEDS ${threshold}/100 AND the target asset is CRITICAL infrastructure (Domain Controller, core server, production database), you MUST escalate to a human. Otherwise autonomous execution is authorized.`,
    `Never authorize destructive actions on CRITICAL infrastructure without human approval.`
  ].join('\n');
  const user = [
    `ALERT: ${JSON.stringify(alert)}`,
    `WEIGHTED RISK: ${riskScore}/100 (policy auto-execute threshold ${threshold}/100)`,
    `CONSENSUS: ${consensus.maliciousVotes}/${consensus.totalVotes} agents MALICIOUS (${consensus.consensusPct}%)`,
    `TARGET ASSET: ${JSON.stringify(asset)}`,
    `Return ONLY JSON: {"decision":"AUTONOMOUS_EXECUTE|ESCALATE_HUMAN","rationale":"<one sentence>","summary":"<one line>"}`
  ].join('\n');

  const aboveThreshold = riskScore > threshold;
  const criticalAsset = asset && asset.criticality === 'CRITICAL';
  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    const decision = String(out && out.decision || '').toUpperCase();
    const modelVote = decision === 'AUTONOMOUS_EXECUTE';
    // Deterministic policy gate (model weighs in only in the gray zone):
    //  - risk over threshold on CRITICAL infrastructure  → always escalate (hard rule)
    //  - risk at or below threshold on non-critical infra → always autonomous
    //  - otherwise the LLM Governance Agent decides
    const approved = (aboveThreshold && criticalAsset) ? false
      : (!aboveThreshold && !criticalAsset) ? true
      : modelVote;
    return {
      decision: approved ? 'AUTONOMOUS_EXECUTE' : 'ESCALATE_HUMAN',
      rationale: (aboveThreshold && criticalAsset)
        ? `Hard policy: risk ${riskScore}>${threshold} on CRITICAL asset ${asset.id}.`
        : (!aboveThreshold && !criticalAsset)
          ? `Policy: risk ${riskScore} within ${threshold} threshold on non-critical asset — autonomous execution authorized.`
          : (out && out.rationale) || 'Governance agent evaluated the gray zone.',
      summary: (out && out.summary) || 'Approval gate evaluated.'
    };
  } catch (e) {
    return rules.approve(alert, riskScore, threshold, consensus);
  }
}

// --- incident response ---------------------------------------------------------

async function respond(ctx, emit) {
  const { alert, decision, votes } = ctx;
  if (decision !== 'AUTONOMOUS_EXECUTE') {
    if (emit) emit({ event: 'log', agent: 'response', type: 'warning', message: 'Containment pending human authorization — no autonomous actions executed.' });
    return { status: 'PENDING_APPROVAL', actions: [], summary: 'Awaiting human authorization.' };
  }
  const system = `You are the Incident Response Agent in the TUESDAY platform. Execute the SOAR containment playbook. Choose concrete containment actions based on the evidence and the target asset's criticality. Prefer network isolation, perimeter firewall blocking, credential revocation, and recovery steps.`;
  const user = [
    `ALERT: ${JSON.stringify(alert)}`,
    `AGENT VOTES: ${JSON.stringify(votes)}`,
    `Return ONLY JSON: {"status":"CONTAINED|PARTIAL","actions":[{"action":"HOST_ISOLATION|FW_BLOCK|CREDENTIAL_REVOKE|SESSION_TERMINATE|SHADOW_COPY_RESTORE","target":"<asset>","status":"EXECUTED","detail":"<detail>"}],"summary":"<one line>"}`
  ].join('\n');
  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    const actions = Array.isArray(out && out.actions) ? out.actions : [];
    let status = String(out && out.status || 'CONTAINED').toUpperCase();
    // The model sometimes returns PARTIAL/SUCCESS/EXECUTED — all mean actions were taken.
    if (/CONTAIN|PARTIAL|EXECUTED|SUCCESS|COMPLETE/.test(status)) status = 'CONTAINED';
    else status = 'PENDING_APPROVAL';
    return {
      status,
      actions: actions.slice(0, 5),
      summary: String(out && out.summary || 'Containment executed.')
    };
  } catch (e) {
    return rules.respond(alert, { decision });
  }
}

// --- compliance -----------------------------------------------------------------

async function comply(ctx, emit) {
  const system = `You are the Compliance & Audit Agent in the TUESDAY platform. Assess regulatory impact (GDPR Art 33, PCI-DSS, HIPAA) and record the audit trail.`;
  const user = [
    `ALERT: ${JSON.stringify(ctx.alert)}`,
    `OUTCOME: ${ctx.status}`,
    `Return ONLY JSON: {"frameworks":["GDPR Art 33","PCI-DSS"],"status":"COMPLIANT_LOGGED","summary":"<one line>"}`
  ].join('\n');
  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.1 });
    return {
      frameworks: Array.isArray(out && out.frameworks) ? out.frameworks : ['GDPR Art 33', 'PCI-DSS'],
      status: String((out && out.status) || 'COMPLIANT_LOGGED'),
      summary: String(out && out.summary || 'Audit trail sealed.')
    };
  } catch (e) {
    return rules.comply(ctx.alert);
  }
}

// --- coordinator final synthesis (predictions + playbook) --------------------------

async function synthesize(ctx, emit) {
  const { alert, killChainState, wasContained, votes, memoryHits } = ctx;
  const activeStages = Object.keys(killChainState);
  const system = `You are the SOC Coordinator finalizing an investigation in the TUESDAY platform. Based on the kill chain so far and episodic memory, predict the adversary's next moves and synthesize an adaptive playbook.`;
  const user = [
    `ALERT: ${JSON.stringify(alert)}`,
    `ACTIVE KILL CHAIN STAGES: ${JSON.stringify(activeStages)}`,
    `EPISODIC MEMORY HITS: ${JSON.stringify(memoryHits || [])}`,
    `CONTAINMENT RESULT: ${wasContained ? 'CONTAINED' : 'PENDING HUMAN APPROVAL'}`,
    `Return ONLY JSON: {"predictedTTPs":[{"id":"T1003.001","name":"<name>","probability":<0-100>,"preemptive":"<action>","reasoning":"<why>"}],"playbook":{"name":"<name>","steps":["STEP 1: ...","STEP 2: ..."],"confidence":<0-100>},"executiveSummary":"<2-3 sentences>"}`
  ].join('\n');
  try {
    const out = await llm.generateJSON({ system, user, temperature: 0.2 });
    const predictedTTPs = Array.isArray(out && out.predictedTTPs) ? out.predictedTTPs : rules.predict(alert, activeStages);
    const pb = (out && out.playbook) || rules.playbook(alert, wasContained, votes);
    return {
      predictedTTPs: predictedTTPs.slice(0, 4),
      playbook: {
        name: pb.name || 'AUTO-PB-ADAPTIVE',
        generatedAt: new Date().toISOString(),
        basedOn: alert.title,
        steps: Array.isArray(pb.steps) ? pb.steps : [],
        confidence: pb.confidence != null ? pb.confidence : 90,
        memoryAugmented: (memoryHits || []).length > 0
      },
      executiveSummary: String(out && out.executiveSummary || 'Investigation complete.')
    };
  } catch (e) {
    return {
      predictedTTPs: rules.predict(alert, activeStages),
      playbook: rules.playbook(alert, wasContained, votes),
      executiveSummary: 'Investigation complete.'
    };
  }
}

module.exports = { AGENTS, INVESTIGATION_AGENTS, decompose, investigate, approve, respond, comply, synthesize };
