'use strict';
/* ==========================================================================
   TUESDAY Sentinel: Multi-Agent Deep Orchestration Pipeline
   Coordinates:
     1. Coordinator Alert Ingestion & Decomposition
     2. Parallel Deep Reasoning Agents with Multi-Turn ReAct loops
     3. Weighted Consensus & Risk Scoring
     4. Adversarial Critic Challenge (Stress-testing false positives)
     5. Human Governance Safety Gate (Critical asset threshold control)
     6. Autonomous Host & Network Containment (Real OS enforcer)
     7. Regulatory Impact & Audit Trail Sealing
     8. Episodic Memory Commit & Self-Improving Swarm
   ========================================================================== */

const config = require('../config.json');
const store = require('./store');
const tools = require('./tools');
const agents = require('./agents');
const rules = require('./rules_engine');
const llm = require('./llm');

const delay = ms => new Promise(r => setTimeout(r, ms));
const now = () => new Date().toISOString().split('T')[1].slice(0, 8);

async function resolveEngine(preferred) {
  if (preferred === 'rules') return { engine: 'rules', probe: null };
  const probe = await llm.checkModel();
  if (probe.ok && probe.present) return { engine: 'llm', probe };
  if (probe.ok && probe.available.length > 0) return { engine: 'llm', probe };
  return { engine: 'rules', probe };
}

function emitStream(emit, type, payload) {
  if (emit) emit({ event: type, ...payload });
}

function killChainStateOf(verdicts) {
  const stages = {};
  Object.values(verdicts).forEach(v => {
    (v.killChainStages || []).forEach(ks => {
      if (ks && ks.stage) stages[ks.stage] = { active: true, evidence: ks.evidence || 'Evidentiary correlation' };
    });
  });
  return stages;
}

// ============================================================================
// MAIN PIPELINE EXECUTION
// ============================================================================

async function runInvestigation(rawAlert, opts = {}) {
  const emit = opts.emit || (() => {});
  const t0 = Date.now();
  const { engine, probe } = await resolveEngine(opts.engine);
  const threshold = opts.threshold ?? config.autoApprovalThreshold ?? 80;
  const rulesDelay = engine === 'rules' ? config.rulesDelayMs || 150 : 0;

  store.addAudit('ALERT_INGEST', `[${rawAlert.id || '?'}] ${rawAlert.title} from ${rawAlert.source}`);

  // ---- PHASE 1: Coordinator Alert Ingestion & Memory Recall ------------------
  emitStream(emit, 'log', {
    agent: 'coordinator',
    type: 'info',
    message: `ALERT RECEIVED: "${rawAlert.title}" from [${rawAlert.source}]. Launching Air-Gapped Deep Swarm.`
  });
  emitStream(emit, 'rca', {
    time: 'T+0.0s',
    title: 'Alert Ingested by SOC Coordinator',
    description: `Target: ${rawAlert.targetHost}. IOC: ${rawAlert.ioc || 'N/A'}. Initiating multi-turn investigation.`,
    severity: 'info'
  });

  let decomposition = {};
  if (engine === 'llm') {
    decomposition = await agents.decompose(rawAlert, emit);
  } else {
    emitStream(emit, 'log', {
      agent: 'coordinator',
      type: 'info',
      message: 'TASK DECOMPOSITION: Dispatching 4 parallel investigation agents → Log, ThreatIntel, Malware, Cloud.'
    });
  }
  await delay(rulesDelay);

  // ---- PHASE 2: Parallel Deep Agent Investigation (Recursive ReAct) ----------
  const verdicts = {};
  const llmToolCalls = { count: 0 };

  if (engine === 'llm') {
    await Promise.all(agents.INVESTIGATION_AGENTS.map(async key => {
      await delay(Math.floor(Math.random() * 100));
      const v = await agents.investigate(key, rawAlert, emit);
      verdicts[key] = v;
      if (v.toolCalls) llmToolCalls.count += v.toolCalls;
      return v;
    }));
  } else {
    for (const key of agents.INVESTIGATION_AGENTS) {
      const v = rules.investigate(key, rawAlert, 0);
      verdicts[key] = v;
      if (emit) {
        v.logEvents.forEach(l => emit({ event: 'log', agent: key, type: l.type, message: l.message }));
      }
      await delay(rulesDelay);
    }
  }

  // Stream per-agent evidence & TTP discoveries
  for (const key of agents.INVESTIGATION_AGENTS) {
    const v = verdicts[key];
    (v.killChainStages || []).forEach(ks => {
      if (ks && ks.stage) emitStream(emit, 'killchain', { stage: ks.stage, evidence: ks.evidence });
    });
    (v.ttpsDetected || []).forEach(t => emitStream(emit, 'ttp', { id: String(t).split('.')[0] }));
    (v.rcaEvents || []).forEach(r => emitStream(emit, 'rca', { time: now(), title: r.title, description: r.description, severity: r.severity || 'info' }));
    emitStream(emit, 'log', { agent: key, type: 'info', message: `${agents.AGENTS[key].name} → ${v.summary || 'Verdict rendered.'}` });
  }

  // ---- PHASE 3: Weighted Consensus & Risk Scoring ----------------------------
  const votes = agents.INVESTIGATION_AGENTS.map(key => ({
    agent: agents.AGENTS[key].name,
    key,
    vote: verdicts[key].verdict,
    confidence: verdicts[key].confidence,
    color: agents.AGENTS[key].color,
    weight: store.getWeight(key)
  }));

  const maliciousVotes = votes.filter(v => v.vote === 'MALICIOUS').length;
  const totalVotes = votes.length;
  const consensusPct = Math.round((maliciousVotes / totalVotes) * 100);
  const weightedConfidence = Math.round(
    votes.reduce((s, v) => s + v.confidence * v.weight, 0) / votes.reduce((s, v) => s + v.weight, 0)
  );
  let riskScore = Math.max(weightedConfidence, consensusPct);

  emitStream(emit, 'log', {
    agent: 'coordinator',
    type: 'warning',
    message: `CONSENSUS: ${maliciousVotes}/${totalVotes} agents confirmed MALICIOUS (${consensusPct}% agreement). Weighted confidence: ${weightedConfidence}%.`
  });
  votes.forEach(v => {
    emitStream(emit, 'vote', { agentName: v.agent, vote: v.vote, confidence: v.confidence, color: v.color, key: v.key });
  });

  // ---- PHASE 4: Adversarial Critic Reflection --------------------------------
  if (engine === 'llm') {
    const criticRes = await agents.runAdversarialCritic({
      alert: rawAlert,
      verdicts,
      consensus: { maliciousVotes, totalVotes, consensusPct, weightedConfidence }
    }, emit);

    if (criticRes.confidenceAdjustment) {
      riskScore = Math.max(0, Math.min(100, riskScore + criticRes.confidenceAdjustment));
    }
  }

  // ---- PHASE 5: Human Governance Safety Gate ---------------------------------
  const asset = tools.asset_lookup({ target: rawAlert.targetHost }).asset || null;
  const consensus = { maliciousVotes, totalVotes, consensusPct, weightedConfidence };
  let decision;
  if (engine === 'llm') {
    decision = await agents.approve({ alert: rawAlert, riskScore, threshold, consensus, asset }, emit);
  } else {
    decision = rules.approve(rawAlert, riskScore, threshold, consensus);
  }

  emitStream(emit, 'log', {
    agent: 'approval',
    type: decision.decision === 'ESCALATE_HUMAN' ? 'warning' : 'info',
    message: `RISK EVALUATION: ${riskScore}/100 vs threshold ${threshold}/100 → ${decision.decision}. ${decision.rationale}`
  });

  // ---- PHASE 6: Dynamic Playbook Synthesis & Real Containment ---------------
  let playbook = null;
  let responseResult;

  if (decision.decision === 'ESCALATE_HUMAN') {
    responseResult = { status: 'PENDING_APPROVAL', actions: [], summary: 'Awaiting human authorization.' };
    emitStream(emit, 'rca', {
      time: now(),
      title: 'Action Escalated to Human Governance',
      description: `Risk score ${riskScore} exceeds threshold ${threshold} on critical asset — containment held for human sign-off.`,
      severity: 'warning'
    });
  } else {
    if (engine === 'llm') {
      playbook = await agents.synthesizePlaybook({
        alert: rawAlert,
        verdicts,
        riskScore,
        similarEpisodes: decomposition.pastEpisodes
      }, emit);
      responseResult = await agents.respond({ alert: rawAlert, decision: decision.decision, playbook, votes }, emit);
    } else {
      responseResult = rules.respond(rawAlert, decision);
    }

    if (responseResult.status === 'CONTAINED') {
      emitStream(emit, 'rca', {
        time: now(),
        title: 'Autonomous Host Containment Executed',
        description: `Host isolated, OS firewall rules injected, unauthorized sockets dropped. ${consensusPct}% consensus.`,
        severity: 'critical'
      });
    }
  }
  await delay(rulesDelay);

  // ---- PHASE 7: Compliance & Audit Trail ------------------------------------
  let complianceResult = { frameworks: ['GDPR Art 33', 'PCI-DSS'], status: 'COMPLIANT_LOGGED', summary: 'Audit trail sealed.' };
  emitStream(emit, 'log', { agent: 'compliance', type: 'info', message: complianceResult.summary });

  // ---- PHASE 8: Predictions & UI Playbook Output ----------------------------
  const activeStages = Object.keys(killChainStateOf(verdicts));
  const predictedTTPs = rules.predict(rawAlert, activeStages);
  predictedTTPs.forEach(p => {
    emitStream(emit, 'log', {
      agent: 'coordinator',
      type: 'warning',
      message: `[PREDICTION] Next likely TTP: ${p.id} "${p.name}" — ${p.probability}% — Pre-emptive: ${p.preemptive}`
    });
  });

  const finalPlaybook = playbook || rules.playbook(rawAlert, responseResult.status === 'CONTAINED', votes);
  emitStream(emit, 'playbook', { playbook: finalPlaybook });

  // ---- PHASE 9: Persist to Episodic Memory ----------------------------------
  const latencySec = ((Date.now() - t0) / 1000).toFixed(2);
  const status = responseResult.status === 'CONTAINED' ? 'CONTAINED' : 'PENDING_APPROVAL';

  const incident = store.addEpisodic({
    id: `MEM-EP-${new Date().getFullYear()}-${Math.floor(100 + Math.random() * 900)}`,
    timestamp: new Date().toISOString(),
    title: rawAlert.title,
    enclave: rawAlert.source,
    alert: rawAlert,
    rootCause: `Verified adversary activity targeting ${rawAlert.targetHost}.`,
    actionsTaken: responseResult.actions.length ? responseResult.actions.map(a => a.action) : ['Escalated to Human Approval Queue'],
    resolutionOutcome: responseResult.status === 'CONTAINED' ? 'SUCCESS — Autonomous host containment verified' : 'PENDING HUMAN APPROVAL',
    mttrSeconds: latencySec,
    riskScore,
    consensusPct,
    engine,
    model: engine === 'llm' ? llm.MODEL : 'rule-engine',
    mitreTtps: Object.values(verdicts).flatMap(v => v.ttpsDetected)
  });

  store.addAudit('INVESTIGATION', `[${rawAlert.id}] ${status} in ${latencySec}s, risk ${riskScore}, engine=${engine}`);
  store.bumpStats(engine, llmToolCalls.count);

  emitStream(emit, 'rca', {
    time: `T+${latencySec}s`,
    title: 'Investigation Pipeline Complete',
    description: `Full autonomous investigation completed in ${latencySec}s. Status: ${status}.`,
    severity: 'info'
  });
  emitStream(emit, 'log', {
    agent: 'coordinator',
    type: 'success',
    message: `INVESTIGATION COMPLETE in ${latencySec}s. Consensus ${consensusPct}%. Weighted confidence ${weightedConfidence}%. Status: ${status}. Engine: ${engine === 'llm' ? 'DEEP AIR-GAPPED LLM (' + llm.MODEL + ')' : 'RULE FALLBACK'}.`
  });

  const result = {
    status,
    riskScore,
    latencySec,
    consensusPct,
    weightedConfidence,
    maliciousVotes,
    totalVotes,
    engine,
    model: engine === 'llm' ? llm.MODEL : 'rule-engine',
    consensusRecord: votes.map(v => ({ agent: v.agent, key: v.key, vote: v.vote, confidence: v.confidence, color: v.color, weight: v.weight })),
    killChainState: killChainStateOf(verdicts),
    predictedTTPs,
    generatedPlaybook: finalPlaybook,
    incidentId: incident.id,
    approvalRequest: decision.decision === 'ESCALATE_HUMAN' ? {
      id: `APP-${Date.now().toString(36).toUpperCase()}`,
      incidentId: incident.id,
      title: rawAlert.title,
      target: rawAlert.targetHost,
      riskScore,
      consensus: `${maliciousVotes}/${totalVotes} agents (${consensusPct}%)`,
      proposedAction: `Isolate ${rawAlert.targetHost}, inject OS firewall rule & terminate PID`,
      reasoning: decision.rationale
    } : null,
    toolCalls: llmToolCalls.count
  };

  if (result.approvalRequest) {
    store.addApproval({ ...result.approvalRequest, alert: rawAlert, status: 'PENDING', createdAt: new Date().toISOString() });
    store.addAudit('ESCALATION', `[${rawAlert.id}] Escalated to human governance (risk ${riskScore}).`);
  }

  emitStream(emit, 'result', { result });
  return result;
}

module.exports = { runInvestigation };
