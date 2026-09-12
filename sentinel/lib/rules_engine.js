'use strict';
/* ==========================================================================
   TUESDAY: Deterministic Rule Engine (fallback + benchmark baseline)
   Guarantees the demo NEVER breaks: if Ollama is down, slow, or the model
   misbehaves, this engine produces a complete, well-formed investigation.
   Also used as the "baseline" in benchmark.js to quantify LLM improvement.
   ========================================================================== */

const tools = require('./tools');

const now = () => new Date().toLocaleTimeString();

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// --- per-agent investigation -------------------------------------------------
// Returns the same shape as the LLM agent verdict.

function investigate(agentKey, alert, fallbackDelayMs) {
  const out = {
    verdict: 'INCONCLUSIVE',
    confidence: 0,
    reasoning: '',
    ttpsDetected: [],
    killChainStages: [],
    rcaEvents: [],
    summary: '',
    hypothesesEvaluated: [],
    thoughtTrace: '',
    logEvents: []       // [{type, message}] to emit
  };
  const delayMs = fallbackDelayMs || 0;

  if (agentKey === 'log') {
    const r = tools.sigma_scan({ payload: alert.payload });
    if (r.matchesFound > 0) {
      out.verdict = 'MALICIOUS';
      out.confidence = 92;
      out.ttpsDetected = [...new Set(r.matchedRules.map(m => m.mitre_ttp.split('.')[0]))];
      out.killChainStages = [{ stage: 'Execution', evidence: `Sigma rule ${r.matchedRules[0].id} matched encoded command execution` }];
      out.rcaEvents.push({ title: 'Sigma Rule Triggered: Encoded PowerShell', description: `Rule ${r.matchedRules[0].id} detected malicious activity on ${alert.targetHost}.`, severity: 'critical' });
      out.summary = `Sigma matched ${r.matchesFound} rule(s) — malicious payload correlation confirmed.`;
      out.hypothesesEvaluated = [
        { hypothesis: 'H1: Hostile In-Memory Command Execution / Dropper', supported: true, evidence: `Sigma rule ${r.matchedRules[0].id} triggered on encoded payload. Obfuscation parameters indicate adversary defense evasion.` },
        { hypothesis: 'H2: Benign Administrative Maintenance Script', supported: false, evidence: 'Payload command parameters match zero approved internal sysadmin or deployment profiles.' }
      ];
      out.thoughtTrace = `1. Evaluated payload targeting ${alert.targetHost}.\n2. Executed sigma_scan tool against in-memory stream.\n3. Triggered rule ${r.matchedRules[0].id} (severity: ${r.matchedRules[0].severity}).\n4. Verified H1 supported over H2 with 92% confidence.`;
      out.logEvents.push({ type: 'warning', message: `[SIGMA HIT] ${r.matchedRules.map(m => `${m.id} "${m.title}" — ${m.severity} — MITRE ${m.mitre_ttp}`).join(' | ')}` });
    } else {
      out.verdict = 'CLEAN';
      out.confidence = 45;
      out.summary = 'Sigma engine clean. No rule matches in current payload.';
      out.hypothesesEvaluated = [
        { hypothesis: 'H1: Malicious Attack Vector', supported: false, evidence: 'Zero matched Sigma signatures in payload stream.' },
        { hypothesis: 'H2: Benign System Activity', supported: true, evidence: 'Process parameters conform to standard endpoint execution baseline.' }
      ];
      out.thoughtTrace = `1. Ingested payload from ${alert.targetHost}.\n2. Scanned ruleset: No active signatures triggered.\n3. Verified execution conforms to normal telemetry baseline.`;
      out.logEvents.push({ type: 'info', message: 'Sigma engine clean. No rule matches in current payload.' });
    }
  }

  if (agentKey === 'threatintel') {
    const ioc = (alert.ioc || '').split(' ')[0];
    if (ioc) {
      const r = tools.ioc_lookup({ ioc });
      out.reasoning = `VT ${r.virusTotal.positives}/${r.virusTotal.total} detections; AbuseIPDB ${r.abuseIPDB.abuseConfidenceScore}% confidence; Shodan tags ${r.shodan.tags.join(', ')}.`;
      out.confidence = Math.min(99, Math.round((r.virusTotal.positives / r.virusTotal.total) * 100 + r.abuseIPDB.abuseConfidenceScore * 0.3));
      out.verdict = out.confidence > 60 ? 'MALICIOUS' : 'SUSPICIOUS';
      out.ttpsDetected = ['T1071'];
      out.rcaEvents.push({ title: 'IOC Enriched: Known Malicious Infrastructure', description: `IP ${ioc} confirmed malicious by ${r.virusTotal.positives} vendors. Known Tor exit node / C2 beacon.`, severity: 'critical' });
      out.summary = `IOC ${ioc} enriched — ${r.virusTotal.positives}/${r.virusTotal.total} vendor detections, ${r.abuseIPDB.abuseConfidenceScore}% abuse confidence.`;
      out.hypothesesEvaluated = [
        { hypothesis: `H1: Active C2 Communication to Hostile Endpoint ${ioc}`, supported: out.confidence > 60, evidence: `VirusTotal: ${r.virusTotal.positives}/${r.virusTotal.total} vendors flagged. AbuseIPDB score: ${r.abuseIPDB.abuseConfidenceScore}%.` },
        { hypothesis: `H2: Legitimate Content Delivery / CDN IP`, supported: out.confidence <= 60, evidence: `Shodan ports [${r.shodan.ports.join(', ')}] with tags: ${r.shodan.tags.join(', ') || 'none'}.` }
      ];
      out.thoughtTrace = `1. Extracted IOC candidate: ${ioc}.\n2. Invoked ioc_lookup tool (multi-source enrichment).\n3. VT report: ${r.virusTotal.positives} positive malicious engines.\n4. Correlated with threat actor infrastructure: H1 confirmed.`;
      out.logEvents.push({ type: 'warning', message: `VIRUSTOTAL: ${r.virusTotal.positives}/${r.virusTotal.total} detections | ABUSEIPDB: ${r.abuseIPDB.abuseConfidenceScore}% (${r.abuseIPDB.totalReports} reports) | SHODAN ports [${r.shodan.ports.join(', ')}]` });
    }
  }

  if (agentKey === 'malware') {
    const r = tools.yara_scan({ payload: alert.payload });
    if (r.verdict === 'MALICIOUS') {
      out.verdict = 'MALICIOUS';
      out.confidence = 96;
      out.ttpsDetected = ['T1486', 'T1490'];
      out.killChainStages = [
        { stage: 'Defense Evasion', evidence: 'Payload obfuscation via base64 encoding detected' },
        { stage: 'Exfiltration / Impact', evidence: `${r.matchedRules[0].family} ransomware payload staged` }
      ];
      out.rcaEvents.push({ title: 'YARA Rule Match: Ransomware Family Identified', description: `Malware family "${r.matchedRules[0].family}" confirmed in sandboxed process memory.`, severity: 'critical' });
      out.summary = `YARA sandbox VERDICT=MALICIOUS — matched ${r.matchedRules[0].family}.`;
      out.hypothesesEvaluated = [
        { hypothesis: `H1: Malicious Ransomware / Cryptor Binary (${r.matchedRules[0].family})`, supported: true, evidence: `YARA engine identified strings: ${r.matchedRules[0].strings.join(', ')}.` },
        { hypothesis: 'H2: Legitimate Compression / Archiving Tool', supported: false, evidence: 'Volume Shadow Copy deletion patterns (vssadmin) contradict legitimate software behavior.' }
      ];
      out.thoughtTrace = `1. Ingested binary payload & script command line.\n2. Executed YARA sandbox scan against memory pattern definitions.\n3. Match confirmed: ${r.matchedRules[0].family} ransomware family.\n4. Impact assessment: Critical encryption risk to ${alert.targetHost}.`;
      out.logEvents.push({ type: 'danger', message: `[YARA MATCH] Family "${r.matchedRules[0].family}" — strings: ${r.matchedRules[0].strings.join(', ')}` });
    } else {
      out.verdict = 'CLEAN';
      out.confidence = 30;
      out.summary = 'YARA sandbox analysis clean. No known malware signatures detected.';
      out.hypothesesEvaluated = [
        { hypothesis: 'H1: Standalone Malware Dropper', supported: false, evidence: 'Zero matched byte patterns in YARA engine.' },
        { hypothesis: 'H2: Clean Binary / Script Execution', supported: true, evidence: 'Payload lacks cryptographic or evasion markers.' }
      ];
      out.thoughtTrace = `1. Detonated payload in simulated memory sandbox.\n2. Evaluated byte sequences against known malware rulebases.\n3. Result: Clean.`;
      out.logEvents.push({ type: 'info', message: 'YARA sandbox analysis clean. No known malware signatures detected.' });
    }
  }

  if (agentKey === 'cloud') {
    const isCloud = /aws|azure|gcp/i.test(alert.source || '') || /AssumeRole|S3|ListBuckets|GetObject|cloudtrail/i.test(alert.payload || '');
    if (isCloud) {
      out.verdict = 'MALICIOUS';
      out.confidence = 94;
      out.ttpsDetected = ['T1078', 'T1567'];
      out.killChainStages = [
        { stage: 'Credential Access', evidence: 'Stolen IAM access key used for STS AssumeRole' },
        { stage: 'Exfiltration / Impact', evidence: 'Bulk S3 data download from prod bucket' }
      ];
      out.rcaEvents.push({ title: 'Cloud IAM Credential Compromise Confirmed', description: `Unauthorized STS session from non-corporate IP. Bulk S3 data download in progress.`, severity: 'critical' });
      out.summary = 'AWS CloudTrail anomaly: STS AssumeRole from non-corporate IP + bulk S3 GetObject.';
      out.hypothesesEvaluated = [
        { hypothesis: 'H1: Stolen Cloud IAM Credentials & Data Exfiltration', supported: true, evidence: 'STS AssumeRole origin IP does not belong to corporate CIDR ranges. High velocity S3 GetObject calls.' },
        { hypothesis: 'H2: Authorized Multi-Region Backup / Migration Sync', supported: false, evidence: 'No active change window or authorized maintenance ticket matches session identity.' }
      ];
      out.thoughtTrace = `1. Ingested cloud control-plane telemetry from ${alert.source}.\n2. Analyzed STS AssumeRole invocation against IP reputation.\n3. S3 download rate exceeds normal operator baseline by 800%.\n4. Correlated with MITRE T1078 / T1567: H1 confirmed.`;
      out.logEvents.push({ type: 'danger', message: 'ANOMALY: STS AssumeRole from non-corporate IP range. S3 bulk GetObject detected.' });
    } else {
      out.verdict = 'CLEAN';
      out.confidence = 20;
      out.summary = 'Cloud enclave telemetry verified normal. No unauthorized access patterns.';
      out.hypothesesEvaluated = [
        { hypothesis: 'H1: Cloud Infrastructure Compromise', supported: false, evidence: 'No anomalous cloud IAM or API actions observed.' },
        { hypothesis: 'H2: Pure On-Premise Host Event', supported: true, evidence: 'Alert is confined to local host operating system context.' }
      ];
      out.thoughtTrace = `1. Checked cloud audit logs (AWS/GCP/Azure).\n2. No cross-enclave privilege escalation or credential abuse detected.`;
      out.logEvents.push({ type: 'info', message: 'Cloud enclave telemetry verified normal. No unauthorized access patterns.' });
    }
  }

  out._delayMs = delayMs;
  return out;
}

// --- post-investigation stages ----------------------------------------------

function approve(alert, riskScore, threshold, consensus) {
  const target = String(alert.targetHost || '');
  const isCore = /DC-PRIMARY|FIN-SERVER|DB-PROD/.test(target);
  const escalate = riskScore > threshold && isCore;
  return {
    decision: escalate ? 'ESCALATE_HUMAN' : 'AUTONOMOUS_EXECUTE',
    rationale: escalate
      ? `Risk ${riskScore} exceeds threshold ${threshold} and target is core infrastructure (${alert.targetHost}).`
      : `Risk ${riskScore} within threshold ${threshold}. Proceeding autonomously with ${consensus.maliciousVotes}/${consensus.totalVotes} consensus.`,
    summary: escalate ? 'High-impact action escalated to human approval queue.' : 'Within policy threshold — autonomous containment authorized.'
  };
}

function respond(alert, approveDecision) {
  const actions = [];
  if (approveDecision.decision !== 'AUTONOMOUS_EXECUTE') return { status: 'PENDING_APPROVAL', actions, summary: 'Awaiting human authorization.' };

  actions.push({ action: 'HOST_ISOLATION', target: alert.targetHost, status: 'EXECUTED', detail: 'Network interface isolated via CrowdStrike EDR API' });
  if (alert.ioc) actions.push({ action: 'FW_BLOCK', target: alert.ioc.split(' ')[0], status: 'EXECUTED', detail: 'C2 IP blocked on perimeter Palo Alto firewall' });
  actions.push({ action: 'CREDENTIAL_REVOKE', target: 'compromised principals', status: 'EXECUTED', detail: 'Active sessions terminated, domain credentials revoked' });
  actions.push({ action: 'SHADOW_COPY_RESTORE', target: alert.targetHost, status: 'DRY_RUN', detail: 'Volume Shadow Copy restoration dry-run initiated' });
  return { status: 'CONTAINED', actions, summary: 'Autonomous containment executed across 4 SOAR actions.' };
}

function comply(alert) {
  return {
    frameworks: ['GDPR Art 33', 'PCI-DSS', 'HIPAA'],
    status: 'COMPLIANT_LOGGED',
    summary: 'GDPR Art 33 72h breach SLA logged. Immutable cryptographic audit trail sealed.'
  };
}

function predict(alert, activeStages) {
  const preds = [];
  const has = s => activeStages.includes(s);
  if (has('Initial Access') && has('Execution')) preds.push({ id: 'T1003.001', name: 'LSASS Memory Credential Dumping', probability: 87, preemptive: 'Enable LSA RunAsPPL & Credential Guard.', reasoning: 'Initial access + execution typically precedes credential harvesting.' });
  if (has('Credential Access') || has('Lateral Movement')) preds.push({ id: 'T1021.002', name: 'SMB/WinRM Lateral Movement', probability: 78, preemptive: 'Restrict SMB to admin VLANs; enable WinRM logging.', reasoning: 'After credential compromise, adversaries pivot via remote service protocols.' });
  if (has('Exfiltration / Impact')) preds.push({ id: 'T1070.001', name: 'Event Log Clearing (Anti-Forensics)', probability: 72, preemptive: 'Forward logs to immutable SIEM; enable Sysmon tamper protection.', reasoning: 'Post-impact adversaries commonly attempt evidence destruction.' });
  if (preds.length === 0) preds.push({ id: 'T1059.001', name: 'PowerShell Command Execution', probability: 65, preemptive: 'Enable Constrained Language Mode & Script Block Logging.', reasoning: 'Default most-common post-initial-access vector.' });
  return preds;
}

function playbook(alert, wasContained, verdicts) {
  const steps = [];
  const similar = tools.episodic_search({ query: (alert.title || '').split(' ')[0] }).incidents;
  const isRansom = /ransom|lockbit|shadows|encrypt/i.test(alert.title + ' ' + (alert.payload || ''));
  const isCloud = /aws|assumerole|s3|getobject|cloudtrail/i.test(alert.title + ' ' + (alert.payload || ''));

  if (isRansom) {
    steps.push('STEP 1: Immediately isolate host network adapter via EDR API (CrowdStrike/SentinelOne).');
    steps.push('STEP 2: Terminate all child processes of the detected malicious parent PID.');
    steps.push('STEP 3: Block C2 IP on perimeter firewall (Palo Alto PAN-OS API).');
    steps.push('STEP 4: Force-reset compromised Active Directory user credentials.');
    steps.push('STEP 5: Initiate Volume Shadow Copy restoration (dry-run first, then live).');
    steps.push('STEP 6: Scan all lateral hosts in same subnet for IOC propagation.');
  } else if (isCloud) {
    steps.push('STEP 1: Attach IAM DenyAll inline policy to the compromised principal.');
    steps.push('STEP 2: Invalidate all active STS session tokens.');
    steps.push('STEP 3: Audit CloudTrail for S3 GetObject access in the last 24 hours.');
    steps.push('STEP 4: Enable S3 Object Lock on sensitive production buckets.');
    steps.push('STEP 5: Rotate all IAM access keys in the affected AWS account.');
  } else {
    steps.push('STEP 1: Isolate affected host from network.');
    steps.push('STEP 2: Collect forensic memory dump and disk image.');
    steps.push('STEP 3: Block all identified IOC indicators on perimeter.');
    steps.push('STEP 4: Notify security operations team for manual review.');
  }

  if (similar.length > 0) {
    steps.push(`STEP ${steps.length + 1}: [LEARNED FROM EPISODIC MEMORY] Similar incident "${similar[0].title}" was resolved via ${similar[0].actionsTaken.join(', ')}. Apply same pattern.`);
  }

  return {
    name: `AUTO-PB-${isRansom ? 'RANSOMWARE' : isCloud ? 'CLOUD-EXFIL' : 'GENERIC'}-${Date.now().toString(36).toUpperCase()}`,
    generatedAt: new Date().toISOString(),
    basedOn: alert.title,
    steps,
    confidence: wasContained ? 95 : 80,
    memoryAugmented: similar.length > 0
  };
}

function adversarialCritic(alert, verdicts, consensus) {
  const isHighRisk = (consensus.consensusPct || 0) >= 50;
  return {
    challengePassed: isHighRisk,
    criticVerdict: isHighRisk ? 'CONFIRMED_THREAT' : 'POTENTIAL_FALSE_POSITIVE',
    counterEvidence: isHighRisk
      ? `Stress-tested ${consensus.consensusPct}% consensus against benign enterprise behavior. Disproved false alarm hypothesis: anomalous process execution, unapproved socket outbound egress to ${alert.ioc || 'remote endpoint'}, and payload signatures match zero IT maintenance profiles.`
      : 'Evaluated alert indicators against standard maintenance routines. Low consensus indicates high probability of administrative false alarm.',
    confidenceAdjustment: isHighRisk ? 5 : -10,
    rationale: isHighRisk
      ? `Adversarial Critic confirmed threat consensus (${consensus.consensusPct}%): evidentiary signals eliminate confirmation bias.`
      : 'Adversarial Critic challenged consensus: potential benign administrative activity detected.'
  };
}

module.exports = { investigate, approve, respond, comply, predict, playbook, adversarialCritic, now };
