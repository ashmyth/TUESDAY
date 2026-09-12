/* ==========================================================================
   TUESDAY: Multi-Agent Swarm v3 — Agentic Engine
   Backend (Node + Ollama) drives real LLM agents over SSE with a live
   reasoning stream. If the backend or model is unavailable, the on-device
   deterministic pipeline keeps the demo alive.
   ========================================================================== */

// ---- Backend connectivity client -----------------------------------------
window.TuesdayBackend = {
    status: { ok: false, engine: 'offline', model: null, checkedAt: 0 },
    async refresh(force) {
        if (!force && this.status.ok && Date.now() - this.status.checkedAt < 5000) return this.status;
        try {
            const res = await fetch('/api/status', { signal: AbortSignal.timeout(4000) });
            if (!res.ok) throw new Error('status ' + res.status);
            this.status = { ...(await res.json()), ok: true, checkedAt: Date.now() };
        } catch (e) {
            this.status = { ok: false, engine: 'offline', model: null, checkedAt: Date.now() };
        }
        return this.status;
    }
};

class SOCAgentSwarm {
    constructor() {
        this.agents = {
            coordinator: { id: 'agent-coord', name: 'SOC Coordinator', role: 'Swarm Orchestration & Task Decomposition', icon: 'fa-sitemap', color: '#3E7A84', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            log:         { id: 'agent-log', name: 'Log Analysis', role: 'SIEM Correlation & Sigma Rules Engine', icon: 'fa-list-check', color: '#4A8CA8', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            threatintel: { id: 'agent-intel', name: 'Threat Intelligence', role: 'IOC Enrichment (VT, AbuseIPDB, Shodan, MISP)', icon: 'fa-globe', color: '#B08C9E', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            malware:     { id: 'agent-malware', name: 'Malware Sandbox', role: 'YARA + Behavioral Sandbox Analysis', icon: 'fa-bug', color: '#EEA4A5', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            cloud:       { id: 'agent-cloud', name: 'Cloud Security', role: 'AWS/Azure IAM & CSPM Posture Audit', icon: 'fa-cloud', color: '#7FB3BB', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            response:    { id: 'agent-response', name: 'Incident Response', role: 'Autonomous Containment & SOAR Playbooks', icon: 'fa-bolt', color: '#FD4040', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            compliance:  { id: 'agent-compliance', name: 'Compliance Audit', role: 'Regulatory Impact & Cryptographic Audit Trail', icon: 'fa-scale-balanced', color: '#C97A7C', status: 'IDLE', confidence: 0, vote: null, logs: [] },
            approval:    { id: 'agent-approval', name: 'Human Governance', role: 'Risk Threshold Gate & Override Control', icon: 'fa-user-shield', color: '#3E7A84', status: 'IDLE', confidence: 0, vote: null, logs: [] }
        };

        this.busListeners = [];
        this.rcaTimeline = [];       // Root Cause Analysis events
        this.killChainState = {};    // Kill chain stage activations
        this.consensusRecord = [];   // Agent negotiation votes
        this.predictedTTPs = [];     // Threat prediction results
        this.generatedPlaybook = null; // Autonomous playbook
    }

    onLogMessage(callback) {
        this.busListeners.push(callback);
    }

    emitLog(agentKey, message, type = 'info') {
        const agent = this.agents[agentKey];
        if (agent) {
            const timestamp = new Date().toLocaleTimeString();
            const formattedLog = `[${timestamp}] [${agent.name}]: ${message}`;
            agent.logs.push({ timestamp, message, type });
            this.busListeners.forEach(cb => cb(agentKey, formattedLog, type));
        }
    }

    addRCAEvent(time, title, description, severity = 'info') {
        this.rcaTimeline.push({ time, title, description, severity });
    }

    activateKillChainStage(stage, evidence) {
        this.killChainState[stage] = { active: true, evidence, timestamp: new Date().toLocaleTimeString() };
    }

    // ===========================================================
    // CORE: Agentic Investigation Entry Point
    // Streams the real LLM swarm from the backend; falls back to the
    // on-device deterministic pipeline if the backend is unreachable.
    // ===========================================================
    async processIncidentAlert(rawAlert, opts = {}) {
        this.resetAll();
        await window.TuesdayBackend.refresh();

        if (window.TuesdayBackend.status.ok) {
            try {
                const result = await this.runBackendInvestigation(rawAlert, opts);
                return result;
            } catch (e) {
                this.emitLog('coordinator', `BACKEND STREAM FAILURE: ${e.message}. Switching to on-device rule engine.`, 'danger');
            }
        }
        return this.runRulesFallback(rawAlert);
    }

    // Streams the investigation over SSE from the Node backend.
    runBackendInvestigation(alert, opts = {}) {
        const self = this;
        return new Promise((resolve, reject) => {
            let settled = false;
            const done = (v) => { if (!settled) { settled = true; resolve(v); } };
            const fail = (e) => { if (!settled) { settled = true; reject(e); } };

            fetch('/api/incident/stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    alert,
                    threshold: opts.threshold ?? (window.AppController?.getAutoThreshold?.() || 80)
                })
            }).then(async (res) => {
                if (!res.ok || !res.body) throw new Error('HTTP ' + res.status);
                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                while (true) {
                    const { done: d, value } = await reader.read();
                    if (d) break;
                    buffer += decoder.decode(value, { stream: true });
                    let idx;
                    while ((idx = buffer.indexOf('\n\n')) !== -1) {
                        const chunk = buffer.slice(0, idx);
                        buffer = buffer.slice(idx + 2);
                        self.applySSEEvent(chunk);
                    }
                }
                if (buffer.trim()) self.applySSEEvent(buffer);
            }).then(() => {
                if (self._lastBackendResult) done(self._lastBackendResult);
                else fail(new Error('stream ended without a result event'));
            }).catch(e => fail(e));
        });
    }

    // Streams an approved escalation's containment execution from the backend.
    // Returns a promise resolving when the SSE stream completes.
    runApprovalExecution(id) {
        const self = this;
        return new Promise((resolve, reject) => {
            fetch('/api/incident/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id })
            }).then(async (res) => {
                if (!res.ok || !res.body) throw new Error('HTTP ' + res.status);
                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                while (true) {
                    const { done: d, value } = await reader.read();
                    if (d) break;
                    buffer += decoder.decode(value, { stream: true });
                    let idx;
                    while ((idx = buffer.indexOf('\n\n')) !== -1) {
                        const chunk = buffer.slice(0, idx);
                        buffer = buffer.slice(idx + 2);
                        self.applySSEEvent(chunk);
                    }
                }
                if (buffer.trim()) self.applySSEEvent(buffer);
            }).then(resolve).catch(reject);
        });
    }

    // Rejects a pending escalation in the backend approval queue.
    async rejectApproval(id, reason) {
        try {
            const res = await fetch('/api/incident/reject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, reason })
            });
            return res.ok;
        } catch (e) {
            return false;
        }
    }

    // Applies a single SSE event frame to swarm state (terminal + panels).
    applySSEEvent(chunk) {
        let event = null;
        const dataLines = [];
        for (const line of chunk.split('\n')) {
            if (line.startsWith('event:')) event = line.slice(6).trim();
            else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
            else if (line.trim() && !line.startsWith(':')) dataLines.push(line.trim());
        }
        if (!event || dataLines.length === 0) return;
        let payload;
        try { payload = JSON.parse(dataLines.join('\n')); } catch (e) { return; }

        switch (event) {
            case 'log':
                this.emitLog(payload.agent, payload.message, payload.type || 'info');
                break;
            case 'rca':
                this.addRCAEvent(payload.time, payload.title, payload.description, payload.severity || 'info');
                break;
            case 'killchain':
                this.activateKillChainStage(payload.stage, payload.evidence);
                break;
            case 'ttp':
                if (typeof MitreEngine !== 'undefined') MitreEngine.flagTTP(payload.id);
                break;
            case 'vote':
                this.consensusRecord.push({ agent: payload.agentName, vote: payload.vote, confidence: payload.confidence, color: payload.color, key: payload.key });
                break;
            case 'playbook':
                this.generatedPlaybook = payload.playbook;
                break;
            case 'result':
                this.applyBackendResult(payload.result);
                break;
            case 'error':
                this.emitLog('coordinator', `ENGINE ERROR: ${payload.message}`, 'danger');
                break;
            default:
                break;
        }
    }

    applyBackendResult(result) {
        this._lastBackendResult = result;
        if (result.rcaTimeline) this.rcaTimeline = result.rcaTimeline;
        if (result.killChainState) this.killChainState = result.killChainState;
        if (result.consensusRecord) this.consensusRecord = result.consensusRecord;
        if (result.predictedTTPs) this.predictedTTPs = result.predictedTTPs;
        if (result.generatedPlaybook) this.generatedPlaybook = result.generatedPlaybook;

        if (result.agents) {
            Object.keys(result.agents).forEach(k => {
                if (this.agents[k]) {
                    this.agents[k].status = result.agents[k].status || 'COMPLETED';
                    this.agents[k].confidence = result.agents[k].confidence || 0;
                    this.agents[k].vote = result.agents[k].vote ?? null;
                }
            });
        }
        if (result.approvalRequest && window.AppController) {
            window.AppController.addApprovalRequest({ ...result.approvalRequest });
        }
    }

    // ===========================================================
    // ON-DEVICE FALLBACK: Deterministic Pipeline v2
    // ===========================================================
    async runRulesFallback(rawAlert) {
        const startTime = performance.now();
        this.resetAll();

        const autoThreshold = window.AppController?.getAutoThreshold?.() || 80;

        // -------------------------------------------------------
        // PHASE 1: COORDINATOR — Task Decomposition
        // -------------------------------------------------------
        this.agents.coordinator.status = 'DECOMPOSING';
        this.agents.coordinator.confidence = 95;
        this.emitLog('coordinator', `ALERT RECEIVED: "${rawAlert.title}" from [${rawAlert.source}]. Initiating autonomous multi-agent investigation pipeline.`, 'info');
        await this.delay(300);

        this.emitLog('coordinator', `TASK DECOMPOSITION: Dispatching 5 parallel sub-tasks → Log Analysis, Threat Intel, Malware Sandbox, Cloud Audit, Compliance Check.`, 'info');
        this.addRCAEvent('T+0.0s', 'Alert Ingested by SOC Coordinator', `SIEM event "${rawAlert.title}" received from ${rawAlert.source}. Target: ${rawAlert.targetHost}.`, 'info');

        await this.delay(300);

        // -------------------------------------------------------
        // PHASE 2: LOG ANALYSIS — Sigma Correlation
        // -------------------------------------------------------
        this.agents.log.status = 'ANALYZING';
        this.emitLog('log', `Evaluating payload against ${SOCTools.sigmaEngine.rules.length} active Sigma correlation rules...`, 'info');
        const sigmaResult = SOCTools.sigmaEngine.scanLog(rawAlert.payload);
        
        let logConfidence = 40;
        if (sigmaResult.matchesFound > 0) {
            logConfidence = 92;
            sigmaResult.matchedRules.forEach(r => {
                this.emitLog('log', `[SIGMA HIT] Rule ${r.id}: "${r.title}" — Severity: ${r.severity} — MITRE: ${r.mitre_ttp}`, 'warning');
                MitreEngine.flagTTP(r.mitre_ttp.split('.')[0]);

                // Kill Chain: Execution stage
                this.activateKillChainStage('Execution', `Sigma rule ${r.id} matched encoded PowerShell execution`);
            });

            this.addRCAEvent('T+0.3s', 'Sigma Rule Triggered: Encoded PowerShell', `Rule SIGMA-2026-001 detected base64 encoded command execution on ${rawAlert.targetHost}.`, 'critical');
            this.activateKillChainStage('Initial Access', 'Spearphishing payload opened by user');
        } else {
            this.emitLog('log', `Sigma engine clean. No rule matches in current payload.`, 'info');
        }
        this.agents.log.confidence = logConfidence;
        this.agents.log.vote = logConfidence > 70 ? 'MALICIOUS' : 'BENIGN';

        await this.delay(400);

        // -------------------------------------------------------
        // PHASE 3: THREAT INTELLIGENCE — VT, AbuseIPDB, Shodan, MISP
        // -------------------------------------------------------
        this.agents.threatintel.status = 'ENRICHING';
        let vtResult = null;
        let abuseResult = null;
        let intelConfidence = 30;

        if (rawAlert.ioc) {
            const iocIp = rawAlert.ioc.split(' ')[0];
            this.emitLog('threatintel', `Enriching IOC [${iocIp}] across 4 threat intelligence platforms...`, 'info');

            const cached = SOCMemory.getIocCache(rawAlert.ioc);
            if (cached) {
                this.emitLog('threatintel', `MEMORY HIT: IOC [${iocIp}] found in Semantic Memory cache. Skipping external API calls.`, 'info');
                vtResult = cached.data.vt;
                abuseResult = cached.data.abuse;
            } else {
                vtResult = await SOCTools.virusTotal.queryIp(iocIp);
                abuseResult = await SOCTools.abuseIPDB.checkIp(iocIp);
                const shodanResult = await SOCTools.shodan.scanHost(iocIp);
                const mispResult = await SOCTools.misp.searchAttributes(iocIp);

                SOCMemory.cacheIoc(rawAlert.ioc, { vt: vtResult, abuse: abuseResult, shodan: shodanResult, misp: mispResult });

                this.emitLog('threatintel', `SHODAN: Ports [${shodanResult.ports.join(', ')}], Tags: [${shodanResult.tags.join(', ')}], CVEs: ${shodanResult.openVulnerabilities.length > 0 ? shodanResult.openVulnerabilities.join(', ') : 'None'}`, 'info');
                this.emitLog('threatintel', `MISP: Threat Actor "${mispResult.threat_actor}" linked to campaign "${mispResult.related_campaigns[0]}".`, 'warning');
            }

            this.emitLog('threatintel', `VIRUSTOTAL: ${vtResult.positives}/${vtResult.total} detections (Reputation: ${vtResult.reputation}). Categories: [${vtResult.categories.join(', ')}].`, 'warning');
            this.emitLog('threatintel', `ABUSEIPDB: Confidence ${abuseResult.abuseConfidenceScore}% (${abuseResult.totalReports} reports, Country: ${abuseResult.countryCode}).`, 'warning');

            intelConfidence = Math.min(99, Math.round((vtResult.positives / vtResult.total) * 100 + abuseResult.abuseConfidenceScore * 0.3));

            this.addRCAEvent('T+0.7s', 'IOC Enriched: Known Malicious Infrastructure', `IP ${iocIp} confirmed malicious by ${vtResult.positives} vendors. Known Tor exit node / C2 beacon.`, 'critical');
        }
        this.agents.threatintel.confidence = intelConfidence;
        this.agents.threatintel.vote = intelConfidence > 60 ? 'MALICIOUS' : 'SUSPICIOUS';

        await this.delay(400);

        // -------------------------------------------------------
        // PHASE 4: MALWARE SANDBOX — YARA & Hash Analysis
        // -------------------------------------------------------
        this.agents.malware.status = 'SCANNING';
        this.emitLog('malware', `Detonating payload in sandboxed environment. Running YARA memory scanner...`, 'info');
        const yaraVerdict = SOCTools.yaraEngine.scanPayload(rawAlert.payload);
        
        let malwareConfidence = 25;
        if (yaraVerdict.verdict === 'MALICIOUS') {
            malwareConfidence = 96;
            yaraVerdict.matchedRules.forEach(r => {
                this.emitLog('malware', `[YARA MATCH] Family: "${r.family}" — Matched strings: ${r.strings.join(', ')}`, 'danger');
            });
            MitreEngine.flagTTP('T1486');
            MitreEngine.flagTTP('T1490');

            this.activateKillChainStage('Defense Evasion', 'Payload obfuscation via base64 encoding detected');
            this.activateKillChainStage('Exfiltration / Impact', `${yaraVerdict.matchedRules[0].family} ransomware payload staged`);

            this.addRCAEvent('T+1.1s', 'YARA Rule Match: Ransomware Family Identified', `Malware family "${yaraVerdict.matchedRules[0].family}" confirmed in sandboxed process memory.`, 'critical');
        } else {
            this.emitLog('malware', `YARA sandbox analysis clean. No known malware signatures detected.`, 'info');
        }
        this.agents.malware.confidence = malwareConfidence;
        this.agents.malware.vote = malwareConfidence > 60 ? 'MALICIOUS' : 'CLEAN';

        await this.delay(400);

        // -------------------------------------------------------
        // PHASE 5: CLOUD SECURITY — AWS/Azure Audit
        // -------------------------------------------------------
        this.agents.cloud.status = 'AUDITING';
        let cloudConfidence = 20;

        if (rawAlert.source.includes('AWS') || rawAlert.payload.includes('AssumeRole') || rawAlert.payload.includes('S3')) {
            this.emitLog('cloud', `AWS CloudTrail event correlation triggered. Auditing STS, IAM, and S3 data plane...`, 'warning');
            this.emitLog('cloud', `ANOMALY: STS AssumeRole from non-corporate IP range. S3 bulk GetObject detected.`, 'danger');
            cloudConfidence = 94;
            MitreEngine.flagTTP('T1078');
            MitreEngine.flagTTP('T1567');

            this.activateKillChainStage('Credential Access', 'Stolen IAM access key used for STS AssumeRole');
            this.activateKillChainStage('Exfiltration / Impact', 'Bulk S3 data download from prod bucket');

            this.addRCAEvent('T+1.5s', 'Cloud IAM Credential Compromise Confirmed', `Unauthorized STS session from non-corporate IP. Bulk S3 data download in progress.`, 'critical');
        } else {
            this.emitLog('cloud', `Cloud enclave telemetry verified normal. No unauthorized access patterns.`, 'info');
        }
        this.agents.cloud.confidence = cloudConfidence;
        this.agents.cloud.vote = cloudConfidence > 60 ? 'MALICIOUS' : 'CLEAN';

        await this.delay(400);

        // -------------------------------------------------------
        // PHASE 6: CONSENSUS PROTOCOL — Agent Negotiation & Voting
        // -------------------------------------------------------
        this.emitLog('coordinator', `INITIATING CONSENSUS PROTOCOL: Collecting votes from all 5 investigation agents...`, 'info');
        await this.delay(200);

        const votingAgents = ['log', 'threatintel', 'malware', 'cloud', 'compliance'];
        this.agents.compliance.confidence = sigmaResult.matchesFound > 0 ? 88 : 50;
        this.agents.compliance.vote = this.agents.compliance.confidence > 70 ? 'MALICIOUS' : 'INCONCLUSIVE';

        this.consensusRecord = votingAgents.map(k => ({
            agent: this.agents[k].name,
            vote: this.agents[k].vote || 'ABSTAIN',
            confidence: this.agents[k].confidence,
            color: this.agents[k].color
        }));

        const maliciousVotes = this.consensusRecord.filter(v => v.vote === 'MALICIOUS').length;
        const totalVotes = this.consensusRecord.length;
        const consensusPct = Math.round((maliciousVotes / totalVotes) * 100);
        const consensusReached = consensusPct >= 60;

        this.emitLog('coordinator', `CONSENSUS RESULT: ${maliciousVotes}/${totalVotes} agents voted MALICIOUS (${consensusPct}% agreement). Consensus: ${consensusReached ? 'REACHED' : 'NOT REACHED'}.`, consensusReached ? 'warning' : 'info');

        this.consensusRecord.forEach(v => {
            this.emitLog('coordinator', `  → ${v.agent}: VOTE=${v.vote} | CONFIDENCE=${v.confidence}%`, v.vote === 'MALICIOUS' ? 'warning' : 'info');
        });

        // Weighted confidence score
        const weightedConfidence = Math.round(
            this.consensusRecord.reduce((sum, v) => sum + v.confidence, 0) / totalVotes
        );

        this.addRCAEvent(`T+1.9s`, 'Multi-Agent Consensus Reached', `${maliciousVotes}/${totalVotes} agents confirmed malicious intent. Weighted confidence: ${weightedConfidence}%.`, 'critical');

        await this.delay(400);

        // -------------------------------------------------------
        // PHASE 7: HUMAN APPROVAL GATE — Risk Threshold Check
        // -------------------------------------------------------
        const calculatedRisk = weightedConfidence;
        this.agents.approval.status = 'EVALUATING';
        this.agents.approval.confidence = 100;
        this.emitLog('approval', `RISK ASSESSMENT: Weighted Severity Score = ${calculatedRisk}/100 (Auto-execution threshold: ${autoThreshold}/100).`, 'info');

        const requireApproval = calculatedRisk > autoThreshold && (rawAlert.targetHost.includes('DC-PRIMARY') || rawAlert.targetHost.includes('FIN-SERVER'));

        let actionExecuted = false;
        if (requireApproval) {
            this.emitLog('approval', `HIGH IMPACT ACTION: Target [${rawAlert.targetHost}] is CRITICAL infrastructure. Escalating to Human Approval Queue.`, 'warning');
            
            this.addRCAEvent('T+2.3s', 'Action Escalated to Human Approval', `Risk score ${calculatedRisk} exceeds threshold ${autoThreshold}. Core infrastructure target requires human authorization.`, 'info');

            window.AppController?.addApprovalRequest({
                alertId: rawAlert.id,
                title: rawAlert.title,
                target: rawAlert.targetHost,
                riskScore: calculatedRisk,
                consensus: `${maliciousVotes}/${totalVotes} agents (${consensusPct}%)`,
                proposedAction: `Isolate network adapter & revoke domain credentials for host ${rawAlert.targetHost}`,
                reasoning: `VT: ${vtResult ? vtResult.positives : '?'}/92, YARA: ${yaraVerdict.verdict}, Sigma: ${sigmaResult.matchesFound} hits, Consensus: ${consensusPct}%.`
            });
        } else {
            // -------------------------------------------------------
            // PHASE 8: AUTONOMOUS INCIDENT RESPONSE — Containment
            // -------------------------------------------------------
            this.agents.response.status = 'EXECUTING';
            this.agents.response.confidence = 97;
            this.emitLog('response', `AUTONOMOUS CONTAINMENT INITIATED. Consensus: ${consensusPct}%. Executing response playbook...`, 'danger');

            this.emitLog('response', `[ACTION 1/4] Host network interface on [${rawAlert.targetHost}] ISOLATED via CrowdStrike EDR API.`, 'success');
            this.activateKillChainStage('Lateral Movement', 'BLOCKED: Network isolation prevents lateral propagation');
            await this.delay(200);

            if (rawAlert.ioc) {
                this.emitLog('response', `[ACTION 2/4] Malicious C2 IP [${rawAlert.ioc.split(' ')[0]}] BLOCKED on Perimeter Palo Alto Firewall.`, 'success');
            }
            await this.delay(200);

            this.emitLog('response', `[ACTION 3/4] Active user sessions TERMINATED. Domain credentials REVOKED.`, 'success');
            this.emitLog('response', `[ACTION 4/4] Volume Shadow Copy restoration dry-run initiated.`, 'success');

            this.addRCAEvent('T+2.5s', 'Autonomous Containment Executed', `Host isolated, C2 IP blocked, credentials revoked. All actions executed with ${consensusPct}% agent consensus.`, 'critical');

            actionExecuted = true;

            if (window.SOCTwinInstance) {
                window.SOCTwinInstance.setNodeStatus('FIN-SERVER-04', 'isolated');
                window.SOCTwinInstance.setAttackPath('FW-PERIMETER-01', 'FIN-SERVER-04');
            }
        }

        await this.delay(300);

        // -------------------------------------------------------
        // PHASE 9: COMPLIANCE AUDIT — Regulatory & SLA Check
        // -------------------------------------------------------
        this.agents.compliance.status = 'COMPLETED';
        this.emitLog('compliance', `GDPR Article 33 72-hour log entry recorded. PCI-DSS enclave safety verified. Immutable cryptographic audit trail sealed.`, 'info');

        const endTime = performance.now();
        const latencySec = ((endTime - startTime) / 1000).toFixed(2);

        this.addRCAEvent(`T+${latencySec}s`, 'Investigation Pipeline Complete', `Full autonomous investigation completed in ${latencySec}s across 8 specialized agents.`, 'info');

        // -------------------------------------------------------
        // PHASE 10: THREAT PREDICTION — Predict Next Likely TTPs
        // -------------------------------------------------------
        this.emitLog('coordinator', `THREAT PREDICTION ENGINE: Analyzing attack progression to predict adversary's next move...`, 'info');
        this.predictedTTPs = this.predictNextTTPs(rawAlert);
        if (this.predictedTTPs.length > 0) {
            this.predictedTTPs.forEach(p => {
                this.emitLog('coordinator', `[PREDICTION] Next likely TTP: ${p.id} "${p.name}" — Probability: ${p.probability}% — Recommended pre-emptive action: ${p.preemptive}`, 'warning');
            });
        }

        // -------------------------------------------------------
        // PHASE 11: AUTONOMOUS PLAYBOOK GENERATION
        // -------------------------------------------------------
        this.generatedPlaybook = this.generatePlaybook(rawAlert, actionExecuted, yaraVerdict, vtResult);
        this.emitLog('coordinator', `PLAYBOOK GENERATOR: New adaptive playbook "${this.generatedPlaybook.name}" synthesized from current incident patterns and episodic memory.`, 'success');

        // Save to Episodic Memory
        SOCMemory.addEpisodicMemory({
            title: rawAlert.title,
            enclave: rawAlert.source,
            rootCause: `Detected execution of malicious payload on asset ${rawAlert.targetHost}`,
            actionsTaken: actionExecuted ? ['Host Isolated via EDR', 'C2 IP Blocked on Perimeter FW', 'Credentials Revoked', 'Shadow Copy Restoration Initiated'] : ['Escalated to Human Approval Queue'],
            resolutionOutcome: actionExecuted ? 'SUCCESS — Autonomous containment complete' : 'PENDING HUMAN APPROVAL',
            mttrSeconds: latencySec
        });

        // Final Coordinator Synthesis
        this.agents.coordinator.status = 'COMPLETED';
        this.agents.coordinator.confidence = 99;
        this.emitLog('coordinator', `INVESTIGATION COMPLETE in ${latencySec}s. Consensus: ${consensusPct}% (${maliciousVotes}/${totalVotes}). Weighted Confidence: ${weightedConfidence}%. Status: ${actionExecuted ? 'CONTAINED' : 'PENDING APPROVAL'}.`, 'success');

        return {
            status: actionExecuted ? 'CONTAINED' : 'PENDING_APPROVAL',
            riskScore: calculatedRisk,
            latencySec,
            consensusPct,
            weightedConfidence,
            maliciousVotes,
            totalVotes
        };
    }

    // ===========================================================
    // THREAT PREDICTION ENGINE (Bonus Feature)
    // Predicts next likely adversary TTPs based on current kill chain
    // ===========================================================
    predictNextTTPs(alert) {
        const predictions = [];
        const activeStages = Object.keys(this.killChainState);

        if (activeStages.includes('Initial Access') && activeStages.includes('Execution')) {
            predictions.push({
                id: 'T1003.001',
                name: 'LSASS Memory Credential Dumping',
                probability: 87,
                preemptive: 'Enable LSA RunAsPPL protection & deploy Credential Guard.',
                reasoning: 'Initial access + code execution typically followed by credential harvesting for lateral movement.'
            });
        }

        if (activeStages.includes('Credential Access') || activeStages.includes('Lateral Movement')) {
            predictions.push({
                id: 'T1021.002',
                name: 'SMB/WinRM Lateral Movement',
                probability: 78,
                preemptive: 'Restrict SMB traffic to admin-only VLANs. Enable WinRM authentication logging.',
                reasoning: 'After credential compromise, adversaries typically pivot via remote service protocols.'
            });
        }

        if (activeStages.includes('Exfiltration / Impact')) {
            predictions.push({
                id: 'T1070.001',
                name: 'Event Log Clearing (Anti-Forensics)',
                probability: 72,
                preemptive: 'Forward all event logs to immutable SIEM. Enable Sysmon with tamper protection.',
                reasoning: 'Post-impact, adversaries commonly attempt evidence destruction to hinder investigation.'
            });
        }

        if (predictions.length === 0) {
            predictions.push({
                id: 'T1059.001',
                name: 'PowerShell Command Execution',
                probability: 65,
                preemptive: 'Enable Constrained Language Mode and Script Block Logging.',
                reasoning: 'Default prediction based on most common post-initial-access execution vector.'
            });
        }

        return predictions;
    }

    // ===========================================================
    // AUTONOMOUS PLAYBOOK GENERATOR (Bonus Feature)
    // Synthesizes new playbooks from current incident + episodic memory
    // ===========================================================
    generatePlaybook(alert, wasContained, yaraResult, vtResult) {
        const steps = [];
        let playbookName = 'ADAPTIVE-PLAYBOOK';

        // Learn from past similar incidents
        const similar = SOCMemory.querySimilarIncidents(alert.title.split(' ')[0]);

        if (yaraResult.verdict === 'MALICIOUS') {
            playbookName = `AUTO-PB-RANSOMWARE-${Date.now().toString(36).toUpperCase()}`;
            steps.push('STEP 1: Immediately isolate host network adapter via EDR API (CrowdStrike/SentinelOne).');
            steps.push('STEP 2: Terminate all child processes of detected malicious parent PID.');
            steps.push('STEP 3: Block C2 IP on perimeter firewall (Palo Alto PAN-OS API).');
            steps.push('STEP 4: Force-reset compromised Active Directory user credentials.');
            steps.push('STEP 5: Initiate Volume Shadow Copy restoration (dry-run first, then live).');
            steps.push('STEP 6: Scan all lateral hosts in same subnet for IOC propagation.');
        } else if (alert.payload.includes('AssumeRole') || alert.payload.includes('S3')) {
            playbookName = `AUTO-PB-CLOUD-EXFIL-${Date.now().toString(36).toUpperCase()}`;
            steps.push('STEP 1: Attach IAM DenyAll inline policy to compromised principal.');
            steps.push('STEP 2: Invalidate all active STS session tokens.');
            steps.push('STEP 3: Audit CloudTrail for S3 GetObject access in last 24 hours.');
            steps.push('STEP 4: Enable S3 Object Lock on sensitive production buckets.');
            steps.push('STEP 5: Rotate all IAM access keys in affected AWS account.');
        } else {
            playbookName = `AUTO-PB-GENERIC-${Date.now().toString(36).toUpperCase()}`;
            steps.push('STEP 1: Isolate affected host from network.');
            steps.push('STEP 2: Collect forensic memory dump and disk image.');
            steps.push('STEP 3: Block all identified IOC indicators on perimeter.');
            steps.push('STEP 4: Notify security operations team for manual review.');
        }

        if (similar.length > 0) {
            steps.push(`STEP ${steps.length + 1}: [LEARNED FROM EPISODIC MEMORY] Similar incident "${similar[0].title}" was resolved via: ${similar[0].actionsTaken.join(', ')}. Apply same pattern.`);
        }

        return {
            name: playbookName,
            generatedAt: new Date().toISOString(),
            basedOn: alert.title,
            steps,
            confidence: wasContained ? 95 : 80
        };
    }

    resetAll() {
        Object.keys(this.agents).forEach(k => {
            this.agents[k].status = 'READY';
            this.agents[k].confidence = 0;
            this.agents[k].vote = null;
            this.agents[k].logs = [];
        });
        this.rcaTimeline = [];
        this.killChainState = {};
        this.consensusRecord = [];
        this.predictedTTPs = [];
        this.generatedPlaybook = null;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

const SwarmEngine = new SOCAgentSwarm();
