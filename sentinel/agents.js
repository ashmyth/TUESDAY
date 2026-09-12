/* ==========================================================================
   TUESDAY: Multi-Agent Swarm Client Adapter (Frontend to Python FastAPI)
   Connects the Sentinel UI directly to the native Python FastAPI backend
   (engine/server.py on port 8090) over SSE for real-time streaming forensics.
   No mock/hardcoded JS simulation — 100% powered by the Python agent swarm.
   ========================================================================== */

// ---- Backend Connectivity Client -----------------------------------------
window.TuesdayBackend = {
    status: { ok: false, engine: 'offline', model: null, checkedAt: 0 },
    async refresh(force) {
        if (!force && this.status.ok && Date.now() - this.status.checkedAt < 5000) return this.status;
        try {
            const res = await fetch('/api/status', { signal: AbortSignal.timeout(4000) });
            if (!res.ok) throw new Error('status ' + res.status);
            const data = await res.json();
            this.status = { ...data, ok: true, checkedAt: Date.now() };
        } catch (e) {
            this.status = { ok: false, engine: 'offline', model: null, checkedAt: Date.now() };
        }
        return this.status;
    }
};

class SOCAgentSwarm {
    constructor() {
        this.agents = {
            coordinator: { id: 'agent-coord', name: 'SOC Coordinator', role: 'Swarm Orchestration & Task Decomposition', icon: 'fa-sitemap', color: '#3E7A84', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            log:         { id: 'agent-log', name: 'Log Analysis', role: 'SIEM Correlation & Sigma Rules Engine', icon: 'fa-list-check', color: '#4A8CA8', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            threatintel: { id: 'agent-intel', name: 'Threat Intelligence', role: 'IOC Enrichment (VT, AbuseIPDB, Shodan, MISP)', icon: 'fa-globe', color: '#B08C9E', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            malware:     { id: 'agent-malware', name: 'Malware Sandbox', role: 'YARA + Behavioral Sandbox Analysis', icon: 'fa-bug', color: '#EEA4A5', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            cloud:       { id: 'agent-cloud', name: 'Cloud Security', role: 'AWS/Azure IAM & CSPM Posture Audit', icon: 'fa-cloud', color: '#7FB3BB', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            critic:      { id: 'agent-critic', name: 'Adversarial Critic', role: 'Hypothesis Verification & False-Positive Disprover', icon: 'fa-user-ninja', color: '#D97706', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            response:    { id: 'agent-response', name: 'Incident Response', role: 'Autonomous Containment & SOAR Playbooks', icon: 'fa-bolt', color: '#FD4040', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            compliance:  { id: 'agent-compliance', name: 'Compliance Audit', role: 'Regulatory Impact & Cryptographic Audit Trail', icon: 'fa-scale-balanced', color: '#C97A7C', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' },
            approval:    { id: 'agent-approval', name: 'Human Governance', role: 'Risk Threshold Gate & Override Control', icon: 'fa-user-shield', color: '#3E7A84', status: 'IDLE', confidence: 0, vote: null, logs: [], hypotheses: [], thoughtTrace: '' }
        };

        this.busListeners = [];
        this.rcaTimeline = [];
        this.killChainState = {};
        this.consensusRecord = [];
        this.predictedTTPs = [];
        this.generatedPlaybook = null;
        this.criticEvaluation = null;
        this.recalledEpisodes = [];
        this._lastBackendResult = null;
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
    // INVESTIGATION ENTRYPOINT
    // Streams the real Python FastAPI swarm via SSE (/api/incident/stream).
    // No hardcoded JS fallback — Python backend is required.
    // ===========================================================
    async processIncidentAlert(rawAlert, opts = {}) {
        this.resetAll();
        await window.TuesdayBackend.refresh();

        if (!window.TuesdayBackend.status.ok) {
            // Check once more in case the health check was just warming up
            try {
                const res = await fetch('/api/health');
                if (res.ok) window.TuesdayBackend.status.ok = true;
            } catch (e) {}
        }

        if (window.TuesdayBackend.status.ok) {
            try {
                return await this.runBackendInvestigation(rawAlert, opts);
            } catch (e) {
                this.emitLog('coordinator', `BACKEND ERROR: ${e.message}`, 'danger');
                return this.reportBackendOffline(e.message);
            }
        }

        return this.reportBackendOffline('Backend not reachable on http://localhost:8090');
    }

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
                else fail(new Error('Stream ended without a result payload from Python engine'));
            }).catch(e => fail(e));
        });
    }

    applySSEEvent(chunk) {
        const lines = chunk.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed.startsWith('data:')) continue;
            const raw = trimmed.slice(5).trim();
            if (!raw || raw === '[DONE]') continue;
            let payload;
            try { payload = JSON.parse(raw); } catch { continue; }

            const type = payload.type;
            if (!type) continue;

            switch (type) {
                case 'log':
                    this.emitLog(payload.agent || 'coordinator', payload.message, payload.level || 'info');
                    if (this.agents[payload.agent]) {
                        this.agents[payload.agent].status = 'ANALYZING';
                    }
                    break;

                case 'result': {
                    const r = payload.data || payload;
                    this._lastBackendResult = r;

                    if (r.killChainState)  this.killChainState  = r.killChainState;
                    if (r.recalledEpisodes) this.recalledEpisodes = r.recalledEpisodes;
                    if (r.playbook)         this.generatedPlaybook = r.playbook;
                    if (r.ttpsDetected)     this.predictedTTPs = r.ttpsDetected.map(id => ({ id, name: id, probability: 85 }));

                    // Build RCA timeline from findings if not explicitly provided
                    if (r.rcaTimeline && r.rcaTimeline.length > 0) {
                        this.rcaTimeline = r.rcaTimeline;
                    } else if (r.votes) {
                        this.rcaTimeline = [];
                        const nowStr = new Date().toLocaleTimeString();
                        this.addRCAEvent(nowStr, 'Alert Ingestion', `Ingested alert for ${r.alert?.host || r.alert?.targetHost || 'host'}`, 'info');
                        r.votes.forEach(v => {
                            if (v.vote === 'MALICIOUS') {
                                this.addRCAEvent(nowStr, `${v.name} Detection`, v.rationale || `${v.name} flagged anomaly`, 'danger');
                            }
                        });
                        if (r.critic?.rationale) {
                            this.addRCAEvent(nowStr, 'Adversarial Audit', r.critic.rationale, r.critic.challengePassed ? 'warning' : 'success');
                        }
                    }

                    // Populate consensusRecord from Python votes
                    if (r.votes) {
                        this.consensusRecord = r.votes;
                        r.votes.forEach(v => {
                            if (this.agents[v.key]) {
                                this.agents[v.key].confidence = v.confidence || 0;
                                this.agents[v.key].vote       = v.vote || 'BENIGN';
                                this.agents[v.key].status     = 'COMPLETED';
                                this.agents[v.key].thoughtTrace = v.rationale || '';
                                if (v.hypotheses) {
                                    this.agents[v.key].hypotheses = v.hypotheses;
                                }
                            }
                        });
                    }

                    // Populate critic evaluation
                    if (r.critic) {
                        this.criticEvaluation = {
                            verdict:                r.critic.verdict || (r.critic.challengePassed ? 'APPROVED' : 'REJECTED'),
                            critique:               r.critic.critique || r.critic.rationale || '',
                            hallucinationRisk:      r.critic.hallucinationRisk || (r.critic.confidence > 80 ? 'Low' : 'Moderate'),
                            alternativeExplanation: r.critic.alternativeExplanation || r.critic.counterEvidence || null,
                            confidence:             r.critic.confidence || 90,
                            challengePassed:        !!r.critic.challengePassed
                        };

                        if (this.agents.critic) {
                            this.agents.critic.status     = 'COMPLETED';
                            this.agents.critic.confidence = this.criticEvaluation.confidence;
                            this.agents.critic.vote       = r.critic.challengePassed ? 'MALICIOUS' : 'BENIGN';
                            this.agents.critic.thoughtTrace = this.criticEvaluation.critique;
                            this.agents.critic.hypotheses = [
                                { hypothesis: 'Challenge: Benign Activity / False Positive', supported: !r.critic.challengePassed, evidence: r.critic.counterEvidence || '' },
                                { hypothesis: 'Verification: Genuine Hostile Threat', supported: !!r.critic.challengePassed, evidence: r.critic.rationale || '' }
                            ];
                        }

                        if (window.AppController?.renderCriticEvaluation) {
                            window.AppController.renderCriticEvaluation(this.criticEvaluation);
                        }
                    }

                    // Surface HITL approval in UI if queued by Python
                    if (r.hitlQueued && r.alert && window.AppController?.addApprovalRequest) {
                        window.AppController.addApprovalRequest({
                            id:             r.hitlApprovalId || `APP-${Date.now().toString(36).toUpperCase()}`,
                            alertId:        r.alert.id,
                            title:          r.alert.title,
                            target:         r.alert.host || r.alert.targetHost,
                            riskScore:      r.riskScore,
                            consensus:      `${r.votes ? r.votes.filter(v=>v.vote==='MALICIOUS').length : '?'}/${r.votes?.length || '?'} agents`,
                            proposedAction: `Isolate host ${r.alert.host || r.alert.targetHost} — awaiting operator decision`,
                            reasoning:      `Risk ${r.riskScore}/100 | ACH: ${r.ach?.preferredHypothesis || 'H1'}`
                        });
                    }
                    break;
                }

                case 'heartbeat':
                    break;

                case 'error':
                    this.emitLog('coordinator', `PYTHON ENGINE ERROR: ${payload.message}`, 'danger');
                    break;

                case 'done':
                    break;

                default:
                    break;
            }
        }
    }

    reportBackendOffline(errMsg) {
        this.emitLog('coordinator',
            'PYTHON FASTAPI ENGINE OFFLINE — Investigation requires the native Python swarm.',
            'danger');
        this.emitLog('coordinator',
            'Start the engine with: python -m uvicorn engine.server:app --port 8090 (or run start.bat)',
            'warning');

        const statusEl = document.getElementById('pill-engine');
        if (statusEl) {
            statusEl.innerText = 'ENGINE: OFFLINE (Start start.bat)';
            statusEl.className = 'matrix-pill badge-matrix-red';
        }

        return {
            status:             'ENGINE_OFFLINE',
            riskScore:          0,
            latencySec:         0,
            consensusPct:       0,
            weightedConfidence: 0,
            votes:              [],
            error:              errMsg
        };
    }

    // ===========================================================
    // HITL & SOAR ACTIONS
    // ===========================================================
    async runApprovalExecution(approvalId) {
        try {
            const res = await fetch(`/api/approvals/${approvalId}/decide`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ decision: 'approve', operator: 'Human SOC Operator' })
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            this.emitLog('response', `SOAR ISOLATION EXECUTED: Status: ${data.containment?.status || 'CONTAINED'}`, 'success');
            return data;
        } catch (e) {
            this.emitLog('response', `APPROVAL EXECUTION FAILED: ${e.message}`, 'danger');
            throw e;
        }
    }

    async rejectApproval(approvalId, reason) {
        try {
            const res = await fetch(`/api/approvals/${approvalId}/decide`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ decision: 'reject', operator: reason || 'SOC Operator Override' })
            });
            return res.ok;
        } catch (e) {
            return false;
        }
    }

    async rollbackContainment(ruleName) {
        try {
            const res = await fetch('/api/containment/rollback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule_name: ruleName })
            });
            return await res.json();
        } catch (e) {
            return { status: 'ERROR', message: e.message };
        }
    }

    resetAll() {
        Object.keys(this.agents).forEach(k => {
            this.agents[k].status     = 'READY';
            this.agents[k].confidence = 0;
            this.agents[k].vote       = null;
            this.agents[k].logs       = [];
            this.agents[k].hypotheses = [];
            this.agents[k].thoughtTrace = '';
        });
        this.rcaTimeline      = [];
        this.killChainState   = {};
        this.consensusRecord  = [];
        this.predictedTTPs    = [];
        this.generatedPlaybook  = null;
        this.criticEvaluation   = null;
        this.recalledEpisodes   = [];
        this._lastBackendResult = null;
    }

    delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
}

const SwarmEngine = new SOCAgentSwarm();
