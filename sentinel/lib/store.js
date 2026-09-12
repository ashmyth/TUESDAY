'use strict';
/* ==========================================================================
   TUESDAY: Persistent Store (JSON-file backed)
   Episodic memory, agent RL weights, audit trail. Survives restarts so the
   swarm genuinely "remembers" past incidents across sessions.
   ========================================================================== */

const fs = require('fs');
const path = require('path');

class Store {
  constructor(filePath) {
    this.filePath = filePath || path.join(__dirname, '..', 'data', 'store.json');
    this.memory = {
      episodicMemory: [],          // past incident records (cap 50)
      agentWeights: {},            // reinforcement-learning trust weights
      auditLog: [],                // immutable-style audit trail (cap 200)
      approvals: [],               // human-approval queue (pending escalations)
      stats: { incidents: 0, llmRuns: 0, rulesRuns: 0, totalToolCalls: 0 }
    };
    this.writeQueue = Promise.resolve();
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        this.memory = { ...this.memory, ...raw };
      }
    } catch (e) {
      console.error('[store] failed to load:', e.message);
    }
  }

  save() {
    this.writeQueue = this.writeQueue.then(() => {
      try {
        fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
        const tmp = this.filePath + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(this.memory, null, 2));
        fs.renameSync(tmp, this.filePath);
      } catch (e) {
        console.error('[store] failed to save:', e.message);
      }
    });
    return this.writeQueue;
  }

  // --- agent RL weights -------------------------------------------------
  getWeight(agentKey) {
    return this.memory.agentWeights[agentKey] ?? 1.0;
  }

  setWeight(agentKey, weight) {
    this.memory.agentWeights[agentKey] = Math.max(0.1, Math.min(3.0, weight));
    this.save();
  }

  adjustWeight(agentKey, delta) {
    this.setWeight(agentKey, this.getWeight(agentKey) + delta);
  }

  // --- episodic memory ---------------------------------------------------
  addEpisodic(incident) {
    this.memory.episodicMemory.unshift(incident);
    if (this.memory.episodicMemory.length > 50) this.memory.episodicMemory.pop();
    this.save();
    return incident;
  }

  updateEpisodic(id, patch) {
    const i = this.memory.episodicMemory.find(x => x.id === id);
    if (!i) return null;
    Object.assign(i, patch);
    this.save();
    return i;
  }

  searchEpisodic(query) {
    const q = String(query || '').toLowerCase();
    if (!q) return [];
    return this.memory.episodicMemory.filter(i =>
      (i.title || '').toLowerCase().includes(q) ||
      (i.rootCause || '').toLowerCase().includes(q) ||
      (i.enclave || '').toLowerCase().includes(q) ||
      (i.mitreTtps || []).some(t => String(t).toLowerCase().includes(q))
    ).slice(0, 3);
  }

  // --- audit ---------------------------------------------------------------
  addAudit(type, details) {
    this.memory.auditLog.unshift({ ts: new Date().toISOString(), type, details });
    if (this.memory.auditLog.length > 200) this.memory.auditLog.pop();
    this.save();
  }

  // --- human approval queue ---------------------------------------------------
  addApproval(approval) {
    this.memory.approvals.unshift(approval);
    if (this.memory.approvals.length > 20) this.memory.approvals.pop();
    this.save();
    return approval;
  }

  getApproval(id) {
    return this.memory.approvals.find(a => a.id === id);
  }

  listApprovals(status) {
    return this.memory.approvals.filter(a => !status || a.status === status);
  }

  updateApproval(id, patch) {
    const a = this.getApproval(id);
    if (!a) return null;
    Object.assign(a, patch);
    this.save();
    return a;
  }

  bumpStats(engine, toolCalls) {
    this.memory.stats.incidents += 1;
    if (engine === 'llm') this.memory.stats.llmRuns += 1; else this.memory.stats.rulesRuns += 1;
    this.memory.stats.totalToolCalls += toolCalls || 0;
    this.save();
  }
}

module.exports = new Store();
