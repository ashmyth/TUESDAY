'use strict';
/* ==========================================================================
   TUESDAY: Zero-Dependency HTTP Server (Node >= 18)
   - Serves the static frontend (index.html, *.js, *.css)
   - REST API + Server-Sent Events for the agentic swarm
   Run: node server.js   (or start.bat)
   ========================================================================== */

const http = require('http');
const fs = require('fs');
const path = require('path');

const config = require('./config.json');
const store = require('./lib/store');
const llm = require('./lib/llm');
const orchestrator = require('./lib/orchestrator');
const { ASSETS, THREAT_ACTORS } = require('./lib/tools');

const PORT = process.env.PORT || config.port || 8080;
const ROOT = __dirname;
const startedAt = Date.now();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8'
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(new Error('invalid JSON body')); } });
    req.on('error', reject);
  });
}

function serveStatic(req, res, urlPath) {
  let filePath = path.join(ROOT, urlPath === '/' ? 'index.html' : urlPath);
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('404 - Not Found');
    return;
  }
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';
  const data = fs.readFileSync(filePath);
  res.writeHead(200, { 'content-type': contentType });
  res.end(data);
}

// SSE framing
function sseWrite(res, event, payload) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  try {
    // ---- API: status -------------------------------------------------------
    if (pathname === '/api/status' && req.method === 'GET') {
      const probe = await llm.checkModel();
      return sendJSON(res, 200, {
        backend: 'online',
        engine: probe.ok && (probe.present || (probe.available || []).length > 0) ? 'llm' : 'rules',
        model: probe.model,
        ollama: probe,
        port: PORT,
        stats: store.memory.stats
      });
    }

    // ---- API: settings/provider --------------------------------------------
    if (pathname === '/api/settings/provider' && req.method === 'POST') {
      const body = await readBody(req);
      if (body.provider) {
        llm.setProvider(body.provider);
      }
      return sendJSON(res, 200, { status: 'ok', provider: llm.getProvider() });
    }

    // ---- API: health -------------------------------------------------------
    if (pathname === '/api/health' && req.method === 'GET') {
      const probe = await llm.checkModel();
      return sendJSON(res, 200, {
        status: 'ok',
        backend: 'online',
        engine: probe.ok && (probe.present || (probe.available || []).length > 0) ? 'llm' : 'rules',
        model: probe.model,
        modelPresent: !!(probe.present || false),
        uptimeSec: Math.round((Date.now() - startedAt) / 1000),
        incidents: store.memory.stats.incidents,
        approvalsPending: store.memory.approvals.filter(a => a.status === 'PENDING').length,
        timestamp: new Date().toISOString()
      });
    }

    // ---- API: agents (weights) ---------------------------------------------
    if (pathname === '/api/agents' && req.method === 'GET') {
      return sendJSON(res, 200, {
        weights: store.memory.agentWeights,
        assets: ASSETS,
        threatActors: THREAT_ACTORS
      });
    }

    // ---- API: memory --------------------------------------------------------
    if (pathname === '/api/memory' && req.method === 'GET') {
      return sendJSON(res, 200, {
        episodicMemory: store.memory.episodicMemory,
        auditLog: store.memory.auditLog,
        agentWeights: store.memory.agentWeights,
        stats: store.memory.stats
      });
    }

    // ---- API: reinforcement learning feedback --------------------------------
    if (pathname === '/api/feedback' && req.method === 'POST') {
      const body = await readBody(req);
      const agentKey = String(body.agent || '');
      const delta = body.type === 'up' ? 0.05 : body.type === 'down' ? -0.05 : 0;
      if (!agentKey || delta === 0) return sendJSON(res, 400, { error: 'agent + type(up|down) required' });
      store.adjustWeight(agentKey, delta);
      store.addAudit('REINFORCEMENT_LEARNING', `Agent ${agentKey} weight adjusted ${body.type} → ${store.getWeight(agentKey).toFixed(2)}`);
      return sendJSON(res, 200, { agent: agentKey, weight: store.getWeight(agentKey) });
    }

    // ---- API: run investigation (SSE stream) ----------------------------------
    if (pathname === '/api/incident/stream' && req.method === 'POST') {
      const body = await readBody(req);
      const alert = body.alert;
      if (!alert || !alert.title) return sendJSON(res, 400, { error: 'alert required' });

      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
        'x-accel-buffering': 'no'
      });
      res.write(': connected\n\n');

      const emit = ev => {
        try { sseWrite(res, ev.event || ev.type, ev); } catch { /* client gone */ }
      };

      try {
        await orchestrator.runInvestigation(alert, { emit, threshold: body.threshold });
        sseWrite(res, 'done', {});
      } catch (e) {
        sseWrite(res, 'error', { message: e.message });
      }
      res.end();
      return;
    }

    // ---- API: run investigation (plain JSON) -----------------------------------
    if (pathname === '/api/incident' && req.method === 'POST') {
      const body = await readBody(req);
      const alert = body.alert;
      if (!alert || !alert.title) return sendJSON(res, 400, { error: 'alert required' });
      const result = await orchestrator.runInvestigation(alert, { threshold: body.threshold });
      return sendJSON(res, 200, result);
    }

    // ---- API: audit -------------------------------------------------------------
    if (pathname === '/api/audit' && req.method === 'GET') {
      return sendJSON(res, 200, store.memory.auditLog);
    }

    // ---- API: approval queue -----------------------------------------------------
    if (pathname === '/api/approvals' && req.method === 'GET') {
      const { status } = url.searchParams;
      return sendJSON(res, 200, store.listApprovals(status || 'PENDING').map(a => ({
        id: a.id, incidentId: a.incidentId, title: a.title, target: a.target,
        riskScore: a.riskScore, consensus: a.consensus, proposedAction: a.proposedAction,
        reasoning: a.reasoning, status: a.status, createdAt: a.createdAt
      })));
    }

    // ---- API: execute approved incident (SSE stream) -------------------------------
    if (pathname === '/api/incident/approve' && req.method === 'POST') {
      const body = await readBody(req);
      const id = String(body.id || '');
      if (!id) return sendJSON(res, 400, { error: 'approval id required' });

      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
        'x-accel-buffering': 'no'
      });
      res.write(': connected\n\n');

      const emit = ev => { try { sseWrite(res, ev.event || ev.type, ev); } catch { /* client gone */ } };
      try {
        await orchestrator.executeApprovedResponse(id, emit);
        sseWrite(res, 'done', {});
      } catch (e) {
        sseWrite(res, 'error', { message: e.message });
      }
      res.end();
      return;
    }

    // ---- API: reject approval -------------------------------------------------------
    if (pathname === '/api/incident/reject' && req.method === 'POST') {
      const body = await readBody(req);
      const id = String(body.id || '');
      if (!id) return sendJSON(res, 400, { error: 'approval id required' });
      try {
        const a = await orchestrator.rejectApproval(id, body.reason || 'rejected by SOC operator');
        return sendJSON(res, 200, { id: a.id, status: a.status });
      } catch (e) {
        return sendJSON(res, 404, { error: e.message });
      }
    }

    // ---- static ---------------------------------------------------------------
    if (pathname === '/api/') return sendJSON(res, 404, { error: 'unknown endpoint' });
    return serveStatic(req, res, pathname);

  } catch (e) {
    if (res.headersSent) { res.end(); return; }
    sendJSON(res, 500, { error: e.message });
  }
});

if (process.env.VERCEL) {
  module.exports = (req, res) => {
    return server.emit('request', req, res);
  };
} else {
  server.listen(PORT, () => {
    console.log('==================================================================');
    console.log('  TUESDAY — AGENTIC AI SWARM v3.0');
    console.log(`  Listening on: http://localhost:${PORT}`);
    console.log('------------------------------------------------------------------');
    llm.checkModel().then(probe => {
      if (probe.ok && probe.present) {
        console.log(`  ENGINE: LLM AGENTIC (model ${probe.model} on Ollama) ✓`);
      } else if (probe.ok) {
        console.log(`  ENGINE: LLM configured but "${probe.model}" not found.`);
        console.log(`  Installed models: ${(probe.available || []).join(', ') || 'none'}`);
        console.log(`  → Run: ollama pull ${probe.model}   (or set model in config.json)`);
        console.log(`  → Until then, the RULE ENGINE fallback keeps the demo alive.`);
      } else {
        console.log(`  ENGINE: Ollama not reachable at ${probe.base}.`);
        console.log('  → Install Ollama (ollama.com) + run: ollama pull qwen2.5:7b');
        console.log('  → Until then, the RULE ENGINE fallback keeps the demo alive.');
      }
      if (probe.ok && probe.present) {
        llm.warmModel().then(w => {
          console.log(w.ok
            ? `  WARMUP: ${probe.model} pre-loaded into memory ✓`
            : `  WARMUP: skipped (${w.error || 'unavailable'}) — first run may be slower.`);
        });
      }
      console.log('==================================================================');
    });
    setTimeout(() => {
      console.log('  Open your browser at http://localhost:' + PORT);
    }, 400);
  });
}
