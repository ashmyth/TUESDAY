'use strict';
/* ==========================================================================
   TUESDAY RedTeam: Attack Console HTTP Server (Port 8095)
   Zero-dependency Node HTTP server providing:
     - Interactive adversary dashboard UI
     - REST endpoints to launch real-time attack drills into Sentinel (Port 8090)
     - Live attack execution telemetry
   ========================================================================== */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { SCENARIOS } = require('./scenarios');

const PORT = process.env.PORT || 8095;
const SENTINEL_URL = process.env.SENTINEL_URL || 'http://localhost:8090';

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // --- API: List available scenarios ---
  if (pathname === '/api/scenarios' && req.method === 'GET') {
    return sendJSON(res, 200, { ok: true, scenarios: SCENARIOS });
  }

  // --- API: Execute live on-host attack drills ---
  if (pathname === '/api/drills/run' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const { drillType } = JSON.parse(body || '{}');
        if (drillType === 'privacy') {
          const result = await require('./drills/privacy_harvester_drill').run();
          return sendJSON(res, 200, { ok: true, drill: 'privacy_harvester', result });
        } else if (drillType === 'ransomware') {
          const result = await require('./drills/ransomware_canary_drill').run();
          return sendJSON(res, 200, { ok: true, drill: 'ransomware_canary', result });
        } else if (drillType === 'registry_plant') {
          const result = await require('./drills/registry_persistence_drill').plantCanary();
          return sendJSON(res, 200, { ok: true, drill: 'registry_plant', result });
        } else if (drillType === 'registry_clean') {
          const result = await require('./drills/registry_persistence_drill').cleanCanary();
          return sendJSON(res, 200, { ok: true, drill: 'registry_clean', result });
        } else {
          return sendJSON(res, 400, { error: 'Unknown drillType: ' + drillType });
        }
      } catch (e) {
        return sendJSON(res, 500, { ok: false, error: e.message });
      }
    });
    return;
  }

  // --- API: Launch attack scenario into Sentinel ---
  if (pathname === '/api/attack/launch' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        const scenario = SCENARIOS[payload.scenarioKey] || payload.customScenario;

        if (!scenario) {
          return sendJSON(res, 400, { ok: false, error: 'Scenario not found' });
        }

        const alertPayload = {
          id: scenario.id || `SIM-${Date.now().toString(36).toUpperCase()}`,
          title: scenario.title,
          source: scenario.source,
          targetHost: scenario.targetHost,
          ioc: scenario.ioc,
          payload: scenario.payload
        };

        // Forward attack alert directly into Sentinel SOC endpoint
        try {
          const sentinelRes = await fetch(`${SENTINEL_URL}/api/incident`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert: alertPayload, threshold: 80 })
          });

          const sentinelData = await sentinelRes.json();
          return sendJSON(res, 200, {
            ok: true,
            message: `Attack drill "${scenario.title}" injected into Sentinel`,
            alert: alertPayload,
            sentinelResponse: sentinelData
          });
        } catch (err) {
          return sendJSON(res, 502, {
            ok: false,
            error: `Failed to reach Sentinel at ${SENTINEL_URL}: ${err.message}`,
            alert: alertPayload,
            hint: 'Ensure TUESDAY Sentinel is running on port 8090.'
          });
        }
      } catch (e) {
        return sendJSON(res, 400, { ok: false, error: e.message });
      }
    });
    return;
  }

  // --- Serve UI dashboard ---
  if (pathname === '/' || pathname === '/index.html') {
    const htmlPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(htmlPath));
    }
  }

  sendJSON(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`[TUESDAY RedTeam] Adversary Attack Suite running on http://localhost:${PORT}`);
  console.log(`[TUESDAY RedTeam] Target Sentinel SOC: ${SENTINEL_URL}`);
});
