'use strict';
/* ==========================================================================
   TUESDAY RedTeam Drill: Privacy & Secret Harvester Simulation
   Demonstrates Track 4 (Cybersecurity & Privacy):
     1. Creates a local sandbox directory with simulated sensitive files (.env, cookies)
     2. Simulates an unauthorized process scanning and reading sensitive credentials
     3. Attempts an outbound socket beacon to a designated external C2 collector
     4. Dispatches the telemetry into Sentinel's autonomous EDR pipeline
   ========================================================================== */

const fs = require('fs');
const path = require('path');
const http = require('http');

const SANDBOX = path.join(__dirname, '..', 'sandbox');
const SENTINEL_URL = process.env.SENTINEL_URL || 'http://localhost:8090';

async function run() {
  console.log('[Privacy Harvester Drill] Initializing realistic telemetry harvesting drill...');

  // 1. Stage simulated sensitive credential targets
  if (!fs.existsSync(SANDBOX)) fs.mkdirSync(SANDBOX, { recursive: true });

  const envFile = path.join(SANDBOX, '.env');
  const cookieFile = path.join(SANDBOX, 'session_cookies.sqlite');

  fs.writeFileSync(envFile, `AWS_SECRET_ACCESS_KEY=mock_akiasimulatedsecret12345\nDATABASE_URL=postgres://admin:supersecret@10.0.0.5/prod\nJWT_SIGNING_KEY=secret_key_88921`);
  fs.writeFileSync(cookieFile, `MOCK_SESSION_TOKEN_BLOB_AUTH_DEV_WORKSTATION_09`);

  console.log('[Privacy Harvester Drill] Staged mock credential canary targets in sandbox.');

  // 2. Read the staged targets (simulating unauthorized background harvesting)
  const envContent = fs.readFileSync(envFile, 'utf8');
  console.log(`[Privacy Harvester Drill] Harvested ${envContent.split('\n').length} secret environment variables.`);

  // 3. Dispatch structured EDR & socket alert into Sentinel
  const alert = {
    id: `HARVEST-${Date.now().toString(36).toUpperCase()}`,
    title: 'Unauthorized Credential Harvester & Outbound Telemetry Siphon',
    source: 'Endpoint Behavioral Sensor / Host Watchdog',
    targetHost: 'DEV-WORKSTATION-09 (192.168.20.14)',
    ioc: '185.220.101.99',
    payload: `PID ${process.pid} inspected ${envFile} & spawned outbound POST to https://185.220.101.99/telemetry/harvest`
  };

  console.log(`[Privacy Harvester Drill] Forwarding hostile alert into Sentinel (${SENTINEL_URL})...`);
  try {
    const res = await fetch(`${SENTINEL_URL}/api/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert, threshold: 80 })
    });
    const data = await res.json();
    console.log('[Privacy Harvester Drill] Sentinel Response Status:', data.status, `in ${data.latencySec}s`);
    console.log('[Privacy Harvester Drill] Sentinel Containment Actions:', JSON.stringify(data.generatedPlaybook ? data.generatedPlaybook.steps : []));
    return data;
  } catch (err) {
    console.error('[Privacy Harvester Drill] Could not connect to Sentinel:', err.message);
  }
}

if (require.main === module) {
  run();
}

module.exports = { run };
