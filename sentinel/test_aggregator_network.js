'use strict';

/**
 * Diagnostic Verification Script:
 * 1. Tests local telemetry temporal aggregation
 * 2. Attempts dispatch to configured Node B (or fallback localhost for single-machine testing)
 */

const { TelemetryAggregator, queryNodeB, NODE_B_CONFIG } = require('./lib/telemetry_aggregator');

const targetHost = process.env.NODE_B_HOST || NODE_B_CONFIG.host;
const targetPort = process.env.NODE_B_PORT || NODE_B_CONFIG.port;
const targetModel = process.env.NODE_B_MODEL || NODE_B_CONFIG.model;

console.log('=================================================================');
console.log('PROJECT TUESDAY: Tactical Aggregator & Node B Connectivity Test');
console.log(`Target: http://${targetHost}:${targetPort} | Model: ${targetModel}`);
console.log('=================================================================');

const aggregator = new TelemetryAggregator({
  windowMs: 800,
  maxBatchSize: 5,
  onIncidentReady: async (incident) => {
    console.log('\n[+] Sliding Temporal Window Closed. Synthesized Incident:');
    console.log(`    - Incident ID: ${incident.incidentId}`);
    console.log(`    - Alerts Ingested: ${incident.alertCount}`);
    console.log(`    - Affected Hosts: [${incident.affectedHosts.join(', ')}]`);
    console.log(`    - Correlated Indicators: [${incident.indicators.join(', ')}]`);
    console.log(`    - Associated PIDs: [${incident.activePIDs.join(', ')}]`);
    console.log(`    - Max Severity: ${incident.severityBaseline}`);

    console.log(`\n[*] Dispatching aggregated test prompt to Node B (http://${targetHost}:${targetPort})...`);
    
    const prompt = `You are an automated triage validator. Given this aggregated incident, output JSON with "status": "RECEIVED", "validated": true, "eventCount": ${incident.alertCount}. Incident ID: "${incident.incidentId}".`;

    try {
      const response = await queryNodeB(prompt, {
        host: targetHost,
        port: targetPort,
        model: targetModel,
        format: 'json'
      });
      console.log(`\n[+] Response received from ${targetHost} in ${response.latencyMs}ms!`);
      console.log('    Evaluation Duration:', response.evalDurationMs, 'ms');
      console.log('    JSON Output:', JSON.stringify(response.result));
      console.log('\n>>> SUCCESS: Aggregator & Low-Latency HTTP Dispatch Verified! <<<');
      process.exit(0);
    } catch (err) {
      console.error(`\n[-] HTTP Dispatch Failed: ${err.message}`);
      console.log('\n[TIP]:');
      console.log('  If testing on a single laptop right now without the second laptop connected, run:');
      console.log('  $env:NODE_B_HOST="127.0.0.1"; node sentinel/test_aggregator_network.js');
      console.log('  (Ensure Ollama is running locally and has the model pulled: ollama run ' + targetModel + ')');
      process.exit(1);
    }
  }
});

console.log('\n[*] Ingesting 3 concurrent telemetry events into aggregator...');

aggregator.ingest({
  id: 'AL-101',
  title: 'Suspicious PowerShell Encoded Command',
  targetHost: 'WORKSTATION-01',
  payload: 'powershell.exe -enc SQBFAFgAK... PID 4912',
  severity: 'HIGH',
  mitreTtp: 'T1059.001'
});

setTimeout(() => {
  aggregator.ingest({
    id: 'AL-102',
    title: 'Outbound Beacon to Untrusted Subnet',
    targetHost: 'WORKSTATION-01',
    ioc: '185.220.101.5:443',
    severity: 'CRITICAL',
    mitreTtp: 'T1071'
  });
}, 150);

setTimeout(() => {
  aggregator.ingest({
    id: 'AL-103',
    title: 'Shadow Copy Deletion Attempt',
    targetHost: 'WORKSTATION-01',
    payload: 'vssadmin delete shadows /all /quiet PID 4912',
    severity: 'CRITICAL',
    mitreTtp: 'T1490'
  });
}, 300);
