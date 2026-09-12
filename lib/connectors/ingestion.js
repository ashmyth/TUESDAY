'use strict';
/* ==========================================================================
   TUESDAY — Connector: Alert Ingestion
   Phase 0 adapter stub. Production replacements implement these signatures
   (Syslog / Splunk HEC / Elastic / Microsoft Sentinel / AWS GuardDuty / EDR
   webhooks) and normalize raw telemetry into the RAW ALERT schema the
   orchestrator already consumes:
     { id, source, title, severity, targetHost, ioc, payload, timestamp }
   Replace `normalize()` internals per vendor; the orchestrator is untouched.
   ========================================================================== */

const normalizeAlert = raw => {
  // STUB — integrate the vendor SDK/endpoint here.
  // Example mapping for a Splunk HEC payload:
  //   id: raw._cd || uuid()
  //   source: raw.source || 'SIEM'
  //   title: raw.name
  //   severity: raw.severity
  //   targetHost: raw.host
  //   ioc: raw.ioc
  //   payload: raw.raw_event
  return {
    id: String(raw.id || 'SIEM-' + Date.now()),
    source: raw.source || 'SIEM',
    title: raw.title || 'Unnamed Alert',
    severity: raw.severity || 'high',
    targetHost: raw.targetHost || raw.host || 'UNKNOWN',
    ioc: raw.ioc || null,
    payload: raw.payload || raw.raw_event || '',
    timestamp: raw.timestamp || new Date().toISOString()
  };
};

const startListener = (handler, opts) => {
  // STUB — start a real listener (UDP/TCP syslog, HEC poll, webhook server).
  // Call `handler(normalizeAlert(raw))` for every inbound event.
  console.log(`[connector] ingestion listener starting (vendor=${opts.vendor || 'syslog'})`);
  return { stop: () => {} };
};

module.exports = { normalizeAlert, startListener };
