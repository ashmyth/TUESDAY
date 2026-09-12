'use strict';
/* ==========================================================================
   TUESDAY — Connector: Containment Actions
   Phase 0 adapter stub. Production replacements call the REAL network
   actuators. Two highest-value actions to wire first in a pilot:
     - firewallBlock : block the C2/IOC IP on the perimeter firewall
     - hostIsolate   : isolate the endpoint via the EDR agent
   Honest design: every action must be individually enable-able and logged.
   Monitoring-only mode = enforce() returns false until explicitly enabled.
   ========================================================================== */

const PERMISSIONS = {
  FW_BLOCK: false,              // enable in Phase 2 controlled autonomy
  HOST_ISOLATION: false,
  CREDENTIAL_REVOKE: false,     // stays behind the human gate by default
  SESSION_TERMINATE: false,
  SHADOW_COPY_RESTORE: true
};

async function firewallBlock(target, opts) {
  if (!PERMISSIONS.FW_BLOCK) return { executed: false, reason: 'disabled' };
  // STUB — call the firewall API (Palo Alto / FortiGate / PfSense / iptables).
  // e.g. firewall.rules.create({ action: 'deny', src: 'any', dst: target })
  return { executed: true, action: 'FW_BLOCK', target };
}

async function hostIsolate(host, opts) {
  if (!PERMISSIONS.HOST_ISOLATION) return { executed: false, reason: 'disabled' };
  // STUB — call the EDR API (CrowdStrike Falcon / Defender / SentinelOne).
  // e.g. edr.hosts.isolate({ hostname: host })
  return { executed: true, action: 'HOST_ISOLATION', target: host };
}

async function credentialRevoke(identity, opts) {
  if (!PERMISSIONS.CREDENTIAL_REVOKE) return { executed: false, reason: 'disabled' };
  // STUB — call IAM (AWS STS / Entra ID). Kept human-gated in the roadmap.
  return { executed: true, action: 'CREDENTIAL_REVOKE', target: identity };
}

const execute = (action, target) => {
  switch (action) {
    case 'FW_BLOCK': return firewallBlock(target);
    case 'HOST_ISOLATION': return hostIsolate(target);
    case 'CREDENTIAL_REVOKE': return credentialRevoke(target);
    default: return Promise.resolve({ executed: false, reason: 'unknown-action' });
  }
};

module.exports = { execute, PERMISSIONS };
