'use strict';
/* ==========================================================================
   TUESDAY Sentinel: Autonomous Host Defense Watchdog Daemon
   Continuously monitors local system state in real time:
     1. Live Network Sockets: Scans TCP/UDP connections for unauthorized C2
     2. Windows Registry Autostart: Hunts for spyware & persistence keys
     3. Running Processes: Inspects anomalous or runaway binaries
   When a hostile indicator is discovered, it autonomously initiates
   a Deep Agent investigation & executes containment.
   ========================================================================== */

const watchdog = require('./connectors/host_watchdog');
const containment = require('./connectors/containment');
const orchestrator = require('./orchestrator');
const store = require('./store');

class HostWatchdogDaemon {
  constructor(opts = {}) {
    this.intervalMs = opts.intervalMs || 6000;
    this.enabled = opts.enabled !== false;
    this.timer = null;
    this.lastScan = null;
    this.recentDetections = new Set();
    this.subscribers = new Set(); // SSE event listeners
  }

  start() {
    if (this.timer) return;
    this.enabled = true;
    console.log(`[Sentinel Watchdog Daemon] Live host monitoring started (interval: ${this.intervalMs}ms)`);
    this.timer = setInterval(() => this.cycle(), this.intervalMs);
    this.cycle(); // immediate first scan
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.enabled = false;
    console.log('[Sentinel Watchdog Daemon] Live host monitoring paused');
  }

  subscribe(fn) {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  broadcast(event, payload) {
    for (const fn of this.subscribers) {
      try { fn(event, payload); } catch (e) {}
    }
  }

  async getTelemetry() {
    const [sockets, registry, processes] = await Promise.all([
      watchdog.inspectActiveSockets(),
      watchdog.inspectRegistry(),
      watchdog.inspectProcesses()
    ]);

    this.lastScan = {
      timestamp: new Date().toISOString(),
      sockets,
      registry,
      processes
    };

    return this.lastScan;
  }

  async cycle() {
    try {
      const telemetry = await this.getTelemetry();
      this.broadcast('telemetry', telemetry);

      // 1. Analyze Active Sockets for Suspicious Outbound Egress / C2
      const knownSuspiciousIps = ['185.220.101', '193.142.146', '45.154.255', '91.240.118'];
      const suspiciousSockets = (telemetry.sockets.sockets || []).filter(s => {
        return s.isExternal && knownSuspiciousIps.some(prefix => s.remote.startsWith(prefix));
      });

      for (const sock of suspiciousSockets) {
        const key = `SOCK_${sock.remote}_${sock.pid}`;
        if (!this.recentDetections.has(key)) {
          this.recentDetections.add(key);
          await this.handleDetectedThreat({
            type: 'SOCKET_C2_CONNECTION',
            title: `Unauthorized Outbound C2 Socket to ${sock.remote}`,
            source: 'Sentinel Live Socket Sniffer',
            targetHost: `Local Endpoint (PID: ${sock.pid})`,
            ioc: sock.remote.split(':')[0],
            payload: `TCP ${sock.local} -> ${sock.remote} (State: ${sock.state}, PID: ${sock.pid})`
          });
        }
      }

      // 2. Analyze Windows Registry for Autostart Spyware / Trojans
      const suspiciousReg = (telemetry.registry.entries || []).filter(e => e.suspicious);
      for (const reg of suspiciousReg) {
        const key = `REG_${reg.name}_${reg.data}`;
        if (!this.recentDetections.has(key)) {
          this.recentDetections.add(key);
          await this.handleDetectedThreat({
            type: 'REGISTRY_PERSISTENCE',
            title: `Suspicious Autostart Run Key: "${reg.name}"`,
            source: 'Sentinel Windows Registry Monitor',
            targetHost: 'Local Machine Registry (HKCU Run)',
            ioc: 'Local Registry Host',
            payload: `Key: ${telemetry.registry.targetKey} | Name: ${reg.name} | Data: ${reg.data}`
          });
        }
      }
    } catch (e) {
      console.error('[Sentinel Watchdog Daemon] Error during cycle:', e.message);
    }
  }

  async handleDetectedThreat(threatAlert) {
    console.log(`[Sentinel Watchdog Alert] Host Threat Discovered: ${threatAlert.title}`);
    this.broadcast('threat_detected', threatAlert);
    store.addAudit('WATCHDOG_DETECTION', `Host anomaly triggered alert: ${threatAlert.title}`);

    // Trigger autonomous investigation
    try {
      await orchestrator.runInvestigation(threatAlert, {
        emit: (ev) => this.broadcast('investigation_stream', ev),
        threshold: 80
      });
    } catch (e) {
      console.error('[Sentinel Watchdog Alert] Investigation error:', e.message);
    }
  }

  async manualBlockIP(ip) {
    return await containment.firewallBlock(ip, { dryRun: false });
  }

  async manualKillProcess(pid) {
    return await containment.processTerminate(pid, { dryRun: false });
  }

  async manualCleanRegistryKey(key, valueName) {
    return await watchdog.removeRegistryKey(key, valueName);
  }
}

const daemonInstance = new HostWatchdogDaemon();
module.exports = daemonInstance;
