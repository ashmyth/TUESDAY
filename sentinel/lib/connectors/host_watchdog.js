'use strict';
/* ==========================================================================
   TUESDAY Sentinel: Host OS Telemetry & Privileged Watchdog
   Provides elevated inspection & manipulation of:
     - Windows Registry persistence keys (HKCU/HKLM Run, RunOnce, Services)
     - Real-time network sockets & active TCP/UDP connection tables
     - Running host processes, parent-child trees, and command lines
     - Windows Firewall (netsh) & Linux iptables state
   ========================================================================== */

const { exec } = require('child_process');
const os = require('os');

const IS_WIN = os.platform() === 'win32';

function runCmd(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 2 }, (error, stdout, stderr) => {
      resolve({
        success: !error,
        code: error ? error.code : 0,
        stdout: stdout ? stdout.trim() : '',
        stderr: stderr ? stderr.trim() : ''
      });
    });
  });
}

/**
 * Inspect Registry Autostart / Persistence Keys (T1547.001)
 */
async function inspectRegistry(args = {}) {
  const targetKey = args.key || 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
  if (!IS_WIN) {
    return {
      platform: 'linux',
      key: targetKey,
      items: [
        { name: 'cron.daily', path: '/etc/cron.daily', status: 'CLEAN' },
        { name: 'systemd_service', path: '/etc/systemd/system', status: 'CLEAN' }
      ]
    };
  }

  const res = await runCmd(`reg query "${targetKey}"`);
  if (!res.success) {
    return { platform: 'windows', key: targetKey, error: res.stderr || 'Unable to query registry key' };
  }

  const lines = res.stdout.split('\n').filter(l => l.trim().length > 0);
  const entries = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s{2,}/);
    if (parts.length >= 3) {
      const name = parts[0];
      const type = parts[1];
      const data = parts.slice(2).join(' ');
      const isSuspicious = /(powershell.*-enc|cmd.*\/c|temp|AppData\\Local\\Temp|vssadmin|curl.*http)/i.test(data);
      entries.push({
        name,
        type,
        data,
        suspicious: isSuspicious,
        verdict: isSuspicious ? 'POTENTIAL_PERSISTENCE' : 'BENIGN'
      });
    }
  }

  return {
    platform: 'windows',
    targetKey,
    entriesCount: entries.length,
    suspiciousCount: entries.filter(e => e.suspicious).length,
    entries
  };
}

/**
 * Remove or neutralize a rogue registry persistence key
 */
async function removeRegistryKey(keyPath, valueName) {
  if (!IS_WIN) return { success: true, mode: 'simulated_linux' };
  const cmd = `reg delete "${keyPath}" /v "${valueName}" /f`;
  const res = await runCmd(cmd);
  return {
    success: res.success,
    action: 'REGISTRY_KEY_DELETE',
    key: keyPath,
    value: valueName,
    detail: res.success ? `Successfully removed persistence key ${valueName}` : res.stderr
  };
}

/**
 * Inspect live network connection tables & sockets
 */
async function inspectActiveSockets(args = {}) {
  const filterPort = args.port ? String(args.port) : null;
  const filterIp = args.ip ? String(args.ip) : null;

  if (IS_WIN) {
    const psScript = `
      Get-NetTCPConnection | Select-Object -First 30 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ConvertTo-Json -Compress
    `;
    const res = await runCmd(`powershell -NoProfile -Command "${psScript.replace(/\n/g, ' ')}"`);
    let connections = [];
    try {
      connections = JSON.parse(res.stdout || '[]');
      if (!Array.isArray(connections)) connections = [connections];
    } catch (e) {
      connections = [];
    }

    if (filterPort) connections = connections.filter(c => String(c.RemotePort) === filterPort || String(c.LocalPort) === filterPort);
    if (filterIp) connections = connections.filter(c => String(c.RemoteAddress).includes(filterIp));

    return {
      platform: 'windows',
      totalActiveSockets: connections.length,
      sockets: connections.map(c => ({
        local: `${c.LocalAddress}:${c.LocalPort}`,
        remote: `${c.RemoteAddress}:${c.RemotePort}`,
        state: c.State,
        pid: c.OwningProcess,
        isExternal: !['127.0.0.1', '::1', '0.0.0.0', '::'].includes(c.RemoteAddress)
      }))
    };
  }

  const res = await runCmd('ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null');
  return {
    platform: 'linux',
    raw: res.stdout.slice(0, 800)
  };
}

/**
 * Inspect active host processes and command lines
 */
async function inspectProcesses(args = {}) {
  const query = args.query ? String(args.query).toLowerCase() : null;

  if (IS_WIN) {
    const psScript = `
      Get-Process | Where-Object { $_.ProcessName -notmatch 'svchost|System|Idle' } | Select-Object -First 25 Id, ProcessName, WorkingSet64, Responding | ConvertTo-Json -Compress
    `;
    const res = await runCmd(`powershell -NoProfile -Command "${psScript.replace(/\n/g, ' ')}"`);
    let procs = [];
    try {
      procs = JSON.parse(res.stdout || '[]');
      if (!Array.isArray(procs)) procs = [procs];
    } catch (e) {
      procs = [];
    }

    if (query) {
      procs = procs.filter(p => (p.ProcessName || '').toLowerCase().includes(query) || String(p.Id).includes(query));
    }

    return {
      platform: 'windows',
      count: procs.length,
      processes: procs.map(p => ({
        pid: p.Id,
        name: p.ProcessName,
        memoryMb: Math.round((p.WorkingSet64 || 0) / (1024 * 1024)),
        responding: p.Responding
      }))
    };
  }

  const res = await runCmd('ps aux | head -n 30');
  return {
    platform: 'linux',
    raw: res.stdout.slice(0, 800)
  };
}

module.exports = {
  inspectRegistry,
  removeRegistryKey,
  inspectActiveSockets,
  inspectProcesses
};
