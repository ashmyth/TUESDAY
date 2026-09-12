'use strict';
/* ==========================================================================
   TUESDAY RedTeam Drill: Ransomware Shadow-Copy & Canary File Encryption
   Demonstrates T1486 (Data Encrypted for Impact) & T1490 (Inhibit Recovery):
     1. Creates dummy target files in sandbox/canary_files/
     2. Simulates a mock encryption pass (.locked extension + ransom note)
     3. Emits high-fidelity EDR event to Sentinel
   ========================================================================== */

const fs = require('fs');
const path = require('path');

const CANARY_DIR = path.join(__dirname, '..', 'sandbox', 'canary_files');
const SENTINEL_URL = process.env.SENTINEL_URL || 'http://localhost:8090';

async function run() {
  console.log('[Ransomware Drill] Setting up canary files for simulated LockBit encryption...');

  if (!fs.existsSync(CANARY_DIR)) fs.mkdirSync(CANARY_DIR, { recursive: true });

  // Stage 5 dummy text documents
  for (let i = 1; i <= 5; i++) {
    fs.writeFileSync(path.join(CANARY_DIR, `financial_records_2026_q${i}.xlsx`), `CONFIDENTIAL REVENUE DATA - SAMPLE DOCUMENT #${i}`);
  }
  console.log('[Ransomware Drill] Staged 5 sample financial documents.');

  // Simulate encryption staging
  const files = fs.readdirSync(CANARY_DIR);
  for (const file of files) {
    if (file.endsWith('.xlsx')) {
      const oldPath = path.join(CANARY_DIR, file);
      const newPath = path.join(CANARY_DIR, `${file}.LockBit3`);
      fs.renameSync(oldPath, newPath);
    }
  }

  // Drop ransom note
  fs.writeFileSync(path.join(CANARY_DIR, 'RESTORE-YOUR-FILES.README.txt'), `=== LOCKBIT 3.0 RANSOM NOTE ===\nYour files have been encrypted using AES-256.\nContact: 185.220.101.5:443`);
  console.log('[Ransomware Drill] Staged file rename to .LockBit3 and dropped ransom note.');

  // Transmit EDR detection to Sentinel
  const alert = {
    id: `RANSOM-${Date.now().toString(36).toUpperCase()}`,
    title: 'LockBit 3.0 Ransomware Outbreak & Shadow Copy Deletion',
    source: 'CrowdStrike Falcon Sensor / Host EDR',
    targetHost: 'FIN-SERVER-04 (192.168.10.45)',
    ioc: '185.220.101.5',
    payload: 'powershell.exe -enc SQBFAFgAKABOAGUAdw... vssadmin delete shadows /all /quiet & LockBit3.0_Payload.exe'
  };

  try {
    const res = await fetch(`${SENTINEL_URL}/api/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert, threshold: 80 })
    });
    const data = await res.json();
    console.log('[Ransomware Drill] Sentinel SOC Response:', data.status, `(Risk: ${data.riskScore}/100, MTTR: ${data.latencySec}s)`);
    return data;
  } catch (err) {
    console.error('[Ransomware Drill] Connection error to Sentinel:', err.message);
  }
}

function cleanCanary() {
  console.log('[Ransomware Drill] Cleaning up canary sandbox files...');
  if (!fs.existsSync(CANARY_DIR)) return { ok: true, count: 0, message: 'Canary sandbox directory clean' };

  let count = 0;
  const files = fs.readdirSync(CANARY_DIR);
  for (const file of files) {
    try {
      fs.unlinkSync(path.join(CANARY_DIR, file));
      count++;
    } catch (e) {
      console.warn(`[Ransomware Drill] Failed to remove canary file ${file}:`, e.message);
    }
  }
  console.log(`[Ransomware Drill] Cleaned ${count} canary artifact files.`);
  return { ok: true, count, message: `Successfully removed ${count} simulated canary files` };
}

if (require.main === module) {
  const mode = process.argv[2];
  if (mode === 'clean') cleanCanary();
  else run();
}

module.exports = { run, cleanCanary };
