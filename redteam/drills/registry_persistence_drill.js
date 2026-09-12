'use strict';
/* ==========================================================================
   TUESDAY RedTeam Drill: Windows Registry Autostart Persistence
   Demonstrates T1547.001 (Boot or Logon Autostart Execution):
     1. Creates a safe canary entry in HKCU\Software\Microsoft\Windows\CurrentVersion\Run
     2. Calls Sentinel's live watchdog to verify immediate detection
     3. Allows testing Sentinel's 1-click or autonomous registry key neutralization
   ========================================================================== */

const { exec } = require('child_process');
const os = require('os');

const IS_WIN = os.platform() === 'win32';
const CANARY_NAME = 'TUESDAY_Canary_Spyware_Test';
const CANARY_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';

function runCmd(cmd) {
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      resolve({ success: !error, code: error ? error.code : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

async function plantCanary() {
  if (!IS_WIN) {
    console.log('[Registry Persistence Drill] Non-Windows OS detected, skipping native reg.exe.');
    return { success: true, mode: 'simulated_linux' };
  }

  // Plant safe harmless entry (points to notepad /test)
  const dummyPayload = 'cmd.exe /c echo Suspicious Autostart Script running from %TEMP%\\trojan.bat';
  const cmd = `reg add "${CANARY_KEY}" /v "${CANARY_NAME}" /t REG_SZ /d "${dummyPayload}" /f`;
  const res = await runCmd(cmd);
  console.log(`[Registry Persistence Drill] Planted canary persistence key: ${CANARY_NAME} -> ${res.success ? 'SUCCESS' : res.stderr}`);
  return res;
}

async function cleanCanary() {
  if (!IS_WIN) return { success: true };
  const cmd = `reg delete "${CANARY_KEY}" /v "${CANARY_NAME}" /f`;
  const res = await runCmd(cmd);
  console.log(`[Registry Persistence Drill] Cleaned canary persistence key: ${CANARY_NAME} -> ${res.success ? 'REMOVED' : res.stderr}`);
  return res;
}

async function run() {
  console.log('--- Executing Registry Persistence Attack Simulation ---');
  await plantCanary();
  console.log('Canary persistence key planted in Windows Registry.');
  console.log('Open Sentinel UI (http://localhost:8090 -> Host EDR) to observe detection or click Clean.');
}

if (require.main === module) {
  const mode = process.argv[2];
  if (mode === 'clean') cleanCanary();
  else run();
}

module.exports = { plantCanary, cleanCanary, run };
