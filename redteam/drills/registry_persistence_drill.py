"""
TUESDAY RedTeam Drill: Windows Registry Autostart Persistence (Python)
Demonstrates T1547.001 (Boot or Logon Autostart Execution).
"""

import sys
import subprocess

IS_WIN = sys.platform == "win32"
CANARY_NAME = "TUESDAY_Canary_Spyware_Test"
CANARY_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

def run_cmd(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return {"success": proc.returncode == 0, "code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"success": False, "code": 1, "stdout": "", "stderr": str(e)}

def plant_canary():
    if not IS_WIN:
        print("[Registry Persistence Drill] Non-Windows OS detected, skipping native reg.exe.")
        return {"success": True, "mode": "simulated_linux"}

    dummy_payload = r"cmd.exe /c echo Suspicious Autostart Script running from %TEMP%\trojan.bat"
    cmd = f'reg add "{CANARY_KEY}" /v "{CANARY_NAME}" /t REG_SZ /d "{dummy_payload}" /f'
    res = run_cmd(cmd)
    print(f"[Registry Persistence Drill] Planted canary persistence key: {CANARY_NAME} -> {'SUCCESS' if res['success'] else res['stderr']}")
    return res

def clean_canary():
    if not IS_WIN:
        return {"success": True}
    cmd = f'reg delete "{CANARY_KEY}" /v "{CANARY_NAME}" /f'
    res = run_cmd(cmd)
    print(f"[Registry Persistence Drill] Cleaned canary persistence key: {CANARY_NAME} -> {'REMOVED' if res['success'] else res['stderr']}")
    return res

def run():
    print("--- Executing Registry Persistence Attack Simulation ---")
    plant_canary()
    print("Canary persistence key planted in Windows Registry.")
    print("Open Sentinel UI (http://localhost:8090 -> Host EDR) to observe detection or click Clean.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean_canary()
    else:
        run()
