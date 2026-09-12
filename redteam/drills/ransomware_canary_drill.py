"""
TUESDAY RedTeam Drill: Ransomware Shadow-Copy & Canary File Encryption (Python)
Demonstrates T1486 (Data Encrypted for Impact) & T1490 (Inhibit Recovery).
"""

import os
import time
import requests

CANARY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sandbox", "canary_files")
SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://localhost:8090")

def run():
    print("[Ransomware Drill] Setting up canary files for simulated LockBit encryption...")
    os.makedirs(CANARY_DIR, exist_ok=True)

    # Stage 5 sample documents
    for i in range(1, 6):
        path = os.path.join(CANARY_DIR, f"financial_records_2026_q{i}.xlsx")
        with open(path, "w") as f:
            f.write(f"CONFIDENTIAL REVENUE DATA - SAMPLE DOCUMENT #{i}")
    print("[Ransomware Drill] Staged 5 sample financial documents.")

    # Simulate encryption pass by renaming
    for fname in os.listdir(CANARY_DIR):
        if fname.endswith(".xlsx"):
            old_p = os.path.join(CANARY_DIR, fname)
            new_p = os.path.join(CANARY_DIR, f"{fname}.LockBit3")
            os.rename(old_p, new_p)

    # Drop ransom note
    note_p = os.path.join(CANARY_DIR, "RESTORE-YOUR-FILES.README.txt")
    with open(note_p, "w") as f:
        f.write("=== LOCKBIT 3.0 RANSOM NOTE ===\nYour files have been encrypted using AES-256.\nContact: 185.220.101.5:443")
    print("[Ransomware Drill] Staged file rename to .LockBit3 and dropped ransom note.")

    # Transmit EDR detection to Sentinel
    alert = {
        "id": f"RANSOM-{hex(int(time.time()))[2:].upper()}",
        "title": "LockBit 3.0 Ransomware Outbreak & Shadow Copy Deletion",
        "source": "CrowdStrike Falcon Sensor / Host EDR",
        "targetHost": "FIN-SERVER-04 (192.168.10.45)",
        "ioc": "185.220.101.5",
        "payload": "powershell.exe -enc SQBFAFgAKABOAGUAdw... vssadmin delete shadows /all /quiet & LockBit3.0_Payload.exe"
    }

    try:
        res = requests.post(f"{SENTINEL_URL}/api/incident", json={"alert": alert, "threshold": 80}, timeout=10)
        data = res.json()
        print(f"[Ransomware Drill] Sentinel SOC Response: {data.get('status')} (Risk: {data.get('riskScore')}/100, MTTR: {data.get('latencySec')}s)")
        return data
    except Exception as e:
        print(f"[Ransomware Drill] Could not connect to Sentinel: {e}")
        return {"status": "FAILED", "error": str(e), "alert": alert}

def clean_canary():
    print("[Ransomware Drill] Cleaning canary files in sandbox...")
    if not os.path.exists(CANARY_DIR):
        return {"ok": True, "count": 0, "message": "Canary directory does not exist"}

    count = 0
    for fname in os.listdir(CANARY_DIR):
        p = os.path.join(CANARY_DIR, fname)
        try:
            if os.path.isfile(p):
                os.unlink(p)
                count += 1
        except Exception:
            pass
    print(f"[Ransomware Drill] Cleaned {count} canary files.")
    return {"ok": True, "count": count, "message": f"Cleaned {count} files"}
