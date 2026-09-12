"""
TUESDAY RedTeam Drill: Privacy & Secret Harvester Simulation (Python)
Demonstrates Track 4 (Cybersecurity & Privacy).
"""

import os
import time
import requests

SANDBOX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sandbox")
SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://localhost:8090")

def run():
    print("[Privacy Harvester Drill] Initializing realistic telemetry harvesting drill...")
    os.makedirs(SANDBOX, exist_ok=True)

    env_file = os.path.join(SANDBOX, ".env")
    cookie_file = os.path.join(SANDBOX, "session_cookies.sqlite")

    with open(env_file, "w") as f:
        f.write("AWS_SECRET_ACCESS_KEY=mock_akiasimulatedsecret12345\nDATABASE_URL=postgres://admin:supersecret@10.0.0.5/prod\nJWT_SIGNING_KEY=secret_key_88921")
    with open(cookie_file, "w") as f:
        f.write("MOCK_SESSION_TOKEN_BLOB_AUTH_DEV_WORKSTATION_09")

    print("[Privacy Harvester Drill] Staged mock credential canary targets in sandbox.")

    with open(env_file, "r") as f:
        env_content = f.read()
    print(f"[Privacy Harvester Drill] Harvested {len(env_content.splitlines())} secret environment variables.")

    alert = {
        "id": f"HARVEST-{hex(int(time.time()))[2:].upper()}",
        "title": "Unauthorized Credential Harvester & Outbound Telemetry Siphon",
        "source": "Endpoint Behavioral Sensor / Host Watchdog",
        "targetHost": "DEV-WORKSTATION-09 (192.168.20.14)",
        "ioc": "185.220.101.99",
        "payload": f"PID {os.getpid()} inspected {env_file} & spawned outbound POST to https://185.220.101.99/telemetry/harvest"
    }

    print(f"[Privacy Harvester Drill] Forwarding hostile alert into Sentinel ({SENTINEL_URL})...")
    try:
        res = requests.post(f"{SENTINEL_URL}/api/incident", json={"alert": alert, "threshold": 80}, timeout=10)
        data = res.json()
        print(f"[Privacy Harvester Drill] Sentinel Response Status: {data.get('status')} in {data.get('latencySec')}s")
        return data
    except Exception as e:
        print(f"[Privacy Harvester Drill] Could not connect to Sentinel: {e}")
        return {"status": "FAILED", "error": str(e), "alert": alert}

def clean_sandbox():
    print("[Privacy Harvester Drill] Cleaning up staged mock secrets in sandbox...")
    if not os.path.exists(SANDBOX):
        return {"ok": True, "count": 0, "message": "Sandbox directory clean"}

    count = 0
    for f in [".env", "session_cookies.sqlite"]:
        p = os.path.join(SANDBOX, f)
        if os.path.exists(p):
            try:
                os.unlink(p)
                count += 1
            except Exception:
                pass
    print(f"[Privacy Harvester Drill] Cleaned {count} mock files.")
    return {"ok": True, "count": count, "message": f"Cleaned {count} files"}
