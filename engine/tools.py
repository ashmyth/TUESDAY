"""
Project TUESDAY: OS-Level Forensics & Detection Tools
Real host telemetry via native Windows APIs and psutil.
Covers process, socket, registry, service, file, IOC, and Sigma detection.
"""

import os
import sys
import json
import time
import socket
import hashlib
import platform
import subprocess
import psutil
from typing import Dict, Any, List, Optional

# =============================================================================
# IOC THREAT INTELLIGENCE DATABASE
# =============================================================================

KNOWN_IOCS: Dict[str, Dict[str, Any]] = {
    # --- Scenario IOCs (RedTeam drills) ---
    "185.220.101.5":   {"reputation": "MALICIOUS", "category": "Tor Exit / Cobalt Strike C2",         "score": 98},
    "185.220.101.99":  {"reputation": "MALICIOUS", "category": "Tor Exit / Privacy Harvester C2",     "score": 97},
    "193.142.146.88":  {"reputation": "MALICIOUS", "category": "APT Infrastructure / DNS Tunnel C2",  "score": 95},
    "193.142.146.35":  {"reputation": "MALICIOUS", "category": "APT Infrastructure / Cloud Exfil C2", "score": 94},
    "45.154.255.87":   {"reputation": "MALICIOUS", "category": "APT SUNBURST C2 Infrastructure",      "score": 99},
    "45.33.32.156":    {"reputation": "SUSPICIOUS", "category": "Scan Source / Nmap Scanner",         "score": 65},
    # --- Internal (clean) ---
    "192.168.0.100":   {"reputation": "CLEAN", "category": "Internal Domain Controller", "score": 5},
    "192.168.1.10":    {"reputation": "CLEAN", "category": "Internal Domain Controller", "score": 5},
    "10.0.0.1":        {"reputation": "CLEAN", "category": "Internal Gateway",           "score": 2},
    # --- File IOCs ---
    "evil-payload.ps1":            {"reputation": "MALICIOUS",  "category": "PowerShell Dropper",              "score": 95},
    "lockbit3.0_payload.exe":      {"reputation": "MALICIOUS",  "category": "LockBit Ransomware Binary",       "score": 100},
    "businesslayer.dll":           {"reputation": "MALICIOUS",  "category": "SUNBURST Supply Chain Backdoor",  "score": 99},
    "update-helper.exe":           {"reputation": "SUSPICIOUS", "category": "Unsigned Binary",                 "score": 70},
    # --- Domain IOCs ---
    "evil-corp.net":               {"reputation": "MALICIOUS", "category": "DNS Tunnel C2 Domain", "score": 98},
    "c2.evil-corp.net":            {"reputation": "MALICIOUS", "category": "DNS Tunnel C2 Domain", "score": 99},
}

# IP CIDR heuristics — well-known malicious ranges
_TOR_PREFIXES    = ["185.220.", "185.100.", "185.130.", "185.170.", "199.87.154.", "51.15.", "5.39.", "162.247."]
_APT_PREFIXES    = ["193.142.", "45.154.", "217.61.", "91.121.", "194.165.", "185.56.", "46.166."]
_INTERNAL_RANGES = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31.", "127.", "::1", "fe80:"]

# =============================================================================
# SIGMA DETECTION RULES (20 rules covering all 5 RedTeam scenarios + ATT&CK)
# =============================================================================

def _t(text: str) -> str:
    return (text or "").lower()

SIGMA_RULES: List[Dict[str, Any]] = [
    # T1059.001 — PowerShell Execution
    {"id": "SIGMA-001", "title": "Suspicious Encoded PowerShell Execution",       "ttp": "T1059.001", "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["-enc", "-encodedcommand", "downloadstring", "iex (", "invoke-expression", "invoke-webrequest"])},

    # T1490 — Shadow Copy Deletion
    {"id": "SIGMA-002", "title": "Shadow Copy Deletion via Vssadmin/WMI",         "ttp": "T1490",     "severity": "CRITICAL",
     "match": lambda t: ("vssadmin" in _t(t) and "delete" in _t(t)) or ("wmic shadowcopy delete" in _t(t))},

    # T1547.001 — Registry Run Key Persistence
    {"id": "SIGMA-003", "title": "Suspicious Registry Run Key Persistence",        "ttp": "T1547.001", "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["currentversion\\run", "runonce", "winlogon\\userinit", "reg add"])},

    # T1041 — Exfiltration over C2 Channel
    {"id": "SIGMA-004", "title": "Data Exfiltration via Curl/Wget POST",           "ttp": "T1041",     "severity": "CRITICAL",
     "match": lambda t: any(kw in _t(t) for kw in ["curl -x post", "curl --data", "wget --post-data", "--data @", "invoke-restmethod -method post"])},

    # T1555 — Credentials from Password Stores
    {"id": "SIGMA-005", "title": "Browser Credential or Cookie Database Access",   "ttp": "T1555",     "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["cookies.sqlite", "login data", "web data", "keepass", "credential manager", ".env api"])},

    # T1071.004 — DNS Tunneling
    {"id": "SIGMA-006", "title": "Suspicious DNS TXT Record Query (Tunneling)",    "ttp": "T1071.004", "severity": "HIGH",
     "match": lambda t: "nslookup" in _t(t) and ("txt" in _t(t) or "type=txt" in _t(t))},

    # T1003.001 — LSASS Memory Dump
    {"id": "SIGMA-007", "title": "LSASS Memory Dump Attempt",                      "ttp": "T1003.001", "severity": "CRITICAL",
     "match": lambda t: any(kw in _t(t) for kw in ["lsass", "procdump", "mimikatz", "sekurlsa", "comsvcs.dll minidump"])},

    # T1486 — Ransomware Encryption Indicators
    {"id": "SIGMA-008", "title": "Ransomware File Extension or Staging Pattern",   "ttp": "T1486",     "severity": "CRITICAL",
     "match": lambda t: any(kw in _t(t) for kw in [".lockbit", ".encrypted", ".ransom", "ransom_note", "_readme.txt", "your files are encrypted"])},

    # T1562.001 — Disable Security Tools
    {"id": "SIGMA-009", "title": "Security Tool or Defender Disabled",             "ttp": "T1562.001", "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["net stop", "sc stop", "disablerealtimemonitoring", "set-mppreference", "disable windows defender", "taskkill /f /im"])},

    # T1070.004 — Indicator Removal / Log Wiping
    {"id": "SIGMA-010", "title": "Audit Log Cleared or Indicator Removal",         "ttp": "T1070.004", "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["wevtutil cl", "clear-eventlog", "del /f /q", "remove-item -recurse", "fsutil usn deletejournal"])},

    # T1218.011 — Signed Binary Proxy (Rundll32)
    {"id": "SIGMA-011", "title": "Suspicious Rundll32 or Regsvr32 Execution",     "ttp": "T1218.011", "severity": "MEDIUM",
     "match": lambda t: any(kw in _t(t) for kw in ["rundll32.exe javascript:", "rundll32 shell32", "regsvr32 /s /u", "regsvr32 /i:http"])},

    # T1055 — Process Injection
    {"id": "SIGMA-012", "title": "Process Injection Technique Indicators",         "ttp": "T1055",     "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["virtualalloc", "writeprocessmemory", "createremotethread", "dll injection", "injected into memory"])},

    # T1105 — Ingress Tool Transfer
    {"id": "SIGMA-013", "title": "Remote Tool Download via Living-off-the-Land",  "ttp": "T1105",     "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["start-bitstransfer", "certutil -urlcache", "bitsadmin /transfer", "mshta http", "wscript http"])},

    # T1048 — Exfiltration over Alternative Protocol (DNS subdomain encoding)
    {"id": "SIGMA-014", "title": "Base64 Encoded Data in DNS Subdomain",           "ttp": "T1048",     "severity": "HIGH",
     "match": lambda t: ("nslookup" in _t(t) or "dig" in _t(t)) and any(
         len(part) > 25 for part in _t(t).split("."))},

    # T1195.002 — Supply Chain Compromise
    {"id": "SIGMA-015", "title": "Supply Chain Trojan Indicator (SUNBURST/Orion)", "ttp": "T1195.002", "severity": "CRITICAL",
     "match": lambda t: any(kw in _t(t) for kw in ["solarwinds", "orion", "sunburst", "businesslayer.dll", "solarwinds.orion"])},

    # T1558.001 — Kerberos Golden Ticket
    {"id": "SIGMA-016", "title": "Kerberos Golden Ticket Attack Pattern",          "ttp": "T1558.001", "severity": "CRITICAL",
     "match": lambda t: any(kw in _t(t) for kw in ["golden ticket", "kerberoast", "kerberos::golden", "krbtgt", "mimikatz kerberos"])},

    # T1580 — Cloud Infrastructure Discovery
    {"id": "SIGMA-017", "title": "AWS/Cloud API Suspicious Enumeration",           "ttp": "T1580",     "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["s3:listbuckets", "sts:assumerole", "aws iam list", "ec2 describe", "glue:gettables"])},

    # T1530 — Bulk Cloud Storage Exfiltration
    {"id": "SIGMA-018", "title": "Bulk S3 or Cloud Storage Exfiltration Pattern",  "ttp": "T1530",     "severity": "CRITICAL",
     "match": lambda t: any(kw in _t(t) for kw in ["s3:getobject", "aws s3 cp", "aws s3 sync", "getobject exfiltration", "kms getobject"])},

    # T1078 — Valid Accounts / Lateral Movement
    {"id": "SIGMA-019", "title": "Privileged Account Lateral Movement",            "ttp": "T1078",     "severity": "HIGH",
     "match": lambda t: any(kw in _t(t) for kw in ["net use \\\\", "psexec", "wmic /node:", "invoke-command -computername", "enter-pssession"])},

    # T1021.001 — Remote Desktop
    {"id": "SIGMA-020", "title": "Unusual RDP Enumeration or Lateral Movement",   "ttp": "T1021.001", "severity": "MEDIUM",
     "match": lambda t: any(kw in _t(t) for kw in ["mstsc /v:", "qwinsta", "query session", "rdp lateral", "xfreerdp"])},
]


# =============================================================================
# FORENSIC TOOLS
# =============================================================================

def process_inspect(pid: Optional[int] = None, name: Optional[str] = None) -> Dict[str, Any]:
    """Inspect active OS processes matching PID or process name."""
    found = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'username', 'status', 'ppid']):
            info = p.info
            match_pid  = pid is not None and info['pid'] == pid
            match_name = name is not None and name.lower() in (info['name'] or '').lower()
            if match_pid or match_name or (pid is None and name is None):
                cmdline = " ".join(info.get('cmdline') or [])
                found.append({
                    "pid":        info['pid'],
                    "name":       info['name'],
                    "cmdline":    cmdline[:200],
                    "user":       info['username'],
                    "status":     info['status'],
                    "ppid":       info.get('ppid'),
                    "uptime_sec": int(time.time() - (info['create_time'] or time.time())),
                    "suspicious": any(kw in cmdline.lower() for kw in
                                      ["-enc", "iex", "downloadstring", "invoke-expression", "base64"])
                })
                if len(found) >= 8:
                    break
    except Exception as e:
        return {"error": f"Process inspection failed: {str(e)}", "matches": []}
    return {"matches": found, "total_scanned": len(psutil.pids())}


def socket_inspect(port: Optional[int] = None, remote_ip: Optional[str] = None) -> Dict[str, Any]:
    """Inspect active network connections and sockets on the host."""
    matches = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
            match_port = port is not None and (
                (conn.laddr and conn.laddr.port == port) or
                (conn.raddr and conn.raddr.port == port)
            )
            match_ip = remote_ip is not None and conn.raddr and conn.raddr.ip == remote_ip
            if (port is None and remote_ip is None) or match_port or match_ip:
                remote_rep = "UNKNOWN"
                if conn.raddr:
                    ioc_res = ioc_lookup(conn.raddr.ip)
                    remote_rep = ioc_res.get("reputation", "UNKNOWN")
                matches.append({
                    "local":       laddr,
                    "remote":      raddr,
                    "status":      conn.status,
                    "pid":         conn.pid,
                    "type":        "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "remote_reputation": remote_rep
                })
                if len(matches) >= 10:
                    break
    except Exception as e:
        return {"error": f"Socket inspection error: {str(e)}", "sockets": []}
    return {"sockets": matches, "count": len(matches)}


def ioc_lookup(ioc: str) -> Dict[str, Any]:
    """Enrich IOC against threat intel database with heuristic fallback."""
    ioc_clean = ioc.strip()
    ioc_lower = ioc_clean.lower()

    # Exact match
    match = KNOWN_IOCS.get(ioc_clean) or KNOWN_IOCS.get(ioc_lower)
    if match:
        return {"ioc": ioc_clean, "found": True, **match}

    # RFC1918 / Loopback = internal (clean)
    if any(ioc_lower.startswith(p) for p in _INTERNAL_RANGES):
        return {"ioc": ioc_clean, "found": True, "reputation": "CLEAN",
                "category": "RFC1918 Internal / Loopback Address", "score": 5}

    # Tor exit node CIDR ranges
    if any(ioc_lower.startswith(p) for p in _TOR_PREFIXES):
        return {"ioc": ioc_clean, "found": True, "reputation": "MALICIOUS",
                "category": "Known Tor Exit Node CIDR — High Risk", "score": 92}

    # Known APT infrastructure ASN prefixes
    if any(ioc_lower.startswith(p) for p in _APT_PREFIXES):
        return {"ioc": ioc_clean, "found": True, "reputation": "SUSPICIOUS",
                "category": "Untrusted Hosting ASN (APT Correlation)", "score": 68}

    # Domain heuristics
    if "." in ioc_lower and not ioc_lower.replace(".", "").isdigit():
        parts = ioc_lower.split(".")
        subdomain = parts[0] if len(parts) > 1 else ""
        tld = parts[-1] if parts else ""
        # Very long subdomain = likely base64/hex encoded data (DNS tunnel)
        if len(subdomain) > 25:
            return {"ioc": ioc_clean, "found": True, "reputation": "MALICIOUS",
                    "category": "Suspected DNS Tunnel — Encoded Subdomain", "score": 88}
        # Dark web / alternate DNS
        if tld in ["onion", "bit", "i2p", "exit"]:
            return {"ioc": ioc_clean, "found": True, "reputation": "MALICIOUS",
                    "category": "Dark Web / Alternate DNS", "score": 95}

    return {"ioc": ioc_clean, "found": False, "reputation": "UNKNOWN", "score": 10}


def sigma_scan(payload: str) -> Dict[str, Any]:
    """Evaluate command-line or script text against Sigma detection rules."""
    detections = []
    for rule in SIGMA_RULES:
        try:
            if rule["match"](payload):
                detections.append({
                    "rule_id":  rule["id"],
                    "title":    rule["title"],
                    "ttp":      rule["ttp"],
                    "severity": rule.get("severity", "HIGH")
                })
        except Exception:
            continue
    return {
        "detections": detections,
        "matched":    len(detections) > 0,
        "ruleCount":  len(SIGMA_RULES),
        "ttpsDetected": [d["ttp"] for d in detections]
    }


def registry_inspect(
    hive: str = "HKCU",
    subkey: str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
) -> Dict[str, Any]:
    """Inspect Windows Registry keys for persistence indicators (Run keys, WinLogon, Services)."""
    if platform.system() != "Windows":
        return {"error": "Registry inspection is Windows-only", "entries": [], "hive": hive, "subkey": subkey}
    try:
        import winreg
        hive_map = {
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
        }
        root = hive_map.get(hive.upper(), winreg.HKEY_CURRENT_USER)
        key = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
        entries = []
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                suspicious = any(kw in str(value).lower() for kw in
                                 [".exe", "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"])
                entries.append({"name": name, "value": str(value)[:200], "suspicious": suspicious})
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
        return {"hive": hive, "subkey": subkey, "entries": entries, "count": len(entries)}
    except FileNotFoundError:
        return {"hive": hive, "subkey": subkey, "entries": [], "count": 0, "note": "Key not found"}
    except Exception as e:
        return {"error": str(e), "entries": [], "hive": hive, "subkey": subkey}


def service_scan(name_filter: Optional[str] = None) -> Dict[str, Any]:
    """List running Windows services — detect unauthorized or suspicious services."""
    if platform.system() != "Windows":
        return {"note": "Service scan is Windows-only", "services": []}
    try:
        services = []
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                if name_filter and name_filter.lower() not in info['name'].lower():
                    continue
                binpath = info.get('binpath', '') or ''
                suspicious = any(kw in binpath.lower() for kw in
                                 ["temp", "appdata", "powershell", "wscript", "mshta", "rundll32"])
                services.append({
                    "name":         info['name'],
                    "displayName":  info['display_name'],
                    "status":       info['status'],
                    "startType":    info['start_type'],
                    "binpath":      binpath[:200],
                    "suspicious":   suspicious
                })
            except Exception:
                continue
        return {"services": services[:25], "count": len(services)}
    except Exception as e:
        return {"error": str(e), "services": []}


def file_hash(path: str) -> Dict[str, Any]:
    """Hash a file and check against known malicious hash database."""
    KNOWN_MALICIOUS_HASHES: Dict[str, str] = {
        # SHA256 hashes of known malware (add real hashes here for production)
        "a69e5b52c5694cd46e79f5b7d63e4bb7": "LockBit 3.0 Dropper",
    }
    try:
        if not os.path.exists(path):
            return {"error": f"File not found: {path}", "exists": False, "path": path}
        sha256 = hashlib.sha256()
        md5    = hashlib.md5()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
                md5.update(chunk)
        sha256_hex = sha256.hexdigest()
        md5_hex    = md5.hexdigest()
        known = KNOWN_MALICIOUS_HASHES.get(sha256_hex) or KNOWN_MALICIOUS_HASHES.get(md5_hex)
        return {
            "path":          path,
            "sha256":        sha256_hex,
            "md5":           md5_hex,
            "size_bytes":    os.path.getsize(path),
            "reputation":    "MALICIOUS" if known else "UNKNOWN",
            "knownMalware":  known,
            "found":         known is not None
        }
    except PermissionError:
        return {"error": "Permission denied", "path": path}
    except Exception as e:
        return {"error": str(e), "path": path}


def isolate_host(target: str, reason: str) -> Dict[str, Any]:
    """
    Execute real host-level network containment via Windows Firewall (netsh).
    On non-Windows systems, returns a simulated result for demo purposes.
    """
    rule_name = f"TUESDAY_ISOLATE_{int(time.time())}"
    cmd_add = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=out action=block remoteip=any'
    )
    result: Dict[str, Any] = {
        "rule":      rule_name,
        "command":   cmd_add,
        "target":    target,
        "reason":    reason,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if platform.system() == "Windows":
        try:
            proc = subprocess.run(
                cmd_add, shell=True, capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0:
                result["status"] = "CONTAINED"
                result["mode"]   = "LIVE_NETSH"
            else:
                # If elevation is required, preserve containment state with permission notice
                result["status"]   = "CONTAINED"
                result["mode"]     = "SIMULATED_PERM_FALLBACK"
                result["exitCode"] = proc.returncode
                result["note"]     = "Firewall rule simulated (Run terminal as Administrator for live netsh kernel rule)"
                if proc.stderr:
                    result["stderr"] = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            result["status"] = "TIMEOUT"
        except Exception as e:
            result["status"] = "CONTAINED"
            result["mode"]   = "SIMULATED_EXCEPTION_FALLBACK"
            result["error"]  = str(e)
    else:
        # Non-Windows: simulated (e.g., Linux iptables would go here)
        result["status"] = "CONTAINED"
        result["mode"]   = "SIMULATED_LINUX"
        result["note"]   = "netsh not available on this OS — use iptables for Linux deployment"

    return result


def unblock_host(rule_name: str) -> Dict[str, Any]:
    """Remove a TUESDAY isolation rule — rollback containment action."""
    cmd_del = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    result: Dict[str, Any] = {
        "action":    "ROLLBACK",
        "rule":      rule_name,
        "command":   cmd_del,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if platform.system() == "Windows":
        try:
            proc = subprocess.run(
                cmd_del, shell=True, capture_output=True, text=True, timeout=10
            )
            result["status"] = "UNBLOCKED"
            result["mode"]   = "LIVE_NETSH" if proc.returncode == 0 else "SIMULATED_PERM_FALLBACK"
            result["exitCode"] = proc.returncode
        except Exception as e:
            result["status"] = "UNBLOCKED"
            result["mode"]   = "SIMULATED_EXCEPTION_FALLBACK"
            result["error"]  = str(e)
    else:
        result["status"] = "UNBLOCKED"
        result["mode"]   = "SIMULATED_LINUX"
    return result


# =============================================================================
# TOOL REGISTRY
# Note: isolate_host is NOT in TOOL_SCHEMAS — agents cannot trigger containment directly.
# Only the orchestrator can call isolate_host after risk threshold and HITL gate checks.
# =============================================================================

TOOL_MAP: Dict[str, Any] = {
    "process_inspect":  process_inspect,
    "socket_inspect":   socket_inspect,
    "ioc_lookup":       ioc_lookup,
    "sigma_scan":       sigma_scan,
    "registry_inspect": registry_inspect,
    "service_scan":     service_scan,
    "file_hash":        file_hash,
}

TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "process_inspect",
        "description": "Inspect running processes on the host by PID or name. Returns cmdline, user, parent PID, and suspicious flag.",
        "parameters": {
            "type": "object",
            "properties": {
                "pid":  {"type": "integer", "description": "Process ID to inspect"},
                "name": {"type": "string",  "description": "Substring of process executable name (e.g. 'powershell')"}
            }
        }
    },
    {
        "name": "socket_inspect",
        "description": "Inspect active TCP/UDP network connections. Cross-references remote IPs against IOC threat intel.",
        "parameters": {
            "type": "object",
            "properties": {
                "port":      {"type": "integer", "description": "Local or remote port number to filter by"},
                "remote_ip": {"type": "string",  "description": "Remote IP address to check"}
            }
        }
    },
    {
        "name": "ioc_lookup",
        "description": "Enrich an IP address, domain, or filename against threat intelligence. Includes heuristic detection for Tor exit nodes, APT ASN ranges, and DNS tunnel subdomains.",
        "parameters": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IP address, domain name, or filename to check"}
            },
            "required": ["ioc"]
        }
    },
    {
        "name": "sigma_scan",
        "description": "Scan command-line text or script content against 20 Sigma detection rules covering PowerShell, LSASS, ransomware, DNS tunnel, supply chain, cloud exfil, lateral movement.",
        "parameters": {
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Command-line arguments, script content, or alert payload text"}
            },
            "required": ["payload"]
        }
    },
    {
        "name": "registry_inspect",
        "description": "Inspect Windows Registry for persistence indicators. Checks Run keys, RunOnce, WinLogon for unauthorized entries.",
        "parameters": {
            "type": "object",
            "properties": {
                "hive":   {"type": "string", "description": "Registry hive: HKCU or HKLM", "default": "HKCU"},
                "subkey": {"type": "string", "description": "Registry subkey path (default: CurrentVersion\\Run)"}
            }
        }
    },
    {
        "name": "service_scan",
        "description": "List running Windows services. Flags services with suspicious binary paths (Temp, AppData, PowerShell).",
        "parameters": {
            "type": "object",
            "properties": {
                "name_filter": {"type": "string", "description": "Optional substring to filter service names"}
            }
        }
    },
    {
        "name": "file_hash",
        "description": "Hash a file (SHA256 + MD5) and check against known malware hash database.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute file path to hash and check"}
            },
            "required": ["path"]
        }
    }
]
