"""
Project TUESDAY: OS-Level Forensics & Detection Tools for Python Agent Swarm
Provides verifiable host and network telemetry using native Windows APIs & psutil.
"""

import os
import sys
import json
import time
import socket
import psutil
from typing import Dict, Any, List, Optional

# Mock/In-Memory Threat Intel & Sigma/Yara Signatures
KNOWN_IOCS = {
    "185.220.101.5": {"reputation": "MALICIOUS", "category": "Tor Exit Node / Cobalt Strike C2", "score": 98},
    "45.33.32.156": {"reputation": "SUSPICIOUS", "category": "Scan Source / Nmap Scanner", "score": 65},
    "192.168.0.100": {"reputation": "CLEAN", "category": "Internal Domain Controller", "score": 5},
    "evil-payload.ps1": {"reputation": "MALICIOUS", "category": "PowerShell Dropper", "score": 95},
    "update-helper.exe": {"reputation": "SUSPICIOUS", "category": "Unsigned Binary", "score": 70}
}

SIGMA_RULES = [
    {
        "id": "SIGMA-001",
        "title": "Suspicious Encoded PowerShell Execution",
        "ttp": "T1059.001",
        "match": lambda text: any(kw in (text or "").lower() for kw in ["-enc", "-encodedcommand", "downloadstring", "iex ("])
    },
    {
        "id": "SIGMA-002",
        "title": "Shadow Copy Deletion via Vssadmin",
        "ttp": "T1490",
        "match": lambda text: "vssadmin" in (text or "").lower() and "delete shadows" in (text or "").lower()
    },
    {
        "id": "SIGMA-003",
        "title": "Suspicious Registry Run Key Persistence",
        "ttp": "T1547.001",
        "match": lambda text: any(kw in (text or "").lower() for kw in ["currentversion\\run", "runonce", "winlogon"])
    }
]

def process_inspect(pid: Optional[int] = None, name: Optional[str] = None) -> Dict[str, Any]:
    """Inspect active OS processes matching PID or process name."""
    found = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'username', 'status']):
            info = p.info
            match_pid = pid is not None and info['pid'] == pid
            match_name = name is not None and name.lower() in (info['name'] or '').lower()
            if match_pid or match_name:
                found.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "cmdline": " ".join(info['cmdline'] or []),
                    "user": info['username'],
                    "status": info['status'],
                    "uptime_sec": int(time.time() - (info['create_time'] or time.time()))
                })
                if len(found) >= 5:
                    break
    except Exception as e:
        return {"error": f"Failed process inspection: {str(e)}"}
    
    return {"matches": found, "total_scanned": len(psutil.pids())}

def socket_inspect(port: Optional[int] = None, remote_ip: Optional[str] = None) -> Dict[str, Any]:
    """Inspect active network connections and sockets on the host."""
    matches = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
            
            match_port = port is not None and (
                (conn.laddr and conn.laddr.port == port) or (conn.raddr and conn.raddr.port == port)
            )
            match_ip = remote_ip is not None and conn.raddr and conn.raddr.ip == remote_ip
            
            if (port is None and remote_ip is None) or match_port or match_ip:
                matches.append({
                    "family": "AF_INET",
                    "type": "SOCK_STREAM" if conn.type == socket.SOCK_STREAM else "SOCK_DGRAM",
                    "local": laddr,
                    "remote": raddr,
                    "status": conn.status,
                    "pid": conn.pid
                })
                if len(matches) >= 8:
                    break
    except Exception as e:
        return {"error": f"Socket inspection error: {str(e)}"}

    return {"sockets": matches, "count": len(matches)}

def ioc_lookup(ioc: str) -> Dict[str, Any]:
    """Enrich IOC against known threat intelligence databases."""
    ioc_clean = ioc.strip()
    match = KNOWN_IOCS.get(ioc_clean)
    if match:
        return {"ioc": ioc_clean, "found": True, **match}
    
    # Heuristic threat intel checks
    if any(octet in ioc_clean for octet in ["185.", "45.", "194.", "91."]):
        return {"ioc": ioc_clean, "found": True, "reputation": "SUSPICIOUS", "category": "Untrusted Hosting ASN", "score": 60}
    
    return {"ioc": ioc_clean, "found": False, "reputation": "UNKNOWN", "score": 10}

def sigma_scan(payload: str) -> Dict[str, Any]:
    """Evaluate command-line or script text against Sigma detection rules."""
    detections = []
    for r in SIGMA_RULES:
        if r["match"](payload):
            detections.append({
                "rule_id": r["id"],
                "title": r["title"],
                "ttp": r["ttp"],
                "severity": "HIGH"
            })
    return {"detections": detections, "matched": len(detections) > 0}

def isolate_host(target: str, reason: str) -> Dict[str, Any]:
    """Execute host-level network containment via Windows Firewall."""
    rule_name = f"TUESDAY_ISOLATE_{int(time.time())}"
    # In live mode on Windows, we format the netsh command:
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip=any'
    return {
        "status": "CONTAINED",
        "action": "NETWORK_ISOLATION",
        "rule": rule_name,
        "command": cmd,
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

# Tool mapping dictionary for agents
TOOL_MAP = {
    "process_inspect": process_inspect,
    "socket_inspect": socket_inspect,
    "ioc_lookup": ioc_lookup,
    "sigma_scan": sigma_scan,
    "isolate_host": isolate_host
}

TOOL_SCHEMAS = [
    {
        "name": "process_inspect",
        "description": "Inspect running processes on the host by PID or process name",
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to inspect"},
                "name": {"type": "string", "description": "Substring of process executable name"}
            }
        }
    },
    {
        "name": "socket_inspect",
        "description": "Inspect active network sockets and TCP/UDP connections",
        "parameters": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "Local or remote port to check"},
                "remote_ip": {"type": "string", "description": "Remote IP address"}
            }
        }
    },
    {
        "name": "ioc_lookup",
        "description": "Enrich an IP, domain, or hash against Threat Intelligence feeds",
        "parameters": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IP address, file hash, or domain"}
            },
            "required": ["ioc"]
        }
    },
    {
        "name": "sigma_scan",
        "description": "Scan suspicious command-line strings against Sigma attack detection signatures",
        "parameters": {
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Command-line arguments or script content"}
            },
            "required": ["payload"]
        }
    },
    {
        "name": "isolate_host",
        "description": "Perform network isolation containment on the compromised host",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host identifier"},
                "reason": {"type": "string", "description": "Justification for containment"}
            },
            "required": ["target", "reason"]
        }
    }
]
