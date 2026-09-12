"""
Project TUESDAY: Multi-Node Cluster Discovery & Distributed Agent Dispatch
Zero-config LAN cluster: nodes broadcast their presence via UDP.
Any responding TUESDAY node becomes a worker for distributed agent execution.

Architecture Narrative:
- Single machine: all 4 agents run locally in parallel (ThreadPoolExecutor)
- 2+ machines on LAN: workloads distributed automatically — no config needed
- Adversarial Critic always dispatches to a DIFFERENT node when available
  (genuine physical independence, not just software isolation)
- Scales linearly: N nodes = N * agent throughput capacity
- Consumer hardware replaces expensive server racks for edge deployment
"""

import socket
import threading
import time
import requests
import json
from typing import List, Dict, Optional, Any

DISCOVERY_PORT = 5757          # UDP port for TUESDAY cluster discovery
DISCOVERY_MSG = b"TUESDAY_CLUSTER_DISCOVERY_V1"
DISCOVERY_REPLY = b"TUESDAY_CLUSTER_NODE_READY_V1"
TUESDAY_PORT = 8090            # HTTP API port all nodes expose
HEALTH_CHECK_INTERVAL = 30     # seconds between node health checks


class ClusterNode:
    """Represents a remote TUESDAY node available for agent dispatch."""

    def __init__(self, ip: str, port: int = TUESDAY_PORT):
        self.ip = ip
        self.port = port
        self.last_seen = time.time()
        self.healthy = True
        self.discovered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def base_url(self) -> str:
        return f"http://{self.ip}:{self.port}"

    def health_check(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/api/health", timeout=3)
            self.healthy = resp.status_code == 200
            self.last_seen = time.time()
        except Exception:
            self.healthy = False
        return self.healthy

    def run_agent(
        self,
        agent_key: str,
        alert: Dict[str, Any],
        past_episodes: List[Dict[str, Any]],
        peer_findings: Dict[str, str]
    ) -> Dict[str, Any]:
        """Dispatch a single agent investigation to this remote node."""
        resp = requests.post(
            f"{self.base_url}/api/agent/run",
            json={
                "agent_key": agent_key,
                "alert": alert,
                "past_episodes": past_episodes,
                "peer_findings": peer_findings
            },
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()

    def run_critic(
        self,
        alert: Dict[str, Any],
        verdicts: Dict[str, Any],
        consensus_pct: int
    ) -> Dict[str, Any]:
        """Dispatch adversarial critic to this remote node for independent validation."""
        resp = requests.post(
            f"{self.base_url}/api/critic/run",
            json={
                "alert": alert,
                "verdicts": verdicts,
                "consensus_pct": consensus_pct
            },
            timeout=60
        )
        resp.raise_for_status()
        return resp.json()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "baseUrl": self.base_url,
            "healthy": self.healthy,
            "lastSeen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(self.last_seen)),
            "discoveredAt": self.discovered_at
        }


class ClusterManager:
    """
    Zero-config cluster manager.
    Discovers peer TUESDAY nodes on the LAN via UDP broadcast.
    No configuration files, no manual IP entry — plug into any network switch and peers auto-register.
    """

    def __init__(self):
        self.nodes: Dict[str, ClusterNode] = {}
        self._lock = threading.Lock()
        self._listener_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start background discovery listener and initial broadcast."""
        if self._running:
            return
        self._running = True

        # Start UDP listener — respond to other nodes' broadcasts
        self._listener_thread = threading.Thread(
            target=self._udp_listener_loop,
            daemon=True,
            name="TUESDAY-ClusterListener"
        )
        self._listener_thread.start()

        # Start heartbeat thread — periodic re-discovery + health checks
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="TUESDAY-ClusterHeartbeat"
        )
        self._heartbeat_thread.start()

        # Initial broadcast to find existing nodes
        self._broadcast_and_collect()
        print(f"[CLUSTER] Discovery started — listening on UDP:{DISCOVERY_PORT}")

    def stop(self):
        self._running = False

    def refresh(self):
        """Manually trigger re-discovery (e.g., when a new node is plugged in)."""
        self._broadcast_and_collect()
        # Also prune stale nodes
        with self._lock:
            stale = [ip for ip, node in self.nodes.items()
                     if time.time() - node.last_seen > 120]
            for ip in stale:
                print(f"[CLUSTER] Pruning stale node: {ip}")
                del self.nodes[ip]

    def _broadcast_and_collect(self):
        """Broadcast discovery packet, collect replies from peer nodes."""
        def _do_broadcast():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(3)
                sock.sendto(DISCOVERY_MSG, ('<broadcast>', DISCOVERY_PORT))

                # Collect replies for 3 seconds
                deadline = time.time() + 3
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data == DISCOVERY_REPLY:
                            self._try_register_node(addr[0])
                    except socket.timeout:
                        break
                sock.close()
            except Exception as e:
                pass  # Broadcast may fail on restrictive networks — that's OK

        t = threading.Thread(target=_do_broadcast, daemon=True)
        t.start()

    def _udp_listener_loop(self):
        """Listen for discovery broadcasts from other nodes and reply."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)
            sock.bind(('', DISCOVERY_PORT))
            print(f"[CLUSTER] UDP listener bound to port {DISCOVERY_PORT}")

            while self._running:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data == DISCOVERY_MSG:
                        sock.sendto(DISCOVERY_REPLY, addr)
                        self._try_register_node(addr[0])
                except socket.timeout:
                    continue
                except Exception:
                    continue
            sock.close()
        except OSError as e:
            print(f"[CLUSTER] UDP listener failed (port {DISCOVERY_PORT} in use?): {e}")

    def _heartbeat_loop(self):
        """Periodic re-discovery and health checks."""
        while self._running:
            time.sleep(HEALTH_CHECK_INTERVAL)
            self.refresh()
            with self._lock:
                for node in list(self.nodes.values()):
                    node.health_check()

    def _try_register_node(self, ip: str):
        """Attempt to register a discovered IP as a cluster node."""
        if ip in self._get_local_ips():
            return  # Skip self

        with self._lock:
            if ip in self.nodes:
                self.nodes[ip].last_seen = time.time()
                return

        # Health check outside the lock (network call)
        node = ClusterNode(ip)
        if node.health_check():
            with self._lock:
                self.nodes[ip] = node
            print(f"[CLUSTER] ✓ Worker node registered: {ip} — cluster size now {len(self.nodes) + 1} nodes")

    def _get_local_ips(self) -> List[str]:
        """Get all local IP addresses to avoid registering self."""
        ips = ['127.0.0.1', 'localhost', '::1']
        try:
            hostname = socket.gethostname()
            info = socket.getaddrinfo(hostname, None)
            for item in info:
                ips.append(item[4][0])
        except Exception:
            pass
        return ips

    def get_healthy_nodes(self) -> List[ClusterNode]:
        """Return list of currently healthy worker nodes."""
        with self._lock:
            return [n for n in self.nodes.values() if n.healthy]

    def node_count(self) -> int:
        return len(self.get_healthy_nodes())

    def get_status(self) -> Dict[str, Any]:
        healthy_nodes = self.get_healthy_nodes()
        return {
            "localNode": {
                "role": "orchestrator",
                "ip": self._get_local_ips()[0] if self._get_local_ips() else "unknown"
            },
            "workerNodes": [n.to_dict() for n in healthy_nodes],
            "clusterSize": len(healthy_nodes) + 1,
            "distributedMode": len(healthy_nodes) > 0,
            "discoveryPort": DISCOVERY_PORT,
            "scalingNarrative": (
                f"Running as {len(healthy_nodes) + 1}-node tactical edge cluster. "
                f"Adversarial critic dispatched to remote node {healthy_nodes[0].ip}."
                if healthy_nodes else
                "Single-node mode. Connect additional TUESDAY nodes to the same network to enable distributed execution."
            )
        }


# Module-level singleton — started by FastAPI lifespan
cluster_manager = ClusterManager()
