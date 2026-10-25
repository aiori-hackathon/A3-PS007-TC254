import subprocess
from typing import Dict, Any, List, Tuple, Optional
from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG
from network.lab_manifest import LabManifest

class LabStatusManager:
    """
    Inspects operational health, interface states, and IPv6 reachability across the lab.
    """
    def __init__(self, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.config = config
        self.manifest = LabManifest(config.manifest_path)

    def get_bridge_status(self) -> Dict[str, Any]:
        res = subprocess.run(["ip", "link", "show", self.config.bridge_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            return {"exists": False, "state": "DOWN"}
        state = "UP" if "state UP" in res.stdout or "state UNKNOWN" in res.stdout else "DOWN"
        return {"exists": True, "state": state, "name": self.config.bridge_name}

    def get_namespace_status(self, namespace: str, peer_iface: str) -> Dict[str, Any]:
        # Check namespace presence
        res_ns = subprocess.run(["ip", "netns", "list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        existing_ns = [l.split()[0] for l in res_ns.stdout.splitlines() if l.strip()]
        if namespace not in existing_ns:
            return {"exists": False, "state": "ABSENT", "ipv6": None}

        # Check peer interface inside namespace
        res_link = subprocess.run(["ip", "-n", namespace, "link", "show", peer_iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res_link.returncode != 0:
            return {"exists": True, "state": "INTERFACE_MISSING", "ipv6": None}

        # Get assigned IPv6 addresses
        res_addr = subprocess.run(["ip", "-n", namespace, "-6", "addr", "show", peer_iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        addrs = []
        for line in res_addr.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6 "):
                addrs.append(line.split()[1])

        return {
            "exists": True,
            "state": "UP" if "state UP" in res_link.stdout or "state UNKNOWN" in res_link.stdout else "DOWN",
            "ipv6_addresses": addrs,
        }

    def get_full_lab_status(self) -> Dict[str, Any]:
        manifest_data = self.manifest.load_manifest()
        bridge_info = self.get_bridge_status()

        devices_status = {}
        for d in self.config.devices:
            devices_status[d.lab_id] = self.get_namespace_status(d.namespace, d.ns_peer)

        router_status = self.get_namespace_status(self.config.router.namespace, self.config.router.ns_peer)
        attacker_status = self.get_namespace_status(self.config.attacker.namespace, self.config.attacker.ns_peer)

        is_healthy = (
            bridge_info.get("exists", False)
            and all(st.get("exists") for st in devices_status.values())
            and router_status.get("exists", False)
        )

        return {
            "is_active": bridge_info.get("exists", False),
            "is_healthy": is_healthy,
            "manifest_recorded": manifest_data is not None,
            "bridge": bridge_info,
            "router": router_status,
            "attacker": attacker_status,
            "devices": devices_status,
        }

    def verify_connectivity(self, source_ns: str, target_ipv6: str, count: int = 1) -> bool:
        """Ping target IPv6 from within source namespace."""
        cmd = ["ip", "netns", "exec", source_ns, "ping", "-6", "-c", str(count), "-W", "1", target_ipv6]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0

    def preflight_attack_check(self) -> Tuple[bool, str]:
        """
        Enforces safety barrier: Prevents attack simulations from running
        unless the designated lab is explicitly active, verified, and healthy.
        """
        status = self.get_full_lab_status()
        if not status["is_active"]:
            return False, "Attack blocked: Target lab bridge is not active."
        if not status["manifest_recorded"]:
            return False, "Attack blocked: No verified ownership manifest recorded for the lab."
        if not status["is_healthy"]:
            return False, "Attack blocked: Lab namespaces are degraded or incomplete."
        return True, "Preflight passed: Lab is verified active and healthy."
