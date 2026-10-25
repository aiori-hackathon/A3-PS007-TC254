import os
import sys
import shutil
import subprocess
import logging
from typing import Dict, Any, List, Tuple
from pathlib import Path

from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG
from network.lab_manifest import LabManifest

logger = logging.getLogger("priv6guard.lab_setup")

class LabSetupError(Exception):
    pass

class LabSetupManager:
    """
    Orchestrates the safe, idempotent setup of the isolated IPv6 virtual lab.
    Strictly adheres to isolation boundaries and ownership verification.
    """
    def __init__(self, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.config = config
        self.manifest = LabManifest(config.manifest_path)

    def preflight_check(self) -> Tuple[bool, str]:
        """Verify operating system capabilities and tool availability."""
        if not sys.platform.startswith("linux"):
            return False, "Priv6Guard lab requires a Linux operating system."

        if not shutil.which("ip"):
            return False, "Required networking utility 'ip' (iproute2) is not installed."

        return True, "Preflight checks passed."

    def detect_conflicts(self) -> List[str]:
        """Detect if any target bridge or namespace already exists."""
        conflicts = []
        # Check bridge
        res = subprocess.run(["ip", "link", "show", self.config.bridge_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode == 0:
            conflicts.append(f"Bridge interface '{self.config.bridge_name}' already exists.")

        # Check namespaces
        res = subprocess.run(["ip", "netns", "list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            existing_ns = [line.split()[0] for line in res.stdout.splitlines() if line.strip()]
            all_target_ns = [d.namespace for d in self.config.devices] + [self.config.router.namespace, self.config.attacker.namespace]
            for ns in all_target_ns:
                if ns in existing_ns:
                    conflicts.append(f"Network namespace '{ns}' already exists.")

        return conflicts

    def _run_cmd(self, cmd: List[str], error_msg: str) -> str:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            raise LabSetupError(f"{error_msg}: {' '.join(cmd)} (Exit {res.returncode}): {err}")
        return res.stdout.strip()

    def setup_lab(self) -> Dict[str, Any]:
        """
        Creates the bridge, namespaces, veth interfaces, and IPv6 assignments.
        Rolls back automatically on failure.
        """
        ok, msg = self.preflight_check()
        if not ok:
            raise LabSetupError(msg)

        conflicts = self.detect_conflicts()
        if conflicts:
            raise LabSetupError(f"Conflicting network resources detected:\n" + "\n".join(conflicts))

        created_namespaces: List[str] = []
        created_interfaces: List[str] = []

        try:
            # 1. Create Bridge
            logger.info(f"Creating isolated virtual bridge '{self.config.bridge_name}'...")
            self._run_cmd(["ip", "link", "add", "name", self.config.bridge_name, "type", "bridge"], "Failed to create bridge")
            created_interfaces.append(self.config.bridge_name)
            self._run_cmd(["ip", "link", "set", "dev", self.config.bridge_name, "up"], "Failed to bring bridge up")

            # 2. Setup Nodes: Router, 5 Devices, Attacker
            all_nodes = [
                (self.config.router.namespace, self.config.router.host_veth, self.config.router.ns_peer, self.config.router.ipv6_address, self.config.router.mac_address),
                (self.config.attacker.namespace, self.config.attacker.host_veth, self.config.attacker.ns_peer, self.config.attacker.ipv6_address, self.config.attacker.mac_address),
            ]
            for d in self.config.devices:
                all_nodes.append((d.namespace, d.host_veth, d.ns_peer, d.ipv6_address, d.mac_address))

            for ns, host_veth, ns_peer, ipv6_addr, mac in all_nodes:
                logger.info(f"Setting up namespace '{ns}' on interface '{host_veth}' <-> '{ns_peer}'...")
                # Create namespace
                self._run_cmd(["ip", "netns", "add", ns], f"Failed to create namespace {ns}")
                created_namespaces.append(ns)
                self._run_cmd(["ip", "-n", ns, "link", "set", "lo", "up"], f"Failed to bring up loopback in {ns}")

                # Create veth pair
                self._run_cmd(["ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_peer], f"Failed to create veth pair {host_veth}")
                created_interfaces.append(host_veth)

                # Attach host side to bridge
                self._run_cmd(["ip", "link", "set", host_veth, "master", self.config.bridge_name], f"Failed to attach {host_veth} to bridge")
                self._run_cmd(["ip", "link", "set", host_veth, "up"], f"Failed to bring up {host_veth}")

                # Move peer to namespace
                self._run_cmd(["ip", "link", "set", ns_peer, "netns", ns], f"Failed to move {ns_peer} to {ns}")

                # Configure peer inside namespace
                self._run_cmd(["ip", "-n", ns, "link", "set", ns_peer, "address", mac], f"Failed to set MAC on {ns_peer}")
                self._run_cmd(["ip", "-n", ns, "link", "set", ns_peer, "up"], f"Failed to bring up {ns_peer}")
                self._run_cmd(["ip", "-n", ns, "addr", "add", f"{ipv6_addr}/{self.config.prefix_length}", "dev", ns_peer, "nodad"], f"Failed to assign IPv6 to {ns_peer}")

            # 3. Record verified manifest
            manifest_record = self.manifest.record_creation(
                bridge=self.config.bridge_name,
                namespaces=created_namespaces,
                interfaces=created_interfaces,
                ipv6_prefix=self.config.ipv6_prefix,
            )

            logger.info("Lab setup completed successfully with all interfaces active.")
            return {
                "status": "SUCCESS",
                "bridge": self.config.bridge_name,
                "namespaces": created_namespaces,
                "interfaces": created_interfaces,
                "manifest_id": manifest_record["manifest_id"],
            }

        except Exception as e:
            logger.error(f"Error during lab setup, performing atomic rollback: {e}")
            self._rollback(created_namespaces, created_interfaces)
            raise e

    def _rollback(self, namespaces: List[str], interfaces: List[str]):
        """Rollback partially created resources safely."""
        for ns in reversed(namespaces):
            try:
                subprocess.run(["ip", "netns", "del", ns], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        for iface in reversed(interfaces):
            try:
                subprocess.run(["ip", "link", "del", iface], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        self.manifest.clear_manifest()
