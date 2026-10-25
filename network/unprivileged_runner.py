import subprocess
import shutil
from typing import Tuple, Dict, Any, List

from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG

class UnprivilegedLabRunner:
    """
    Executes real Linux networking operations (bridge creation, network namespaces,
    veth pairs, IPv6 assignments, ICMPv6 packets) inside a safe rootless Linux user
    and mount namespace (unshare -m -n -U -r).

    This enables automated testing and demonstrations without requiring root privileges
    or sudo passwords, while still exercising the real Linux kernel networking stack.
    """
    def __init__(self, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.config = config

    @staticmethod
    def is_supported() -> bool:
        """Check if rootless user namespaces with network isolation are supported."""
        if not shutil.which("unshare"):
            return False
        res = subprocess.run(
            ["unshare", "-m", "-n", "-U", "-r", "ip", "link"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0

    def generate_setup_script(self) -> str:
        """Generate bash script to create the entire lab inside the isolated namespace."""
        lines = [
            "set -euo pipefail",
            "mkdir -p /run/netns",
            "mount -t tmpfs tmpfs /run/netns",
            "ip link set lo up",
            f"ip link add {self.config.bridge_name} type bridge",
            f"ip link set {self.config.bridge_name} up",
        ]

        all_nodes = [
            (self.config.router.namespace, self.config.router.host_veth, self.config.router.ns_peer, self.config.router.ipv6_address, self.config.router.mac_address),
            (self.config.attacker.namespace, self.config.attacker.host_veth, self.config.attacker.ns_peer, self.config.attacker.ipv6_address, self.config.attacker.mac_address),
        ]
        for d in self.config.devices:
            all_nodes.append((d.namespace, d.host_veth, d.ns_peer, d.ipv6_address, d.mac_address))

        for ns, host_veth, ns_peer, ipv6_addr, mac in all_nodes:
            lines.extend([
                f"ip netns add {ns}",
                f"ip link add {host_veth} type veth peer name {ns_peer}",
                f"ip link set {host_veth} master {self.config.bridge_name}",
                f"ip link set {host_veth} up",
                f"ip link set {ns_peer} netns {ns}",
                f"ip -n {ns} link set lo up",
                f"ip -n {ns} link set {ns_peer} address {mac}",
                f"ip -n {ns} link set {ns_peer} up",
                f"ip -n {ns} addr add {ipv6_addr}/{self.config.prefix_length} dev {ns_peer} nodad",
            ])

        return "\n".join(lines)

    def run_isolated_command(self, commands: str, timeout: int = 15) -> Tuple[int, str, str]:
        """Runs arbitrary shell commands within an isolated lab session."""
        setup_script = self.generate_setup_script()
        full_script = f"{setup_script}\n{commands}\n"
        
        proc = subprocess.run(
            ["unshare", "-m", "-n", "-U", "-r", "bash", "-c", full_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
