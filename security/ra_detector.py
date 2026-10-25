from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import logging

from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

logger = logging.getLogger("priv6guard.ra_detector")

@dataclass
class RAPolicyConfig:
    authorized_router_link_locals: List[str] = field(default_factory=lambda: ["fe80::1"])
    authorized_prefixes: List[str] = field(default_factory=lambda: ["2001:db8:6::/64", "fd00:cafe:1::/64"])
    min_router_lifetime_sec: int = 60
    max_router_lifetime_sec: int = 1800
    allow_zero_lifetime_deprecation: bool = True

@dataclass
class RADetectionResult:
    is_rogue: bool
    violation_type: Optional[str] = None
    severity: str = "LOW"
    source_ip: str = ""
    interface: str = "p6g-br0"
    rule_id: str = "RULE-RA-RFC6105"
    reason: str = ""
    advertised_prefixes: List[str] = field(default_factory=list)
    router_lifetime: int = 0
    managed_flag: bool = False
    other_flag: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

class RouterAdvertisementDetector:
    """
    RFC 4861 & RFC 6105 IPv6 Router Advertisement Policy Enforcement Engine.

    CRITICAL SECURITY DESIGN:
    - Implements an explicit local router trust policy (link-local identity, authorized prefixes, lifetime constraints).
    - Uses default-deny trust policy for unknown RA sources in the controlled lab, while clearly
      distinguishing an unknown source from proof of malicious intent.
    - Refuses to classify a router as rogue merely because it sends frequent advertisements (frequency != rogue).
    - Rogue classification is driven by unauthorized gateway identity, foreign prefix announcements,
      or abnormal lifetime manipulation.
    - Handles malformed packets and non-RA ICMPv6 messages without crashing or mislabeling.
    """
    def __init__(self, policy: Optional[RAPolicyConfig] = None):
        self.policy = policy or RAPolicyConfig()
        self.ra_count_by_source: Dict[str, int] = {}

    def inspect_ra_packet(
        self,
        packet: Any,
        current_time: Optional[datetime] = None,
        interface: str = "p6g-br0"
    ) -> RADetectionResult:
        """
        Inspects an IPv6 packet for ICMPv6 Router Advertisement violations.
        Can receive Scapy packet objects or parsed attribute dictionaries.
        """
        now = current_time or datetime.now(timezone.utc)

        try:
            # 1. Extract IPv6 & ICMPv6 RA layer data
            if hasattr(packet, "haslayer"):
                if not packet.haslayer(ICMPv6ND_RA):
                    # Non-RA message (Echo, NS, NA, etc.): Must NEVER be labeled rogue RA
                    return RADetectionResult(
                        is_rogue=False,
                        interface=interface,
                        rule_id="RULE-NON-RA",
                        reason="Non-RA ICMPv6 message ignored by Router Advertisement detector.",
                    )

                src_ip = packet[IPv6].src if packet.haslayer(IPv6) else "unknown"
                ra_layer = packet[ICMPv6ND_RA]
                router_lifetime = ra_layer.routerlifetime
                managed_flag = bool(ra_layer.M)
                other_flag = bool(ra_layer.O)

                # Extract advertised prefixes
                prefixes = []
                if packet.haslayer(ICMPv6NDOptPrefixInfo):
                    curr = packet.getlayer(ICMPv6NDOptPrefixInfo)
                    while curr:
                        prefix_str = f"{curr.prefix}/{curr.prefixlen}"
                        prefixes.append(prefix_str)
                        curr = curr.payload.getlayer(ICMPv6NDOptPrefixInfo) if curr.payload else None
            elif isinstance(packet, dict):
                itype = packet.get("icmp6_type")
                mtype = packet.get("msg_type")
                if itype is not None and itype != 134:
                    return RADetectionResult(
                        is_rogue=False,
                        interface=interface,
                        rule_id="RULE-NON-RA",
                        reason="Non-RA message ignored by Router Advertisement detector.",
                    )
                if mtype is not None and mtype not in ("RA", "ROUTER_ADVERTISEMENT"):
                    return RADetectionResult(
                        is_rogue=False,
                        interface=interface,
                        rule_id="RULE-NON-RA",
                        reason="Non-RA message ignored by Router Advertisement detector.",
                    )
                src_ip = packet.get("source_ip", "")
                if not src_ip:
                    return RADetectionResult(
                        is_rogue=False,
                        interface=interface,
                        rule_id="RULE-RA-MALFORMED",
                        reason="Malformed RA dictionary without source_ip.",
                    )
                router_lifetime = packet.get("router_lifetime", 1800)
                managed_flag = packet.get("managed_flag", False)
                other_flag = packet.get("other_flag", False)
                prefixes = packet.get("prefixes", packet.get("advertised_prefixes", []))
            else:
                return RADetectionResult(
                    is_rogue=False,
                    interface=interface,
                    rule_id="RULE-NON-RA",
                    reason="Unrecognized or malformed packet safely ignored.",
                )

            # Track frequency (for telemetry, NOT for rogue classification)
            self.ra_count_by_source[src_ip] = self.ra_count_by_source.get(src_ip, 0) + 1

            # 2. Check 1: Authorized Router Link-Local Address Whitelist (Default-Deny Policy)
            if src_ip not in self.policy.authorized_router_link_locals:
                reason = f"Source {src_ip} is not in authorized router whitelist (default-deny policy)."
                logger.warning(f"Rogue RA detected: Unauthorized router address {src_ip}")
                return RADetectionResult(
                    is_rogue=True,
                    violation_type="UNAUTHORIZED_ROUTER_ADDRESS",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    interface=interface,
                    rule_id="RULE-RA-UNAUTHORIZED-SOURCE",
                    reason=reason,
                    advertised_prefixes=prefixes,
                    router_lifetime=router_lifetime,
                    managed_flag=managed_flag,
                    other_flag=other_flag,
                    details={
                        "message": reason,
                        "authorized_routers": self.policy.authorized_router_link_locals,
                        "rule_id": "RULE-RA-UNAUTHORIZED-SOURCE",
                        "interface": interface,
                    }
                )

            # 3. Check 2: Unauthorized Prefix Advertisements (Rogue SLAAC injection)
            for prefix in prefixes:
                if prefix not in self.policy.authorized_prefixes:
                    reason = f"Prefix {prefix} is foreign to this network policy."
                    logger.warning(f"Rogue RA detected: Unauthorized prefix {prefix} from {src_ip}")
                    return RADetectionResult(
                        is_rogue=True,
                        violation_type="UNAUTHORIZED_PREFIX_ANNOUNCEMENT",
                        severity="CRITICAL",
                        source_ip=src_ip,
                        interface=interface,
                        rule_id="RULE-RA-UNAUTHORIZED-PREFIX",
                        reason=reason,
                        advertised_prefixes=prefixes,
                        router_lifetime=router_lifetime,
                        managed_flag=managed_flag,
                        other_flag=other_flag,
                        details={
                            "message": reason,
                            "foreign_prefix": prefix,
                            "authorized_prefixes": self.policy.authorized_prefixes,
                            "rule_id": "RULE-RA-UNAUTHORIZED-PREFIX",
                            "interface": interface,
                        }
                    )

            # 4. Check 3: Abnormal Lifetime Manipulation
            if router_lifetime > self.policy.max_router_lifetime_sec:
                reason = f"Lifetime {router_lifetime}s exceeds maximum allowed {self.policy.max_router_lifetime_sec}s."
                logger.warning(f"Rogue RA detected: Router lifetime {router_lifetime} exceeds maximum policy threshold.")
                return RADetectionResult(
                    is_rogue=True,
                    violation_type="ABNORMAL_ROUTER_LIFETIME",
                    severity="HIGH",
                    source_ip=src_ip,
                    interface=interface,
                    rule_id="RULE-RA-ABNORMAL-LIFETIME",
                    reason=reason,
                    advertised_prefixes=prefixes,
                    router_lifetime=router_lifetime,
                    managed_flag=managed_flag,
                    other_flag=other_flag,
                    details={
                        "message": reason,
                        "lifetime": router_lifetime,
                        "max_allowed": self.policy.max_router_lifetime_sec,
                        "rule_id": "RULE-RA-ABNORMAL-LIFETIME",
                        "interface": interface,
                    }
                )

            # 5. Legitimate Router Advertisement (Permitted)
            return RADetectionResult(
                is_rogue=False,
                source_ip=src_ip,
                interface=interface,
                rule_id="RULE-RA-PERMITTED",
                reason=f"Permitted Router Advertisement from trusted router {src_ip}.",
                advertised_prefixes=prefixes,
                router_lifetime=router_lifetime,
                managed_flag=managed_flag,
                other_flag=other_flag,
                details={
                    "status": "PERMITTED",
                    "interface": interface,
                }
            )

        except Exception as e:
            logger.error(f"Malformed or unexpected packet in RA detector: {e}")
            return RADetectionResult(
                is_rogue=False,
                interface=interface,
                rule_id="RULE-RA-MALFORMED",
                reason=f"Malformed packet safely handled: {e}",
            )
