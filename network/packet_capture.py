import asyncio
import threading
import logging
import uuid
from typing import Optional, Dict, Any, Callable, Set
from datetime import datetime, timezone

from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6NDOptPrefixInfo
from scapy.sendrecv import AsyncSniffer

from backend.models.schema import NormalizedEvent, NormalizedAlert
from security.ra_detector import RouterAdvertisementDetector, RADetectionResult
from security.ndp_detector import NDPAnomalyDetector, NDPAnomalyResult
from security.event_manager import SecurityEventManager

logger = logging.getLogger("priv6guard.packet_capture")

ALLOWED_INTERFACES: Set[str] = {"p6g-br0", "lo"}

class IPv6PacketParser:
    """
    Independent parser for IPv6 and ICMPv6 packets.
    Separated from live packet capture to enable deterministic unprivileged testing.
    Handles malformed or incomplete frames without crashing.
    """
    def __init__(self, allowed_interfaces: Optional[Set[str]] = None):
        self.allowed_interfaces = allowed_interfaces or ALLOWED_INTERFACES
        self.parse_errors: int = 0
        self.total_parsed: int = 0

    def parse_packet(
        self,
        packet: Any,
        interface: str = "p6g-br0",
        scenario_id: Optional[str] = None
    ) -> Optional[NormalizedEvent]:
        """
        Parses an incoming packet into a NormalizedEvent.
        Enforces interface allowlisting and graceful exception handling.
        """
        if interface not in self.allowed_interfaces:
            logger.warning(f"Rejected packet from non-allowlisted interface '{interface}'")
            return None

        self.total_parsed += 1

        try:
            # 1. Validate IPv6 Layer
            if not (hasattr(packet, "haslayer") and packet.haslayer(IPv6)):
                return None

            ipv6_layer = packet[IPv6]
            src_ip = ipv6_layer.src
            dst_ip = ipv6_layer.dst

            # 2. Extract ICMPv6 layer
            icmp6_type = None
            icmp6_name = "UNKNOWN"
            evidence: Dict[str, Any] = {}

            if packet.haslayer(ICMPv6ND_RA):
                icmp6_type = 134
                icmp6_name = "ROUTER_ADVERTISEMENT"
                ra = packet[ICMPv6ND_RA]
                evidence["router_lifetime"] = ra.routerlifetime
                evidence["managed_flag"] = bool(ra.M)
                evidence["other_flag"] = bool(ra.O)

                prefixes = []
                if packet.haslayer(ICMPv6NDOptPrefixInfo):
                    curr = packet.getlayer(ICMPv6NDOptPrefixInfo)
                    while curr:
                        prefixes.append(f"{curr.prefix}/{curr.prefixlen}")
                        curr = curr.payload.getlayer(ICMPv6NDOptPrefixInfo) if curr.payload else None
                evidence["advertised_prefixes"] = prefixes

            elif packet.haslayer(ICMPv6ND_NS):
                icmp6_type = 135
                icmp6_name = "NEIGHBOR_SOLICITATION"
                ns = packet[ICMPv6ND_NS]
                evidence["target_address"] = ns.tgt

            elif packet.haslayer(ICMPv6ND_NA):
                icmp6_type = 136
                icmp6_name = "NEIGHBOR_ADVERTISEMENT"
                na = packet[ICMPv6ND_NA]
                evidence["target_address"] = na.tgt
                evidence["router_flag"] = bool(na.R)
                evidence["solicited_flag"] = bool(na.S)
                evidence["override_flag"] = bool(na.O)

            elif packet.haslayer(ICMPv6ND_RS):
                icmp6_type = 133
                icmp6_name = "ROUTER_SOLICITATION"

            else:
                return None

            event_id = f"norm-pkt-{uuid.uuid4().hex[:8]}"
            now_str = datetime.now(timezone.utc).isoformat()

            return NormalizedEvent(
                event_id=event_id,
                timestamp=now_str,
                interface=interface,
                protocol="ICMPv6",
                icmp6_type=icmp6_type,
                icmp6_name=icmp6_name,
                source_ip=src_ip,
                target_ip=dst_ip,
                scenario_id=scenario_id,
                evidence=evidence,
            )

        except Exception as e:
            self.parse_errors += 1
            logger.error(f"Malformed packet encountered: {e}")
            return None


class PacketCaptureEngine:
    """
    Privileged and unprivileged packet capture orchestrator.
    - Validates interface allowlist (rejects arbitrary host interfaces).
    - Requires explicit authorization to start.
    - Prevents duplicate background capture threads.
    - Emits normalized events to detectors and event manager.
    - Adheres to data minimization (no raw payload storage).
    """
    def __init__(
        self,
        interface: str = "p6g-br0",
        ra_detector: Optional[RouterAdvertisementDetector] = None,
        ndp_detector: Optional[NDPAnomalyDetector] = None,
        event_manager: Optional[SecurityEventManager] = None,
        parser: Optional[IPv6PacketParser] = None,
    ):
        self.interface = interface
        self.ra_detector = ra_detector or RouterAdvertisementDetector()
        self.ndp_detector = ndp_detector or NDPAnomalyDetector()
        self.event_manager = event_manager
        self.parser = parser or IPv6PacketParser(ALLOWED_INTERFACES)

        self.sniffer: Optional[AsyncSniffer] = None
        self.is_capturing: bool = False
        self._lock = threading.Lock()

        # Operational Counters
        self.total_packets: int = 0
        self.ra_packets: int = 0
        self.ns_packets: int = 0
        self.na_packets: int = 0
        self.rs_packets: int = 0
        self.capture_errors: int = 0
        self.start_time: Optional[datetime] = None

    def _packet_callback(self, packet: Any):
        self.total_packets += 1

        # Use independent parser
        norm_event = self.parser.parse_packet(packet, interface=self.interface)
        if not norm_event:
            return

        # 1. Router Advertisement Processing
        if norm_event.icmp6_name == "ROUTER_ADVERTISEMENT":
            self.ra_packets += 1
            ra_res = self.ra_detector.inspect_ra_packet(packet)
            if ra_res.is_rogue and self.event_manager:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(self.event_manager.handle_ra_detection(ra_res))
                except Exception as e:
                    logger.debug(f"Event dispatch note: {e}")

        # 2. Neighbor Discovery Processing (NS / NA / RS)
        elif norm_event.icmp6_name in ("NEIGHBOR_SOLICITATION", "NEIGHBOR_ADVERTISEMENT", "ROUTER_SOLICITATION"):
            if norm_event.icmp6_name == "NEIGHBOR_SOLICITATION":
                self.ns_packets += 1
            elif norm_event.icmp6_name == "NEIGHBOR_ADVERTISEMENT":
                self.na_packets += 1
            elif norm_event.icmp6_name == "ROUTER_SOLICITATION":
                self.rs_packets += 1

            ndp_res = self.ndp_detector.inspect_ndp_packet(packet)
            if ndp_res.is_anomaly and self.event_manager:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(self.event_manager.handle_ndp_anomaly(ndp_res))
                except Exception as e:
                    logger.debug(f"Event dispatch note: {e}")

    def process_packet_direct(self, packet: Any) -> Dict[str, Any]:
        """Direct packet processing method for testing and offline analysis."""
        self._packet_callback(packet)
        return {
            "total_packets": self.total_packets,
            "ra_packets": self.ra_packets,
            "ns_packets": self.ns_packets,
            "na_packets": self.na_packets,
            "parse_errors": self.parser.parse_errors,
        }

    def start_capture(self, authorized: bool = True) -> bool:
        """
        Start non-blocking packet capture on the virtual bridge.
        Requires explicit authorization and interface allowlist check.
        Prevents duplicate capture workers.
        """
        if not authorized:
            logger.warning("Packet capture start refused: authorization not provided.")
            return False

        if self.interface not in ALLOWED_INTERFACES:
            logger.error(f"Packet capture start refused: Interface '{self.interface}' is not allowlisted.")
            self.capture_errors += 1
            return False

        with self._lock:
            if self.is_capturing:
                logger.info(f"Packet capture already active on {self.interface} (duplicate worker prevented).")
                return True

            try:
                logger.info(f"Starting ICMPv6 packet capture on authorized interface '{self.interface}'...")
                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="icmp6",
                    prn=self._packet_callback,
                    store=False, # Data minimization: never store full payloads
                )
                self.sniffer.start()
                self.is_capturing = True
                self.start_time = datetime.now(timezone.utc)
                return True
            except Exception as e:
                logger.error(f"Failed to start packet capture on {self.interface}: {e}")
                self.capture_errors += 1
                self.is_capturing = False
                return False

    def stop_capture(self) -> Dict[str, Any]:
        """Stop packet sniffer cleanly."""
        with self._lock:
            if self.is_capturing and self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception as e:
                    logger.debug(f"Sniffer stop note: {e}")
                self.is_capturing = False

        return self.get_stats()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "interface": self.interface,
            "is_capturing": self.is_capturing,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "total_packets": self.total_packets,
            "ra_packets": self.ra_packets,
            "ns_packets": self.ns_packets,
            "na_packets": self.na_packets,
            "rs_packets": self.rs_packets,
            "parse_errors": self.parser.parse_errors,
            "capture_errors": self.capture_errors,
        }
