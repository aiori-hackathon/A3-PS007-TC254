import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
import logging

from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS

logger = logging.getLogger("priv6guard.ndp_detector")

@dataclass
class NDPThresholds:
    max_ns_per_sec: float = 15.0
    max_na_per_sec: float = 15.0
    max_rs_per_sec: float = 5.0
    max_total_ndp_per_sec: float = 25.0

@dataclass
class NDPAnomalyResult:
    is_anomaly: bool
    anomaly_type: Optional[str] = None
    classification: str = "BENIGN"
    rule_id: str = "RULE-NDP-RATE-LIMIT"
    interface: str = "p6g-br0"
    current_rate_pps: float = 0.0
    threshold_pps: float = 0.0
    observed_count: int = 0
    window_seconds: float = 5.0
    source_ip: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

class NDPAnomalyDetector:
    """
    Rolling-window ICMPv6 Neighbor Discovery rate anomaly detector.

    CRITICAL ARCHITECTURAL INVARIANT:
    A high NDP message rate is an ANOMALY INDICATOR, not definitive proof of malicious intent.
    Valid network events (e.g., multicast group joins, address re-resolution bursts,
    or rapid host migrations) can generate bursts. This module tags high rates as
    'ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF' and maintains configurable cooldowns.

    Counted ICMPv6 ND message types:
    - Neighbor Solicitation (NS, Type 135)
    - Neighbor Advertisement (NA, Type 136)
    - Router Solicitation (RS, Type 133)
    """
    def __init__(
        self,
        rolling_window_seconds: float = 5.0,
        thresholds: Optional[NDPThresholds] = None,
        cooldown_seconds: float = 10.0,
    ):
        self.window_sec = rolling_window_seconds
        self.thresholds = thresholds or NDPThresholds()
        self.cooldown_sec = cooldown_seconds

        # Rolling timestamp deques scoped to: (interface, source_ip, msg_type) -> deque of timestamps
        self._history: Dict[Tuple[str, str, str], deque] = {}
        self._last_alert_time: Dict[Tuple[str, str, str], float] = {}

    def _prune_old_entries(self, dq: deque, cutoff: float):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def prune_idle_sources(self, current_time: Optional[datetime] = None) -> int:
        """
        Expires old counter state for sources that have been idle past the window.
        Prevents unbounded in-memory state growth.
        """
        now_ts = (current_time or datetime.now(timezone.utc)).timestamp()
        cutoff = now_ts - self.window_sec
        stale_keys = []
        for key, dq in self._history.items():
            self._prune_old_entries(dq, cutoff)
            if not dq:
                stale_keys.append(key)

        for k in stale_keys:
            self._history.pop(k, None)
        return len(stale_keys)

    def inspect_ndp_packet(
        self,
        packet: Any,
        current_time: Optional[datetime] = None,
        interface: str = "p6g-br0",
    ) -> NDPAnomalyResult:
        """
        Processes an ICMPv6 packet and checks rolling window rates.
        Accepts Scapy packet objects or parsed attribute dictionaries.
        Safely handles malformed packets and missing fields without crashing.
        """
        now_dt = current_time or datetime.now(timezone.utc)
        now_ts = now_dt.timestamp()

        try:
            # Extract source IP and message type
            src_ip = "unknown"
            msg_type = "UNKNOWN"

            if hasattr(packet, "haslayer"):
                if packet.haslayer(IPv6):
                    src_ip = packet[IPv6].src
                if packet.haslayer(ICMPv6ND_NS):
                    msg_type = "NS"
                elif packet.haslayer(ICMPv6ND_NA):
                    msg_type = "NA"
                elif packet.haslayer(ICMPv6ND_RS):
                    msg_type = "RS"
                else:
                    return NDPAnomalyResult(
                        is_anomaly=False,
                        interface=interface,
                        source_ip=src_ip,
                        rule_id="RULE-NON-NDP",
                    )
            elif isinstance(packet, dict):
                src_ip = packet.get("source_ip", "unknown")
                msg_type = packet.get("msg_type", packet.get("icmp6_name", "UNKNOWN"))
                if msg_type in ("NEIGHBOR_SOLICITATION", "NS"):
                    msg_type = "NS"
                elif msg_type in ("NEIGHBOR_ADVERTISEMENT", "NA"):
                    msg_type = "NA"
                elif msg_type in ("ROUTER_SOLICITATION", "RS"):
                    msg_type = "RS"
                else:
                    return NDPAnomalyResult(
                        is_anomaly=False,
                        interface=interface,
                        source_ip=src_ip,
                        rule_id="RULE-NON-NDP",
                    )
            else:
                return NDPAnomalyResult(
                    is_anomaly=False,
                    interface=interface,
                    rule_id="RULE-MALFORMED",
                )

            key = (interface, src_ip, msg_type)
            if key not in self._history:
                self._history[key] = deque()

            dq = self._history[key]
            dq.append(now_ts)

            # Prune entries older than the rolling window
            cutoff = now_ts - self.window_sec
            self._prune_old_entries(dq, cutoff)

            # Calculate current rate
            count = len(dq)
            rate = count / self.window_sec

            # Determine threshold
            if msg_type == "NS":
                threshold = self.thresholds.max_ns_per_sec
                rule_id = "RULE-NDP-NS-RATE-LIMIT"
            elif msg_type == "NA":
                threshold = self.thresholds.max_na_per_sec
                rule_id = "RULE-NDP-NA-RATE-LIMIT"
            elif msg_type == "RS":
                threshold = self.thresholds.max_rs_per_sec
                rule_id = "RULE-NDP-RS-RATE-LIMIT"
            else:
                threshold = self.thresholds.max_total_ndp_per_sec
                rule_id = "RULE-NDP-TOTAL-RATE-LIMIT"

            # Check threshold violation
            if rate > threshold:
                last_alert = self._last_alert_time.get(key, 0.0)
                if (now_ts - last_alert) >= self.cooldown_sec:
                    self._last_alert_time[key] = now_ts
                    logger.warning(
                        f"NDP rate anomaly indicator on {interface} from {src_ip}: {msg_type} rate {rate:.2f} pps "
                        f"exceeds threshold {threshold:.2f} pps (burst: {count} pkts/{self.window_sec}s)"
                    )
                    return NDPAnomalyResult(
                        is_anomaly=True,
                        anomaly_type=f"NDP_{msg_type}_RATE_ANOMALY",
                        classification="ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF",
                        rule_id=rule_id,
                        interface=interface,
                        current_rate_pps=round(rate, 2),
                        threshold_pps=threshold,
                        observed_count=count,
                        window_seconds=self.window_sec,
                        source_ip=src_ip,
                        details={
                            "message_type": msg_type,
                            "interface": interface,
                            "window_seconds": self.window_sec,
                            "observed_burst_count": count,
                            "cooldown_seconds": self.cooldown_sec,
                            "rule_id": rule_id,
                            "guidance": (
                                "High rate is an anomaly indicator, not definitive proof of malicious attack. "
                                "Corroborate with active session status and link state before taking remediation action."
                            ),
                        }
                    )

            return NDPAnomalyResult(
                is_anomaly=False,
                interface=interface,
                current_rate_pps=round(rate, 2),
                threshold_pps=threshold,
                observed_count=count,
                window_seconds=self.window_sec,
                source_ip=src_ip,
                rule_id=rule_id,
            )

        except Exception as e:
            logger.error(f"Malformed or unexpected packet in NDP detector: {e}")
            return NDPAnomalyResult(
                is_anomaly=False,
                interface=interface,
                rule_id="RULE-NDP-MALFORMED",
            )

    def reset_cooldown(self, source_ip: Optional[str] = None, msg_type: Optional[str] = None, interface: Optional[str] = None):
        """Reset cooldown timers to allow fresh experiment execution."""
        if source_ip and msg_type and interface:
            self._last_alert_time.pop((interface, source_ip, msg_type), None)
        else:
            self._last_alert_time.clear()

    def evaluate_threshold_tradeoffs(self) -> Dict[str, Any]:
        """
        Explains how threshold tuning impacts false positives and false negatives.
        Useful for lab operators calibrating monitoring thresholds for diverse IoT workloads.
        """
        return {
            "configured_thresholds": {
                "max_ns_per_sec": self.thresholds.max_ns_per_sec,
                "max_na_per_sec": self.thresholds.max_na_per_sec,
                "max_rs_per_sec": self.thresholds.max_rs_per_sec,
                "rolling_window_seconds": self.window_sec,
                "cooldown_seconds": self.cooldown_sec,
            },
            "tradeoff_analysis": {
                "lower_thresholds": (
                    "Higher sensitivity; detects low-volume reconnaissance scans and slow port scans, "
                    "but increases False Positives during valid host migrations, address re-resolutions, or DHCPv6/SLAAC churn."
                ),
                "balanced_thresholds (current)": (
                    f"Configured at {self.thresholds.max_ns_per_sec} NS/sec over {self.window_sec}s. "
                    "Optimized to suppress benign retransmissions (RFC 4861 allows 3 rapid solicitations) "
                    "while reliably flagging sustained volumetric floods or address exhaustion attacks."
                ),
                "higher_thresholds": (
                    "Zero false alarms in high-traffic environments, but increases False Negatives "
                    "by allowing stealthy or rate-throttled discovery bursts to pass undetected."
                ),
            },
        }

