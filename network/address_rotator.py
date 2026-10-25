import secrets
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG
from security.correlation_engine import CorrelationEngine
from security.audit_logger import PrivacyAuditLogger

class AddressRotationManager:
    """
    Simulates controlled IPv6 temporary address rotation (RFC 8981 privacy extensions).

    DISTINCTION FROM OPERATING SYSTEM PRIVACY EXTENSIONS:
    In a native OS kernel (RFC 8981), address rotation is autonomous: the kernel generates
    MD5/SHA-256 randomized interface identifiers based on a secret key and clock counter,
    managing preferred vs valid lifetimes. Deprecated addresses remain bound to open sockets
    until closed.

    In this prototype simulator:
    1. We generate cryptographically randomized temporary IIDs in the lab subnet.
    2. We configure the new address in the device's isolated namespace.
    3. We notify the privacy correlation manager via the authenticated control path.
    4. We retire the old address cleanly.
    5. We record rotation event timestamps for audit and evaluation metrics.
    """
    def __init__(self, correlation_engine: CorrelationEngine, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.correlation_engine = correlation_engine
        self.config = config

    def generate_random_temporary_ipv6(self) -> str:
        """Generates a random 64-bit host identifier within prefix 2001:db8:6::/64."""
        # Generate 4 random 16-bit hex chunks
        h1 = secrets.token_hex(2)
        h2 = secrets.token_hex(2)
        h3 = secrets.token_hex(2)
        h4 = secrets.token_hex(2)
        return f"2001:db8:6:{h1}:{h2}:{h3}:{h4}"

    def rotate_device_address(
        self,
        device_id: str,
        session_token: str,
        tenant_id: str,
        old_ipv6: str,
        current_time: Optional[datetime] = None,
        apply_network_change: bool = False,
    ) -> Tuple[bool, Dict[str, Any], str]:
        """
        Executes an authorized address rotation for a device.
        """
        t0 = time.time()
        start_ts = current_time or datetime.now(timezone.utc)

        # 1. Generate new temporary IPv6 address
        new_ipv6 = self.generate_random_temporary_ipv6()

        # 2. Authorize via correlation engine
        authorized, new_pseudonym, msg = self.correlation_engine.authorize_address_rotation(
            session_id=session_token,
            tenant_id=tenant_id,
            old_ipv6=old_ipv6,
            new_ipv6=new_ipv6,
            current_time=start_ts,
        )

        if not authorized or not new_pseudonym:
            return False, {}, msg

        # 3. Apply safe network interface update if requested (in live lab)
        if apply_network_change:
            device_cfg = next((d for d in self.config.devices if d.lab_id == device_id), None)
            if device_cfg:
                ns = device_cfg.namespace
                peer = device_cfg.ns_peer
                # Add new address
                subprocess.run(
                    ["ip", "-n", ns, "addr", "add", f"{new_ipv6}/64", "dev", peer, "nodad"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                # Remove old address
                subprocess.run(
                    ["ip", "-n", ns, "addr", "del", f"{old_ipv6}/64", "dev", peer],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

        t1 = time.time()
        duration_ms = (t1 - t0) * 1000.0

        rotation_record = {
            "device_id": device_id,
            "tenant_id": tenant_id,
            "old_ipv6": old_ipv6,
            "new_ipv6": new_ipv6,
            "new_pseudonym": new_pseudonym,
            "rotation_timestamp": start_ts.isoformat(),
            "duration_ms": round(duration_ms, 2),
            "rfc_standard": "RFC 8981",
        }

        PrivacyAuditLogger.log_event(
            "ADDRESS_ROTATION_COMPLETED",
            tenant_id,
            {"duration_ms": round(duration_ms, 2)},
            device_id=device_id,
            pseudonym=new_pseudonym
        )

        return True, rotation_record, "Address rotation executed successfully."
