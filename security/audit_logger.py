import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger("priv6guard.audit")

class PrivacyAuditLogger:
    """
    Structured audit logger for privacy-relevant events.
    Enforces data minimization: Never logs passwords, bearer tokens, or full
    private address-to-device tracking maps.
    """
    @staticmethod
    def _mask_id(identifier: str) -> str:
        if not identifier:
            return "N/A"
        # Return first 4 chars + 8-char SHA-256 digest
        digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()[:8]
        return f"{identifier[:4]}...[{digest}]"

    @classmethod
    def log_event(
        cls,
        event_name: str,
        tenant_id: str,
        details: Optional[Dict[str, Any]] = None,
        device_id: Optional[str] = None,
        pseudonym: Optional[str] = None,
    ):
        safe_details = {}
        if details:
            for k, v in details.items():
                lower_k = k.lower()
                if any(sec in lower_k for sec in ("token", "secret", "password", "key", "auth")):
                    safe_details[k] = "[REDACTED_CREDENTIAL]"
                else:
                    safe_details[k] = v

        record = {
            "audit_event": event_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "device_ref": cls._mask_id(device_id) if device_id else None,
            "pseudonym": pseudonym,
            "details": safe_details,
        }
        logger.info(f"AUDIT_RECORD: {record}")
        return record
