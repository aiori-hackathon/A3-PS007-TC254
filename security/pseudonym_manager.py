import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass

from security.audit_logger import PrivacyAuditLogger

@dataclass
class PseudonymRecord:
    pseudonym: str
    tenant_id: str
    session_id: str
    ipv6_address: str
    created_at: datetime
    expires_at: datetime
    is_expired: bool = False

    def is_active(self, current_time: Optional[datetime] = None) -> bool:
        if self.is_expired:
            return False
        now = current_time or datetime.now(timezone.utc)
        return now < self.expires_at

class PseudonymManager:
    """
    Manages short-lived, privacy-preserving device pseudonyms.
    Generates pseudonyms using Python's cryptographically secure secrets module.
    Maintains strict separation between active correlation state and permanent history.
    """
    def __init__(self, default_epoch_seconds: int = 120):
        self.epoch_duration = timedelta(seconds=default_epoch_seconds)
        # Active in-memory correlation mapping: pseudonym -> PseudonymRecord
        self._active_pseudonyms: Dict[str, PseudonymRecord] = {}

    def generate_pseudonym(self) -> str:
        """
        Generate a cryptographically random, collision-resistant pseudonym.
        Format: p6g-ps-<24 base64url characters>
        """
        token = secrets.token_urlsafe(16)
        return f"p6g-ps-{token}"

    def issue_pseudonym_for_session(
        self,
        session_id: str,
        tenant_id: str,
        current_ipv6: str,
        current_time: Optional[datetime] = None,
    ) -> PseudonymRecord:
        """
        Issues a new temporary pseudonym for an authenticated device session.
        """
        now = current_time or datetime.now(timezone.utc)
        expires_at = now + self.epoch_duration

        pseudo = self.generate_pseudonym()
        record = PseudonymRecord(
            pseudonym=pseudo,
            tenant_id=tenant_id,
            session_id=session_id,
            ipv6_address=current_ipv6,
            created_at=now,
            expires_at=expires_at,
            is_expired=False,
        )

        self._active_pseudonyms[pseudo] = record

        PrivacyAuditLogger.log_event(
            "PSEUDONYM_ISSUED",
            tenant_id,
            {"epoch_seconds": int(self.epoch_duration.total_seconds())},
            pseudonym=pseudo
        )

        return record

    def lookup_active_pseudonym(
        self,
        pseudonym: str,
        tenant_id: str,
        current_time: Optional[datetime] = None
    ) -> Optional[PseudonymRecord]:
        """
        Look up active pseudonym. Rejects expired records or cross-tenant access.
        """
        rec = self._active_pseudonyms.get(pseudonym)
        if not rec:
            return None

        if rec.tenant_id != tenant_id:
            PrivacyAuditLogger.log_event("ACCESS_DENIED", tenant_id, {"reason": "cross_tenant_pseudonym_lookup"}, pseudonym=pseudonym)
            return None

        now = current_time or datetime.now(timezone.utc)
        if not rec.is_active(now):
            # Expired mapping: reject and mark for cleanup
            rec.is_expired = True
            return None

        return rec

    def purge_expired_mappings(self, current_time: Optional[datetime] = None) -> int:
        """
        Purges expired pseudonym records from active storage.
        """
        now = current_time or datetime.now(timezone.utc)
        expired_keys = [k for k, v in self._active_pseudonyms.items() if not v.is_active(now)]
        
        for k in expired_keys:
            rec = self._active_pseudonyms.pop(k)
            PrivacyAuditLogger.log_event(
                "MAPPING_REMOVED",
                rec.tenant_id,
                {"reason": "expired_epoch"},
                pseudonym=rec.pseudonym
            )

        return len(expired_keys)
