import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, Any
from collections import defaultdict

from security.audit_logger import PrivacyAuditLogger

# Simulated secure device credentials for the prototype
# In a full deployment, this would be backed by 802.1AR Secure Device Identifiers
# or mutual TLS with hardware TPM/secure elements.
DEVICE_CREDENTIALS_STORE: Dict[str, Dict[str, str]] = {
    "p6g-iot1": {"tenant_id": "tenant-alpha", "secret": "sec-thermostat-alpha-9921"},
    "p6g-iot2": {"tenant_id": "tenant-alpha", "secret": "sec-heartmon-alpha-4412"},
    "p6g-iot3": {"tenant_id": "tenant-alpha", "secret": "sec-flowmeter-alpha-7834"},
    "p6g-iot4": {"tenant_id": "tenant-beta",  "secret": "sec-cctvcam-beta-1198"},
    "p6g-iot5": {"tenant_id": "tenant-beta",  "secret": "sec-airsensor-beta-5563"},
}

class Session:
    def __init__(
        self,
        session_id: str,
        device_id: str,
        tenant_id: str,
        created_at: datetime,
        expires_at: datetime,
    ):
        self.session_id = session_id
        self.device_id = device_id
        self.tenant_id = tenant_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.is_revoked = False

    def is_valid(self, current_time: Optional[datetime] = None) -> bool:
        if self.is_revoked:
            return False
        now = current_time or datetime.now(timezone.utc)
        return now < self.expires_at

class SessionManager:
    """
    Manages authenticated, time-limited device sessions.
    
    PROTOTYPE LIMITATIONS:
    - Uses pre-shared device secrets for prototype demonstration.
    - Does not provide hardware-rooted attestation or full EAP-TLS.
    - In production, device identity should be verified via 802.1AR DevID certificates.
    """
    def __init__(self, default_ttl_seconds: int = 300, max_auth_attempts: int = 5, rate_window_seconds: int = 60):
        self.default_ttl = timedelta(seconds=default_ttl_seconds)
        self.max_attempts = max_auth_attempts
        self.rate_window = timedelta(seconds=rate_window_seconds)
        
        self._sessions: Dict[str, Session] = {}
        self._auth_attempts: Dict[str, list] = defaultdict(list)

    def _check_rate_limit(self, device_id: str, current_time: datetime) -> bool:
        """Rate limit authentication attempts per device identifier."""
        attempts = [t for t in self._auth_attempts[device_id] if (current_time - t) < self.rate_window]
        self._auth_attempts[device_id] = attempts
        return len(attempts) < self.max_attempts

    def authenticate_device(
        self,
        device_id: str,
        tenant_id: str,
        provided_secret: str,
        current_time: Optional[datetime] = None
    ) -> Tuple[bool, Optional[str], str]:
        """
        Authenticate a device and issue a cryptographically secure, random session token.
        """
        now = current_time or datetime.now(timezone.utc)

        if not self._check_rate_limit(device_id, now):
            PrivacyAuditLogger.log_event("SESSION_REJECTED", tenant_id, {"reason": "rate_limited"}, device_id=device_id)
            return False, None, "Authentication rate limit exceeded. Please wait before retrying."

        self._auth_attempts[device_id].append(now)

        cred = DEVICE_CREDENTIALS_STORE.get(device_id)
        if not cred:
            PrivacyAuditLogger.log_event("SESSION_REJECTED", tenant_id, {"reason": "unknown_device"}, device_id=device_id)
            return False, None, "Invalid device credentials."

        if cred["tenant_id"] != tenant_id:
            PrivacyAuditLogger.log_event("ACCESS_DENIED", tenant_id, {"reason": "tenant_mismatch"}, device_id=device_id)
            return False, None, "Device does not belong to specified tenant."

        # Constant time secret comparison to prevent timing side channels
        if not secrets.compare_digest(cred["secret"], provided_secret):
            PrivacyAuditLogger.log_event("SESSION_REJECTED", tenant_id, {"reason": "invalid_secret"}, device_id=device_id)
            return False, None, "Invalid device credentials."

        # Issue secure 256-bit token
        session_token = secrets.token_urlsafe(32)
        session = Session(
            session_id=session_token,
            device_id=device_id,
            tenant_id=tenant_id,
            created_at=now,
            expires_at=now + self.default_ttl,
        )
        self._sessions[session_token] = session

        PrivacyAuditLogger.log_event(
            "SESSION_CREATED",
            tenant_id,
            {"ttl_seconds": int(self.default_ttl.total_seconds())},
            device_id=device_id
        )

        return True, session_token, "Authentication successful."

    def validate_session(
        self,
        session_id: str,
        tenant_id: str,
        current_time: Optional[datetime] = None
    ) -> Tuple[bool, Optional[Session], str]:
        """
        Validates session status, expiry, and tenant boundary.
        """
        session = self._sessions.get(session_id)
        if not session:
            return False, None, "Session not found."

        if session.tenant_id != tenant_id:
            PrivacyAuditLogger.log_event("ACCESS_DENIED", tenant_id, {"reason": "cross_tenant_session_query"})
            return False, None, "Cross-tenant session access denied."

        now = current_time or datetime.now(timezone.utc)
        if not session.is_valid(now):
            PrivacyAuditLogger.log_event("SESSION_EXPIRED", tenant_id, {"session_expired": True})
            return False, None, "Session is expired or has been revoked."

        return True, session, "Session valid."

    def revoke_session(self, session_id: str, tenant_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session and session.tenant_id == tenant_id:
            session.is_revoked = True
            PrivacyAuditLogger.log_event("SESSION_REVOKED", tenant_id)
            return True
        return False
