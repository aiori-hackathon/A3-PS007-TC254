import pytest
from datetime import datetime, timezone, timedelta
from security.auth_manager import SessionManager, DEVICE_CREDENTIALS_STORE
from security.pseudonym_manager import PseudonymManager
from security.correlation_engine import CorrelationEngine
from security.audit_logger import PrivacyAuditLogger

def test_mapping_removal_and_purge():
    pm = PseudonymManager(default_epoch_seconds=60)
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Issue 2 pseudonyms
    rec1 = pm.issue_pseudonym_for_session("sess-1", "tenant-alpha", "2001:db8:6::11", current_time=now)
    rec2 = pm.issue_pseudonym_for_session("sess-2", "tenant-alpha", "2001:db8:6::12", current_time=now)

    # Active lookup at t = 30s
    t_30 = now + timedelta(seconds=30)
    assert pm.lookup_active_pseudonym(rec1.pseudonym, "tenant-alpha", current_time=t_30) is not None

    # Expired lookup at t = 65s (must be immediately rejected)
    t_65 = now + timedelta(seconds=65)
    assert pm.lookup_active_pseudonym(rec1.pseudonym, "tenant-alpha", current_time=t_65) is None

    # Purge mappings
    purged_count = pm.purge_expired_mappings(current_time=t_65)
    assert purged_count == 2
    assert len(pm._active_pseudonyms) == 0

def test_address_rotation_authorization():
    sm = SessionManager(default_ttl_seconds=300)
    pm = PseudonymManager(default_epoch_seconds=120)
    engine = CorrelationEngine(sm, pm)

    cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]
    ok, token, _ = sm.authenticate_device("p6g-iot1", cred["tenant_id"], cred["secret"])
    assert ok is True

    # Authorize rotation from 2001:db8:6::11 -> 2001:db8:6::99
    auth_ok, new_pseudo, msg = engine.authorize_address_rotation(
        session_id=token,
        tenant_id="tenant-alpha",
        old_ipv6="2001:db8:6::11",
        new_ipv6="2001:db8:6::99",
    )
    assert auth_ok is True
    assert new_pseudo is not None
    assert new_pseudo.startswith("p6g-ps-")

def test_unauthorized_correlation_rejection():
    sm = SessionManager(default_ttl_seconds=300)
    pm = PseudonymManager()
    engine = CorrelationEngine(sm, pm)

    # Attempt rotation with fabricated or expired session token
    auth_ok, new_pseudo, msg = engine.authorize_address_rotation(
        session_id="fabricated-or-expired-token",
        tenant_id="tenant-alpha",
        old_ipv6="2001:db8:6::11",
        new_ipv6="2001:db8:6::99",
    )
    assert auth_ok is False
    assert new_pseudo is None
    assert "denied" in msg.lower()

    # Direct passive correlation rejection
    ok, refuse_msg = engine.attempt_unauthorized_correlation("2001:db8:6::11", "2001:db8:6::99")
    assert ok is False
    assert "prohibits passive fingerprinting" in refuse_msg

def test_audit_log_data_minimization():
    """
    Test 10: Verify that audit events NEVER log plaintext passwords, bearer tokens,
    or sensitive cross-address tracking tables.
    """
    raw_token = "very-sensitive-bearer-token-12345"
    raw_secret = "super-secret-password-xyz"

    record = PrivacyAuditLogger.log_event(
        event_name="SESSION_AUTH_TEST",
        tenant_id="tenant-alpha",
        details={
            "bearer_token": raw_token,
            "device_password": raw_secret,
            "safe_metric": 42,
        },
        device_id="p6g-iot1",
        pseudonym="p6g-ps-123456",
    )

    record_str = str(record)
    assert raw_token not in record_str
    assert raw_secret not in record_str
    assert record["details"]["bearer_token"] == "[REDACTED_CREDENTIAL]"
    assert record["details"]["device_password"] == "[REDACTED_CREDENTIAL]"
    assert record["details"]["safe_metric"] == 42
    # Ensure device identifier is masked
    assert record["device_ref"] != "p6g-iot1"
    assert "p6g-" in record["device_ref"]
