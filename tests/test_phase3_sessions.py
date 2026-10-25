import pytest
from datetime import datetime, timezone, timedelta
from security.auth_manager import SessionManager, DEVICE_CREDENTIALS_STORE
from backend.storage.database import Database

def test_session_authentication_success_and_failure():
    sm = SessionManager(default_ttl_seconds=300)
    
    # 1. Valid authentication
    cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]
    ok, token, msg = sm.authenticate_device("p6g-iot1", cred["tenant_id"], cred["secret"])
    assert ok is True
    assert token is not None
    assert len(token) > 20

    # 2. Invalid secret
    ok_bad, token_bad, msg_bad = sm.authenticate_device("p6g-iot1", cred["tenant_id"], "wrong-secret")
    assert ok_bad is False
    assert token_bad is None
    assert "Invalid device credentials" in msg_bad

    # 3. Unknown device
    ok_unk, _, msg_unk = sm.authenticate_device("unknown-dev", "tenant-alpha", "some-sec")
    assert ok_unk is False
    assert "Invalid device credentials" in msg_unk

def test_session_rate_limiting():
    sm = SessionManager(max_auth_attempts=3, rate_window_seconds=60)
    cred = DEVICE_CREDENTIALS_STORE["p6g-iot2"]

    # 3 attempts allowed
    for _ in range(3):
        sm.authenticate_device("p6g-iot2", cred["tenant_id"], "bad-secret")

    # 4th attempt must be rate-limited
    ok, token, msg = sm.authenticate_device("p6g-iot2", cred["tenant_id"], cred["secret"])
    assert ok is False
    assert "rate limit exceeded" in msg.lower()

def test_session_expiry_with_controllable_clock():
    sm = SessionManager(default_ttl_seconds=300)
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    cred = DEVICE_CREDENTIALS_STORE["p6g-iot3"]
    ok, token, _ = sm.authenticate_device("p6g-iot3", cred["tenant_id"], cred["secret"], current_time=now)
    assert ok is True

    # Check validity at t = 299s (should be valid)
    t_valid = now + timedelta(seconds=299)
    valid, sess, _ = sm.validate_session(token, cred["tenant_id"], current_time=t_valid)
    assert valid is True
    assert sess is not None

    # Check validity at t = 301s (should be expired)
    t_expired = now + timedelta(seconds=301)
    valid_exp, sess_exp, msg = sm.validate_session(token, cred["tenant_id"], current_time=t_expired)
    assert valid_exp is False
    assert sess_exp is None
    assert "expired" in msg.lower()

def test_tenant_isolation_sessions():
    sm = SessionManager()
    cred_a = DEVICE_CREDENTIALS_STORE["p6g-iot1"] # tenant-alpha
    
    ok, token_a, _ = sm.authenticate_device("p6g-iot1", "tenant-alpha", cred_a["secret"])
    assert ok is True

    # Tenant B tries to validate Tenant A's token
    valid_b, _, msg_b = sm.validate_session(token_a, "tenant-beta")
    assert valid_b is False
    assert "Cross-tenant session access denied" in msg_b

    # Guessing invalid session ID
    valid_guess, _, _ = sm.validate_session("fabricated-session-id-12345", "tenant-alpha")
    assert valid_guess is False

@pytest.mark.asyncio
async def test_restart_behavior_for_expired_mappings(temp_db: Database):
    """
    Test 9: Verifies that expired mappings stored in SQLite remain permanently expired
    and are not reactivated or restored when the application restarts.
    """
    now = datetime.now(timezone.utc)
    expired_time = (now - timedelta(seconds=100)).isoformat()

    # Insert an expired mapping into SQLite
    await temp_db.add_pseudonym_mapping(
        device_id="p6g-iot1",
        pseudonym="p6g-ps-expired-before-restart",
        ipv6_address="2001:db8:6::11",
        tenant_id="tenant-alpha",
        session_id="old-sess-1",
        expires_at=expired_time,
    )

    # Purge the expired record
    await temp_db.purge_expired_pseudonyms()

    # Simulate restart by creating a new database connection object to the same file
    db_after_restart = Database(temp_db.db_path)
    
    # Verify mapping is still rejected and cannot be queried
    rec = await db_after_restart.get_active_pseudonym_mapping("p6g-ps-expired-before-restart")
    assert rec is None, "Expired mapping must remain purged and unqueryable across restarts"
