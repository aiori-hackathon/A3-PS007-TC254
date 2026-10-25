import pytest
from network.traffic_simulator import NormalTrafficSimulator
from network.address_rotator import AddressRotationManager
from security.auth_manager import SessionManager, DEVICE_CREDENTIALS_STORE
from security.pseudonym_manager import PseudonymManager
from security.correlation_engine import CorrelationEngine

def test_traffic_simulator_lifecycle():
    sim = NormalTrafficSimulator()
    status = sim.start_traffic_simulation(duration_seconds=2, packet_interval_sec=0.2)
    
    assert status["is_running"] is True
    assert status["scenario_id"] is not None
    assert len(status["target_namespaces"]) == 5
    assert status["traffic_profile"] == "benign_iot_telemetry"

    # Stop simulator
    stopped = sim.stop_traffic_simulation()
    assert stopped["is_running"] is False
    assert stopped["stop_time"] is not None
    assert stopped["packets_sent"] >= 0

def test_address_rotator_authorized_cycle():
    sm = SessionManager()
    pm = PseudonymManager()
    engine = CorrelationEngine(sm, pm)
    rotator = AddressRotationManager(engine)

    # Authenticate device p6g-iot1
    cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]
    ok, token, _ = sm.authenticate_device("p6g-iot1", cred["tenant_id"], cred["secret"])
    assert ok is True

    # Execute authorized address rotation
    success, rec, msg = rotator.rotate_device_address(
        device_id="p6g-iot1",
        session_token=token,
        tenant_id=cred["tenant_id"],
        old_ipv6="2001:db8:6::11",
        apply_network_change=False,
    )

    assert success is True
    assert rec["device_id"] == "p6g-iot1"
    assert rec["old_ipv6"] == "2001:db8:6::11"
    assert rec["new_ipv6"].startswith("2001:db8:6:")
    assert rec["new_pseudonym"].startswith("p6g-ps-")
    assert rec["rfc_standard"] == "RFC 8981"
    assert rec["duration_ms"] >= 0.0

def test_address_rotator_blocked_with_revoked_session():
    sm = SessionManager()
    pm = PseudonymManager()
    engine = CorrelationEngine(sm, pm)
    rotator = AddressRotationManager(engine)

    cred = DEVICE_CREDENTIALS_STORE["p6g-iot2"]
    ok, token, _ = sm.authenticate_device("p6g-iot2", cred["tenant_id"], cred["secret"])
    assert ok is True

    # Revoke session
    sm.revoke_session(token, cred["tenant_id"])

    # Attempt rotation
    success, rec, msg = rotator.rotate_device_address(
        device_id="p6g-iot2",
        session_token=token,
        tenant_id=cred["tenant_id"],
        old_ipv6="2001:db8:6::12",
    )

    assert success is False
    assert "denied" in msg.lower()
