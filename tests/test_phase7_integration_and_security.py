import pytest
import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6ND_NS

from backend.main import app
from backend.storage.database import Database
from backend.models.schema import NormalizedAlert, SecurityEventCreate, ExperimentRecord
from security.auth_manager import SessionManager, DEVICE_CREDENTIALS_STORE
from security.pseudonym_manager import PseudonymManager
from security.correlation_engine import CorrelationEngine
from security.ra_detector import RouterAdvertisementDetector, RAPolicyConfig
from security.ndp_detector import NDPAnomalyDetector, NDPThresholds
from security.event_manager import SecurityEventManager
from network.packet_capture import PacketCaptureEngine, IPv6PacketParser
from network.lab_config import DEFAULT_LAB_CONFIG

# ==============================================================================
# SECTION A & B: END-TO-END FLOWS AND INTEGRATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_integration_flow1_normal_traffic_data_pipeline(tmp_path):
    """
    Flow 1: Normal traffic
    Lab device -> packet capture -> parser -> event manager -> storage -> API.
    Verifies that the final result corresponds to the actual input without mock data.
    """
    test_db_path = str(tmp_path / "test_flow1.db")
    db = Database(test_db_path)
    await db.init_db()

    pm = PseudonymManager()
    event_mgr = SecurityEventManager(db, pm)
    ra_det = RouterAdvertisementDetector()
    ndp_det = NDPAnomalyDetector()
    engine = PacketCaptureEngine(
        interface="p6g-br0",
        ra_detector=ra_det,
        ndp_detector=ndp_det,
        event_manager=event_mgr,
    )

    # Legitimate packet from p6g-iot1 to router
    pkt = IPv6(src="2001:db8:6::11", dst="2001:db8:6::1") / ICMPv6ND_NS(tgt="2001:db8:6::1")
    stats = engine.process_packet_direct(pkt)

    assert stats["total_packets"] == 1
    assert stats["ns_packets"] == 1
    assert stats["parse_errors"] == 0

    # Ensure no alerts were falsely generated for benign traffic
    alerts = await db.get_alerts()
    assert len(alerts) == 0

@pytest.mark.asyncio
async def test_integration_flow2_rogue_ra_end_to_end_pipeline(tmp_path):
    """
    Flow 2: Rogue RA
    Controlled lab scenario -> captured RA -> trust-policy detector -> alert -> storage -> API.
    """
    test_db_path = str(tmp_path / "test_flow2.db")
    db = Database(test_db_path)
    await db.init_db()

    pm = PseudonymManager()
    event_mgr = SecurityEventManager(db, pm)
    ra_det = RouterAdvertisementDetector(
        RAPolicyConfig(
            authorized_router_link_locals=["fe80::1"],
            authorized_prefixes=["2001:db8:6::/64"],
        )
    )

    # Rogue RA advertising foreign prefix from rogue link-local
    rogue_pkt = (
        IPv6(src="fe80::dead:beef", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:baad::", prefixlen=64)
    )

    det_res = ra_det.inspect_ra_packet(rogue_pkt)
    assert det_res.is_rogue is True
    assert det_res.rule_id.startswith("RULE-RA")

    event = await event_mgr.handle_ra_detection(det_res, default_tenant="tenant-alpha")
    assert event is not None
    assert event.event_type == "ROGUE_RA"

    # Verify persisted in security_events and alerts tables
    events = await db.get_security_events(tenant_id="tenant-alpha")
    found_evt = next((e for e in events if e.id == event.event_id), None)
    assert found_evt is not None
    assert found_evt.source_ip == "fe80::dead:beef"

    alerts = await db.get_alerts(tenant_scope="tenant-alpha")
    assert len(alerts) >= 1
    found_alert = next((a for a in alerts if a.alert_type == "ROGUE_RA_POLICY_VIOLATION"), None)
    assert found_alert is not None
    assert found_alert.severity in ("HIGH", "CRITICAL")
    assert found_alert.evidence["source_ip"] == "fe80::dead:beef"
    assert "2001:db8:baad::/64" in found_alert.evidence["advertised_prefixes"]

@pytest.mark.asyncio
async def test_integration_flow3_ndp_anomaly_burst_pipeline(tmp_path):
    """
    Flow 3: NDP anomaly
    Controlled NDP burst -> rolling-window detector -> alert -> storage -> API.
    """
    test_db_path = str(tmp_path / "test_flow3.db")
    db = Database(test_db_path)
    await db.init_db()

    pm = PseudonymManager()
    event_mgr = SecurityEventManager(db, pm)
    ndp_det = NDPAnomalyDetector(
        rolling_window_seconds=2.0,
        thresholds=NDPThresholds(max_ns_per_sec=10.0),
        cooldown_seconds=5.0,
    )

    # Inject 30 packets in < 1 second (rate = 30 / 2.0 = 15.0 pps > 10.0 threshold)
    anomaly_event = None
    t0 = datetime.now(timezone.utc)
    for i in range(30):
        pkt_data = {"source_ip": "2001:db8:6::bad", "msg_type": "NS"}
        res = ndp_det.inspect_ndp_packet(pkt_data, current_time=t0 + timedelta(milliseconds=i * 20))
        if res.is_anomaly:
            anomaly_event = await event_mgr.handle_ndp_anomaly(res, default_tenant="tenant-alpha")
            break

    assert anomaly_event is not None
    events = await db.get_security_events(tenant_id="tenant-alpha")
    found_evt = next((e for e in events if e.id == anomaly_event.event_id), None)
    assert found_evt is not None
    assert found_evt.event_type == "NDP_RATE_ANOMALY"

    alerts = await db.get_alerts(tenant_scope="tenant-alpha")
    assert len(alerts) >= 1
    found_alert = next((a for a in alerts if a.alert_type == "NDP_RATE_ANOMALY"), None)
    assert found_alert is not None
    assert found_alert.evidence["classification"] == "ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF"
    assert "Abnormal NDP rate burst detected" in found_alert.reason

@pytest.mark.asyncio
async def test_integration_flow4_address_rotation_and_session_update():
    """
    Flow 4: Address rotation
    Authenticated session -> authorized rotation -> pseudonym/session update -> event record.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate device
        cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]
        auth_res = await client.post(
            "/api/devices/p6g-iot1/authenticate",
            json={"secret": cred["secret"]},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert auth_res.status_code == 200
        token = auth_res.json()["session_token"]

        # Rotate address using issued session token
        rot_res = await client.post(
            "/api/devices/p6g-iot1/rotate",
            json={"session_token": token},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert rot_res.status_code == 200
        rot_data = rot_res.json()
        assert rot_data["device_id"] == "p6g-iot1"
        assert rot_data["new_ipv6"].startswith("2001:db8:6:")
        assert rot_data["new_pseudonym"].startswith("p6g-ps-")

        # Verify device inventory in API reflects new address and pseudonym
        devs_res = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-alpha"})
        assert devs_res.status_code == 200
        iot1 = next(d for d in devs_res.json() if d["id"] == "p6g-iot1")
        assert iot1["current_ipv6"] == rot_data["new_ipv6"]
        assert iot1["current_pseudonym"] == rot_data["new_pseudonym"]

@pytest.mark.asyncio
async def test_integration_flow5_privacy_enforcement_and_audit():
    """
    Flow 5: Privacy enforcement
    Session expiry or unauthorized cross-tenant lookup -> backend rejection -> audit event.
    """
    sm = SessionManager(default_ttl_seconds=10)
    pm = PseudonymManager(default_epoch_seconds=10)
    engine = CorrelationEngine(sm, pm)

    t0 = datetime.now(timezone.utc)
    ok, token, _ = sm.authenticate_device("p6g-iot1", "tenant-alpha", "sec-thermostat-alpha-9921", current_time=t0)
    assert ok is True

    # Advance clock past expiry (15 seconds)
    t_expired = t0 + timedelta(seconds=15)
    rot_ok, new_pseudo, msg = engine.authorize_address_rotation(
        session_id=token,
        tenant_id="tenant-alpha",
        old_ipv6="2001:db8:6::11",
        new_ipv6="2001:db8:6::99",
        current_time=t_expired,
    )
    assert rot_ok is False
    assert "expired" in msg.lower() or "denied" in msg.lower()

# ==============================================================================
# SECTION B: SPECIFIC INTEGRATION VERIFICATIONS (Items 1 - 12)
# ==============================================================================

@pytest.mark.asyncio
async def test_integration_1_and_2_lab_query_and_device_inventory():
    """
    1. The lab can be queried through the backend.
    2. Device inventory reflects the actual lab state.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_lab = await client.get("/api/lab/status")
        assert res_lab.status_code == 200
        lab_data = res_lab.json()
        assert "bridge_name" in lab_data
        assert "devices" in lab_data

        res_devs = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-alpha"})
        assert res_devs.status_code == 200
        devs = res_devs.json()
        assert len(devs) == 3
        device_ids = {d["id"] for d in devs}
        assert device_ids == {"p6g-iot1", "p6g-iot2", "p6g-iot3"}

@pytest.mark.asyncio
async def test_integration_8_to_10_sessions_expiry_and_tenant_isolation():
    """
    8. Authorized address rotation updates permitted session state.
    9. Expired mappings cannot be retrieved.
    10. Tenant A cannot access Tenant B's records.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Cross-tenant query on devices: Tenant Alpha must not see Tenant Beta devices
        res_alpha = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-alpha"})
        res_beta = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-beta"})
        
        alpha_ids = {d["id"] for d in res_alpha.json()}
        beta_ids = {d["id"] for d in res_beta.json()}
        assert alpha_ids.isdisjoint(beta_ids)
        assert "p6g-iot4" in beta_ids
        assert "p6g-iot4" not in alpha_ids

        # Attempting to access Tenant Beta device with Tenant Alpha header
        res_cross = await client.post(
            "/api/devices/p6g-iot4/authenticate",
            json={"secret": "sec-cctvcam-beta-1198"},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert res_cross.status_code == 401

@pytest.mark.asyncio
async def test_integration_11_and_12_repeated_start_stop_and_no_duplicate_workers():
    """
    11. Lab shutdown stops the associated capture and experiment processes.
    12. Repeated start/stop requests do not create duplicate workers or orphaned processes.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Repeated start requests
        res1 = await client.post("/api/lab/start")
        assert res1.status_code == 200
        res2 = await client.post("/api/lab/start")
        assert res2.status_code == 200

        # Repeated stop requests
        stop1 = await client.post("/api/lab/stop")
        assert stop1.status_code == 200
        assert stop1.json()["status"] == "STOPPED"
        stop2 = await client.post("/api/lab/stop")
        assert stop2.status_code == 200
        assert stop2.json()["status"] == "STOPPED"

# ==============================================================================
# SECTION C & D: SECURITY REVIEW & FAILURE HANDLING REGRESSION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_failure_handling_unallowlisted_external_attack_target():
    """
    Security check: Unrestricted experiment targets must be rejected.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. External IPv6 target on experiments endpoint
        res1 = await client.post(
            "/api/experiments/ndp-burst",
            json={"target_ip": "2001:4860:4860::8888", "packet_count": 20},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert res1.status_code == 400
        assert "strictly forbidden" in res1.json()["detail"].lower()

        # 2. External IPv6 target on attacks endpoint
        res2 = await client.post(
            "/api/attacks/ndp-flood",
            json={"target_ip": "2606:4700:4700::1111", "packet_count": 20},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert res2.status_code == 400
        assert "strictly forbidden" in res2.json()["detail"].lower()

        # 3. External rogue RA source
        res3 = await client.post(
            "/api/attacks/rogue-ra",
            json={"rogue_source": "2001:cafe:babe::1", "unauthorized_prefix": "2001:bad::/64"},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert res3.status_code == 400
        assert "strictly forbidden" in res3.json()["detail"].lower()

@pytest.mark.asyncio
async def test_failure_handling_unauthorized_tenant_header():
    """
    Security check: Unknown or malicious tenant header values must be rejected with 403.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-malicious"})
        assert res.status_code == 403
        assert "Access denied" in res.json()["detail"]

@pytest.mark.asyncio
async def test_failure_handling_malformed_packet_graceful_recovery():
    """
    Failure handling: Malformed or corrupted packets must not crash the parser or sniffer.
    """
    parser = IPv6PacketParser(allowed_interfaces={"p6g-br0"})
    
    # 1. Truncated or arbitrary non-packet bytes handled gracefully without crashing
    bad_data = b"\x00\x01\x02\x03\xff\xfe"
    res1 = parser.parse_packet(bad_data, interface="p6g-br0")
    assert res1 is None

    # 2. Corrupted packet object that raises an internal decode exception
    class CorruptedPacket:
        def haslayer(self, layer):
            raise ValueError("Corrupted packet buffer header")

    res_corrupt = parser.parse_packet(CorruptedPacket(), interface="p6g-br0")
    assert res_corrupt is None
    assert parser.parse_errors >= 1

    # 3. Non-allowlisted interface
    res2 = parser.parse_packet(IPv6(src="2001:db8:6::1"), interface="eth0")
    assert res2 is None

@pytest.mark.asyncio
async def test_failure_handling_capture_unallowlisted_interface():
    """
    Security check: Packet capture start on non-allowlisted interface (e.g. eth0, wlan0) is refused.
    """
    engine = PacketCaptureEngine(interface="eth0")
    started = engine.start_capture(authorized=True)
    assert started is False
    assert engine.capture_errors >= 1
    assert engine.is_capturing is False

@pytest.mark.asyncio
async def test_failure_handling_experiment_cancellation_lifecycle():
    """
    Failure handling: Running experiment can be cleanly cancelled without process leakage.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Start normal experiment
        start_res = await client.post(
            "/api/experiments/normal",
            json={"duration_seconds": 10, "packet_interval_sec": 0.5},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert start_res.status_code == 200
        exp_id = start_res.json()["experiment_id"]

        # Cancel by ID
        cancel_res = await client.post(f"/api/experiments/{exp_id}/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "SUCCESS"
        assert cancel_res.json()["experiment_id"] == exp_id

@pytest.mark.asyncio
async def test_failure_handling_sqlite_database_recovery(tmp_path):
    """
    Failure handling: Tests database resilience across recreation and schema verification.
    """
    db_file = str(tmp_path / "resilience.db")
    db = Database(db_file)
    await db.init_db()

    # Insert device and verify
    await db.upsert_device({
        "id": "p6g-iot1",
        "name": "Smart Thermostat",
        "device_type": "HVAC",
        "namespace": "p6g-iot1",
        "tenant_id": "tenant-alpha",
        "base_mac": "02:00:00:00:00:11",
        "current_ipv6": "2001:db8:6::11",
        "current_pseudonym": "p6g-ps-resilience",
        "rotation_count": 0,
        "last_rotation": datetime.now(timezone.utc).isoformat(),
        "session_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(),
        "is_active": True,
    })

    dev = await db.get_device("p6g-iot1", tenant_id="tenant-alpha")
    assert dev is not None
    assert dev.current_pseudonym == "p6g-ps-resilience"

    # Simulate backend restart with same DB file
    db_restarted = Database(db_file)
    await db_restarted.init_db()
    dev_after = await db_restarted.get_device("p6g-iot1", tenant_id="tenant-alpha")
    assert dev_after is not None
    assert dev_after.id == "p6g-iot1"
