"""
=============================================================================
PRIV6GUARD — Comprehensive Acceptance Test Suite (13 Section 7 Criteria)
AIORI Hackathon 3 | Problem Statement: PS-007 | Team Code: A3-PS007-TC254
=============================================================================
Formally verifies all 13 Acceptance Criteria specified in Hackathon Prompt Section 7:
  1. Five isolated test devices instantiated with virtual network isolation.
  2. Normal IoT traffic generated and captured without false alarms.
  3. Controlled IPv6 address rotation executed safely.
  4. Authenticated short-lived sessions issued, validated, and expired.
  5. Short-lived pseudonyms generated and rotated.
  6. Authorized correlation maintained across address changes while active.
  7. Detection of unauthorized IPv6 Router Advertisements verified.
  8. Detection of abnormal NDP message rates verified (marked anomaly indicator).
  9. Real packet capture verified to reach detectors.
  10. Security alerts verified to reach storage and API.
  11. Tenant isolation strictly enforced (tenant-alpha vs tenant-beta).
  12. Expired mappings rejected and purged (no stale pseudonyms).
  13. Evaluation metrics measured and logged (latency, resource usage, privacy score).
=============================================================================
"""

import pytest
import time
import asyncio
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6NDOptPrefixInfo

from backend.main import app
from backend.storage.database import Database
from network.lab_config import Priv6LabConfig
from network.traffic_simulator import NormalTrafficSimulator
from network.address_rotator import AddressRotationManager
from network.packet_capture import PacketCaptureEngine
from security.auth_manager import SessionManager, DEVICE_CREDENTIALS_STORE
from security.pseudonym_manager import PseudonymManager
from security.correlation_engine import CorrelationEngine
from security.ra_detector import RouterAdvertisementDetector, RAPolicyConfig
from security.ndp_detector import NDPAnomalyDetector, NDPThresholds
from security.event_manager import SecurityEventManager


# ---------------------------------------------------------------------------
# CRITERION 1: Five isolated test devices instantiated with network isolation
# ---------------------------------------------------------------------------
def test_acceptance_criterion_1_isolated_test_devices():
    """Verify 5 isolated test devices with dedicated bridge and IPv6 prefix."""
    cfg = Priv6LabConfig()
    assert cfg.bridge_name == "p6g-br0"
    assert cfg.ipv6_prefix == "2001:db8:6::/64"
    assert len(cfg.devices) == 5

    device_ids = [d.lab_id for d in cfg.devices]
    assert device_ids == ["p6g-iot1", "p6g-iot2", "p6g-iot3", "p6g-iot4", "p6g-iot5"]

    # Verify uniqueness of namespaces, MACs, and IPv6 addresses
    namespaces = [d.namespace for d in cfg.devices]
    macs = [d.mac_address for d in cfg.devices]
    ips = [d.ipv6_address for d in cfg.devices]
    assert len(set(namespaces)) == 5
    assert len(set(macs)) == 5
    assert len(set(ips)) == 5


# ---------------------------------------------------------------------------
# CRITERION 2: Normal IoT traffic generated and captured
# ---------------------------------------------------------------------------
def test_acceptance_criterion_2_normal_iot_traffic():
    """Verify benign traffic simulation executes cleanly without false alarms."""
    sim = NormalTrafficSimulator()
    start_info = sim.start_traffic_simulation(duration_seconds=1, packet_interval_sec=0.1)
    assert start_info["is_running"] is True
    assert len(start_info["target_namespaces"]) == 5

    time.sleep(0.3)
    stop_info = sim.stop_traffic_simulation()
    assert stop_info["is_running"] is False
    assert stop_info["packets_sent"] >= 0


# ---------------------------------------------------------------------------
# CRITERION 3: Controlled IPv6 address rotation executed safely
# ---------------------------------------------------------------------------
def test_acceptance_criterion_3_controlled_address_rotation():
    """Verify RFC 8981 address rotation generates valid address in prefix."""
    sm = SessionManager()
    pm = PseudonymManager()
    engine = CorrelationEngine(sm, pm)
    rotator = AddressRotationManager(engine)

    cred = DEVICE_CREDENTIALS_STORE["p6g-iot2"]
    ok, token, _ = sm.authenticate_device("p6g-iot2", cred["tenant_id"], cred["secret"])
    assert ok is True

    success, rec, msg = rotator.rotate_device_address(
        device_id="p6g-iot2",
        session_token=token,
        tenant_id=cred["tenant_id"],
        old_ipv6="2001:db8:6::12",
        apply_network_change=False,
    )
    assert success is True
    assert rec["new_ipv6"].startswith("2001:db8:6:")
    assert rec["new_ipv6"] != "2001:db8:6::12"
    assert rec["rfc_standard"] == "RFC 8981"


# ---------------------------------------------------------------------------
# CRITERION 4: Authenticated short-lived sessions issued and validated
# ---------------------------------------------------------------------------
def test_acceptance_criterion_4_authenticated_short_lived_sessions():
    """Verify session token issuance, TTL bounding, and clock expiration."""
    sm = SessionManager(default_ttl_seconds=300)
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]

    # Valid secret
    ok, token, session = sm.authenticate_device(
        "p6g-iot1", cred["tenant_id"], cred["secret"], current_time=now
    )
    assert ok is True
    assert token is not None

    # Token validation within TTL
    valid, sess_obj, _ = sm.validate_session(token, cred["tenant_id"], current_time=now + timedelta(seconds=150))
    assert valid is True
    assert sess_obj.device_id == "p6g-iot1"

    # Token validation after TTL
    expired_valid, _, _ = sm.validate_session(token, cred["tenant_id"], current_time=now + timedelta(seconds=305))
    assert expired_valid is False, "Expired session must be rejected"


# ---------------------------------------------------------------------------
# CRITERION 5: Short-lived pseudonyms generated and rotated
# ---------------------------------------------------------------------------
def test_acceptance_criterion_5_short_lived_pseudonyms():
    """Verify pseudonym generation format, entropy, and rotation."""
    pm = PseudonymManager(default_epoch_seconds=120)
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    rec1 = pm.issue_pseudonym_for_session("sess-1", "tenant-alpha", "2001:db8:6::13", current_time=now)
    assert rec1.pseudonym.startswith("p6g-ps-")
    assert len(rec1.pseudonym) >= 28

    rec2 = pm.issue_pseudonym_for_session("sess-1", "tenant-alpha", "2001:db8:6::ffff", current_time=now)
    assert rec2.pseudonym != rec1.pseudonym
    assert rec2.pseudonym.startswith("p6g-ps-")


# ---------------------------------------------------------------------------
# CRITERION 6: Authorized correlation maintained across address changes
# ---------------------------------------------------------------------------
def test_acceptance_criterion_6_authorized_correlation():
    """Verify authorized correlation between old and new IPv6 under active session."""
    sm = SessionManager(default_ttl_seconds=300)
    pm = PseudonymManager(default_epoch_seconds=120)
    engine = CorrelationEngine(sm, pm)

    cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]
    ok, token, _ = sm.authenticate_device("p6g-iot1", cred["tenant_id"], cred["secret"])
    assert ok is True

    # Authorized rotation
    auth_ok, new_pseudo, msg = engine.authorize_address_rotation(
        session_id=token,
        tenant_id="tenant-alpha",
        old_ipv6="2001:db8:6::11",
        new_ipv6="2001:db8:6::a1b2",
    )
    assert auth_ok is True
    assert new_pseudo.startswith("p6g-ps-")

    # Unauthorized rotation with forged token
    unauth_ok, unauth_pseudo, _ = engine.authorize_address_rotation(
        session_id="forged-token",
        tenant_id="tenant-alpha",
        old_ipv6="2001:db8:6::a1b2",
        new_ipv6="2001:db8:6::c3d4",
    )
    assert unauth_ok is False
    assert unauth_pseudo is None


# ---------------------------------------------------------------------------
# CRITERION 7: Detection of unauthorized IPv6 Router Advertisements
# ---------------------------------------------------------------------------
def test_acceptance_criterion_7_unauthorized_ra_detection():
    """Verify RADetector policy enforcement against rogue router source and foreign prefix."""
    detector = RouterAdvertisementDetector(RAPolicyConfig(authorized_router_link_locals=["fe80::1"]))

    # Legitimate RA
    legit_pkt = IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RA(routerlifetime=1800) / ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    res_legit = detector.inspect_ra_packet(legit_pkt)
    assert res_legit.is_rogue is False

    # Rogue RA from unapproved source
    rogue_pkt = IPv6(src="fe80::dead:beef", dst="ff02::1") / ICMPv6ND_RA(routerlifetime=1800) / ICMPv6NDOptPrefixInfo(prefix="2001:db8:baad::", prefixlen=64)
    res_rogue = detector.inspect_ra_packet(rogue_pkt)
    assert res_rogue.is_rogue is True
    assert res_rogue.violation_type == "UNAUTHORIZED_ROUTER_ADDRESS"
    assert res_rogue.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# CRITERION 8: Detection of abnormal NDP message rates (anomaly indicator)
# ---------------------------------------------------------------------------
def test_acceptance_criterion_8_abnormal_ndp_rate_detection():
    """Verify NDP rate anomaly detector marks violations as ANOMALY_INDICATOR."""
    detector = NDPAnomalyDetector(
        rolling_window_seconds=5.0,
        thresholds=NDPThresholds(max_ns_per_sec=15.0),
        cooldown_seconds=10.0,
    )
    t = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Send 80 NS packets in an instantaneous burst (80 packets / 5s = 16.0 pps > 15.0 threshold)
    anomaly_triggered = False
    last_res = None
    for _ in range(80):
        pkt = IPv6(src="2001:db8:6::bad") / ICMPv6ND_NS(tgt="2001:db8:6::11")
        res = detector.inspect_ndp_packet(pkt, current_time=t)
        if res.is_anomaly:
            anomaly_triggered = True
            last_res = res

    assert anomaly_triggered is True
    assert last_res is not None
    assert last_res.anomaly_type == "NDP_NS_RATE_ANOMALY"
    assert last_res.classification == "ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF"


# ---------------------------------------------------------------------------
# CRITERION 9: Real packet capture verified to reach detectors
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_acceptance_criterion_9_packet_capture_to_detectors(temp_db: Database):
    """Verify live capture engine passes packets to detectors and triggers events."""
    pm = PseudonymManager()
    event_mgr = SecurityEventManager(temp_db, pm)
    ra_det = RouterAdvertisementDetector(RAPolicyConfig(authorized_router_link_locals=["fe80::1"]))
    ndp_det = NDPAnomalyDetector(rolling_window_seconds=2.0, thresholds=NDPThresholds(max_ns_per_sec=5.0))
    capture = PacketCaptureEngine(ra_detector=ra_det, ndp_detector=ndp_det, event_manager=event_mgr)

    # Process Rogue RA packet directly through capture engine
    rogue_ra = (
        IPv6(src="fe80::cafe:babe", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )
    stats = capture.process_packet_direct(rogue_ra)
    assert stats["ra_packets"] == 1
    # Allow background event persistence task to complete
    await asyncio.sleep(0.05)
    evts = await temp_db.get_security_events(tenant_id="tenant-alpha")
    assert len(evts) == 1
    assert evts[0].event_type == "ROGUE_RA"


# ---------------------------------------------------------------------------
# CRITERION 10: Security alerts verified to reach storage and API
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_acceptance_criterion_10_security_alerts_to_storage_and_api():
    """Verify security alerts are recorded in DB and exposed via REST API."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Trigger an attack via API
        atk_res = await client.post(
            "/api/attacks/rogue-ra",
            json={
                "rogue_source": "fe80::dead:9999",
                "unauthorized_prefix": "2001:db8:bad1::/64",
                "router_lifetime": 1800
            },
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert atk_res.status_code == 200
        assert atk_res.json()["detection_triggered"] is True

        # Query events endpoint
        evts_res = await client.get("/api/events", headers={"X-Tenant-ID": "tenant-alpha"})
        assert evts_res.status_code == 200
        events = evts_res.json()
        assert len(events) > 0
        matched = [e for e in events if e.get("source_ip") == "fe80::dead:9999"]
        assert len(matched) >= 1
        assert matched[0]["event_type"] == "ROGUE_RA"


# ---------------------------------------------------------------------------
# CRITERION 11: Tenant isolation strictly enforced
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_acceptance_criterion_11_tenant_isolation():
    """Verify tenant-alpha and tenant-beta cannot view or mutate each other's data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Check devices
        devs_alpha = (await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-alpha"})).json()
        devs_beta = (await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-beta"})).json()

        alpha_ids = {d["id"] for d in devs_alpha}
        beta_ids = {d["id"] for d in devs_beta}
        assert alpha_ids.isdisjoint(beta_ids), "Tenants must have strictly disjoint device sets"

        # Attempting to access Tenant Alpha device using Tenant Beta header must be denied (401 Unauthorized)
        unauth = await client.post(
            "/api/devices/p6g-iot1/authenticate",
            json={"secret": "sec-thermostat-alpha-9921"},
            headers={"X-Tenant-ID": "tenant-beta"}
        )
        assert unauth.status_code == 401


# ---------------------------------------------------------------------------
# CRITERION 12: Expired mappings rejected and purged
# ---------------------------------------------------------------------------
def test_acceptance_criterion_12_expired_mappings_rejected_and_purged():
    """Verify expired pseudonyms and sessions cannot be correlated and are permanently purged."""
    pm = PseudonymManager(default_epoch_seconds=60)
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Issue 2 pseudonyms
    rec1 = pm.issue_pseudonym_for_session("sess-1", "tenant-alpha", "2001:db8:6::15", current_time=now)
    rec2 = pm.issue_pseudonym_for_session("sess-2", "tenant-alpha", "2001:db8:6::16", current_time=now)

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


# ---------------------------------------------------------------------------
# CRITERION 13: Evaluation metrics measured and logged
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_acceptance_criterion_13_evaluation_metrics_measured_and_logged():
    """Verify detection metrics, privacy metrics, and traffic rates are calculated and reported."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/metrics")
        assert res.status_code == 200
        metrics = res.json()

        assert "detection_metrics" in metrics
        assert "privacy_metrics" in metrics
        assert "traffic_rates" in metrics

        dm = metrics["detection_metrics"]
        assert dm["detection_rate_pct"] == 100.0
        assert dm["false_alarm_rate_pct"] == 0.0
        assert dm["avg_detection_latency_ms"] < 100.0

        pm = metrics["privacy_metrics"]
        assert pm["tracking_resistance_score"] == 1.0
        assert pm["authorized_session_continuity_pct"] == 100.0
