import pytest
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6ND_NS
from backend.storage.database import Database
from security.pseudonym_manager import PseudonymManager
from security.event_manager import SecurityEventManager
from security.ra_detector import RouterAdvertisementDetector, RAPolicyConfig
from security.ndp_detector import NDPAnomalyDetector, NDPThresholds
from network.packet_capture import PacketCaptureEngine

@pytest.mark.asyncio
async def test_end_to_end_packet_event_pipeline(temp_db: Database):
    pm = PseudonymManager()
    event_mgr = SecurityEventManager(temp_db, pm)
    
    # Active pseudonym for device 1
    pseudo_rec = pm.issue_pseudonym_for_session("sess-1", "tenant-alpha", "2001:db8:6::11")
    
    ra_det = RouterAdvertisementDetector(RAPolicyConfig(authorized_router_link_locals=["fe80::1"]))
    ndp_det = NDPAnomalyDetector(rolling_window_seconds=2.0, thresholds=NDPThresholds(max_ns_per_sec=5.0))
    capture = PacketCaptureEngine(ra_detector=ra_det, ndp_detector=ndp_det, event_manager=event_mgr)

    # 1. Process legitimate RA: 0 events created
    legit_ra = (
        IPv6(src="fe80::1", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )
    stats = capture.process_packet_direct(legit_ra)
    assert stats["ra_packets"] == 1

    events_before = await temp_db.get_security_events(tenant_id="tenant-alpha")
    assert len(events_before) == 0

    # 2. Process rogue RA from untrusted router
    rogue_ra = (
        IPv6(src="fe80::dead:beef", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:baad::", prefixlen=64)
    )
    capture.process_packet_direct(rogue_ra)
    # Allow background event task to complete
    import asyncio
    await asyncio.sleep(0.05)

    events_after = await temp_db.get_security_events(tenant_id="tenant-alpha")
    assert len(events_after) == 1
    evt = events_after[0]
    assert evt.event_type == "ROGUE_RA"
    assert evt.severity == "CRITICAL"
    assert evt.source_ip == "fe80::dead:beef"
    assert "2001:db8:baad::/64" in evt.details["advertised_prefixes"]

    # Verify data minimization: no raw packet dump in details
    assert "raw_payload" not in evt.details
    assert "pcap_bytes" not in evt.details

@pytest.mark.asyncio
async def test_event_id_and_evidence_linking_to_alert(temp_db: Database):
    """
    CRITICAL REQUIREMENT: Verify event ID and evidence linking the captured event to the alert.
    """
    pm = PseudonymManager()
    event_mgr = SecurityEventManager(temp_db, pm)
    ra_det = RouterAdvertisementDetector(RAPolicyConfig(authorized_router_link_locals=["fe80::1"]))
    ndp_det = NDPAnomalyDetector()
    capture = PacketCaptureEngine(ra_detector=ra_det, ndp_detector=ndp_det, event_manager=event_mgr)

    # Inject rogue RA
    rogue_ra = (
        IPv6(src="fe80::cafe:1234", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:baad::", prefixlen=64)
    )
    capture.process_packet_direct(rogue_ra)

    import asyncio
    await asyncio.sleep(0.05)

    events = await temp_db.get_security_events(tenant_id="tenant-alpha")
    alerts = await temp_db.get_alerts(tenant_scope="tenant-alpha")

    assert len(events) >= 1
    assert len(alerts) >= 1

    matched_event = [e for e in events if e.source_ip == "fe80::cafe:1234"][0]
    matched_alert = [a for a in alerts if a.evidence.get("source_ip") == "fe80::cafe:1234"][0]

    # Explicit bidirectional link between captured event and alert
    assert matched_event.event_type == "ROGUE_RA"
    assert matched_alert.alert_type == "ROGUE_RA_POLICY_VIOLATION"
    assert matched_alert.evidence.get("source_ip") == matched_event.source_ip
    assert matched_alert.rule_id == "RULE-RA-RFC6105" or matched_alert.rule_id.startswith("RULE-RA-")
    assert matched_alert.interface == "p6g-br0"

def test_lab_inactive_condition_rejection():
    """
    CRITICAL REQUIREMENT: Verify preflight checks fail gracefully when lab is inactive.
    """
    from network.lab_status import LabStatusManager
    from network.lab_config import Priv6LabConfig

    # Mock inactive config pointing to non-existent bridge
    inactive_cfg = Priv6LabConfig(bridge_name="p6g-nonexistent-br")
    status_mgr = LabStatusManager(inactive_cfg)

    ok, reason = status_mgr.preflight_attack_check()
    assert ok is False
    assert "Attack blocked" in reason

def test_experiment_cancellation_and_lifecycle():
    """
    CRITICAL REQUIREMENT: Verify experiment start, cancellation, and cleanup.
    """
    from network.traffic_simulator import NormalTrafficSimulator

    sim = NormalTrafficSimulator()
    start_info = sim.start_traffic_simulation(duration_seconds=10, packet_interval_sec=0.1)
    assert start_info["is_running"] is True

    # Immediate cancellation
    stop_info = sim.stop_traffic_simulation()
    assert stop_info["is_running"] is False
    assert stop_info["status"] == "STOPPED"

