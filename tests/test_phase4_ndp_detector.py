import pytest
from datetime import datetime, timezone, timedelta
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from security.ndp_detector import NDPAnomalyDetector, NDPThresholds

def test_ndp_baseline_normal_rate():
    detector = NDPAnomalyDetector(
        rolling_window_seconds=5.0,
        thresholds=NDPThresholds(max_ns_per_sec=15.0),
    )
    start_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Send 5 NS packets over 5 seconds (1 packet/sec)
    for sec in range(5):
        t = start_time + timedelta(seconds=sec)
        pkt = IPv6(src="2001:db8:6::11") / ICMPv6ND_NS(tgt="2001:db8:6::1")
        res = detector.inspect_ndp_packet(pkt, current_time=t)
        assert res.is_anomaly is False

def test_ndp_rate_anomaly_burst_detection():
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
    # Verify architectural requirement: ANOMALY INDICATOR
    assert last_res.classification == "ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF"
    assert last_res.source_ip == "2001:db8:6::bad"

def test_ndp_cooldown_behavior():
    detector = NDPAnomalyDetector(
        rolling_window_seconds=5.0,
        thresholds=NDPThresholds(max_ns_per_sec=10.0),
        cooldown_seconds=10.0,
    )
    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # First burst: triggers anomaly
    triggered = []
    for _ in range(60):
        pkt = IPv6(src="2001:db8:6::bad") / ICMPv6ND_NS(tgt="2001:db8:6::12")
        r = detector.inspect_ndp_packet(pkt, current_time=t0)
        if r.is_anomaly:
            triggered.append(r)

    assert len(triggered) == 1, "Should trigger exactly 1 alert on the first threshold breach"

    # Second burst at t0 + 2 seconds (within 10s cooldown): must NOT trigger duplicate alert
    t_cool = t0 + timedelta(seconds=2)
    cool_triggered = []
    for _ in range(20):
        pkt = IPv6(src="2001:db8:6::bad") / ICMPv6ND_NS(tgt="2001:db8:6::12")
        r = detector.inspect_ndp_packet(pkt, current_time=t_cool)
        if r.is_anomaly:
            cool_triggered.append(r)

    assert len(cool_triggered) == 0, "Cooldown must suppress duplicate alert floods"

def test_ndp_rolling_window_expiration():
    """
    CRITICAL REQUIREMENT: Verify rolling-window state expiration.
    When a burst stops and time moves beyond the window, rate drops back to 0
    and stale state is safely pruned.
    """
    detector = NDPAnomalyDetector(
        rolling_window_seconds=5.0,
        thresholds=NDPThresholds(max_ns_per_sec=10.0),
        cooldown_seconds=5.0,
    )
    t0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Send burst of 60 packets at t0 -> triggers anomaly
    for _ in range(60):
        detector.inspect_ndp_packet(
            {"source_ip": "2001:db8:6::burst", "msg_type": "NS"},
            current_time=t0,
        )

    # Time advances 6 seconds later (past 5s rolling window)
    t1 = t0 + timedelta(seconds=6)

    # Send a single benign packet at t1
    res_after = detector.inspect_ndp_packet(
        {"source_ip": "2001:db8:6::burst", "msg_type": "NS"},
        current_time=t1,
    )
    # 1 packet / 5s = 0.2 pps <= 10.0 threshold
    assert res_after.is_anomaly is False
    assert res_after.current_rate_pps == 0.2

    # Prune idle sources
    t2 = t1 + timedelta(seconds=6)
    pruned = detector.prune_idle_sources(current_time=t2)
    assert pruned >= 1

def test_ndp_malformed_and_missing_fields_safely_handled():
    """Verify malformed packets or missing fields do not crash the detector."""
    detector = NDPAnomalyDetector()

    # Pass non-packet string
    res_str = detector.inspect_ndp_packet("invalid-raw-bytes")
    assert res_str.is_anomaly is False
    assert res_str.rule_id == "RULE-MALFORMED"

    # Pass dict without required keys
    res_empty_dict = detector.inspect_ndp_packet({})
    assert res_empty_dict.is_anomaly is False

    # Pass None
    res_none = detector.inspect_ndp_packet(None)
    assert res_none.is_anomaly is False

def test_ndp_interface_scoped_counters():
    """Verify counters are isolated by interface."""
    detector = NDPAnomalyDetector(
        rolling_window_seconds=5.0,
        thresholds=NDPThresholds(max_ns_per_sec=10.0),
        cooldown_seconds=10.0,
    )
    t = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Send 40 packets on p6g-br0
    for _ in range(40):
        detector.inspect_ndp_packet(
            {"source_ip": "2001:db8:6::iso", "msg_type": "NS"},
            current_time=t,
            interface="p6g-br0",
        )

    # Send 5 packets on lo with the same source IP: must NOT trigger because it is a separate interface
    res_lo = detector.inspect_ndp_packet(
        {"source_ip": "2001:db8:6::iso", "msg_type": "NS"},
        current_time=t,
        interface="lo",
    )
    assert res_lo.is_anomaly is False
    assert res_lo.interface == "lo"

def test_ndp_threshold_tradeoff_guidance():
    """Verify detector provides tradeoff explanation for FP/FN calibration."""
    detector = NDPAnomalyDetector()
    tradeoffs = detector.evaluate_threshold_tradeoffs()
    assert "configured_thresholds" in tradeoffs
    assert "tradeoff_analysis" in tradeoffs
    assert "lower_thresholds" in tradeoffs["tradeoff_analysis"]
    assert "higher_thresholds" in tradeoffs["tradeoff_analysis"]

