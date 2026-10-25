import pytest
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo
from security.ra_detector import RouterAdvertisementDetector, RAPolicyConfig

def test_legitimate_router_advertisement():
    detector = RouterAdvertisementDetector(
        RAPolicyConfig(
            authorized_router_link_locals=["fe80::1"],
            authorized_prefixes=["2001:db8:6::/64"],
            min_router_lifetime_sec=60,
            max_router_lifetime_sec=1800,
        )
    )

    # Craft legitimate Scapy RA packet
    pkt = (
        IPv6(src="fe80::1", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )

    res = detector.inspect_ra_packet(pkt)
    assert res.is_rogue is False
    assert res.source_ip == "fe80::1"
    assert "2001:db8:6::/64" in res.advertised_prefixes

def test_rogue_ra_unauthorized_router_address():
    detector = RouterAdvertisementDetector(
        RAPolicyConfig(authorized_router_link_locals=["fe80::1"])
    )

    # Rogue RA from untrusted link-local router
    pkt = (
        IPv6(src="fe80::dead:beef:1", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )

    res = detector.inspect_ra_packet(pkt)
    assert res.is_rogue is True
    assert res.violation_type == "UNAUTHORIZED_ROUTER_ADDRESS"
    assert res.severity == "CRITICAL"
    assert res.source_ip == "fe80::dead:beef:1"

def test_rogue_ra_unauthorized_prefix():
    detector = RouterAdvertisementDetector(
        RAPolicyConfig(
            authorized_router_link_locals=["fe80::1"],
            authorized_prefixes=["2001:db8:6::/64"]
        )
    )

    # RA from whitelisted router but announcing unauthorized foreign prefix
    pkt = (
        IPv6(src="fe80::1", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:baad::", prefixlen=64)
    )

    res = detector.inspect_ra_packet(pkt)
    assert res.is_rogue is True
    assert res.violation_type == "UNAUTHORIZED_PREFIX_ANNOUNCEMENT"
    assert "2001:db8:baad::/64" in res.advertised_prefixes

def test_rogue_ra_abnormal_lifetime():
    detector = RouterAdvertisementDetector(
        RAPolicyConfig(
            authorized_router_link_locals=["fe80::1"],
            authorized_prefixes=["2001:db8:6::/64"],
            max_router_lifetime_sec=1800,
        )
    )

    # RA with abnormal 99999s lifetime
    pkt = (
        IPv6(src="fe80::1", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=99999) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )

    res = detector.inspect_ra_packet(pkt)
    assert res.is_rogue is True
    assert res.violation_type == "ABNORMAL_ROUTER_LIFETIME"

def test_frequency_invariance_for_legitimate_router():
    """
    Critical requirement: Do NOT classify a router as rogue merely because
    it sends frequent advertisements.
    """
    detector = RouterAdvertisementDetector(
        RAPolicyConfig(
            authorized_router_link_locals=["fe80::1"],
            authorized_prefixes=["2001:db8:6::/64"]
        )
    )

    pkt = (
        IPv6(src="fe80::1", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )

    # Send 100 rapid RAs from legitimate gateway
    for i in range(100):
        res = detector.inspect_ra_packet(pkt)
        assert res.is_rogue is False, f"Iteration {i} erroneously flagged legitimate RA as rogue"

    assert detector.ra_count_by_source["fe80::1"] == 100

def test_non_ra_icmpv6_messages_not_labeled_as_rogue():
    """
    CRITICAL REQUIREMENT: Ensure the detector does not label non-RA messages as rogue RAs.
    """
    detector = RouterAdvertisementDetector()
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6ND_NS, ICMPv6ND_NA

    # 1. Echo Request
    echo_pkt = IPv6(src="fe80::dead:beef", dst="ff02::1") / ICMPv6EchoRequest()
    res_echo = detector.inspect_ra_packet(echo_pkt)
    assert res_echo.is_rogue is False
    assert res_echo.rule_id == "RULE-NON-RA"

    # 2. Neighbor Solicitation
    ns_pkt = IPv6(src="fe80::dead:beef", dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="2001:db8:6::1")
    res_ns = detector.inspect_ra_packet(ns_pkt)
    assert res_ns.is_rogue is False
    assert res_ns.rule_id == "RULE-NON-RA"

def test_malformed_packets_handled_safely():
    """Verify malformed or incomplete packet fixtures handled without crashing."""
    detector = RouterAdvertisementDetector()

    # Pass strings, arbitrary objects, truncated dicts
    res_str = detector.inspect_ra_packet("malformed-packet-bytes")
    assert res_str.is_rogue is False

    res_dict = detector.inspect_ra_packet({"icmp6_type": 999})
    assert res_dict.is_rogue is False

    res_none = detector.inspect_ra_packet(None)
    assert res_none.is_rogue is False

def test_ra_detector_structured_alert_and_rule_id():
    """Verify structured rule ID, reason, interface, and minimal evidence."""
    detector = RouterAdvertisementDetector(
        RAPolicyConfig(authorized_router_link_locals=["fe80::1"], authorized_prefixes=["2001:db8:6::/64"])
    )

    rogue_pkt = (
        IPv6(src="fe80::bad1:cafe", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    )

    res = detector.inspect_ra_packet(rogue_pkt, interface="p6g-br0")
    assert res.is_rogue is True
    assert res.rule_id == "RULE-RA-UNAUTHORIZED-SOURCE"
    assert res.interface == "p6g-br0"
    assert "default-deny policy" in res.reason
    assert res.source_ip == "fe80::bad1:cafe"
    assert "authorized_routers" in res.details

