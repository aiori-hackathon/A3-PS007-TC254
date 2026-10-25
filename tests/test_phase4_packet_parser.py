import pytest
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6NDOptPrefixInfo

from network.packet_capture import IPv6PacketParser, PacketCaptureEngine, ALLOWED_INTERFACES
from security.ra_detector import RouterAdvertisementDetector
from security.ndp_detector import NDPAnomalyDetector

def test_parser_valid_packets():
    parser = IPv6PacketParser(allowed_interfaces={"p6g-br0", "lo"})

    # 1. Valid RA
    ra_pkt = IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RA(routerlifetime=1800) / ICMPv6NDOptPrefixInfo(prefix="2001:db8:6::", prefixlen=64)
    event_ra = parser.parse_packet(ra_pkt, interface="p6g-br0")
    assert event_ra is not None
    assert event_ra.icmp6_type == 134
    assert event_ra.icmp6_name == "ROUTER_ADVERTISEMENT"
    assert event_ra.source_ip == "fe80::1"
    assert "2001:db8:6::/64" in event_ra.evidence["advertised_prefixes"]

    # 2. Valid NS
    ns_pkt = IPv6(src="2001:db8:6::11", dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="2001:db8:6::1")
    event_ns = parser.parse_packet(ns_pkt, interface="p6g-br0")
    assert event_ns is not None
    assert event_ns.icmp6_type == 135
    assert event_ns.icmp6_name == "NEIGHBOR_SOLICITATION"
    assert event_ns.evidence["target_address"] == "2001:db8:6::1"

    # 3. Valid NA
    na_pkt = IPv6(src="2001:db8:6::1", dst="2001:db8:6::11") / ICMPv6ND_NA(tgt="2001:db8:6::1", R=1, S=1)
    event_na = parser.parse_packet(na_pkt, interface="p6g-br0")
    assert event_na is not None
    assert event_na.icmp6_type == 136
    assert event_na.icmp6_name == "NEIGHBOR_ADVERTISEMENT"
    assert event_na.evidence["router_flag"] is True

def test_parser_interface_allowlisting():
    parser = IPv6PacketParser(allowed_interfaces={"p6g-br0", "lo"})
    ra_pkt = IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RA(routerlifetime=1800)

    # Allowed interface
    ev_ok = parser.parse_packet(ra_pkt, interface="p6g-br0")
    assert ev_ok is not None

    # Forbidden host interface
    ev_bad = parser.parse_packet(ra_pkt, interface="eth0")
    assert ev_bad is None

def test_parser_malformed_packets_graceful_handling():
    parser = IPv6PacketParser()

    # Pass non-packet garbage or raw bytes
    ev_none = parser.parse_packet("not-a-packet-string", interface="p6g-br0")
    assert ev_none is None

    # Check non-ICMP packet
    from scapy.layers.inet6 import ICMPv6EchoRequest
    echo_pkt = IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest()
    ev_echo = parser.parse_packet(echo_pkt, interface="p6g-br0")
    assert ev_echo is None

def test_capture_engine_authorization_and_duplicate_prevention():
    engine = PacketCaptureEngine(interface="lo")

    # Unauthorized start attempt must fail
    assert engine.start_capture(authorized=False) is False
    assert engine.is_capturing is False

    # Start authorized capture on lo
    ok = engine.start_capture(authorized=True)
    assert ok is True
    assert engine.is_capturing is True

    # Duplicate start must not spawn a new worker
    ok_dup = engine.start_capture(authorized=True)
    assert ok_dup is True
    assert engine.is_capturing is True

    # Stop cleanly
    stats = engine.stop_capture()
    assert engine.is_capturing is False
    assert stats["is_capturing"] is False
