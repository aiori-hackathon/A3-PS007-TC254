import ipaddress
import pytest
from network.lab_config import DEFAULT_LAB_CONFIG, Priv6LabConfig

def test_lab_config_defaults():
    cfg = DEFAULT_LAB_CONFIG
    assert cfg.bridge_name == "p6g-br0"
    assert cfg.ipv6_prefix == "2001:db8:6::/64"
    assert len(cfg.devices) == 5

    # Check documentation prefix validity
    network = ipaddress.IPv6Network(cfg.ipv6_prefix)
    assert network.is_private or str(network).startswith("2001:db8:")

def test_device_address_uniqueness():
    cfg = DEFAULT_LAB_CONFIG
    addrs = [d.ipv6_address for d in cfg.devices]
    addrs.append(cfg.router.ipv6_address)
    addrs.append(cfg.attacker.ipv6_address)
    
    assert len(addrs) == len(set(addrs)), "IPv6 addresses must be unique"

    network = ipaddress.IPv6Network(cfg.ipv6_prefix)
    for addr_str in addrs:
        addr = ipaddress.IPv6Address(addr_str)
        assert addr in network, f"Address {addr_str} not in prefix {network}"

def test_device_mac_and_namespace_uniqueness():
    cfg = DEFAULT_LAB_CONFIG
    namespaces = [d.namespace for d in cfg.devices] + [cfg.router.namespace, cfg.attacker.namespace]
    assert len(namespaces) == len(set(namespaces)), "Namespaces must be unique"

    macs = [d.mac_address for d in cfg.devices] + [cfg.router.mac_address, cfg.attacker.mac_address]
    assert len(macs) == len(set(macs)), "MAC addresses must be unique"

    veths = [d.host_veth for d in cfg.devices] + [cfg.router.host_veth, cfg.attacker.host_veth]
    assert len(veths) == len(set(veths)), "Host veth interface names must be unique"
