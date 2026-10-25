from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

@dataclass(frozen=True)
class LabDeviceConfig:
    lab_id: str                   # Administrative identifier only (never used for event correlation)
    role: str                     # Descriptive role
    namespace: str                # e.g. p6g-iot1
    host_veth: str                # e.g. p6g-veth1 (connected to bridge)
    ns_peer: str                  # e.g. p6g-peer1 (inside namespace)
    ipv6_address: str             # e.g. 2001:db8:6::11
    tenant_id: str                # e.g. tenant-alpha
    mac_address: str              # Local administration MAC

@dataclass(frozen=True)
class LabRouterConfig:
    lab_id: str = "p6g-router"
    role: str = "Authorized Gateway"
    namespace: str = "p6g-router"
    host_veth: str = "p6g-veth0"
    ns_peer: str = "p6g-peer0"
    ipv6_address: str = "2001:db8:6::1"
    link_local: str = "fe80::1"
    mac_address: str = "02:00:00:00:00:00"

@dataclass(frozen=True)
class LabAttackerConfig:
    lab_id: str = "p6g-attacker"
    role: str = "Controlled Attack Simulator"
    namespace: str = "p6g-attacker"
    host_veth: str = "p6g-veth-atk"
    ns_peer: str = "p6g-peer-atk"
    ipv6_address: str = "2001:db8:6::bad"
    mac_address: str = "02:00:00:00:00:ee"

@dataclass
class Priv6LabConfig:
    project_prefix: str = "p6g"
    bridge_name: str = "p6g-br0"
    ipv6_prefix: str = "2001:db8:6::/64"
    prefix_length: int = 64
    manifest_path: str = str(BASE_DIR / "data" / "lab_manifest.json")
    router: LabRouterConfig = field(default_factory=LabRouterConfig)
    attacker: LabAttackerConfig = field(default_factory=LabAttackerConfig)
    devices: List[LabDeviceConfig] = field(default_factory=lambda: [
        LabDeviceConfig(
            lab_id="p6g-iot1",
            role="Smart Thermostat",
            namespace="p6g-iot1",
            host_veth="p6g-veth1",
            ns_peer="p6g-peer1",
            ipv6_address="2001:db8:6::11",
            tenant_id="tenant-alpha",
            mac_address="02:00:00:00:00:11",
        ),
        LabDeviceConfig(
            lab_id="p6g-iot2",
            role="Medical Heart Monitor",
            namespace="p6g-iot2",
            host_veth="p6g-veth2",
            ns_peer="p6g-peer2",
            ipv6_address="2001:db8:6::12",
            tenant_id="tenant-alpha",
            mac_address="02:00:00:00:00:12",
        ),
        LabDeviceConfig(
            lab_id="p6g-iot3",
            role="Industrial Flowmeter",
            namespace="p6g-iot3",
            host_veth="p6g-veth3",
            ns_peer="p6g-peer3",
            ipv6_address="2001:db8:6::13",
            tenant_id="tenant-alpha",
            mac_address="02:00:00:00:00:13",
        ),
        LabDeviceConfig(
            lab_id="p6g-iot4",
            role="CCTV Security Streamer",
            namespace="p6g-iot4",
            host_veth="p6g-veth4",
            ns_peer="p6g-peer4",
            ipv6_address="2001:db8:6::14",
            tenant_id="tenant-beta",
            mac_address="02:00:00:00:00:14",
        ),
        LabDeviceConfig(
            lab_id="p6g-iot5",
            role="Environmental Air Sensor",
            namespace="p6g-iot5",
            host_veth="p6g-veth5",
            ns_peer="p6g-peer5",
            ipv6_address="2001:db8:6::15",
            tenant_id="tenant-beta",
            mac_address="02:00:00:00:00:15",
        ),
    ])

DEFAULT_LAB_CONFIG = Priv6LabConfig()
