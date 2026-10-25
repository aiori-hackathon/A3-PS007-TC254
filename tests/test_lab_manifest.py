import json
import pytest
from pathlib import Path
from network.lab_manifest import LabManifest

def test_manifest_creation_and_ownership(tmp_path: Path):
    manifest_file = tmp_path / "test_manifest.json"
    manifest = LabManifest(str(manifest_file))

    rec = manifest.record_creation(
        bridge="p6g-br0",
        namespaces=["p6g-iot1", "p6g-iot2"],
        interfaces=["p6g-veth1", "p6g-veth2", "p6g-br0"],
        ipv6_prefix="2001:db8:6::/64",
    )

    assert rec["bridge"] == "p6g-br0"
    assert "checksum" in rec

    # Verify ownership check
    assert manifest.is_owned_resource("p6g-br0", "bridge") is True
    assert manifest.is_owned_resource("p6g-iot1", "namespace") is True
    assert manifest.is_owned_resource("p6g-veth1", "interface") is True

    # Critical: Do NOT assume ownership just because prefix matches!
    assert manifest.is_owned_resource("p6g-foreign-ns", "namespace") is False
    assert manifest.is_owned_resource("p6g-foreign-veth", "interface") is False
    assert manifest.is_owned_resource("eth0", "interface") is False

def test_manifest_tampering_detection(tmp_path: Path):
    manifest_file = tmp_path / "test_manifest.json"
    manifest = LabManifest(str(manifest_file))

    manifest.record_creation(
        bridge="p6g-br0",
        namespaces=["p6g-iot1"],
        interfaces=["p6g-veth1"],
        ipv6_prefix="2001:db8:6::/64",
    )

    # Tamper with file
    with open(manifest_file, "r") as f:
        data = json.load(f)
    data["namespaces"].append("evil-ns")
    with open(manifest_file, "w") as f:
        json.dump(data, f)

    # Corrupted manifest must be rejected
    loaded = manifest.load_manifest()
    assert loaded is None
