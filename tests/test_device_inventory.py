import pytest
from network.device_inventory import DeviceInventory

def test_inventory_initialization():
    inv = DeviceInventory()
    devices = inv.list_devices()
    assert len(devices) == 5

    ids = [d.lab_id for d in devices]
    assert ids == ["p6g-iot1", "p6g-iot2", "p6g-iot3", "p6g-iot4", "p6g-iot5"]

def test_inventory_tenant_filtering():
    inv = DeviceInventory()
    alpha = inv.list_devices(tenant_id="tenant-alpha")
    assert len(alpha) == 3
    for d in alpha:
        assert d.tenant_id == "tenant-alpha"

    beta = inv.list_devices(tenant_id="tenant-beta")
    assert len(beta) == 2
    for d in beta:
        assert d.tenant_id == "tenant-beta"

def test_inventory_privacy_guarantee():
    inv = DeviceInventory()
    d1 = inv.get_device("p6g-iot1")
    assert d1 is not None

    dump = d1.to_dict()
    # Ensure NO tracking identities or correlation keys are present
    assert "tracking_id" not in dump
    assert "permanent_id" not in dump
    assert "correlation_key" not in dump
    assert "token" not in dump

def test_inventory_status_update():
    inv = DeviceInventory()
    updated = inv.update_status("p6g-iot1", "ACTIVE", new_ipv6="2001:db8:6::99")
    assert updated is True

    d1 = inv.get_device("p6g-iot1")
    assert d1.operational_status == "ACTIVE"
    assert d1.current_ipv6 == "2001:db8:6::99"
