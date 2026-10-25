from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from network.lab_config import LabDeviceConfig, DEFAULT_LAB_CONFIG

@dataclass
class DeviceInventoryItem:
    lab_id: str                   # Administrative name (e.g. p6g-iot1)
    role: str                     # Descriptive role (e.g. Smart Thermostat)
    current_ipv6: str             # Current assigned IPv6 address
    namespace: str                # Linux network namespace
    operational_status: str       # "ACTIVE", "STOPPED", "ROTATING"
    tenant_id: str                # Multi-tenant isolation boundary

    def to_dict(self) -> Dict[str, Any]:
        """
        Export dictionary representation.
        Explicitly does NOT include correlation tokens or permanent tracking identities.
        """
        return {
            "lab_id": self.lab_id,
            "role": self.role,
            "current_ipv6": self.current_ipv6,
            "namespace": self.namespace,
            "operational_status": self.operational_status,
            "tenant_id": self.tenant_id,
        }

class DeviceInventory:
    """
    Manages the operational state of emulated IoT devices in the lab.
    Maintains strict separation between administrative lab management
    and the privacy-preserving pseudonym correlation engine.
    """
    def __init__(self, device_configs: Optional[List[LabDeviceConfig]] = None):
        configs = device_configs or DEFAULT_LAB_CONFIG.devices
        self._inventory: Dict[str, DeviceInventoryItem] = {}
        for cfg in configs:
            self._inventory[cfg.lab_id] = DeviceInventoryItem(
                lab_id=cfg.lab_id,
                role=cfg.role,
                current_ipv6=cfg.ipv6_address,
                namespace=cfg.namespace,
                operational_status="READY",
                tenant_id=cfg.tenant_id,
            )

    def list_devices(self, tenant_id: Optional[str] = None) -> List[DeviceInventoryItem]:
        items = list(self._inventory.values())
        if tenant_id:
            items = [item for item in items if item.tenant_id == tenant_id]
        return items

    def get_device(self, lab_id: str) -> Optional[DeviceInventoryItem]:
        return self._inventory.get(lab_id)

    def update_status(self, lab_id: str, status: str, new_ipv6: Optional[str] = None) -> bool:
        item = self._inventory.get(lab_id)
        if not item:
            return False
        item.operational_status = status
        if new_ipv6:
            item.current_ipv6 = new_ipv6
        return True
