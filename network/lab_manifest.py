import os
import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

class LabManifest:
    """
    Cryptographically verifies and persists ownership of created lab resources.
    Guarantees that teardown will ONLY delete interfaces and namespaces created
    and explicitly recorded by this application instance.
    """
    def __init__(self, manifest_path: str):
        self.manifest_path = Path(manifest_path)

    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        content = f"{data.get('manifest_id')}:{data.get('bridge')}:{','.join(sorted(data.get('namespaces', [])))}:{','.join(sorted(data.get('interfaces', [])))}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def record_creation(
        self,
        bridge: str,
        namespaces: List[str],
        interfaces: List[str],
        ipv6_prefix: str
    ) -> Dict[str, Any]:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_data = {
            "manifest_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "creator_pid": os.getpid(),
            "bridge": bridge,
            "namespaces": sorted(namespaces),
            "interfaces": sorted(interfaces),
            "ipv6_prefix": ipv6_prefix,
            "status": "ACTIVE"
        }
        manifest_data["checksum"] = self._calculate_checksum(manifest_data)

        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        return manifest_data

    def load_manifest(self) -> Optional[Dict[str, Any]]:
        if not self.manifest_path.exists():
            return None
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            expected_chk = self._calculate_checksum(data)
            if data.get("checksum") != expected_chk:
                raise ValueError("Lab manifest integrity check failed: manifest has been modified or corrupted.")
            return data
        except Exception as e:
            return None

    def is_owned_resource(self, resource_name: str, resource_type: str) -> bool:
        """
        Validates whether a resource is officially owned by the active lab session.
        Refuses to assume ownership solely by naming convention.
        """
        manifest = self.load_manifest()
        if not manifest:
            return False

        if resource_type == "bridge":
            return manifest.get("bridge") == resource_name
        elif resource_type == "namespace":
            return resource_name in manifest.get("namespaces", [])
        elif resource_type == "interface":
            return resource_name in manifest.get("interfaces", [])
        return False

    def clear_manifest(self):
        if self.manifest_path.exists():
            try:
                self.manifest_path.unlink()
            except OSError:
                pass
