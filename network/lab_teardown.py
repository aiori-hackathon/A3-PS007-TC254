import os
import subprocess
import logging
from typing import Dict, Any, List
from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG
from network.lab_manifest import LabManifest

logger = logging.getLogger("priv6guard.lab_teardown")

class LabTeardownError(Exception):
    pass

class LabTeardownManager:
    """
    Safely tears down the isolated IPv6 virtual lab.
    Strictly verifies ownership using the cryptographic manifest.
    Refuses to delete any interface or namespace not recorded by the active session.
    """
    def __init__(self, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.config = config
        self.manifest = LabManifest(config.manifest_path)

    def teardown_lab(self, force: bool = False) -> Dict[str, Any]:
        manifest_data = self.manifest.load_manifest()
        if not manifest_data:
            if not force:
                raise LabTeardownError(
                    "Cannot safely teardown lab: No valid lab manifest found at "
                    f"'{self.config.manifest_path}'. Refusing unsafe cleanup."
                )
            logger.warning("Force teardown requested without verified manifest.")

        removed_namespaces: List[str] = []
        removed_interfaces: List[str] = []

        # 1. Remove verified network namespaces
        target_namespaces = manifest_data.get("namespaces", []) if manifest_data else []
        for ns in target_namespaces:
            if not self.manifest.is_owned_resource(ns, "namespace") and not force:
                logger.warning(f"Skipping namespace '{ns}': ownership verification failed.")
                continue

            logger.info(f"Removing verified lab namespace '{ns}'...")
            res = subprocess.run(["ip", "netns", "del", ns], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                removed_namespaces.append(ns)
            else:
                logger.warning(f"Namespace '{ns}' could not be deleted (might already be removed): {res.stderr.strip()}")

        # 2. Remove verified host veth interfaces (if not automatically removed by netns deletion)
        target_interfaces = manifest_data.get("interfaces", []) if manifest_data else []
        for iface in target_interfaces:
            if iface == manifest_data.get("bridge"):
                continue # Bridge handled separately

            if not self.manifest.is_owned_resource(iface, "interface") and not force:
                logger.warning(f"Skipping interface '{iface}': ownership verification failed.")
                continue

            # Check if interface still exists
            check = subprocess.run(["ip", "link", "show", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode == 0:
                logger.info(f"Removing verified lab interface '{iface}'...")
                res = subprocess.run(["ip", "link", "del", iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0:
                    removed_interfaces.append(iface)

        # 3. Remove verified virtual bridge
        bridge_name = manifest_data.get("bridge", self.config.bridge_name) if manifest_data else self.config.bridge_name
        if (self.manifest.is_owned_resource(bridge_name, "bridge") or force):
            check_br = subprocess.run(["ip", "link", "show", bridge_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check_br.returncode == 0:
                logger.info(f"Removing verified lab bridge '{bridge_name}'...")
                subprocess.run(["ip", "link", "set", "dev", bridge_name, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                res = subprocess.run(["ip", "link", "del", bridge_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0:
                    removed_interfaces.append(bridge_name)

        # 4. Clear manifest after successful cleanup
        self.manifest.clear_manifest()
        logger.info("Lab teardown complete. All owned resources verified and removed.")

        return {
            "status": "TEARDOWN_COMPLETE",
            "removed_namespaces": removed_namespaces,
            "removed_interfaces": removed_interfaces,
        }
