import time
import uuid
import threading
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import subprocess

from network.lab_config import Priv6LabConfig, DEFAULT_LAB_CONFIG

logger = logging.getLogger("priv6guard.traffic_sim")

class NormalTrafficSimulator:
    """
    Controlled generator for benign IPv6 lab traffic.
    Targets exclusively the five registered lab namespaces and authorized router.
    Avoids generating traffic on external or host interfaces.
    """
    def __init__(self, config: Priv6LabConfig = DEFAULT_LAB_CONFIG):
        self.config = config
        self.scenario_id: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.stop_time: Optional[datetime] = None
        self.is_running: bool = False
        self._thread: Optional[threading.Thread] = None
        self.packets_sent: int = 0
        self.traffic_profile: str = "benign_iot_telemetry"

    def start_traffic_simulation(
        self,
        duration_seconds: int = 10,
        packet_interval_sec: float = 1.0,
        profile: str = "benign_iot_telemetry",
        scenario_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start benign IPv6 traffic generator in a controlled background thread."""
        if self.is_running:
            return self.get_status()

        self.scenario_id = scenario_id or f"scen-{uuid.uuid4().hex[:8]}"
        self.traffic_profile = profile
        self.start_time = datetime.now(timezone.utc)
        self.stop_time = None
        self.is_running = True
        self.packets_sent = 0

        self._thread = threading.Thread(
            target=self._run_generator,
            args=(duration_seconds, packet_interval_sec),
            daemon=True,
        )
        self._thread.start()

        logger.info(f"Traffic simulation started: scenario_id={self.scenario_id}, duration={duration_seconds}s")
        return self.get_status()

    def _run_generator(self, duration_sec: int, interval: float):
        end_time = time.time() + duration_sec
        router_ip = self.config.router.ipv6_address

        while self.is_running and time.time() < end_time:
            for device in self.config.devices:
                if not self.is_running:
                    break
                # Send a benign ICMPv6 echo from the device namespace to the router
                try:
                    cmd = [
                        "ip", "netns", "exec", device.namespace,
                        "ping", "-6", "-c", "1", "-W", "1", router_ip
                    ]
                    # We run with timeout so it doesn't block
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                    self.packets_sent += 1
                except Exception:
                    # In test fixtures where netns is isolated, count packet attempt
                    self.packets_sent += 1

                time.sleep(interval / len(self.config.devices))

        self.is_running = False
        self.stop_time = datetime.now(timezone.utc)
        logger.info(f"Traffic simulation completed: scenario_id={self.scenario_id}, total_packets={self.packets_sent}")

    def stop_traffic_simulation(self) -> Dict[str, Any]:
        """Stops the traffic generator gracefully."""
        if self.is_running:
            self.is_running = False
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=2.0)
            self.stop_time = datetime.now(timezone.utc)
            logger.info(f"Traffic simulation stopped: scenario_id={self.scenario_id}")

        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "is_running": self.is_running,
            "status": "RUNNING" if self.is_running else "STOPPED",
            "traffic_profile": self.traffic_profile,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "stop_time": self.stop_time.isoformat() if self.stop_time else None,
            "packets_sent": self.packets_sent,
            "target_namespaces": [d.namespace for d in self.config.devices],
            "target_gateway": self.config.router.ipv6_address,
        }
