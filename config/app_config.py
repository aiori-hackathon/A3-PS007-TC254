import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"

class RouterConfig(BaseModel):
    name: str = "Authorized-Gateway"
    namespace: str = "priv6-ns-router"
    interface: str = "priv6-peer-rtr"
    veth: str = "priv6-veth-rtr"
    link_local: str = "fe80::1"
    global_ip: str = "fd00:cafe:1::1"

class DeviceConfig(BaseModel):
    id: str
    name: str
    type: str
    namespace: str
    interface: str
    veth: str
    tenant_id: str
    base_mac: str
    initial_ip: str
    traffic_profile: str = "telemetry_burst"
    packet_interval_sec: float = 2.0

class AttackerConfig(BaseModel):
    namespace: str = "priv6-ns-attacker"
    interface: str = "priv6-peer-atk"
    veth: str = "priv6-veth-atk"
    base_mac: str = "02:00:00:00:00:ee"
    ip: str = "fd00:cafe:1::bad"

class LabConfig(BaseModel):
    name: str = "priv6guard-lab"
    bridge_name: str = "priv6-br0"
    ipv6_prefix: str = "fd00:cafe:1::/64"
    slaac_prefix_length: int = 64
    router: RouterConfig
    devices: List[DeviceConfig]
    attacker: AttackerConfig
    rotation_interval_sec: int = 60

class AuthorizedRouter(BaseModel):
    name: str
    link_local: str
    allowed_prefixes: List[str]
    min_router_lifetime_sec: int = 60
    max_router_lifetime_sec: int = 1800
    expected_managed_flag: bool = False
    expected_other_flag: bool = False

class RAPolicy(BaseModel):
    description: str
    authorized_routers: List[AuthorizedRouter]
    severity: str = "CRITICAL"

class NDPThresholds(BaseModel):
    max_neighbor_solicitations_per_sec: float = 15.0
    max_neighbor_advertisements_per_sec: float = 15.0
    max_router_solicitations_per_sec: float = 5.0
    max_total_ndp_per_sec: float = 25.0

class NDPPolicy(BaseModel):
    description: str
    rolling_window_seconds: float = 5.0
    thresholds: NDPThresholds
    cooldown_seconds: float = 10.0
    anomaly_severity: str = "HIGH"

class PrivacyPolicy(BaseModel):
    description: str
    session_token_ttl_seconds: int = 300
    pseudonym_epoch_seconds: int = 120
    purge_interval_seconds: int = 30
    hmac_algorithm: str = "SHA256"

class DetectionRules(BaseModel):
    ra_policy: RAPolicy
    ndp_anomaly_policy: NDPPolicy
    privacy_policy: PrivacyPolicy

class AppSettings(BaseSettings):
    app_name: str = "PRIV6GUARD"
    version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    db_path: str = str(BASE_DIR / "data" / "priv6guard.db")
    secret_key: str = "priv6guard-hackathon-insecure-default-change-me"
    lab_config_path: str = str(CONFIG_DIR / "lab_config.yaml")
    detection_rules_path: str = str(CONFIG_DIR / "detection_rules.yaml")

    def load_lab_config(self) -> LabConfig:
        with open(self.lab_config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return LabConfig(
            name=raw["lab"]["name"],
            bridge_name=raw["lab"]["bridge_name"],
            ipv6_prefix=raw["lab"]["ipv6_prefix"],
            slaac_prefix_length=raw["lab"].get("slaac_prefix_length", 64),
            router=RouterConfig(**raw["router"]),
            devices=[DeviceConfig(**d) for d in raw["devices"]],
            attacker=AttackerConfig(**raw["attacker"]),
            rotation_interval_sec=raw.get("rotation", {}).get("rotation_interval_sec", 60),
        )

    def load_detection_rules(self) -> DetectionRules:
        with open(self.detection_rules_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return DetectionRules(
            ra_policy=RAPolicy(**raw["ra_policy"]),
            ndp_anomaly_policy=NDPPolicy(**raw["ndp_anomaly_policy"]),
            privacy_policy=PrivacyPolicy(**raw["privacy_policy"]),
        )

settings = AppSettings()
