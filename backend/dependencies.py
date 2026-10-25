from typing import Optional
from fastapi import Header, Query, HTTPException, status

from config.app_config import settings
from backend.storage.database import Database
from security.auth_manager import SessionManager
from security.pseudonym_manager import PseudonymManager
from security.correlation_engine import CorrelationEngine
from security.event_manager import SecurityEventManager
from security.ra_detector import RouterAdvertisementDetector, RAPolicyConfig
from security.ndp_detector import NDPAnomalyDetector, NDPThresholds
from network.address_rotator import AddressRotationManager
from network.attack_simulator import ControlledAttackSimulator
from network.packet_capture import PacketCaptureEngine
from network.lab_config import DEFAULT_LAB_CONFIG

# Shared backend service singletons
_db = Database(settings.db_path)
_session_mgr = SessionManager(default_ttl_seconds=300)
_pseudonym_mgr = PseudonymManager(default_epoch_seconds=120)
_correlation_engine = CorrelationEngine(_session_mgr, _pseudonym_mgr)
_address_rotator = AddressRotationManager(_correlation_engine, DEFAULT_LAB_CONFIG)
_event_mgr = SecurityEventManager(_db, _pseudonym_mgr)

_ra_detector = RouterAdvertisementDetector(
    RAPolicyConfig(
        authorized_router_link_locals=["fe80::1"],
        authorized_prefixes=["2001:db8:6::/64", "fd00:cafe:1::/64"],
    )
)
_ndp_detector = NDPAnomalyDetector(
    rolling_window_seconds=5.0,
    thresholds=NDPThresholds(max_ns_per_sec=15.0, max_na_per_sec=15.0),
    cooldown_seconds=10.0,
)
_packet_capture = PacketCaptureEngine(
    interface=DEFAULT_LAB_CONFIG.bridge_name,
    ra_detector=_ra_detector,
    ndp_detector=_ndp_detector,
    event_manager=_event_mgr,
)
_attack_sim = ControlledAttackSimulator(DEFAULT_LAB_CONFIG)

def get_db() -> Database:
    return _db

def get_session_manager() -> SessionManager:
    return _session_mgr

def get_pseudonym_manager() -> PseudonymManager:
    return _pseudonym_mgr

def get_correlation_engine() -> CorrelationEngine:
    return _correlation_engine

def get_address_rotator() -> AddressRotationManager:
    return _address_rotator

def get_event_manager() -> SecurityEventManager:
    return _event_mgr

def get_attack_simulator() -> ControlledAttackSimulator:
    return _attack_sim

def get_ra_detector() -> RouterAdvertisementDetector:
    return _ra_detector

def get_ndp_detector() -> NDPAnomalyDetector:
    return _ndp_detector

def get_packet_capture() -> PacketCaptureEngine:
    return _packet_capture

def get_current_tenant_id(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    tenant_id: Optional[str] = Query(None),
) -> str:
    """
    Extracts and validates tenant identity for multi-tenant isolation.
    Enforced at the backend service layer.
    """
    tenant = x_tenant_id or tenant_id or "tenant-alpha"
    if tenant not in ("tenant-alpha", "tenant-beta"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Tenant '{tenant}' is not recognized or authorized."
        )
    return tenant
