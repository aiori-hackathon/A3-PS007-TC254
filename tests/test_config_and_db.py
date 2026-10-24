import pytest
from datetime import datetime, timezone, timedelta
from config.app_config import LabConfig, DetectionRules
from backend.storage.database import Database
from backend.models.schema import SecurityEventCreate

def test_lab_config_validation(lab_config: LabConfig):
    assert lab_config.name == "priv6guard-lab"
    assert lab_config.bridge_name == "priv6-br0"
    assert lab_config.ipv6_prefix == "fd00:cafe:1::/64"
    assert len(lab_config.devices) == 5
    
    device_ids = [d.id for d in lab_config.devices]
    assert device_ids == ["dev-01", "dev-02", "dev-03", "dev-04", "dev-05"]
    assert lab_config.router.link_local == "fe80::1"
    assert lab_config.attacker.namespace == "priv6-ns-attacker"

def test_detection_rules_validation(detection_rules: DetectionRules):
    ra = detection_rules.ra_policy
    assert len(ra.authorized_routers) == 1
    assert ra.authorized_routers[0].link_local == "fe80::1"
    assert "fd00:cafe:1::/64" in ra.authorized_routers[0].allowed_prefixes
    
    ndp = detection_rules.ndp_anomaly_policy
    assert ndp.rolling_window_seconds == 5.0
    assert ndp.thresholds.max_neighbor_solicitations_per_sec == 15.0

@pytest.mark.asyncio
async def test_database_device_crud(temp_db: Database, lab_config: LabConfig):
    # Upsert devices
    for d in lab_config.devices:
        await temp_db.upsert_device({
            "id": d.id,
            "name": d.name,
            "device_type": d.type,
            "namespace": d.namespace,
            "tenant_id": d.tenant_id,
            "base_mac": d.base_mac,
            "current_ipv6": d.initial_ip,
            "current_pseudonym": f"pseudo-{d.id}",
            "rotation_count": 0,
            "last_rotation": datetime.now(timezone.utc).isoformat(),
            "session_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "is_active": True,
        })

    # Retrieve all devices
    all_devs = await temp_db.get_devices()
    assert len(all_devs) == 5

    # Retrieve with tenant isolation
    alpha_devs = await temp_db.get_devices(tenant_id="tenant-alpha")
    assert len(alpha_devs) == 3
    beta_devs = await temp_db.get_devices(tenant_id="tenant-beta")
    assert len(beta_devs) == 2

    # Verify single device lookup
    d1 = await temp_db.get_device("dev-01")
    assert d1 is not None
    assert d1.name == "Smart Thermostat"
    assert d1.tenant_id == "tenant-alpha"

@pytest.mark.asyncio
async def test_pseudonym_lifecycle_storage(temp_db: Database):
    now = datetime.now(timezone.utc)
    active_exp = (now + timedelta(seconds=120)).isoformat()
    past_exp = (now - timedelta(seconds=10)).isoformat()

    # Active pseudonym
    await temp_db.add_pseudonym_mapping(
        device_id="dev-01",
        pseudonym="pseudo-active-123",
        ipv6_address="fd00:cafe:1::101",
        tenant_id="tenant-alpha",
        session_id="sess-xyz",
        expires_at=active_exp,
    )

    # Stale pseudonym
    await temp_db.add_pseudonym_mapping(
        device_id="dev-02",
        pseudonym="pseudo-stale-999",
        ipv6_address="fd00:cafe:1::102",
        tenant_id="tenant-alpha",
        session_id="sess-old",
        expires_at=past_exp,
    )

    # Query active
    active_rec = await temp_db.get_active_pseudonym_mapping("pseudo-active-123")
    assert active_rec is not None
    assert active_rec["device_id"] == "dev-01"

    # Query stale should return None (already past expiration)
    stale_rec = await temp_db.get_active_pseudonym_mapping("pseudo-stale-999")
    assert stale_rec is None

    # Run purge
    purged = await temp_db.purge_expired_pseudonyms()
    assert purged == 1

@pytest.mark.asyncio
async def test_security_events_and_metrics(temp_db: Database):
    event = SecurityEventCreate(
        event_id="evt-test-01",
        tenant_id="tenant-alpha",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="ROGUE_RA",
        severity="CRITICAL",
        source_ip="fe80::dead:beef",
        target_ip=None,
        affected_pseudonym="pseudo-active-123",
        details={"unauthorized_prefix": "2001:db8:evil::/64"},
        verified=True,
    )
    await temp_db.record_security_event(event)

    # Tenant-filtered retrieval
    alpha_events = await temp_db.get_security_events(tenant_id="tenant-alpha")
    assert len(alpha_events) == 1
    assert alpha_events[0].event_type == "ROGUE_RA"

    beta_events = await temp_db.get_security_events(tenant_id="tenant-beta")
    assert len(beta_events) == 0

    # Metrics evaluation
    metrics = await temp_db.get_metrics()
    assert metrics.detection_metrics.true_positives >= 1
    assert metrics.detection_metrics.false_positives == 0
    assert metrics.detection_metrics.detection_rate_pct == 100.0
