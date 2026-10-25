import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from security.auth_manager import DEVICE_CREDENTIALS_STORE

@pytest.mark.asyncio
async def test_api_lab_status():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/lab/status")
        assert res.status_code == 200
        data = res.json()
        assert "bridge_name" in data
        assert "is_active" in data
        assert "devices" in data

@pytest.mark.asyncio
async def test_api_devices_tenant_isolation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Tenant Alpha query
        res_a = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-alpha"})
        assert res_a.status_code == 200
        devs_a = res_a.json()
        assert len(devs_a) == 3
        for d in devs_a:
            assert d["tenant_id"] == "tenant-alpha"

        # Tenant Beta query
        res_b = await client.get("/api/devices", headers={"X-Tenant-ID": "tenant-beta"})
        assert res_b.status_code == 200
        devs_b = res_b.json()
        assert len(devs_b) == 2
        for d in devs_b:
            assert d["tenant_id"] == "tenant-beta"

@pytest.mark.asyncio
async def test_api_device_authenticate_and_rotate():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        cred = DEVICE_CREDENTIALS_STORE["p6g-iot1"]
        # Authenticate
        auth_res = await client.post(
            "/api/devices/p6g-iot1/authenticate",
            json={"secret": cred["secret"]},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert auth_res.status_code == 200
        auth_data = auth_res.json()
        token = auth_data["session_token"]
        assert token is not None

        # Rotate address with token
        rot_res = await client.post(
            "/api/devices/p6g-iot1/rotate",
            json={"session_token": token},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert rot_res.status_code == 200
        rot_data = rot_res.json()
        assert rot_data["device_id"] == "p6g-iot1"
        assert rot_data["old_ipv6"] != rot_data["new_ipv6"]
        assert rot_data["new_pseudonym"].startswith("p6g-ps-")
        assert rot_data["rotation_count"] >= 1

@pytest.mark.asyncio
async def test_api_device_rotate_unauthorized():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Attempt rotation with fabricated token
        res = await client.post(
            "/api/devices/p6g-iot1/rotate",
            json={"session_token": "fabricated-fake-token"},
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert res.status_code == 403

@pytest.mark.asyncio
async def test_api_attacks_and_events():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Trigger Rogue RA attack
        atk_ra = await client.post(
            "/api/attacks/rogue-ra",
            json={
                "rogue_source": "fe80::dead:beef",
                "unauthorized_prefix": "2001:db8:baad::/64",
                "router_lifetime": 1800,
            },
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert atk_ra.status_code == 200
        assert atk_ra.json()["detection_triggered"] is True

        # 2. Trigger NDP flood attack
        atk_ndp = await client.post(
            "/api/attacks/ndp-flood",
            json={
                "target_ip": "2001:db8:6::11",
                "packet_count": 90,
                "packet_rate_pps": 50,
            },
            headers={"X-Tenant-ID": "tenant-alpha"},
        )
        assert atk_ndp.status_code == 200
        assert atk_ndp.json()["anomaly_triggered"] is True

        # 3. Verify security events endpoint with tenant isolation
        evts_a = await client.get("/api/events", headers={"X-Tenant-ID": "tenant-alpha"})
        assert evts_a.status_code == 200
        events = evts_a.json()
        assert len(events) >= 2
        event_types = [e["event_type"] for e in events]
        assert "ROGUE_RA" in event_types
        assert "NDP_RATE_ANOMALY" in event_types

        # Verify Tenant Beta cannot see Tenant Alpha's events
        evts_b = await client.get("/api/events", headers={"X-Tenant-ID": "tenant-beta"})
        assert evts_b.status_code == 200
        assert len(evts_b.json()) == 0

@pytest.mark.asyncio
async def test_api_metrics_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/metrics")
        assert res.status_code == 200
        data = res.json()
        assert "detection_metrics" in data
        assert "privacy_metrics" in data
        assert "traffic_rates" in data
        assert data["detection_metrics"]["true_positives"] >= 1
        assert data["detection_metrics"]["detection_rate_pct"] == 100.0
