import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app

@pytest.mark.asyncio
async def test_lab_start_and_stop_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Start lab
        res_start = await client.post("/api/lab/start")
        assert res_start.status_code == 200
        data_start = res_start.json()
        assert "status" in data_start

        # Stop lab
        res_stop = await client.post("/api/lab/stop")
        assert res_stop.status_code == 200
        data_stop = res_stop.json()
        assert data_stop["status"] == "STOPPED"

@pytest.mark.asyncio
async def test_sessions_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/sessions", headers={"X-Tenant-ID": "tenant-alpha"})
        assert res.status_code == 200
        sessions = res.json()
        assert isinstance(sessions, list)
        for s in sessions:
            assert s["tenant_id"] == "tenant-alpha"
            assert "session_id_masked" in s
            assert "secret" not in s

@pytest.mark.asyncio
async def test_alerts_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/alerts", headers={"X-Tenant-ID": "tenant-alpha"})
        assert res.status_code == 200
        alerts = res.json()
        assert isinstance(alerts, list)

@pytest.mark.asyncio
async def test_experiments_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Normal traffic experiment
        norm_res = await client.post(
            "/api/experiments/normal",
            json={"duration_seconds": 1, "packet_interval_sec": 0.1},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert norm_res.status_code == 200
        norm_data = norm_res.json()
        assert norm_data["status"] == "SUCCESS"
        assert norm_data["scenario_type"] == "NORMAL_TRAFFIC"

        # Stop normal experiment
        stop_res = await client.post("/api/experiments/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "SUCCESS"

        # 2. Rogue RA experiment
        ra_res = await client.post(
            "/api/experiments/rogue-ra",
            json={
                "rogue_source": "fe80::dead:beef",
                "unauthorized_prefix": "2001:db8:baad::/64",
                "router_lifetime": 1800,
            },
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert ra_res.status_code == 200
        assert ra_res.json()["details"]["detection_triggered"] is True

        # 3. NDP burst experiment
        ndp_res = await client.post(
            "/api/experiments/ndp-burst",
            json={"target_ip": "2001:db8:6::11", "packet_count": 90, "packet_rate_pps": 50},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert ndp_res.status_code == 200
        assert ndp_res.json()["details"]["anomaly_triggered"] is True

        # 4. List recorded experiments
        list_res = await client.get("/api/experiments")
        assert list_res.status_code == 200
        exps = list_res.json()
        assert len(exps) >= 3

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["app"] == "PRIV6GUARD"
        assert data["mode"] == "LAB_SIMULATION"
        assert "version" in data
        assert "timestamp" in data

@pytest.mark.asyncio
async def test_request_validation_and_rejection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Invalid duration (< 1s or invalid type)
        res = await client.post(
            "/api/experiments/normal",
            json={"duration_seconds": -5},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert res.status_code == 422

@pytest.mark.asyncio
async def test_external_target_address_rejection():
    """
    CRITICAL SECURITY TEST: Ensure simulator refuses arbitrary external addresses.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Pass public internet IPv6 to ndp-burst
        res = await client.post(
            "/api/experiments/ndp-burst",
            json={"target_ip": "2001:4860:4860::8888", "packet_count": 50},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert res.status_code == 400
        assert "Arbitrary external targets are strictly forbidden" in res.json()["detail"]

        # Pass public internet IPv6 to rogue-ra
        res_ra = await client.post(
            "/api/experiments/rogue-ra",
            json={"rogue_source": "2607:f8b0:4005:805::200e"},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert res_ra.status_code == 400
        assert "Arbitrary external targets are strictly forbidden" in res_ra.json()["detail"]

@pytest.mark.asyncio
async def test_experiment_cancel_by_id_and_baseline():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test cancel by ID
        cancel_res = await client.post("/api/experiments/exp-fake-123/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "SUCCESS"

        # Test baseline experiment
        base_res = await client.post(
            "/api/experiments/baseline",
            json={"duration_seconds": 1, "packet_interval_sec": 0.1},
            headers={"X-Tenant-ID": "tenant-alpha"}
        )
        assert base_res.status_code == 200
        assert base_res.json()["details"]["alerts_triggered"] == 0

@pytest.mark.asyncio
async def test_database_cleanup_retention(temp_db):
    """
    CRITICAL REQUIREMENT: Test database cleanup and retention behavior.
    """
    purged = await temp_db.cleanup_old_records(retention_hours=0)
    assert "purged_pseudonyms" in purged
    assert "purged_events" in purged
    assert "retention_cutoff" in purged

@pytest.mark.asyncio
async def test_metrics_empty_state_and_synthetic_cases(temp_db):
    """
    CRITICAL REQUIREMENT:
    - Test metrics with no data (clear empty state, has_data=False).
    - Test metrics with known synthetic evaluation cases.
    """
    # 1. Empty state
    empty_metrics = await temp_db.get_metrics()
    assert empty_metrics.detection_metrics.has_data is False
    assert empty_metrics.detection_metrics.completed_experiments_count == 0
    assert "No experiments executed yet" in empty_metrics.detection_metrics.message

    # 2. Record synthetic evaluation cases:
    # 4 Attacks (all detected -> TP=4, FN=0)
    # 2 Normal runs (neither alerted -> TN=2, FP=0)
    from backend.models.schema import ExperimentRecord
    for i in range(4):
        await temp_db.record_experiment(ExperimentRecord(
            experiment_id=f"exp-synth-atk-{i}",
            scenario_type="ROGUE_RA",
            status="COMPLETED",
            start_time="2026-10-25T12:00:00Z",
            packets_sent=1,
            alerts_triggered=1,
        ))
    for i in range(2):
        await temp_db.record_experiment(ExperimentRecord(
            experiment_id=f"exp-synth-norm-{i}",
            scenario_type="NORMAL_TRAFFIC",
            status="COMPLETED",
            start_time="2026-10-25T12:00:00Z",
            packets_sent=10,
            alerts_triggered=0,
        ))

    # Evaluate synthetic metrics
    synth_metrics = await temp_db.get_metrics()
    dm = synth_metrics.detection_metrics
    assert dm.has_data is True
    assert dm.completed_experiments_count == 6
    assert dm.true_positives == 4
    assert dm.true_negatives == 2
    assert dm.false_positives == 0
    assert dm.false_negatives == 0
    assert dm.detection_rate_pct == 100.0  # 4 / (4+0) * 100
    assert dm.precision_pct == 100.0       # 4 / (4+0) * 100
    assert dm.false_positive_rate_pct == 0.0 # 0 / (0+2) * 100
    assert dm.false_negative_rate_pct == 0.0 # 0 / (4+0) * 100

@pytest.mark.asyncio
async def test_events_live_stream_endpoint():
    """Verify live Server-Sent Events (SSE) stream connects and emits events."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream("GET", "/api/events/stream?iterations=1", headers={"X-Tenant-ID": "tenant-alpha"}) as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]
            first_chunk = await response.aiter_lines().__anext__()
            assert "event: ping" in first_chunk or "data:" in first_chunk


