import pytest
import logging
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.logging_config import SensitiveDataFilter

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        
        # Verify required keys
        assert data["status"] == "healthy"
        assert data["app"] == "PRIV6GUARD"
        assert data["version"] == "1.0.0"
        assert data["mode"] == "LAB_SIMULATION"
        assert data["config_loaded"] is True
        assert "timestamp" in data

        # Security check: Ensure no secrets or filesystem paths leak
        response_str = str(data)
        assert "secret" not in response_str.lower()
        assert "key" not in response_str.lower()
        assert "/home/" not in response_str
        assert "password" not in response_str.lower()

def test_sensitive_log_filter():
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Connecting with token=secret12345 to bridge",
        args=(),
        exc_info=None,
    )
    filt.filter(record)
    assert "token=[REDACTED]" in record.msg
    assert "secret12345" not in record.msg
