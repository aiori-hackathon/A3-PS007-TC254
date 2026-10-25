from typing import List, Optional
from fastapi import APIRouter, Depends, Query

from backend.dependencies import get_db, get_current_tenant_id
from backend.models.schema import SecurityEventResponse, NormalizedAlert
from backend.storage.database import Database

router = APIRouter(prefix="/api/events", tags=["Security Events"])
alerts_router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])

@router.get("", response_model=List[SecurityEventResponse])
async def list_security_events(
    limit: int = Query(50, ge=1, le=200),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
):
    """
    Returns verified security events for the requesting tenant.
    Strictly isolated: Tenant A cannot inspect Tenant B's alerts.
    """
    return await db.get_security_events(tenant_id=tenant_id, limit=limit)

@alerts_router.get("", response_model=List[NormalizedAlert])
async def list_normalized_alerts(
    limit: int = Query(50, ge=1, le=200),
    alert_type: Optional[str] = Query(None, description="Filter by ROGUE_RA_POLICY_VIOLATION or NDP_RATE_ANOMALY"),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
):
    """
    Returns structured NormalizedAlert objects for the requesting tenant.
    Supports filtering by alert_type (RA violations vs NDP anomalies).
    """
    return await db.get_alerts(tenant_scope=tenant_id, alert_type=alert_type, limit=limit)

import json
import asyncio
from fastapi import Request
from fastapi.responses import StreamingResponse

@router.get("/stream")
async def stream_security_events(
    request: Request,
    iterations: int = Query(30, ge=1, le=3600),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
):
    """
    Live event updates via Server-Sent Events (SSE).
    Scoped strictly by tenant ID.
    Prevents cross-tenant broadcast leaks.
    """
    async def event_generator():
        last_seen = None
        # Send initial connected event
        yield f"event: ping\ndata: {{\"status\": \"connected\", \"tenant\": \"{tenant_id}\"}}\n\n"
        for _ in range(iterations):
            if await request.is_disconnected():
                break
            events = await db.get_security_events(tenant_id=tenant_id, limit=3)
            if events:
                latest = events[0]
                if last_seen != latest.id:
                    last_seen = latest.id
                    payload = json.dumps(latest.model_dump())
                    yield f"event: security_event\ndata: {payload}\n\n"
            await asyncio.sleep(0.2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )

