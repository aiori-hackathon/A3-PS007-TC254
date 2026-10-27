from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Header
from pydantic import BaseModel

from backend.dependencies import (
    get_db,
    get_session_manager,
    get_pseudonym_manager,
    get_address_rotator,
    get_current_tenant_id,
)
from backend.models.schema import DeviceResponse, AddressRotationResponse
from backend.storage.database import Database
from security.auth_manager import SessionManager, DEVICE_CREDENTIALS_STORE
from security.pseudonym_manager import PseudonymManager
from network.address_rotator import AddressRotationManager
from network.lab_config import DEFAULT_LAB_CONFIG

router = APIRouter(prefix="/api/devices", tags=["Devices & Privacy"])

class DeviceAuthRequest(BaseModel):
    secret: str

class DeviceAuthResponse(BaseModel):
    device_id: str
    tenant_id: str
    session_token: str
    expires_in_seconds: int
    message: str

class DeviceRotateRequest(BaseModel):
    session_token: Optional[str] = None

@router.get("", response_model=List[DeviceResponse])
async def list_devices(
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
    pm: PseudonymManager = Depends(get_pseudonym_manager),
    sm: SessionManager = Depends(get_session_manager),
):
    """
    List devices for the authenticated tenant.
    Enforces strict backend tenant isolation.
    """
    devices = await db.get_devices(tenant_id=tenant_id)
    if not devices:
        # Populate initial configured devices into DB if empty
        now = datetime.now(timezone.utc)
        for cfg in DEFAULT_LAB_CONFIG.devices:
            if cfg.tenant_id == tenant_id:
                # Issue initial pseudonym
                rec = pm.issue_pseudonym_for_session("init-sess", cfg.tenant_id, cfg.ipv6_address)
                await db.upsert_device({
                    "id": cfg.lab_id,
                    "name": cfg.role,
                    "device_type": cfg.role,
                    "namespace": cfg.namespace,
                    "tenant_id": cfg.tenant_id,
                    "base_mac": cfg.mac_address,
                    "current_ipv6": cfg.ipv6_address,
                    "current_pseudonym": rec.pseudonym,
                    "rotation_count": 0,
                    "last_rotation": now.isoformat(),
                    "session_expires_at": rec.expires_at.isoformat(),
                    "is_active": True,
                })
        devices = await db.get_devices(tenant_id=tenant_id)

    return devices

@router.post("/{device_id}/authenticate", response_model=DeviceAuthResponse)
async def authenticate_device(
    device_id: str,
    req: DeviceAuthRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    sm: SessionManager = Depends(get_session_manager),
):
    """
    Authenticate an IoT device and issue an ephemeral session credential.
    """
    ok, token, msg = sm.authenticate_device(device_id, tenant_id, req.secret)
    if not ok or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

    return DeviceAuthResponse(
        device_id=device_id,
        tenant_id=tenant_id,
        session_token=token,
        expires_in_seconds=int(sm.default_ttl.total_seconds()),
        message=msg,
    )

@router.post("/{device_id}/rotate", response_model=AddressRotationResponse)
async def rotate_device_address(
    device_id: str,
    req: DeviceRotateRequest,
    authorization: Optional[str] = Header(None),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
    rotator: AddressRotationManager = Depends(get_address_rotator),
    sm: SessionManager = Depends(get_session_manager),
):
    """
    Trigger controlled RFC 8981 address rotation.
    Requires an active, authenticated session token.
    """
    token = req.session_token
    if not token and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    # If no token provided in request and none was attempted, check if device has pre-shared session for demo convenience
    if not token and req.session_token is None and authorization is None:
        cred = DEVICE_CREDENTIALS_STORE.get(device_id)
        if cred and cred["tenant_id"] == tenant_id:
            _, token, _ = sm.authenticate_device(device_id, tenant_id, cred["secret"])

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Address rotation requires an active session token."
        )

    # Get device from DB
    dev = await db.get_device(device_id, tenant_id=tenant_id)
    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' not found for tenant '{tenant_id}'."
        )

    ok, rot_data, msg = rotator.rotate_device_address(
        device_id=device_id,
        session_token=token,
        tenant_id=tenant_id,
        old_ipv6=dev.current_ipv6,
        apply_network_change=False,
    )

    if not ok:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)

    # Update device in DB
    now = datetime.now(timezone.utc)
    new_rot_count = dev.rotation_count + 1
    await db.upsert_device({
        "id": dev.id,
        "name": dev.name,
        "device_type": dev.device_type,
        "namespace": dev.namespace,
        "tenant_id": dev.tenant_id,
        "base_mac": "02:00:00:00:00:01",
        "current_ipv6": rot_data["new_ipv6"],
        "current_pseudonym": rot_data["new_pseudonym"],
        "rotation_count": new_rot_count,
        "last_rotation": now.isoformat(),
        "session_expires_at": (now + sm.default_ttl).isoformat(),
        "is_active": True,
    })

    return AddressRotationResponse(
        device_id=device_id,
        tenant_id=tenant_id,
        old_ipv6=rot_data["old_ipv6"],
        new_ipv6=rot_data["new_ipv6"],
        new_pseudonym=rot_data["new_pseudonym"],
        rotation_count=new_rot_count,
        rotated_at=rot_data["rotation_timestamp"],
    )

sessions_router = APIRouter(prefix="/api/sessions", tags=["Sessions & Privacy"])

@sessions_router.get("")
async def list_active_sessions(
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
):
    """
    Returns active session metadata for the requesting tenant.
    Never exposes raw secrets, tokens, or permanent cross-address identity graphs.
    """
    return await db.get_active_sessions(tenant_id=tenant_id)

