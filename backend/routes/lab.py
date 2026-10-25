from fastapi import APIRouter, Depends
from typing import Dict, Any

from network.lab_status import LabStatusManager
from backend.dependencies import get_attack_simulator, get_packet_capture
from backend.models.schema import LabStatusResponse

router = APIRouter(prefix="/api/lab", tags=["Lab Management"])

@router.get("/status")
async def get_lab_status() -> Dict[str, Any]:
    status_mgr = LabStatusManager()
    status_data = status_mgr.get_full_lab_status()
    capture = get_packet_capture()

    return {
        "bridge_name": status_data["bridge"].get("name", "p6g-br0"),
        "bridge_status": status_data["bridge"].get("state", "DOWN"),
        "is_active": status_data["is_active"],
        "is_healthy": status_data["is_healthy"],
        "manifest_recorded": status_data["manifest_recorded"],
        "monitor_running": capture.is_capturing,
        "namespaces": list(status_data["devices"].keys()),
        "devices": status_data["devices"],
        "router": status_data["router"],
        "attacker": status_data["attacker"],
    }

@router.get("/preflight")
async def check_lab_preflight() -> Dict[str, Any]:
    status_mgr = LabStatusManager()
    ok, msg = status_mgr.preflight_attack_check()
    return {"passed": ok, "message": msg}

@router.post("/start")
async def start_lab() -> Dict[str, Any]:
    """
    Start Priv6Guard lab monitoring and packet capture engine.
    """
    capture = get_packet_capture()
    started = capture.start_capture(authorized=True)
    return {
        "status": "RUNNING" if started else "STANDBY",
        "message": "Priv6Guard lab monitoring and packet capture started." if started else "Packet capture started in standby simulation mode.",
        "interface": capture.interface,
        "is_capturing": capture.is_capturing,
    }

@router.post("/stop")
async def stop_lab() -> Dict[str, Any]:
    """
    Gracefully stop Priv6Guard lab packet capture engine.
    """
    capture = get_packet_capture()
    stats = capture.stop_capture()
    return {
        "status": "STOPPED",
        "message": "Priv6Guard packet capture engine stopped gracefully.",
        "stats": stats,
    }

