from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.dependencies import (
    get_attack_simulator,
    get_event_manager,
    get_ra_detector,
    get_ndp_detector,
    get_current_tenant_id,
)
from network.attack_simulator import ControlledAttackSimulator
from security.event_manager import SecurityEventManager
from security.ra_detector import RouterAdvertisementDetector
from security.ndp_detector import NDPAnomalyDetector

router = APIRouter(prefix="/api/attacks", tags=["Controlled Attack Simulator"])

class RogueRARequest(BaseModel):
    rogue_source: str = "fe80::dead:beef"
    unauthorized_prefix: str = "2001:db8:baad::/64"
    router_lifetime: int = 1800

class NDPFloodRequest(BaseModel):
    target_ip: str = "2001:db8:6::11"
    packet_count: int = 90
    packet_rate_pps: int = 50

@router.post("/rogue-ra")
async def trigger_rogue_ra(
    req: RogueRARequest,
    tenant_id: str = Depends(get_current_tenant_id),
    attack_sim: ControlledAttackSimulator = Depends(get_attack_simulator),
    ra_detector: RouterAdvertisementDetector = Depends(get_ra_detector),
    event_mgr: SecurityEventManager = Depends(get_event_manager),
) -> Dict[str, Any]:
    """
    Trigger a controlled Rogue Router Advertisement injection.
    Guarded by preflight lab validation.
    """
    # 1. Execute attack simulation
    attack_res = attack_sim.inject_rogue_ra(
        rogue_source=req.rogue_source,
        unauthorized_prefix=req.unauthorized_prefix,
        router_lifetime=req.router_lifetime,
        use_netns=False, # Safe direct simulation
    )

    # 2. Process packet directly through RA detector to generate live alert
    ra_result = ra_detector.inspect_ra_packet(attack_res["packet_object"])
    if ra_result.is_rogue:
        await event_mgr.handle_ra_detection(ra_result, default_tenant=tenant_id)

    return {
        "status": "SUCCESS",
        "attack_type": "ROGUE_RA",
        "rogue_source": req.rogue_source,
        "unauthorized_prefix": req.unauthorized_prefix,
        "detection_triggered": ra_result.is_rogue,
        "violation_type": ra_result.violation_type,
    }

@router.post("/ndp-flood")
async def trigger_ndp_flood(
    req: NDPFloodRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    attack_sim: ControlledAttackSimulator = Depends(get_attack_simulator),
    ndp_detector: NDPAnomalyDetector = Depends(get_ndp_detector),
    event_mgr: SecurityEventManager = Depends(get_event_manager),
) -> Dict[str, Any]:
    """
    Trigger a controlled NDP flood burst to test rolling-window rate anomaly detection.
    """
    attack_res = attack_sim.inject_ndp_flood(
        target_ip=req.target_ip,
        packet_count=req.packet_count,
        packet_rate_pps=req.packet_rate_pps,
        use_netns=False,
    )

    # Feed burst packets into NDP detector
    anomaly_triggered = False
    for _ in range(req.packet_count):
        ndp_res = ndp_detector.inspect_ndp_packet({
            "source_ip": "2001:db8:6::bad",
            "msg_type": "NS",
        })
        if ndp_res.is_anomaly:
            anomaly_triggered = True
            await event_mgr.handle_ndp_anomaly(ndp_res, default_tenant=tenant_id)
            break

    return {
        "status": "SUCCESS",
        "attack_type": "NDP_FLOOD",
        "packets_sent": req.packet_count,
        "target_ip": req.target_ip,
        "anomaly_triggered": anomaly_triggered,
        "indicator": "ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF",
    }

@router.post("/stop")
async def stop_attacks(
    attack_sim: ControlledAttackSimulator = Depends(get_attack_simulator),
) -> Dict[str, Any]:
    return attack_sim.stop_attack()
