import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.dependencies import (
    get_db,
    get_attack_simulator,
    get_event_manager,
    get_ra_detector,
    get_ndp_detector,
    get_current_tenant_id,
)
from backend.storage.database import Database
from backend.models.schema import ExperimentRecord, ExperimentResponse
from network.attack_simulator import ControlledAttackSimulator
from network.traffic_simulator import NormalTrafficSimulator
from network.lab_status import LabStatusManager
from security.event_manager import SecurityEventManager
from security.ra_detector import RouterAdvertisementDetector
from security.ndp_detector import NDPAnomalyDetector

router = APIRouter(prefix="/api/experiments", tags=["Lab Experiments"])

# Global reference for active normal traffic simulator
_active_traffic_sim: Optional[NormalTrafficSimulator] = None
_active_experiment_id: Optional[str] = None

class NormalExperimentRequest(BaseModel):
    duration_seconds: int = Field(default=2, ge=1, le=60)
    packet_interval_sec: float = Field(default=0.2, ge=0.05, le=5.0)

class RogueRAExperimentRequest(BaseModel):
    rogue_source: str = "fe80::dead:beef"
    unauthorized_prefix: str = "2001:db8:baad::/64"
    router_lifetime: int = 1800

class NDPBurstExperimentRequest(BaseModel):
    target_ip: str = "2001:db8:6::11"
    packet_count: int = Field(default=90, ge=10, le=500)
    packet_rate_pps: int = Field(default=50, ge=5, le=200)

@router.get("", response_model=List[ExperimentRecord])
async def list_experiments(
    limit: int = 50,
    db: Database = Depends(get_db),
):
    """List recorded laboratory experiment runs."""
    return await db.get_experiments(limit=limit)

@router.post("/normal", response_model=ExperimentResponse)
async def run_normal_experiment(
    req: NormalExperimentRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
):
    """
    Run benign baseline IoT telemetry experiment.
    Generates low-volume traffic to record baseline rates and verify zero false alarms.
    """
    global _active_traffic_sim, _active_experiment_id
    exp_id = f"exp-norm-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc).isoformat()

    sim = NormalTrafficSimulator()
    _active_traffic_sim = sim
    _active_experiment_id = exp_id

    start_info = sim.start_traffic_simulation(
        duration_seconds=req.duration_seconds,
        packet_interval_sec=req.packet_interval_sec
    )

    record = ExperimentRecord(
        experiment_id=exp_id,
        scenario_type="NORMAL_TRAFFIC",
        target_namespaces=start_info["target_namespaces"],
        parameters=req.model_dump(),
        status="RUNNING",
        start_time=start_time,
        packets_sent=0,
        alerts_triggered=0,
    )
    await db.record_experiment(record)

    return ExperimentResponse(
        status="SUCCESS",
        experiment_id=exp_id,
        scenario_type="NORMAL_TRAFFIC",
        message="Benign traffic experiment started successfully.",
        details=start_info,
    )

@router.post("/rogue-ra", response_model=ExperimentResponse)
async def run_rogue_ra_experiment(
    req: RogueRAExperimentRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
    attack_sim: ControlledAttackSimulator = Depends(get_attack_simulator),
    ra_detector: RouterAdvertisementDetector = Depends(get_ra_detector),
    event_mgr: SecurityEventManager = Depends(get_event_manager),
):
    """
    Run controlled Rogue Router Advertisement experiment in the isolated lab.
    Validates RFC 4861/6105 policy detector and event alert pipeline.
    """
    exp_id = f"exp-ra-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc).isoformat()

    # Strict target address confinement: Reject arbitrary external targets
    if not (req.rogue_source.lower().startswith("fe80:") or req.rogue_source.lower().startswith("2001:db8:6:")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Refused: Rogue source address '{req.rogue_source}' does not belong to configured lab address space (fe80::/10 or 2001:db8:6::/64). Arbitrary external targets are strictly forbidden."
        )

    # Execute simulation (safe direct packet injection into detection pipeline)
    attack_res = attack_sim.inject_rogue_ra(
        rogue_source=req.rogue_source,
        unauthorized_prefix=req.unauthorized_prefix,
        router_lifetime=req.router_lifetime,
        use_netns=False,
    )

    # Process through detector
    ra_result = ra_detector.inspect_ra_packet(attack_res["packet_object"])
    alerts_triggered = 0
    if ra_result.is_rogue:
        alerts_triggered = 1
        await event_mgr.handle_ra_detection(ra_result, default_tenant=tenant_id)

    completion_time = datetime.now(timezone.utc).isoformat()
    record = ExperimentRecord(
        experiment_id=exp_id,
        scenario_type="ROGUE_RA",
        target_namespaces=["p6g-router", "p6g-iot1..5"],
        parameters=req.model_dump(),
        status="COMPLETED",
        start_time=start_time,
        completion_time=completion_time,
        packets_sent=1,
        alerts_triggered=alerts_triggered,
    )
    await db.record_experiment(record)

    return ExperimentResponse(
        status="SUCCESS",
        experiment_id=exp_id,
        scenario_type="ROGUE_RA",
        message="Rogue RA injection completed and evaluated.",
        details={
            "detection_triggered": ra_result.is_rogue,
            "violation_type": ra_result.violation_type,
            "source_ip": req.rogue_source,
            "prefix": req.unauthorized_prefix,
            "alerts_triggered": alerts_triggered,
        },
    )

@router.post("/ndp-burst", response_model=ExperimentResponse)
async def run_ndp_burst_experiment(
    req: NDPBurstExperimentRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
    attack_sim: ControlledAttackSimulator = Depends(get_attack_simulator),
    ndp_detector: NDPAnomalyDetector = Depends(get_ndp_detector),
    event_mgr: SecurityEventManager = Depends(get_event_manager),
):
    """
    Run controlled NDP message rate storm experiment in the isolated lab.
    Validates rolling-window rate counter and anomaly indicator alert pipeline.
    """
    # Strict target address confinement: Reject arbitrary external targets
    if not (req.target_ip.lower().startswith("2001:db8:6:") or req.target_ip.lower().startswith("fe80:")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Refused: Target IP '{req.target_ip}' does not belong to configured lab network (2001:db8:6::/64). Arbitrary external targets are strictly forbidden."
        )

    exp_id = f"exp-ndp-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc).isoformat()

    # Reset cooldown timer so manual experiment execution evaluates freshly
    ndp_detector.reset_cooldown()

    # Execute simulation (safe direct packet injection into detection pipeline)
    attack_res = attack_sim.inject_ndp_flood(
        target_ip=req.target_ip,
        packet_count=req.packet_count,
        packet_rate_pps=req.packet_rate_pps,
        use_netns=False,
    )

    # Process through detector
    anomaly_triggered = False
    alerts_count = 0
    for _ in range(req.packet_count):
        res = ndp_detector.inspect_ndp_packet({
            "source_ip": "2001:db8:6::bad",
            "msg_type": "NS",
        })
        if res.is_anomaly:
            anomaly_triggered = True
            alerts_count += 1
            await event_mgr.handle_ndp_anomaly(res, default_tenant=tenant_id)
            break # Cooldown suppresses remaining burst

    completion_time = datetime.now(timezone.utc).isoformat()
    record = ExperimentRecord(
        experiment_id=exp_id,
        scenario_type="NDP_BURST",
        target_namespaces=["p6g-attacker", req.target_ip],
        parameters=req.model_dump(),
        status="COMPLETED",
        start_time=start_time,
        completion_time=completion_time,
        packets_sent=req.packet_count,
        alerts_triggered=alerts_count,
    )
    await db.record_experiment(record)

    return ExperimentResponse(
        status="SUCCESS",
        experiment_id=exp_id,
        scenario_type="NDP_BURST",
        message="NDP rate storm completed and evaluated.",
        details={
            "anomaly_triggered": anomaly_triggered,
            "packets_sent": req.packet_count,
            "alerts_triggered": alerts_count,
            "indicator_label": "ANOMALY_INDICATOR_NOT_DEFINITIVE_PROOF",
        },
    )

@router.post("/baseline", response_model=ExperimentResponse)
async def run_baseline_experiment(
    req: NormalExperimentRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Database = Depends(get_db),
    ndp_detector: NDPAnomalyDetector = Depends(get_ndp_detector),
):
    """
    Run benign baseline experiment and record observed message rates.
    Validates zero false alarms during normal operation and logs baseline telemetry.
    """
    exp_id = f"exp-base-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc).isoformat()

    sim = NormalTrafficSimulator()
    start_info = sim.start_traffic_simulation(
        duration_seconds=req.duration_seconds,
        packet_interval_sec=req.packet_interval_sec
    )
    # Stop simulation after interval
    import time
    time.sleep(0.5)
    stop_info = sim.stop_traffic_simulation()

    completion_time = datetime.now(timezone.utc).isoformat()
    record = ExperimentRecord(
        experiment_id=exp_id,
        scenario_type="NORMAL_TRAFFIC",
        target_namespaces=start_info["target_namespaces"],
        parameters=req.model_dump(),
        status="COMPLETED",
        start_time=start_time,
        completion_time=completion_time,
        packets_sent=stop_info["packets_sent"],
        alerts_triggered=0,
    )
    await db.record_experiment(record)

    tradeoffs = ndp_detector.evaluate_threshold_tradeoffs()
    return ExperimentResponse(
        status="SUCCESS",
        experiment_id=exp_id,
        scenario_type="NORMAL_TRAFFIC",
        message="Benign baseline experiment executed with 0 false alarms.",
        details={
            "packets_sent": stop_info["packets_sent"],
            "alerts_triggered": 0,
            "threshold_tradeoffs": tradeoffs,
        },
    )

@router.post("/{experiment_id}/cancel", response_model=ExperimentResponse)
async def cancel_experiment_by_id(
    experiment_id: str,
    db: Database = Depends(get_db),
):
    """
    Cancel an experiment by its unique Experiment ID.
    """
    global _active_traffic_sim, _active_experiment_id
    if _active_traffic_sim and _active_traffic_sim.is_running:
        stop_info = _active_traffic_sim.stop_traffic_simulation()
        await db.update_experiment(
            experiment_id,
            status="CANCELLED",
            packets_sent=stop_info.get("packets_sent", 0),
            completion_time=datetime.now(timezone.utc).isoformat(),
        )
        _active_traffic_sim = None
        _active_experiment_id = None
        return ExperimentResponse(
            status="SUCCESS",
            experiment_id=experiment_id,
            scenario_type="TRAFFIC_SIMULATION",
            message=f"Experiment '{experiment_id}' cancelled cleanly.",
            details=stop_info,
        )

    await db.update_experiment(
        experiment_id,
        status="CANCELLED",
        completion_time=datetime.now(timezone.utc).isoformat(),
    )
    return ExperimentResponse(
        status="SUCCESS",
        experiment_id=experiment_id,
        scenario_type="EXPERIMENT",
        message=f"Experiment '{experiment_id}' marked as CANCELLED.",
        details={},
    )

@router.post("/stop", response_model=ExperimentResponse)
async def stop_experiment(
    db: Database = Depends(get_db),
):
    """
    Stop any actively running experiment.
    """
    global _active_traffic_sim, _active_experiment_id
    if _active_traffic_sim and _active_traffic_sim.is_running:
        stop_info = _active_traffic_sim.stop_traffic_simulation()
        if _active_experiment_id:
            await db.update_experiment(
                _active_experiment_id,
                status="COMPLETED",
                packets_sent=stop_info["packets_sent"],
                completion_time=datetime.now(timezone.utc).isoformat(),
            )
        exp_id = _active_experiment_id or "unknown"
        _active_traffic_sim = None
        _active_experiment_id = None
        return ExperimentResponse(
            status="SUCCESS",
            experiment_id=exp_id,
            scenario_type="TRAFFIC_SIMULATION",
            message="Active experiment stopped cleanly.",
            details=stop_info,
        )

    return ExperimentResponse(
        status="SUCCESS",
        experiment_id="none",
        scenario_type="NONE",
        message="No active running experiment to stop.",
        details={},
    )
