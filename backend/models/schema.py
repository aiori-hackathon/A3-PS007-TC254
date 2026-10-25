from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class DeviceResponse(BaseModel):
    id: str
    name: str
    device_type: str
    namespace: str
    tenant_id: str
    current_ipv6: str
    current_pseudonym: str
    rotation_count: int
    last_rotation: Optional[str]
    session_expires_at: Optional[str]
    session_ttl_remaining: int = 0
    is_active: bool = True

class AddressRotationResponse(BaseModel):
    device_id: str
    tenant_id: str
    old_ipv6: str
    new_ipv6: str
    new_pseudonym: str
    rotation_count: int
    rotated_at: str

class SecurityEventCreate(BaseModel):
    event_id: str
    tenant_id: str
    timestamp: str
    event_type: str
    severity: str
    source_ip: str
    target_ip: Optional[str] = None
    affected_pseudonym: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    verified: bool = True

class SecurityEventResponse(BaseModel):
    id: str
    tenant_id: str
    timestamp: str
    event_type: str
    severity: str
    source_ip: str
    target_ip: Optional[str] = None
    affected_pseudonym: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    verified: bool = True
    remediation_status: str = "ALERTED"

class AttackTriggerRequest(BaseModel):
    attack_type: str
    rogue_prefix: Optional[str] = "2001:db8:evil::/64"
    router_lifetime: Optional[int] = 1800
    packet_rate_pps: Optional[int] = 50
    duration_seconds: Optional[int] = 5

class AttackTriggerResponse(BaseModel):
    status: str
    attack_type: str
    target_bridge: str
    message: str
    triggered_at: str

class DetectionMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    detection_rate_pct: float = 100.0
    precision_pct: float = 100.0
    false_alarm_rate_pct: float = 0.0
    false_positive_rate_pct: float = 0.0
    false_negative_rate_pct: float = 0.0
    avg_detection_latency_ms: float = 0.0
    completed_experiments_count: int = 0
    evaluation_unit: str = "experiment"
    has_data: bool = True
    message: Optional[str] = None

class PrivacyMetrics(BaseModel):
    active_pseudonyms: int = 0
    expired_pseudonyms_purged: int = 0
    total_rotations: int = 0
    authorized_session_continuity_pct: float = 100.0
    unauthorized_correlations_blocked: int = 0
    tracking_resistance_score: float = 1.0

class TrafficRates(BaseModel):
    current_pps: float = 0.0
    icmpv6_ns_rate: float = 0.0
    icmpv6_na_rate: float = 0.0
    icmpv6_ra_rate: float = 0.0
    ndp_threshold: float = 15.0

class EvaluationMetricsResponse(BaseModel):
    timestamp: str
    detection_metrics: DetectionMetrics
    privacy_metrics: PrivacyMetrics
    traffic_rates: TrafficRates

class LabStatusResponse(BaseModel):
    bridge_name: str
    bridge_status: str
    ipv6_prefix: str
    namespaces: List[str]
    monitor_active: bool
    traffic_generator_active: bool
    mode: str = "simulation"

# ==========================================
# Phase 4 & 5: Normalized Events & Alerts
# ==========================================

class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str
    interface: str = "p6g-br0"
    protocol: str = "ICMPv6"
    icmp6_type: int
    icmp6_name: str
    source_ip: str
    target_ip: Optional[str] = None
    tenant_id: Optional[str] = None
    session_pseudonym: Optional[str] = None
    scenario_id: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)

class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: str
    alert_type: str = Field(description="ROGUE_RA_POLICY_VIOLATION or NDP_RATE_ANOMALY")
    severity: str = Field(description="CRITICAL, HIGH, WARNING, INFO")
    rule_id: str
    reason: str
    interface: str = "p6g-br0"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    experiment_id: Optional[str] = None
    status: str = "ACTIVE"
    tenant_scope: Optional[str] = "tenant-alpha"

class ExperimentRecord(BaseModel):
    experiment_id: str
    scenario_type: str
    target_namespaces: List[str] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: str = "RUNNING" # RUNNING, COMPLETED, CANCELLED, FAILED
    start_time: str
    completion_time: Optional[str] = None
    packets_sent: int = 0
    alerts_triggered: int = 0

class ExperimentResponse(BaseModel):
    status: str
    experiment_id: str
    scenario_type: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)

class SessionInfoResponse(BaseModel):
    session_id_masked: str
    device_id: str
    tenant_id: str
    current_pseudonym: str
    created_at: str
    expires_at: str
    ttl_remaining_seconds: int
    is_valid: bool

