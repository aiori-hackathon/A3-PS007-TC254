import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import logging

from backend.storage.database import Database
from backend.models.schema import SecurityEventCreate, NormalizedAlert
from security.ra_detector import RADetectionResult
from security.ndp_detector import NDPAnomalyResult
from security.pseudonym_manager import PseudonymManager

logger = logging.getLogger("priv6guard.event_manager")

class SecurityEventManager:
    """
    Orchestrates the conversion of detector anomalies into verified, tenant-isolated security events.
    Applies strict data minimization: extracts only essential security event metadata,
    avoiding persistent full-packet payload storage.
    """
    def __init__(self, database: Database, pseudonym_mgr: PseudonymManager):
        self.db = database
        self.pseudonym_mgr = pseudonym_mgr
        self._recent_events: List[Dict[str, Any]] = []

    async def handle_ra_detection(
        self,
        result: RADetectionResult,
        default_tenant: str = "tenant-alpha"
    ) -> Optional[SecurityEventCreate]:
        if not result.is_rogue:
            return None

        event_id = f"evt-ra-{uuid.uuid4().hex[:8]}"
        alert_id = f"alt-ra-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()

        event = SecurityEventCreate(
            event_id=event_id,
            tenant_id=default_tenant,
            timestamp=now_str,
            event_type="ROGUE_RA",
            severity=result.severity,
            source_ip=result.source_ip,
            target_ip="ff02::1", # All-nodes multicast
            affected_pseudonym=None,
            details={
                "violation_type": result.violation_type,
                "advertised_prefixes": result.advertised_prefixes,
                "router_lifetime": result.router_lifetime,
                "managed_flag": result.managed_flag,
                "other_flag": result.other_flag,
                "explanation": result.details.get("message", "Unauthorized Router Advertisement detected."),
            },
            verified=True,
        )

        alert = NormalizedAlert(
            alert_id=alert_id,
            timestamp=now_str,
            alert_type="ROGUE_RA_POLICY_VIOLATION",
            severity=result.severity,
            rule_id="RULE-RA-RFC6105",
            reason=result.details.get("message", f"Unauthorized router advertisement from {result.source_ip}"),
            interface="p6g-br0",
            evidence={
                "source_ip": result.source_ip,
                "advertised_prefixes": result.advertised_prefixes,
                "router_lifetime": result.router_lifetime,
                "violation_type": result.violation_type,
            },
            tenant_scope=default_tenant,
        )

        await self.db.record_security_event(event)
        try:
            await self.db.record_alert(alert)
        except Exception as e:
            logger.debug(f"Alert record note: {e}")

        self._recent_events.append(event.model_dump())
        logger.info(f"Recorded security event {event.event_id}: ROGUE_RA from {result.source_ip}")
        return event

    async def handle_ndp_anomaly(
        self,
        result: NDPAnomalyResult,
        default_tenant: str = "tenant-alpha",
        active_pseudonym: Optional[str] = None,
    ) -> Optional[SecurityEventCreate]:
        if not result.is_anomaly:
            return None

        event_id = f"evt-ndp-{uuid.uuid4().hex[:8]}"
        alert_id = f"alt-ndp-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()

        event = SecurityEventCreate(
            event_id=event_id,
            tenant_id=default_tenant,
            timestamp=now_str,
            event_type="NDP_RATE_ANOMALY",
            severity="HIGH",
            source_ip=result.source_ip,
            target_ip=None,
            affected_pseudonym=active_pseudonym,
            details={
                "anomaly_type": result.anomaly_type,
                "classification": result.classification,
                "current_rate_pps": result.current_rate_pps,
                "threshold_pps": result.threshold_pps,
                "guidance": result.details.get("guidance", "High rate is an anomaly indicator."),
            },
            verified=True,
        )

        alert = NormalizedAlert(
            alert_id=alert_id,
            timestamp=now_str,
            alert_type="NDP_RATE_ANOMALY",
            severity="HIGH",
            rule_id="RULE-NDP-RATE-LIMIT",
            reason=f"Abnormal NDP rate burst detected: {result.current_rate_pps:.1f} pps exceeds threshold {result.threshold_pps:.1f} pps",
            interface="p6g-br0",
            evidence={
                "source_ip": result.source_ip,
                "current_rate_pps": result.current_rate_pps,
                "threshold_pps": result.threshold_pps,
                "classification": result.classification,
            },
            tenant_scope=default_tenant,
        )

        await self.db.record_security_event(event)
        try:
            await self.db.record_alert(alert)
        except Exception as e:
            logger.debug(f"Alert record note: {e}")

        self._recent_events.append(event.model_dump())
        logger.info(f"Recorded security event {event.event_id}: {result.anomaly_type} from {result.source_ip}")
        return event

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._recent_events[-limit:]
